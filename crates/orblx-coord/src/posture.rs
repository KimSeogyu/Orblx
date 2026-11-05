//! Device posture for grants and tickets.
//!
//! The node reports `os` and `clientVersion` on the authenticated node channel.
//! Those two facts are self-reported. The coordinator does not attest them.
//! `nodeLock` comes from the node-lock store. `lastSeen` comes from the last
//! authenticated message. A missing fact fails closed.
//!
//! A node that leaves posture loses its capability ticket and its issued agent
//! grants through the deny file. Peers also see the node SVID in the deny list
//! they already poll, so open sessions close on that path. The SVID is not
//! stored in the deny file. The node can still reach the coordinator and report
//! a recovery. One `posture-deny` or `posture-revoke` record is written for each
//! fall, not for each check. One `posture-restore` record is written for each
//! return to posture. Old ticket nonces stay in the deny file.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use orblx_datapath::NetmapPeer;
use orblx_identity::{
    clean_os, clean_version, PostureFacts, PostureFailure, ReceiverGrants, SpiffeId,
};
use serde::{Deserialize, Serialize};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::nodelock::LockStore;
use crate::store::StoredNode;

pub(crate) const FILE: &str = "posture.json";
const FILE_VERSION: u32 = 1;
const MAX_NODES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct PostureState {
    #[serde(default)]
    version: u32,
    /// Changes when the pass or fail set changes. The grant cache key uses it.
    #[serde(default)]
    pub gen: u64,
    #[serde(default)]
    nodes: BTreeMap<String, NodeRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NodeRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_seen_unix: Option<u64>,
    /// Hex nonce of the live capability ticket. The log must not print it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ticket_nonce: Option<String>,
    #[serde(default)]
    ticket_live: bool,
    #[serde(default)]
    deny_latched: bool,
    #[serde(default)]
    revoke_latched: bool,
    /// Failing posture names. Empty means the node is in posture.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    block_key: String,
}

/// Work the coordinator must do before it writes the latches.
pub(crate) struct PostureWork {
    pub ticket_nonces: Vec<String>,
    pub requesters: Vec<String>,
    rows: Vec<RowPlan>,
    gen_bump: bool,
}

struct RowPlan {
    name: String,
    block_key: String,
    was_live: bool,
    was_out: bool,
    /// The nonce to drop. A newer ticket with another nonce stays.
    clear_nonce: Option<String>,
}

/// One audit row. The detail has no secret and no ticket nonce.
pub(crate) struct PostureAudit {
    pub kind: PostureKind,
    pub node: String,
    pub detail: String,
}

/// The posture audit action for one row.
pub(crate) enum PostureKind {
    Deny,
    Revoke,
    Restore,
}

pub(crate) fn load(dir: &std::path::Path) -> Result<PostureState, CoordError> {
    let path = dir.join(FILE);
    if !path.exists() {
        return Ok(PostureState {
            version: FILE_VERSION,
            ..PostureState::default()
        });
    }
    let text = read_text(&path)?;
    if text.contains("PRIVATE KEY") || text.contains("ge1.") || text.contains("orblx-at1.") {
        return Err(CoordError::State);
    }
    let state: PostureState = serde_json::from_str(&text).map_err(|_| CoordError::State)?;
    if state.version != FILE_VERSION {
        return Err(CoordError::State);
    }
    Ok(state)
}

pub(crate) fn save(dir: &std::path::Path, state: &PostureState) -> Result<(), CoordError> {
    let text = serde_json::to_string(state).map_err(|_| CoordError::State)?;
    if text.contains("PRIVATE KEY") || text.contains("ge1.") || text.contains("orblx-at1.") {
        return Err(CoordError::State);
    }
    write_text(&dir.join(FILE), &text, 0o600)
}

/// Stamp last-seen from one authenticated coordinator event.
///
/// The caller has already checked that `name` is the authenticated peer and
/// that the node is enrolled. A report body does not carry this clock.
pub(crate) fn note_seen(
    state: &mut PostureState,
    name: &str,
    now: SystemTime,
) -> Result<(), CoordError> {
    let _ = SpiffeId::node(name)?;
    if !state.nodes.contains_key(name) && state.nodes.len() >= MAX_NODES {
        return Err(CoordError::State);
    }
    let row = state.nodes.entry(name.to_string()).or_default();
    row.last_seen_unix = Some(unix_secs(now)?);
    Ok(())
}

/// Store one self-report on a row that `note_seen` already created.
///
/// An omitted field clears the stored fact. A text that is not a known token
/// also clears it. This function does not set last-seen.
pub(crate) fn apply_report(
    state: &mut PostureState,
    name: &str,
    os: Option<&str>,
    version: Option<&str>,
) -> Result<(), CoordError> {
    let row = state
        .nodes
        .get_mut(name)
        .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".into()))?;
    row.os = os.and_then(clean_os);
    row.client_version = version.and_then(clean_version);
    Ok(())
}

/// Record the nonce of a ticket the coordinator just issued.
pub(crate) fn note_ticket(state: &mut PostureState, name: &str, nonce_hex: &str) {
    let row = state.nodes.entry(name.to_string()).or_default();
    row.ticket_nonce = Some(nonce_hex.to_string());
    row.ticket_live = true;
}

pub(crate) fn generation(state: &PostureState) -> u64 {
    state.gen
}

/// Build the revoke list. This function does not change `state`.
pub(crate) fn plan(
    policy: &orblx_identity::Policy,
    state: &PostureState,
    nodes: &[StoredNode],
    lock: &LockStore,
    now: SystemTime,
) -> Result<PostureWork, CoordError> {
    let signed = lock_map(lock, nodes)?;
    let mut work = PostureWork {
        ticket_nonces: Vec::new(),
        requesters: Vec::new(),
        rows: Vec::new(),
        gen_bump: false,
    };
    for node in nodes {
        let Some(id) = SpiffeId::parse(&node.svid).ok() else {
            continue;
        };
        let facts = facts_for(
            state,
            &node.name,
            signed.get(&node.name).copied().flatten(),
            now,
        )?;
        let block_key = policy.posture_block_key(&id, &facts);
        let row = state.nodes.get(&node.name);
        let was_live = row.is_some_and(|item| item.ticket_live);
        let previous = row.map(|item| item.block_key.as_str()).unwrap_or("");
        if previous != block_key {
            work.gen_bump = true;
        }
        if block_key.is_empty() {
            work.rows.push(RowPlan {
                name: node.name.clone(),
                block_key,
                was_live: false,
                was_out: false,
                clear_nonce: None,
            });
            continue;
        }
        work.requesters.push(node.name.clone());
        let clear_nonce = if was_live {
            row.and_then(|item| item.ticket_nonce.clone())
        } else {
            None
        };
        if let Some(nonce) = clear_nonce.clone() {
            work.ticket_nonces.push(nonce);
        }
        work.rows.push(RowPlan {
            name: node.name.clone(),
            block_key,
            was_live,
            was_out: true,
            clear_nonce,
        });
    }
    Ok(work)
}

/// Apply latches after the deny file and the agent grants are updated.
///
/// `grant_counts` is the number of issued grants revoked for each requester.
pub(crate) fn commit(
    state: &mut PostureState,
    work: &PostureWork,
    grant_counts: &BTreeMap<String, usize>,
) -> Vec<PostureAudit> {
    let mut audits = Vec::new();
    if work.gen_bump {
        state.gen = state.gen.saturating_add(1);
    }
    for row in &work.rows {
        let node = state.nodes.entry(row.name.clone()).or_default();
        if !row.was_out {
            let was_out = !node.block_key.is_empty() || node.deny_latched || node.revoke_latched;
            if was_out {
                let rule = if node.block_key.is_empty() {
                    "restored".to_string()
                } else {
                    format!("rule {}", node.block_key)
                };
                node.block_key.clear();
                node.deny_latched = false;
                node.revoke_latched = false;
                audits.push(PostureAudit {
                    kind: PostureKind::Restore,
                    node: row.name.clone(),
                    detail: rule,
                });
            }
            continue;
        }
        let grants = grant_counts.get(&row.name).copied().unwrap_or(0);
        let revoked = row.was_live || grants > 0;
        node.block_key = row.block_key.clone();
        if revoked && !node.revoke_latched {
            node.revoke_latched = true;
            let ticket = usize::from(row.was_live);
            audits.push(PostureAudit {
                kind: PostureKind::Revoke,
                node: row.name.clone(),
                detail: format!("rule {} ticket {ticket} grants {grants}", row.block_key),
            });
        } else if !node.deny_latched && !node.revoke_latched {
            node.deny_latched = true;
            audits.push(PostureAudit {
                kind: PostureKind::Deny,
                node: row.name.clone(),
                detail: format!("rule {} attr blocked reason mismatch", row.block_key),
            });
        }
        if let Some(nonce) = &row.clear_nonce {
            if node.ticket_nonce.as_ref() == Some(nonce) {
                node.ticket_live = false;
                node.ticket_nonce = None;
            }
        }
    }
    audits
}

/// Record one posture deny for a refused issue, once per fall.
pub(crate) fn latch_deny(
    state: &mut PostureState,
    name: &str,
    failure: &PostureFailure,
) -> Option<PostureAudit> {
    let row = state.nodes.entry(name.to_string()).or_default();
    if row.deny_latched {
        return None;
    }
    row.deny_latched = true;
    Some(PostureAudit {
        kind: PostureKind::Deny,
        node: name.to_string(),
        detail: format!(
            "rule {} attr {} reason {}",
            failure.rule, failure.attr, failure.reason
        ),
    })
}

pub(crate) fn blocked(
    policy: &orblx_identity::Policy,
    state: &PostureState,
    node: &StoredNode,
    lock: &LockStore,
    now: SystemTime,
) -> Result<Option<PostureFailure>, CoordError> {
    let id = SpiffeId::parse(&node.svid)?;
    let signed = lock_signed(lock, node)?;
    let facts = facts_for(state, &node.name, signed, now)?;
    Ok(policy.posture_ticket_failure(&id, &facts))
}

pub(crate) fn deny_uris(state: &PostureState, nodes: &[StoredNode]) -> Vec<String> {
    nodes
        .iter()
        .filter(|node| {
            state
                .nodes
                .get(&node.name)
                .is_some_and(|row| !row.block_key.is_empty())
        })
        .map(|node| node.svid.clone())
        .collect()
}

pub(crate) fn apply_grants(
    policy: &orblx_identity::Policy,
    state: &PostureState,
    nodes: &[StoredNode],
    lock: &LockStore,
    receiver: &SpiffeId,
    grants: &mut ReceiverGrants,
    now: SystemTime,
) -> Result<(), CoordError> {
    let signed = lock_map(lock, nodes)?;
    let mut facts_by_svid = BTreeMap::new();
    for node in nodes {
        let fact = facts_for(
            state,
            &node.name,
            signed.get(&node.name).copied().flatten(),
            now,
        )?;
        facts_by_svid.insert(node.svid.clone(), fact);
    }
    let unknown = PostureFacts::unknown();
    grants.grants.retain(|grant| {
        let Ok(src) = SpiffeId::parse(&grant.src) else {
            return false;
        };
        let facts = facts_by_svid.get(&grant.src).unwrap_or(&unknown);
        policy.posture_allows_grant(
            &src,
            receiver,
            grant.proto,
            grant.port_start,
            grant.port_end,
            facts,
        )
    });
    grants.subnets.retain(|grant| {
        let Ok(src) = SpiffeId::parse(&grant.src) else {
            return false;
        };
        let Some((prefix, prefix_len)) = parse_prefix(&grant.dst) else {
            return false;
        };
        let facts = facts_by_svid.get(&grant.src).unwrap_or(&unknown);
        policy.posture_allows_subnet(
            &src,
            prefix,
            prefix_len,
            grant.proto,
            (grant.port_start, grant.port_end),
            facts,
        )
    });
    let self_facts = facts_by_svid.get(receiver.as_uri()).unwrap_or(&unknown);
    grants.reach.retain(|dst| {
        let Ok(dst_id) = SpiffeId::parse(dst) else {
            return false;
        };
        policy.posture_allows_reach(receiver, &dst_id, self_facts)
    });
    Ok(())
}

fn facts_for(
    state: &PostureState,
    name: &str,
    node_lock_signed: Option<bool>,
    now: SystemTime,
) -> Result<PostureFacts, CoordError> {
    let row = state.nodes.get(name);
    let last_seen_secs = match row.and_then(|item| item.last_seen_unix) {
        None => None,
        Some(seen) => Some(unix_secs(now)?.saturating_sub(seen)),
    };
    Ok(PostureFacts {
        os: row.and_then(|item| item.os.clone()),
        client_version: row.and_then(|item| item.client_version.clone()),
        node_lock_signed,
        last_seen_secs,
    })
}

fn lock_map(
    lock: &LockStore,
    nodes: &[StoredNode],
) -> Result<BTreeMap<String, Option<bool>>, CoordError> {
    let mut out = BTreeMap::new();
    for node in nodes {
        out.insert(node.name.clone(), lock_signed(lock, node)?);
    }
    Ok(out)
}

fn lock_signed(lock: &LockStore, node: &StoredNode) -> Result<Option<bool>, CoordError> {
    if !lock.enabled() {
        return Ok(Some(false));
    }
    let Ok(current) = lock.current() else {
        return Ok(None);
    };
    let peer = NetmapPeer {
        name: node.name.clone(),
        overlay_ip: node.overlay_ip.clone(),
        svid: node.svid.clone(),
        endpoints: Vec::new(),
        routes: Vec::new(),
        exit_node: false,
        owner: String::new(),
        lock_sig: lock.sigs.get(&node.name).cloned(),
    };
    Ok(Some(current.verify_peer(&peer)))
}

fn parse_prefix(text: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, len) = text.split_once('/')?;
    let prefix = addr.parse().ok()?;
    let prefix_len = len.parse().ok()?;
    Some((prefix, prefix_len))
}

fn unix_secs(now: SystemTime) -> Result<u64, CoordError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoordError::Time)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use orblx_audit::{verify_config_file, ConfigAction};
    use orblx_identity::SpiffeId;

    use crate::proto::GrantAsk;
    use crate::state::{Coordinator, OidcConfig, CONFIG_AUDIT_FILE};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "orblx-posture-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(dir: &Path, policy: &str) -> Coordinator {
        fs::write(dir.join("policy.hujson"), policy).unwrap();
        let coord = Coordinator::open(dir, "coord", OidcConfig::TokenOnly).unwrap();
        coord.set_policy_file(&dir.join("policy.hujson")).unwrap();
        coord.enable_config_audit().unwrap();
        coord
    }

    fn enroll(
        coord: &Coordinator,
        name: &str,
        os: Option<&str>,
        version: Option<&str>,
        now: SystemTime,
    ) -> Option<crate::ticket::IssuedTicket> {
        let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        let result = coord
            .enroll_token_reported(
                name,
                &token.secret,
                &[format!("{name}:443")],
                &[],
                now,
                os,
                version,
            )
            .unwrap();
        result.ticket
    }

    fn tally(dir: &Path) -> (usize, usize, usize) {
        let verified = verify_config_file(&dir.join(CONFIG_AUDIT_FILE)).unwrap();
        let deny = verified
            .records
            .iter()
            .filter(|record| record.event.action == ConfigAction::PostureDeny)
            .count();
        let revoke = verified
            .records
            .iter()
            .filter(|record| record.event.action == ConfigAction::PostureRevoke)
            .count();
        let restore = verified
            .records
            .iter()
            .filter(|record| record.event.action == ConfigAction::PostureRestore)
            .count();
        (deny, revoke, restore)
    }

    fn grants_on(coord: &Coordinator, name: &str) -> usize {
        coord
            .netmap_for(name)
            .unwrap()
            .signed_grants
            .grants
            .grants
            .len()
    }

    const DESK: &str = r#"{
      "nodeApproval": false,
      "postures": {"desk": ["os == linux", "clientVersion >= 0.1.0", "lastSeen <= 3600s"]},
      "postureTests": [
        {"name": "desk", "os": "linux", "clientVersion": "0.1.0", "nodeLock": "unsigned", "lastSeen": "5s", "action": "allow"},
        {"name": "desk", "os": "windows", "clientVersion": "0.1.0", "nodeLock": "unsigned", "lastSeen": "5s", "action": "deny"}
      ],
      "acls": [{
        "action": "accept",
        "src": ["spiffe://orblx.local/node/a"],
        "proto": "tcp",
        "dst": ["spiffe://orblx.local/node/b:22"],
        "srcPosture": ["desk"]
      }]
    }"#;

    #[test]
    fn a_posture_fall_revokes_once_and_a_second_fall_revokes_again() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), now).is_some());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 0, 0));
        assert_eq!(grants_on(&coord, "b"), 1);

        coord
            .stage_posture("a", Some("windows"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        assert_eq!(grants_on(&coord, "b"), 0);

        let stored = crate::admin::deny_json(&coord, now).unwrap();
        let projected = crate::admin::deny_json_for(&coord, "b", now).unwrap();
        let svid = SpiffeId::node("a").unwrap().as_uri().to_string();
        assert!(!stored.contains(&svid));
        assert!(projected.contains(&svid));
        let nonces = nonce_count(&stored);
        assert_eq!(nonces.len(), 1);
        let audit = fs::read_to_string(scratch.0.join(CONFIG_AUDIT_FILE)).unwrap();
        assert!(!audit.contains(&nonces[0]));
        assert!(!audit.contains("PRIVATE KEY"));
        assert!(!audit.contains("ge1."));
        assert!(!audit.contains("orblx-at1."));

        coord
            .stage_posture("a", Some("linux"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 1));
        let kept = nonce_count(&crate::admin::deny_json(&coord, now).unwrap());
        assert_eq!(kept, nonces);
        assert!(coord.renew_node("a", now).unwrap().ticket.is_some());
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 1));
        assert_eq!(grants_on(&coord, "b"), 1);

        coord
            .stage_posture("a", Some("windows"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 2, 1));
        assert_eq!(grants_on(&coord, "b"), 0);
        assert_eq!(
            nonce_count(&crate::admin::deny_json(&coord, now).unwrap()).len(),
            2
        );
    }

    #[test]
    fn an_unknown_os_withholds_the_ticket_and_denies_once() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("not-an-os"), Some("0.1.0"), now).is_none());
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (1, 0, 0));
        coord.reconcile_posture(now).unwrap();
        coord
            .stage_posture("a", Some("not-an-os"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (1, 0, 0));
        assert!(coord.renew_node("a", now).unwrap().ticket.is_none());
        assert_eq!(tally(&scratch.0), (1, 0, 0));
    }

    #[test]
    fn an_agent_grant_request_denies_once_while_the_node_is_out() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("windows"), Some("0.1.0"), now).is_none());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        let ask = GrantAsk {
            agent: "bot".to_string(),
            node: "b".to_string(),
            service: "web".to_string(),
            port: 22,
            ttl_secs: 30,
            path_prefix: None,
        };
        assert!(crate::agent::request(&coord, "a", &ask, now).is_err());
        assert_eq!(tally(&scratch.0), (1, 0, 0));
        assert!(crate::agent::request(&coord, "a", &ask, now).is_err());
        assert_eq!(tally(&scratch.0), (1, 0, 0));
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (1, 0, 0));
    }

    #[test]
    fn a_last_seen_age_past_the_limit_revokes_once() {
        let scratch = Scratch::new();
        let past = SystemTime::now()
            .checked_sub(Duration::from_secs(10))
            .unwrap();
        let policy = r#"{
          "nodeApproval": false,
          "postures": {"desk": ["os == linux", "clientVersion >= 0.1.0", "lastSeen <= 1s"]},
          "postureTests": [
            {"name": "desk", "os": "linux", "clientVersion": "0.1.0", "nodeLock": "unsigned", "lastSeen": "1s", "action": "allow"},
            {"name": "desk", "os": "linux", "clientVersion": "0.1.0", "nodeLock": "unsigned", "lastSeen": "2s", "action": "deny"}
          ],
          "acls": [{
            "action": "accept",
            "src": ["spiffe://orblx.local/node/a"],
            "proto": "tcp",
            "dst": ["spiffe://orblx.local/node/b:22"],
            "srcPosture": ["desk"]
          }]
        }"#;
        let coord = open(&scratch.0, policy);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), past).is_some());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), past).is_some());
        let later = SystemTime::now();
        coord.reconcile_posture(later).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        coord.reconcile_posture(later).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        assert_eq!(grants_on(&coord, "b"), 0);
    }

    #[test]
    fn node_lock_off_fails_a_rule_that_requires_a_signature() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let policy = r#"{
          "nodeApproval": false,
          "postures": {"locked": ["os == linux", "clientVersion >= 0.1.0", "nodeLock == signed"]},
          "acls": [{
            "action": "accept",
            "src": ["spiffe://orblx.local/node/a"],
            "proto": "tcp",
            "dst": ["spiffe://orblx.local/node/b:22"],
            "srcPosture": ["locked"]
          }]
        }"#;
        let coord = open(&scratch.0, policy);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), now).is_none());
        coord.reconcile_posture(now).unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (1, 0, 0));
    }

    #[test]
    fn a_peer_refuses_data_and_a_new_handshake_and_the_node_can_still_report() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        let enrolled = {
            let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
            coord
                .enroll_token_reported(
                    "a",
                    &token.secret,
                    &["a:443".to_string()],
                    &[],
                    now,
                    Some("linux"),
                    Some("0.1.0"),
                )
                .unwrap()
        };
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        let ticket = enrolled.ticket.expect("the in-posture node gets a ticket");
        let leaf = orblx_identity::decode_certificate_pem(&enrolled.certificate_pem).unwrap();
        let trust = orblx_identity::TrustBundle::from_pem(&enrolled.trust_bundle_pem).unwrap();
        let verifier =
            orblx_identity::TicketVerifier::from_public_pem(&ticket.verifier_pem).unwrap();
        let key = orblx_crypto::TicketKey::new(
            verifier,
            ticket.mac_key,
            std::time::UNIX_EPOCH + Duration::from_secs(ticket.not_before),
            std::time::UNIX_EPOCH + Duration::from_secs(ticket.not_after),
        )
        .unwrap();
        let ring = orblx_crypto::TicketRing::single(key, &ticket.svid_ca_pub).unwrap();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        let empty = orblx_identity::DenySet::empty();
        let mut open_session = orblx_datapath::PeerGate::new();
        open_session.bind_leaf(&trust, &leaf, now, &empty).unwrap();
        let hash = open_session
            .admit_ticket(&ring, &ticket.bytes, &ticket.mac, now, &empty)
            .unwrap();
        let frame = open_session.encode_data(1, 1, hash, &packet).unwrap();
        assert!(open_session.payload_from_data(&frame, now, &empty).is_ok());

        coord
            .stage_posture("a", Some("windows"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        assert!(coord.renew_node("a", now).unwrap().ticket.is_none());
        assert_eq!(tally(&scratch.0), (0, 1, 0));

        let peer_text = crate::admin::deny_json_for(&coord, "b", now).unwrap();
        let mut peer_deny = orblx_identity::DenySet::empty();
        peer_deny.apply_json(peer_text.as_bytes()).unwrap();
        let mut handshake = orblx_datapath::PeerGate::new();
        assert!(handshake.bind_leaf(&trust, &leaf, now, &peer_deny).is_err());
        assert!(open_session
            .payload_from_data(&frame, now, &peer_deny)
            .is_err());

        let stored = crate::admin::deny_json(&coord, now).unwrap();
        let mut coord_deny = orblx_identity::DenySet::empty();
        coord_deny.apply_json(stored.as_bytes()).unwrap();
        assert!(trust.authenticate_leaf(&leaf, now, &coord_deny).is_ok());
        coord
            .stage_posture("a", Some("windows"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));

        coord
            .stage_posture("a", Some("linux"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 1));
        let kept = crate::admin::deny_json(&coord, now).unwrap();
        assert!(kept.contains(&nonce_count(&stored)[0]));
        let mut still = orblx_identity::DenySet::empty();
        still.apply_json(kept.as_bytes()).unwrap();
        assert!(open_session.payload_from_data(&frame, now, &still).is_err());
    }

    #[test]
    fn a_pending_agent_grant_is_not_issued_while_the_node_is_out() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), now).is_some());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        let ask = GrantAsk {
            agent: "bot".to_string(),
            node: "b".to_string(),
            service: "web".to_string(),
            port: 22,
            ttl_secs: 30,
            path_prefix: None,
        };
        let reply = crate::agent::request(&coord, "a", &ask, now).unwrap();
        let id = reply["id"].as_str().unwrap();
        let owner = SpiffeId::node("owner").unwrap();
        crate::agent::approve(&coord, id, owner.as_uri(), now).unwrap();
        coord
            .stage_posture("a", Some("windows"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        assert!(crate::agent::fetch(&coord, "a", id, now).is_err());
        assert_eq!(tally(&scratch.0), (1, 1, 0));
        assert!(crate::agent::fetch(&coord, "a", id, now).is_err());
        assert_eq!(tally(&scratch.0), (1, 1, 0));
        let listed = crate::agent::list(&coord, now).unwrap();
        let state = listed["grants"][0]["state"].as_str().unwrap();
        assert_eq!(state, "approved");
        let dest = orblx_identity::Ipv4Destination {
            addr: "100.64.0.2".parse().unwrap(),
            proto: 6,
            port: 22,
        };
        assert!(coord
            .issue_agent_material(
                &SpiffeId::agent("bot").unwrap(),
                "a",
                now,
                Duration::from_secs(30),
                dest,
                &orblx_identity::DenySet::empty(),
            )
            .is_err());
        assert_eq!(tally(&scratch.0), (1, 1, 0));
    }

    fn posture_file(dir: &Path) -> String {
        fs::read_to_string(dir.join("posture.json")).unwrap_or_default()
    }

    fn posture_node_count(text: &str) -> usize {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        value["nodes"]
            .as_object()
            .map(|nodes| nodes.len())
            .unwrap_or(0)
    }

    fn fact(text: &str, name: &str, key: &str) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        value["nodes"][name][key].as_str().map(str::to_string)
    }

    #[test]
    fn an_unauthenticated_report_changes_nothing_and_writes_no_restore() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), now).is_some());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        coord
            .stage_posture("a", Some("windows"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        let before = posture_file(&scratch.0);
        assert!(coord
            .enroll_token_reported(
                "a",
                "not-a-token",
                &["a:443".to_string()],
                &[],
                now,
                Some("linux"),
                Some("0.1.0"),
            )
            .is_err());
        assert!(coord
            .enroll_token_reported(
                "intruder",
                "not-a-token",
                &["intruder:443".to_string()],
                &[],
                now,
                Some("linux"),
                Some("0.1.0"),
            )
            .is_err());
        assert_eq!(posture_file(&scratch.0), before);
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        assert!(!posture_file(&scratch.0).contains("intruder"));
    }

    #[test]
    fn a_report_for_another_node_is_refused() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), now).is_some());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        coord
            .stage_posture("a", Some("windows"), Some("0.1.0"), now)
            .unwrap();
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        let before = posture_file(&scratch.0);
        let err = coord
            .accept_peer_posture("b", "a", Some("linux"), Some("9.9.9"), now)
            .unwrap_err();
        assert!(matches!(err, crate::error::CoordError::Peer));
        assert_eq!(posture_file(&scratch.0), before);
        assert_eq!(fact(&before, "a", "os").as_deref(), Some("windows"));
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
    }

    #[test]
    fn junk_names_do_not_consume_posture_capacity() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), now).is_some());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        let before = posture_file(&scratch.0);
        assert_eq!(posture_node_count(&before), 2);
        for index in 0..5000 {
            let name = format!("n{index}");
            assert!(coord
                .stage_posture(&name, Some("linux"), Some("0.1.0"), now)
                .is_err());
            assert!(coord
                .accept_peer_posture("a", &name, Some("linux"), Some("0.1.0"), now)
                .is_err());
        }
        assert_eq!(posture_file(&scratch.0), before);
        assert_eq!(posture_node_count(&posture_file(&scratch.0)), 2);
    }

    #[test]
    fn an_omitted_os_or_version_clears_the_stored_fact() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = open(&scratch.0, DESK);
        assert!(enroll(&coord, "a", Some("linux"), Some("0.1.0"), now).is_some());
        assert!(enroll(&coord, "b", Some("linux"), Some("0.1.0"), now).is_some());
        coord.stage_posture("a", None, Some("0.1.0"), now).unwrap();
        let cleared = posture_file(&scratch.0);
        assert!(fact(&cleared, "a", "os").is_none());
        assert_eq!(
            fact(&cleared, "a", "client_version").as_deref(),
            Some("0.1.0")
        );
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        assert_eq!(grants_on(&coord, "b"), 0);
        coord.stage_posture("a", Some("linux"), None, now).unwrap();
        let version = posture_file(&scratch.0);
        assert_eq!(fact(&version, "a", "os").as_deref(), Some("linux"));
        assert!(fact(&version, "a", "client_version").is_none());
        coord.reconcile_posture(now).unwrap();
        assert_eq!(tally(&scratch.0), (0, 1, 0));
        assert!(coord.renew_node("a", now).unwrap().ticket.is_none());
    }

    fn nonce_count(text: &str) -> Vec<String> {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        value["revoked_ticket_nonces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect()
    }
}
