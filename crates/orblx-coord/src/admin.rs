//! Admin reads and writes for the owner SVID.
//!
//! The coordinator checks the caller SVID against the policy owner list.
//! Approve puts a node into netmaps and grants.
//! Revoke adds the node SVID to the deny set.
//! Expire removes the node from netmaps until the next approve.
//! Revoke-all stops all access of one principal with one deny change and one
//! audit record: the SVID, the agent grants, SSH, and file send.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use orblx_audit::{sha256_digest, verify_config_jsonl, ConfigAction, EMPTY_DIGEST};
use orblx_identity::{DenySet, SpiffeId, WorkloadKind};
use serde_json::{json, Value};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::state::Coordinator;

const DENY_FILE: &str = "deny.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct DenyFile {
    version: u64,
    generated_at: u64,
    revoked_uris: Vec<String>,
    revoked_ticket_nonces: Vec<String>,
}

impl DenyFile {
    fn empty(now: SystemTime) -> Self {
        Self {
            version: 0,
            generated_at: unix_now(now).unwrap_or(0),
            revoked_uris: Vec::new(),
            revoked_ticket_nonces: Vec::new(),
        }
    }

    fn to_json(&self) -> Result<String, CoordError> {
        serde_json::to_string(self).map_err(|_| CoordError::State)
    }
}

pub fn deny_json(coord: &Coordinator, now: SystemTime) -> Result<String, CoordError> {
    let file = read_deny(coord, now)?;
    file.to_json()
}

/// Return the deny list for one node (W25-1).
///
/// The list is the global deny list plus the nodes that this node does not see.
/// A guest node does not see the other nodes of the owner, and the owner nodes do not see it.
/// The version is the global version plus the config record count.
/// Each change that can change the hidden nodes writes a config record, so the version grows.
pub fn deny_json_for(
    coord: &Coordinator,
    name: &str,
    now: SystemTime,
) -> Result<String, CoordError> {
    let mut file = read_deny(coord, now)?;
    let (hidden, count) = coord.share_deny_for(name)?;
    file.version = file.version.saturating_add(count);
    for uri in hidden {
        if !file.revoked_uris.contains(&uri) {
            file.revoked_uris.push(uri);
        }
    }
    file.to_json()
}

/// Return the ETag of one deny list text (W25-2).
///
/// The ETag is the SHA-256 of the list with `generated_at` set to 0, in hex.
/// A list with no file has the time of the call in `generated_at`, so the time is not in the ETag.
pub fn deny_etag(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::from_str::<DenyFile>(text)
        .ok()
        .and_then(|mut file| {
            file.generated_at = 0;
            file.to_json().ok()
        })
        .unwrap_or_else(|| text.to_string());
    Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn deny_set(coord: &Coordinator, now: SystemTime) -> Result<DenySet, CoordError> {
    let text = deny_json(coord, now)?;
    let mut deny = DenySet::empty();
    let _ = deny
        .apply_json(text.as_bytes())
        .map_err(|_| CoordError::State)?;
    Ok(deny)
}

pub fn approve(coord: &Coordinator, name: &str, actor: &str) -> Result<Value, CoordError> {
    let _ = SpiffeId::node(name)?;
    coord.approve_node_by(name, actor)?;
    Ok(json!({
        "op": "approve",
        "name": name,
        "approved": true
    }))
}

pub fn expire(coord: &Coordinator, name: &str, actor: &str) -> Result<Value, CoordError> {
    let _ = SpiffeId::node(name)?;
    coord.expire_node_by(name, actor)?;
    Ok(json!({
        "op": "expire",
        "name": name,
        "expired": true
    }))
}

pub fn revoke(
    coord: &Coordinator,
    name: &str,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    let _ = SpiffeId::node(name)?;
    let nodes = coord.node_list()?;
    let node = nodes
        .iter()
        .find(|node| node.name == name)
        .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
    let before = deny_digest(coord)?;
    let version = push_revoke(coord, &node.svid, now)?;
    let after = deny_digest(coord)?;
    coord.record_change(
        actor,
        ConfigAction::Revoke,
        name,
        before,
        after,
        &format!("svid {} deny_version {version}", node.svid),
    )?;
    Ok(json!({
        "op": "revoke",
        "name": name,
        "svid": node.svid,
        "deny_version": version
    }))
}

/// Revoke all access of one principal (W24-D).
///
/// `principal` is a node name or a SPIFFE URI of a node, a user, or an agent.
/// The call adds the principal URI and the ticket nonce of each issued grant of
/// the principal to the deny file in one deny version. It marks the grants of
/// the principal revoked. It writes one `revoke` audit record with `scope all`.
/// SSH servers and file receivers check the sender SVID against the deny file,
/// so the URI entry stops SSH and file send. The coordinator refuses the SVID.
pub fn revoke_all(
    coord: &Coordinator,
    principal: &str,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    let id = principal_id(coord, principal)?;
    if id.as_uri() == actor {
        return Err(CoordError::Protocol(
            "The caller cannot revoke its own SVID.".to_string(),
        ));
    }
    let before = deny_digest(coord)?;
    let done = crate::agent::revoke_principal(coord, &id, now)?;
    let after = deny_digest(coord)?;
    let detail = format!(
        "principal {} scope all svid denied grants {} nonces {} deny_version {}",
        id.as_uri(),
        done.grants.len(),
        done.nonces,
        done.deny_version
    );
    coord.record_change(
        actor,
        ConfigAction::Revoke,
        id.as_uri(),
        before,
        after,
        &detail,
    )?;
    Ok(json!({
        "op": "revoke-all",
        "principal": id.as_uri(),
        "scope": "all",
        "svid_denied": true,
        "grants": done.grants,
        "nonces": done.nonces,
        "deny_version": done.deny_version
    }))
}

/// Undo the SVID deny of one principal (W25-2).
///
/// The call removes the principal URI from the deny file in one new deny version.
/// It writes one `unrevoke` audit record. The grants that a revoke-all marked
/// revoked stay revoked, and their ticket nonces stay denied. The owner issues
/// new grants when the principal needs them again.
pub fn revoke_undo(
    coord: &Coordinator,
    principal: &str,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    let id = principal_id(coord, principal)?;
    let uri = id.as_uri().to_string();
    let mut file = read_deny(coord, now)?;
    if !file.revoked_uris.contains(&uri) {
        return Err(CoordError::Protocol(
            "The principal is not in the deny list.".to_string(),
        ));
    }
    let before = deny_digest(coord)?;
    file.revoked_uris.retain(|item| *item != uri);
    file.version = file.version.saturating_add(1);
    file.generated_at = unix_now(now)?;
    let text = file.to_json()?;
    write_text(&coord.state_dir()?.join(DENY_FILE), &text, 0o644)?;
    let after = deny_digest(coord)?;
    let detail = format!(
        "principal {uri} scope all svid restored deny_version {}",
        file.version
    );
    coord.record_change(actor, ConfigAction::Unrevoke, &uri, before, after, &detail)?;
    Ok(json!({
        "op": "revoke-undo",
        "principal": uri,
        "svid_restored": true,
        "deny_version": file.version
    }))
}

/// Read a node name or a SPIFFE URI. A node must be enrolled.
fn principal_id(coord: &Coordinator, principal: &str) -> Result<SpiffeId, CoordError> {
    let bad = || CoordError::Protocol("The principal is not valid.".to_string());
    let id = if principal.starts_with("spiffe://") {
        SpiffeId::parse(principal).map_err(|_| bad())?
    } else {
        SpiffeId::node(principal).map_err(|_| bad())?
    };
    match id.kind() {
        WorkloadKind::Node => {
            let nodes = coord.node_list()?;
            if !nodes.iter().any(|node| node.name == id.name()) {
                return Err(CoordError::Protocol(
                    "The node is not enrolled.".to_string(),
                ));
            }
        }
        WorkloadKind::User | WorkloadKind::Agent => {}
        WorkloadKind::Coord => return Err(bad()),
    }
    Ok(id)
}

pub fn nodes(coord: &Coordinator) -> Result<Value, CoordError> {
    let list = coord.node_list()?;
    let nodes: Vec<Value> = list
        .iter()
        .map(|node| {
            json!({
                "name": node.name,
                "overlay_ip": node.overlay_ip,
                "svid": node.svid,
                "owner": node.owner,
                "approved": node.approved && !node.expired,
                "expired": node.expired,
                "pending": !node.approved && !node.expired
            })
        })
        .collect();
    Ok(json!({"op": "nodes", "nodes": nodes}))
}

pub fn users(coord: &Coordinator) -> Result<Value, CoordError> {
    let list = coord.node_list()?;
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for node in list {
        let Some(subject) = node.owner.strip_prefix("oidc:") else {
            continue;
        };
        if subject.is_empty() {
            continue;
        }
        groups
            .entry(subject.to_string())
            .or_default()
            .push(node.name);
    }
    let users: Vec<Value> = groups
        .into_iter()
        .map(|(subject, nodes)| json!({"subject": subject, "nodes": nodes}))
        .collect();
    Ok(json!({"op": "users", "users": users}))
}

pub fn routes(coord: &Coordinator) -> Result<Value, CoordError> {
    Ok(json!({"op": "routes", "nodes": coord.route_report()?}))
}

/// Return config chain records and the chain check result.
///
/// `since` is Unix seconds. The list holds records at or after that time.
/// The check always covers the full chain.
pub fn audit(coord: &Coordinator, since: Option<u64>) -> Result<Value, CoordError> {
    let text = coord.config_audit_text()?;
    let verify = match verify_config_jsonl(&text) {
        Ok(checked) => json!({
            "ok": true,
            "records": checked.records.len(),
            "tip": checked.tip_hex()
        }),
        Err(err) => json!({"ok": false, "error": err.to_string()}),
    };
    let mut lines = Vec::new();
    for raw in text.split('\n') {
        if raw.trim().is_empty() {
            continue;
        }
        let keep = match (since, serde_json::from_str::<Value>(raw)) {
            (None, _) => true,
            (Some(limit), Ok(value)) => value
                .get("at_unix")
                .and_then(Value::as_u64)
                .is_none_or(|at| at >= limit),
            (Some(_), Err(_)) => true,
        };
        if keep {
            lines.push(raw.to_string());
        }
    }
    let mut total = 0usize;
    let mut kept = Vec::new();
    for line in lines.into_iter().rev() {
        total = total.saturating_add(line.len() + 1);
        if total > AUDIT_REPLY_LIMIT {
            break;
        }
        kept.push(line);
    }
    kept.reverse();
    Ok(json!({"op": "audit", "verify": verify, "lines": kept}))
}

/// Return the policy file text and its SHA-256 (W25-3, scope `policy:read`).
pub fn policy_show(coord: &Coordinator) -> Result<Value, CoordError> {
    let path = coord.policy_file()?;
    if !path.exists() {
        return Ok(json!({"op": "policy", "present": false}));
    }
    let text = read_text(&path)?;
    if text.len() > POLICY_REPLY_LIMIT {
        return Err(CoordError::Protocol(
            "The policy file is too large for one reply.".to_string(),
        ));
    }
    Ok(json!({
        "op": "policy",
        "present": true,
        "sha256": crate::netmap::encode_hex(&sha256_digest(text.as_bytes())),
        "text": text
    }))
}

static POLICY_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Proof that the caller holds the policy write lock (W25-3b).
///
/// A token caller checks the owner list and writes the policy with the same lock.
/// So an owner change between the check and the write cannot be lost.
pub struct PolicyWrite(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Take the policy write lock.
pub fn policy_write_lock() -> Result<PolicyWrite, CoordError> {
    POLICY_WRITE_LOCK
        .lock()
        .map(PolicyWrite)
        .map_err(|_| CoordError::State)
}

/// Return true when the policy text has the same owner set as the loaded policy.
///
/// A text that is not a valid policy returns true. `policy_set` refuses it later.
pub fn policy_keeps_owners(
    coord: &Coordinator,
    _lock: &PolicyWrite,
    text: &str,
) -> Result<bool, CoordError> {
    let Ok(next) = orblx_identity::Policy::from_hujson(text.as_bytes()) else {
        return Ok(true);
    };
    let mut now: Vec<String> = coord
        .policy_owners()?
        .iter()
        .map(|id| id.as_uri().to_string())
        .collect();
    let mut want: Vec<String> = next
        .owners()
        .iter()
        .map(|id| id.as_uri().to_string())
        .collect();
    now.sort();
    want.sort();
    Ok(now == want)
}

/// Replace the policy file (W25-3, scope `policy:write`).
///
/// The coordinator checks the text first. A bad text does not change the file.
/// The coordinator then loads the file and writes one `policy-replace` record.
/// The caller holds the policy write lock.
///
/// W25-9: when `expect` is given, the call writes only when the live policy sha256
/// is `expect` (`none`: no policy file). Otherwise it returns `CoordError::Conflict`.
/// When the text is the same as the live policy, the call does not write and
/// returns `"changed": false`. Then no new policy record is written.
pub fn policy_set(
    coord: &Coordinator,
    _lock: &PolicyWrite,
    text: &str,
    expect: Option<&str>,
) -> Result<Value, CoordError> {
    if orblx_identity::Policy::from_hujson(text.as_bytes()).is_err() {
        return Err(CoordError::Protocol("The policy is not valid.".to_string()));
    }
    let path = coord.policy_file()?;
    let live = if path.exists() {
        crate::netmap::encode_hex(&sha256_digest(read_text(&path)?.as_bytes()))
    } else {
        "none".to_string()
    };
    let sha = crate::netmap::encode_hex(&sha256_digest(text.as_bytes()));
    if expect.is_some_and(|want| want != live) {
        return Err(CoordError::Conflict);
    }
    if live == sha {
        return Ok(json!({"op": "policy-set", "sha256": sha, "changed": false}));
    }
    write_text(&path, text, 0o644)?;
    coord.set_policy_file(&path)?;
    Ok(json!({"op": "policy-set", "sha256": sha, "changed": true}))
}

/// The largest policy text in one admin reply.
const POLICY_REPLY_LIMIT: usize = 160 * 1024;

/// The largest record text in one admin reply.
const AUDIT_REPLY_LIMIT: usize = 160 * 1024;

pub(crate) fn deny_digest(coord: &Coordinator) -> Result<[u8; 32], CoordError> {
    let path = coord.state_dir()?.join(DENY_FILE);
    if !path.exists() {
        return Ok(EMPTY_DIGEST);
    }
    let text = read_text(&path)?;
    Ok(sha256_digest(text.as_bytes()))
}

fn push_revoke(coord: &Coordinator, svid: &str, now: SystemTime) -> Result<u64, CoordError> {
    push_deny(coord, &[svid.to_string()], &[], now)
}

/// Add SPIFFE IDs and ticket nonces to the deny file.
///
/// The function raises the deny version by one.
pub(crate) fn push_deny(
    coord: &Coordinator,
    uris: &[String],
    nonces: &[String],
    now: SystemTime,
) -> Result<u64, CoordError> {
    let mut file = read_deny(coord, now)?;
    for uri in uris {
        let _ = SpiffeId::parse(uri)?;
        if !file.revoked_uris.iter().any(|item| item == uri) {
            file.revoked_uris.push(uri.clone());
        }
    }
    for nonce in nonces {
        if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CoordError::State);
        }
        if !file.revoked_ticket_nonces.iter().any(|item| item == nonce) {
            file.revoked_ticket_nonces.push(nonce.clone());
        }
    }
    file.revoked_uris.sort();
    file.revoked_ticket_nonces.sort();
    file.version = file.version.saturating_add(1);
    file.generated_at = unix_now(now)?;
    let text = file.to_json()?;
    write_text(&coord.state_dir()?.join(DENY_FILE), &text, 0o644)?;
    Ok(file.version)
}

fn read_deny(coord: &Coordinator, now: SystemTime) -> Result<DenyFile, CoordError> {
    let path = coord.state_dir()?.join(DENY_FILE);
    if !path.exists() {
        return Ok(DenyFile::empty(now));
    }
    let text = read_text(&path)?;
    serde_json::from_str(&text).map_err(|_| CoordError::State)
}

fn unix_now(now: SystemTime) -> Result<u64, CoordError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoordError::Time)
}
