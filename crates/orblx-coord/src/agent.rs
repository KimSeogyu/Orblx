//! Agent JIT grants on the coordinator.
//!
//! A node asks for a grant for one agent, one target node, one service,
//! one TCP port, and a life of 5 minutes or less. The grant stays pending.
//! An owner approves it with the admin API. The policy does not approve
//! agent grants. The requesting node then fetches the material one time.
//! The fetch issues the agent SVID and the agent JIT ticket. The life starts
//! at the fetch. The coordinator does not store the agent key.
//! Revoke adds the ticket nonce of that one grant to the deny file.
//! Other grants for the same agent name stay valid.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_agent::{
    grant_id_ok, path_prefix_ok, service_name_ok, AgentGrant, SignedAgentGrant, GRANT_VERSION,
    MAX_GRANT_SECS,
};
use orblx_audit::{sha256_digest, ConfigAction, EMPTY_DIGEST};
use orblx_identity::{Ipv4Destination, SpiffeId, WorkloadKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::admin::{deny_digest, deny_set, push_deny};
use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::netmap::encode_hex;
use crate::proto::GrantAsk;
use crate::state::{AgentMaterial, Coordinator};

const GRANT_FILE: &str = "agent-grants.json";
static GRANT_LOCK: Mutex<()> = Mutex::new(());

const PENDING: &str = "pending";
const APPROVED: &str = "approved";
const ISSUED: &str = "issued";
const REVOKED: &str = "revoked";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GrantRecord {
    id: String,
    agent: String,
    requester: String,
    node: String,
    service: String,
    port: u16,
    path_prefix: String,
    ttl_secs: u64,
    requested_at: u64,
    state: String,
    #[serde(default)]
    approver: Option<String>,
    #[serde(default)]
    expires: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    ticket_hash: Option<String>,
    #[serde(default)]
    expire_logged: bool,
}

impl GrantRecord {
    fn agent_uri(&self) -> Result<String, CoordError> {
        Ok(SpiffeId::agent(&self.agent)?.as_uri().to_string())
    }

    fn view(&self, now: u64) -> Value {
        let state = match (self.state.as_str(), self.expires) {
            (ISSUED, Some(expires)) if now >= expires => "expired",
            (other, _) => other,
        };
        json!({
            "id": self.id,
            "agent": self.agent,
            "requester": self.requester,
            "node": self.node,
            "service": self.service,
            "port": self.port,
            "path_prefix": self.path_prefix,
            "ttl_secs": self.ttl_secs,
            "state": state,
            "approver": self.approver,
            "expires": self.expires,
            "ticket_hash": self.ticket_hash,
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct GrantFile {
    grants: Vec<GrantRecord>,
}

/// The result of one fetch call.
pub(crate) enum Fetched {
    /// The grant waits for an owner.
    Pending(Value),
    /// The grant material. The caller must not log it.
    Issued(Box<(AgentMaterial, SignedAgentGrant)>),
}

fn grant_path(coord: &Coordinator) -> Result<PathBuf, CoordError> {
    Ok(coord.state_dir()?.join(GRANT_FILE))
}

fn load(coord: &Coordinator) -> Result<GrantFile, CoordError> {
    let path = grant_path(coord)?;
    if !path.exists() {
        return Ok(GrantFile::default());
    }
    let text = read_text(&path)?;
    serde_json::from_str(&text).map_err(|_| CoordError::State)
}

fn save(coord: &Coordinator, file: &GrantFile) -> Result<(), CoordError> {
    let text = serde_json::to_string(file).map_err(|_| CoordError::State)?;
    write_text(&grant_path(coord)?, &text, 0o600)
}

fn unix_now(now: SystemTime) -> Result<u64, CoordError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoordError::Time)
}

fn bad(text: &str) -> CoordError {
    CoordError::Protocol(text.to_string())
}

fn record_digest(record: &GrantRecord) -> [u8; 32] {
    serde_json::to_vec(record).map_or(EMPTY_DIGEST, |bytes| sha256_digest(&bytes))
}

/// Store one pending grant for `requester`.
pub(crate) fn request(
    coord: &Coordinator,
    requester: &str,
    ask: &GrantAsk,
    now: SystemTime,
) -> Result<Value, CoordError> {
    let _ = SpiffeId::agent(&ask.agent).map_err(|_| bad("The agent name is not valid."))?;
    let _ = SpiffeId::node(&ask.node).map_err(|_| bad("The target node name is not valid."))?;
    if !service_name_ok(&ask.service) {
        return Err(bad("The service name is not valid."));
    }
    if ask.port == 0 {
        return Err(bad("The port is not valid."));
    }
    if ask.ttl_secs == 0 || ask.ttl_secs > MAX_GRANT_SECS {
        return Err(bad("The grant life must be 1 to 300 seconds."));
    }
    let path_prefix = ask.path_prefix.clone().unwrap_or_else(|| "/".to_string());
    if !path_prefix_ok(&path_prefix) {
        return Err(bad("The path prefix is not valid."));
    }
    let nodes = coord.node_list()?;
    let target = nodes
        .iter()
        .find(|node| node.name == ask.node)
        .ok_or_else(|| bad("The target node is not enrolled."))?;
    if !target.approved || target.expired {
        return Err(bad("The target node is not approved."));
    }
    let mut raw = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    let record = GrantRecord {
        id: encode_hex(&raw),
        agent: ask.agent.clone(),
        requester: requester.to_string(),
        node: ask.node.clone(),
        service: ask.service.clone(),
        port: ask.port,
        path_prefix,
        ttl_secs: ask.ttl_secs,
        requested_at: unix_now(now)?,
        state: PENDING.to_string(),
        approver: None,
        expires: None,
        nonce: None,
        ticket_hash: None,
        expire_logged: false,
    };
    let _guard = GRANT_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = load(coord)?;
    file.grants.push(record.clone());
    save(coord, &file)?;
    let actor = SpiffeId::node(requester)?.as_uri().to_string();
    coord.record_change(
        &actor,
        ConfigAction::AgentGrant,
        &record.id,
        EMPTY_DIGEST,
        record_digest(&record),
        &format!(
            "agent {} node {} service {} port {} path {} ttl {} pending",
            record.agent,
            record.node,
            record.service,
            record.port,
            record.path_prefix,
            record.ttl_secs
        ),
    )?;
    Ok(json!({"op": "agent-grant", "id": record.id, "state": PENDING, "agent": record.agent}))
}

/// Return the material of one approved grant one time.
pub(crate) fn fetch(
    coord: &Coordinator,
    requester: &str,
    id: &str,
    now: SystemTime,
) -> Result<Fetched, CoordError> {
    if !grant_id_ok(id) {
        return Err(bad("The grant id is not valid."));
    }
    let _guard = GRANT_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = load(coord)?;
    let index = file
        .grants
        .iter()
        .position(|record| record.id == id && record.requester == requester)
        .ok_or_else(|| bad("The grant is not known."))?;
    let now_unix = unix_now(now)?;
    let record = file.grants[index].clone();
    match record.state.as_str() {
        PENDING => {
            return Ok(Fetched::Pending(
                json!({"op": "agent-grant-fetch", "id": id, "state": PENDING}),
            ))
        }
        APPROVED => {}
        ISSUED => return Err(bad("The grant material was already delivered.")),
        _ => return Err(bad("The grant is revoked.")),
    }
    let nodes = coord.node_list()?;
    let target = nodes
        .iter()
        .find(|node| node.name == record.node)
        .ok_or_else(|| bad("The target node is not enrolled."))?;
    let addr: std::net::Ipv4Addr = target
        .overlay_ip
        .parse()
        .map_err(|_| bad("The target address is not valid."))?;
    let agent = SpiffeId::agent(&record.agent)?;
    let ttl = Duration::from_secs(record.ttl_secs);
    let deny = deny_set(coord, now)?;
    let dest = Ipv4Destination {
        addr,
        proto: 6,
        port: record.port,
    };
    let material = coord.issue_agent_material(&agent, now, ttl, dest, &deny)?;
    let expires = now_unix.saturating_add(record.ttl_secs);
    let grant = AgentGrant {
        version: GRANT_VERSION,
        id: record.id.clone(),
        agent: agent.as_uri().to_string(),
        requester: SpiffeId::node(&record.requester)?.as_uri().to_string(),
        approver: record.approver.clone().unwrap_or_default(),
        node: SpiffeId::node(&record.node)?.as_uri().to_string(),
        addr: addr.to_string(),
        service: record.service.clone(),
        port: record.port,
        path_prefix: record.path_prefix.clone(),
        not_before: now_unix,
        expires,
        ticket_hash: encode_hex(&material.ticket.hash),
    };
    let signed = coord.sign_agent_grant(&grant)?;
    let before = record_digest(&record);
    let updated = &mut file.grants[index];
    updated.state = ISSUED.to_string();
    updated.expires = Some(expires);
    updated.nonce = Some(encode_hex(&material.ticket.nonce));
    updated.ticket_hash = Some(grant.ticket_hash.clone());
    let after = record_digest(updated);
    save(coord, &file)?;
    coord.record_change(
        &grant.requester,
        ConfigAction::AgentGrant,
        id,
        before,
        after,
        &format!(
            "issued agent {} not_before {} expires {} ticket_hash {}",
            grant.agent, grant.not_before, grant.expires, grant.ticket_hash
        ),
    )?;
    Ok(Fetched::Issued(Box::new((material, signed))))
}

/// Record each new grant expiry in the config chain.
///
/// The coordinator tick calls this each 500 ms. `list` also calls it.
/// The detail holds the end time and the time of the record in Unix ms.
pub(crate) fn expire_due(coord: &Coordinator, now: SystemTime) -> Result<usize, CoordError> {
    let _guard = GRANT_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = load(coord)?;
    let count = expire_locked(coord, &mut file, now)?;
    if count > 0 {
        save(coord, &file)?;
    }
    Ok(count)
}

fn expire_locked(
    coord: &Coordinator,
    file: &mut GrantFile,
    now: SystemTime,
) -> Result<usize, CoordError> {
    let now_unix = unix_now(now)?;
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoordError::State)?
        .as_millis();
    let mut count = 0;
    for record in &mut file.grants {
        let ended = record.state == ISSUED
            && record.expires.is_some_and(|expires| now_unix >= expires)
            && !record.expire_logged;
        if ended {
            let actor = coord.coord_actor()?;
            record.expire_logged = true;
            count += 1;
            let expires = record.expires.unwrap_or(0);
            coord.record_change(
                &actor,
                ConfigAction::AgentExpire,
                &record.id,
                EMPTY_DIGEST,
                EMPTY_DIGEST,
                &format!("expires {expires} seen_ms {now_ms}"),
            )?;
            println!(
                "coord agent grant {} expired expires {expires} seen_ms {now_ms}",
                record.id
            );
        }
    }
    Ok(count)
}

/// List grants. The call also records each new expiry in the config chain.
pub(crate) fn list(coord: &Coordinator, now: SystemTime) -> Result<Value, CoordError> {
    let now_unix = unix_now(now)?;
    let _guard = GRANT_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = load(coord)?;
    if expire_locked(coord, &mut file, now)? > 0 {
        save(coord, &file)?;
    }
    let grants: Vec<Value> = file
        .grants
        .iter()
        .map(|record| record.view(now_unix))
        .collect();
    Ok(json!({"op": "grants", "grants": grants}))
}

/// Approve one pending grant.
pub(crate) fn approve(
    coord: &Coordinator,
    id: &str,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    if !grant_id_ok(id) {
        return Err(bad("The grant id is not valid."));
    }
    let _guard = GRANT_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = load(coord)?;
    let record = file
        .grants
        .iter_mut()
        .find(|record| record.id == id)
        .ok_or_else(|| bad("The grant is not known."))?;
    if record.state != PENDING {
        return Err(bad("The grant is not pending."));
    }
    let before = record_digest(record);
    record.state = APPROVED.to_string();
    record.approver = Some(actor.to_string());
    let after = record_digest(record);
    let view = record.view(unix_now(now)?);
    let detail = format!(
        "agent {} node {} service {} port {} ttl {}",
        record.agent, record.node, record.service, record.port, record.ttl_secs
    );
    save(coord, &file)?;
    coord.record_change(
        actor,
        ConfigAction::AgentApprove,
        id,
        before,
        after,
        &detail,
    )?;
    Ok(json!({"op": "grant-approve", "grant": view}))
}

/// Revoke one grant.
///
/// An issued grant puts its ticket nonce in the deny file. The agent SVID
/// does not go in the deny file, so other grants for the same agent name
/// stay valid. Each grant has its own random ticket nonce.
pub(crate) fn revoke(
    coord: &Coordinator,
    id: &str,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    if !grant_id_ok(id) {
        return Err(bad("The grant id is not valid."));
    }
    let _guard = GRANT_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = load(coord)?;
    let record = file
        .grants
        .iter_mut()
        .find(|record| record.id == id)
        .ok_or_else(|| bad("The grant is not known."))?;
    if record.state == REVOKED {
        return Err(bad("The grant is already revoked."));
    }
    let issued = record.state == ISSUED;
    record.state = REVOKED.to_string();
    let uri = record.agent_uri()?;
    let nonce = record.nonce.clone();
    let view = record.view(unix_now(now)?);
    save(coord, &file)?;
    let before = deny_digest(coord)?;
    let version = if issued {
        let nonces: Vec<String> = nonce.into_iter().collect();
        if nonces.is_empty() {
            // An issued grant always has a ticket nonce.
            return Err(CoordError::State);
        }
        Some(push_deny(coord, &[], &nonces, now)?)
    } else {
        None
    };
    let after = deny_digest(coord)?;
    let detail = match version {
        Some(version) => format!("agent {uri} scope grant deny_version {version}"),
        None => format!("agent {uri} not issued"),
    };
    coord.record_change(actor, ConfigAction::AgentRevoke, id, before, after, &detail)?;
    Ok(json!({"op": "grant-revoke", "grant": view, "deny_version": version}))
}

/// The result of one revoke-all call for the grants.
pub(crate) struct PrincipalRevoke {
    /// The grant IDs that changed to revoked.
    pub(crate) grants: Vec<String>,
    /// The number of ticket nonces that went into the deny file.
    pub(crate) nonces: usize,
    /// The deny file version after the call.
    pub(crate) deny_version: u64,
}

/// Revoke all grants of one principal and deny the principal SPIFFE ID.
///
/// A node principal owns the grants that it requested. An agent principal owns
/// the grants for its agent name. A user principal owns no grants.
/// The function writes the deny file one time: the principal URI and the
/// ticket nonce of each issued grant. Then it marks the grants revoked.
/// The deny file changes first, so a failure after that leaves the access denied.
/// The function writes no audit record. The caller writes one record.
pub(crate) fn revoke_principal(
    coord: &Coordinator,
    principal: &SpiffeId,
    now: SystemTime,
) -> Result<PrincipalRevoke, CoordError> {
    let _guard = GRANT_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = load(coord)?;
    let owned = |record: &GrantRecord| match principal.kind() {
        WorkloadKind::Node => record.requester == principal.name(),
        WorkloadKind::Agent => record.agent == principal.name(),
        WorkloadKind::User | WorkloadKind::Coord => false,
    };
    let mut ids = Vec::new();
    let mut nonces = Vec::new();
    for record in file.grants.iter().filter(|record| owned(record)) {
        if record.state == REVOKED {
            continue;
        }
        if record.state == ISSUED {
            // An issued grant always has a ticket nonce.
            let nonce = record.nonce.clone().ok_or(CoordError::State)?;
            nonces.push(nonce);
        }
        ids.push(record.id.clone());
    }
    let deny_version = push_deny(coord, &[principal.as_uri().to_string()], &nonces, now)?;
    for record in file.grants.iter_mut() {
        if ids.contains(&record.id) {
            record.state = REVOKED.to_string();
        }
    }
    if !ids.is_empty() {
        save(coord, &file)?;
    }
    Ok(PrincipalRevoke {
        grants: ids,
        nonces: nonces.len(),
        deny_version,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    use orblx_identity::SpiffeId;
    use serde_json::Value;

    use super::{approve, expire_due, fetch, list, request, revoke, Fetched};
    use crate::proto::GrantAsk;
    use crate::{Coordinator, OidcConfig};

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        let mut raw = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
        let path =
            std::env::temp_dir().join(format!("orblx-agent-coord-{}", super::encode_hex(&raw)));
        fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    fn ask(port: u16, ttl: u64) -> GrantAsk {
        GrantAsk {
            agent: "bot".to_string(),
            node: "b".to_string(),
            service: "web".to_string(),
            port,
            ttl_secs: ttl,
            path_prefix: None,
        }
    }

    #[test]
    fn a_grant_goes_from_request_to_revoke() {
        let dir = scratch();
        let now = SystemTime::now();
        let coord = Coordinator::open(&dir.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        for name in ["a", "b"] {
            let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
            coord
                .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
                .unwrap();
        }
        assert!(request(&coord, "a", &ask(8080, 301), now).is_err());
        assert!(request(&coord, "a", &ask(0, 30), now).is_err());
        let reply = request(&coord, "a", &ask(8080, 30), now).unwrap();
        let id = reply["id"].as_str().unwrap().to_string();
        assert_eq!(reply["state"], "pending");
        assert!(matches!(
            fetch(&coord, "a", &id, now).unwrap(),
            Fetched::Pending(_)
        ));
        // Only the requester can fetch.
        assert!(fetch(&coord, "b", &id, now).is_err());
        let owner = SpiffeId::node("owner").unwrap();
        approve(&coord, &id, owner.as_uri(), now).unwrap();
        let Fetched::Issued(issued) = fetch(&coord, "a", &id, now).unwrap() else {
            panic!("the grant was not issued");
        };
        let (material, signed) = *issued;
        assert_eq!(signed.grant.port, 8080);
        assert_eq!(signed.grant.service, "web");
        assert_eq!(signed.grant.approver, owner.as_uri());
        assert_eq!(signed.grant.expires - signed.grant.not_before, 30);
        assert!(material.private_key_pem.contains("PRIVATE KEY"));
        // The material is delivered one time.
        assert!(fetch(&coord, "a", &id, now).is_err());
        let store = fs::read_to_string(dir.0.join("agent-grants.json")).unwrap();
        assert!(!store.contains("PRIVATE KEY"));
        let later = now + Duration::from_secs(31);
        // Before the end the tick records nothing.
        assert_eq!(
            expire_due(&coord, now + Duration::from_secs(29)).unwrap(),
            0
        );
        // The tick records the expiry without a list call, one time only.
        assert_eq!(expire_due(&coord, later).unwrap(), 1);
        assert_eq!(expire_due(&coord, later).unwrap(), 0);
        let listed = list(&coord, later).unwrap();
        assert_eq!(listed["grants"][0]["state"], "expired");
        let revoked = revoke(&coord, &id, owner.as_uri(), now).unwrap();
        assert!(revoked["deny_version"].as_u64().unwrap() >= 1);
        let text = crate::deny_json(&coord, now).unwrap();
        // A revoke denies the ticket nonce of this grant, not the agent name.
        assert!(!text.contains("spiffe://orblx.local/agent/bot"));
        assert!(text.contains(&hex_of(&material.ticket.nonce)));
        let audit = crate::audit(&coord, None).unwrap();
        assert_eq!(audit["verify"]["ok"], Value::Bool(true));
        let lines = audit["lines"].as_array().unwrap();
        let actions: Vec<String> = lines
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line.as_str()?).ok())
            .filter_map(|record| record["action"].as_str().map(str::to_string))
            .collect();
        for action in [
            "agent-grant",
            "agent-approve",
            "agent-expire",
            "agent-revoke",
        ] {
            assert!(actions.iter().any(|item| item == action), "no {action}");
        }
        // The list call after the tick does not add a second expire record.
        let expires = actions
            .iter()
            .filter(|item| *item == "agent-expire")
            .count();
        assert_eq!(expires, 1);
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn issue(coord: &Coordinator, owner: &SpiffeId, now: SystemTime) -> (String, String) {
        let reply = request(coord, "a", &ask(8080, 120), now).unwrap();
        let id = reply["id"].as_str().unwrap().to_string();
        approve(coord, &id, owner.as_uri(), now).unwrap();
        let Fetched::Issued(issued) = fetch(coord, "a", &id, now).unwrap() else {
            panic!("the grant was not issued");
        };
        (id, hex_of(&issued.0.ticket.nonce))
    }

    fn issue_for(
        coord: &Coordinator,
        requester: &str,
        owner: &SpiffeId,
        now: SystemTime,
    ) -> (String, String) {
        let reply = request(coord, requester, &ask(8080, 120), now).unwrap();
        let id = reply["id"].as_str().unwrap().to_string();
        approve(coord, &id, owner.as_uri(), now).unwrap();
        let Fetched::Issued(issued) = fetch(coord, requester, &id, now).unwrap() else {
            panic!("the grant was not issued");
        };
        (id, hex_of(&issued.0.ticket.nonce))
    }

    fn audit_actions(coord: &Coordinator) -> Vec<Value> {
        let audit = crate::audit(coord, None).unwrap();
        assert_eq!(audit["verify"]["ok"], Value::Bool(true));
        audit["lines"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line.as_str()?).ok())
            .collect()
    }

    #[test]
    fn revoke_all_stops_one_principal_with_one_record() {
        let dir = scratch();
        let now = SystemTime::now();
        let coord = Coordinator::open(&dir.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        for name in ["a", "b", "c"] {
            let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
            coord
                .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
                .unwrap();
        }
        let owner = SpiffeId::node("owner").unwrap();
        let (a1, a1_nonce) = issue_for(&coord, "a", &owner, now);
        let (a2, a2_nonce) = issue_for(&coord, "a", &owner, now);
        let pending = request(&coord, "a", &ask(8080, 60), now).unwrap();
        let pending = pending["id"].as_str().unwrap().to_string();
        let (c1, c1_nonce) = issue_for(&coord, "c", &owner, now);
        let records_before = audit_actions(&coord).len();

        let reply = crate::revoke_all(&coord, "a", owner.as_uri(), now).unwrap();
        assert_eq!(reply["principal"], "spiffe://orblx.local/node/a");
        assert_eq!(reply["scope"], "all");
        assert_eq!(reply["nonces"], 2);
        let mut revoked: Vec<String> = reply["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();
        revoked.sort();
        let mut want = vec![a1.clone(), a2.clone(), pending.clone()];
        want.sort();
        assert_eq!(revoked, want);

        // One deny change holds the SVID and both issued nonces of a.
        let deny = crate::deny_set(&coord, now).unwrap();
        assert!(deny.reject_uri(&SpiffeId::node("a").unwrap()).is_err());
        assert!(deny.reject_uri(&SpiffeId::node("c").unwrap()).is_ok());
        let text = crate::deny_json(&coord, now).unwrap();
        assert!(text.contains(&a1_nonce));
        assert!(text.contains(&a2_nonce));
        assert!(!text.contains(&c1_nonce));
        assert!(!text.contains("spiffe://orblx.local/agent/bot"));
        assert_eq!(reply["deny_version"], 1);

        // The grants of a are revoked. The grant of c stays issued.
        let listed = list(&coord, now).unwrap();
        for grant in listed["grants"].as_array().unwrap() {
            let id = grant["id"].as_str().unwrap();
            if id == c1 {
                assert_eq!(grant["state"], "issued");
            } else {
                assert_eq!(grant["state"], "revoked", "grant {id}");
            }
        }
        assert!(fetch(&coord, "a", &pending, now).is_err());

        // Exactly one audit record for the call.
        let records = audit_actions(&coord);
        assert_eq!(records.len(), records_before + 1);
        let last = records.last().unwrap();
        assert_eq!(last["action"], "revoke");
        assert_eq!(last["target"], "spiffe://orblx.local/node/a");
        let detail = last["detail"].as_str().unwrap();
        assert!(detail.contains("scope all"), "{detail}");
        assert!(detail.contains("grants 3 nonces 2"), "{detail}");

        // A second call adds no grant and keeps one URI entry.
        let again =
            crate::revoke_all(&coord, "spiffe://orblx.local/node/a", owner.as_uri(), now).unwrap();
        assert_eq!(again["grants"].as_array().unwrap().len(), 0);
        let text = crate::deny_json(&coord, now).unwrap();
        assert_eq!(text.matches("spiffe://orblx.local/node/a").count(), 1);
    }

    #[test]
    fn revoke_undo_restores_the_svid_with_one_record() {
        let dir = scratch();
        let now = SystemTime::now();
        let coord = Coordinator::open(&dir.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        for name in ["a", "b", "c"] {
            let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
            coord
                .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
                .unwrap();
        }
        let owner = SpiffeId::node("owner").unwrap();
        let (a1, a1_nonce) = issue_for(&coord, "a", &owner, now);
        // Undo needs a deny entry.
        assert!(crate::revoke_undo(&coord, "a", owner.as_uri(), now).is_err());
        crate::revoke_all(&coord, "a", owner.as_uri(), now).unwrap();
        crate::revoke_all(&coord, "c", owner.as_uri(), now).unwrap();
        let records_before = audit_actions(&coord).len();

        let reply = crate::revoke_undo(&coord, "a", owner.as_uri(), now).unwrap();
        assert_eq!(reply["principal"], "spiffe://orblx.local/node/a");
        assert_eq!(reply["svid_restored"], true);
        assert_eq!(reply["deny_version"], 3);

        // The SVID of a is allowed again. The other entry and the grant nonce stay.
        let deny = crate::deny_set(&coord, now).unwrap();
        assert!(deny.reject_uri(&SpiffeId::node("a").unwrap()).is_ok());
        assert!(deny.reject_uri(&SpiffeId::node("c").unwrap()).is_err());
        let text = crate::deny_json(&coord, now).unwrap();
        assert!(text.contains(&a1_nonce));
        let listed = list(&coord, now).unwrap();
        let grant = listed["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|grant| grant["id"] == a1.as_str())
            .unwrap();
        assert_eq!(grant["state"], "revoked");

        // Exactly one audit record for the undo.
        let records = audit_actions(&coord);
        assert_eq!(records.len(), records_before + 1);
        let last = records.last().unwrap();
        assert_eq!(last["action"], "unrevoke");
        assert_eq!(last["target"], "spiffe://orblx.local/node/a");
        let detail = last["detail"].as_str().unwrap();
        assert!(detail.contains("svid restored deny_version 3"), "{detail}");

        // A second undo has no entry to remove and writes no record.
        assert!(crate::revoke_undo(&coord, "a", owner.as_uri(), now).is_err());
        assert_eq!(audit_actions(&coord).len(), records_before + 1);
    }

    #[test]
    fn revoke_all_refuses_bad_principals() {
        let dir = scratch();
        let now = SystemTime::now();
        let coord = Coordinator::open(&dir.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let owner = SpiffeId::node("owner").unwrap();
        // The node is not enrolled.
        assert!(crate::revoke_all(&coord, "ghost", owner.as_uri(), now).is_err());
        assert!(crate::revoke_all(
            &coord,
            "spiffe://orblx.local/coord/coord",
            owner.as_uri(),
            now
        )
        .is_err());
        assert!(crate::revoke_all(&coord, "spiffe://other/node/a", owner.as_uri(), now).is_err());
        assert!(crate::revoke_all(&coord, owner.as_uri(), owner.as_uri(), now).is_err());
        assert!(!dir.0.join("deny.json").exists());
        // A user and an agent need no enroll. An agent owns the grants for its name.
        let user = crate::revoke_all(
            &coord,
            "spiffe://orblx.local/user/alice",
            owner.as_uri(),
            now,
        )
        .unwrap();
        assert_eq!(user["grants"].as_array().unwrap().len(), 0);
        let agent = crate::revoke_all(
            &coord,
            "spiffe://orblx.local/agent/bot",
            owner.as_uri(),
            now,
        )
        .unwrap();
        assert_eq!(agent["deny_version"], 2);
    }

    #[test]
    fn a_revoke_stops_one_grant_only() {
        let dir = scratch();
        let now = SystemTime::now();
        let coord = Coordinator::open(&dir.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        for name in ["a", "b"] {
            let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
            coord
                .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
                .unwrap();
        }
        let owner = SpiffeId::node("owner").unwrap();
        let (first, first_nonce) = issue(&coord, &owner, now);
        let (_second, second_nonce) = issue(&coord, &owner, now);
        assert_ne!(first_nonce, second_nonce);
        revoke(&coord, &first, owner.as_uri(), now).unwrap();
        let text = crate::deny_json(&coord, now).unwrap();
        assert!(text.contains(&first_nonce));
        assert!(!text.contains(&second_nonce));
        assert!(!text.contains("spiffe://orblx.local/agent/bot"));
        // The coordinator still issues a new grant for the same agent name.
        let (_third, third_nonce) = issue(&coord, &owner, now);
        assert!(!crate::deny_json(&coord, now)
            .unwrap()
            .contains(&third_nonce));
        assert!(revoke(&coord, &first, owner.as_uri(), now).is_err());
        let audit = crate::audit(&coord, None).unwrap();
        assert_eq!(audit["verify"]["ok"], Value::Bool(true));
    }
}
