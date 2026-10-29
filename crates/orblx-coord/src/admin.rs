//! Admin reads and writes for the owner SVID.
//!
//! The coordinator checks the caller SVID against the policy owner list.
//! Approve puts a node into netmaps and grants.
//! Revoke adds the node SVID to the deny set.
//! Expire removes the node from netmaps until the next approve.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use orblx_identity::{DenySet, SpiffeId};
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

pub fn deny_set(coord: &Coordinator, now: SystemTime) -> Result<DenySet, CoordError> {
    let text = deny_json(coord, now)?;
    let mut deny = DenySet::empty();
    let _ = deny
        .apply_json(text.as_bytes())
        .map_err(|_| CoordError::State)?;
    Ok(deny)
}

pub fn approve(coord: &Coordinator, name: &str) -> Result<Value, CoordError> {
    let _ = SpiffeId::node(name)?;
    coord.approve_node(name)?;
    Ok(json!({
        "op": "approve",
        "name": name,
        "approved": true
    }))
}

pub fn expire(coord: &Coordinator, name: &str) -> Result<Value, CoordError> {
    let _ = SpiffeId::node(name)?;
    coord.expire_node(name)?;
    Ok(json!({
        "op": "expire",
        "name": name,
        "expired": true
    }))
}

pub fn revoke(coord: &Coordinator, name: &str, now: SystemTime) -> Result<Value, CoordError> {
    let _ = SpiffeId::node(name)?;
    let nodes = coord.node_list()?;
    let node = nodes
        .iter()
        .find(|node| node.name == name)
        .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
    let version = push_revoke(coord, &node.svid, now)?;
    Ok(json!({
        "op": "revoke",
        "name": name,
        "svid": node.svid,
        "deny_version": version
    }))
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

fn push_revoke(coord: &Coordinator, svid: &str, now: SystemTime) -> Result<u64, CoordError> {
    let _ = SpiffeId::parse(svid)?;
    let mut file = read_deny(coord, now)?;
    if !file.revoked_uris.iter().any(|item| item == svid) {
        file.revoked_uris.push(svid.to_string());
        file.revoked_uris.sort();
    }
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
