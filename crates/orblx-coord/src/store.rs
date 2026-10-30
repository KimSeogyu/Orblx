use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::ippool::{canonical_route, overlay_ip, parse_endpoint};
use crate::netmap::encode_hex;

const STORE_VERSION: u32 = 1;
const TOKEN_PREFIX: &str = "ge1.";
const MAX_TOKEN_TTL: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiskStore {
    version: u32,
    next_index: u32,
    nodes: Vec<NodeRecord>,
    tokens: Vec<TokenRecord>,
}

fn default_approved() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeRecord {
    name: String,
    overlay_ip: String,
    svid: String,
    owner: String,
    endpoints: Vec<String>,
    routes: Vec<String>,
    #[serde(default)]
    exit_node: bool,
    enrolled_unix: u64,
    #[serde(default = "default_approved")]
    approved: bool,
    #[serde(default)]
    expired: bool,
    /// W25-18: the coordinator removes the node after it stays offline too long.
    #[serde(default)]
    ephemeral: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRecord {
    id: String,
    hash_hex: String,
    expires_unix: u64,
    used: bool,
    /// W25-18: a node that enrolls with this token is ephemeral.
    #[serde(default)]
    ephemeral: bool,
}

#[derive(Clone)]
pub struct NodeStore {
    path: std::path::PathBuf,
    disk: DiskStore,
}

pub struct CreatedToken {
    pub id: String,
    pub secret: String,
    pub expires_unix: u64,
}

impl std::fmt::Debug for CreatedToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedToken")
            .field("id", &self.id)
            .field("secret", &"[elided]")
            .field("expires_unix", &self.expires_unix)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct StoredNode {
    pub name: String,
    pub overlay_ip: String,
    pub svid: String,
    pub owner: String,
    pub endpoints: Vec<String>,
    pub routes: Vec<String>,
    pub exit_node: bool,
    pub approved: bool,
    pub expired: bool,
    /// W25-18: the node is ephemeral.
    pub ephemeral: bool,
}

impl From<&NodeRecord> for StoredNode {
    fn from(node: &NodeRecord) -> Self {
        Self {
            name: node.name.clone(),
            overlay_ip: node.overlay_ip.clone(),
            svid: node.svid.clone(),
            owner: node.owner.clone(),
            endpoints: node.endpoints.clone(),
            routes: node.routes.clone(),
            exit_node: node.exit_node,
            approved: node.approved,
            expired: node.expired,
            ephemeral: node.ephemeral,
        }
    }
}

impl NodeStore {
    pub fn open(path: &Path) -> Result<Self, CoordError> {
        if path.exists() {
            let text = read_text(path)?;
            let disk: DiskStore = serde_json::from_str(&text).map_err(|_| CoordError::State)?;
            if disk.version != STORE_VERSION {
                return Err(CoordError::State);
            }
            if text.contains("PRIVATE KEY") || text.contains(TOKEN_PREFIX) {
                return Err(CoordError::State);
            }
            return Ok(Self {
                path: path.to_path_buf(),
                disk,
            });
        }
        let store = Self {
            path: path.to_path_buf(),
            disk: DiskStore {
                version: STORE_VERSION,
                next_index: 0,
                nodes: Vec::new(),
                tokens: Vec::new(),
            },
        };
        store.persist()?;
        Ok(store)
    }

    pub fn nodes(&self) -> Vec<StoredNode> {
        self.disk.nodes.iter().map(StoredNode::from).collect()
    }

    pub fn create_token(
        &mut self,
        ttl: Duration,
        now: SystemTime,
    ) -> Result<CreatedToken, CoordError> {
        self.create_token_with(ttl, now, false)
    }

    /// Create one enroll token. A node that enrolls with an `ephemeral` token is ephemeral (W25-18).
    pub fn create_token_with(
        &mut self,
        ttl: Duration,
        now: SystemTime,
        ephemeral: bool,
    ) -> Result<CreatedToken, CoordError> {
        let ttl_secs = whole_secs(ttl)?;
        if !(1..=MAX_TOKEN_TTL).contains(&ttl_secs) {
            return Err(CoordError::Time);
        }
        let now_unix = unix_now(now)?;
        let expires_unix = now_unix.checked_add(ttl_secs).ok_or(CoordError::Time)?;
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let secret = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
        let hash_hex = token_hash(&secret);
        let id = hash_hex.get(..16).ok_or(CoordError::State)?.to_string();
        self.disk.tokens.push(TokenRecord {
            id: id.clone(),
            hash_hex,
            expires_unix,
            used: false,
            ephemeral,
        });
        self.persist()?;
        Ok(CreatedToken {
            id,
            secret,
            expires_unix,
        })
    }

    /// Consume a token and allocate the next overlay address.
    ///
    /// The token stays unused when the caller does not keep the returned plan.
    pub fn begin_enroll(
        &self,
        name: &str,
        secret: &str,
        now: SystemTime,
        endpoints: &[String],
        routes: &[String],
    ) -> Result<EnrollPlan, CoordError> {
        if self.disk.nodes.iter().any(|node| node.name == name) {
            return Err(CoordError::Exists);
        }
        let now_unix = unix_now(now)?;
        let hash = token_hash(secret);
        let record = self
            .disk
            .tokens
            .iter()
            .find(|token| constant_eq(&token.hash_hex, &hash))
            .ok_or(CoordError::Token)?;
        if record.used {
            return Err(CoordError::TokenUsed);
        }
        if now_unix >= record.expires_unix {
            return Err(CoordError::TokenExpired);
        }
        let mut plan = self.plan(
            name,
            endpoints,
            routes,
            format!("token:{}", record.id),
            record.id.clone(),
        )?;
        plan.ephemeral = record.ephemeral;
        Ok(plan)
    }

    pub fn begin_oidc(
        &self,
        name: &str,
        owner: &str,
        endpoints: &[String],
        routes: &[String],
    ) -> Result<EnrollPlan, CoordError> {
        if self.disk.nodes.iter().any(|node| node.name == name) {
            return Err(CoordError::Exists);
        }
        if owner.is_empty() || owner.len() > 128 || owner.contains(['\n', ':']) {
            return Err(CoordError::Oidc);
        }
        self.plan(
            name,
            endpoints,
            routes,
            format!("oidc:{owner}"),
            String::new(),
        )
    }

    pub fn commit(
        &mut self,
        plan: EnrollPlan,
        svid: String,
        now: SystemTime,
    ) -> Result<StoredNode, CoordError> {
        let now_unix = unix_now(now)?;
        if !plan.token_id.is_empty() {
            let token = self
                .disk
                .tokens
                .iter_mut()
                .find(|token| token.id == plan.token_id)
                .ok_or(CoordError::Token)?;
            if token.used {
                return Err(CoordError::TokenUsed);
            }
            token.used = true;
        }
        let node = NodeRecord {
            name: plan.name.clone(),
            overlay_ip: plan.overlay_ip.clone(),
            svid,
            owner: plan.owner.clone(),
            endpoints: plan.endpoints.clone(),
            routes: plan.routes.clone(),
            exit_node: false,
            enrolled_unix: now_unix,
            approved: true,
            expired: false,
            ephemeral: plan.ephemeral,
        };
        let stored = StoredNode::from(&node);
        self.disk.nodes.push(node);
        self.disk.next_index = plan.next_index;
        self.persist()?;
        Ok(stored)
    }

    /// Delete one ephemeral node record and return it (W25-18).
    ///
    /// The overlay address of the node becomes free for the next enroll.
    /// The function refuses a node that is not ephemeral.
    pub fn remove_ephemeral(&mut self, name: &str) -> Result<StoredNode, CoordError> {
        let position = self
            .disk
            .nodes
            .iter()
            .position(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        if !self.disk.nodes[position].ephemeral {
            return Err(CoordError::Protocol(
                "The node is not ephemeral.".to_string(),
            ));
        }
        let node = self.disk.nodes.remove(position);
        self.persist()?;
        Ok(StoredNode::from(&node))
    }

    /// Replace the advertised routes for an enrolled node.
    ///
    /// The caller publishes a route only after policy approval.
    pub fn set_routes(&mut self, name: &str, routes: &[String]) -> Result<(), CoordError> {
        let canonical_routes = subnet_routes(routes)?;
        let node = self
            .disk
            .nodes
            .iter_mut()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        node.routes = canonical_routes;
        self.persist()
    }

    /// Store whether this node offers to be an exit node.
    ///
    /// The signed netmap sets the flag only after policy approval.
    pub fn set_exit_node(&mut self, name: &str, enabled: bool) -> Result<(), CoordError> {
        let node = self
            .disk
            .nodes
            .iter_mut()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        node.exit_node = enabled;
        self.persist()
    }

    /// Mark a node approved or waiting.
    ///
    /// Approve also clears key expiry.
    pub fn set_approved(&mut self, name: &str, approved: bool) -> Result<(), CoordError> {
        let node = self
            .disk
            .nodes
            .iter_mut()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        node.approved = approved;
        if approved {
            node.expired = false;
        }
        self.persist()
    }

    /// Mark the node key expired.
    ///
    /// An expired node stays out of every netmap.
    pub fn set_expired(&mut self, name: &str) -> Result<(), CoordError> {
        let node = self
            .disk
            .nodes
            .iter_mut()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        node.expired = true;
        self.persist()
    }

    /// Replace the endpoint list for an enrolled node.
    ///
    /// The caller passes the reflexive address gathered by STUN.
    pub fn set_endpoints(&mut self, name: &str, endpoints: &[String]) -> Result<(), CoordError> {
        if endpoints.is_empty() || endpoints.len() > 8 {
            return Err(CoordError::Endpoint);
        }
        for endpoint in endpoints {
            crate::ippool::parse_endpoint(endpoint)?;
        }
        let node = self
            .disk
            .nodes
            .iter_mut()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        if node.endpoints == endpoints {
            return Ok(());
        }
        node.endpoints = endpoints.to_vec();
        self.persist()
    }

    fn plan(
        &self,
        name: &str,
        endpoints: &[String],
        routes: &[String],
        owner: String,
        token_id: String,
    ) -> Result<EnrollPlan, CoordError> {
        if endpoints.is_empty() {
            return Err(CoordError::Endpoint);
        }
        for endpoint in endpoints {
            parse_endpoint(endpoint)?;
        }
        let canonical_routes = subnet_routes(routes)?;
        // W25-18: use the lowest index that no node holds. The address of a removed
        // ephemeral node is free again. With no removed node, the index is `next_index`.
        let mut index = 0u32;
        let ip = loop {
            let ip = overlay_ip(index)?.to_string();
            if index >= self.disk.next_index
                || !self.disk.nodes.iter().any(|node| node.overlay_ip == ip)
            {
                break ip;
            }
            index = index.checked_add(1).ok_or(CoordError::Pool)?;
        };
        let next_index = index
            .checked_add(1)
            .ok_or(CoordError::Pool)?
            .max(self.disk.next_index);
        Ok(EnrollPlan {
            name: name.to_string(),
            overlay_ip: ip,
            endpoints: endpoints.to_vec(),
            routes: canonical_routes,
            owner,
            token_id,
            next_index,
            ephemeral: false,
        })
    }

    fn persist(&self) -> Result<(), CoordError> {
        let text = serde_json::to_string_pretty(&self.disk).map_err(|_| CoordError::State)?;
        if text.contains("PRIVATE KEY") || text.contains(TOKEN_PREFIX) {
            return Err(CoordError::State);
        }
        write_text(&self.path, &text, 0o600)
    }
}

pub struct EnrollPlan {
    pub name: String,
    pub overlay_ip: String,
    pub endpoints: Vec<String>,
    pub routes: Vec<String>,
    owner: String,
    token_id: String,
    next_index: u32,
    /// W25-18: the node is ephemeral.
    pub ephemeral: bool,
}

fn subnet_routes(routes: &[String]) -> Result<Vec<String>, CoordError> {
    let mut canonical_routes = Vec::with_capacity(routes.len());
    for route in routes {
        let canonical = canonical_route(route)?;
        if canonical == "0.0.0.0/0" {
            return Err(CoordError::Protocol(
                "The route 0.0.0.0/0 is an exit route.".to_string(),
            ));
        }
        if !canonical_routes.contains(&canonical) {
            canonical_routes.push(canonical);
        }
    }
    canonical_routes.sort();
    Ok(canonical_routes)
}

fn token_hash(secret: &str) -> String {
    encode_hex(Sha256::digest(secret.as_bytes()).as_slice())
}

fn constant_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in left.bytes().zip(right.bytes()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

fn whole_secs(ttl: Duration) -> Result<u64, CoordError> {
    if ttl.is_zero() || ttl.subsec_nanos() != 0 {
        return Err(CoordError::Time);
    }
    Ok(ttl.as_secs())
}

pub fn unix_now(now: SystemTime) -> Result<u64, CoordError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoordError::Time)
}

#[cfg(test)]
mod ephemeral_tests {
    use super::*;

    fn store(label: &str) -> (NodeStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "orblx-w25q-store-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (NodeStore::open(&dir.join("nodes.json")).unwrap(), dir)
    }

    fn add(store: &mut NodeStore, name: &str, ephemeral: bool) -> String {
        let now = SystemTime::now();
        let token = store
            .create_token_with(Duration::from_secs(60), now, ephemeral)
            .unwrap();
        let plan = store
            .begin_enroll(
                name,
                &token.secret,
                now,
                &["127.0.0.1:443".to_string()],
                &[],
            )
            .unwrap();
        let svid = format!("spiffe://orblx.local/node/{name}");
        store.commit(plan, svid, now).unwrap().overlay_ip
    }

    #[test]
    fn the_default_token_is_not_ephemeral() {
        let (mut store, dir) = store("default");
        let token = store
            .create_token(Duration::from_secs(60), SystemTime::now())
            .unwrap();
        let plan = store
            .begin_enroll(
                "plain",
                &token.secret,
                SystemTime::now(),
                &["127.0.0.1:443".to_string()],
                &[],
            )
            .unwrap();
        assert!(!plan.ephemeral);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_refuses_a_node_that_is_not_ephemeral() {
        let (mut store, dir) = store("refuse");
        add(&mut store, "plain", false);
        assert!(store.remove_ephemeral("plain").is_err());
        assert_eq!(store.nodes().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_removed_address_is_used_again_and_others_do_not_move() {
        let (mut store, dir) = store("reuse");
        let first = add(&mut store, "a", false);
        let second = add(&mut store, "b", true);
        let third = add(&mut store, "c", false);
        assert_eq!(store.remove_ephemeral("b").unwrap().overlay_ip, second);
        assert_eq!(add(&mut store, "d", true), second);
        let fifth = add(&mut store, "e", false);
        assert!(![first.as_str(), second.as_str(), third.as_str()].contains(&fifth.as_str()));
        let reopened = NodeStore::open(&dir.join("nodes.json")).unwrap();
        assert_eq!(reopened.nodes().len(), 4);
        assert!(reopened
            .nodes()
            .iter()
            .any(|node| node.name == "d" && node.ephemeral));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_old_store_reads_as_not_ephemeral() {
        let (mut store, dir) = store("old");
        add(&mut store, "a", true);
        let path = dir.join("nodes.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for list in ["nodes", "tokens"] {
            for item in value[list].as_array_mut().unwrap() {
                item.as_object_mut().unwrap().remove("ephemeral");
            }
        }
        std::fs::write(&path, value.to_string()).unwrap();
        let reopened = NodeStore::open(&path).unwrap();
        assert!(!reopened.nodes()[0].ephemeral);
        assert!(!reopened.disk.tokens[0].ephemeral);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
