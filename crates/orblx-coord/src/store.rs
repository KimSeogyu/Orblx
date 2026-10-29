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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeRecord {
    name: String,
    overlay_ip: String,
    svid: String,
    owner: String,
    endpoints: Vec<String>,
    routes: Vec<String>,
    enrolled_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRecord {
    id: String,
    hash_hex: String,
    expires_unix: u64,
    used: bool,
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
    pub endpoints: Vec<String>,
    pub routes: Vec<String>,
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
        self.disk
            .nodes
            .iter()
            .map(|node| StoredNode {
                name: node.name.clone(),
                overlay_ip: node.overlay_ip.clone(),
                svid: node.svid.clone(),
                endpoints: node.endpoints.clone(),
                routes: node.routes.clone(),
            })
            .collect()
    }

    pub fn create_token(
        &mut self,
        ttl: Duration,
        now: SystemTime,
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
        self.plan(
            name,
            endpoints,
            routes,
            format!("token:{}", record.id),
            record.id.clone(),
        )
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
            owner: plan.owner,
            endpoints: plan.endpoints.clone(),
            routes: plan.routes.clone(),
            enrolled_unix: now_unix,
        };
        let stored = StoredNode {
            name: node.name.clone(),
            overlay_ip: node.overlay_ip.clone(),
            svid: node.svid.clone(),
            endpoints: node.endpoints.clone(),
            routes: node.routes.clone(),
        };
        self.disk.nodes.push(node);
        self.disk.next_index = plan.next_index;
        self.persist()?;
        Ok(stored)
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
        let ip = overlay_ip(self.disk.next_index)?;
        let next_index = self
            .disk
            .next_index
            .checked_add(1)
            .ok_or(CoordError::Pool)?;
        Ok(EnrollPlan {
            name: name.to_string(),
            overlay_ip: ip.to_string(),
            endpoints: endpoints.to_vec(),
            routes: canonical_routes,
            owner,
            token_id,
            next_index,
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
