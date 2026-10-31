use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use orblx_audit::{ConfigAction, ConfigEvent, ConfigLog, ConfigRecord, EMPTY_DIGEST};
use orblx_datapath::{Netmap, NetmapPeer, NetmapSelf, SplitDns};
use orblx_identity::{
    google_client_id_ok, DenySet, GoogleJwks, IssueGate, IssuedSvid, MiniCa, OidcIssuer, OidcJwks,
    Policy, SpiffeId, MAX_USER_TTL,
};
use sha2::{Digest, Sha256};

use crate::error::CoordError;
use crate::files::{create_private_dir, read_text, write_bytes, write_text};
use crate::netmap::{
    decode_hex_32, verify_signed_endpoint, verify_signed_grants, verify_signed_netmap, NetmapKey,
    SignedEndpoint, SignedGrants, SignedNetmap,
};
use crate::store::{CreatedToken, NodeStore, StoredNode, StoredUser, UserState};
use crate::ticket::{self, IssuedTicket};

const COORD_NAME_FILE: &str = "coord-name";
const CA_CERT_FILE: &str = "ca.crt.pem";
const CA_KEY_FILE: &str = "ca.key.pem";
const TRUST_FILE: &str = "trust-bundle.pem";
const SEED_FILE: &str = "netmap.seed";
const STORE_FILE: &str = "nodes.json";
const POLICY_FILE: &str = "policy.hujson";
const LOADED_POLICY_FILE: &str = "policy.loaded.hujson";
/// The control-plane audit chain in the state directory.
pub const CONFIG_AUDIT_FILE: &str = "config-audit.jsonl";

/// How the coordinator checks a laptop enrollment.
pub enum OidcConfig {
    /// Enroll tokens only.
    TokenOnly,
    /// Google ID tokens.
    ///
    /// `jwks` may be empty until a fetch succeeds.
    Google {
        /// The OAuth client id.
        client_id: String,
        /// Google signing keys.
        jwks: Option<GoogleJwks>,
    },
    /// The mock IdP.
    ///
    /// Tests use this variant.
    /// `orblx coord serve` does not select it.
    Mock(Box<IssueGate>),
    /// A generic OIDC issuer from the `[oidc]` config section.
    ///
    /// The coordinator reads discovery and the JWKS on the first OIDC enrollment.
    Issuer {
        /// The issuer, the client id, and the allowed lists.
        issuer: Box<OidcIssuer>,
        /// Extra TLS roots for the issuer HTTPS server, as PEM text.
        extra_roots_pem: Option<String>,
    },
}

/// The life of a cached issuer JWKS.
pub const ISSUER_JWKS_TTL_SECS: u64 = 300;

/// The shortest time between two JWKS fetches for an unknown `kid`.
pub const ISSUER_REFETCH_SECS: u64 = 10;

/// One planned discovery and JWKS fetch for a generic issuer.
#[derive(Debug, Clone)]
pub struct IssuerFetch {
    /// The issuer.
    pub issuer: OidcIssuer,
    /// Extra TLS roots as PEM text.
    pub extra_roots_pem: Option<String>,
    /// The reason for the fetch: `first`, `stale`, or `unknown-kid`.
    pub reason: &'static str,
}

struct IssuerCache {
    issuer: OidcIssuer,
    extra_roots_pem: Option<String>,
    jwks: Option<OidcJwks>,
    fetched_at: u64,
    attempted_at: Option<u64>,
}

/// Build the OIDC mode for `orblx coord serve`.
///
/// Mock mode keeps token enrollment and does not install a test IdP.
pub fn oidc_config(
    mode: orblx_identity::OidcMode,
    client_id: Option<String>,
) -> Result<OidcConfig, CoordError> {
    match mode {
        orblx_identity::OidcMode::Mock => Ok(OidcConfig::TokenOnly),
        orblx_identity::OidcMode::Google => {
            let client_id = client_id.and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            });
            match client_id {
                Some(client_id) => {
                    google_client_id_ok(&client_id).map_err(|_| {
                        CoordError::Protocol("The OIDC configuration is not valid.".to_string())
                    })?;
                    Ok(OidcConfig::Google {
                        client_id,
                        jwks: None,
                    })
                }
                None => Ok(OidcConfig::TokenOnly),
            }
        }
    }
}

enum OidcState {
    TokenOnly,
    Google {
        client_id: String,
        jwks: Option<GoogleJwks>,
    },
    Mock(Box<IssueGate>),
    Issuer(Box<IssuerCache>),
}

struct Inner {
    state_dir: PathBuf,
    coord_name: String,
    store: NodeStore,
    ca: MiniCa,
    coord_svid: IssuedSvid,
    netmap_key: NetmapKey,
    oidc: OidcState,
    /// Life of a node leaf. The maximum is [`MAX_USER_TTL`].
    svid_ttl: Duration,
    policy_path: PathBuf,
    policy: Policy,
    policy_hash: Option<[u8; 32]>,
    /// The digest of the policy rules without the `shares` list (W25-1).
    rules_hash: Option<[u8; 32]>,
    policy_fail: Option<String>,
    has_good: bool,
    saw_file: bool,
    /// The config chain. The serve path opens it.
    audit: Option<ConfigLog>,
    /// The digest of the last refused policy file.
    fail_hash: Option<[u8; 32]>,
}

/// The coordinator state.
///
/// The state directory holds the CA, the netmap key, and the node store.
#[derive(Clone)]
pub struct Coordinator {
    inner: Arc<Mutex<Inner>>,
}

/// A successful enrollment.
///
/// Debug output elides the node private key.
pub struct EnrollResult {
    pub name: String,
    pub overlay_ip: String,
    pub svid: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub trust_bundle_pem: String,
    pub netmap_public: [u8; 32],
    pub signed_netmap: SignedNetmap,
    pub signed_grants: SignedGrants,
    pub endpoints: Vec<SignedEndpoint>,
    pub approved_routes: Vec<String>,
    pub advertised_routes: Vec<String>,
    pub exit_approved: bool,
    pub ticket: Option<IssuedTicket>,
}

impl std::fmt::Debug for EnrollResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollResult")
            .field("name", &self.name)
            .field("overlay_ip", &self.overlay_ip)
            .field("svid", &self.svid)
            .field("private_key_pem", &"[elided]")
            .field("ticket", &"[elided]")
            .finish()
    }
}

/// The agent SVID and the agent JIT ticket of one grant.
///
/// Debug output elides the key and the ticket.
pub(crate) struct AgentMaterial {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub trust_bundle_pem: String,
    pub ticket: orblx_identity::SignedTicket,
}

impl std::fmt::Debug for AgentMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentMaterial")
            .field("private_key_pem", &"[elided]")
            .field("ticket", &"[elided]")
            .finish()
    }
}

/// A signed netmap for one enrolled node.
#[derive(Debug, Clone)]
pub struct NetmapView {
    pub signed_netmap: SignedNetmap,
    pub signed_grants: SignedGrants,
    pub endpoints: Vec<SignedEndpoint>,
    pub netmap_public: [u8; 32],
    /// Advertised CIDRs that the policy approved for this node.
    pub approved_routes: Vec<String>,
    /// Every CIDR this node advertised, including held routes.
    pub advertised_routes: Vec<String>,
    /// True when this node is an approved exit node.
    pub exit_approved: bool,
}

/// Files a node keeps after enrollment.
pub struct NodeMaterial {
    pub name: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub trust_bundle_pem: String,
    pub netmap_public: [u8; 32],
}

impl std::fmt::Debug for NodeMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeMaterial")
            .field("name", &self.name)
            .field("private_key_pem", &"[elided]")
            .finish()
    }
}

impl Coordinator {
    /// Open or create the state directory.
    pub fn open(dir: &Path, coord_name: &str, oidc: OidcConfig) -> Result<Self, CoordError> {
        let _ = SpiffeId::coord(coord_name)?;
        create_private_dir(dir)?;
        let name_path = dir.join(COORD_NAME_FILE);
        if name_path.exists() {
            let stored = read_text(&name_path)?;
            if stored.trim() != coord_name {
                return Err(CoordError::Protocol(
                    "The coordinator name does not match the state directory.".to_string(),
                ));
            }
        } else {
            write_text(&name_path, &format!("{coord_name}\n"), 0o644)?;
        }
        let now = SystemTime::now();
        let ca = load_ca(dir, now)?;
        write_text(dir.join(TRUST_FILE).as_path(), ca.trust_bundle_pem(), 0o644)?;
        let netmap_key = load_netmap_key(dir)?;
        let store = NodeStore::open(&dir.join(STORE_FILE))?;
        let coord_id = SpiffeId::coord(coord_name)?;
        let coord_svid = ca.issue(&coord_id, now, MAX_USER_TTL, &DenySet::empty())?;
        let oidc = match oidc {
            OidcConfig::TokenOnly => OidcState::TokenOnly,
            OidcConfig::Google { client_id, jwks } => {
                google_client_id_ok(&client_id).map_err(|_| {
                    CoordError::Protocol("The OIDC configuration is not valid.".to_string())
                })?;
                OidcState::Google { client_id, jwks }
            }
            OidcConfig::Mock(gate) => OidcState::Mock(gate),
            OidcConfig::Issuer {
                issuer,
                extra_roots_pem,
            } => OidcState::Issuer(Box::new(IssuerCache {
                issuer: *issuer,
                extra_roots_pem,
                jwks: None,
                fetched_at: 0,
                attempted_at: None,
            })),
        };
        let coord = Self {
            inner: Arc::new(Mutex::new(Inner {
                state_dir: dir.to_path_buf(),
                coord_name: coord_name.to_string(),
                store,
                ca,
                coord_svid,
                netmap_key,
                oidc,
                svid_ttl: MAX_USER_TTL,
                policy_path: dir.join(POLICY_FILE),
                policy: Policy::empty(),
                policy_hash: None,
                rules_hash: None,
                policy_fail: None,
                has_good: false,
                saw_file: false,
                audit: None,
                fail_hash: None,
            })),
        };
        {
            let mut inner = coord.lock()?;
            refresh_policy(&mut inner);
        }
        Ok(coord)
    }

    /// Read policy from `path` on later netmap builds.
    ///
    /// A failed file does not replace the last good policy.
    pub fn set_policy_file(&self, path: &Path) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        if inner.policy_path != path {
            inner.policy_path = path.to_path_buf();
            inner.policy_hash = None;
            inner.policy_fail = None;
            inner.saw_file = false;
        }
        refresh_policy(&mut inner);
        Ok(())
    }

    /// Set the life of the next node leaf.
    ///
    /// The value is a whole number of seconds from 1 through the user maximum.
    pub fn set_node_svid_ttl(&self, ttl: Duration) -> Result<(), CoordError> {
        if ttl.is_zero() || ttl.subsec_nanos() != 0 || ttl > MAX_USER_TTL {
            return Err(CoordError::Time);
        }
        let mut inner = self.lock()?;
        inner.svid_ttl = ttl;
        Ok(())
    }

    /// Issue a new leaf for an enrolled node.
    ///
    /// The overlay address does not change.
    /// The caller must not log `private_key_pem`.
    pub fn renew_node(&self, name: &str, now: SystemTime) -> Result<EnrollResult, CoordError> {
        let _ = SpiffeId::node(name)?;
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let node = inner
            .store
            .nodes()
            .into_iter()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        if node.expired {
            return Err(CoordError::Protocol("The node key is expired.".to_string()));
        }
        issue_leaf(&mut inner, name, now)
    }

    pub fn create_token(&self, ttl: std::time::Duration) -> Result<CreatedToken, CoordError> {
        self.create_token_at(ttl, SystemTime::now())
    }

    pub fn create_token_at(
        &self,
        ttl: std::time::Duration,
        now: SystemTime,
    ) -> Result<CreatedToken, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        inner.store.create_token(ttl, now)
    }

    pub fn enroll_token(
        &self,
        name: &str,
        secret: &str,
        endpoints: &[String],
        routes: &[String],
        now: SystemTime,
    ) -> Result<EnrollResult, CoordError> {
        let _ = SpiffeId::node(name)?;
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let plan = inner
            .store
            .begin_enroll(name, secret, now, endpoints, routes)?;
        finish_enroll(&mut inner, plan, now)
    }

    pub fn enroll_oidc(
        &self,
        name: &str,
        id_token: &str,
        nonce: Option<&str>,
        endpoints: &[String],
        routes: &[String],
        now: SystemTime,
    ) -> Result<EnrollResult, CoordError> {
        let _ = SpiffeId::node(name)?;
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let login = owner_from_oidc(&inner.oidc, id_token, nonce, now)?;
        // W25-15: a user that is not approved gets no plan, no overlay address, and no SVID.
        admit_user(&mut inner, &login, now)?;
        let plan = inner
            .store
            .begin_oidc(name, &login.subject, endpoints, routes)?;
        finish_enroll(&mut inner, plan, now)
    }

    /// Return the OIDC users and their nodes (W25-15).
    pub fn user_list(&self) -> Result<(Vec<StoredUser>, Vec<StoredNode>), CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        Ok((inner.store.users(), inner.store.nodes()))
    }

    /// Approve one OIDC user for `actor` and write one config record (W25-15).
    ///
    /// `user` is `oidc:SUBJECT`. An unknown user gets an approved record, so an owner
    /// can approve a user before the first sign-in.
    pub fn approve_user_by(
        &self,
        user: &str,
        actor: &str,
        now: SystemTime,
    ) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        if inner.store.user(user).map(|stored| stored.state) == Some(UserState::Approved) {
            return Err(CoordError::Protocol(
                "The user is already approved.".to_string(),
            ));
        }
        set_user_recorded(
            &mut inner,
            user,
            UserState::Approved,
            actor,
            ConfigAction::UserApprove,
            "owner",
            now,
        )
    }

    /// Reject one OIDC user for `actor` and write one config record (W25-15).
    ///
    /// The user gets no SVID. An owner user cannot be rejected.
    /// An approved user cannot be rejected. Expire or revoke the user nodes.
    pub fn reject_user_by(
        &self,
        user: &str,
        actor: &str,
        now: SystemTime,
    ) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        if inner.policy.user_approval().is_owner_user(user) {
            return Err(CoordError::Protocol(
                "The user is an owner user. An owner user cannot be rejected.".to_string(),
            ));
        }
        match inner.store.user(user).map(|stored| stored.state) {
            Some(UserState::Approved) => {
                return Err(CoordError::Protocol(
                    "The user is approved. Expire or revoke the user nodes.".to_string(),
                ))
            }
            Some(UserState::Rejected) => {
                return Err(CoordError::Protocol(
                    "The user is already rejected.".to_string(),
                ))
            }
            Some(UserState::Pending) | None => {}
        }
        set_user_recorded(
            &mut inner,
            user,
            UserState::Rejected,
            actor,
            ConfigAction::UserReject,
            "owner",
            now,
        )
    }

    /// Return the SPIFFE IDs that node `name` does not see, and the config record count (W25-1).
    ///
    /// The deny list of a node adds these IDs.
    /// The count grows with each record, so the deny list version stays monotonic.
    pub fn share_deny_for(&self, name: &str) -> Result<(Vec<String>, u64), CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let nodes = inner.store.nodes();
        let viewer = nodes
            .iter()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        let hidden = crate::share::hidden_for(&inner.policy, viewer, &nodes);
        let count = inner.audit.as_ref().map_or(0, ConfigLog::len);
        Ok((hidden, count))
    }

    pub fn netmap_for(&self, name: &str) -> Result<NetmapView, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        sign_view(&inner, name)
    }

    /// Store advertised subnet routes and return a fresh signed netmap.
    ///
    /// The signed netmap contains a route only when [`Policy::approves_route`] allows it.
    pub fn advertise_routes(
        &self,
        name: &str,
        routes: &[String],
    ) -> Result<NetmapView, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let before = node_digest(&inner, name);
        let old_routes = node_routes(&inner, name);
        inner.store.set_routes(name, routes)?;
        let after = node_digest(&inner, name);
        if before != after {
            let actor = node_actor(&inner, name);
            let detail = format!(
                "from [{}] to [{}]",
                old_routes.join(","),
                node_routes(&inner, name).join(",")
            );
            record(
                &mut inner,
                &actor,
                ConfigAction::Routes,
                name,
                before,
                after,
                &detail,
            )?;
        }
        let view = sign_view(&inner, name)?;
        println!("advertise {name} approved {}", view.approved_routes.len());
        for route in &view.approved_routes {
            println!("approved route {route}");
        }
        for route in &view.advertised_routes {
            if !view.approved_routes.iter().any(|item| item == route) {
                println!("held route {route}");
            }
        }
        Ok(view)
    }

    /// Store reflexive endpoints and return a fresh signed view.
    ///
    /// Each endpoint is signed with the netmap Ed25519 key.
    pub fn set_candidates(
        &self,
        name: &str,
        endpoints: &[String],
    ) -> Result<NetmapView, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        inner.store.set_endpoints(name, endpoints)?;
        let view = sign_view(&inner, name)?;
        println!("candidates {name}");
        Ok(view)
    }

    /// Store the exit-node offer and return a fresh signed netmap.
    ///
    /// The signed netmap sets `exit_node` only when [`Policy::approves_exit_node`] allows it.
    pub fn advertise_exit(&self, name: &str, enabled: bool) -> Result<NetmapView, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let before = node_digest(&inner, name);
        inner.store.set_exit_node(name, enabled)?;
        let after = node_digest(&inner, name);
        if before != after {
            let actor = node_actor(&inner, name);
            let detail = if enabled { "offer on" } else { "offer off" };
            record(
                &mut inner,
                &actor,
                ConfigAction::ExitNode,
                name,
                before,
                after,
                detail,
            )?;
        }
        let view = sign_view(&inner, name)?;
        if view.exit_approved {
            println!("approved exit node {name}");
        } else if enabled {
            println!("held exit node {name}");
        }
        Ok(view)
    }

    pub fn tls_material(&self) -> Result<TlsMaterial, CoordError> {
        let inner = self.lock()?;
        Ok(TlsMaterial {
            certificate_pem: inner.coord_svid.certificate_pem.clone(),
            private_key_pem: inner.coord_svid.private_key_pem.clone(),
            trust_pem: inner.ca.trust_bundle_pem().to_string(),
            coord_id: SpiffeId::coord(&inner.coord_name)?,
        })
    }

    pub fn google_client_id_for_fetch(&self) -> Result<Option<String>, CoordError> {
        let inner = self.lock()?;
        Ok(match &inner.oidc {
            OidcState::Google {
                client_id,
                jwks: None,
            } => Some(client_id.clone()),
            OidcState::Google { .. }
            | OidcState::TokenOnly
            | OidcState::Mock(_)
            | OidcState::Issuer(_) => None,
        })
    }

    /// Plan a discovery and JWKS fetch for the generic issuer.
    ///
    /// The function returns a plan when the cache is empty, when the cache is
    /// older than [`ISSUER_JWKS_TTL_SECS`], or when the cache does not have `kid`.
    /// A fetch for an unknown `kid` happens at most once in [`ISSUER_REFETCH_SECS`].
    pub fn issuer_fetch_plan(
        &self,
        kid: Option<&str>,
        now: SystemTime,
    ) -> Result<Option<IssuerFetch>, CoordError> {
        let now = unix_secs(now);
        let mut inner = self.lock()?;
        let OidcState::Issuer(cache) = &mut inner.oidc else {
            return Ok(None);
        };
        let recent = cache
            .attempted_at
            .is_some_and(|at| now < at.saturating_add(ISSUER_REFETCH_SECS));
        let reason = match &cache.jwks {
            None if recent => return Ok(None),
            None => "first",
            Some(_) if now >= cache.fetched_at.saturating_add(ISSUER_JWKS_TTL_SECS) => "stale",
            Some(jwks) => match kid {
                Some(kid) if !jwks.has_kid(kid) && !recent => "unknown-kid",
                _ => return Ok(None),
            },
        };
        cache.attempted_at = Some(now);
        Ok(Some(IssuerFetch {
            issuer: cache.issuer.clone(),
            extra_roots_pem: cache.extra_roots_pem.clone(),
            reason,
        }))
    }

    /// Replace the cached generic issuer JWKS.
    pub fn install_issuer_jwks(&self, jwks: OidcJwks, now: SystemTime) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        match &mut inner.oidc {
            OidcState::Issuer(cache) => {
                cache.jwks = Some(jwks);
                cache.fetched_at = unix_secs(now);
                Ok(())
            }
            _ => Err(CoordError::Oidc),
        }
    }

    /// Approve a node and clear key expiry.
    ///
    /// The config chain names the coordinator as the actor.
    pub fn approve_node(&self, name: &str) -> Result<(), CoordError> {
        let actor = self.coord_actor()?;
        self.approve_node_by(name, &actor)
    }

    /// Approve a node for `actor` and write one config record.
    pub fn approve_node_by(&self, name: &str, actor: &str) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let before = node_digest(&inner, name);
        inner.store.set_approved(name, true)?;
        let after = node_digest(&inner, name);
        record(
            &mut inner,
            actor,
            ConfigAction::Approve,
            name,
            before,
            after,
            "",
        )
    }

    /// Expire a node key.
    ///
    /// The node leaves every netmap until approve.
    pub fn expire_node(&self, name: &str) -> Result<(), CoordError> {
        let actor = self.coord_actor()?;
        self.expire_node_by(name, &actor)
    }

    /// Expire a node key for `actor` and write one config record.
    pub fn expire_node_by(&self, name: &str, actor: &str) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let before = node_digest(&inner, name);
        inner.store.set_expired(name)?;
        let after = node_digest(&inner, name);
        record(
            &mut inner,
            actor,
            ConfigAction::Expire,
            name,
            before,
            after,
            "",
        )
    }

    /// Open the config chain and record the policy state at start.
    ///
    /// The serve path calls this function one time.
    /// A chain that fails the hash check stops the start.
    pub fn enable_config_audit(&self) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        if inner.audit.is_some() {
            return Ok(());
        }
        let path = inner.state_dir.join(CONFIG_AUDIT_FILE);
        let log = ConfigLog::open(&path).map_err(|err| {
            CoordError::Protocol(format!("The config audit chain is not valid. {err}"))
        })?;
        let before = log.last_policy_digest().unwrap_or(EMPTY_DIGEST);
        inner.audit = Some(log);
        let actor = coord_actor_of(&inner)?;
        let target = policy_target(&inner);
        if inner.has_good {
            let after = inner.policy_hash.unwrap_or(EMPTY_DIGEST);
            let detail = if inner.saw_file {
                "start"
            } else {
                "start saved"
            };
            record(
                &mut inner,
                &actor,
                ConfigAction::PolicyLoad,
                &target,
                before,
                after,
                detail,
            )?;
        }
        if let Some(sentence) = inner.policy_fail.clone() {
            let current = inner.policy_hash.unwrap_or(EMPTY_DIGEST);
            let after = inner.fail_hash.unwrap_or(EMPTY_DIGEST);
            record(
                &mut inner,
                &actor,
                ConfigAction::PolicyReject,
                &target,
                current,
                after,
                &sentence,
            )?;
        }
        record_user_migration(&mut inner, &actor)?;
        Ok(())
    }

    /// Write one config record for `actor`.
    ///
    /// The function does nothing when the chain is not open.
    pub fn record_change(
        &self,
        actor: &str,
        action: ConfigAction,
        target: &str,
        before: [u8; 32],
        after: [u8; 32],
        detail: &str,
    ) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        record(&mut inner, actor, action, target, before, after, detail)
    }

    /// Set up node lock with the first trusted owner keys (W23-1).
    ///
    /// The call fails when node lock is already set up.
    pub fn lock_init(&self, keys: &[String], actor: &str) -> Result<serde_json::Value, CoordError> {
        let mut inner = self.lock()?;
        let dir = inner.state_dir.clone();
        let mut store = crate::nodelock::read_store(&dir)?;
        if store.enabled() {
            return Err(CoordError::Protocol(
                "Node lock is already set up.".to_string(),
            ));
        }
        let state = crate::nodelock::LockState::genesis(keys)?;
        let before = crate::nodelock::store_digest(&dir)?;
        store.genesis = state.keys.clone();
        crate::nodelock::write_store(&dir, &store)?;
        let after = crate::nodelock::store_digest(&dir)?;
        let prints = fingerprints(&state.keys);
        record(
            &mut inner,
            actor,
            ConfigAction::LockInit,
            "node-lock",
            before,
            after,
            &format!("version 0 keys {} fp {prints}", state.keys.len()),
        )?;
        Ok(lock_value("lock-init", &store, &state))
    }

    /// Store one owner signature for one node (W23-1).
    ///
    /// The coordinator checks the signature with the current trusted keys.
    pub fn lock_sign(
        &self,
        name: &str,
        sig: orblx_datapath::NodeLockSig,
        actor: &str,
    ) -> Result<serde_json::Value, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let dir = inner.state_dir.clone();
        let mut store = crate::nodelock::read_store(&dir)?;
        if !store.enabled() {
            return Err(CoordError::Protocol("Node lock is not set up.".to_string()));
        }
        let state = store.current()?;
        let node = inner
            .store
            .nodes()
            .into_iter()
            .find(|node| node.name == name)
            .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
        let peer = NetmapPeer {
            name: node.name.clone(),
            overlay_ip: node.overlay_ip.clone(),
            svid: node.svid.clone(),
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            owner: String::new(),
            lock_sig: Some(sig.clone()),
        };
        if !state.verify_peer(&peer) {
            return Err(CoordError::Protocol(
                "A trusted owner key did not sign this node.".to_string(),
            ));
        }
        let before = crate::nodelock::store_digest(&dir)?;
        let fp = crate::nodelock::fingerprint(&sig.key_id);
        store.sigs.insert(node.name.clone(), sig);
        crate::nodelock::write_store(&dir, &store)?;
        let after = crate::nodelock::store_digest(&dir)?;
        record(
            &mut inner,
            actor,
            ConfigAction::LockSign,
            &node.name,
            before,
            after,
            &format!("version {} key fp {fp}", state.version),
        )?;
        let mut value = lock_value("lock-sign", &store, &state);
        value["name"] = serde_json::Value::String(node.name);
        Ok(value)
    }

    /// Add one owner key update (W23-1).
    ///
    /// The coordinator checks the chain and the signature with the current trusted keys.
    pub fn lock_update(
        &self,
        update: orblx_datapath::LockUpdate,
        actor: &str,
    ) -> Result<serde_json::Value, CoordError> {
        let mut inner = self.lock()?;
        let dir = inner.state_dir.clone();
        let mut store = crate::nodelock::read_store(&dir)?;
        if !store.enabled() {
            return Err(CoordError::Protocol("Node lock is not set up.".to_string()));
        }
        let current = store.current()?;
        let next = current.apply(&update)?;
        let action = if update.action == crate::nodelock::ACTION_ROTATE {
            ConfigAction::LockRotate
        } else {
            ConfigAction::LockRemove
        };
        let removed: Vec<String> = current
            .keys
            .iter()
            .filter(|key| !next.keys.contains(key))
            .cloned()
            .collect();
        let added: Vec<String> = next
            .keys
            .iter()
            .filter(|key| !current.keys.contains(key))
            .cloned()
            .collect();
        let before = crate::nodelock::store_digest(&dir)?;
        store.updates.push(update.clone());
        crate::nodelock::write_store(&dir, &store)?;
        let after = crate::nodelock::store_digest(&dir)?;
        let mut detail = format!(
            "version {} keys {} signer fp {} removed fp {}",
            next.version,
            next.keys.len(),
            crate::nodelock::fingerprint(&update.signer),
            fingerprints(&removed)
        );
        if !added.is_empty() {
            detail.push_str(&format!(" added fp {}", fingerprints(&added)));
        }
        record(
            &mut inner,
            actor,
            action,
            "node-lock",
            before,
            after,
            &detail,
        )?;
        Ok(lock_value(action.as_str(), &store, &next))
    }

    /// Return the node lock view (W23-1). The view holds public keys only.
    pub fn lock_show(&self) -> Result<serde_json::Value, CoordError> {
        let inner = self.lock()?;
        let store = crate::nodelock::read_store(&inner.state_dir)?;
        if !store.enabled() {
            return Ok(serde_json::json!({"op": "lock", "enabled": false}));
        }
        let state = store.current()?;
        Ok(lock_value("lock", &store, &state))
    }

    /// Return the config chain text.
    ///
    /// The text is empty when the file does not exist.
    pub fn config_audit_text(&self) -> Result<String, CoordError> {
        let inner = self.lock()?;
        let path = inner.state_dir.join(CONFIG_AUDIT_FILE);
        if !path.exists() {
            return Ok(String::new());
        }
        read_text(&path)
    }

    /// Return the coordinator SPIFFE ID text.
    pub fn coord_actor(&self) -> Result<String, CoordError> {
        let inner = self.lock()?;
        coord_actor_of(&inner)
    }

    /// Return the enrolled nodes.
    pub fn node_list(&self) -> Result<Vec<StoredNode>, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        Ok(inner.store.nodes())
    }

    /// Return true when `id` is an owner in the loaded policy.
    pub fn caller_is_owner(&self, id: &SpiffeId) -> Result<bool, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        Ok(inner.policy.is_owner(id))
    }

    /// Return the owner SPIFFE IDs of the loaded policy (W25-3b).
    pub fn policy_owners(&self) -> Result<Vec<SpiffeId>, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        Ok(inner.policy.owners().to_vec())
    }

    /// Return the audit webhook URLs of the loaded policy (W25-7).
    ///
    /// The call does not read the policy file.
    pub fn audit_webhook_urls(&self) -> Result<Vec<String>, CoordError> {
        let inner = self.lock()?;
        Ok(inner.policy.audit_webhooks().to_vec())
    }

    /// Return the SIEM sinks of the loaded policy (W25-13).
    ///
    /// The call does not read the policy file.
    pub fn audit_sinks(&self) -> Result<Vec<orblx_identity::AuditSink>, CoordError> {
        let inner = self.lock()?;
        Ok(inner.policy.audit_sinks().to_vec())
    }

    /// Write one `sink-error` record for the sink `name` (W25-13).
    ///
    /// The delivery thread calls this one time for each run of failures.
    /// The detail holds the failed step. It does not hold a credential.
    pub fn record_sink_error(&self, name: &str, detail: &str) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        let actor = coord_actor_of(&inner)?;
        let digest = orblx_audit::sha256_digest(name.as_bytes());
        record(
            &mut inner,
            &actor,
            ConfigAction::SinkError,
            name,
            digest,
            digest,
            detail,
        )
    }

    /// Return the policy file path.
    pub fn policy_file(&self) -> Result<PathBuf, CoordError> {
        let inner = self.lock()?;
        Ok(inner.policy_path.clone())
    }

    /// Return the state directory.
    pub fn state_dir(&self) -> Result<PathBuf, CoordError> {
        let inner = self.lock()?;
        Ok(inner.state_dir.clone())
    }

    /// Return advertised and approved routes for every node.
    pub fn route_report(&self) -> Result<Vec<serde_json::Value>, CoordError> {
        let mut inner = self.lock()?;
        reload(&mut inner)?;
        let mut rows = Vec::new();
        for node in inner.store.nodes() {
            let approved = if node_visible(&node) {
                published_routes(&inner.policy, &node.svid, &node.routes)
            } else {
                Vec::new()
            };
            rows.push(serde_json::json!({
                "name": node.name,
                "advertised": node.routes,
                "approved": approved
            }));
        }
        Ok(rows)
    }

    pub fn install_google_jwks(&self, jwks: GoogleJwks) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        match &mut inner.oidc {
            OidcState::Google { jwks: slot, .. } => {
                *slot = Some(jwks);
                Ok(())
            }
            OidcState::TokenOnly | OidcState::Mock(_) | OidcState::Issuer(_) => {
                Err(CoordError::Oidc)
            }
        }
    }

    /// Issue one agent SVID and one agent JIT ticket.
    ///
    /// The caller must not log the key or the ticket.
    pub(crate) fn issue_agent_material(
        &self,
        agent: &SpiffeId,
        now: SystemTime,
        ttl: Duration,
        dest: orblx_identity::Ipv4Destination,
        deny: &DenySet,
    ) -> Result<AgentMaterial, CoordError> {
        let inner = self.lock()?;
        let issued = inner.ca.issue(agent, now, ttl, deny)?;
        let ticket = ticket::issue_agent_ticket(
            &inner.state_dir,
            inner.ca.public_key(),
            &inner.coord_name,
            agent,
            now,
            ttl,
            dest,
        )?;
        Ok(AgentMaterial {
            certificate_pem: issued.certificate_pem,
            private_key_pem: issued.private_key_pem,
            trust_bundle_pem: inner.ca.trust_bundle_pem().to_string(),
            ticket,
        })
    }

    /// Sign one agent grant document with the netmap key.
    pub(crate) fn sign_agent_grant(
        &self,
        grant: &orblx_agent::AgentGrant,
    ) -> Result<orblx_agent::SignedAgentGrant, CoordError> {
        let inner = self.lock()?;
        inner.netmap_key.sign_agent_grant(grant)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, CoordError> {
        self.inner.lock().map_err(|_| CoordError::State)
    }
}

fn reload(inner: &mut Inner) -> Result<(), CoordError> {
    inner.store = NodeStore::open(&inner.state_dir.join(STORE_FILE))?;
    refresh_policy(inner);
    if inner.audit.is_some() && !inner.store.migration_unrecorded().is_empty() {
        let actor = coord_actor_of(inner)?;
        record_user_migration(inner, &actor)?;
    }
    Ok(())
}

fn refresh_policy(inner: &mut Inner) {
    let path = inner.policy_path.clone();
    if !path.exists() {
        if inner.saw_file {
            note_policy_failure(
                inner,
                "The policy file is missing. The coordinator keeps the last good policy.",
            );
        } else if !inner.has_good {
            adopt_saved_policy(inner);
        }
        return;
    }
    inner.saw_file = true;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            note_policy_failure(
                inner,
                "The policy file did not open. The coordinator keeps the last good policy.",
            );
            if !inner.has_good {
                adopt_saved_policy(inner);
            }
            return;
        }
    };
    let hash = sha256(&bytes);
    if inner.has_good && inner.policy_hash == Some(hash) {
        return;
    }
    match Policy::from_hujson(&bytes) {
        Ok(policy) => {
            let before = inner.policy_hash.filter(|_| inner.has_good);
            let old_lines = crate::share::share_lines(&inner.policy);
            let new_lines = crate::share::share_lines(&policy);
            let rules = rules_digest(&bytes);
            let rules_changed = inner.rules_hash != Some(rules);
            inner.policy = policy;
            inner.policy_hash = Some(hash);
            inner.rules_hash = Some(rules);
            inner.has_good = true;
            inner.policy_fail = None;
            inner.fail_hash = None;
            match before {
                None => {
                    record_policy(inner, ConfigAction::PolicyLoad, EMPTY_DIGEST, hash, "file");
                }
                Some(before) => {
                    // A change of only the shares writes one record for each share
                    // and no policy record (W25-1).
                    if rules_changed || old_lines == new_lines {
                        record_policy(inner, ConfigAction::PolicyReplace, before, hash, "file");
                    }
                    record_share_diff(inner, &old_lines, &new_lines);
                }
            }
            let saved = inner.state_dir.join(LOADED_POLICY_FILE);
            match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    if write_text(&saved, text, 0o644).is_err() {
                        println!("policy load failed: The last good policy was not saved.");
                    }
                }
                Err(_) => {
                    println!("policy load failed: The last good policy was not saved.");
                }
            }
        }
        Err(err) => {
            note_policy_failure_with(inner, &err.to_string(), Some(hash));
            if !inner.has_good {
                adopt_saved_policy(inner);
            }
        }
    }
}

fn adopt_saved_policy(inner: &mut Inner) {
    let path = inner.state_dir.join(LOADED_POLICY_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    if let Ok(policy) = Policy::from_hujson(&bytes) {
        inner.policy = policy;
        inner.has_good = true;
        inner.policy_hash = Some(sha256(&bytes));
        inner.rules_hash = Some(rules_digest(&bytes));
    }
}

/// The digest of the policy rules without the `shares` list.
fn rules_digest(bytes: &[u8]) -> [u8; 32] {
    match orblx_identity::rules_without_shares(bytes) {
        Some(text) => sha256(text.as_bytes()),
        None => sha256(bytes),
    }
}

/// Write one `unshare` record for each removed share and one `share` record for each new share.
///
/// The target is the shared node. The detail is the share line.
fn record_share_diff(
    inner: &mut Inner,
    old_lines: &std::collections::BTreeSet<String>,
    new_lines: &std::collections::BTreeSet<String>,
) {
    if inner.audit.is_none() {
        return;
    }
    let Ok(actor) = coord_actor_of(inner) else {
        return;
    };
    let mut changes: Vec<(ConfigAction, &String)> = Vec::new();
    for line in old_lines.difference(new_lines) {
        changes.push((ConfigAction::Unshare, line));
    }
    for line in new_lines.difference(old_lines) {
        changes.push((ConfigAction::Share, line));
    }
    for (action, line) in changes {
        let target = line.split(' ').next().unwrap_or_default().to_string();
        let digest = sha256(line.as_bytes());
        let (before, after) = if action == ConfigAction::Share {
            (EMPTY_DIGEST, digest)
        } else {
            (digest, EMPTY_DIGEST)
        };
        if record(inner, &actor, action, &target, before, after, line).is_err() {
            println!("config audit write failed: {}", action.as_str());
        }
    }
}

fn note_policy_failure(inner: &mut Inner, sentence: &str) {
    note_policy_failure_with(inner, sentence, None);
}

fn note_policy_failure_with(inner: &mut Inner, sentence: &str, hash: Option<[u8; 32]>) {
    if inner.policy_fail.as_deref() == Some(sentence) && inner.fail_hash == hash {
        return;
    }
    println!("policy load failed: {sentence}");
    inner.policy_fail = Some(sentence.to_string());
    inner.fail_hash = hash;
    let current = inner
        .policy_hash
        .filter(|_| inner.has_good)
        .unwrap_or(EMPTY_DIGEST);
    record_policy(
        inner,
        ConfigAction::PolicyReject,
        current,
        hash.unwrap_or(EMPTY_DIGEST),
        sentence,
    );
}

fn record_policy(
    inner: &mut Inner,
    action: ConfigAction,
    before: [u8; 32],
    after: [u8; 32],
    detail: &str,
) {
    if inner.audit.is_none() {
        return;
    }
    let actor = match coord_actor_of(inner) {
        Ok(actor) => actor,
        Err(_) => return,
    };
    let target = policy_target(inner);
    if record(inner, &actor, action, &target, before, after, detail).is_err() {
        println!("config audit write failed: {}", action.as_str());
    }
}

fn fingerprints(keys: &[String]) -> String {
    let prints: Vec<String> = keys
        .iter()
        .map(|key| crate::nodelock::fingerprint(key))
        .collect();
    if prints.is_empty() {
        "none".to_string()
    } else {
        prints.join(",")
    }
}

fn lock_value(
    op: &str,
    store: &crate::nodelock::LockStore,
    state: &crate::nodelock::LockState,
) -> serde_json::Value {
    let signed: Vec<serde_json::Value> = store
        .sigs
        .iter()
        .map(|(name, sig)| serde_json::json!({"name": name, "key_id": sig.key_id}))
        .collect();
    serde_json::json!({
        "op": op,
        "enabled": true,
        "version": state.version,
        "head": state.head,
        "keys": state.keys,
        "signed": signed,
    })
}

/// Append one record when the chain is open.
fn record(
    inner: &mut Inner,
    actor: &str,
    action: ConfigAction,
    target: &str,
    before: [u8; 32],
    after: [u8; 32],
    detail: &str,
) -> Result<(), CoordError> {
    let Some(log) = inner.audit.as_mut() else {
        return Ok(());
    };
    let at_unix = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoordError::Time)?
        .as_secs();
    let detail = clip_detail(detail);
    let event = ConfigEvent {
        actor: actor.to_string(),
        at_unix,
        action,
        target: target.to_string(),
        before,
        after,
        detail,
    };
    let written: ConfigRecord = log.append(event).map_err(|err| {
        println!("config audit write failed: {}", action.as_str());
        CoordError::Protocol(format!("The config audit write failed. {err}"))
    })?;
    println!(
        "config audit {} {} {} {}",
        written.index,
        action.as_str(),
        target,
        actor
    );
    Ok(())
}

fn clip_detail(detail: &str) -> String {
    let clean: String = detail
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let mut out = String::new();
    for ch in clean.chars() {
        if out.len() + ch.len_utf8() > orblx_audit::MAX_CONFIG_TEXT {
            break;
        }
        out.push(ch);
    }
    out
}

fn coord_actor_of(inner: &Inner) -> Result<String, CoordError> {
    Ok(SpiffeId::coord(&inner.coord_name)?.as_uri().to_string())
}

fn policy_target(inner: &Inner) -> String {
    let name = inner
        .policy_path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| POLICY_FILE.to_string());
    let clean: String = name
        .chars()
        .filter(|ch| !ch.is_whitespace() && !ch.is_control())
        .collect();
    if clean.is_empty() {
        POLICY_FILE.to_string()
    } else {
        clean
    }
}

fn node_actor(inner: &Inner, name: &str) -> String {
    inner
        .store
        .nodes()
        .into_iter()
        .find(|node| node.name == name)
        .map(|node| node.svid)
        .unwrap_or_else(|| format!("node:{name}"))
}

fn node_routes(inner: &Inner, name: &str) -> Vec<String> {
    inner
        .store
        .nodes()
        .into_iter()
        .find(|node| node.name == name)
        .map(|node| node.routes)
        .unwrap_or_default()
}

/// SHA-256 over the control-plane fields of one node.
///
/// The digest leaves out endpoints because NAT candidates change often.
/// An absent node uses the zero digest.
fn node_digest(inner: &Inner, name: &str) -> [u8; 32] {
    let Some(node) = inner
        .store
        .nodes()
        .into_iter()
        .find(|node| node.name == name)
    else {
        return EMPTY_DIGEST;
    };
    let value = serde_json::json!({
        "name": node.name,
        "overlay_ip": node.overlay_ip,
        "svid": node.svid,
        "owner": node.owner,
        "routes": node.routes,
        "exit_node": node.exit_node,
        "approved": node.approved,
        "expired": node.expired,
    });
    sha256(value.to_string().as_bytes())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn finish_enroll(
    inner: &mut Inner,
    plan: crate::store::EnrollPlan,
    now: SystemTime,
) -> Result<EnrollResult, CoordError> {
    let id = SpiffeId::node(&plan.name)?;
    let issued = inner
        .ca
        .issue(&id, now, inner.svid_ttl, &DenySet::empty())?;
    let stored = inner
        .store
        .commit(plan, issued.spiffe_id.as_uri().to_string(), now)?;
    let approved = initial_approved(&inner.policy, &stored.name);
    if !approved {
        inner.store.set_approved(&stored.name, false)?;
    }
    let after = node_digest(inner, &stored.name);
    let detail = format!(
        "svid {} ip {} {}",
        stored.svid,
        stored.overlay_ip,
        if approved { "approved" } else { "pending" }
    );
    record(
        inner,
        &stored.owner,
        ConfigAction::Enroll,
        &stored.name,
        EMPTY_DIGEST,
        after,
        &detail,
    )?;
    let view = sign_view(inner, &stored.name)?;
    let ticket = issue_ticket(inner, &stored.name, now)?;
    Ok(EnrollResult {
        name: stored.name,
        overlay_ip: stored.overlay_ip,
        svid: stored.svid,
        certificate_pem: issued.certificate_pem,
        private_key_pem: issued.private_key_pem,
        trust_bundle_pem: inner.ca.trust_bundle_pem().to_string(),
        netmap_public: view.netmap_public,
        signed_netmap: view.signed_netmap,
        signed_grants: view.signed_grants,
        endpoints: view.endpoints,
        approved_routes: view.approved_routes,
        advertised_routes: view.advertised_routes,
        exit_approved: view.exit_approved,
        ticket: Some(ticket),
    })
}

fn initial_approved(policy: &Policy, name: &str) -> bool {
    if !policy.node_approval() {
        return true;
    }
    match SpiffeId::node(name) {
        Ok(id) => policy.is_owner(&id),
        Err(_) => false,
    }
}

fn issue_ticket(inner: &Inner, name: &str, now: SystemTime) -> Result<IssuedTicket, CoordError> {
    ticket::issue_node_ticket(
        &inner.state_dir,
        inner.ca.public_key(),
        &inner.coord_name,
        name,
        now,
        inner.svid_ttl,
    )
}

fn issue_leaf(inner: &mut Inner, name: &str, now: SystemTime) -> Result<EnrollResult, CoordError> {
    let id = SpiffeId::node(name)?;
    let issued = inner
        .ca
        .issue(&id, now, inner.svid_ttl, &DenySet::empty())?;
    let view = sign_view(inner, name)?;
    let self_node = view.signed_netmap.netmap.self_node.clone();
    let ticket = issue_ticket(inner, name, now)?;
    Ok(EnrollResult {
        name: self_node.name,
        overlay_ip: self_node.overlay_ip,
        svid: issued.spiffe_id.as_uri().to_string(),
        certificate_pem: issued.certificate_pem,
        private_key_pem: issued.private_key_pem,
        trust_bundle_pem: inner.ca.trust_bundle_pem().to_string(),
        netmap_public: view.netmap_public,
        signed_netmap: view.signed_netmap,
        signed_grants: view.signed_grants,
        endpoints: view.endpoints,
        approved_routes: view.approved_routes,
        advertised_routes: view.advertised_routes,
        exit_approved: view.exit_approved,
        ticket: Some(ticket),
    })
}

fn node_visible(node: &StoredNode) -> bool {
    node.approved && !node.expired
}

fn sign_view(inner: &Inner, name: &str) -> Result<NetmapView, CoordError> {
    let lock_store = crate::nodelock::read_store(&inner.state_dir)?;
    let nodes = inner.store.nodes();
    let self_node = nodes
        .iter()
        .find(|node| node.name == name)
        .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?
        .clone();
    let self_visible = node_visible(&self_node);
    let mut peers = Vec::new();
    let mut endpoints = Vec::new();
    if self_visible {
        for node in nodes.iter().filter(|node| {
            node_visible(node) && crate::share::sees(&inner.policy, &self_node, node)
        }) {
            for endpoint in &node.endpoints {
                endpoints.push(inner.netmap_key.sign_endpoint(&node.name, endpoint)?);
            }
            if node.name == self_node.name {
                continue;
            }
            // A shared node from another tenant gives no subnet routes and no exit node.
            let other = crate::share::cross_tenant(&inner.policy, &self_node, node);
            peers.push(NetmapPeer {
                name: node.name.clone(),
                overlay_ip: node.overlay_ip.clone(),
                svid: node.svid.clone(),
                endpoints: node.endpoints.clone(),
                routes: if other {
                    Vec::new()
                } else {
                    published_routes(&inner.policy, &node.svid, &node.routes)
                },
                exit_node: !other && published_exit(&inner.policy, &node.svid, node.exit_node),
                owner: String::new(),
                lock_sig: lock_store.sigs.get(&node.name).cloned(),
            });
        }
    }
    let payload = Netmap {
        version: 1,
        self_node: NetmapSelf {
            name: self_node.name.clone(),
            overlay_ip: self_node.overlay_ip.clone(),
            owner: String::new(),
        },
        peers,
        lock: lock_store.updates.clone(),
        split_dns: published_split_dns(&inner.policy, self_visible),
    };
    let signed_netmap = inner.netmap_key.sign_netmap(&payload)?;
    let receiver = SpiffeId::node(&self_node.name)?;
    let grants = filtered_grants(inner, &receiver, &self_node, self_visible);
    let signed_grants = inner.netmap_key.sign_grants(&grants)?;
    let netmap_public = inner.netmap_key.public();
    verify_signed_netmap(&signed_netmap, &netmap_public)?;
    verify_signed_grants(&signed_grants, &netmap_public)?;
    for endpoint in &endpoints {
        verify_signed_endpoint(endpoint, &netmap_public)?;
    }
    let approved_routes = published_routes(&inner.policy, &self_node.svid, &self_node.routes);
    let exit_approved = published_exit(&inner.policy, &self_node.svid, self_node.exit_node);
    Ok(NetmapView {
        signed_netmap,
        signed_grants,
        endpoints,
        netmap_public,
        approved_routes,
        advertised_routes: self_node.routes.clone(),
        exit_approved,
    })
}

/// Copy the policy `splitDns` zones into the netmap (W24-F).
///
/// A node that waits for approval gets no zone.
fn published_split_dns(policy: &Policy, self_visible: bool) -> Vec<SplitDns> {
    if !self_visible {
        return Vec::new();
    }
    policy
        .split_dns()
        .iter()
        .map(|zone| SplitDns {
            domain: zone.domain.clone(),
            nameservers: zone.nameservers.iter().map(ToString::to_string).collect(),
        })
        .collect()
}

fn published_exit(policy: &Policy, svid: &str, offered: bool) -> bool {
    if !offered {
        return false;
    }
    let Ok(id) = SpiffeId::parse(svid) else {
        return false;
    };
    policy.approves_exit_node(&id)
}

fn filtered_grants(
    inner: &Inner,
    receiver: &SpiffeId,
    self_node: &StoredNode,
    self_visible: bool,
) -> orblx_identity::ReceiverGrants {
    if !self_visible {
        return orblx_identity::ReceiverGrants {
            version: 1,
            receiver: receiver.as_uri().to_string(),
            grants: Vec::new(),
            reach: Vec::new(),
            filter: inner.policy.acl_set(),
            subnets: Vec::new(),
            guarded: Vec::new(),
        };
    }
    let nodes = inner.store.nodes();
    // A node that the receiver does not see gives no grant and is not in reach (W25-1).
    let hidden: std::collections::BTreeSet<String> = nodes
        .iter()
        .filter(|node| !node_visible(node) || !crate::share::sees(&inner.policy, self_node, node))
        .map(|node| node.svid.clone())
        .collect();
    // Between two tenants, only a share gives a grant or a reach entry.
    // A policy acl does not cross a tenant (W25-1).
    let other: std::collections::BTreeSet<String> = nodes
        .iter()
        .filter(|node| crate::share::cross_tenant(&inner.policy, self_node, node))
        .map(|node| node.svid.clone())
        .collect();
    let mut grants = inner.policy.receiver_grants(receiver);
    grants.grants.retain(|grant| !other.contains(&grant.src));
    grants.reach.retain(|dst| !other.contains(dst));
    for grant in crate::share::share_grants(&inner.policy, self_node, &nodes) {
        if !grants.grants.contains(&grant) {
            grants.grants.push(grant);
        }
    }
    for dst in crate::share::share_reach(&inner.policy, self_node) {
        if !grants.reach.contains(&dst) {
            grants.reach.push(dst);
        }
    }
    grants.grants.retain(|grant| !hidden.contains(&grant.src));
    grants.subnets.retain(|grant| !hidden.contains(&grant.src));
    grants.reach.retain(|dst| !hidden.contains(dst));
    // A peer in another tenant gets only the grants of a share, also without an `acls` list (W25-1b).
    grants.guarded = other.difference(&hidden).cloned().collect();
    grants
}

fn published_routes(policy: &Policy, svid: &str, routes: &[String]) -> Vec<String> {
    let Ok(id) = SpiffeId::parse(svid) else {
        return Vec::new();
    };
    routes
        .iter()
        .filter(|route| policy.approves_route(&id, route))
        .cloned()
        .collect()
}

/// The checked OIDC sign-in.
struct OidcLogin {
    subject: String,
    email: Option<String>,
    email_verified: bool,
}

impl OidcLogin {
    fn subject_only(subject: String) -> Self {
        Self {
            subject,
            email: None,
            email_verified: false,
        }
    }

    fn user(&self) -> String {
        format!("oidc:{}", self.subject)
    }
}

/// Let an approved OIDC user enroll, or refuse the user (W25-15).
///
/// - An owner user in `userApproval.ownerUsers` is never pending.
/// - A rejected user is refused.
/// - A verified email in `userApproval.autoApproveDomains` is approved. The list is empty by default.
/// - Each other new user is stored as pending and refused.
///
/// Each approval that this function makes writes one `user-approve` record.
fn admit_user(inner: &mut Inner, login: &OidcLogin, now: SystemTime) -> Result<(), CoordError> {
    let user = login.user();
    if crate::store::check_user(&user).is_err() {
        return Err(CoordError::Oidc);
    }
    let state = inner.store.user(&user).map(|stored| stored.state);
    if state == Some(UserState::Approved) {
        return Ok(());
    }
    let approval = inner.policy.user_approval();
    let reason = if approval.is_owner_user(&user) {
        Some("policy owner user".to_string())
    } else if state == Some(UserState::Rejected) {
        println!("user refused {user} rejected");
        return Err(CoordError::UserRejected);
    } else {
        approval
            .auto_domain(login.email.as_deref(), login.email_verified)
            .map(|domain| format!("policy auto-approve domain {domain}"))
    };
    if let Some(reason) = reason {
        let actor = coord_actor_of(inner)?;
        return set_user_recorded(
            inner,
            &user,
            UserState::Approved,
            &actor,
            ConfigAction::UserApprove,
            &reason,
            now,
        );
    }
    let email = login.email.as_deref().filter(|_| login.email_verified);
    if inner.store.add_pending(&user, email, now)? {
        println!("user pending {user}");
    } else {
        println!("user refused {user} pending");
    }
    Err(CoordError::UserPending)
}

/// Write one `user-approve` record for each user that the store migration approved (W25-15).
///
/// The store migration runs when the store opens. When the chain is not open yet, the store
/// keeps a mark, and the function runs again when the chain opens. Then each approval has a record.
fn record_user_migration(inner: &mut Inner, actor: &str) -> Result<(), CoordError> {
    for user in inner.store.migration_unrecorded() {
        let after = user_digest(inner.store.user(&user).as_ref());
        record(
            inner,
            actor,
            ConfigAction::UserApprove,
            &user,
            EMPTY_DIGEST,
            after,
            "store migration",
        )?;
        inner.store.set_migration_recorded(&user)?;
    }
    Ok(())
}

/// Change one user state and write one config record (W25-15).
///
/// The change needs the config chain. When the record write fails, the state goes back.
fn set_user_recorded(
    inner: &mut Inner,
    user: &str,
    state: UserState,
    actor: &str,
    action: ConfigAction,
    detail: &str,
    now: SystemTime,
) -> Result<(), CoordError> {
    if inner.audit.is_none() {
        return Err(CoordError::Protocol(
            "The config audit chain is off. A user change needs a record.".to_string(),
        ));
    }
    let old = inner.store.user(user);
    let before = user_digest(old.as_ref());
    inner.store.set_user_state(user, state, now)?;
    let after = user_digest(inner.store.user(user).as_ref());
    if let Err(err) = record(inner, actor, action, user, before, after, detail) {
        let _ = match old {
            Some(old) => inner.store.set_user_state(user, old.state, now),
            None => inner.store.remove_user(user),
        };
        return Err(err);
    }
    Ok(())
}

fn user_digest(user: Option<&StoredUser>) -> [u8; 32] {
    let Some(user) = user else {
        return EMPTY_DIGEST;
    };
    let value = serde_json::json!({
        "user": user.user,
        "state": user.state.as_str(),
    });
    sha256(value.to_string().as_bytes())
}

fn owner_from_oidc(
    oidc: &OidcState,
    id_token: &str,
    nonce: Option<&str>,
    now: SystemTime,
) -> Result<OidcLogin, CoordError> {
    match oidc {
        OidcState::TokenOnly => Err(CoordError::Oidc),
        OidcState::Mock(gate) => gate
            .owner_subject(id_token, nonce, now)
            .map(OidcLogin::subject_only)
            .map_err(|_| CoordError::Oidc),
        OidcState::Google { client_id, jwks } => {
            let jwks = jwks.as_ref().ok_or(CoordError::Oidc)?;
            let nonce = nonce.ok_or(CoordError::Oidc)?;
            jwks.verify(id_token, client_id, nonce, now)
                .map(|claims| OidcLogin::subject_only(claims.subject))
                .map_err(|_| CoordError::Oidc)
        }
        OidcState::Issuer(cache) => {
            let Some(jwks) = cache.jwks.as_ref() else {
                println!("oidc reject jwks-missing");
                return Err(CoordError::Oidc);
            };
            match jwks.verify(id_token, &cache.issuer, nonce, now) {
                Ok(claims) => {
                    println!("oidc accept sub {}", claims.subject);
                    Ok(OidcLogin {
                        subject: claims.subject,
                        email: claims.email,
                        email_verified: claims.email_verified,
                    })
                }
                Err(reason) => {
                    println!("oidc reject {reason}");
                    Err(CoordError::Oidc)
                }
            }
        }
    }
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

fn load_ca(dir: &Path, now: SystemTime) -> Result<MiniCa, CoordError> {
    let cert_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);
    if cert_path.exists() || key_path.exists() {
        let certificate_pem = read_text(&cert_path)?;
        let private_key_pem = read_text(&key_path)?;
        return MiniCa::from_pem(&certificate_pem, &private_key_pem).map_err(CoordError::from);
    }
    let ca = MiniCa::generate(now)?;
    write_text(&cert_path, ca.certificate_pem(), 0o644)?;
    write_text(&key_path, &ca.private_key_pem(), 0o600)?;
    Ok(ca)
}

fn load_netmap_key(dir: &Path) -> Result<NetmapKey, CoordError> {
    let path = dir.join(SEED_FILE);
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(CoordError::io)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| CoordError::State)?;
        return Ok(NetmapKey::from_seed(&seed));
    }
    let key = NetmapKey::generate();
    write_bytes(&path, &key.seed(), 0o600)?;
    Ok(key)
}

/// Certificate material for the QUIC listener.
pub struct TlsMaterial {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub trust_pem: String,
    pub coord_id: SpiffeId,
}

impl EnrollResult {
    /// Write the node files.
    ///
    /// The private key file mode is `0600`.
    pub fn write_state(&self, dir: &Path) -> Result<(), CoordError> {
        install_netmap_check();
        create_private_dir(dir)?;
        write_text(&dir.join("node-name"), &format!("{}\n", self.name), 0o644)?;
        write_text(&dir.join("node.crt.pem"), &self.certificate_pem, 0o644)?;
        write_text(&dir.join("node.key.pem"), &self.private_key_pem, 0o600)?;
        write_text(&dir.join("trust-bundle.pem"), &self.trust_bundle_pem, 0o644)?;
        write_text(&dir.join("cert.pem"), &self.certificate_pem, 0o644)?;
        write_text(&dir.join("key.pem"), &self.private_key_pem, 0o600)?;
        write_text(&dir.join("bundle.pem"), &self.trust_bundle_pem, 0o644)?;
        write_text(
            &dir.join("netmap.pub"),
            &format!("{}\n", crate::netmap::encode_hex(&self.netmap_public)),
            0o644,
        )?;
        write_view(
            dir,
            &self.signed_netmap,
            &self.signed_grants,
            &self.endpoints,
        )?;
        if let Some(ticket) = &self.ticket {
            write_ticket_files(dir, ticket)?;
        }
        Ok(())
    }
}

fn write_ticket_files(dir: &Path, ticket: &IssuedTicket) -> Result<(), CoordError> {
    write_bytes(&dir.join("ticket.bin"), &ticket.bytes, 0o600)?;
    write_bytes(&dir.join("ticket.bin.mac"), &ticket.mac, 0o600)?;
    write_text(
        &dir.join("ticket-verifier.pem"),
        &ticket.verifier_pem,
        0o644,
    )?;
    write_bytes(&dir.join("ticket-mac.key"), &ticket.mac_key, 0o600)?;
    write_bytes(&dir.join("svid-ca.pub"), &ticket.svid_ca_pub, 0o644)?;
    write_text(
        &dir.join("ticket-not-before"),
        &format!("{}\n", ticket.not_before),
        0o644,
    )?;
    write_text(
        &dir.join("ticket-not-after"),
        &format!("{}\n", ticket.not_after),
        0o644,
    )?;
    Ok(())
}

impl NetmapView {
    pub fn write_state(&self, dir: &Path) -> Result<(), CoordError> {
        install_netmap_check();
        write_view(
            dir,
            &self.signed_netmap,
            &self.signed_grants,
            &self.endpoints,
        )
    }
}

fn write_view(
    dir: &Path,
    netmap: &SignedNetmap,
    grants: &SignedGrants,
    endpoints: &[SignedEndpoint],
) -> Result<(), CoordError> {
    let mut local = netmap.netmap.clone();
    if let Some(report) = crate::nodelock::apply_node_lock(dir, &mut local)? {
        crate::nodelock::print_report(&report);
    }
    let netmap_text = serde_json::to_string(&local)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    orblx_datapath::Netmap::from_slice(netmap_text.as_bytes())
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    let signed_text = serde_json::to_string(netmap)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    let endpoint_text = serde_json::to_string(endpoints)
        .map_err(|_| CoordError::Protocol("The endpoint list is not valid.".to_string()))?;
    let grant_text = serde_json::to_string(&grants.grants)
        .map_err(|_| CoordError::Protocol("The grants are not valid.".to_string()))?;
    let signed_grants = serde_json::to_string(grants)
        .map_err(|_| CoordError::Protocol("The grants are not valid.".to_string()))?;
    write_text(&dir.join("netmap.json"), &netmap_text, 0o644)?;
    write_text(&dir.join("netmap.signed.json"), &signed_text, 0o644)?;
    write_text(&dir.join("grants.json"), &grant_text, 0o644)?;
    write_text(&dir.join("grants.signed.json"), &signed_grants, 0o644)?;
    write_text(&dir.join("endpoints.json"), &endpoint_text, 0o644)?;
    Ok(())
}

pub fn read_node_material(dir: &Path) -> Result<NodeMaterial, CoordError> {
    let name = read_text(&dir.join("node-name"))?;
    let name = name.trim().to_string();
    let _ = SpiffeId::node(&name)?;
    let certificate_pem = read_text(&dir.join("node.crt.pem"))?;
    let private_key_pem = read_text(&dir.join("node.key.pem"))?;
    let trust_bundle_pem = read_text(&dir.join("trust-bundle.pem"))?;
    let netmap_public = decode_hex_32(read_text(&dir.join("netmap.pub"))?.trim())?;
    Ok(NodeMaterial {
        name,
        certificate_pem,
        private_key_pem,
        trust_bundle_pem,
        netmap_public,
    })
}

/// Read the node netmap from the signed netmap file only (W25-36).
///
/// The function reads `netmap.signed.json` and checks the signature with the pinned key in
/// `netmap.pub`. It does not read `netmap.json`. Then it applies node lock, as `write_view` does.
/// Thus a change to the bytes of `netmap.json` on disk does not change the parsed netmap, and a
/// change to the bytes of `netmap.signed.json` makes the signature check fail.
pub fn read_verified_netmap(
    dir: &Path,
) -> Result<(Netmap, Option<crate::nodelock::LockReport>), CoordError> {
    // W25-36 (c): an enrolled node without the pinned key fails closed. It does not use
    // netmap.json in its place.
    if !dir.join("netmap.pub").exists() {
        return Err(CoordError::Protocol(
            "The node has coordinator state, but netmap.pub is missing. \
             The node does not use netmap.json. Enroll the node again."
                .to_string(),
        ));
    }
    if !dir.join("netmap.signed.json").exists() {
        return Err(CoordError::Protocol(
            "The node has coordinator state, but netmap.signed.json is missing. \
             The node does not use netmap.json."
                .to_string(),
        ));
    }
    let public = decode_hex_32(read_text(&dir.join("netmap.pub"))?.trim())?;
    let text = read_text(&dir.join("netmap.signed.json"))?;
    let signed: SignedNetmap = serde_json::from_str(&text)
        .map_err(|_| CoordError::Protocol("The signed netmap is not valid.".to_string()))?;
    verify_signed_netmap(&signed, &public)?;
    let mut netmap = signed.netmap;
    let report = crate::nodelock::apply_node_lock(dir, &mut netmap)?;
    let text = serde_json::to_vec(&netmap)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    let netmap = Netmap::from_slice(&text)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    Ok((netmap, report))
}

/// Read the netmap of a node state directory (W25-36).
///
/// A node with coordinator state uses [`read_verified_netmap`]. If `netmap.pub` or
/// `netmap.signed.json` is missing, the read fails closed.
/// A node without coordinator state (a static `orblx issue` node) reads `netmap.json`, as before.
/// `netmap.pub` alone does not mean coordinator state: a static `--policy` node has it too.
pub fn read_node_netmap(dir: &Path) -> Result<Netmap, CoordError> {
    if orblx_datapath::has_coordinator_state(dir) {
        return read_verified_netmap(dir).map(|(netmap, _)| netmap);
    }
    Netmap::from_path(&dir.join("netmap.json"))
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))
}

/// The signed netmap check for the running node readers in `orblx-datapath` (W25-36).
fn running_netmap_check(dir: &Path) -> Result<Netmap, String> {
    read_verified_netmap(dir)
        .map(|(netmap, _)| netmap)
        .map_err(|err| err.to_string())
}

/// Install the signed netmap check for the datapath watcher, DNS, status, and serve.
///
/// The CLI calls this at start. [`write_state`] also calls it, so each process that
/// writes coordinator state has the check.
pub fn install_netmap_check() {
    orblx_datapath::set_netmap_verifier(running_netmap_check);
}

#[cfg(test)]
mod tests {
    use super::oidc_config;
    use super::OidcConfig;

    mod signed_netmap {
        use std::path::{Path, PathBuf};

        use orblx_datapath::{Netmap, NetmapPeer, NetmapSelf};

        use crate::netmap::{encode_hex, NetmapKey};
        use crate::{read_node_netmap, read_verified_netmap};

        fn temp_dir(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "orblx-w25-36-{name}-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn sample() -> Netmap {
            Netmap {
                version: 1,
                self_node: NetmapSelf {
                    name: "server".to_string(),
                    overlay_ip: "100.64.0.1".to_string(),
                    owner: String::new(),
                },
                peers: vec![NetmapPeer {
                    name: "laptop".to_string(),
                    overlay_ip: "100.64.0.2".to_string(),
                    svid: "spiffe://orblx.local/node/laptop".to_string(),
                    endpoints: vec!["10.0.0.2:443".to_string()],
                    routes: vec!["192.168.1.0/24".to_string()],
                    exit_node: false,
                    owner: String::new(),
                    lock_sig: None,
                }],
                lock: Vec::new(),
                split_dns: Vec::new(),
            }
        }

        /// Write the netmap files as `write_view` writes them (a valid write).
        fn write_valid(dir: &Path) -> Netmap {
            let key = NetmapKey::generate();
            let netmap = sample();
            let signed = key.sign_netmap(&netmap).unwrap();
            std::fs::write(
                dir.join("netmap.pub"),
                format!("{}\n", encode_hex(&key.public())),
            )
            .unwrap();
            std::fs::write(
                dir.join("netmap.json"),
                serde_json::to_string(&netmap).unwrap(),
            )
            .unwrap();
            std::fs::write(
                dir.join("netmap.signed.json"),
                serde_json::to_string(&signed).unwrap(),
            )
            .unwrap();
            // `write_state` writes the node name with the netmap files.
            std::fs::write(dir.join("node-name"), "server\n").unwrap();
            netmap
        }

        /// Changes to the bytes of `netmap.json` after a valid write.
        fn netmap_json_tampers() -> Vec<String> {
            let mut moved = sample();
            moved.peers[0].endpoints = vec!["203.0.113.9:443".to_string()];
            let mut added = sample();
            let mut extra = added.peers[0].clone();
            extra.name = "intruder".to_string();
            extra.overlay_ip = "100.64.0.9".to_string();
            extra.svid = "spiffe://orblx.local/node/intruder".to_string();
            added.peers.push(extra);
            let mut route = sample();
            route.peers[0].routes = vec!["0.0.0.0/0".to_string()];
            route.peers[0].exit_node = true;
            let mut self_ip = sample();
            self_ip.self_node.overlay_ip = "100.64.0.7".to_string();
            vec![
                serde_json::to_string(&moved).unwrap(),
                serde_json::to_string(&added).unwrap(),
                serde_json::to_string(&route).unwrap(),
                serde_json::to_string(&self_ip).unwrap(),
                "{}".to_string(),
                String::new(),
            ]
        }

        #[test]
        fn untampered_files_give_the_same_netmap_as_before() {
            let dir = temp_dir("same");
            let netmap = write_valid(&dir);
            let before = Netmap::from_path(&dir.join("netmap.json")).unwrap();
            assert_eq!(before, netmap);
            let (verified, report) = read_verified_netmap(&dir).unwrap();
            assert!(report.is_none());
            assert_eq!(verified, before);
            assert_eq!(read_node_netmap(&dir).unwrap(), before);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn tampered_netmap_json_is_never_parsed() {
            let mut accepted = 0;
            let tampers = netmap_json_tampers();
            for text in &tampers {
                let dir = temp_dir("json");
                let netmap = write_valid(&dir);
                std::fs::write(dir.join("netmap.json"), text).unwrap();
                let parsed = read_node_netmap(&dir).unwrap();
                if parsed != netmap {
                    accepted += 1;
                }
                assert_eq!(read_verified_netmap(&dir).unwrap().0, netmap);
                std::fs::remove_dir_all(&dir).unwrap();
            }
            println!(
                "tampered_netmap_json files {} accepted {accepted}",
                tampers.len()
            );
            assert_eq!(accepted, 0);
        }

        #[test]
        fn tampered_signed_netmap_is_rejected() {
            let mut accepted = 0;
            let mut total = 0;
            for (from, to) in [
                ("10.0.0.2:443", "10.0.0.3:443"),
                ("100.64.0.2", "100.64.0.3"),
                ("192.168.1.0/24", "192.168.0.0/16"),
                (
                    "\"name\":\"laptop\",",
                    "\"name\":\"laptop\",\"exit_node\":true,",
                ),
                ("\"name\":\"laptop\"", "\"name\":\"laptoq\""),
            ] {
                let dir = temp_dir("signed");
                write_valid(&dir);
                let path = dir.join("netmap.signed.json");
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(text.contains(from), "{from}");
                std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
                total += 1;
                let verified = read_verified_netmap(&dir);
                assert!(verified.is_err(), "{from}");
                if read_node_netmap(&dir).is_ok() {
                    accepted += 1;
                }
                std::fs::remove_dir_all(&dir).unwrap();
            }
            // A changed signature or key id also fails.
            for field in ["sig", "key_id"] {
                let dir = temp_dir("sig");
                write_valid(&dir);
                let path = dir.join("netmap.signed.json");
                let mut value: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                let old = value[field].as_str().unwrap().to_string();
                let new = if old.starts_with('A') { "B" } else { "A" };
                value[field] = serde_json::Value::String(format!("{new}{}", &old[1..]));
                std::fs::write(&path, value.to_string()).unwrap();
                total += 1;
                if read_node_netmap(&dir).is_ok() {
                    accepted += 1;
                }
                std::fs::remove_dir_all(&dir).unwrap();
            }
            println!("tampered_signed_netmap files {total} accepted {accepted}");
            assert_eq!(accepted, 0);
        }

        #[test]
        fn a_node_without_a_coordinator_reads_netmap_json() {
            let dir = temp_dir("static");
            let netmap = sample();
            std::fs::write(
                dir.join("netmap.json"),
                serde_json::to_string(&netmap).unwrap(),
            )
            .unwrap();
            assert_eq!(read_node_netmap(&dir).unwrap(), netmap);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        /// A static `orblx issue --policy` node has `netmap.pub` and signed grants, but no
        /// coordinator state. It keeps its netmap file.
        #[test]
        fn a_static_node_with_netmap_pub_reads_netmap_json() {
            let dir = temp_dir("static-pub");
            let netmap = sample();
            std::fs::write(
                dir.join("netmap.json"),
                serde_json::to_string(&netmap).unwrap(),
            )
            .unwrap();
            std::fs::write(dir.join("netmap.pub"), format!("{}\n", "00".repeat(32))).unwrap();
            std::fs::write(dir.join("grants.signed.json"), "{}").unwrap();
            assert_eq!(read_node_netmap(&dir).unwrap(), netmap);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        /// W25-36 (c): coordinator state without `netmap.pub` fails closed with a clear error.
        /// The node does not use `netmap.json` in its place, for each coordinator file.
        #[test]
        fn an_enrolled_node_without_netmap_pub_fails_closed() {
            crate::install_netmap_check();
            let mut accepted = 0;
            for marker in orblx_datapath::COORDINATOR_STATE_FILES {
                let dir = temp_dir("no-pub");
                let netmap = sample();
                std::fs::write(
                    dir.join("netmap.json"),
                    serde_json::to_string(&netmap).unwrap(),
                )
                .unwrap();
                if marker == "netmap.signed.json" {
                    let key = NetmapKey::generate();
                    let signed = key.sign_netmap(&netmap).unwrap();
                    std::fs::write(dir.join(marker), serde_json::to_string(&signed).unwrap())
                        .unwrap();
                } else {
                    std::fs::write(dir.join(marker), "x\n").unwrap();
                }
                let err = read_node_netmap(&dir).unwrap_err().to_string();
                assert!(err.contains("netmap.pub is missing"), "{marker}: {err}");
                let running = orblx_datapath::read_running_netmap(&dir, &dir.join("netmap.json"));
                match running {
                    Ok(_) => accepted += 1,
                    Err(err) => assert!(err.contains("netmap.pub is missing"), "{marker}: {err}"),
                }
                std::fs::remove_dir_all(&dir).unwrap();
            }
            println!(
                "enrolled_without_netmap_pub markers {} accepted {accepted}",
                orblx_datapath::COORDINATOR_STATE_FILES.len()
            );
            assert_eq!(accepted, 0);
        }

        /// W25-36 (b): tamper with both files while a reader runs as the node runtime does.
        ///
        /// The reader thread does what the datapath netmap watcher, the DNS watcher, and the
        /// serve check do on each tick: it reads the source file and parses the netmap only
        /// through `read_running_netmap`. The test changes `netmap.json` and
        /// `netmap.signed.json` while the thread runs. No tampered netmap is accepted.
        #[test]
        fn tampers_while_the_node_reads_are_never_accepted() {
            use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
            use std::sync::Arc;

            crate::install_netmap_check();
            let dir = temp_dir("running");
            let netmap = write_valid(&dir);
            let netmap_path = dir.join("netmap.json");
            let source = orblx_datapath::netmap_source_file(&dir, &netmap_path);
            assert_eq!(source, dir.join("netmap.signed.json"));
            let good_signed = std::fs::read(&source).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let accepted = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(AtomicUsize::new(0));
            let reader = {
                let (dir, netmap_path, netmap) = (dir.clone(), netmap_path.clone(), netmap.clone());
                let (stop, accepted, reads) =
                    (Arc::clone(&stop), Arc::clone(&accepted), Arc::clone(&reads));
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        if let Ok(read) = orblx_datapath::read_running_netmap(&dir, &netmap_path) {
                            if read != netmap {
                                accepted.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        reads.fetch_add(1, Ordering::SeqCst);
                    }
                })
            };
            let wait_reads = |count: usize| {
                let goal = reads.load(Ordering::SeqCst) + count;
                while reads.load(Ordering::SeqCst) < goal {
                    std::thread::yield_now();
                }
            };
            let mut files = 0;
            for text in netmap_json_tampers() {
                std::fs::write(&netmap_path, text).unwrap();
                files += 1;
                wait_reads(3);
            }
            let good_text = String::from_utf8(good_signed.clone()).unwrap();
            for (from, to) in [
                ("10.0.0.2:443", "10.0.0.3:443"),
                ("100.64.0.2", "100.64.0.3"),
                ("192.168.1.0/24", "0.0.0.0/0"),
            ] {
                std::fs::write(&source, good_text.replacen(from, to, 1)).unwrap();
                files += 1;
                wait_reads(3);
            }
            std::fs::write(&source, &good_signed).unwrap();
            wait_reads(3);
            stop.store(true, Ordering::SeqCst);
            reader.join().unwrap();
            let accepted = accepted.load(Ordering::SeqCst);
            println!(
                "running_tamper files {files} reads {} accepted {accepted}",
                reads.load(Ordering::SeqCst)
            );
            assert_eq!(accepted, 0);
            // The untampered signed file still gives the netmap.
            assert_eq!(
                orblx_datapath::read_running_netmap(&dir, &netmap_path).unwrap(),
                netmap
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn an_enrolled_node_without_the_signed_file_fails() {
            let dir = temp_dir("missing");
            write_valid(&dir);
            std::fs::remove_file(dir.join("netmap.signed.json")).unwrap();
            assert!(read_node_netmap(&dir).is_err());
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn blank_google_client_id_is_token_only() {
        let blank = oidc_config(orblx_identity::OidcMode::Google, Some("   ".to_string())).unwrap();
        let missing = oidc_config(orblx_identity::OidcMode::Google, None).unwrap();
        assert!(matches!(blank, OidcConfig::TokenOnly));
        assert!(matches!(missing, OidcConfig::TokenOnly));
    }
}
