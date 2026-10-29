use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use orblx_datapath::{Netmap, NetmapPeer, NetmapSelf};
use orblx_identity::{
    google_client_id_ok, DenySet, GoogleJwks, IssueGate, IssuedSvid, MiniCa, Policy, SpiffeId,
    MAX_USER_TTL,
};
use sha2::{Digest, Sha256};

use crate::error::CoordError;
use crate::files::{create_private_dir, read_text, write_bytes, write_text};
use crate::netmap::{
    decode_hex_32, verify_signed_endpoint, verify_signed_grants, verify_signed_netmap, NetmapKey,
    SignedEndpoint, SignedGrants, SignedNetmap,
};
use crate::store::{CreatedToken, NodeStore};

const COORD_NAME_FILE: &str = "coord-name";
const CA_CERT_FILE: &str = "ca.crt.pem";
const CA_KEY_FILE: &str = "ca.key.pem";
const TRUST_FILE: &str = "trust-bundle.pem";
const SEED_FILE: &str = "netmap.seed";
const STORE_FILE: &str = "nodes.json";
const POLICY_FILE: &str = "policy.hujson";
const LOADED_POLICY_FILE: &str = "policy.loaded.hujson";

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
}

struct Inner {
    state_dir: PathBuf,
    coord_name: String,
    store: NodeStore,
    ca: MiniCa,
    coord_svid: IssuedSvid,
    netmap_key: NetmapKey,
    oidc: OidcState,
    policy_path: PathBuf,
    policy: Policy,
    policy_hash: Option<[u8; 32]>,
    policy_fail: Option<String>,
    has_good: bool,
    saw_file: bool,
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
}

impl std::fmt::Debug for EnrollResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollResult")
            .field("name", &self.name)
            .field("overlay_ip", &self.overlay_ip)
            .field("svid", &self.svid)
            .field("private_key_pem", &"[elided]")
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
                policy_path: dir.join(POLICY_FILE),
                policy: Policy::empty(),
                policy_hash: None,
                policy_fail: None,
                has_good: false,
                saw_file: false,
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
        let owner = owner_from_oidc(&inner.oidc, id_token, nonce, now)?;
        let plan = inner.store.begin_oidc(name, &owner, endpoints, routes)?;
        finish_enroll(&mut inner, plan, now)
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
        inner.store.set_routes(name, routes)?;
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
            OidcState::Google { .. } | OidcState::TokenOnly | OidcState::Mock(_) => None,
        })
    }

    pub fn install_google_jwks(&self, jwks: GoogleJwks) -> Result<(), CoordError> {
        let mut inner = self.lock()?;
        match &mut inner.oidc {
            OidcState::Google { jwks: slot, .. } => {
                *slot = Some(jwks);
                Ok(())
            }
            OidcState::TokenOnly | OidcState::Mock(_) => Err(CoordError::Oidc),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, CoordError> {
        self.inner.lock().map_err(|_| CoordError::State)
    }
}

fn reload(inner: &mut Inner) -> Result<(), CoordError> {
    inner.store = NodeStore::open(&inner.state_dir.join(STORE_FILE))?;
    refresh_policy(inner);
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
            inner.policy = policy;
            inner.policy_hash = Some(hash);
            inner.has_good = true;
            inner.policy_fail = None;
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
            note_policy_failure(inner, &err.to_string());
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
    }
}

fn note_policy_failure(inner: &mut Inner, sentence: &str) {
    if inner.policy_fail.as_deref() == Some(sentence) {
        return;
    }
    println!("policy load failed: {sentence}");
    inner.policy_fail = Some(sentence.to_string());
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
    let issued = inner.ca.issue(&id, now, MAX_USER_TTL, &DenySet::empty())?;
    let stored = inner
        .store
        .commit(plan, issued.spiffe_id.as_uri().to_string(), now)?;
    let view = sign_view(inner, &stored.name)?;
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
    })
}

fn sign_view(inner: &Inner, name: &str) -> Result<NetmapView, CoordError> {
    let nodes = inner.store.nodes();
    let self_node = nodes
        .iter()
        .find(|node| node.name == name)
        .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
    let mut peers = Vec::new();
    let mut endpoints = Vec::new();
    for node in &nodes {
        for endpoint in &node.endpoints {
            endpoints.push(inner.netmap_key.sign_endpoint(&node.name, endpoint)?);
        }
        if node.name == self_node.name {
            continue;
        }
        peers.push(NetmapPeer {
            name: node.name.clone(),
            overlay_ip: node.overlay_ip.clone(),
            svid: node.svid.clone(),
            endpoints: node.endpoints.clone(),
            routes: published_routes(&inner.policy, &node.svid, &node.routes),
        });
    }
    let payload = Netmap {
        version: 1,
        self_node: NetmapSelf {
            name: self_node.name.clone(),
            overlay_ip: self_node.overlay_ip.clone(),
        },
        peers,
    };
    let signed_netmap = inner.netmap_key.sign_netmap(&payload)?;
    let receiver = SpiffeId::node(&self_node.name)?;
    let signed_grants = inner
        .netmap_key
        .sign_grants(&inner.policy.receiver_grants(&receiver))?;
    let netmap_public = inner.netmap_key.public();
    verify_signed_netmap(&signed_netmap, &netmap_public)?;
    verify_signed_grants(&signed_grants, &netmap_public)?;
    for endpoint in &endpoints {
        verify_signed_endpoint(endpoint, &netmap_public)?;
    }
    let approved_routes = published_routes(&inner.policy, &self_node.svid, &self_node.routes);
    Ok(NetmapView {
        signed_netmap,
        signed_grants,
        endpoints,
        netmap_public,
        approved_routes,
        advertised_routes: self_node.routes.clone(),
    })
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

fn owner_from_oidc(
    oidc: &OidcState,
    id_token: &str,
    nonce: Option<&str>,
    now: SystemTime,
) -> Result<String, CoordError> {
    match oidc {
        OidcState::TokenOnly => Err(CoordError::Oidc),
        OidcState::Mock(gate) => gate
            .owner_subject(id_token, nonce, now)
            .map_err(|_| CoordError::Oidc),
        OidcState::Google { client_id, jwks } => {
            let jwks = jwks.as_ref().ok_or(CoordError::Oidc)?;
            let nonce = nonce.ok_or(CoordError::Oidc)?;
            jwks.verify(id_token, client_id, nonce, now)
                .map(|claims| claims.subject)
                .map_err(|_| CoordError::Oidc)
        }
    }
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
        )
    }
}

impl NetmapView {
    pub fn write_state(&self, dir: &Path) -> Result<(), CoordError> {
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
    let netmap_text = serde_json::to_string(&netmap.netmap)
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

#[cfg(test)]
mod tests {
    use super::oidc_config;
    use super::OidcConfig;

    #[test]
    fn blank_google_client_id_is_token_only() {
        let blank = oidc_config(orblx_identity::OidcMode::Google, Some("   ".to_string())).unwrap();
        let missing = oidc_config(orblx_identity::OidcMode::Google, None).unwrap();
        assert!(matches!(blank, OidcConfig::TokenOnly));
        assert!(matches!(missing, OidcConfig::TokenOnly));
    }
}
