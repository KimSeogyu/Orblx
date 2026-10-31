//! SSH user certificates (W25-31).
//!
//! The coordinator issues one OpenSSH ed25519 user certificate to a node over the mTLS session
//! of that node. The node SVID authenticates the request. The certificate names the user who
//! owns the node in the coordinator store. The request does not name the user.
//!
//! The request holds an SSH public key and an SSHSIG by that key (namespace
//! [`SSH_CERT_NAMESPACE`]). The signed message is the TLS exporter of the same connection
//! ([`SSH_EXPORTER_LABEL`], 32 bytes) and a single-use nonce from the coordinator.
//! Thus a signature from a different connection, or a used nonce, gets a deny.
//!
//! The SSH user CA key is not the SVID CA key and not the ticket key.
//! The coordinator keeps two CA keys: the current key signs, and the next key is in the netmap
//! before it becomes current. Each [`SSH_CA_ROTATE_SECS`] the next key becomes current and the
//! old key leaves the netmap at once.
//!
//! The crypto and the certificate format come from the `ssh-key` crate.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::SystemTime;

use orblx_identity::{Policy, SpiffeId, WorkloadKind};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{HashAlg, PrivateKey, PublicKey, SshSig};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::netmap::{decode_hex_32, encode_hex};
use crate::store::{StoredNode, UserState};

/// The SSHSIG namespace of one certificate request.
pub const SSH_CERT_NAMESPACE: &str = "cert-request@orblx";

/// The TLS exporter label of one certificate request.
pub const SSH_EXPORTER_LABEL: &[u8] = b"EXPORTER-orblx-ssh-cert-v1";

/// The TLS exporter length in bytes.
pub const SSH_EXPORTER_LEN: usize = 32;

/// The longest life of one certificate in seconds (15 min).
pub const SSH_CERT_MAX_LIFE_SECS: u64 = 900;

/// The certificate starts this many seconds before the issue time, for clock skew.
pub const SSH_CERT_BACKDATE_SECS: u64 = 60;

/// The time between two CA key rotations in seconds (24 h).
pub const SSH_CA_ROTATE_SECS: u64 = 86_400;

/// The life of one request nonce in seconds.
pub const SSH_NONCE_LIFE_SECS: u64 = 60;

/// The most open nonces. An old nonce leaves first.
const MAX_NONCES: usize = 4096;

/// The most live certificates in the index.
const MAX_LIVE: usize = 8192;

/// The CA key file. Mode 0600 in the private coordinator state directory.
pub const SSH_CA_FILE: &str = "ssh-user-ca.json";

/// The serial counter, the live index, and the revoked list.
pub const SSH_CERTS_FILE: &str = "ssh-certs.json";

/// Why the coordinator refused one certificate request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshDeny {
    /// The peer has an agent SVID. Agents get no SSH certificate.
    AgentSvid,
    /// The peer has a coordinator SVID.
    CoordSvid,
    /// The peer has a user SVID. Only a node SVID can ask.
    UserSvid,
    /// The nonce is unknown, used, too old, or from another connection.
    Nonce,
    /// The SSH public key or the SSHSIG is not valid.
    Signature,
    /// The node is not in the store.
    NodeUnknown,
    /// The node SVID is in the deny list.
    NodeRevoked,
    /// The node waits for approval.
    NodeNotApproved,
    /// The node is expired.
    NodeExpired,
    /// The node has no user owner (for example a token node).
    NoOwner,
    /// The owner waits for approval.
    UserPending,
    /// An owner rejected the user.
    UserRejected,
    /// The user SPIFFE ID is in the deny list.
    UserRevoked,
    /// No SSH policy rule names the user as a source.
    NoGrant,
}

impl SshDeny {
    /// The stable reason token for the audit record and the reply.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentSvid => "agent-svid",
            Self::CoordSvid => "coord-svid",
            Self::UserSvid => "user-svid",
            Self::Nonce => "nonce",
            Self::Signature => "signature",
            Self::NodeUnknown => "node-unknown",
            Self::NodeRevoked => "node-revoked",
            Self::NodeNotApproved => "node-not-approved",
            Self::NodeExpired => "node-expired",
            Self::NoOwner => "no-owner",
            Self::UserPending => "user-pending",
            Self::UserRejected => "user-rejected",
            Self::UserRevoked => "user-revoked",
            Self::NoGrant => "no-grant",
        }
    }
}

/// The message that the node signs: the TLS exporter and the nonce.
#[must_use]
pub fn signed_message(exporter: &[u8; SSH_EXPORTER_LEN], nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SSH_EXPORTER_LEN + 32);
    message.extend_from_slice(exporter);
    message.extend_from_slice(nonce);
    message
}

/// Sign one certificate request with the SSH private key of the node (client side).
pub fn sign_request(
    key: &PrivateKey,
    exporter: &[u8; SSH_EXPORTER_LEN],
    nonce: &[u8; 32],
) -> Result<String, CoordError> {
    let signature = key
        .sign(
            SSH_CERT_NAMESPACE,
            HashAlg::Sha512,
            &signed_message(exporter, nonce),
        )
        .map_err(|_| CoordError::Protocol("The SSH request did not sign.".to_string()))?;
    signature
        .to_pem(ssh_key::LineEnding::LF)
        .map_err(|_| CoordError::Protocol("The SSH request did not sign.".to_string()))
}

/// Check the SSHSIG of one request. Return the SSH public key.
///
/// The key must be ed25519. The SSHSIG must be by that key, in the namespace
/// [`SSH_CERT_NAMESPACE`], over the exporter of this connection and the nonce.
pub fn verify_request(
    public_key: &str,
    sshsig_pem: &str,
    exporter: &[u8; SSH_EXPORTER_LEN],
    nonce: &[u8; 32],
) -> Result<PublicKey, SshDeny> {
    if public_key.len() > 512 || sshsig_pem.len() > 4096 {
        return Err(SshDeny::Signature);
    }
    let key = PublicKey::from_openssh(public_key).map_err(|_| SshDeny::Signature)?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(SshDeny::Signature);
    }
    let signature = SshSig::from_pem(sshsig_pem).map_err(|_| SshDeny::Signature)?;
    if signature.public_key() != key.key_data() {
        return Err(SshDeny::Signature);
    }
    key.verify(
        SSH_CERT_NAMESPACE,
        &signed_message(exporter, nonce),
        &signature,
    )
    .map_err(|_| SshDeny::Signature)?;
    Ok(key)
}

/// Single-use request nonces. Each nonce belongs to one connection.
#[derive(Default)]
pub struct NonceBook {
    open: HashMap<[u8; 32], (u64, u64)>,
}

impl NonceBook {
    /// Make one nonce for the connection `connection` at `now_unix`.
    pub fn issue(&mut self, connection: u64, now_unix: u64) -> [u8; 32] {
        self.open.retain(|_, (_, expires)| *expires > now_unix);
        while self.open.len() >= MAX_NONCES {
            let oldest = self
                .open
                .iter()
                .min_by_key(|(_, (_, expires))| *expires)
                .map(|(nonce, _)| *nonce);
            match oldest {
                Some(nonce) => {
                    self.open.remove(&nonce);
                }
                None => break,
            }
        }
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.open.insert(
            nonce,
            (connection, now_unix.saturating_add(SSH_NONCE_LIFE_SECS)),
        );
        nonce
    }

    /// Use one nonce. Return true only one time, on the same connection, before it expires.
    pub fn take(&mut self, connection: u64, nonce: &[u8; 32], now_unix: u64) -> bool {
        match self.open.remove(nonce) {
            Some((owner, expires)) => owner == connection && now_unix < expires,
            None => false,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct CaKeyRecord {
    seed_hex: String,
    created_unix: u64,
}

#[derive(Serialize, Deserialize)]
struct CaFile {
    version: u32,
    /// Index 0 is the current key. Index 1 is the next key.
    keys: Vec<CaKeyRecord>,
}

/// The SSH user CA: the current key and the next key.
pub struct SshCa {
    current: (PrivateKey, u64),
    next: (PrivateKey, u64),
}

fn key_from_seed(seed: &[u8; 32]) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(seed))
}

fn new_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

impl SshCa {
    /// Open the CA key file, or make two new keys.
    pub fn open(dir: &Path, now_unix: u64) -> Result<Self, CoordError> {
        let path = dir.join(SSH_CA_FILE);
        if !path.exists() {
            let file = CaFile {
                version: 1,
                keys: vec![
                    CaKeyRecord {
                        seed_hex: encode_hex(&new_seed()),
                        created_unix: now_unix,
                    },
                    CaKeyRecord {
                        seed_hex: encode_hex(&new_seed()),
                        created_unix: now_unix,
                    },
                ],
            };
            write_ca_file(&path, &file)?;
        }
        let file: CaFile =
            serde_json::from_str(&read_text(&path)?).map_err(|_| CoordError::State)?;
        if file.version != 1 || file.keys.len() != 2 {
            return Err(CoordError::State);
        }
        let load = |record: &CaKeyRecord| -> Result<(PrivateKey, u64), CoordError> {
            let seed = decode_hex_32(&record.seed_hex)?;
            Ok((key_from_seed(&seed), record.created_unix))
        };
        Ok(Self {
            current: load(&file.keys[0])?,
            next: load(&file.keys[1])?,
        })
    }

    /// Rotate when the current key is [`SSH_CA_ROTATE_SECS`] old. Return true on a rotation.
    ///
    /// The next key becomes current. A new next key is made. The old key leaves the netmap.
    pub fn rotate_due(&mut self, dir: &Path, now_unix: u64) -> Result<bool, CoordError> {
        if now_unix.saturating_sub(self.current.1) < SSH_CA_ROTATE_SECS {
            return Ok(false);
        }
        self.rotate(dir, now_unix)?;
        Ok(true)
    }

    /// Rotate now.
    pub fn rotate(&mut self, dir: &Path, now_unix: u64) -> Result<(), CoordError> {
        let seed = new_seed();
        let next = (key_from_seed(&seed), now_unix);
        let current = std::mem::replace(&mut self.next, next);
        let current = (current.0, now_unix);
        let file = CaFile {
            version: 1,
            keys: vec![
                CaKeyRecord {
                    seed_hex: encode_hex(&seed_of(&current.0)?),
                    created_unix: current.1,
                },
                CaKeyRecord {
                    seed_hex: encode_hex(&seed),
                    created_unix: now_unix,
                },
            ],
        };
        write_ca_file(&dir.join(SSH_CA_FILE), &file)?;
        self.current = current;
        Ok(())
    }

    /// The CA public keys for the netmap: the current key and then the next key.
    pub fn public_lines(&self) -> Result<Vec<String>, CoordError> {
        [&self.current.0, &self.next.0]
            .into_iter()
            .map(|key| {
                PublicKey::new(key.public_key().key_data().clone(), "")
                    .to_openssh()
                    .map(|line| line.trim().to_string())
                    .map_err(|_| CoordError::State)
            })
            .collect()
    }

    /// The current signing key.
    pub fn current(&self) -> &PrivateKey {
        &self.current.0
    }
}

fn seed_of(key: &PrivateKey) -> Result<[u8; 32], CoordError> {
    let pair = key.key_data().ed25519().ok_or(CoordError::State)?;
    Ok(pair.private.to_bytes())
}

fn write_ca_file(path: &Path, file: &CaFile) -> Result<(), CoordError> {
    let text = serde_json::to_string(file).map_err(|_| CoordError::State)?;
    write_text(path, &text, 0o600)
}

/// One live certificate in the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveCert {
    pub serial: u64,
    pub key_id: String,
    /// The node SVID URI.
    pub node: String,
    /// The owner principal, `oidc:SUBJECT`.
    pub owner: String,
    pub valid_before: u64,
}

/// One revoked certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedCert {
    pub serial: u64,
    pub key_id: String,
    pub valid_before: u64,
}

/// The serial counter, the index from (node, owner) to the live serials, and the revoked list.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CertBook {
    next_serial: u64,
    live: Vec<LiveCert>,
    revoked: Vec<RevokedCert>,
}

impl CertBook {
    /// Open the book, or start a new one.
    ///
    /// A new book starts the serial at the Unix time shifted left by 20 bits. Thus a lost book
    /// does not give a serial again.
    pub fn open(dir: &Path, now_unix: u64) -> Result<Self, CoordError> {
        let path = dir.join(SSH_CERTS_FILE);
        if !path.exists() {
            return Ok(Self {
                next_serial: now_unix << 20,
                live: Vec::new(),
                revoked: Vec::new(),
            });
        }
        serde_json::from_str(&read_text(&path)?).map_err(|_| CoordError::State)
    }

    /// Write the book (mode 0600).
    pub fn save(&self, dir: &Path) -> Result<(), CoordError> {
        let text = serde_json::to_string(self).map_err(|_| CoordError::State)?;
        write_text(&dir.join(SSH_CERTS_FILE), &text, 0o600)
    }

    /// Take the next serial.
    pub fn take_serial(&mut self) -> u64 {
        let serial = self.next_serial.max(1);
        self.next_serial = serial.wrapping_add(1);
        serial
    }

    /// Add one issued certificate to the index.
    pub fn add_live(&mut self, cert: LiveCert, now_unix: u64) {
        self.prune(now_unix);
        if self.live.len() >= MAX_LIVE {
            self.live.remove(0);
        }
        self.live.push(cert);
    }

    /// The live serials of one (node, owner) pair.
    #[must_use]
    pub fn live_serials(&self, node: &str, owner: &str) -> Vec<u64> {
        self.live
            .iter()
            .filter(|cert| cert.node == node && cert.owner == owner)
            .map(|cert| cert.serial)
            .collect()
    }

    /// Remove the entries that expired more than one backdate period ago.
    pub fn prune(&mut self, now_unix: u64) {
        let keep =
            |valid_before: u64| valid_before.saturating_add(SSH_CERT_BACKDATE_SECS) > now_unix;
        self.live.retain(|cert| keep(cert.valid_before));
        self.revoked.retain(|cert| keep(cert.valid_before));
    }

    /// Move each live certificate of a revoked pair to the revoked list.
    ///
    /// `revoked(node, owner)` is true when the node or the owner is revoked.
    /// Return true when the book changed.
    pub fn sweep(&mut self, now_unix: u64, revoked: impl Fn(&LiveCert) -> bool) -> bool {
        let before = (self.live.len(), self.revoked.len());
        self.prune(now_unix);
        let mut kept = Vec::new();
        for cert in std::mem::take(&mut self.live) {
            if revoked(&cert) {
                self.revoked.push(RevokedCert {
                    serial: cert.serial,
                    key_id: cert.key_id,
                    valid_before: cert.valid_before,
                });
            } else {
                kept.push(cert);
            }
        }
        self.live = kept;
        before != (self.live.len(), self.revoked.len())
    }

    /// The revoked set for the netmap: the stored list and the live entries of revoked pairs.
    #[must_use]
    pub fn revoked_set(
        &self,
        now_unix: u64,
        revoked: impl Fn(&LiveCert) -> bool,
    ) -> Vec<orblx_datapath::SshRevoked> {
        let keep =
            |valid_before: u64| valid_before.saturating_add(SSH_CERT_BACKDATE_SECS) > now_unix;
        let mut out: BTreeMap<u64, String> = BTreeMap::new();
        for cert in self.revoked.iter().filter(|cert| keep(cert.valid_before)) {
            out.insert(cert.serial, cert.key_id.clone());
        }
        for cert in self
            .live
            .iter()
            .filter(|cert| keep(cert.valid_before) && revoked(cert))
        {
            out.insert(cert.serial, cert.key_id.clone());
        }
        out.into_iter()
            .take(orblx_datapath::MAX_SSH_REVOKED)
            .map(|(serial, key_id)| orblx_datapath::SshRevoked { serial, key_id })
            .collect()
    }
}

/// The user SPIFFE ID of one owner principal `oidc:SUBJECT`.
#[must_use]
pub fn owner_user_id(owner: &str) -> Option<SpiffeId> {
    let subject = owner.strip_prefix("oidc:")?;
    SpiffeId::user(subject).ok()
}

/// The coordinator facts for one decision.
pub struct IssueFacts<'a> {
    pub nodes: &'a [StoredNode],
    pub user_state: &'a dyn Fn(&str) -> Option<UserState>,
    pub revoked_uris: &'a BTreeSet<String>,
    pub policy: &'a Policy,
}

/// The facts of one allowed request.
#[derive(Debug, Clone)]
pub struct Granted {
    pub node: StoredNode,
    pub owner: String,
    pub rule: usize,
}

/// Decide one request after the nonce and the SSHSIG checks.
///
/// The owner comes from the coordinator store: the owner of the node of the peer SVID.
/// The request body, the target node, and a share record do not change it.
pub fn decide(peer: &SpiffeId, facts: &IssueFacts<'_>) -> Result<Granted, SshDeny> {
    peer_kind(peer)?;
    let node = facts
        .nodes
        .iter()
        .find(|node| node.name == peer.name() && node.svid == peer.as_uri())
        .ok_or(SshDeny::NodeUnknown)?;
    if facts.revoked_uris.contains(peer.as_uri()) {
        return Err(SshDeny::NodeRevoked);
    }
    if !node.approved {
        return Err(SshDeny::NodeNotApproved);
    }
    if node.expired {
        return Err(SshDeny::NodeExpired);
    }
    let user = owner_user_id(&node.owner).ok_or(SshDeny::NoOwner)?;
    match (facts.user_state)(&node.owner) {
        Some(UserState::Approved) => {}
        Some(UserState::Rejected) => return Err(SshDeny::UserRejected),
        Some(UserState::Pending) | None => return Err(SshDeny::UserPending),
    }
    if facts.revoked_uris.contains(user.as_uri()) {
        return Err(SshDeny::UserRevoked);
    }
    let rule = facts
        .policy
        .ssh_rule_for_source(&user)
        .ok_or(SshDeny::NoGrant)?;
    Ok(Granted {
        node: node.clone(),
        owner: node.owner.clone(),
        rule,
    })
}

/// Refuse a peer that is not a node.
pub fn peer_kind(peer: &SpiffeId) -> Result<(), SshDeny> {
    match peer.kind() {
        WorkloadKind::Node => Ok(()),
        WorkloadKind::Agent => Err(SshDeny::AgentSvid),
        WorkloadKind::Coord => Err(SshDeny::CoordSvid),
        WorkloadKind::User => Err(SshDeny::UserSvid),
    }
}

/// One issued certificate.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// The certificate in OpenSSH text.
    pub text: String,
    pub serial: u64,
    pub key_id: String,
    /// The SHA-256 fingerprint of the certified key.
    pub fingerprint: String,
    pub valid_after: u64,
    pub valid_before: u64,
}

/// Make and sign one user certificate.
///
/// - principal: the owner of the node.
/// - key ID: the node SVID URI, the owner, and the serial.
/// - valid after: now - [`SSH_CERT_BACKDATE_SECS`].
/// - valid before: the earlier of now + [`SSH_CERT_MAX_LIFE_SECS`] and the node SVID end.
/// - extensions: `permit-pty` only.
/// - critical option `source-address`: the overlay address of the node only.
pub fn build_cert(
    ca: &PrivateKey,
    subject: &PublicKey,
    granted: &Granted,
    serial: u64,
    svid_not_after: u64,
    now_unix: u64,
) -> Result<IssuedCert, CoordError> {
    let bad = || CoordError::Protocol("The SSH certificate was not made.".to_string());
    let valid_after = now_unix.saturating_sub(SSH_CERT_BACKDATE_SECS);
    let valid_before = now_unix
        .saturating_add(SSH_CERT_MAX_LIFE_SECS)
        .min(svid_not_after);
    if valid_before <= now_unix {
        return Err(CoordError::Protocol(
            "The node SVID ends too soon for an SSH certificate.".to_string(),
        ));
    }
    let overlay: std::net::Ipv4Addr = granted.node.overlay_ip.parse().map_err(|_| bad())?;
    let key_id = orblx_datapath::ssh_key_id(&granted.node.svid, &granted.owner, serial);
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut builder = Builder::new(
        nonce.to_vec(),
        subject.key_data().clone(),
        valid_after,
        valid_before,
    )
    .map_err(|_| bad())?;
    builder
        .serial(serial)
        .and_then(|builder| builder.cert_type(CertType::User))
        .and_then(|builder| builder.key_id(key_id.clone()))
        .and_then(|builder| builder.valid_principal(granted.owner.clone()))
        .and_then(|builder| builder.critical_option("source-address", format!("{overlay}/32")))
        .and_then(|builder| builder.extension("permit-pty", ""))
        .map_err(|_| bad())?;
    let cert = builder.sign(ca).map_err(|_| bad())?;
    let text = cert.to_openssh().map_err(|_| bad())?;
    Ok(IssuedCert {
        text,
        serial,
        key_id,
        fingerprint: subject.fingerprint(HashAlg::Sha256).to_string(),
        valid_after,
        valid_before,
    })
}

/// Make one new ed25519 key for one certificate login (client side). The key stays in memory.
#[must_use]
pub fn new_session_key() -> PrivateKey {
    key_from_seed(&new_seed())
}

/// Return the Unix time in seconds.
pub fn unix_secs(now: SystemTime) -> Result<u64, CoordError> {
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoordError::Time)
}
