//! Overlay session state for a NAT path.
//!
//! The session id and the send counter stay in place when the path changes.
//! Direct and relay carry the same sealed frames.
//! The hello frame carries the X.509-SVID of the sender.
//! The receiver checks the SVID against the trust bundle before it uses the key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use orblx_identity::{leaf_ed25519_public_key, leaf_not_after, DenySet, TrustBundle};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::punch::PunchToken;
use crate::EdgeError;

/// A direct UDP path or the orblx Relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayPath {
    /// The punched UDP path.
    Direct,
    /// The orblx Relay path.
    Relay,
}

impl OverlayPath {
    /// The status word for this path.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// Silence that moves an active direct path to relay.
///
/// Each path sends a probe each 100 ms.
/// Three lost probes in a row make the path stale.
pub const STALE_MS: u64 = 300;

/// The time between two probes on one path.
pub const PROBE_GAP_MS: u64 = 100;

/// After a move from relay to direct, the node sends each frame on both paths for this time.
///
/// The old path stays up until the new path carries traffic.
pub const OVERLAP_MS: u64 = 600;

/// After a move from direct to relay, the node sends again the frames from this window.
///
/// The receiver drops a copy that it already opened.
pub const RESEND_MS: u64 = STALE_MS + 2 * PROBE_GAP_MS;

/// The probe flag that tells the peer: "I receive your probes on this path."
pub const PROBE_HEARS: u8 = 1;

/// The wait after a move to relay before a direct upgrade.
pub const RELAY_HOLD_MS: u64 = 1_000;

/// Signed hello.
///
/// The payload is the X25519 public key, an Ed25519 signature, and the leaf SVID DER.
pub const KIND_HELLO: u8 = 1;
/// Encrypted probe. The frame does not enter the TUN device.
pub const KIND_PROBE: u8 = 2;
/// Encrypted IPv4 packet.
pub const KIND_DATA: u8 = 3;

const MAGIC: &[u8; 8] = b"ORBLXNAT";
const VERSION: u8 = 1;
const HEADER: usize = 26;
const HELLO_CONTEXT: &[u8] = b"orblx-nat-hello-v1\n";
const HELLO_FIXED: usize = 32 + 64;
const HELLO_DER_MAX: usize = 2048;

/// The path choice for one overlay session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathSelect {
    /// The path that carries TUN packets.
    pub current: Option<OverlayPath>,
    /// Direct stays idle until this monotonic time.
    pub relay_hold_until_ms: u64,
    /// The relay also carries each frame until this monotonic time.
    pub overlap_until_ms: u64,
}

/// The paths that get one sealed frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPlan {
    /// No path is up. The node holds the packet.
    Hold,
    /// Only the direct path.
    Direct,
    /// Only the relay path.
    Relay,
    /// The direct path and the relay path.
    ///
    /// The receiver opens the first copy and drops the second copy.
    Both,
}

impl SendPlan {
    /// Return true when the plan uses the direct path.
    #[must_use]
    pub const fn uses_direct(self) -> bool {
        matches!(self, Self::Direct | Self::Both)
    }

    /// Return true when the plan uses the relay path.
    #[must_use]
    pub const fn uses_relay(self) -> bool {
        matches!(self, Self::Relay | Self::Both)
    }
}

impl PathSelect {
    /// The send plan at `now_ms`.
    ///
    /// Make before break: after a move to direct, the relay also carries frames for [`OVERLAP_MS`].
    #[must_use]
    pub fn plan(&self, now_ms: u64) -> SendPlan {
        match self.current {
            None => SendPlan::Hold,
            Some(OverlayPath::Relay) => SendPlan::Relay,
            Some(OverlayPath::Direct) if now_ms < self.overlap_until_ms => SendPlan::Both,
            Some(OverlayPath::Direct) => SendPlan::Direct,
        }
    }
}

/// Return true when the relay may carry TUN packets.
///
/// The first direct attempt keeps the relay idle.
/// After that attempt fails, the relay may carry packets.
/// After a direct path has been up, the relay may carry packets when direct is silent.
#[must_use]
pub fn relay_allowed(saw_direct: bool, direct_ok: bool, budget_done: bool) -> bool {
    !direct_ok && (saw_direct || budget_done)
}

/// Choose the path that carries the overlay session.
///
/// `direct_ok` means recent probes went both ways on the direct path.
/// `relay_ok` means recent probes went both ways on the relay path.
/// `relay_allowed` is false during the first direct attempt.
/// A move from direct to relay sets a hold.
/// The hold keeps the session on relay until the hold time.
/// A move from relay to direct starts an overlap window.
/// The function does not change a session id.
pub fn select_path(
    state: &mut PathSelect,
    direct_ok: bool,
    relay_ok: bool,
    relay_allowed: bool,
    now_ms: u64,
) -> Option<OverlayPath> {
    let next = match state.current {
        Some(OverlayPath::Direct) if direct_ok => Some(OverlayPath::Direct),
        Some(OverlayPath::Direct) => {
            state.relay_hold_until_ms = now_ms.saturating_add(RELAY_HOLD_MS);
            if relay_ok && relay_allowed {
                Some(OverlayPath::Relay)
            } else {
                None
            }
        }
        Some(OverlayPath::Relay) if direct_ok && now_ms >= state.relay_hold_until_ms => {
            if relay_ok {
                state.overlap_until_ms = now_ms.saturating_add(OVERLAP_MS);
            }
            Some(OverlayPath::Direct)
        }
        Some(OverlayPath::Relay) if relay_ok || !direct_ok => Some(OverlayPath::Relay),
        Some(OverlayPath::Relay) => Some(OverlayPath::Direct),
        None if direct_ok => Some(OverlayPath::Direct),
        None if relay_ok && relay_allowed => Some(OverlayPath::Relay),
        current => current,
    };
    state.current = next;
    next
}

/// The stable id for the pair of node names.
///
/// The order of the names does not change the id.
pub fn session_id(left: &str, right: &str) -> Result<[u8; 16], EdgeError> {
    if !valid_name(left) || !valid_name(right) || left == right {
        return Err(EdgeError::BadCandidate);
    }
    let (first, second) = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"orblx-nat-session-v1\n");
    hasher.update(first.as_bytes());
    hasher.update(b"\n");
    hasher.update(second.as_bytes());
    hasher.update(b"\n");
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(id)
}

/// The punch token for one overlay session.
#[must_use]
pub fn session_punch_token(session: &[u8; 16]) -> PunchToken {
    let mut token = [0u8; 8];
    token.copy_from_slice(&session[..8]);
    PunchToken::from_bytes(token)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn hello_message(session: &[u8; 16], public_key: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(HELLO_CONTEXT.len() + 48);
    message.extend_from_slice(HELLO_CONTEXT);
    message.extend_from_slice(session);
    message.extend_from_slice(public_key);
    message
}

/// The SVID material that signs and checks a hello.
///
/// The value does not print the signing key.
pub struct HelloAuth {
    /// The local leaf SVID DER.
    pub cert_der: Vec<u8>,
    /// The local leaf SVID key.
    pub signing: SigningKey,
    /// The trust bundle that issued the peer SVID.
    pub bundle: TrustBundle,
    /// The SPIFFE ID that the peer SVID must contain.
    pub peer_svid: String,
}

impl HelloAuth {
    /// Build the material from the leaf DER and the Ed25519 seed of the leaf key.
    ///
    /// The caller must not log the seed.
    #[must_use]
    pub fn new(cert_der: Vec<u8>, seed: &[u8; 32], bundle: TrustBundle, peer_svid: &str) -> Self {
        Self {
            cert_der,
            signing: SigningKey::from_bytes(seed),
            bundle,
            peer_svid: peer_svid.to_string(),
        }
    }
}

impl std::fmt::Debug for HelloAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HelloAuth")
            .field("peer_svid", &self.peer_svid)
            .finish_non_exhaustive()
    }
}

/// One result from a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// The peer public key is stored.
    Hello,
    /// A probe opened. The value is the probe flag byte.
    Probe(u8),
    /// One IPv4 packet.
    Data(Vec<u8>),
}

/// Keys and counters for one overlay session.
///
/// The path does not own this value.
/// A path switch keeps the same value.
pub struct KeyGate {
    session: [u8; 16],
    local_name: String,
    peer_name: String,
    secret: StaticSecret,
    public_key: [u8; 32],
    auth: HelloAuth,
    peer_public: Option<[u8; 32]>,
    peer_not_after: Option<u64>,
    /// The peer leaf DER of the last hello that set `peer_not_after`.
    peer_der: Option<Vec<u8>>,
    key: Option<[u8; 32]>,
    send_counter: u64,
    replay: Replay,
}

impl std::fmt::Debug for KeyGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyGate")
            .field("ready", &self.key.is_some())
            .field("send_counter", &self.send_counter)
            .finish()
    }
}

impl KeyGate {
    /// Draw an X25519 key for this session.
    ///
    /// `auth` signs the local hello and checks the peer hello.
    pub fn generate(
        session: [u8; 16],
        local_name: &str,
        peer_name: &str,
        auth: HelloAuth,
    ) -> Result<Self, EdgeError> {
        if !valid_name(local_name) || !valid_name(peer_name) {
            return Err(EdgeError::BadCandidate);
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|err| EdgeError::Io(err.to_string()))?;
        let secret = StaticSecret::from(seed);
        let public_key = PublicKey::from(&secret).to_bytes();
        Ok(Self {
            session,
            local_name: local_name.to_string(),
            peer_name: peer_name.to_string(),
            secret,
            public_key,
            auth,
            peer_public: None,
            peer_not_after: None,
            peer_der: None,
            key: None,
            send_counter: 0,
            replay: Replay::default(),
        })
    }

    /// The signed hello frame for this session.
    #[must_use]
    pub fn hello_frame(&self) -> Vec<u8> {
        let signature = self
            .auth
            .signing
            .sign(&hello_message(&self.session, &self.public_key));
        let mut frame = Vec::with_capacity(HEADER + HELLO_FIXED + self.auth.cert_der.len());
        push_header(&mut frame, KIND_HELLO, &self.session);
        frame.extend_from_slice(&self.public_key);
        frame.extend_from_slice(&signature.to_bytes());
        frame.extend_from_slice(&self.auth.cert_der);
        frame
    }

    /// Use a renewed local leaf SVID for the next hello frames.
    ///
    /// The X25519 key and the counters do not change.
    /// The caller must not log the seed.
    pub fn set_leaf(&mut self, cert_der: Vec<u8>, seed: &[u8; 32]) {
        self.auth.cert_der = cert_der;
        self.auth.signing = SigningKey::from_bytes(seed);
    }

    /// The `not_after` time of the peer SVID as Unix seconds.
    ///
    /// The value is `None` until a signed peer hello is checked.
    #[must_use]
    pub fn peer_not_after(&self) -> Option<u64> {
        self.peer_not_after
    }

    fn check_hello(&mut self, body: &[u8]) -> Result<[u8; 32], EdgeError> {
        if body.len() <= HELLO_FIXED || body.len() > HELLO_FIXED + HELLO_DER_MAX {
            return Err(hello_error());
        }
        let mut peer = [0u8; 32];
        peer.copy_from_slice(&body[..32]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&body[32..HELLO_FIXED]);
        let der = &body[HELLO_FIXED..];
        // The same key and the same leaf were checked before.
        // A renewed leaf has a different DER, so the node checks it again.
        if self.peer_public == Some(peer) && self.peer_der.as_deref() == Some(der) {
            return Ok(peer);
        }
        let id = self
            .auth
            .bundle
            .authenticate_leaf(der, std::time::SystemTime::now(), &DenySet::empty())
            .map_err(|_| hello_error())?;
        if id.as_uri() != self.auth.peer_svid {
            return Err(hello_error());
        }
        let leaf_key = leaf_ed25519_public_key(der).map_err(|_| hello_error())?;
        let verifying = VerifyingKey::from_bytes(&leaf_key).map_err(|_| hello_error())?;
        verifying
            .verify_strict(
                &hello_message(&self.session, &peer),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| hello_error())?;
        let not_after = leaf_not_after(der).map_err(|_| hello_error())?;
        // For the same key, an older leaf does not move the expiry back.
        // This stops a replay of an old hello.
        let same_key = self.peer_public == Some(peer);
        if !same_key
            || self
                .peer_not_after
                .is_none_or(|current| not_after >= current)
        {
            self.peer_not_after = Some(not_after);
            self.peer_der = Some(der.to_vec());
        }
        Ok(peer)
    }

    /// The session id.
    #[cfg(test)]
    fn session(&self) -> [u8; 16] {
        self.session
    }

    /// Frames sealed so far.
    #[cfg(test)]
    fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Return true after the peer public key is stored.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.key.is_some()
    }

    /// Store the peer public key and derive the session key.
    ///
    /// The same public key does not reset the send counter.
    fn absorb_peer(&mut self, peer: &[u8; 32]) -> Result<(), EdgeError> {
        if self.peer_public.as_ref() == Some(peer) {
            return Ok(());
        }
        if self.peer_public.is_some() {
            self.send_counter = 0;
            self.replay = Replay::default();
        }
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        let hk = Hkdf::<Sha256>::new(Some(&self.session), shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"orblx-nat-v1", &mut key)
            .map_err(|_| EdgeError::BadCandidate)?;
        self.peer_public = Some(*peer);
        self.key = Some(key);
        Ok(())
    }

    /// Seal a probe or a data packet.
    pub fn seal(&mut self, kind: u8, plain: &[u8]) -> Result<Vec<u8>, EdgeError> {
        if kind != KIND_PROBE && kind != KIND_DATA {
            return Err(EdgeError::BadCandidate);
        }
        let key = self.key.ok_or(EdgeError::WrongState)?;
        let counter = self
            .send_counter
            .checked_add(1)
            .ok_or(EdgeError::WrongState)?;
        self.send_counter = counter;
        let direction = direction_bit(&self.local_name, &self.peer_name);
        let cipher_text = seal_bytes(&key, direction, counter, &self.session, kind, plain)?;
        Ok(encode_sealed(kind, &self.session, counter, &cipher_text))
    }

    /// Open one frame.
    ///
    /// `Ok(None)` means the frame is a replay or it is not for this session.
    /// The caller ignores that result.
    pub fn open_frame(&mut self, frame: &[u8]) -> Result<Option<Opened>, EdgeError> {
        let Some(parsed) = parse_frame(frame)? else {
            return Ok(None);
        };
        if parsed.session != self.session {
            return Ok(None);
        }
        match parsed.kind {
            KIND_HELLO => {
                let peer = self.check_hello(&parsed.body)?;
                self.absorb_peer(&peer)?;
                Ok(Some(Opened::Hello))
            }
            KIND_PROBE | KIND_DATA => {
                let key = self.key.ok_or(EdgeError::WrongState)?;
                if parsed.body.len() < 8 {
                    return Err(EdgeError::BadCandidate);
                }
                let counter = u64::from_be_bytes(parsed.body[..8].try_into().unwrap_or([0; 8]));
                let direction = direction_bit(&self.peer_name, &self.local_name);
                let plain = open_bytes(
                    &key,
                    direction,
                    counter,
                    &self.session,
                    parsed.kind,
                    &parsed.body[8..],
                )?;
                if !self.replay.accept(counter) {
                    return Ok(None);
                }
                if parsed.kind == KIND_PROBE {
                    Ok(Some(Opened::Probe(plain.first().copied().unwrap_or(0))))
                } else {
                    Ok(Some(Opened::Data(plain)))
                }
            }
            _ => Err(EdgeError::BadCandidate),
        }
    }
}

fn hello_error() -> EdgeError {
    EdgeError::Identity("The peer hello is not valid.".to_string())
}

struct ParsedFrame {
    kind: u8,
    session: [u8; 16],
    body: Vec<u8>,
}

fn parse_frame(frame: &[u8]) -> Result<Option<ParsedFrame>, EdgeError> {
    if frame.len() < HEADER || &frame[..8] != MAGIC {
        return Ok(None);
    }
    if frame[8] != VERSION {
        return Err(EdgeError::BadCandidate);
    }
    let mut session = [0u8; 16];
    session.copy_from_slice(&frame[10..26]);
    Ok(Some(ParsedFrame {
        kind: frame[9],
        session,
        body: frame[HEADER..].to_vec(),
    }))
}

fn push_header(frame: &mut Vec<u8>, kind: u8, session: &[u8; 16]) {
    frame.extend_from_slice(MAGIC);
    frame.push(VERSION);
    frame.push(kind);
    frame.extend_from_slice(session);
}

fn encode_sealed(kind: u8, session: &[u8; 16], counter: u64, cipher_text: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER + 8 + cipher_text.len());
    push_header(&mut frame, kind, session);
    frame.extend_from_slice(&counter.to_be_bytes());
    frame.extend_from_slice(cipher_text);
    frame
}

fn direction_bit(sender: &str, receiver: &str) -> u8 {
    if sender < receiver {
        0
    } else {
        1
    }
}

fn nonce_bytes(direction: u8, counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn aad(session: &[u8; 16], kind: u8, counter: u64) -> [u8; 25] {
    let mut out = [0u8; 25];
    out[..16].copy_from_slice(session);
    out[16] = kind;
    out[17..].copy_from_slice(&counter.to_be_bytes());
    out
}

fn seal_bytes(
    key: &[u8; 32],
    direction: u8,
    counter: u64,
    session: &[u8; 16],
    kind: u8,
    plain: &[u8],
) -> Result<Vec<u8>, EdgeError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| EdgeError::BadCandidate)?;
    let nonce = nonce_bytes(direction, counter);
    let extra = aad(session, kind, counter);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &extra,
            },
        )
        .map_err(|_| EdgeError::BadCandidate)
}

fn open_bytes(
    key: &[u8; 32],
    direction: u8,
    counter: u64,
    session: &[u8; 16],
    kind: u8,
    cipher_text: &[u8],
) -> Result<Vec<u8>, EdgeError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| EdgeError::BadCandidate)?;
    let nonce = nonce_bytes(direction, counter);
    let extra = aad(session, kind, counter);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: cipher_text,
                aad: &extra,
            },
        )
        .map_err(|_| EdgeError::BadCandidate)
}

#[derive(Debug, Default)]
struct Replay {
    highest: u64,
    bits: u128,
}

impl Replay {
    fn accept(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if self.highest == 0 {
            self.highest = counter;
            self.bits = 1;
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.bits = if shift >= 128 {
                1
            } else {
                (self.bits << shift) | 1
            };
            self.highest = counter;
            return true;
        }
        let back = self.highest - counter;
        if back >= 128 {
            return false;
        }
        let mask = 1u128 << back;
        if self.bits & mask != 0 {
            return false;
        }
        self.bits |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use ed25519_dalek::SigningKey;
    use orblx_identity::{ed25519_seed_from_private_pem, DenySet, MiniCa, SpiffeId, TrustBundle};

    use super::{
        relay_allowed, select_path, session_id, HelloAuth, KeyGate, Opened, OverlayPath,
        PathSelect, SendPlan, KIND_DATA, KIND_PROBE, OVERLAP_MS, RELAY_HOLD_MS,
    };

    struct Lab {
        ca: MiniCa,
    }

    impl Lab {
        fn new() -> Self {
            Self {
                ca: MiniCa::generate(SystemTime::now()).unwrap(),
            }
        }

        fn auth(&self, local: &str, peer: &str) -> (HelloAuth, u64) {
            self.auth_for(local, peer, Duration::from_secs(600))
        }

        fn auth_for(&self, local: &str, peer: &str, life: Duration) -> (HelloAuth, u64) {
            let issued = self
                .ca
                .issue(
                    &SpiffeId::node(local).unwrap(),
                    SystemTime::now(),
                    life,
                    &DenySet::empty(),
                )
                .unwrap();
            let seed = ed25519_seed_from_private_pem(&issued.private_key_pem).unwrap();
            let auth = HelloAuth {
                cert_der: issued.certificate_der.clone(),
                signing: SigningKey::from_bytes(&seed),
                bundle: TrustBundle::from_pem(self.ca.trust_bundle_pem()).unwrap(),
                peer_svid: SpiffeId::node(peer).unwrap().as_uri().to_string(),
            };
            (auth, issued.not_after)
        }
    }

    fn gate(lab: &Lab, local: &str, peer: &str) -> (KeyGate, u64) {
        let id = session_id(local, peer).unwrap();
        let (auth, not_after) = lab.auth(local, peer);
        (KeyGate::generate(id, local, peer, auth).unwrap(), not_after)
    }

    fn pair() -> (KeyGate, KeyGate) {
        let lab = Lab::new();
        let (mut left, left_expiry) = gate(&lab, "node-x", "node-z");
        let (mut right, right_expiry) = gate(&lab, "node-z", "node-x");
        let hello_left = left.hello_frame();
        let hello_right = right.hello_frame();
        assert_eq!(right.open_frame(&hello_left).unwrap(), Some(Opened::Hello));
        assert_eq!(left.open_frame(&hello_right).unwrap(), Some(Opened::Hello));
        assert!(left.ready());
        assert!(right.ready());
        assert_eq!(left.peer_not_after(), Some(right_expiry));
        assert_eq!(right.peer_not_after(), Some(left_expiry));
        (left, right)
    }

    #[test]
    fn session_id_ignores_name_order() {
        let left = session_id("node-x", "node-z").unwrap();
        let right = session_id("node-z", "node-x").unwrap();
        assert_eq!(left, right);
        assert!(session_id("node-x", "node-x").is_err());
    }

    #[test]
    fn hello_from_the_wrong_svid_is_rejected() {
        let lab = Lab::new();
        let (mut right, _) = gate(&lab, "node-z", "node-x");
        // node-y signs a valid hello, but node-z expects node-x.
        let id = session_id("node-x", "node-z").unwrap();
        let (auth, _) = lab.auth("node-y", "node-z");
        let impostor = KeyGate::generate(id, "node-x", "node-z", auth).unwrap();
        assert!(right.open_frame(&impostor.hello_frame()).is_err());
        assert!(!right.ready());
        assert_eq!(right.peer_not_after(), None);
    }

    #[test]
    fn hello_from_another_ca_is_rejected() {
        let lab = Lab::new();
        let other = Lab::new();
        let (mut right, _) = gate(&lab, "node-z", "node-x");
        let (left, _) = gate(&other, "node-x", "node-z");
        assert!(right.open_frame(&left.hello_frame()).is_err());
        assert!(!right.ready());
    }

    #[test]
    fn hello_with_a_changed_key_is_rejected() {
        let lab = Lab::new();
        let (mut right, _) = gate(&lab, "node-z", "node-x");
        let (left, _) = gate(&lab, "node-x", "node-z");
        let mut hello = left.hello_frame();
        // Change one byte of the X25519 key. The signature no longer matches.
        hello[26] ^= 1;
        assert!(right.open_frame(&hello).is_err());
        assert!(!right.ready());
    }

    #[test]
    fn a_renewed_hello_moves_the_peer_expiry_forward() {
        let lab = Lab::new();
        let id = session_id("node-x", "node-z").unwrap();
        let (auth, _) = lab.auth_for("node-x", "node-z", Duration::from_secs(300));
        let mut left = KeyGate::generate(id, "node-x", "node-z", auth).unwrap();
        let (mut right, _) = gate(&lab, "node-z", "node-x");
        let first = left.hello_frame();
        assert_eq!(right.open_frame(&first).unwrap(), Some(Opened::Hello));
        assert_eq!(
            left.open_frame(&right.hello_frame()).unwrap(),
            Some(Opened::Hello)
        );
        let before = right.peer_not_after().unwrap();
        let sealed = left.seal(KIND_DATA, &[1, 2, 3]).unwrap();
        assert!(right.open_frame(&sealed).unwrap().is_some());

        // The coordinator issues a leaf with a longer life.
        let issued = lab
            .ca
            .issue(
                &SpiffeId::node("node-x").unwrap(),
                SystemTime::now(),
                Duration::from_secs(600),
                &DenySet::empty(),
            )
            .unwrap();
        assert!(issued.not_after > before);
        let seed = ed25519_seed_from_private_pem(&issued.private_key_pem).unwrap();
        left.set_leaf(issued.certificate_der.clone(), &seed);
        assert_eq!(
            right.open_frame(&left.hello_frame()).unwrap(),
            Some(Opened::Hello)
        );
        assert_eq!(right.peer_not_after(), Some(issued.not_after));

        // The session key and the counters stay in place.
        let sealed = left.seal(KIND_DATA, &[4, 5, 6]).unwrap();
        assert_eq!(
            right.open_frame(&sealed).unwrap(),
            Some(Opened::Data(vec![4, 5, 6]))
        );

        // A replay of the old hello does not move the expiry back.
        assert_eq!(right.open_frame(&first).unwrap(), Some(Opened::Hello));
        assert_eq!(right.peer_not_after(), Some(issued.not_after));
    }

    #[test]
    fn a_renewed_hello_from_another_ca_is_rejected() {
        let lab = Lab::new();
        let other = Lab::new();
        let (mut left, _) = gate(&lab, "node-x", "node-z");
        let (mut right, _) = gate(&lab, "node-z", "node-x");
        assert_eq!(
            right.open_frame(&left.hello_frame()).unwrap(),
            Some(Opened::Hello)
        );
        let before = right.peer_not_after();
        let issued = other
            .ca
            .issue(
                &SpiffeId::node("node-x").unwrap(),
                SystemTime::now(),
                Duration::from_secs(600),
                &DenySet::empty(),
            )
            .unwrap();
        let seed = ed25519_seed_from_private_pem(&issued.private_key_pem).unwrap();
        left.set_leaf(issued.certificate_der.clone(), &seed);
        assert!(right.open_frame(&left.hello_frame()).is_err());
        assert_eq!(right.peer_not_after(), before);
    }

    #[test]
    fn path_switch_keeps_the_overlay_session() {
        let (mut left, mut right) = pair();
        let id = left.session();
        let mut select = PathSelect::default();
        let path = select_path(&mut select, true, true, false, 0);
        assert_eq!(path, Some(OverlayPath::Direct));
        let first = left.seal(KIND_DATA, b"one").unwrap();
        let counter = left.send_counter();
        let path = select_path(&mut select, false, true, true, 100);
        assert_eq!(path, Some(OverlayPath::Relay));
        assert_eq!(select.relay_hold_until_ms, 100 + RELAY_HOLD_MS);
        let second = left.seal(KIND_PROBE, &[1]).unwrap();
        assert_eq!(left.session(), id);
        assert_eq!(left.send_counter(), counter + 1);
        assert_eq!(
            right.open_frame(&first).unwrap(),
            Some(Opened::Data(b"one".to_vec()))
        );
        assert_eq!(right.open_frame(&second).unwrap(), Some(Opened::Probe(1)));
        assert_eq!(right.open_frame(&first).unwrap(), None);
        let held = select_path(&mut select, true, true, true, 200);
        assert_eq!(held, Some(OverlayPath::Relay));
        let upgraded = select_path(&mut select, true, true, true, 100 + RELAY_HOLD_MS);
        assert_eq!(upgraded, Some(OverlayPath::Direct));
        assert_eq!(left.session(), id);
        let mut silent = PathSelect {
            current: Some(OverlayPath::Direct),
            ..PathSelect::default()
        };
        assert_eq!(select_path(&mut silent, false, false, true, 50), None);
    }

    #[test]
    fn upgrade_to_direct_keeps_the_relay_for_the_overlap() {
        let mut select = PathSelect {
            current: Some(OverlayPath::Relay),
            ..PathSelect::default()
        };
        assert_eq!(select.plan(0), SendPlan::Relay);
        let now = 5_000;
        assert_eq!(
            select_path(&mut select, true, true, true, now),
            Some(OverlayPath::Direct)
        );
        assert_eq!(select.plan(now), SendPlan::Both);
        assert_eq!(select.plan(now + OVERLAP_MS - 1), SendPlan::Both);
        assert_eq!(select.plan(now + OVERLAP_MS), SendPlan::Direct);
        assert!(SendPlan::Both.uses_direct() && SendPlan::Both.uses_relay());
        assert_eq!(PathSelect::default().plan(0), SendPlan::Hold);
    }

    #[test]
    fn a_copy_on_the_second_path_is_dropped() {
        let (mut left, mut right) = pair();
        let frame = left.seal(KIND_DATA, b"ping").unwrap();
        assert_eq!(
            right.open_frame(&frame).unwrap(),
            Some(Opened::Data(b"ping".to_vec()))
        );
        // The same frame on the second path is a replay.
        assert_eq!(right.open_frame(&frame).unwrap(), None);
        // A late frame that the receiver did not open is still accepted.
        let late = left.seal(KIND_DATA, b"late").unwrap();
        let next = left.seal(KIND_DATA, b"next").unwrap();
        assert!(right.open_frame(&next).unwrap().is_some());
        assert_eq!(
            right.open_frame(&late).unwrap(),
            Some(Opened::Data(b"late".to_vec()))
        );
    }

    #[test]
    fn relay_stays_down_until_the_direct_budget_ends() {
        let mut select = PathSelect::default();
        assert_eq!(select_path(&mut select, false, true, false, 10), None);
        assert_eq!(
            select_path(&mut select, false, true, true, 3_000),
            Some(OverlayPath::Relay)
        );
    }

    #[test]
    fn the_relay_waits_for_the_direct_attempt() {
        assert!(!relay_allowed(false, false, false));
        assert!(relay_allowed(false, false, true));
        assert!(!relay_allowed(true, true, true));
        assert!(relay_allowed(true, false, false));
    }
}
