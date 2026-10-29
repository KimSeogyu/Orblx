//! Overlay session state for a NAT path.
//!
//! The session id and the send counter stay in place when the path changes.
//! Direct and relay carry the same sealed frames.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
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
pub const STALE_MS: u64 = 350;

/// The wait after a move to relay before a direct upgrade.
pub const RELAY_HOLD_MS: u64 = 1_000;

/// Plain hello. The payload is one X25519 public key.
pub const KIND_HELLO: u8 = 1;
/// Encrypted probe. The frame does not enter the TUN device.
pub const KIND_PROBE: u8 = 2;
/// Encrypted IPv4 packet.
pub const KIND_DATA: u8 = 3;

const MAGIC: &[u8; 8] = b"ORBLXNAT";
const VERSION: u8 = 1;
const HEADER: usize = 26;

/// The path choice for one overlay session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathSelect {
    /// The path that carries TUN packets.
    pub current: Option<OverlayPath>,
    /// Direct stays idle until this monotonic time.
    pub relay_hold_until_ms: u64,
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
/// `direct_ok` means a recent decrypted frame arrived on the direct path.
/// `relay_ok` means a recent decrypted frame arrived on the relay path.
/// `relay_allowed` is false during the first direct attempt.
/// A move from direct to relay sets a hold.
/// The hold keeps the session on relay until the hold time.
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

/// Build a hello frame.
#[must_use]
pub fn encode_hello(session: &[u8; 16], public_key: &[u8; 32]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER + 32);
    push_header(&mut frame, KIND_HELLO, session);
    frame.extend_from_slice(public_key);
    frame
}

/// One result from a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// The peer public key is stored.
    Hello,
    /// A probe opened.
    Probe,
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
    peer_public: Option<[u8; 32]>,
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
    pub fn generate(
        session: [u8; 16],
        local_name: &str,
        peer_name: &str,
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
            peer_public: None,
            key: None,
            send_counter: 0,
            replay: Replay::default(),
        })
    }

    /// The local X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
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
    pub fn absorb_peer(&mut self, peer: &[u8; 32]) -> Result<(), EdgeError> {
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
                if parsed.body.len() != 32 {
                    return Err(EdgeError::BadCandidate);
                }
                let mut peer = [0u8; 32];
                peer.copy_from_slice(&parsed.body);
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
                    Ok(Some(Opened::Probe))
                } else {
                    Ok(Some(Opened::Data(plain)))
                }
            }
            _ => Err(EdgeError::BadCandidate),
        }
    }
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
    use super::{
        encode_hello, select_path, session_id, KeyGate, Opened, OverlayPath, PathSelect, KIND_DATA,
        KIND_PROBE, RELAY_HOLD_MS,
    };

    fn pair() -> (KeyGate, KeyGate) {
        let id = session_id("node-x", "node-z").unwrap();
        let mut left = KeyGate::generate(id, "node-x", "node-z").unwrap();
        let mut right = KeyGate::generate(id, "node-z", "node-x").unwrap();
        let hello_left = encode_hello(&id, &left.public_key());
        let hello_right = encode_hello(&id, &right.public_key());
        assert_eq!(right.open_frame(&hello_left).unwrap(), Some(Opened::Hello));
        assert_eq!(left.open_frame(&hello_right).unwrap(), Some(Opened::Hello));
        assert!(left.ready());
        assert!(right.ready());
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
        let second = left.seal(KIND_PROBE, b"p").unwrap();
        assert_eq!(left.session(), id);
        assert_eq!(left.send_counter(), counter + 1);
        assert_eq!(
            right.open_frame(&first).unwrap(),
            Some(Opened::Data(b"one".to_vec()))
        );
        assert_eq!(right.open_frame(&second).unwrap(), Some(Opened::Probe));
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
        use super::relay_allowed;
        assert!(!relay_allowed(false, false, false));
        assert!(relay_allowed(false, false, true));
        assert!(!relay_allowed(true, true, true));
        assert!(relay_allowed(true, false, false));
    }
}
