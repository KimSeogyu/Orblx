//! Node lock (W23-1).
//!
//! A node with a node lock file accepts a peer only when a trusted owner key signed that peer.
//! The owner keeps the owner private key. The coordinator never holds it.
//! The coordinator only stores and forwards owner signatures.
//!
//! The design uses Ed25519 from `ed25519-dalek`, as the netmap key does.
//! It adds no new primitive and no new handshake.
//!
//! - A node signature covers the node name, the node SPIFFE ID, and the overlay address.
//! - A key update holds the full trusted key set after the change.
//!   A key in the set before the change signs it. The update links to the hash of the update before it.
//! - The node pins the first key set out of band (`orblx lock trust`).
//!   The node applies later updates from the netmap only when the chain and the signatures are valid.

use std::collections::BTreeMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use orblx_datapath::{LockUpdate, Netmap, NetmapPeer, NodeLockSig, NODE_LOCK_FILE};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::netmap::{decode_hex_32, encode_hex};

/// The coordinator file that stores owner signatures and key updates.
pub const COORD_LOCK_FILE: &str = "node-lock-store.json";

/// The largest trusted key set.
pub const MAX_LOCK_KEYS: usize = 16;

/// The rotate action token.
pub const ACTION_ROTATE: &str = "rotate";
/// The remove action token.
pub const ACTION_REMOVE: &str = "remove";

const NODE_DOMAIN: &str = "orblx-node-lock-v1";
const UPDATE_DOMAIN: &str = "orblx-lock-update-v1";

/// The trusted owner key set at one version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockState {
    /// Version 0 is the pinned key set. Each update adds one.
    pub version: u64,
    /// The trusted owner public keys, as sorted 64-hex-character text.
    pub keys: Vec<String>,
    /// The hash of the last applied update. Empty at version 0.
    pub head: String,
}

impl LockState {
    /// Make the version 0 key set.
    pub fn genesis(keys: &[String]) -> Result<Self, CoordError> {
        Ok(Self {
            version: 0,
            keys: canonical_keys(keys)?,
            head: String::new(),
        })
    }

    /// Return true when the set holds `key_id`.
    pub fn trusts(&self, key_id: &str) -> bool {
        self.keys.iter().any(|key| key == key_id)
    }

    /// Check one update against this state and return the next state.
    pub fn apply(&self, update: &LockUpdate) -> Result<Self, CoordError> {
        if update.version != self.version.saturating_add(1) {
            return Err(lock_error(
                "The lock update version is not the next version.",
            ));
        }
        if update.prev != self.head {
            return Err(lock_error(
                "The lock update does not link to the current head.",
            ));
        }
        if !self.trusts(&update.signer) {
            return Err(lock_error(
                "A trusted owner key did not sign the lock update.",
            ));
        }
        let next = canonical_keys(&update.keys)?;
        if next != update.keys {
            return Err(lock_error("The lock update key list is not sorted."));
        }
        let removed: Vec<&String> = self.keys.iter().filter(|key| !next.contains(key)).collect();
        let added: Vec<&String> = next.iter().filter(|key| !self.keys.contains(key)).collect();
        match update.action.as_str() {
            ACTION_ROTATE => {
                if removed.len() != 1 || added.len() != 1 || removed[0] != &update.signer {
                    return Err(lock_error(
                        "A rotate update must replace the signer key with one new key.",
                    ));
                }
            }
            ACTION_REMOVE => {
                if removed.len() != 1 || !added.is_empty() {
                    return Err(lock_error("A remove update must remove one key only."));
                }
            }
            _ => return Err(lock_error("The lock update action is not valid.")),
        }
        let public = decode_hex_32(&update.signer)?;
        verify_b64(&public, &update_payload(update), &update.sig)?;
        Ok(Self {
            version: update.version,
            keys: next,
            head: update_hash(update),
        })
    }

    /// Apply the updates that are newer than this state.
    ///
    /// An update at or below the current version must match the stored head.
    /// A different update at the current version is a fork, and the function refuses it.
    pub fn apply_all(&self, updates: &[LockUpdate]) -> Result<Self, CoordError> {
        let mut state = self.clone();
        let mut sorted: Vec<&LockUpdate> = updates.iter().collect();
        sorted.sort_by_key(|update| update.version);
        for update in sorted {
            if update.version < state.version {
                continue;
            }
            if update.version == state.version {
                if state.version > 0 && update_hash(update) != state.head {
                    return Err(lock_error(
                        "The lock update at the current version does not match.",
                    ));
                }
                continue;
            }
            state = state.apply(update)?;
        }
        Ok(state)
    }

    /// Return true when a trusted key signed this peer.
    pub fn verify_peer(&self, peer: &NetmapPeer) -> bool {
        let Some(lock_sig) = &peer.lock_sig else {
            return false;
        };
        if !self.trusts(&lock_sig.key_id) {
            return false;
        }
        let Ok(public) = decode_hex_32(&lock_sig.key_id) else {
            return false;
        };
        let payload = node_payload(&peer.name, &peer.svid, &peer.overlay_ip);
        verify_b64(&public, &payload, &lock_sig.sig).is_ok()
    }
}

/// One owner signing key.
///
/// Debug output shows the fingerprint only.
pub struct OwnerKey {
    signing: SigningKey,
}

impl std::fmt::Debug for OwnerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerKey")
            .field("fingerprint", &fingerprint(&self.key_id()))
            .finish()
    }
}

impl OwnerKey {
    /// Make a new random key.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Read a key file. The file holds the 32-byte seed as 64 hex characters.
    pub fn from_file(path: &Path) -> Result<Self, CoordError> {
        let text = read_text(path)?;
        let seed = decode_hex_32(text.trim())
            .map_err(|_| lock_error("The owner key file is not valid."))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Write the seed file with mode `0600` and the public file with mode `0644`.
    pub fn write_files(&self, key_path: &Path, pub_path: &Path) -> Result<(), CoordError> {
        write_text(
            key_path,
            &format!("{}\n", encode_hex(&self.signing.to_bytes())),
            0o600,
        )?;
        write_text(pub_path, &format!("{}\n", self.key_id()), 0o644)
    }

    /// Return the public key as 64 hex characters.
    pub fn key_id(&self) -> String {
        encode_hex(&self.signing.verifying_key().to_bytes())
    }

    /// Sign one node.
    pub fn sign_node(&self, name: &str, svid: &str, overlay_ip: &str) -> NodeLockSig {
        let payload = node_payload(name, svid, overlay_ip);
        NodeLockSig {
            key_id: self.key_id(),
            sig: STANDARD.encode(self.signing.sign(&payload).to_bytes()),
        }
    }

    /// Make and sign one key update on top of `state`.
    pub fn sign_update(
        &self,
        state: &LockState,
        action: &str,
        keys: &[String],
    ) -> Result<LockUpdate, CoordError> {
        let mut update = LockUpdate {
            version: state.version.saturating_add(1),
            action: action.to_string(),
            keys: canonical_keys(keys)?,
            prev: state.head.clone(),
            signer: self.key_id(),
            sig: String::new(),
        };
        update.sig = STANDARD.encode(self.signing.sign(&update_payload(&update)).to_bytes());
        state.apply(&update)?;
        Ok(update)
    }
}

/// Read a public key file. The file holds 64 hex characters.
pub fn read_pub_file(path: &Path) -> Result<String, CoordError> {
    let text = read_text(path)?;
    let key = text.trim().to_string();
    decode_hex_32(&key).map_err(|_| lock_error("The owner public key file is not valid."))?;
    Ok(key)
}

/// Return a short fingerprint for logs: the first 16 hex characters of SHA-256 over the public key.
pub fn fingerprint(key_id: &str) -> String {
    let digest = Sha256::digest(key_id.as_bytes());
    encode_hex(&digest[..8])
}

/// The bytes that an owner signs for one node.
pub fn node_payload(name: &str, svid: &str, overlay_ip: &str) -> Vec<u8> {
    format!("{NODE_DOMAIN}\nname={name}\nsvid={svid}\noverlay_ip={overlay_ip}\n").into_bytes()
}

fn update_payload(update: &LockUpdate) -> Vec<u8> {
    format!(
        "{UPDATE_DOMAIN}\nversion={}\naction={}\nprev={}\nsigner={}\nkeys={}\n",
        update.version,
        update.action,
        update.prev,
        update.signer,
        update.keys.join(",")
    )
    .into_bytes()
}

/// Return the hash of one update: SHA-256 over the signed bytes and the signature text.
pub fn update_hash(update: &LockUpdate) -> String {
    let mut hasher = Sha256::new();
    hasher.update(update_payload(update));
    hasher.update(update.sig.as_bytes());
    encode_hex(&hasher.finalize())
}

fn canonical_keys(keys: &[String]) -> Result<Vec<String>, CoordError> {
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        decode_hex_32(key).map_err(|_| lock_error("An owner key is not valid."))?;
        if key.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(lock_error("An owner key is not valid."));
        }
        out.push(key.clone());
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(lock_error("The trusted key set is empty."));
    }
    if out.len() > MAX_LOCK_KEYS {
        return Err(lock_error("The trusted key set is too large."));
    }
    if out.len() != keys.len() {
        return Err(lock_error("The trusted key set repeats a key."));
    }
    Ok(out)
}

fn verify_b64(public: &[u8; 32], message: &[u8], sig_b64: &str) -> Result<(), CoordError> {
    let bytes = STANDARD
        .decode(sig_b64.as_bytes())
        .map_err(|_| CoordError::Signature)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| CoordError::Signature)?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| CoordError::Signature)?;
    key.verify(message, &signature)
        .map_err(|_| CoordError::Signature)
}

fn lock_error(text: &str) -> CoordError {
    CoordError::Protocol(text.to_string())
}

// ---- node side ----

/// The result of one node lock pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockReport {
    /// The lock version after the pass.
    pub version: u64,
    /// The number of trusted keys after the pass.
    pub keys: usize,
    /// The peers with a valid owner signature.
    pub kept: Vec<String>,
    /// The peers that the node dropped.
    pub dropped: Vec<String>,
}

/// Read the node lock file. None means the node has no node lock.
pub fn read_node_lock(dir: &Path) -> Result<Option<LockState>, CoordError> {
    let path = dir.join(NODE_LOCK_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let text = read_text(&path)?;
    let state: LockState =
        serde_json::from_str(&text).map_err(|_| lock_error("The node lock file is not valid."))?;
    if canonical_keys(&state.keys)? != state.keys {
        return Err(lock_error("The node lock file is not valid."));
    }
    Ok(Some(state))
}

/// Pin the first trusted key set on this node.
///
/// The function refuses to replace a node lock file that holds a different key set.
pub fn trust_keys(dir: &Path, keys: &[String]) -> Result<LockState, CoordError> {
    let state = LockState::genesis(keys)?;
    if let Some(current) = read_node_lock(dir)? {
        if current.version == 0 && current.keys == state.keys {
            return Ok(current);
        }
        return Err(lock_error(
            "The node lock file exists. Remove it to pin a new key set.",
        ));
    }
    write_lock_file(dir, &state)?;
    Ok(state)
}

fn write_lock_file(dir: &Path, state: &LockState) -> Result<(), CoordError> {
    let text =
        serde_json::to_string(state).map_err(|_| lock_error("The node lock is not valid."))?;
    write_text(&dir.join(NODE_LOCK_FILE), &text, 0o644)
}

/// Apply the node lock to one netmap.
///
/// The function applies the key updates in the netmap, stores the new state,
/// and removes each peer without a valid owner signature.
/// It returns None when the node has no node lock file.
pub fn apply_node_lock(dir: &Path, netmap: &mut Netmap) -> Result<Option<LockReport>, CoordError> {
    let Some(state) = read_node_lock(dir)? else {
        return Ok(None);
    };
    let next = state.apply_all(&netmap.lock)?;
    if next != state {
        write_lock_file(dir, &next)?;
    }
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    netmap.peers.retain(|peer| {
        if next.verify_peer(peer) {
            kept.push(peer.name.clone());
            true
        } else {
            dropped.push(peer.name.clone());
            false
        }
    });
    Ok(Some(LockReport {
        version: next.version,
        keys: next.keys.len(),
        kept,
        dropped,
    }))
}

/// Print one report. The text holds node names and counts only.
/// Write the netmap file again after node lock dropped peers (W25-34).
///
/// The function writes a temp file, syncs it, and renames it. A reader or a crash never
/// sees a part of the file: the file has the old netmap or the new netmap.
pub fn write_locked_netmap(path: &Path, netmap: &Netmap) -> Result<(), CoordError> {
    let text = serde_json::to_string(netmap)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    write_text(path, &text, 0o644)
}

pub fn print_report(report: &LockReport) {
    println!(
        "node lock version {} keys {} keeps {} drops {}",
        report.version,
        report.keys,
        report.kept.len(),
        report.dropped.len()
    );
    for name in &report.dropped {
        println!("node lock drops peer {name}: no trusted owner signature");
    }
}

// ---- coordinator side ----

/// The coordinator copy of the node lock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockStore {
    /// The version 0 key set.
    pub genesis: Vec<String>,
    /// The key updates in version order.
    pub updates: Vec<LockUpdate>,
    /// The owner signature for each node name.
    pub sigs: BTreeMap<String, NodeLockSig>,
}

impl LockStore {
    /// Return true when an owner set up the node lock.
    pub fn enabled(&self) -> bool {
        !self.genesis.is_empty()
    }

    /// Return the current key set.
    pub fn current(&self) -> Result<LockState, CoordError> {
        LockState::genesis(&self.genesis)?.apply_all(&self.updates)
    }
}

/// Read the coordinator lock store. A missing file is an empty store.
pub fn read_store(dir: &Path) -> Result<LockStore, CoordError> {
    let path = dir.join(COORD_LOCK_FILE);
    if !path.exists() {
        return Ok(LockStore::default());
    }
    let text = read_text(&path)?;
    serde_json::from_str(&text).map_err(|_| lock_error("The node lock store is not valid."))
}

/// Write the coordinator lock store.
pub fn write_store(dir: &Path, store: &LockStore) -> Result<(), CoordError> {
    let text = serde_json::to_string(store)
        .map_err(|_| lock_error("The node lock store is not valid."))?;
    write_text(&dir.join(COORD_LOCK_FILE), &text, 0o644)
}

/// Return the SHA-256 of the store file, or zero bytes when the file does not exist.
pub fn store_digest(dir: &Path) -> Result<[u8; 32], CoordError> {
    let path = dir.join(COORD_LOCK_FILE);
    if !path.exists() {
        return Ok([0u8; 32]);
    }
    let text = read_text(&path)?;
    Ok(Sha256::digest(text.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use orblx_datapath::{Netmap, NetmapPeer, NetmapSelf};

    use super::*;

    fn peer(name: &str, ip: &str) -> NetmapPeer {
        NetmapPeer {
            name: name.to_string(),
            overlay_ip: ip.to_string(),
            svid: format!("spiffe://orblx.local/node/{name}"),
            endpoints: vec![format!("{name}:443")],
            routes: Vec::new(),
            exit_node: false,
            owner: String::new(),
            lock_sig: None,
        }
    }

    fn signed(key: &OwnerKey, name: &str, ip: &str) -> NetmapPeer {
        let mut item = peer(name, ip);
        item.lock_sig = Some(key.sign_node(&item.name, &item.svid, &item.overlay_ip));
        item
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orblx-nodelock-{name}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unsigned_and_foreign_peers_are_dropped() {
        let owner = OwnerKey::generate();
        let other = OwnerKey::generate();
        let state = LockState::genesis(&[owner.key_id()]).unwrap();
        assert!(state.verify_peer(&signed(&owner, "b", "100.64.0.2")));
        assert!(!state.verify_peer(&peer("rogue", "100.64.0.9")));
        assert!(!state.verify_peer(&signed(&other, "x", "100.64.0.3")));
        let mut moved = signed(&owner, "b", "100.64.0.2");
        moved.overlay_ip = "100.64.0.7".to_string();
        assert!(!state.verify_peer(&moved));
        let mut renamed = signed(&owner, "b", "100.64.0.2");
        renamed.name = "c".to_string();
        renamed.svid = "spiffe://orblx.local/node/c".to_string();
        assert!(!state.verify_peer(&renamed));
    }

    #[test]
    fn rotate_and_remove_follow_the_chain() {
        let k1 = OwnerKey::generate();
        let k2 = OwnerKey::generate();
        let k3 = OwnerKey::generate();
        let genesis = LockState::genesis(&[k1.key_id(), k2.key_id()]).unwrap();
        let rotate = k1
            .sign_update(&genesis, ACTION_ROTATE, &[k2.key_id(), k3.key_id()])
            .unwrap();
        let s1 = genesis.apply(&rotate).unwrap();
        assert!(!s1.trusts(&k1.key_id()));
        assert!(s1.trusts(&k3.key_id()));
        let remove = k3.sign_update(&s1, ACTION_REMOVE, &[k3.key_id()]).unwrap();
        let s2 = s1.apply(&remove).unwrap();
        assert_eq!(s2.keys, vec![k3.key_id()]);
        assert_eq!(s2.version, 2);
        // Out of order and repeated updates give the same state.
        let again = genesis
            .apply_all(&[remove.clone(), rotate.clone(), rotate.clone()])
            .unwrap();
        assert_eq!(again, s2);
        assert_eq!(s2.apply_all(&[rotate, remove]).unwrap(), s2);
    }

    #[test]
    fn bad_updates_are_refused() {
        let k1 = OwnerKey::generate();
        let k2 = OwnerKey::generate();
        let outsider = OwnerKey::generate();
        let genesis = LockState::genesis(&[k1.key_id(), k2.key_id()]).unwrap();
        // An outside key cannot sign.
        assert!(outsider
            .sign_update(&genesis, ACTION_REMOVE, &[k1.key_id()])
            .is_err());
        // Rotate must replace the signer key.
        assert!(k1
            .sign_update(&genesis, ACTION_ROTATE, &[k1.key_id(), outsider.key_id()])
            .is_err());
        // Remove cannot empty the set or add a key.
        let only = LockState::genesis(&[k1.key_id()]).unwrap();
        assert!(k1.sign_update(&only, ACTION_REMOVE, &[]).is_err());
        assert!(k1
            .sign_update(&genesis, ACTION_REMOVE, &[k1.key_id(), outsider.key_id()])
            .is_err());
        // A changed key list breaks the signature.
        let mut update = k1
            .sign_update(&genesis, ACTION_REMOVE, &[k1.key_id()])
            .unwrap();
        let mut forged = update.clone();
        forged.keys = vec![k2.key_id()];
        assert!(genesis.apply(&forged).is_err());
        // A wrong link is refused.
        update.prev = "00".repeat(32);
        assert!(genesis.apply(&update).is_err());
    }

    #[test]
    fn a_fork_at_the_current_version_is_refused() {
        let k1 = OwnerKey::generate();
        let k2 = OwnerKey::generate();
        let genesis = LockState::genesis(&[k1.key_id(), k2.key_id()]).unwrap();
        let first = k1
            .sign_update(&genesis, ACTION_REMOVE, &[k2.key_id()])
            .unwrap();
        let other = k2
            .sign_update(&genesis, ACTION_REMOVE, &[k1.key_id()])
            .unwrap();
        let state = genesis.apply(&first).unwrap();
        assert!(state.apply_all(&[other]).is_err());
    }

    #[test]
    fn node_lock_file_filters_the_netmap() {
        let dir = temp_dir("filter");
        let k1 = OwnerKey::generate();
        let k2 = OwnerKey::generate();
        let mut netmap = Netmap {
            version: 1,
            self_node: NetmapSelf {
                name: "a".to_string(),
                overlay_ip: "100.64.0.1".to_string(),
                owner: String::new(),
            },
            peers: vec![
                signed(&k1, "b", "100.64.0.2"),
                peer("rogue", "100.64.0.9"),
                signed(&k2, "c", "100.64.0.3"),
            ],
            lock: Vec::new(),
            split_dns: Vec::new(),
            seq: 0,
            issued_at_ms: 0,
        };
        let untouched = netmap.clone();
        let mut plain = netmap.clone();
        assert_eq!(apply_node_lock(&dir, &mut plain).unwrap(), None);
        assert_eq!(plain, untouched);
        trust_keys(&dir, &[k1.key_id(), k2.key_id()]).unwrap();
        let genesis = read_node_lock(&dir).unwrap().unwrap();
        // k2 removes k1: b loses its trusted signer.
        let update = k2
            .sign_update(&genesis, ACTION_REMOVE, &[k2.key_id()])
            .unwrap();
        netmap.lock.push(update);
        let report = apply_node_lock(&dir, &mut netmap).unwrap().unwrap();
        assert_eq!(report.version, 1);
        assert_eq!(report.kept, vec!["c".to_string()]);
        assert_eq!(report.dropped, vec!["b".to_string(), "rogue".to_string()]);
        assert_eq!(read_node_lock(&dir).unwrap().unwrap().version, 1);
        // A different pin is refused while the file exists.
        assert!(trust_keys(&dir, &[k1.key_id()]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn node_lock_drop_write_is_atomic() {
        // W25-34 crash test: a reader during the node lock drop write always sees one full
        // netmap, the old one or the new one. A temp file that a crash left changes nothing.
        let dir = temp_dir("atomic");
        let path = dir.join("netmap.json");
        let mut big = Netmap {
            version: 1,
            self_node: NetmapSelf {
                name: "a".to_string(),
                overlay_ip: "100.64.0.1".to_string(),
                owner: String::new(),
            },
            peers: (2..200)
                .map(|n| peer(&format!("p{n}"), &format!("100.64.0.{n}")))
                .collect(),
            lock: Vec::new(),
            split_dns: Vec::new(),
            seq: 0,
            issued_at_ms: 0,
        };
        write_locked_netmap(&path, &big).unwrap();
        let small = {
            big.peers.truncate(1);
            big.clone()
        };
        std::fs::write(dir.join("netmap.json.tmp"), b"{\"version\":").unwrap();
        assert!(Netmap::from_path(&path).is_ok());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                let mut reads = 0_u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let bytes = std::fs::read(&path).unwrap();
                    assert!(Netmap::from_slice(&bytes).is_ok(), "a torn netmap file");
                    reads += 1;
                }
                reads
            })
        };
        let full = Netmap::from_path(&path).unwrap();
        for round in 0..300 {
            let next = if round % 2 == 0 { &small } else { &full };
            write_locked_netmap(&path, next).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn owner_key_files_round_trip() {
        let dir = temp_dir("files");
        let key = OwnerKey::generate();
        key.write_files(&dir.join("owner.key"), &dir.join("owner.pub"))
            .unwrap();
        let back = OwnerKey::from_file(&dir.join("owner.key")).unwrap();
        assert_eq!(back.key_id(), key.key_id());
        assert_eq!(read_pub_file(&dir.join("owner.pub")).unwrap(), key.key_id());
        let debug = format!("{back:?}");
        assert!(!debug.contains(&key.key_id()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
