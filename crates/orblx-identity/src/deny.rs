use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::codec::decode_hex_array;
use crate::error::IdentityError;
use crate::spiffe::SpiffeId;

/// The result of one deny document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyApply {
    /// The document replaced the current set.
    Applied,
    /// The document version is not higher than the current version.
    IgnoredOlder,
}

/// The current deny set.
///
/// A document replaces the whole set. A lower version does not change the set.
/// A document that fails the parse check does not change the set.
///
/// A set from [`DenySet::refuse_all`] refuses each identifier and each nonce (W25-38).
/// A node uses it when its deny file is not valid, did not open, or is missing after enroll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenySet {
    refuse_all: bool,
    version: Option<u64>,
    generated_at: Option<u64>,
    revoked_uris: BTreeSet<String>,
    revoked_nonces: BTreeSet<[u8; 16]>,
    /// Leaf key id to the certificate `not_after` unix second.
    ///
    /// A reader ignores an entry when `now > not_after + MAX_SKEW`.
    revoked_leaf_keys: BTreeMap<[u8; 32], u64>,
}

impl Default for DenySet {
    fn default() -> Self {
        Self::empty()
    }
}

impl DenySet {
    pub fn empty() -> Self {
        Self {
            refuse_all: false,
            version: None,
            generated_at: None,
            revoked_uris: BTreeSet::new(),
            revoked_nonces: BTreeSet::new(),
            revoked_leaf_keys: BTreeMap::new(),
        }
    }

    /// Return a set that refuses each identifier and each nonce (W25-38).
    ///
    /// The set fails closed. It is not an empty list. A valid document that
    /// [`DenySet::apply_json`] applies replaces it.
    pub fn refuse_all() -> Self {
        Self {
            refuse_all: true,
            ..Self::empty()
        }
    }

    /// Return true when the set refuses each identifier and each nonce.
    pub fn refuses_all(&self) -> bool {
        self.refuse_all
    }

    /// Mark the set as stale after a failed reload (W25-38).
    ///
    /// The set keeps its version and its entries, as the agent guard keeps its last
    /// good set. A stale set refuses each identifier and each nonce. A valid document
    /// with a higher version, or the same document again, makes it current.
    pub fn mark_stale(&mut self) {
        self.refuse_all = true;
    }

    /// Parse one deny JSON document into a new set.
    pub fn from_json(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut deny = Self::empty();
        deny.apply_json(bytes)?;
        Ok(deny)
    }

    pub fn version(&self) -> Option<u64> {
        self.version
    }

    pub fn generated_at(&self) -> Option<u64> {
        self.generated_at
    }

    /// Apply one deny JSON document.
    ///
    /// The document shape is
    /// `{ "version", "generated_at", "revoked_uris", "revoked_ticket_nonces" }`.
    pub fn apply_json(&mut self, bytes: &[u8]) -> Result<DenyApply, IdentityError> {
        let document: DenyDocument =
            serde_json::from_slice(bytes).map_err(|_| IdentityError::DenyDocument)?;
        let mut uris = BTreeSet::new();
        for uri in document.revoked_uris {
            let id = SpiffeId::parse(&uri).map_err(|_| IdentityError::DenyDocument)?;
            uris.insert(id.as_uri().to_string());
        }
        let mut nonces = BTreeSet::new();
        for nonce in document.revoked_ticket_nonces {
            let bytes = decode_hex_array::<16>(&nonce).map_err(|_| IdentityError::DenyDocument)?;
            nonces.insert(bytes);
        }
        let mut leaf_keys = BTreeMap::new();
        for item in document.revoked_leaf_keys {
            if !leaf_key_text_ok(&item.key_id) {
                return Err(IdentityError::DenyDocument);
            }
            let key =
                decode_hex_array::<32>(&item.key_id).map_err(|_| IdentityError::DenyDocument)?;
            match leaf_keys.get(&key).copied() {
                Some(end) if end >= item.not_after => {}
                _ => {
                    leaf_keys.insert(key, item.not_after);
                }
            }
        }
        if let Some(current) = self.version {
            // W25-38: the same document again makes a stale set current.
            // The set never moves to a lower version.
            let same = document.version == current
                && document.generated_at == self.generated_at.unwrap_or_default()
                && uris == self.revoked_uris
                && nonces == self.revoked_nonces
                && leaf_keys == self.revoked_leaf_keys;
            if self.refuse_all && same {
                self.refuse_all = false;
                return Ok(DenyApply::Applied);
            }
            if document.version <= current {
                return Ok(DenyApply::IgnoredOlder);
            }
        }
        self.refuse_all = false;
        self.version = Some(document.version);
        self.generated_at = Some(document.generated_at);
        self.revoked_uris = uris;
        self.revoked_nonces = nonces;
        self.revoked_leaf_keys = leaf_keys;
        Ok(DenyApply::Applied)
    }

    pub fn reject_uri(&self, id: &SpiffeId) -> Result<(), IdentityError> {
        if self.refuse_all {
            return Err(IdentityError::DenyDocument);
        }
        if self.revoked_uris.contains(id.as_uri()) {
            return Err(IdentityError::Revoked);
        }
        Ok(())
    }

    pub fn reject_nonce(&self, nonce: &[u8; 16]) -> Result<(), IdentityError> {
        if self.refuse_all {
            return Err(IdentityError::DenyDocument);
        }
        if self.revoked_nonces.contains(nonce) {
            return Err(IdentityError::Revoked);
        }
        Ok(())
    }

    /// Refuse one lowercase hex ticket nonce.
    ///
    /// An empty string is not a nonce. `refuse_all` still fails closed.
    pub fn reject_nonce_hex(&self, nonce: &str) -> Result<(), IdentityError> {
        if self.refuse_all {
            return Err(IdentityError::DenyDocument);
        }
        if nonce.is_empty() {
            return Ok(());
        }
        let bytes = decode_hex_array::<16>(nonce).map_err(|_| IdentityError::DenyDocument)?;
        self.reject_nonce(&bytes)
    }

    /// Refuse one leaf key while `now` is within `not_after + MAX_SKEW`.
    ///
    /// A later `now` ignores the entry. The entry needs no deny after that time.
    pub fn reject_leaf_key(&self, key: &[u8; 32], now_unix: u64) -> Result<(), IdentityError> {
        if self.refuse_all {
            return Err(IdentityError::DenyDocument);
        }
        if let Some(not_after) = self.revoked_leaf_keys.get(key) {
            if now_unix <= not_after.saturating_add(crate::clock::MAX_SKEW.as_secs()) {
                return Err(IdentityError::Revoked);
            }
        }
        Ok(())
    }

    /// Refuse one lowercase hex leaf key id. An empty string is not a key id.
    pub fn reject_leaf_key_hex(&self, key_id: &str, now_unix: u64) -> Result<(), IdentityError> {
        if self.refuse_all {
            return Err(IdentityError::DenyDocument);
        }
        if key_id.is_empty() {
            return Ok(());
        }
        if !leaf_key_text_ok(key_id) {
            return Err(IdentityError::DenyDocument);
        }
        let key = decode_hex_array::<32>(key_id).map_err(|_| IdentityError::DenyDocument)?;
        self.reject_leaf_key(&key, now_unix)
    }
}

fn leaf_key_text_ok(key_id: &str) -> bool {
    key_id.len() == 64
        && key_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !key_id.bytes().any(|byte| byte.is_ascii_uppercase())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DenyDocument {
    version: u64,
    generated_at: u64,
    revoked_uris: Vec<String>,
    revoked_ticket_nonces: Vec<String>,
    #[serde(default)]
    revoked_leaf_keys: Vec<RevokedLeafKeyDoc>,
}

#[derive(Debug, Deserialize)]
struct RevokedLeafKeyDoc {
    key_id: String,
    not_after: u64,
}
