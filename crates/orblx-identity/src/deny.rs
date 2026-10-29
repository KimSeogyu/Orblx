use std::collections::BTreeSet;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenySet {
    version: Option<u64>,
    generated_at: Option<u64>,
    revoked_uris: BTreeSet<String>,
    revoked_nonces: BTreeSet<[u8; 16]>,
}

impl Default for DenySet {
    fn default() -> Self {
        Self::empty()
    }
}

impl DenySet {
    pub fn empty() -> Self {
        Self {
            version: None,
            generated_at: None,
            revoked_uris: BTreeSet::new(),
            revoked_nonces: BTreeSet::new(),
        }
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
        if let Some(current) = self.version {
            if document.version <= current {
                return Ok(DenyApply::IgnoredOlder);
            }
        }
        self.version = Some(document.version);
        self.generated_at = Some(document.generated_at);
        self.revoked_uris = uris;
        self.revoked_nonces = nonces;
        Ok(DenyApply::Applied)
    }

    pub fn reject_uri(&self, id: &SpiffeId) -> Result<(), IdentityError> {
        if self.revoked_uris.contains(id.as_uri()) {
            return Err(IdentityError::Revoked);
        }
        Ok(())
    }

    pub fn reject_nonce(&self, nonce: &[u8; 16]) -> Result<(), IdentityError> {
        if self.revoked_nonces.contains(nonce) {
            return Err(IdentityError::Revoked);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DenyDocument {
    version: u64,
    generated_at: u64,
    revoked_uris: Vec<String>,
    revoked_ticket_nonces: Vec<String>,
}
