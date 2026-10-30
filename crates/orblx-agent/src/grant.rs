//! The signed grant document.
//!
//! The coordinator signs one grant document with its netmap key.
//! The document names the agent, the target node, one service, one port,
//! one path prefix, the time window, and the ticket fingerprint.
//! The document is public. It does not hold the ticket or a key.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::hex::{decode_hex, encode_hex};
use crate::AgentError;

/// The grant document version.
pub const GRANT_VERSION: u8 = 1;

/// The longest grant life in seconds.
pub const MAX_GRANT_SECS: u64 = 300;

const DOC_LABEL: &[u8] = b"orblx-agent-grant-doc-v1\n";
const MAX_SERVICE: usize = 32;
const MAX_PATH: usize = 128;

/// One agent JIT grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGrant {
    /// Document version.
    pub version: u8,
    /// Grant id. 16 lowercase hex characters.
    pub id: String,
    /// Agent SPIFFE ID.
    pub agent: String,
    /// SPIFFE ID of the node that asked for the grant.
    pub requester: String,
    /// SPIFFE ID of the owner that approved the grant.
    pub approver: String,
    /// Target node SPIFFE ID.
    pub node: String,
    /// Target overlay IPv4 address.
    pub addr: String,
    /// Service name.
    pub service: String,
    /// TCP port.
    pub port: u16,
    /// HTTP path prefix. A TCP guard does not use it.
    pub path_prefix: String,
    /// Unix seconds.
    pub not_before: u64,
    /// Unix seconds. The grant is not valid at or after this second.
    pub expires: u64,
    /// Ticket fingerprint in hex.
    pub ticket_hash: String,
}

/// One grant document and the coordinator signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentGrant {
    /// The grant.
    pub grant: AgentGrant,
    /// Base64 Ed25519 signature.
    pub sig: String,
    /// Hex of the netmap public key.
    pub key_id: String,
}

/// Return true when `name` is a valid service name.
///
/// A name has 1 to 32 characters from `a-z`, `0-9`, and `-`.
#[must_use]
pub fn service_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SERVICE
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Return true when `prefix` is a valid path prefix.
#[must_use]
pub fn path_prefix_ok(prefix: &str) -> bool {
    prefix.starts_with('/')
        && prefix.len() <= MAX_PATH
        && prefix
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'?' && byte != b'#')
        && !prefix.split('/').any(|part| part == ".." || part == ".")
}

/// Return true when `id` is a valid grant id.
#[must_use]
pub fn grant_id_ok(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl AgentGrant {
    /// Check the field shapes and the time window.
    pub fn check(&self) -> Result<(), AgentError> {
        if self.version != GRANT_VERSION
            || !grant_id_ok(&self.id)
            || !service_name_ok(&self.service)
            || !path_prefix_ok(&self.path_prefix)
            || self.port == 0
            || self.expires <= self.not_before
            || self.expires - self.not_before > MAX_GRANT_SECS
            || self.addr.parse::<std::net::Ipv4Addr>().is_err()
            || decode_hex(&self.ticket_hash).map(|bytes| bytes.len()) != Ok(16)
        {
            return Err(AgentError::Grant);
        }
        for uri in [&self.agent, &self.requester, &self.approver, &self.node] {
            orblx_identity::SpiffeId::parse(uri).map_err(|_| AgentError::Grant)?;
        }
        Ok(())
    }

    fn signed_bytes(&self) -> Result<Vec<u8>, AgentError> {
        let body = serde_json::to_vec(self).map_err(|_| AgentError::Grant)?;
        let mut out = DOC_LABEL.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Sign one grant document.
pub fn sign_grant(
    signing: &SigningKey,
    grant: &AgentGrant,
) -> Result<SignedAgentGrant, AgentError> {
    grant.check()?;
    let bytes = grant.signed_bytes()?;
    Ok(SignedAgentGrant {
        grant: grant.clone(),
        sig: STANDARD.encode(signing.sign(&bytes).to_bytes()),
        key_id: encode_hex(&signing.verifying_key().to_bytes()),
    })
}

/// Check the coordinator signature and the field shapes.
pub fn verify_grant(signed: &SignedAgentGrant, public: &[u8; 32]) -> Result<(), AgentError> {
    if signed.key_id != encode_hex(public) {
        return Err(AgentError::Signature);
    }
    signed.grant.check()?;
    let bytes = signed.grant.signed_bytes()?;
    let raw = STANDARD
        .decode(signed.sig.as_bytes())
        .map_err(|_| AgentError::Signature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| AgentError::Signature)?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| AgentError::Signature)?;
    key.verify_strict(&bytes, &signature)
        .map_err(|_| AgentError::Signature)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{path_prefix_ok, service_name_ok, sign_grant, verify_grant, AgentGrant};

    pub(crate) fn sample() -> AgentGrant {
        AgentGrant {
            version: 1,
            id: "0123456789abcdef".to_string(),
            agent: "spiffe://orblx.local/agent/helper".to_string(),
            requester: "spiffe://orblx.local/node/a".to_string(),
            approver: "spiffe://orblx.local/node/owner".to_string(),
            node: "spiffe://orblx.local/node/b".to_string(),
            addr: "100.64.0.2".to_string(),
            service: "web".to_string(),
            port: 8080,
            path_prefix: "/".to_string(),
            not_before: 1000,
            expires: 1300,
            ticket_hash: "00112233445566778899aabbccddeeff".to_string(),
        }
    }

    #[test]
    fn a_signed_grant_verifies_and_a_changed_grant_fails() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = sign_grant(&key, &sample()).unwrap();
        let public = key.verifying_key().to_bytes();
        verify_grant(&signed, &public).unwrap();
        let mut changed = signed.clone();
        changed.grant.port = 8081;
        assert!(verify_grant(&changed, &public).is_err());
        let other = SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(verify_grant(&signed, &other).is_err());
    }

    #[test]
    fn a_long_grant_is_refused() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut grant = sample();
        grant.expires = grant.not_before + 301;
        assert!(sign_grant(&key, &grant).is_err());
    }

    #[test]
    fn names_and_prefixes_are_bounded() {
        assert!(service_name_ok("web-1"));
        assert!(!service_name_ok("Web"));
        assert!(!service_name_ok(""));
        assert!(path_prefix_ok("/api/v1/"));
        assert!(!path_prefix_ok("api"));
        assert!(!path_prefix_ok("/a/../b"));
        assert!(!path_prefix_ok("/a?b"));
    }
}
