//! Coordinator signatures on endpoint candidates.
//!
//! ADR 0003 left the signer open.
//! The coordinator signs [`crate::endpoint_sign_payload`] with the netmap Ed25519 key.
//! This module verifies that signature before a node uses the address.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::endpoint_sign_payload;
use crate::EdgeError;

/// One endpoint candidate signed by the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCandidate {
    /// The node name.
    pub name: String,
    /// The `host:port` text that the coordinator signed.
    pub endpoint: String,
    /// The base64 Ed25519 signature.
    pub sig: String,
    /// The hex netmap key id.
    pub key_id: String,
}

/// The log line for a rejected candidate.
///
/// The line names the node.
/// The line does not contain the signature or the key.
#[must_use]
pub fn candidate_reject_line(name: &str) -> String {
    let safe = if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        "peer"
    } else {
        name
    };
    format!("The candidate signature for {safe} was rejected.")
}

/// Verify one coordinator signature.
///
/// A bad signature prints [`candidate_reject_line`].
/// The log line does not contain the signature.
pub fn verify_signed_candidate(
    signed: &SignedCandidate,
    public: &[u8; 32],
) -> Result<(), EdgeError> {
    match verify_inner(signed, public) {
        Ok(()) => Ok(()),
        Err(err) => {
            eprintln!("{}", candidate_reject_line(&signed.name));
            Err(err)
        }
    }
}

fn verify_inner(signed: &SignedCandidate, public: &[u8; 32]) -> Result<(), EdgeError> {
    if signed.key_id != encode_hex(public) {
        return Err(EdgeError::Signature);
    }
    let payload = endpoint_sign_payload(&signed.name, &signed.endpoint)?;
    let bytes = STANDARD
        .decode(signed.sig.as_bytes())
        .map_err(|_| EdgeError::Signature)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| EdgeError::Signature)?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| EdgeError::Signature)?;
    key.verify(payload.as_bytes(), &signature)
        .map_err(|_| EdgeError::Signature)
}

/// Decode 64 hex characters into 32 bytes.
pub fn decode_hex_key(text: &str) -> Result<[u8; 32], EdgeError> {
    let text = text.trim();
    if text.len() != 64 {
        return Err(EdgeError::Signature);
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = text
            .get(index * 2..index * 2 + 2)
            .ok_or(EdgeError::Signature)?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| EdgeError::Signature)?;
    }
    Ok(out)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    use super::{
        candidate_reject_line, decode_hex_key, encode_hex, verify_signed_candidate, SignedCandidate,
    };
    use crate::endpoint_sign_payload;

    fn sign(name: &str, endpoint: &str, seed: &[u8; 32]) -> SignedCandidate {
        let signing = SigningKey::from_bytes(seed);
        let payload = endpoint_sign_payload(name, endpoint).unwrap();
        let signature = signing.sign(payload.as_bytes());
        SignedCandidate {
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            sig: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            key_id: encode_hex(signing.verifying_key().as_bytes()),
        }
    }

    #[test]
    fn a_valid_candidate_signature_passes() {
        let seed = [7u8; 32];
        let signed = sign("node-a", "203.0.113.10:443", &seed);
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(signed.key_id, encode_hex(&public));
        verify_signed_candidate(&signed, &public).unwrap();
    }

    #[test]
    fn tampered_candidate_signature_is_rejected() {
        let seed = [7u8; 32];
        let signed = sign("node-a", "203.0.113.10:443", &seed);
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut tampered = signed.clone();
        tampered.endpoint = "203.0.113.11:443".to_string();
        let err = verify_signed_candidate(&tampered, &public).unwrap_err();
        assert_eq!(err, crate::EdgeError::Signature);
        let line = candidate_reject_line(&tampered.name);
        assert_eq!(line, "The candidate signature for node-a was rejected.");
        assert!(!line.contains(&tampered.sig));
        assert!(!line.contains(&encode_hex(&public)));
        let mut bad_sig = signed.clone();
        bad_sig.sig = "AAAA".to_string();
        assert_eq!(
            verify_signed_candidate(&bad_sig, &public).unwrap_err(),
            crate::EdgeError::Signature
        );
        assert!(decode_hex_key("zz").is_err());
    }
}
