//! The signed deny list (W25-37).
//!
//! The coordinator signs the deny object with the netmap Ed25519 key.
//! The signed message is [`DENY_SIGN_PREFIX`] plus the raw deny object bytes.
//! [`deny_sign_message`] is the only function that builds that message.
//! The verifier checks the signature over the received bytes. It does not
//! encode the object again.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::codec::encode_hex;
use crate::error::IdentityError;

/// The domain-separation prefix for a deny list signature.
///
/// The prefix is 19 bytes and ends with `\n`. A netmap message and a grants
/// message start with `{`. This message starts with `o`.
pub const DENY_SIGN_PREFIX: &[u8] = b"orblx-deny-list-v1\n";

/// The age after which the node logs `ALERT deny-fetch-old` (W25-37).
pub const DENY_FETCH_OLD_MS: u64 = 5 * 60 * 1000;

/// The state file with the Unix ms time of the last good deny fetch.
pub const DENY_FETCH_FILE: &str = "deny-fetch-ok";

/// `DENY_SIGN_PREFIX` plus `raw`. This is the only way to build the deny sign message.
#[must_use]
pub fn deny_sign_message(raw: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DENY_SIGN_PREFIX.len() + raw.len());
    message.extend_from_slice(DENY_SIGN_PREFIX);
    message.extend_from_slice(raw);
    message
}

/// The deny object that the netmap key signs (W25-37).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyObject {
    pub version: u64,
    pub generated_at: u64,
    pub revoked_uris: Vec<String>,
    pub revoked_ticket_nonces: Vec<String>,
    /// The node SVID URI, for example `spiffe://orblx.local/node/a`.
    pub node_uri: String,
    pub seq: u64,
    pub issued_at_ms: u64,
}

/// One deny list that passed the signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeny {
    object: DenyObject,
    raw: Vec<u8>,
    key_id: String,
}

impl VerifiedDeny {
    /// The parsed deny object.
    #[must_use]
    pub fn object(&self) -> &DenyObject {
        &self.object
    }

    /// The received deny object bytes. The signature covers these bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    #[must_use]
    pub fn seq(&self) -> u64 {
        self.object.seq
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.object.version
    }

    #[must_use]
    pub fn issued_at_ms(&self) -> u64 {
        self.object.issued_at_ms
    }

    #[must_use]
    pub fn node_uri(&self) -> &str {
        &self.object.node_uri
    }

    /// The lowercase hex of the netmap public key that signed this list.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Sign `raw` with `key` and return the wire JSON.
///
/// `raw` is the deny object bytes. The function signs [`deny_sign_message`] of
/// those bytes and checks the signature with `verify_strict` before it returns.
pub fn seal_deny(key: &SigningKey, raw: &[u8]) -> Result<String, IdentityError> {
    if raw.first() != Some(&b'{') {
        return Err(IdentityError::DenyDocument);
    }
    let message = deny_sign_message(raw);
    let signature = key.sign(&message);
    key.verifying_key()
        .verify_strict(&message, &signature)
        .map_err(|_| IdentityError::Signature)?;
    let sig = STANDARD.encode(signature.to_bytes());
    let key_id = encode_hex(key.verifying_key().as_bytes());
    deny_wire(raw, &sig, &key_id)
}

/// Build the wire JSON. The function embeds `raw` unchanged.
pub fn deny_wire(raw: &[u8], sig: &str, key_id: &str) -> Result<String, IdentityError> {
    let text = std::str::from_utf8(raw).map_err(|_| IdentityError::DenyDocument)?;
    let deny = RawValue::from_string(text.to_string()).map_err(|_| IdentityError::DenyDocument)?;
    let wire = SignedDenyWire {
        deny: &deny,
        sig,
        key_id,
    };
    serde_json::to_string(&wire).map_err(|_| IdentityError::DenyDocument)
}

#[derive(Serialize)]
struct SignedDenyWire<'a> {
    deny: &'a RawValue,
    sig: &'a str,
    key_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedDenyIn {
    deny: Box<RawValue>,
    sig: String,
    key_id: String,
}

/// Check one received deny list.
///
/// `public` is the netmap public key. The function does not build a key from
/// `key_id`. `node_uri` is the node SVID URI. The check uses the received
/// deny object bytes.
pub fn verify_signed_deny(
    bytes: &[u8],
    public: &[u8; 32],
    node_uri: &str,
) -> Result<VerifiedDeny, IdentityError> {
    let wire: SignedDenyIn =
        serde_json::from_slice(bytes).map_err(|_| IdentityError::DenyDocument)?;
    let raw = wire.deny.get().as_bytes();
    if raw.first() != Some(&b'{') {
        return Err(IdentityError::DenyDocument);
    }
    let key_id = encode_hex(public);
    if wire.key_id != key_id {
        return Err(IdentityError::Signature);
    }
    let sig_bytes = STANDARD
        .decode(wire.sig.as_bytes())
        .map_err(|_| IdentityError::Signature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| IdentityError::Signature)?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| IdentityError::Signature)?;
    let message = deny_sign_message(raw);
    key.verify_strict(&message, &signature)
        .map_err(|_| IdentityError::Signature)?;
    let object: DenyObject =
        serde_json::from_slice(raw).map_err(|_| IdentityError::DenyDocument)?;
    if object.seq == 0 || object.issued_at_ms == 0 {
        return Err(IdentityError::DenyDocument);
    }
    if object.node_uri != node_uri {
        return Err(IdentityError::DenyDocument);
    }
    Ok(VerifiedDeny {
        object,
        raw: raw.to_vec(),
        key_id,
    })
}

/// Return the age in seconds when the node must log `ALERT deny-fetch-old`.
///
/// The first alert is when the age is more than 5 min. The next alert is 5 min
/// after `last_alert_ms`. The function does not refuse a session.
#[must_use]
pub fn deny_fetch_old_age(ok_ms: u64, now_ms: u64, last_alert_ms: Option<u64>) -> Option<u64> {
    let age = now_ms.saturating_sub(ok_ms);
    if age <= DENY_FETCH_OLD_MS {
        return None;
    }
    if let Some(last) = last_alert_ms {
        if now_ms.saturating_sub(last) < DENY_FETCH_OLD_MS {
            return None;
        }
    }
    Some(age / 1000)
}

/// The alert line for one old deny fetch.
#[must_use]
pub fn deny_fetch_old_line(age_s: u64) -> String {
    format!("ALERT deny-fetch-old age_s {age_s}")
}

/// One status line for the last good deny fetch.
#[must_use]
pub fn deny_fetch_status_line(ok_ms: u64, now_ms: u64) -> String {
    let age_s = now_ms.saturating_sub(ok_ms) / 1000;
    format!("deny_fetch_ok_ms {ok_ms} age_s {age_s}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn object(node: &str, seq: u64, version: u64) -> Vec<u8> {
        let object = DenyObject {
            version,
            generated_at: 10,
            revoked_uris: vec!["spiffe://orblx.local/node/b".to_string()],
            revoked_ticket_nonces: Vec::new(),
            node_uri: node.to_string(),
            seq,
            issued_at_ms: seq,
        };
        serde_json::to_vec(&object).unwrap()
    }

    const NODE: &str = "spiffe://orblx.local/node/a";

    #[test]
    fn deny_sign_prefix_bytes_are_fixed() {
        assert_eq!(DENY_SIGN_PREFIX, b"orblx-deny-list-v1\n");
        assert_eq!(DENY_SIGN_PREFIX.len(), 19);
        assert_eq!(DENY_SIGN_PREFIX.last(), Some(&b'\n'));
        assert_ne!(DENY_SIGN_PREFIX.first(), Some(&b'{'));
    }

    #[test]
    fn a_valid_signed_list_is_accepted() {
        let key = key_from(3);
        let raw = object(NODE, 50, 1);
        let text = seal_deny(&key, &raw).unwrap();
        let verified =
            verify_signed_deny(text.as_bytes(), key.verifying_key().as_bytes(), NODE).unwrap();
        assert_eq!(verified.raw(), raw.as_slice());
        assert_eq!(verified.seq(), 50);
        assert_eq!(verified.node_uri(), NODE);
    }

    #[test]
    fn a_bit_flip_in_the_payload_or_the_signature_is_refused() {
        let key = key_from(3);
        let raw = object(NODE, 50, 1);
        let text = seal_deny(&key, &raw).unwrap();
        let public = key.verifying_key().to_bytes();
        let mut payload = text.clone().into_bytes();
        let at = payload.iter().position(|byte| *byte == b'b').unwrap();
        payload[at] ^= 1;
        assert!(verify_signed_deny(&payload, &public, NODE).is_err());
        let mut signature = text.into_bytes();
        let sig_at = signature
            .windows(5)
            .position(|window| window == b"\"sig\"")
            .unwrap()
            + 8;
        signature[sig_at] ^= 1;
        assert!(verify_signed_deny(&signature, &public, NODE).is_err());
    }

    #[test]
    fn a_list_signed_by_another_key_is_refused() {
        let key = key_from(3);
        let other = key_from(4);
        let raw = object(NODE, 50, 1);
        let text = seal_deny(&other, &raw).unwrap();
        assert!(verify_signed_deny(text.as_bytes(), key.verifying_key().as_bytes(), NODE).is_err());
        let wire = deny_wire(&raw, "AAAA", &encode_hex(key.verifying_key().as_bytes())).unwrap();
        let message = deny_sign_message(&raw);
        let sig = STANDARD.encode(other.sign(&message).to_bytes());
        let matched = deny_wire(&raw, &sig, &encode_hex(key.verifying_key().as_bytes())).unwrap();
        assert!(
            verify_signed_deny(matched.as_bytes(), key.verifying_key().as_bytes(), NODE).is_err()
        );
        let _ = wire;
    }

    #[test]
    fn a_list_for_another_node_uri_is_refused() {
        let key = key_from(3);
        let raw = object("spiffe://orblx.local/node/b", 50, 1);
        let text = seal_deny(&key, &raw).unwrap();
        assert!(verify_signed_deny(text.as_bytes(), key.verifying_key().as_bytes(), NODE).is_err());
        let other_domain = object("spiffe://other.local/node/a", 50, 1);
        let text = seal_deny(&key, &other_domain).unwrap();
        assert!(verify_signed_deny(text.as_bytes(), key.verifying_key().as_bytes(), NODE).is_err());
    }

    #[test]
    fn a_wrong_prefix_or_a_missing_prefix_is_refused() {
        let key = key_from(3);
        let raw = object(NODE, 50, 1);
        let public = key.verifying_key().to_bytes();
        let key_id = encode_hex(&public);
        let bare = key.sign(&raw);
        let missing = deny_wire(&raw, &STANDARD.encode(bare.to_bytes()), &key_id).unwrap();
        assert!(verify_signed_deny(missing.as_bytes(), &public, NODE).is_err());
        let mut wrong = b"orblx-deny-list-v2\n".to_vec();
        wrong.extend_from_slice(&raw);
        let sig = key.sign(&wrong);
        let text = deny_wire(&raw, &STANDARD.encode(sig.to_bytes()), &key_id).unwrap();
        assert!(verify_signed_deny(text.as_bytes(), &public, NODE).is_err());
    }

    #[test]
    fn a_payload_whose_first_byte_is_not_an_object_is_refused() {
        let key = key_from(3);
        let raw = b"1";
        let message = deny_sign_message(raw);
        let sig = STANDARD.encode(key.sign(&message).to_bytes());
        let text = deny_wire(raw, &sig, &encode_hex(key.verifying_key().as_bytes())).unwrap();
        assert!(verify_signed_deny(text.as_bytes(), key.verifying_key().as_bytes(), NODE).is_err());
    }

    #[test]
    fn the_verifier_uses_the_received_bytes() {
        let key = key_from(3);
        let raw = br#"{"version":1, "generated_at":10,"revoked_uris":[],"revoked_ticket_nonces":[],"node_uri":"spiffe://orblx.local/node/a","seq":50,"issued_at_ms":50}"#;
        let text = seal_deny(&key, raw).unwrap();
        let verified =
            verify_signed_deny(text.as_bytes(), key.verifying_key().as_bytes(), NODE).unwrap();
        assert_eq!(verified.raw(), raw);
        assert!(verified.raw().windows(2).any(|pair| pair == b", "));
    }

    #[test]
    fn an_uppercase_key_id_is_refused() {
        let key = key_from(3);
        let raw = object(NODE, 50, 1);
        let message = deny_sign_message(&raw);
        let sig = STANDARD.encode(key.sign(&message).to_bytes());
        let upper = encode_hex(key.verifying_key().as_bytes()).to_ascii_uppercase();
        let text = deny_wire(&raw, &sig, &upper).unwrap();
        assert!(verify_signed_deny(text.as_bytes(), key.verifying_key().as_bytes(), NODE).is_err());
    }

    #[test]
    fn deny_fetch_old_uses_the_given_clock() {
        let ok = 1_000_000;
        assert_eq!(deny_fetch_old_age(ok, ok + DENY_FETCH_OLD_MS, None), None);
        let age_s = deny_fetch_old_age(ok, ok + DENY_FETCH_OLD_MS + 1, None).unwrap();
        assert_eq!(age_s, (DENY_FETCH_OLD_MS + 1) / 1000);
        assert!(deny_fetch_old_line(age_s).starts_with("ALERT deny-fetch-old age_s "));
        let fired = ok + DENY_FETCH_OLD_MS + 1;
        assert_eq!(
            deny_fetch_old_age(ok, fired + DENY_FETCH_OLD_MS - 1, Some(fired)),
            None
        );
        assert!(deny_fetch_old_age(ok, fired + DENY_FETCH_OLD_MS, Some(fired)).is_some());
    }
}
