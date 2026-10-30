//! Audit webhook body and signature (W25-7).
//!
//! The coordinator posts each config audit record to the audit webhook URLs in the policy.
//! The body holds the record id (the record hash), the sequence number (the record index),
//! and the full record.
//! The header [`WEBHOOK_SIGNATURE_HEADER`] holds HMAC-SHA256 over the body bytes.
//! The HMAC key is a shared secret from an env var or a file. The policy never holds it.

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

use crate::hexutil::{decode_hex_array, encode_hex};
use crate::AuditError;

/// The HTTP header that holds the body signature.
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-Orblx-Signature";

/// The `type` value in each webhook body.
pub const WEBHOOK_BODY_TYPE: &str = "orblx.config-audit";

/// The webhook body version.
pub const WEBHOOK_BODY_VERSION: u8 = 1;

/// The shortest webhook secret in bytes.
pub const MIN_WEBHOOK_SECRET: usize = 32;

/// The longest webhook secret in bytes.
pub const MAX_WEBHOOK_SECRET: usize = 1024;

/// One webhook body for one config audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookBody {
    /// The record index. The first record has 0.
    pub seq: u64,
    /// The record hash as lowercase hex. The id is unique in one chain.
    pub id: String,
    /// The action name, for example `revoke`.
    pub action: String,
    /// The record time in Unix seconds (UTC).
    pub at_unix: u64,
    /// The record time as RFC 3339 UTC text, for example `2026-10-30T12:00:00Z`.
    pub at_utc: String,
    /// The JSON body bytes.
    pub json: String,
}

#[derive(Serialize)]
struct BodyOut<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    version: u8,
    id: &'a str,
    seq: u64,
    record: &'a serde_json::Value,
}

/// Make the webhook body for one config chain line.
///
/// The line is one line of `config-audit.jsonl` without the line end.
pub fn webhook_body(line: &str) -> Result<WebhookBody, AuditError> {
    let record: serde_json::Value =
        serde_json::from_str(line).map_err(|_| AuditError::BadLine { line: 0 })?;
    let seq = record
        .get("index")
        .and_then(serde_json::Value::as_u64)
        .ok_or(AuditError::BadLine { line: 0 })?;
    let id = record
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuditError::BadLine { line: 0 })?;
    decode_hex_array::<32>(id).map_err(|_| AuditError::BadLine { line: 0 })?;
    let action = record
        .get("action")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuditError::BadLine { line: 0 })?
        .to_string();
    let at_unix = record
        .get("at_unix")
        .and_then(serde_json::Value::as_u64)
        .ok_or(AuditError::BadLine { line: 0 })?;
    let at_utc = record
        .get("at_utc")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuditError::BadLine { line: 0 })?
        .to_string();
    let json = serde_json::to_string(&BodyOut {
        kind: WEBHOOK_BODY_TYPE,
        version: WEBHOOK_BODY_VERSION,
        id,
        seq,
        record: &record,
    })
    .map_err(|_| AuditError::Export)?;
    Ok(WebhookBody {
        seq,
        id: id.to_string(),
        action,
        at_unix,
        at_utc,
        json,
    })
}

/// Return `sha256=<hex>`: HMAC-SHA256 of `body` with `secret`.
#[must_use]
pub fn webhook_signature(secret: &[u8], body: &[u8]) -> String {
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret) {
        Ok(mac) => mac,
        // HMAC accepts a key of any length, so this branch does not run.
        Err(_) => return String::new(),
    };
    mac.update(body);
    format!("sha256={}", encode_hex(&mac.finalize().into_bytes()))
}

/// Return true when `header` is the HMAC-SHA256 signature of `body` with `secret`.
///
/// The compare uses constant time.
#[must_use]
pub fn webhook_signature_ok(secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(hex) = header.trim().strip_prefix("sha256=") else {
        return false;
    };
    let Ok(tag) = decode_hex_array::<32>(hex) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&tag).is_ok()
}

/// Check the webhook secret bytes.
///
/// The function removes one line end. The secret has 32 to 1024 bytes.
/// The error text does not hold the secret.
pub fn webhook_secret(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut bytes = raw;
    if let Some(rest) = bytes.strip_suffix(b"\n") {
        bytes = rest;
    }
    if let Some(rest) = bytes.strip_suffix(b"\r") {
        bytes = rest;
    }
    if bytes.len() < MIN_WEBHOOK_SECRET {
        return Err("The audit webhook secret has fewer than 32 bytes.");
    }
    if bytes.len() > MAX_WEBHOOK_SECRET {
        return Err("The audit webhook secret has more than 1024 bytes.");
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigAction, ConfigEvent, ConfigLog};

    fn one_line(tag: &str) -> (String, crate::ConfigRecord) {
        let dir = std::env::temp_dir().join(format!("orblx-webhook-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut log = ConfigLog::open(&dir.join("c.jsonl")).unwrap();
        let record = log
            .append(ConfigEvent {
                actor: "spiffe://orblx.local/node/owner".to_string(),
                at_unix: 1_700_000_000,
                action: ConfigAction::Revoke,
                target: "a".to_string(),
                before: [1; 32],
                after: [2; 32],
                detail: "note".to_string(),
            })
            .unwrap();
        let line = record.to_json_line().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (line, record)
    }

    #[test]
    fn the_body_has_the_record_id_and_sequence() {
        let (line, record) = one_line("body");
        let body = webhook_body(&line).unwrap();
        assert_eq!(body.seq, record.index);
        assert_eq!(body.id, encode_hex(&record.hash));
        assert_eq!(body.action, "revoke");
        let value: serde_json::Value = serde_json::from_str(&body.json).unwrap();
        assert_eq!(value["type"], WEBHOOK_BODY_TYPE);
        assert_eq!(value["id"], body.id.as_str());
        assert_eq!(value["seq"], 0);
        assert_eq!(value["record"]["target"], "a");
        assert!(webhook_body("{\"index\": 0}").is_err());
        assert!(webhook_body("not json").is_err());
    }

    #[test]
    fn hmac_sha256_known_answer() {
        // RFC 4231 test case 2.
        let sig = webhook_signature(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_changed_body_fails_the_signature_check() {
        let secret = [7u8; 32];
        let (line, _) = one_line("sig");
        let body = webhook_body(&line).unwrap();
        let sig = webhook_signature(&secret, body.json.as_bytes());
        assert!(webhook_signature_ok(&secret, body.json.as_bytes(), &sig));
        let changed = body.json.replace("\"a\"", "\"b\"");
        assert_ne!(changed, body.json);
        assert!(!webhook_signature_ok(&secret, changed.as_bytes(), &sig));
        assert!(!webhook_signature_ok(
            &[8u8; 32],
            body.json.as_bytes(),
            &sig
        ));
        assert!(!webhook_signature_ok(
            &secret,
            body.json.as_bytes(),
            "sha256=00"
        ));
        assert!(!webhook_signature_ok(&secret, body.json.as_bytes(), ""));
    }

    #[test]
    fn the_secret_needs_32_bytes() {
        assert!(webhook_secret(b"short\n").is_err());
        assert_eq!(webhook_secret(&[b'k'; 33]).unwrap().len(), 33);
        let mut with_end = vec![b'k'; 32];
        with_end.extend_from_slice(b"\r\n");
        assert_eq!(webhook_secret(&with_end).unwrap().len(), 32);
        assert!(webhook_secret(&[b'k'; 1025]).is_err());
    }
}
