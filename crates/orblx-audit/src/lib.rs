//! Session audit hash chain.
//!
//! The chain records session start, session end, session deny, and session recording.
//! A record event stores the SHA-256 of one SSH session recording file.
//! Each record stores the previous SHA-256 hash.
//! The hash covers the previous hash and the canonical event bytes.
//! An auditor can check an export file without the data path.
//! The Relay session id is `RelaySessionId`.
//! The frame session id is the datapath frame `session_id`.
//! The peer is a SPIFFE ID from `orblx-identity`.
//! The ticket hash is `orblx_identity::ticket_hash`.
//!
//! A second chain records control-plane changes. See [`ConfigLog`].

mod chain;
mod config;
mod demo;
mod error;
mod event;
mod expose;
mod hexutil;
mod metrics;
mod siem;
mod webhook;

pub use chain::{
    canonical_bytes, event_hash, recording_path_ok, verify_file, verify_jsonl, AuditLog,
    ChainRecord, VerifiedChain, EVENT_VERSION, GENESIS_HASH,
};
pub use config::{
    config_canonical_bytes, config_hash, digest_hex, parse_utc_text, sha256_digest, utc_text,
    verify_config_file, verify_config_jsonl, ConfigAction, ConfigEvent, ConfigLog, ConfigRecord,
    VerifiedConfig, CONFIG_EVENT_VERSION, EMPTY_DIGEST, MAX_CONFIG_TEXT,
};
pub use demo::{
    escape_demo, DEMO_DENY_FRAME, DEMO_DENY_PEER, DEMO_DENY_RELAY, DEMO_DENY_TICKET,
    DEMO_DENY_UNIX, DEMO_END_UNIX, DEMO_OK_FRAME, DEMO_OK_PEER, DEMO_OK_RELAY, DEMO_OK_TICKET,
    DEMO_START_UNIX,
};
pub use error::AuditError;
pub use event::{DenyReason, EventKind, SessionEvent, SessionIds};
pub use expose::{default_metrics_addr, sample_line, spawn_metrics_server, DEFAULT_METRICS_PORT};
pub use metrics::SessionMetrics;
pub use siem::{
    datadog_batch, ndjson_batch, splunk_hec_batch, syslog_frame, syslog_host, SIEM_SOURCE,
    SIEM_SOURCETYPE, SYSLOG_APP_NAME, SYSLOG_MSG_ID, SYSLOG_PRI, SYSLOG_SD_ID,
};
pub use webhook::{
    webhook_body, webhook_secret, webhook_signature, webhook_signature_ok, WebhookBody,
    MAX_WEBHOOK_SECRET, MIN_WEBHOOK_SECRET, WEBHOOK_BODY_TYPE, WEBHOOK_BODY_VERSION,
    WEBHOOK_SIGNATURE_HEADER,
};

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "orblx-audit"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "orblx-audit");
    }

    #[test]
    fn audit_manifest_has_no_datapath_and_no_forbidden_stack() {
        let text = include_str!("../Cargo.toml").to_ascii_lowercase();
        for banned in [
            "orblx-datapath",
            "quinn",
            "rustls",
            "wireguard",
            "boringtun",
            "headscale",
            "derp",
            "tailscale",
            "defguard",
        ] {
            assert!(!text.contains(banned), "the audit manifest names {banned}");
        }
    }
}
