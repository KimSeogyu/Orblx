//! Session audit hash chain.
//!
//! The chain records session start, session end, and session deny.
//! Each record stores the previous SHA-256 hash.
//! The hash covers the previous hash and the canonical event bytes.
//! An auditor can check an export file without the data path.
//! The Relay session id is `RelaySessionId`.
//! The frame session id is the datapath frame `session_id`.
//! The peer is a SPIFFE ID from `gyeol-identity`.
//! The ticket hash is `gyeol_identity::ticket_hash`.

mod chain;
mod demo;
mod error;
mod event;
mod hexutil;
mod metrics;

pub use chain::{
    canonical_bytes, event_hash, verify_file, verify_jsonl, AuditLog, ChainRecord, VerifiedChain,
    EVENT_VERSION, GENESIS_HASH,
};
pub use demo::{
    escape_demo, DEMO_DENY_FRAME, DEMO_DENY_PEER, DEMO_DENY_RELAY, DEMO_DENY_TICKET,
    DEMO_DENY_UNIX, DEMO_END_UNIX, DEMO_OK_FRAME, DEMO_OK_PEER, DEMO_OK_RELAY, DEMO_OK_TICKET,
    DEMO_START_UNIX,
};
pub use error::AuditError;
pub use event::{DenyReason, EventKind, SessionEvent, SessionIds};
pub use metrics::SessionMetrics;

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "gyeol-audit"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "gyeol-audit");
    }

    #[test]
    fn audit_manifest_has_no_datapath_and_no_forbidden_stack() {
        let text = include_str!("../Cargo.toml").to_ascii_lowercase();
        for banned in [
            "gyeol-datapath",
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
