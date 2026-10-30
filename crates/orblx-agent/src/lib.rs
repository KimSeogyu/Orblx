//! Agent JIT grants.
//!
//! An agent asks the coordinator for one grant.
//! A grant names one target node, one service, one TCP port, and a life of
//! 5 minutes or less. An owner approves the grant.
//! The coordinator then issues a short agent SVID, one agent JIT ticket,
//! and one signed grant document.
//! The agent shows a proof line to the guard on the target node.
//! The guard checks the proof, the ticket, the grant, and the deny set
//! for each new connection, and writes each decision to a hash chain.
//! The HTTP gateway uses the same checks for each request, and adds a path
//! scope and a nonce replay check.
//!
//! This crate adds no new cryptographic design.
//! It uses the SVID, Ed25519 signatures, and the W19 SSH JIT ticket pattern.

mod client;
mod gateway;
mod grant;
mod guard;
mod hex;
mod nonce_store;
mod proof;

pub use client::{connect, ConnectError, GrantFiles};
pub use gateway::{
    check_request, forward_bytes, header_block, http_extra, new_nonce, parse_request,
    path_in_scope, plain_http_request, request_header, run_gateway, seal_http_request, send_http,
    GatewayDecision, HttpReply, RequestHead, NONCE_HEADER, PROOF_HEADER,
};
pub use grant::{
    grant_id_ok, path_prefix_ok, service_name_ok, sign_grant, verify_grant, AgentGrant,
    SignedAgentGrant, GRANT_VERSION, MAX_GRANT_SECS,
};
pub use guard::{run_guard, DenyFetch, GuardConfig, GuardCore, GuardDecision, RequestCheck};
pub use nonce_store::default_nonce_path;
pub use proof::{
    open_use, seal_use, unix_millis, Admitted, Refused, UseTarget, UseTrust, PROOF_WINDOW_SECS,
};

/// An agent grant error.
///
/// The text does not hold a key, a ticket, or a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// The grant document is not valid.
    Grant,
    /// A signature check failed.
    Signature,
    /// A key or a certificate is not valid.
    Key,
    /// The proof is not valid or is too large.
    Proof,
    /// The clock is not valid.
    Time,
    /// A file or a socket call failed.
    Io(String),
    /// The audit chain call failed.
    Audit(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grant => write!(formatter, "The grant is not valid."),
            Self::Signature => write!(formatter, "The grant signature is not valid."),
            Self::Key => write!(formatter, "The agent key or certificate is not valid."),
            Self::Proof => write!(formatter, "The grant proof is not valid."),
            Self::Time => write!(formatter, "The clock is not valid."),
            Self::Io(text) => write!(formatter, "The file or socket call failed. {text}"),
            Self::Audit(text) => write!(formatter, "The audit chain call failed. {text}"),
        }
    }
}

impl std::error::Error for AgentError {}

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "orblx-agent"
}
