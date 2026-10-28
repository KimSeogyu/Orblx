//! Mini CA, mock OIDC issue, capability tickets, and the deny list.
//!
//! The trust domain is `gyeol.local`.
//! A human SVID is `spiffe://gyeol.local/user/{oidc_sub}`.
//! An agent SVID is `spiffe://gyeol.local/agent/{id}`.
//! The agent SVID requires a parent human ID token.
//! The agent SVID life is at most 5 minutes.
//! The SVID key is Ed25519.
//! The ticket key is a different Ed25519 key.
//! An agent capability ticket is separate from the SVID.
//! The agent ticket allows one destination.
//! Every other agent destination is denied.
//!
//! `decode_certificate_pem_file` reads one certificate PEM file.
//! `TrustBundle::from_pem_file` reads a trust bundle PEM file.
//! `IssuedSvid::from_pem_files` reads a leaf certificate PEM file and a private key PEM file.
//! Those functions read the file text and call the in-memory PEM decode path.

mod ca;
mod cert;
mod clock;
mod codec;
mod deny;
mod error;
mod oidc;
mod spiffe;
mod ticket;

pub use ca::{IssuedSvid, MiniCa};
pub use cert::{
    decode_certificate_pem, decode_certificate_pem_file, extract_spiffe_id, TrustBundle,
};
pub use clock::{MAX_AGENT_TTL, MAX_SKEW, MAX_USER_TTL};
pub use deny::{DenyApply, DenySet};
pub use error::IdentityError;
pub use oidc::{AgentSvid, IssueGate, MockOidc, MOCK_OIDC_ISSUER, OIDC_AUDIENCE};
pub use spiffe::{SpiffeId, WorkloadKind, TRUST_DOMAIN};
pub use ticket::{
    allow_agent_jit, sign_agent_jit_ticket, sign_ticket, ticket_hash, verify_ticket,
    Ipv4Destination, SignedTicket, TicketClaims, TicketFlags, TicketSigner, TicketVerifier,
    VerifiedTicket, FLAG_AGENT_JIT, FLAG_ONE_SHOT,
};

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "gyeol-identity"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "gyeol-identity");
    }
}
