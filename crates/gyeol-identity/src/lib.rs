//! Mini CA, mock OIDC issue, capability tickets, and the deny list.
//!
//! The trust domain is `gyeol.local`.
//! A human SVID is `spiffe://gyeol.local/user/{oidc_sub}`.
//! The SVID key is Ed25519.
//! The ticket key is a different Ed25519 key.

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
pub use cert::{decode_certificate_pem, extract_spiffe_id, TrustBundle};
pub use clock::{MAX_AGENT_TTL, MAX_SKEW, MAX_USER_TTL};
pub use deny::{DenyApply, DenySet};
pub use error::IdentityError;
pub use oidc::{IssueGate, MockOidc, MOCK_OIDC_ISSUER, OIDC_AUDIENCE};
pub use spiffe::{SpiffeId, WorkloadKind, TRUST_DOMAIN};
pub use ticket::{
    sign_ticket, ticket_hash, verify_ticket, SignedTicket, TicketClaims, TicketFlags, TicketSigner,
    TicketVerifier, VerifiedTicket, FLAG_AGENT_JIT, FLAG_ONE_SHOT,
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
