//! Mini CA, OIDC issue, capability tickets, and the deny list.
//!
//! The trust domain is `orblx.local`.
//! A human SVID is `spiffe://orblx.local/user/{oidc_sub}`.
//! City Breeze uses a Google ID token.
//! `OidcIssuer` and `OidcJwks` check an ID token from a generic issuer with `RS256` or `ES256`.
//! The Google subject is the SPIFFE user name.
//! `MockOidc` remains for CI and the harness when `ORBLX_OIDC_MODE=mock`.
//! An agent SVID is `spiffe://orblx.local/agent/{id}`.
//! The agent SVID requires a parent human ID token.
//! The agent SVID life is at most 5 minutes.
//! The SVID key is Ed25519.
//! The ticket key is a different Ed25519 key.
//! An agent capability ticket is separate from the SVID.
//! The agent ticket allows one destination.
//! Every other agent destination is denied.
//! `Policy::from_hujson` loads groups, tags, accept rules, route approval, node approval, owners, SSH rules, and inline tests.
//! A failed test rejects the file.
//! `autoApprovers` and `routeApprovals` approve subnet CIDRs.
//! `autoApprovers.exitNode` approves an exit node.
//! `0.0.0.0/0` stays an exit route.
//! Node enrollment calls `IssueGate::owner_subject`.
//! That call does not issue the node SVID.
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
mod google;
mod issuer;
mod oidc;
mod policy;
mod share;
mod spiffe;
mod ticket;
mod user_approval;

pub use ca::{IssuedSvid, MiniCa};
pub use cert::{
    decode_certificate_pem, decode_certificate_pem_file, extract_spiffe_id, leaf_not_after,
    leaf_validity, TrustBundle,
};
pub use clock::{MAX_AGENT_TTL, MAX_SKEW, MAX_USER_TTL};
pub use deny::{DenyApply, DenySet};
pub use error::IdentityError;
pub use google::{
    google_client_id_ok, GoogleClient, GoogleIdClaims, GoogleJwks, GoogleTokenRequest, OidcMode,
    GOOGLE_AUTHORIZE_ENDPOINT, GOOGLE_CLIENT_ID_ENV, GOOGLE_CLIENT_SECRET_ENV, GOOGLE_ISSUER,
    GOOGLE_JWKS_URL, GOOGLE_REDIRECT_LOCALHOST, GOOGLE_REDIRECT_LOOPBACK, GOOGLE_TOKEN_ENDPOINT,
    OIDC_MODE_ENV,
};
pub use issuer::{token_kid, OidcIdClaims, OidcIssuer, OidcJwks, OidcReject, DISCOVERY_PATH};
pub use oidc::{AgentSvid, IssueGate, MockOidc, MOCK_OIDC_ISSUER, OIDC_AUDIENCE};
pub use policy::{
    Policy, PolicyAssertion, PolicyError, ReceiverGrant, ReceiverGrants, SplitDnsZone,
    SshAssertion, SubnetGrant,
};

/// Return the Ed25519 seed from a PKCS#8 private key PEM.
///
/// The caller must not write the seed to a log.
pub fn ed25519_seed_from_private_pem(pem: &str) -> Result<[u8; 32], IdentityError> {
    let blocks = codec::pem_blocks(pem, "PRIVATE KEY")?;
    if blocks.len() != 1 {
        return Err(IdentityError::Certificate);
    }
    let (seed, _) = codec::ed25519_seed_from_pkcs8(&blocks[0])?;
    Ok(seed)
}

/// Return the Ed25519 public key from a certificate PEM.
pub fn ed25519_public_key_from_certificate_pem(pem: &str) -> Result<[u8; 32], IdentityError> {
    let der = decode_certificate_pem(pem)?;
    cert::certificate_ed25519_public_key(&der)
}
/// Return the Ed25519 public key from a leaf certificate DER.
///
/// The function does not check the certificate chain.
/// Call `TrustBundle::authenticate_leaf` first.
pub fn leaf_ed25519_public_key(der: &[u8]) -> Result<[u8; 32], IdentityError> {
    cert::certificate_ed25519_public_key(der)
}
pub use share::{rules_without_shares, Share, ShareGuest};
pub use spiffe::{SpiffeId, WorkloadKind, TRUST_DOMAIN};
pub use ticket::{
    allow_agent_jit, sign_agent_jit_ticket, sign_ticket, ticket_hash, verify_ticket,
    Ipv4Destination, SignedTicket, TicketClaims, TicketFlags, TicketSigner, TicketVerifier,
    VerifiedTicket, FLAG_AGENT_JIT, FLAG_ONE_SHOT,
};
pub use user_approval::UserApproval;

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "orblx-identity"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "orblx-identity");
    }
}
