use std::fmt;

use orblx_identity::IdentityError;

/// A failure from the crypto scaffold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The handshake phase does not allow this call.
    Phase,
    /// The cipher suite is outside the locked pair.
    Suite,
    /// The HKDF input is not valid.
    Schedule,
    /// The X25519 shared secret is all zeros.
    SharedSecret,
    /// The peer SPIFFE URI is not available for this call.
    PeerUri,
    /// The ticket HMAC-SHA256 check failed.
    TicketMac,
    /// The ticket subject differs from the peer SPIFFE URI.
    TicketSubject,
    /// The frame ticket hash differs from the verified ticket.
    TicketHash,
    /// The ticket key is outside its validity window or the key set is not valid.
    TicketKey,
    /// The ticket key matches the SVID CA key.
    TicketKeySeparation,
    /// The two ticket keys overlap for more than 24 hours.
    TicketOverlap,
    /// The epoch is due. Run a new handshake.
    Rehandshake,
    /// The session cap or the SVID cap rejected the leaf.
    SessionCap,
    /// Identity rejected the leaf, the signature, the time, or the deny list.
    Identity(IdentityError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Phase => {
                formatter.write_str("The handshake phase does not allow this call.")
            }
            CryptoError::Suite => formatter.write_str(
                "The cipher suite is not TLS_AES_128_GCM_SHA256 or TLS_CHACHA20_POLY1305_SHA256.",
            ),
            CryptoError::Schedule => formatter.write_str("The key schedule input is not valid."),
            CryptoError::SharedSecret => {
                formatter.write_str("The X25519 shared secret is all zeros.")
            }
            CryptoError::PeerUri => {
                formatter.write_str("The peer SPIFFE URI is not available for this call.")
            }
            CryptoError::TicketMac => formatter.write_str("The ticket HMAC-SHA256 check failed."),
            CryptoError::TicketSubject => {
                formatter.write_str("The ticket subject differs from the peer SPIFFE URI.")
            }
            CryptoError::TicketHash => {
                formatter.write_str("The frame ticket hash differs from the verified ticket.")
            }
            CryptoError::TicketKey => {
                formatter.write_str("The ticket key is not valid for this call.")
            }
            CryptoError::TicketKeySeparation => {
                formatter.write_str("The ticket key matches the SVID CA key.")
            }
            CryptoError::TicketOverlap => {
                formatter.write_str("The ticket key overlap is longer than 24 hours.")
            }
            CryptoError::Rehandshake => {
                formatter.write_str("The session must run a new handshake.")
            }
            CryptoError::SessionCap => formatter.write_str("The session cap check failed."),
            CryptoError::Identity(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::Identity(err) => Some(err),
            CryptoError::Phase
            | CryptoError::Suite
            | CryptoError::Schedule
            | CryptoError::SharedSecret
            | CryptoError::PeerUri
            | CryptoError::TicketMac
            | CryptoError::TicketSubject
            | CryptoError::TicketHash
            | CryptoError::TicketKey
            | CryptoError::TicketKeySeparation
            | CryptoError::TicketOverlap
            | CryptoError::Rehandshake
            | CryptoError::SessionCap => None,
        }
    }
}
