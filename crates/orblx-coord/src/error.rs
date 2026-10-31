use std::fmt;

use orblx_identity::IdentityError;

/// A failure from the coordinator.
#[derive(Debug)]
pub enum CoordError {
    /// A file or socket operation failed.
    Io(String),
    /// The identity check failed.
    Identity(IdentityError),
    /// The overlay pool has no free address.
    Pool,
    /// The node name is not a valid SPIFFE name.
    Name,
    /// The node is already enrolled.
    Exists,
    /// The enroll token is not valid.
    Token,
    /// The enroll token is already used.
    TokenUsed,
    /// The enroll token is expired.
    TokenExpired,
    /// The OIDC check failed.
    Oidc,
    /// The signature check failed.
    Signature,
    /// The peer certificate is not valid for this request.
    Peer,
    /// The request or the netmap is not valid.
    Protocol(String),
    /// The QUIC or TLS check failed.
    Tls(String),
    /// The coordinator state is not usable.
    State,
    /// The endpoint is not `host:port`.
    Endpoint,
    /// The route is not an IPv4 network prefix.
    Route,
    /// The time value is not valid.
    Time,
    /// The live policy sha256 is not the expected sha256 (W25-9).
    Conflict,
    /// The OIDC user waits for owner approval (W25-15).
    UserPending,
    /// An owner rejected the OIDC user (W25-15).
    UserRejected,
}

impl CoordError {
    pub(crate) fn io(err: impl fmt::Display) -> Self {
        Self::Io(err.to_string())
    }

    /// A client-facing sentence.
    ///
    /// The sentence does not include token text, private keys, or OAuth secrets.
    pub fn public_text(&self) -> String {
        match self {
            Self::Io(_) | Self::State | Self::Tls(_) | Self::Identity(_) => {
                "The coordinator request failed.".to_string()
            }
            Self::Pool => "The overlay pool has no free address.".to_string(),
            Self::Name => "The node name is not valid.".to_string(),
            Self::Exists => "The node is already enrolled.".to_string(),
            Self::Token => "The enroll token is not valid.".to_string(),
            Self::TokenUsed => "The enroll token is already used.".to_string(),
            Self::TokenExpired => "The enroll token is expired.".to_string(),
            Self::Oidc => "The OIDC check failed.".to_string(),
            Self::Signature => "The signature check failed.".to_string(),
            Self::Peer => "The peer certificate is not valid for this request.".to_string(),
            Self::Protocol(text) => sanitize_protocol(text),
            Self::Endpoint => "The endpoint is not valid.".to_string(),
            Self::Route => "The route is not valid.".to_string(),
            Self::Time => "The time value is not valid.".to_string(),
            Self::Conflict => {
                "The live policy changed. Its sha256 is not the expected sha256.".to_string()
            }
            Self::UserPending => USER_PENDING_TEXT.to_string(),
            Self::UserRejected => USER_REJECTED_TEXT.to_string(),
        }
    }
}

/// The enroll error text for a pending OIDC user (W25-15).
///
/// `orblx coord enroll --wait-approval` tries again on this text.
pub const USER_PENDING_TEXT: &str = "The user waits for owner approval.";

/// The enroll error text for a rejected OIDC user (W25-15).
pub const USER_REJECTED_TEXT: &str = "The owner rejected this user.";

fn sanitize_protocol(text: &str) -> String {
    if text.is_empty()
        || text.len() > 200
        || text.chars().any(|ch| ch.is_control())
        || text.contains("ge1.")
        || text.contains(crate::apitoken::API_TOKEN_PREFIX)
    {
        return "The coordinator request failed.".to_string();
    }
    text.to_string()
}

impl fmt::Display for CoordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.public_text())
    }
}

impl std::error::Error for CoordError {}

impl From<IdentityError> for CoordError {
    fn from(err: IdentityError) -> Self {
        match err {
            IdentityError::Expired => Self::TokenExpired,
            IdentityError::Token | IdentityError::Audience | IdentityError::Signature => Self::Oidc,
            IdentityError::SpiffeId => Self::Name,
            IdentityError::Time => Self::Time,
            other => Self::Identity(other),
        }
    }
}
