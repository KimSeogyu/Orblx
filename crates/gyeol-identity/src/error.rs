use std::fmt;

/// A failure from the identity crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The token audience is not `gyeol-issue`.
    Audience,
    /// The certificate check failed.
    Certificate,
    /// The deny document check failed.
    DenyDocument,
    /// The byte encoding check failed.
    Encoding,
    /// The end time has passed.
    Expired,
    /// The start time is still in the future.
    NotYetValid,
    /// The certificate profile check failed.
    Profile,
    /// The deny list contains this identifier.
    Revoked,
    /// The signature check failed.
    Signature,
    /// The SPIFFE ID check failed.
    SpiffeId,
    /// The ticket check failed.
    Ticket,
    /// The time value check failed.
    Time,
    /// The token check failed.
    Token,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            IdentityError::Audience => "The token audience is not gyeol-issue.",
            IdentityError::Certificate => "The certificate check failed.",
            IdentityError::DenyDocument => "The deny document check failed.",
            IdentityError::Encoding => "The byte encoding check failed.",
            IdentityError::Expired => "The end time has passed.",
            IdentityError::NotYetValid => "The start time is still in the future.",
            IdentityError::Profile => "The certificate profile check failed.",
            IdentityError::Revoked => "The deny list contains this identifier.",
            IdentityError::Signature => "The signature check failed.",
            IdentityError::SpiffeId => "The SPIFFE ID check failed.",
            IdentityError::Ticket => "The ticket check failed.",
            IdentityError::Time => "The time value check failed.",
            IdentityError::Token => "The token check failed.",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for IdentityError {}
