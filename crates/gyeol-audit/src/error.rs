use std::fmt;

/// A failure from the session audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// A file operation failed.
    Io(String),
    /// One JSONL line is not a chain record.
    BadLine { line: usize },
    /// The stored hash differs from the event bytes.
    BadHash { index: u64 },
    /// The previous hash does not link to the prior record.
    BadLink { index: u64 },
    /// The record index is not the next index.
    BadIndex { line: usize },
    /// The Relay session id is not 32 lowercase hex characters.
    BadSession,
    /// The peer is not a `gyeol.local` SPIFFE ID.
    BadPeer,
    /// The event kind is outside start, end, and deny.
    BadKind,
    /// The ticket hash is not 32 lowercase hex characters.
    BadTicketHash,
    /// The reason does not match the event kind.
    BadReason,
    /// The export encoder failed.
    Export,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(detail) => write!(formatter, "The audit file operation failed. {detail}"),
            Self::BadLine { line } => write!(formatter, "The chain line {line} is not valid."),
            Self::BadHash { index } => {
                write!(formatter, "The hash check failed at index {index}.")
            }
            Self::BadLink { index } => {
                write!(formatter, "The link check failed at index {index}.")
            }
            Self::BadIndex { line } => {
                write!(formatter, "The index check failed on line {line}.")
            }
            Self::BadSession => formatter.write_str("The Relay session id is not valid."),
            Self::BadPeer => formatter.write_str("The peer SPIFFE ID is not valid."),
            Self::BadKind => formatter.write_str("The event kind is not start, end, or deny."),
            Self::BadTicketHash => formatter.write_str("The ticket hash is not valid."),
            Self::BadReason => formatter.write_str("The deny reason is not valid."),
            Self::Export => formatter.write_str("The chain export failed."),
        }
    }
}

impl std::error::Error for AuditError {}
