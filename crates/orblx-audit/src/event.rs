use orblx_identity::SpiffeId;
use orblx_relay::RelaySessionId;

use crate::AuditError;

/// The session names that already exist in the workspace.
///
/// `relay` is `RelaySessionId`.
/// `frame` is the datapath frame `session_id`.
/// `peer` is a SPIFFE ID from `orblx-identity`.
/// `ticket_hash` is `orblx_identity::ticket_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIds {
    /// Relay routing id.
    pub relay: RelaySessionId,
    /// Datapath frame session id.
    pub frame: u32,
    /// Peer SPIFFE ID.
    pub peer: SpiffeId,
    /// Capability ticket fingerprint.
    pub ticket_hash: [u8; 16],
}

impl SessionIds {
    /// Build the session names for one receiver ACL decision.
    ///
    /// The decision does not use the Relay.
    /// The Relay session id is 16 zero bytes.
    #[must_use]
    pub fn receiver_acl(peer: SpiffeId, frame: u32, ticket_hash: [u8; 16]) -> Self {
        Self {
            relay: RelaySessionId::from_bytes([0u8; 16]),
            frame,
            peer,
            ticket_hash,
        }
    }
}

/// The session event classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A session opened.
    Start,
    /// A session closed.
    End,
    /// A session was refused.
    Deny,
    /// A session recording closed.
    Record,
}

impl EventKind {
    /// Return the stable kind token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::End => "end",
            Self::Deny => "deny",
            Self::Record => "record",
        }
    }

    pub(crate) fn from_str(text: &str) -> Result<Self, AuditError> {
        match text {
            "start" => Ok(Self::Start),
            "end" => Ok(Self::End),
            "deny" => Ok(Self::Deny),
            "record" => Ok(Self::Record),
            _ => Err(AuditError::BadKind),
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Start => 1,
            Self::End => 2,
            Self::Deny => 3,
            Self::Record => 4,
        }
    }
}

/// A stable deny cause.
///
/// The token is part of the hashed event bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The destination is outside the allow.
    Destination,
    /// The deny list contains the peer or the ticket.
    Revoked,
    /// The ticket check failed.
    Ticket,
    /// The ticket or the SVID is outside its time window.
    Expired,
    /// The ticket is absent.
    Missing,
    /// The rule needs a session recording and the recording failed.
    Recording,
}

impl DenyReason {
    /// Return the stable reason token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Destination => "destination",
            Self::Revoked => "revoked",
            Self::Ticket => "ticket",
            Self::Expired => "expired",
            Self::Missing => "missing",
            Self::Recording => "recording",
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self, AuditError> {
        match text {
            "destination" => Ok(Self::Destination),
            "revoked" => Ok(Self::Revoked),
            "ticket" => Ok(Self::Ticket),
            "expired" => Ok(Self::Expired),
            "missing" => Ok(Self::Missing),
            "recording" => Ok(Self::Recording),
            _ => Err(AuditError::BadReason),
        }
    }
}

/// One session event for the hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The session opened.
    Start {
        /// Session names.
        ids: SessionIds,
        /// Unix time in seconds.
        at_unix: u64,
    },
    /// The session closed.
    End {
        /// Session names.
        ids: SessionIds,
        /// Unix time in seconds.
        at_unix: u64,
    },
    /// The session was refused.
    Deny {
        /// Session names.
        ids: SessionIds,
        /// Unix time in seconds.
        at_unix: u64,
        /// Deny cause.
        reason: DenyReason,
    },
    /// The session recording closed.
    ///
    /// `file` is the recording path relative to the chain file directory.
    /// `sha256` is the SHA-256 of the full recording file.
    Record {
        /// Session names.
        ids: SessionIds,
        /// Unix time in seconds.
        at_unix: u64,
        /// Recording path relative to the chain file directory.
        file: String,
        /// SHA-256 of the recording file.
        sha256: [u8; 32],
    },
}

impl SessionEvent {
    /// Return the event class.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        match self {
            Self::Start { .. } => EventKind::Start,
            Self::End { .. } => EventKind::End,
            Self::Deny { .. } => EventKind::Deny,
            Self::Record { .. } => EventKind::Record,
        }
    }

    /// Return the session names.
    #[must_use]
    pub fn ids(&self) -> &SessionIds {
        match self {
            Self::Start { ids, .. }
            | Self::End { ids, .. }
            | Self::Deny { ids, .. }
            | Self::Record { ids, .. } => ids,
        }
    }

    /// Return the Unix time in seconds.
    #[must_use]
    pub fn at_unix(&self) -> u64 {
        match self {
            Self::Start { at_unix, .. }
            | Self::End { at_unix, .. }
            | Self::Deny { at_unix, .. }
            | Self::Record { at_unix, .. } => *at_unix,
        }
    }

    /// Return the deny cause.
    ///
    /// Start, end, and record have no cause.
    #[must_use]
    pub fn reason(&self) -> Option<DenyReason> {
        match self {
            Self::Start { .. } | Self::End { .. } | Self::Record { .. } => None,
            Self::Deny { reason, .. } => Some(*reason),
        }
    }

    /// Return the recording path and the recording SHA-256.
    ///
    /// Only a record event has a recording.
    #[must_use]
    pub fn recording(&self) -> Option<(&str, &[u8; 32])> {
        match self {
            Self::Record { file, sha256, .. } => Some((file.as_str(), sha256)),
            _ => None,
        }
    }
}
