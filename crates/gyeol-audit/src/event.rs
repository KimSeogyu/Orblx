use gyeol_identity::SpiffeId;
use gyeol_relay::RelaySessionId;

use crate::AuditError;

/// The session names that already exist in the workspace.
///
/// `relay` is `RelaySessionId`.
/// `frame` is the datapath frame `session_id`.
/// `peer` is a SPIFFE ID from `gyeol-identity`.
/// `ticket_hash` is `gyeol_identity::ticket_hash`.
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

/// The three session event classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A session opened.
    Start,
    /// A session closed.
    End,
    /// A session was refused.
    Deny,
}

impl EventKind {
    /// Return the stable kind token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::End => "end",
            Self::Deny => "deny",
        }
    }

    pub(crate) fn from_str(text: &str) -> Result<Self, AuditError> {
        match text {
            "start" => Ok(Self::Start),
            "end" => Ok(Self::End),
            "deny" => Ok(Self::Deny),
            _ => Err(AuditError::BadKind),
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Start => 1,
            Self::End => 2,
            Self::Deny => 3,
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
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self, AuditError> {
        match text {
            "destination" => Ok(Self::Destination),
            "revoked" => Ok(Self::Revoked),
            "ticket" => Ok(Self::Ticket),
            "expired" => Ok(Self::Expired),
            "missing" => Ok(Self::Missing),
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
}

impl SessionEvent {
    /// Return the event class.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        match self {
            Self::Start { .. } => EventKind::Start,
            Self::End { .. } => EventKind::End,
            Self::Deny { .. } => EventKind::Deny,
        }
    }

    /// Return the session names.
    #[must_use]
    pub fn ids(&self) -> &SessionIds {
        match self {
            Self::Start { ids, .. } | Self::End { ids, .. } | Self::Deny { ids, .. } => ids,
        }
    }

    /// Return the Unix time in seconds.
    #[must_use]
    pub fn at_unix(&self) -> u64 {
        match self {
            Self::Start { at_unix, .. }
            | Self::End { at_unix, .. }
            | Self::Deny { at_unix, .. } => *at_unix,
        }
    }

    /// Return the deny cause.
    ///
    /// Start and end have no cause.
    #[must_use]
    pub fn reason(&self) -> Option<DenyReason> {
        match self {
            Self::Start { .. } | Self::End { .. } => None,
            Self::Deny { reason, .. } => Some(*reason),
        }
    }
}
