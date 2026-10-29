use std::fmt;

/// A failure from the Relay wire path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// A socket operation failed.
    Io(String),
    /// The datagram is not a Relay datagram.
    BadDatagram,
    /// The session id is not valid.
    BadSession,
    /// UDP did not reach the Relay.
    UdpBlocked,
    /// The read did not complete before the timeout.
    Timeout,
    /// The peer closed the connection.
    Closed,
    /// The payload does not fit in one datagram.
    TooBig,
    /// The session already has two peers.
    SessionFull,
    /// The caller is not attached to the session.
    NotAttached,
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(detail) => write!(formatter, "The I/O operation failed. {detail}"),
            Self::BadDatagram => formatter.write_str("The Relay datagram is not valid."),
            Self::BadSession => formatter.write_str("The Relay session id is not valid."),
            Self::UdpBlocked => formatter.write_str("UDP did not reach the Relay."),
            Self::Timeout => formatter.write_str("The Relay read timed out."),
            Self::Closed => formatter.write_str("The Relay connection is closed."),
            Self::TooBig => formatter.write_str("The Relay payload is too large."),
            Self::SessionFull => formatter.write_str("The Relay session already has two peers."),
            Self::NotAttached => formatter.write_str("The peer is not attached to the session."),
        }
    }
}

impl std::error::Error for RelayError {}

pub(crate) fn io_error(err: std::io::Error) -> RelayError {
    RelayError::Io(err.to_string())
}
