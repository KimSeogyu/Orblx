use std::fmt;

use gyeol_crypto::CryptoError;
use gyeol_identity::IdentityError;

use crate::FrameError;

/// A failure from the hello-quic path.
#[derive(Debug)]
pub enum HelloError {
    /// The identity crate rejected the leaf or the ticket material.
    Identity(IdentityError),
    /// The peer SPIFFE ID is not bound.
    PeerNotBound,
    /// The leaf check did not match the extracted SPIFFE ID.
    PeerRejected,
    /// The payload is not one IPv4 packet.
    NotIpv4,
    /// The frame type is not DATA.
    NotData,
    /// The sequence number is not the next value.
    BadSeq,
    /// The frame decoder failed.
    Frame(FrameError),
    /// The length prefix is outside the allowed range.
    BadFrameLength,
    /// The packet device is closed.
    DeviceClosed,
    /// The QUIC stream is closed.
    StreamClosed,
    /// The TLS configuration failed.
    Tls(String),
    /// A socket or file operation failed.
    Io(String),
    /// The TUN device did not open.
    Tun(String),
    /// The QUIC connection failed.
    Quic(String),
    /// The capability ticket check rejected the peer.
    Ticket(CryptoError),
    /// The peer did not present a capability ticket.
    TicketMissing,
    /// The frame `ticket_hash` differs from the verified ticket.
    TicketHash,
    /// The agent destination is not the one JIT allow.
    DestinationDenied,
    /// The connector hub-spoke path failed.
    Connector(String),
    /// The QUIC endpoint is closed.
    EndpointClosed,
    /// The node daemon failed.
    Node(String),
}

impl fmt::Display for HelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(err) => write!(formatter, "The leaf check failed. {err}"),
            Self::PeerNotBound => {
                formatter.write_str("The peer SPIFFE ID is not bound. The path rejects DATA.")
            }
            Self::PeerRejected => {
                formatter.write_str("The peer leaf did not match the trust bundle.")
            }
            Self::NotIpv4 => formatter.write_str("The payload is not one IPv4 packet."),
            Self::NotData => formatter.write_str("The frame type is not DATA."),
            Self::BadSeq => formatter.write_str("The sequence number is not the next value."),
            Self::Frame(err) => write!(formatter, "The frame decoder failed. {err}"),
            Self::BadFrameLength => formatter.write_str("The frame length is not valid."),
            Self::DeviceClosed => formatter.write_str("The packet device is closed."),
            Self::StreamClosed => formatter.write_str("The QUIC stream is closed."),
            Self::Tls(detail) => write!(formatter, "The TLS configuration failed. {detail}"),
            Self::Io(detail) => write!(formatter, "The I/O operation failed. {detail}"),
            Self::Tun(detail) => write!(formatter, "The TUN device did not open. {detail}"),
            Self::Quic(detail) => write!(formatter, "The QUIC connection failed. {detail}"),
            Self::Ticket(err) => {
                write!(
                    formatter,
                    "The capability ticket check rejected the peer. {err}"
                )
            }
            Self::TicketMissing => {
                formatter.write_str("The capability ticket is missing. The path rejects DATA.")
            }
            Self::TicketHash => {
                formatter.write_str("The frame ticket hash differs from the verified ticket.")
            }
            Self::DestinationDenied => {
                formatter.write_str("The destination is not allowed. The path rejects DATA.")
            }
            Self::Connector(detail) => write!(formatter, "The connector failed. {detail}"),
            Self::EndpointClosed => formatter.write_str("The QUIC endpoint is closed."),
            Self::Node(detail) => write!(formatter, "The node failed. {detail}"),
        }
    }
}

impl std::error::Error for HelloError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(err) => Some(err),
            Self::Frame(err) => Some(err),
            Self::Ticket(err) => Some(err),
            Self::PeerNotBound
            | Self::PeerRejected
            | Self::NotIpv4
            | Self::NotData
            | Self::BadSeq
            | Self::BadFrameLength
            | Self::DeviceClosed
            | Self::StreamClosed
            | Self::Tls(_)
            | Self::Io(_)
            | Self::Tun(_)
            | Self::Quic(_)
            | Self::TicketMissing
            | Self::TicketHash
            | Self::DestinationDenied
            | Self::Connector(_)
            | Self::EndpointClosed
            | Self::Node(_) => None,
        }
    }
}
