use std::fmt;

/// A failure from STUN or the path machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeError {
    /// A socket operation failed.
    Io(String),
    /// The buffer is shorter than the STUN message.
    ShortStun {
        /// The buffer length in bytes.
        len: usize,
        /// The required length in bytes.
        need: usize,
    },
    /// The first two bits of the message type are not zero.
    NotStun,
    /// The magic cookie is not the RFC 5389 cookie.
    BadCookie,
    /// An attribute length or value is not valid.
    BadAttribute,
    /// The fingerprint CRC does not match.
    BadFingerprint,
    /// The address family is not IPv4 or IPv6.
    BadFamily {
        /// The family byte from the address attribute.
        family: u8,
    },
    /// The message is not a Binding request.
    NotBindingRequest {
        /// The STUN message type.
        message_type: u16,
    },
    /// The message is not a Binding success response.
    NotBindingSuccess {
        /// The STUN message type.
        message_type: u16,
    },
    /// The transaction ID does not match the request.
    TransactionMismatch,
    /// The success response has no mapped address.
    NoMappedAddress,
    /// The message contains an unknown comprehension-required attribute.
    UnknownRequired {
        /// The attribute type.
        attr_type: u16,
    },
    /// The server returned a Binding error response.
    BindingError {
        /// The STUN error code.
        /// Zero means the response has no ERROR-CODE attribute.
        code: u16,
    },
    /// The socket read timed out.
    Timeout,
    /// The path state does not allow this step.
    WrongState,
    /// The candidate sink rejected the unsigned set.
    CandidateRejected,
    /// A lab thread stopped.
    LabThread,
}

impl fmt::Display for EdgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(detail) => write!(formatter, "The I/O operation failed. {detail}"),
            Self::ShortStun { len, need } => write!(
                formatter,
                "The STUN buffer has {len} bytes and the message needs {need} bytes."
            ),
            Self::NotStun => {
                formatter.write_str("The first two bits of the STUN message are not zero.")
            }
            Self::BadCookie => formatter.write_str("The magic cookie is not the RFC 5389 cookie."),
            Self::BadAttribute => formatter.write_str("A STUN attribute is not valid."),
            Self::BadFingerprint => formatter.write_str("The STUN fingerprint does not match."),
            Self::BadFamily { family } => {
                write!(
                    formatter,
                    "The address family {family} is not IPv4 or IPv6."
                )
            }
            Self::NotBindingRequest { message_type } => write!(
                formatter,
                "The STUN message type {message_type:#06x} is not a Binding request."
            ),
            Self::NotBindingSuccess { message_type } => write!(
                formatter,
                "The STUN message type {message_type:#06x} is not a Binding success response."
            ),
            Self::TransactionMismatch => {
                formatter.write_str("The STUN transaction ID does not match the request.")
            }
            Self::NoMappedAddress => {
                formatter.write_str("The Binding success response has no mapped address.")
            }
            Self::UnknownRequired { attr_type } => write!(
                formatter,
                "The STUN attribute {attr_type:#06x} is required and not known."
            ),
            Self::BindingError { code } => {
                write!(formatter, "The STUN server returned error {code}.")
            }
            Self::Timeout => formatter.write_str("The socket read timed out."),
            Self::WrongState => formatter.write_str("The path state does not allow this step."),
            Self::CandidateRejected => {
                formatter.write_str("The candidate sink rejected the unsigned set.")
            }
            Self::LabThread => formatter.write_str("The lab thread stopped."),
        }
    }
}

impl std::error::Error for EdgeError {}

pub(crate) fn io_error(err: std::io::Error) -> EdgeError {
    EdgeError::Io(err.to_string())
}
