use std::fmt;

use crate::{RelayError, RelaySessionId};

/// The socket that carries one Relay attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTransport {
    /// UDP port 443 is the preferred path.
    Udp,
    /// TCP port 443 is the fallback path.
    Tcp,
}

impl fmt::Display for RelayTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => formatter.write_str("udp"),
            Self::Tcp => formatter.write_str("tcp"),
        }
    }
}

/// How a peer chooses UDP or TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPreference {
    /// Try UDP. When UDP fails, try TCP.
    Auto,
    /// Use UDP only.
    Udp,
    /// Use TCP only.
    Tcp,
}

impl fmt::Display for RelayPreference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => formatter.write_str("auto"),
            Self::Udp => formatter.write_str("udp"),
            Self::Tcp => formatter.write_str("tcp"),
        }
    }
}

/// Relay datagram version.
pub const RELAY_VERSION: u8 = 1;

/// Preferred Relay UDP and TCP port.
pub const RELAY_PORT: u16 = 443;

/// Bytes before the opaque payload.
///
/// The bytes are version, kind, and session id.
/// The header has no peer address.
/// The header has no key.
/// The header has no ticket.
pub const RELAY_HEADER_LEN: usize = 18;

/// The largest Relay datagram, including the header.
pub const MAX_DATAGRAM_LEN: usize = 65_535;

/// The largest opaque payload.
pub const MAX_PAYLOAD_LEN: usize = MAX_DATAGRAM_LEN - RELAY_HEADER_LEN;

const KIND_ATTACH: u8 = 1;
const KIND_DATA: u8 = 2;
const KIND_DETACH: u8 = 3;

/// The datagram kind.
///
/// The kind is framing.
/// The route lookup uses the session id only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayKind {
    /// Register this socket on the session.
    Attach,
    /// Forward the opaque payload to the other peer.
    Data,
    /// Remove this socket from the session.
    Detach,
}

impl RelayKind {
    fn as_u8(self) -> u8 {
        match self {
            Self::Attach => KIND_ATTACH,
            Self::Data => KIND_DATA,
            Self::Detach => KIND_DETACH,
        }
    }

    fn from_u8(value: u8) -> Result<Self, RelayError> {
        match value {
            KIND_ATTACH => Ok(Self::Attach),
            KIND_DATA => Ok(Self::Data),
            KIND_DETACH => Ok(Self::Detach),
            _ => Err(RelayError::BadDatagram),
        }
    }
}

/// One Relay datagram.
///
/// On UDP, the datagram is one UDP payload.
/// On TCP, a 16-bit length prefix stands in front of the same datagram.
/// A DATA payload is opaque.
/// The primary TCP path puts one QUIC packet in that payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDatagram {
    /// Framing kind.
    pub kind: RelayKind,
    /// The only route key.
    pub session_id: RelaySessionId,
    /// Opaque bytes.
    ///
    /// ATTACH and DETACH use an empty payload.
    /// DATA uses the peer ciphertext.
    pub payload: Vec<u8>,
}

/// Encode one datagram.
pub fn encode_datagram(
    kind: RelayKind,
    session_id: RelaySessionId,
    payload: &[u8],
) -> Result<Vec<u8>, RelayError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(RelayError::TooBig);
    }
    let mut out = Vec::with_capacity(RELAY_HEADER_LEN + payload.len());
    out.push(RELAY_VERSION);
    out.push(kind.as_u8());
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode one datagram.
///
/// The function does not inspect the payload.
pub fn decode_datagram(buf: &[u8]) -> Result<RelayDatagram, RelayError> {
    if buf.len() < RELAY_HEADER_LEN || buf.len() > MAX_DATAGRAM_LEN {
        return Err(RelayError::BadDatagram);
    }
    if buf[0] != RELAY_VERSION {
        return Err(RelayError::BadDatagram);
    }
    let kind = RelayKind::from_u8(buf[1])?;
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&buf[2..RELAY_HEADER_LEN]);
    Ok(RelayDatagram {
        kind,
        session_id: RelaySessionId::from_bytes(raw),
        payload: buf[RELAY_HEADER_LEN..].to_vec(),
    })
}

/// Encode one TCP record.
///
/// The record is a big-endian u16 length and one Relay datagram.
/// This is the QUIC-style TCP/443 framing.
/// The length is not a TLS record header.
/// The record is not a Noise frame.
pub fn encode_tcp_record(datagram: &[u8]) -> Result<Vec<u8>, RelayError> {
    if datagram.len() < RELAY_HEADER_LEN || datagram.len() > MAX_DATAGRAM_LEN {
        return Err(RelayError::BadDatagram);
    }
    let len = u16::try_from(datagram.len()).map_err(|_| RelayError::TooBig)?;
    let mut out = Vec::with_capacity(2 + datagram.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(datagram);
    Ok(out)
}

/// Take one TCP record from the front of `buf`.
///
/// The function returns `Ok(None)` when `buf` does not hold a full record yet.
/// The `usize` is the number of bytes the record used, including the length.
pub fn take_tcp_record(buf: &[u8]) -> Result<Option<(RelayDatagram, usize)>, RelayError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if !(RELAY_HEADER_LEN..=MAX_DATAGRAM_LEN).contains(&len) {
        return Err(RelayError::BadDatagram);
    }
    let end = 2 + len;
    if buf.len() < end {
        return Ok(None);
    }
    let datagram = decode_datagram(&buf[2..end])?;
    Ok(Some((datagram, end)))
}

/// Return the framing name for the transport that carried the payload.
#[must_use]
pub fn framing_name(transport: RelayTransport) -> &'static str {
    match transport {
        RelayTransport::Udp => "udp-datagram",
        RelayTransport::Tcp => "quic-style",
    }
}

/// Return true when `payload` contains `needle` as a byte substring.
///
/// The scan does not decrypt.
/// A lab uses it to show that a known probe is absent.
#[must_use]
pub fn contains_needle(payload: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || payload.len() < needle.len() {
        return false;
    }
    payload.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        contains_needle, decode_datagram, encode_datagram, encode_tcp_record, framing_name,
        take_tcp_record, RelayKind, RELAY_HEADER_LEN, RELAY_PORT, RELAY_VERSION,
    };
    use crate::{RelaySessionId, RelayTransport};

    #[test]
    fn header_is_version_kind_and_session_id() {
        let session = RelaySessionId::from_bytes([0x11; 16]);
        let bytes = encode_datagram(RelayKind::Data, session, b"cipher").unwrap();
        assert_eq!(bytes.len(), RELAY_HEADER_LEN + 6);
        assert_eq!(bytes[0], RELAY_VERSION);
        assert_eq!(bytes[1], 2);
        assert_eq!(&bytes[2..RELAY_HEADER_LEN], session.as_bytes());
        assert_eq!(&bytes[RELAY_HEADER_LEN..], b"cipher");
        let decoded = decode_datagram(&bytes).unwrap();
        assert_eq!(decoded.kind, RelayKind::Data);
        assert_eq!(decoded.session_id, session);
        assert_eq!(decoded.payload, b"cipher");
        assert_eq!(RELAY_PORT, 443);
    }

    #[test]
    fn tcp_record_is_a_length_and_one_datagram() {
        let session = RelaySessionId::from_bytes([0x22; 16]);
        let datagram = encode_datagram(RelayKind::Data, session, b"quic-packet").unwrap();
        let record = encode_tcp_record(&datagram).unwrap();
        assert_eq!(
            u16::from_be_bytes([record[0], record[1]]) as usize,
            datagram.len()
        );
        assert_eq!(&record[2..], datagram.as_slice());
        let (decoded, used) = take_tcp_record(&record).unwrap().unwrap();
        assert_eq!(used, record.len());
        assert_eq!(decoded.payload, b"quic-packet");
        assert!(take_tcp_record(&record[..record.len() - 1])
            .unwrap()
            .is_none());
        assert_eq!(framing_name(RelayTransport::Tcp), "quic-style");
        assert_eq!(framing_name(RelayTransport::Udp), "udp-datagram");
    }

    #[test]
    fn needle_scan_does_not_require_a_key() {
        assert!(contains_needle(
            b"xxgyeol-w6-relay-probeyy",
            b"gyeol-w6-relay-probe"
        ));
        assert!(!contains_needle(b"ciphertext", b"gyeol-w6-relay-probe"));
        assert!(!contains_needle(b"short", b"gyeol-w6-relay-probe"));
    }

    #[test]
    fn short_and_bad_version_are_rejected() {
        assert!(decode_datagram(&[1, 2, 3]).is_err());
        let mut bytes =
            encode_datagram(RelayKind::Attach, RelaySessionId::from_bytes([0; 16]), &[]).unwrap();
        bytes[0] = 9;
        assert!(decode_datagram(&bytes).is_err());
    }
}
