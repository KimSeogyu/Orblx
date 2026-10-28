use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::io_error;
use crate::EdgeError;

/// RFC 5389 magic cookie.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// High 16 bits of the magic cookie.
/// The client uses these bits to encode the XOR port.
const COOKIE_HIGH: u16 = (MAGIC_COOKIE >> 16) as u16;

const HEADER_LEN: usize = 20;
const TRANSACTION_ID_LEN: usize = 12;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;

/// The fingerprint value is the CRC-32 XORed with this constant.
const FINGERPRINT_XOR: u32 = 0x5354_554E;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

const SOFTWARE: &[u8] = b"gyeol-edge";

struct Header {
    message_type: u16,
    transaction_id: [u8; TRANSACTION_ID_LEN],
    end: usize,
}

struct Attr {
    attr_type: u16,
    value: Vec<u8>,
}

/// An RFC 5389 STUN client.
///
/// The client sends a Binding request.
/// The client reads a Binding success response.
/// The client returns the server-reflexive address.
/// The client does not use STUN credentials.
/// Week 4 does not check MESSAGE-INTEGRITY.
#[derive(Debug)]
pub struct StunClient {
    socket: UdpSocket,
}

impl StunClient {
    /// Bind a UDP socket for STUN.
    pub fn bind(local: SocketAddr) -> Result<Self, EdgeError> {
        let socket = UdpSocket::bind(local).map_err(io_error)?;
        Ok(Self { socket })
    }

    /// Return the bound socket.
    pub fn local_addr(&self) -> Result<SocketAddr, EdgeError> {
        self.socket.local_addr().map_err(io_error)
    }

    /// Send one Binding request to `server`.
    ///
    /// The function waits up to `timeout`.
    /// The function returns the XOR-MAPPED-ADDRESS.
    /// The function returns the MAPPED-ADDRESS when the XOR address is absent.
    pub fn gather(&self, server: SocketAddr, timeout: Duration) -> Result<SocketAddr, EdgeError> {
        let transaction_id = random_transaction_id()?;
        let request = binding_request(transaction_id)?;
        self.socket.send_to(&request, server).map_err(io_error)?;
        let start = Instant::now();
        let mut buf = [0u8; 2048];
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(EdgeError::Timeout);
            }
            self.socket
                .set_read_timeout(Some(remaining))
                .map_err(io_error)?;
            match self.socket.recv_from(&mut buf) {
                Ok((size, _)) => match parse_binding_success(&buf[..size], transaction_id) {
                    Ok(addr) => return Ok(addr),
                    Err(EdgeError::TransactionMismatch) => continue,
                    Err(err) => return Err(err),
                },
                Err(err) if is_timeout(&err) => return Err(EdgeError::Timeout),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(io_error(err)),
            }
        }
    }
}

/// A lab STUN server.
///
/// The server answers a Binding request with a Binding success response.
/// The mapped address is the UDP source address.
/// This type is for tests and the lab smoke.
#[derive(Debug)]
pub struct LabStunServer {
    socket: UdpSocket,
}

impl LabStunServer {
    /// Bind a UDP socket for the lab server.
    pub fn bind(local: SocketAddr) -> Result<Self, EdgeError> {
        let socket = UdpSocket::bind(local).map_err(io_error)?;
        Ok(Self { socket })
    }

    /// Return the bound socket.
    pub fn local_addr(&self) -> Result<SocketAddr, EdgeError> {
        self.socket.local_addr().map_err(io_error)
    }

    /// Answer one Binding request.
    ///
    /// The function returns the source address that the response maps.
    /// The function returns an error when `timeout` elapses.
    pub fn serve_one(&self, timeout: Duration) -> Result<SocketAddr, EdgeError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(io_error)?;
        let mut buf = [0u8; 2048];
        let (size, from) = loop {
            match self.socket.recv_from(&mut buf) {
                Ok(packet) => break packet,
                Err(err) if is_timeout(&err) => return Err(EdgeError::Timeout),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(io_error(err)),
            }
        };
        let transaction_id = parse_binding_request(&buf[..size])?;
        let response = binding_success(transaction_id, from)?;
        self.socket.send_to(&response, from).map_err(io_error)?;
        Ok(from)
    }
}

fn random_transaction_id() -> Result<[u8; TRANSACTION_ID_LEN], EdgeError> {
    let mut id = [0u8; TRANSACTION_ID_LEN];
    getrandom::getrandom(&mut id).map_err(|err| EdgeError::Io(err.to_string()))?;
    Ok(id)
}

fn is_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

fn binding_request(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Result<Vec<u8>, EdgeError> {
    encode_message(
        BINDING_REQUEST,
        transaction_id,
        &[Attr {
            attr_type: ATTR_SOFTWARE,
            value: SOFTWARE.to_vec(),
        }],
        true,
    )
}

fn binding_success(
    transaction_id: [u8; TRANSACTION_ID_LEN],
    mapped: SocketAddr,
) -> Result<Vec<u8>, EdgeError> {
    encode_message(
        BINDING_SUCCESS,
        transaction_id,
        &[Attr {
            attr_type: ATTR_XOR_MAPPED_ADDRESS,
            value: address_value(mapped, Some(&transaction_id)),
        }],
        true,
    )
}

fn encode_message(
    message_type: u16,
    transaction_id: [u8; TRANSACTION_ID_LEN],
    attrs: &[Attr],
    fingerprint: bool,
) -> Result<Vec<u8>, EdgeError> {
    let mut body = Vec::new();
    for attr in attrs {
        push_attr(&mut body, attr)?;
    }
    let extra = if fingerprint { 8 } else { 0 };
    let message_len = body
        .len()
        .checked_add(extra)
        .ok_or(EdgeError::BadAttribute)?;
    if message_len > usize::from(u16::MAX) || message_len % 4 != 0 {
        return Err(EdgeError::BadAttribute);
    }
    let message_len = u16::try_from(message_len).map_err(|_| EdgeError::BadAttribute)?;
    let mut out = Vec::with_capacity(HEADER_LEN + usize::from(message_len));
    out.extend_from_slice(&message_type.to_be_bytes());
    out.extend_from_slice(&message_len.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&transaction_id);
    out.extend_from_slice(&body);
    if fingerprint {
        let crc = crc32_ieee(&out) ^ FINGERPRINT_XOR;
        push_attr(
            &mut out,
            &Attr {
                attr_type: ATTR_FINGERPRINT,
                value: crc.to_be_bytes().to_vec(),
            },
        )?;
    }
    Ok(out)
}

fn push_attr(body: &mut Vec<u8>, attr: &Attr) -> Result<(), EdgeError> {
    let len = u16::try_from(attr.value.len()).map_err(|_| EdgeError::BadAttribute)?;
    body.extend_from_slice(&attr.attr_type.to_be_bytes());
    body.extend_from_slice(&len.to_be_bytes());
    body.extend_from_slice(&attr.value);
    let pad_to = (body.len() + 3) & !3;
    body.resize(pad_to, 0);
    Ok(())
}

fn parse_binding_request(buf: &[u8]) -> Result<[u8; TRANSACTION_ID_LEN], EdgeError> {
    let header = split_header(buf)?;
    if header.message_type != BINDING_REQUEST {
        return Err(EdgeError::NotBindingRequest {
            message_type: header.message_type,
        });
    }
    let _attrs = read_attributes(buf, header.end)?;
    Ok(header.transaction_id)
}

fn parse_binding_success(
    buf: &[u8],
    expected_id: [u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, EdgeError> {
    let header = split_header(buf)?;
    if header.transaction_id != expected_id {
        return Err(EdgeError::TransactionMismatch);
    }
    let attrs = read_attributes(buf, header.end)?;
    if header.message_type == BINDING_ERROR {
        return Err(EdgeError::BindingError {
            code: error_code(&attrs)?,
        });
    }
    if header.message_type != BINDING_SUCCESS {
        return Err(EdgeError::NotBindingSuccess {
            message_type: header.message_type,
        });
    }
    reflexive_address(&attrs, &header.transaction_id)
}

fn split_header(buf: &[u8]) -> Result<Header, EdgeError> {
    if buf.len() < HEADER_LEN {
        return Err(EdgeError::ShortStun {
            len: buf.len(),
            need: HEADER_LEN,
        });
    }
    let message_type = u16::from_be_bytes([buf[0], buf[1]]);
    if message_type & 0xC000 != 0 {
        return Err(EdgeError::NotStun);
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(EdgeError::BadCookie);
    }
    let message_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if message_len % 4 != 0 {
        return Err(EdgeError::BadAttribute);
    }
    let end = HEADER_LEN + message_len;
    if buf.len() < end {
        return Err(EdgeError::ShortStun {
            len: buf.len(),
            need: end,
        });
    }
    let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
    transaction_id.copy_from_slice(&buf[8..20]);
    Ok(Header {
        message_type,
        transaction_id,
        end,
    })
}

fn read_attributes(buf: &[u8], end: usize) -> Result<Vec<(u16, Vec<u8>)>, EdgeError> {
    let mut attrs = Vec::new();
    let mut offset = HEADER_LEN;
    while offset < end {
        if offset + 4 > end {
            return Err(EdgeError::BadAttribute);
        }
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]));
        let value_at = offset + 4;
        let value_end = value_at.checked_add(len).ok_or(EdgeError::BadAttribute)?;
        if value_end > end {
            return Err(EdgeError::BadAttribute);
        }
        let pad = (4 - (len % 4)) % 4;
        let next = value_end.checked_add(pad).ok_or(EdgeError::BadAttribute)?;
        if next > end {
            return Err(EdgeError::BadAttribute);
        }
        let value = buf[value_at..value_end].to_vec();
        if attr_type == ATTR_FINGERPRINT {
            if next != end || value.len() != 4 {
                return Err(EdgeError::BadFingerprint);
            }
            let got = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            let expect = crc32_ieee(&buf[..offset]) ^ FINGERPRINT_XOR;
            if got != expect {
                return Err(EdgeError::BadFingerprint);
            }
        } else if is_unknown_required(attr_type) {
            return Err(EdgeError::UnknownRequired { attr_type });
        }
        attrs.push((attr_type, value));
        offset = next;
    }
    Ok(attrs)
}

fn is_unknown_required(attr_type: u16) -> bool {
    if attr_type >= 0x8000 {
        return false;
    }
    !matches!(
        attr_type,
        ATTR_MAPPED_ADDRESS
            | ATTR_MESSAGE_INTEGRITY
            | ATTR_ERROR_CODE
            | ATTR_UNKNOWN_ATTRIBUTES
            | ATTR_XOR_MAPPED_ADDRESS
    )
}

fn reflexive_address(
    attrs: &[(u16, Vec<u8>)],
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, EdgeError> {
    let mut mapped = None;
    for (attr_type, value) in attrs {
        if *attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return decode_address(value, Some(transaction_id));
        }
        if *attr_type == ATTR_MAPPED_ADDRESS && mapped.is_none() {
            mapped = Some(decode_address(value, None)?);
        }
    }
    mapped.ok_or(EdgeError::NoMappedAddress)
}

fn error_code(attrs: &[(u16, Vec<u8>)]) -> Result<u16, EdgeError> {
    for (attr_type, value) in attrs {
        if *attr_type == ATTR_ERROR_CODE {
            return decode_error_code(value);
        }
    }
    Ok(0)
}

fn decode_error_code(value: &[u8]) -> Result<u16, EdgeError> {
    if value.len() < 4 {
        return Err(EdgeError::BadAttribute);
    }
    let word = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    let class = (word >> 8) & 0x07;
    let number = word & 0xff;
    u16::try_from(class * 100 + number).map_err(|_| EdgeError::BadAttribute)
}

fn decode_address(
    value: &[u8],
    transaction_id: Option<&[u8; TRANSACTION_ID_LEN]>,
) -> Result<SocketAddr, EdgeError> {
    if value.len() < 4 {
        return Err(EdgeError::BadAttribute);
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if transaction_id.is_some() {
        port ^= COOKIE_HIGH;
    }
    match family {
        FAMILY_IPV4 => {
            if value.len() != 8 {
                return Err(EdgeError::BadAttribute);
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&value[4..8]);
            if transaction_id.is_some() {
                let mask = MAGIC_COOKIE.to_be_bytes();
                for (octet, mask_byte) in octets.iter_mut().zip(mask) {
                    *octet ^= mask_byte;
                }
            }
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                port,
            )))
        }
        FAMILY_IPV6 => {
            if value.len() != 20 {
                return Err(EdgeError::BadAttribute);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if let Some(id) = transaction_id {
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for (octet, mask_byte) in octets.iter_mut().zip(cookie) {
                    *octet ^= mask_byte;
                }
                for (octet, mask_byte) in octets[4..].iter_mut().zip(id) {
                    *octet ^= mask_byte;
                }
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            )))
        }
        other => Err(EdgeError::BadFamily { family: other }),
    }
}

fn address_value(addr: SocketAddr, transaction_id: Option<&[u8; TRANSACTION_ID_LEN]>) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut port = v4.port();
            let mut octets = v4.ip().octets();
            if transaction_id.is_some() {
                port ^= COOKIE_HIGH;
                let mask = MAGIC_COOKIE.to_be_bytes();
                for (octet, mask_byte) in octets.iter_mut().zip(mask) {
                    *octet ^= mask_byte;
                }
            }
            let mut out = vec![0, FAMILY_IPV4];
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&octets);
            out
        }
        SocketAddr::V6(v6) => {
            let mut port = v6.port();
            let mut octets = v6.ip().octets();
            if let Some(id) = transaction_id {
                port ^= COOKIE_HIGH;
                let cookie = MAGIC_COOKIE.to_be_bytes();
                for (octet, mask_byte) in octets.iter_mut().zip(cookie) {
                    *octet ^= mask_byte;
                }
                for (octet, mask_byte) in octets[4..].iter_mut().zip(id) {
                    *octet ^= mask_byte;
                }
            }
            let mut out = vec![0, FAMILY_IPV6];
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&octets);
            out
        }
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::thread;
    use std::time::Duration;

    use super::{
        address_value, binding_request, crc32_ieee, decode_address, encode_message,
        parse_binding_request, parse_binding_success, Attr, LabStunServer, StunClient,
        ATTR_ERROR_CODE, ATTR_FINGERPRINT, ATTR_MAPPED_ADDRESS, ATTR_SOFTWARE,
        ATTR_XOR_MAPPED_ADDRESS, BINDING_ERROR, BINDING_REQUEST, BINDING_SUCCESS, HEADER_LEN,
        MAGIC_COOKIE,
    };
    use crate::EdgeError;

    fn id() -> [u8; 12] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ]
    }

    fn v4(octets: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(octets), port))
    }

    #[test]
    fn crc32_matches_the_iso_hdlc_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn empty_binding_request_matches_the_header_bytes() {
        let bytes = encode_message(BINDING_REQUEST, id(), &[], false).unwrap();
        let golden = [
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        assert_eq!(bytes, golden);
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            MAGIC_COOKIE
        );
    }

    #[test]
    fn golden_binding_success_returns_the_xor_address() {
        let golden = [
            0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x20, 0xA9,
            0xEA, 0x12, 0xD5, 0x47, 0x80, 0x28, 0x00, 0x04, 0xC6, 0xFF, 0x0F, 0x76,
        ];
        let addr = parse_binding_success(&golden, id()).unwrap();
        assert_eq!(addr, v4([203, 0, 113, 5], 443));
        let encoded = encode_message(
            BINDING_SUCCESS,
            id(),
            &[Attr {
                attr_type: ATTR_XOR_MAPPED_ADDRESS,
                value: address_value(v4([203, 0, 113, 5], 443), Some(&id())),
            }],
            true,
        )
        .unwrap();
        assert_eq!(encoded, golden);
    }

    #[test]
    fn mapped_address_is_the_fallback() {
        let golden = [
            0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x01, 0xbb,
            0xcb, 0x00, 0x71, 0x05,
        ];
        let addr = parse_binding_success(&golden, id()).unwrap();
        assert_eq!(addr, v4([203, 0, 113, 5], 443));
    }

    #[test]
    fn xor_address_wins_over_mapped_address() {
        let mapped = address_value(v4([198, 51, 100, 9], 9), None);
        let xor = address_value(v4([203, 0, 113, 5], 443), Some(&id()));
        let bytes = encode_message(
            BINDING_SUCCESS,
            id(),
            &[
                Attr {
                    attr_type: ATTR_MAPPED_ADDRESS,
                    value: mapped,
                },
                Attr {
                    attr_type: ATTR_XOR_MAPPED_ADDRESS,
                    value: xor,
                },
            ],
            true,
        )
        .unwrap();
        let addr = parse_binding_success(&bytes, id()).unwrap();
        assert_eq!(addr, v4([203, 0, 113, 5], 443));
    }

    #[test]
    fn ipv6_xor_address_round_trip() {
        let addr = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
        let bytes = encode_message(
            BINDING_SUCCESS,
            id(),
            &[Attr {
                attr_type: ATTR_XOR_MAPPED_ADDRESS,
                value: address_value(addr, Some(&id())),
            }],
            true,
        )
        .unwrap();
        assert_eq!(parse_binding_success(&bytes, id()).unwrap(), addr);
        assert_eq!(
            decode_address(&address_value(addr, Some(&id())), Some(&id())).unwrap(),
            addr
        );
    }

    #[test]
    fn binding_request_carries_software_and_a_valid_fingerprint() {
        let bytes = binding_request(id()).unwrap();
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), BINDING_REQUEST);
        assert_eq!(parse_binding_request(&bytes).unwrap(), id());
        assert!(bytes
            .windows(2)
            .any(|item| item == ATTR_SOFTWARE.to_be_bytes()));
        assert!(bytes
            .windows(2)
            .any(|item| item == ATTR_FINGERPRINT.to_be_bytes()));
    }

    #[test]
    fn bad_fingerprint_is_rejected() {
        let mut bytes = binding_request(id()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(
            parse_binding_request(&bytes).unwrap_err(),
            EdgeError::BadFingerprint
        );
    }

    #[test]
    fn short_buffer_and_bad_cookie_and_top_bits_fail() {
        assert_eq!(
            parse_binding_request(&[0u8; HEADER_LEN - 1]).unwrap_err(),
            EdgeError::ShortStun {
                len: HEADER_LEN - 1,
                need: HEADER_LEN,
            }
        );
        let mut bytes = encode_message(BINDING_REQUEST, id(), &[], false).unwrap();
        bytes[4] = 0;
        assert_eq!(
            parse_binding_request(&bytes).unwrap_err(),
            EdgeError::BadCookie
        );
        bytes = encode_message(BINDING_REQUEST, id(), &[], false).unwrap();
        bytes[0] = 0xC0;
        assert_eq!(
            parse_binding_request(&bytes).unwrap_err(),
            EdgeError::NotStun
        );
    }

    #[test]
    fn transaction_mismatch_is_distinct_from_a_bad_type() {
        let bytes = encode_message(
            BINDING_SUCCESS,
            id(),
            &[Attr {
                attr_type: ATTR_XOR_MAPPED_ADDRESS,
                value: address_value(v4([203, 0, 113, 5], 443), Some(&id())),
            }],
            false,
        )
        .unwrap();
        let mut other = id();
        other[0] ^= 0xff;
        assert_eq!(
            parse_binding_success(&bytes, other).unwrap_err(),
            EdgeError::TransactionMismatch
        );
        let indication = encode_message(0x0011, id(), &[], false).unwrap();
        assert_eq!(
            parse_binding_success(&indication, id()).unwrap_err(),
            EdgeError::NotBindingSuccess {
                message_type: 0x0011
            }
        );
    }

    #[test]
    fn unknown_optional_attribute_is_ignored() {
        let bytes = encode_message(
            BINDING_SUCCESS,
            id(),
            &[
                Attr {
                    attr_type: 0x8055,
                    value: vec![1, 2, 3],
                },
                Attr {
                    attr_type: ATTR_MAPPED_ADDRESS,
                    value: address_value(v4([203, 0, 113, 5], 443), None),
                },
            ],
            false,
        )
        .unwrap();
        assert_eq!(
            parse_binding_success(&bytes, id()).unwrap(),
            v4([203, 0, 113, 5], 443)
        );
    }

    #[test]
    fn unknown_required_attribute_fails() {
        let bytes = encode_message(
            BINDING_SUCCESS,
            id(),
            &[Attr {
                attr_type: 0x0007,
                value: vec![1, 2, 3, 4],
            }],
            false,
        )
        .unwrap();
        assert_eq!(
            parse_binding_success(&bytes, id()).unwrap_err(),
            EdgeError::UnknownRequired { attr_type: 0x0007 }
        );
    }

    #[test]
    fn binding_error_reports_the_code() {
        let bytes = encode_message(
            BINDING_ERROR,
            id(),
            &[Attr {
                attr_type: ATTR_ERROR_CODE,
                value: vec![0x00, 0x00, 0x04, 0x00],
            }],
            false,
        )
        .unwrap();
        assert_eq!(
            parse_binding_success(&bytes, id()).unwrap_err(),
            EdgeError::BindingError { code: 400 }
        );
    }

    #[test]
    fn success_without_an_address_fails() {
        let bytes = encode_message(BINDING_SUCCESS, id(), &[], false).unwrap();
        assert_eq!(
            parse_binding_success(&bytes, id()).unwrap_err(),
            EdgeError::NoMappedAddress
        );
    }

    #[test]
    fn gather_reports_the_socket_the_server_sees() {
        let server = LabStunServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve_one(Duration::from_secs(3)));
        let client = StunClient::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let reflexive = client.gather(server_addr, Duration::from_secs(2)).unwrap();
        let observed = handle.join().unwrap().unwrap();
        assert_eq!(reflexive, observed);
        assert_eq!(reflexive, client.local_addr().unwrap());
    }
}
