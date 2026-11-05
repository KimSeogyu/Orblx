//! A payload a peer relay is allowed to forward.
//!
//! The only constructor is [`SealedPayload::parse`].
//! Parse accepts one sealed NAT frame.
//! Parse rejects an IPv4 packet and any other bytes.
//! This module has no key and no decrypt function.

use crate::RelayError;

/// NAT frame magic. The bytes match the overlay frame in `orblx-edge`.
const NAT_MAGIC: &[u8; 8] = b"ORBLXNAT";

/// Bytes before the NAT frame body.
const NAT_HEADER: usize = 26;

const NAT_VERSION: u8 = 1;
const KIND_HELLO: u8 = 1;
const KIND_PROBE: u8 = 2;
const KIND_DATA: u8 = 3;

/// A Poly1305 tag is 16 bytes. A sealed probe or data body also has an 8 byte counter.
const SEALED_BODY: usize = 8 + 16;

/// A hello body has an X25519 key and an Ed25519 signature.
const HELLO_BODY: usize = 32 + 64;

/// One sealed NAT frame.
///
/// The value borrows the original bytes.
/// The peer relay forwards those bytes.
/// The value cannot hold an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedPayload<'a>(&'a [u8]);

impl<'a> SealedPayload<'a> {
    /// Accept one sealed NAT frame.
    ///
    /// A hello frame carries the public key material.
    /// A probe frame and a data frame carry ciphertext.
    /// Any other byte string is rejected.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RelayError> {
        if bytes.len() < NAT_HEADER || &bytes[..8] != NAT_MAGIC || bytes[8] != NAT_VERSION {
            return Err(RelayError::Plaintext);
        }
        let body = bytes.len() - NAT_HEADER;
        let ok = match bytes[9] {
            KIND_HELLO => body > HELLO_BODY,
            KIND_PROBE | KIND_DATA => body >= SEALED_BODY,
            _ => false,
        };
        if ok {
            Ok(Self(bytes))
        } else {
            Err(RelayError::Plaintext)
        }
    }

    /// The original sealed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{SealedPayload, NAT_HEADER, NAT_MAGIC};

    fn sealed(kind: u8, body: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; NAT_HEADER + body];
        bytes[..8].copy_from_slice(NAT_MAGIC);
        bytes[8] = 1;
        bytes[9] = kind;
        bytes
    }

    #[test]
    fn a_sealed_probe_and_a_sealed_data_frame_parse() {
        let probe = sealed(2, 8 + 16);
        let data = sealed(3, 8 + 16 + 20);
        assert_eq!(
            SealedPayload::parse(&probe).unwrap().as_bytes(),
            probe.as_slice()
        );
        assert!(SealedPayload::parse(&data).is_ok());
    }

    #[test]
    fn a_hello_parses_and_an_ipv4_packet_does_not() {
        let hello = sealed(1, 32 + 64 + 1);
        assert!(SealedPayload::parse(&hello).is_ok());
        let mut packet = vec![0x45, 0, 0, 28];
        packet.extend_from_slice(b"ORBLXPLAIN");
        assert!(SealedPayload::parse(&packet).is_err());
        assert!(SealedPayload::parse(b"ORBLXPLAIN").is_err());
        assert!(SealedPayload::parse(&sealed(2, 8)).is_err());
        assert!(SealedPayload::parse(&sealed(9, 40)).is_err());
    }
}
