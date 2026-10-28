use crate::error::CryptoError;

/// SHA-256 output length in bytes.
///
/// Both locked cipher suites use this hash.
pub const HASH_LEN: usize = 32;

/// The gyeol-quic transport.
pub const TRANSPORT: Transport = Transport::QuicTls13Mtls;

/// The locked KDF.
pub const KDF: Kdf = Kdf::HkdfSha256;

/// The locked ECDHE group.
pub const NAMED_GROUP: NamedGroup = NamedGroup::X25519;

/// The locked SVID signature scheme.
pub const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Ed25519;

/// QUIC TLS 1.3 with mutual X.509-SVID authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Quinn and rustls run this transport.
    QuicTls13Mtls,
}

impl Transport {
    /// Return the stable transport name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Transport::QuicTls13Mtls => "quic-tls13-mtls",
        }
    }
}

/// The KDF for the TLS schedule and for ticket material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// HKDF-SHA256 from RFC 5869.
    HkdfSha256,
}

impl Kdf {
    /// Return the stable KDF name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Kdf::HkdfSha256 => "hkdf-sha256",
        }
    }
}

/// The ECDHE group for the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// X25519. The IANA group id is 0x001d.
    X25519,
}

impl NamedGroup {
    /// Return the TLS NamedGroup id.
    pub const fn iana(self) -> u16 {
        match self {
            NamedGroup::X25519 => 0x001d,
        }
    }
}

/// The signature scheme for an SVID leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Ed25519. The IANA signature scheme id is 0x0807.
    Ed25519,
}

impl SignatureScheme {
    /// Return the TLS SignatureScheme id.
    pub const fn iana(self) -> u16 {
        match self {
            SignatureScheme::Ed25519 => 0x0807,
        }
    }
}

/// One locked TLS 1.3 cipher suite.
///
/// rustls selects the suite during the handshake.
/// This enum records that choice for the policy binder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// `TLS_AES_128_GCM_SHA256`.
    Aes128GcmSha256,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Return the TLS cipher suite id.
    pub const fn iana(self) -> u16 {
        match self {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Parse a TLS cipher suite id.
    ///
    /// The function accepts only the two locked suites.
    pub const fn from_iana(id: u16) -> Result<Self, CryptoError> {
        match id {
            0x1301 => Ok(CipherSuite::Aes128GcmSha256),
            0x1303 => Ok(CipherSuite::ChaCha20Poly1305Sha256),
            _ => Err(CryptoError::Suite),
        }
    }

    /// Return the hash length for this suite.
    pub const fn hash_len(self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 | CipherSuite::ChaCha20Poly1305Sha256 => HASH_LEN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CipherSuite, Kdf, NamedGroup, SignatureScheme, Transport, HASH_LEN, KDF, NAMED_GROUP,
        SIGNATURE_SCHEME, TRANSPORT,
    };
    use crate::CryptoError;

    #[test]
    fn locked_ids_round_trip() {
        assert_eq!(TRANSPORT.as_str(), "quic-tls13-mtls");
        assert_eq!(KDF.as_str(), "hkdf-sha256");
        assert_eq!(NAMED_GROUP.iana(), 0x001d);
        assert_eq!(SIGNATURE_SCHEME.iana(), 0x0807);
        assert_eq!(NamedGroup::X25519.iana(), NAMED_GROUP.iana());
        assert_eq!(SignatureScheme::Ed25519.iana(), SIGNATURE_SCHEME.iana());
        assert_eq!(Kdf::HkdfSha256, KDF);
        assert_eq!(Transport::QuicTls13Mtls, TRANSPORT);

        let suites = [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::ChaCha20Poly1305Sha256,
        ];
        for suite in suites {
            assert_eq!(CipherSuite::from_iana(suite.iana()).unwrap(), suite);
            assert_eq!(suite.hash_len(), HASH_LEN);
        }
        assert_eq!(
            CipherSuite::from_iana(0x1302).unwrap_err(),
            CryptoError::Suite
        );
        assert_eq!(
            CipherSuite::from_iana(0x1304).unwrap_err(),
            CryptoError::Suite
        );
    }
}
