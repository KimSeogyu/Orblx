use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::binding::PolicyBinding;
use crate::error::CryptoError;
use crate::suite::{
    CipherSuite, Kdf, NamedGroup, Transport, HASH_LEN, KDF, NAMED_GROUP, TRANSPORT,
};

/// The `tls13 ` prefix from RFC 8446.
const TLS13_PREFIX: &str = "tls13 ";

const ZEROS: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// One TLS 1.3 HKDF label used by the orblx schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleLabel {
    /// Salt step between extracts.
    Derived,
    /// Client handshake traffic secret.
    ClientHandshakeTraffic,
    /// Server handshake traffic secret.
    ServerHandshakeTraffic,
    /// Client application traffic secret.
    ClientApplicationTraffic,
    /// Server application traffic secret.
    ServerApplicationTraffic,
    /// Exporter master secret.
    ExporterMaster,
    /// RFC 8446 exporter inner label.
    Exporter,
    /// orblx policy label on the exporter master.
    Policy,
}

impl ScheduleLabel {
    /// Return the label text without the `tls13 ` prefix.
    pub const fn as_str(self) -> &'static str {
        match self {
            ScheduleLabel::Derived => "derived",
            ScheduleLabel::ClientHandshakeTraffic => "c hs traffic",
            ScheduleLabel::ServerHandshakeTraffic => "s hs traffic",
            ScheduleLabel::ClientApplicationTraffic => "c ap traffic",
            ScheduleLabel::ServerApplicationTraffic => "s ap traffic",
            ScheduleLabel::ExporterMaster => "exp master",
            ScheduleLabel::Exporter => "exporter",
            ScheduleLabel::Policy => "orblx policy",
        }
    }
}

/// The direction of a traffic secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to server.
    Client,
    /// Server to client.
    Server,
}

/// One TLS 1.3 traffic secret.
///
/// rustls applies the same secret as the record key.
/// This type has no seal function and no open function.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
pub struct TrafficSecret {
    direction: Direction,
    /// TLS 1.3 traffic secret bytes.
    ///
    /// The bytes stay private so callers cannot build an application AEAD.
    bytes: [u8; HASH_LEN],
}

impl TrafficSecret {
    fn new(direction: Direction, bytes: [u8; HASH_LEN]) -> Self {
        Self { direction, bytes }
    }

    /// Return the traffic direction.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Return the secret length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return false.
    ///
    /// The locked secret length is 32 bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for TrafficSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrafficSecret")
            .field("direction", &self.direction)
            .field("len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// A 32-byte X25519 shared secret from rustls.
///
/// This type does not generate a key pair.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
pub struct X25519Shared([u8; HASH_LEN]);

impl X25519Shared {
    /// Store a shared secret.
    ///
    /// The function rejects 32 zero bytes.
    pub fn new(bytes: [u8; HASH_LEN]) -> Result<Self, CryptoError> {
        if bytes == ZEROS {
            return Err(CryptoError::SharedSecret);
        }
        Ok(Self(bytes))
    }

    /// Return the locked ECDHE group.
    pub fn group(&self) -> NamedGroup {
        NAMED_GROUP
    }
}

impl fmt::Debug for X25519Shared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("X25519Shared")
            .field("group", &NAMED_GROUP)
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// TLS 1.3 HKDF-SHA256 secrets for one handshake.
///
/// The traffic secrets are placeholders for the rustls record keys.
/// Call `export_binding` for the policy binder.
#[derive(Clone, PartialEq, Eq)]
#[must_use]
pub struct KeySchedule {
    suite: CipherSuite,
    client_handshake: TrafficSecret,
    server_handshake: TrafficSecret,
    client_application: TrafficSecret,
    server_application: TrafficSecret,
    exporter_master: [u8; HASH_LEN],
}

impl fmt::Debug for KeySchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeySchedule")
            .field("suite", &self.suite)
            .field("kdf", &KDF)
            .field("client_handshake", &self.client_handshake)
            .field("server_handshake", &self.server_handshake)
            .field("client_application", &self.client_application)
            .field("server_application", &self.server_application)
            .field("exporter_master", &"[redacted]")
            .finish()
    }
}

impl KeySchedule {
    /// Derive the schedule from an X25519 shared secret and two transcript hashes.
    ///
    /// `hello_hash` is the transcript through ServerHello.
    /// `server_finished_hash` is the transcript through the server Finished message.
    pub fn derive(
        suite: CipherSuite,
        shared: &X25519Shared,
        hello_hash: &[u8; HASH_LEN],
        server_finished_hash: &[u8; HASH_LEN],
    ) -> Result<Self, CryptoError> {
        if suite.hash_len() != HASH_LEN {
            return Err(CryptoError::Schedule);
        }
        let empty = hash_bytes(b"");
        let early = hkdf_extract(&ZEROS, &ZEROS)?;
        let early_derived = derive_secret(&early, ScheduleLabel::Derived, &empty)?;
        let handshake = hkdf_extract(&early_derived, &shared.0)?;
        let client_handshake = derive_secret(
            &handshake,
            ScheduleLabel::ClientHandshakeTraffic,
            hello_hash,
        )?;
        let server_handshake = derive_secret(
            &handshake,
            ScheduleLabel::ServerHandshakeTraffic,
            hello_hash,
        )?;
        let handshake_derived = derive_secret(&handshake, ScheduleLabel::Derived, &empty)?;
        let master = hkdf_extract(&handshake_derived, &ZEROS)?;
        let client_application = derive_secret(
            &master,
            ScheduleLabel::ClientApplicationTraffic,
            server_finished_hash,
        )?;
        let server_application = derive_secret(
            &master,
            ScheduleLabel::ServerApplicationTraffic,
            server_finished_hash,
        )?;
        let exporter_master =
            derive_secret(&master, ScheduleLabel::ExporterMaster, server_finished_hash)?;
        Ok(Self {
            suite,
            client_handshake: TrafficSecret::new(Direction::Client, client_handshake),
            server_handshake: TrafficSecret::new(Direction::Server, server_handshake),
            client_application: TrafficSecret::new(Direction::Client, client_application),
            server_application: TrafficSecret::new(Direction::Server, server_application),
            exporter_master,
        })
    }

    /// Return the suite recorded for this schedule.
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Return the locked transport.
    pub fn transport(&self) -> Transport {
        TRANSPORT
    }

    /// Return the locked KDF.
    pub fn kdf(&self) -> Kdf {
        KDF
    }

    /// Return the locked ECDHE group.
    pub fn group(&self) -> NamedGroup {
        NAMED_GROUP
    }

    /// Return the client handshake traffic secret.
    pub fn client_handshake(&self) -> &TrafficSecret {
        &self.client_handshake
    }

    /// Return the server handshake traffic secret.
    pub fn server_handshake(&self) -> &TrafficSecret {
        &self.server_handshake
    }

    /// Return the client application traffic secret.
    pub fn client_application(&self) -> &TrafficSecret {
        &self.client_application
    }

    /// Return the server application traffic secret.
    pub fn server_application(&self) -> &TrafficSecret {
        &self.server_application
    }

    /// Export the 32-byte policy binder.
    ///
    /// The binder is not a record key.
    /// The function rejects a policy context whose suite differs from this schedule.
    pub fn export_binding(&self, binding: &PolicyBinding) -> Result<[u8; HASH_LEN], CryptoError> {
        if binding.suite() != self.suite {
            return Err(CryptoError::Suite);
        }
        let context = binding.encode()?;
        export_policy(&self.exporter_master, &context)
    }
}

fn export_policy(
    exporter_master: &[u8; HASH_LEN],
    context: &[u8],
) -> Result<[u8; HASH_LEN], CryptoError> {
    let empty = hash_bytes(b"");
    let secret = derive_secret(exporter_master, ScheduleLabel::Policy, &empty)?;
    let context_hash = hash_bytes(context);
    expand_label(&secret, ScheduleLabel::Exporter, &context_hash)
}

fn derive_secret(
    secret: &[u8; HASH_LEN],
    label: ScheduleLabel,
    transcript: &[u8; HASH_LEN],
) -> Result<[u8; HASH_LEN], CryptoError> {
    expand_label(secret, label, transcript)
}

fn expand_label(
    secret: &[u8; HASH_LEN],
    label: ScheduleLabel,
    context: &[u8],
) -> Result<[u8; HASH_LEN], CryptoError> {
    let info = hkdf_label(HASH_LEN, label, context)?;
    hkdf_expand(secret, &info)
}

fn hkdf_label(length: usize, label: ScheduleLabel, context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let text = label.as_str();
    let full_len = TLS13_PREFIX
        .len()
        .checked_add(text.len())
        .ok_or(CryptoError::Schedule)?;
    if full_len > 255 || context.len() > 255 || length > u16::MAX as usize {
        return Err(CryptoError::Schedule);
    }
    let length = u16::try_from(length).map_err(|_| CryptoError::Schedule)?;
    let mut info = Vec::with_capacity(2 + 1 + full_len + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(u8::try_from(full_len).map_err(|_| CryptoError::Schedule)?);
    info.extend_from_slice(TLS13_PREFIX.as_bytes());
    info.extend_from_slice(text.as_bytes());
    info.push(u8::try_from(context.len()).map_err(|_| CryptoError::Schedule)?);
    info.extend_from_slice(context);
    Ok(info)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<[u8; HASH_LEN], CryptoError> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    array32(prk.as_slice())
}

fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8]) -> Result<[u8; HASH_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::Schedule)?;
    let mut okm = [0u8; HASH_LEN];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::Schedule)?;
    Ok(okm)
}

fn hash_bytes(bytes: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

fn array32(bytes: &[u8]) -> Result<[u8; HASH_LEN], CryptoError> {
    let mut out = [0u8; HASH_LEN];
    if bytes.len() != HASH_LEN {
        return Err(CryptoError::Schedule);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        hash_bytes, hkdf_expand, hkdf_extract, hkdf_label, KeySchedule, ScheduleLabel, X25519Shared,
    };
    use crate::binding::PolicyBinding;
    use crate::suite::{CipherSuite, HASH_LEN};
    use crate::CryptoError;
    use orblx_identity::SpiffeId;

    fn decode_hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    fn expect_bytes(bytes: &[u8], hex_text: &str) {
        assert_eq!(bytes, decode_hex(hex_text).as_slice());
    }

    #[test]
    fn rfc5869_case_1_extract_and_expand() {
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_extract(&salt, &ikm).unwrap();
        expect_bytes(
            &prk,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        );
        let mut okm = [0u8; 42];
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(&prk).unwrap();
        hk.expand(&info, &mut okm).unwrap();
        expect_bytes(
            &okm,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        let short = hkdf_expand(&prk, &info).unwrap();
        assert_eq!(short.as_slice(), &okm[..HASH_LEN]);
    }

    #[test]
    fn derived_label_matches_the_tls13_encoding() {
        let empty = hash_bytes(b"");
        let info = hkdf_label(HASH_LEN, ScheduleLabel::Derived, &empty).unwrap();
        expect_bytes(
            &info,
            "00200d746c733133206465726976656420e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            hash_bytes(b"").as_slice(),
            decode_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .as_slice()
        );
    }

    #[test]
    fn schedule_matches_the_locked_vector() {
        let shared = X25519Shared::new([0x11; 32]).unwrap();
        let hello = [0x22; 32];
        let finished = [0x33; 32];
        let schedule =
            KeySchedule::derive(CipherSuite::Aes128GcmSha256, &shared, &hello, &finished).unwrap();
        assert_eq!(schedule.suite(), CipherSuite::Aes128GcmSha256);
        assert_eq!(schedule.kdf().as_str(), "hkdf-sha256");
        assert_eq!(schedule.group().iana(), 0x001d);
        assert_eq!(schedule.transport().as_str(), "quic-tls13-mtls");
        expect_bytes(
            &schedule.client_handshake.bytes,
            "5acb2dba3af0a93c6481d7b30306cf27f9c206d5bb16cf4641f18b2165adfe4e",
        );
        expect_bytes(
            &schedule.server_handshake.bytes,
            "a9672808fb7c7c1c7297ef1c25649cb9ea9b647d48928dee97680f9791b47309",
        );
        expect_bytes(
            &schedule.client_application.bytes,
            "334e01b0aa88e398eb6f75f4a819cb63574b400a1b6f851ce2581454799485f3",
        );
        expect_bytes(
            &schedule.server_application.bytes,
            "e8f2dd96717e16632d52c4ae05381b81c4aca9e99f4687794db14464c0f6d3a6",
        );
        expect_bytes(
            &schedule.exporter_master,
            "1e17f261d3bc24af4dbf94726c1ffd5d9e3fdc5ff7f654a7af5cfb5f10e2f8f7",
        );
        let exported = export_for_test(&schedule, b"ctx");
        expect_bytes(
            &exported,
            "5ac85aaf560ae31f642a479955d9c40c7057881cf28f30d9f54716b9327420d6",
        );
        assert_eq!(schedule.client_application().len(), 32);
        assert!(!schedule.client_application().is_empty());
        assert!(format!("{:?}", schedule.client_application()).contains("redacted"));
        assert!(!format!("{:?}", schedule).contains("334e01b0"));
        assert!(!format!("{:?}", shared).contains("111111"));
    }

    fn export_for_test(schedule: &KeySchedule, context: &[u8]) -> [u8; 32] {
        super::export_policy(&schedule.exporter_master, context).unwrap()
    }

    #[test]
    fn zero_shared_secret_is_rejected() {
        assert_eq!(
            X25519Shared::new([0u8; 32]).unwrap_err(),
            CryptoError::SharedSecret
        );
    }

    #[test]
    fn export_binding_tracks_the_suite_and_the_context() {
        let shared = X25519Shared::new([0x11; 32]).unwrap();
        let hash = [0x44; 32];
        let left =
            KeySchedule::derive(CipherSuite::Aes128GcmSha256, &shared, &hash, &hash).unwrap();
        let right = KeySchedule::derive(CipherSuite::ChaCha20Poly1305Sha256, &shared, &hash, &hash)
            .unwrap();
        let peer = SpiffeId::user("seogyu-dev").unwrap();
        let binding = PolicyBinding::new(CipherSuite::Aes128GcmSha256, hash, &peer, [0x55; 16]);
        let other =
            PolicyBinding::new(CipherSuite::ChaCha20Poly1305Sha256, hash, &peer, [0x55; 16]);
        assert!(left.export_binding(&binding).is_ok());
        assert_eq!(left.export_binding(&other).unwrap_err(), CryptoError::Suite);
        assert_ne!(
            left.export_binding(&binding).unwrap(),
            right.export_binding(&other).unwrap()
        );
        let changed = PolicyBinding::new(CipherSuite::Aes128GcmSha256, hash, &peer, [0x66; 16]);
        assert_ne!(
            left.export_binding(&binding).unwrap(),
            left.export_binding(&changed).unwrap()
        );
    }
}
