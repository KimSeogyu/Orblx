use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_identity::{decode_certificate_pem, DenySet, SpiffeId, TrustBundle, WorkloadKind};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::error::CoordError;
use crate::state::TlsMaterial;

pub const ALPN: &[u8] = b"orblx-coord";
pub const SERVER_NAME: &str = "orblx.local";

pub struct ClientTls {
    pub trust_pem: String,
    pub expect_coord: SpiffeId,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
}

pub fn crypto_provider() -> Arc<CryptoProvider> {
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The live coordinator leaf that the QUIC server shows in each new handshake (W25-33).
///
/// The coordinator replaces the leaf when it renews it. A connection that is open keeps
/// its session. Only a new handshake uses the new leaf.
pub struct LiveCert {
    provider: Arc<CryptoProvider>,
    current: std::sync::RwLock<(u64, Arc<rustls::sign::CertifiedKey>)>,
}

impl std::fmt::Debug for LiveCert {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveCert")
            .field("not_after", &self.not_after())
            .finish()
    }
}

impl LiveCert {
    fn new(provider: Arc<CryptoProvider>, material: &TlsMaterial) -> Result<Self, CoordError> {
        let (not_after, key) = certified_key(&provider, material)?;
        Ok(Self {
            provider,
            current: std::sync::RwLock::new((not_after, key)),
        })
    }

    /// The end time of the leaf that new handshakes get.
    pub fn not_after(&self) -> u64 {
        match self.current.read() {
            Ok(current) => current.0,
            Err(poisoned) => poisoned.into_inner().0,
        }
    }

    /// Show `material` in the next handshakes.
    ///
    /// The function keeps the old leaf when the new material is not valid.
    pub fn install(&self, material: &TlsMaterial) -> Result<u64, CoordError> {
        let (not_after, key) = certified_key(&self.provider, material)?;
        let mut current = match self.current.write() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        *current = (not_after, key);
        Ok(not_after)
    }
}

impl rustls::server::ResolvesServerCert for LiveCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let current = match self.current.read() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        Some(Arc::clone(&current.1))
    }
}

fn certified_key(
    provider: &CryptoProvider,
    material: &TlsMaterial,
) -> Result<(u64, Arc<rustls::sign::CertifiedKey>), CoordError> {
    let (chain, key) = identity_parts(&material.certificate_pem, &material.private_key_pem)?;
    let leaf = chain
        .first()
        .ok_or_else(|| CoordError::Tls("The certificate chain is empty.".to_string()))?;
    let (_, not_after) = orblx_identity::leaf_validity(leaf.as_ref())?;
    let signer = provider
        .key_provider
        .load_private_key(key)
        .map_err(|err| CoordError::Tls(err.to_string()))?;
    let certified = rustls::sign::CertifiedKey::new(chain, signer);
    certified
        .keys_match()
        .map_err(|err| CoordError::Tls(err.to_string()))?;
    Ok((not_after, Arc::new(certified)))
}

pub fn server_endpoint(
    material: &TlsMaterial,
    listen: SocketAddr,
) -> Result<(quinn::Endpoint, Arc<LiveCert>), CoordError> {
    let provider = crypto_provider();
    let trust = TrustBundle::from_pem(&material.trust_pem)?;
    let verifier = Arc::new(NodeClientVerifier {
        provider: Arc::clone(&provider),
        trust,
    });
    let live = Arc::new(LiveCert::new(Arc::clone(&provider), material)?);
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| CoordError::Tls(err.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::clone(&live) as Arc<dyn rustls::server::ResolvesServerCert>);
    server.alpn_protocols = vec![ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(server)
        .map_err(|err| CoordError::Tls(err.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(transport_config());
    let endpoint = quinn::Endpoint::server(config, listen).map_err(CoordError::io)?;
    Ok((endpoint, live))
}

pub fn client_endpoint(
    material: &ClientTls,
    bind: SocketAddr,
) -> Result<quinn::Endpoint, CoordError> {
    let provider = crypto_provider();
    let trust = TrustBundle::from_pem(&material.trust_pem)?;
    let verifier = Arc::new(CoordServerVerifier {
        provider: Arc::clone(&provider),
        trust,
        expect: material.expect_coord.clone(),
    });
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| CoordError::Tls(err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut client = match (&material.certificate_pem, &material.private_key_pem) {
        (Some(certificate), Some(key)) => {
            let (chain, private) = identity_parts(certificate, key)?;
            builder
                .with_client_auth_cert(chain, private)
                .map_err(|err| CoordError::Tls(err.to_string()))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(CoordError::Tls(
                "The client certificate is incomplete.".to_string(),
            ))
        }
    };
    client.alpn_protocols = vec![ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(client)
        .map_err(|err| CoordError::Tls(err.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    config.transport_config(transport_config());
    let mut endpoint = quinn::Endpoint::client(bind).map_err(CoordError::io)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(8));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(60)) {
        transport.max_idle_timeout(Some(idle));
    }
    Arc::new(transport)
}

fn identity_parts(
    certificate_pem: &str,
    private_key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), CoordError> {
    let der = decode_certificate_pem(certificate_pem)?;
    let mut cursor = std::io::Cursor::new(private_key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut cursor)
        .map_err(|err| CoordError::Tls(err.to_string()))?
        .ok_or_else(|| CoordError::Tls("The private key PEM is empty.".to_string()))?;
    Ok((vec![CertificateDer::from(der)], key))
}

fn system_time(now: UnixTime) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(now.as_secs())
}

struct CoordServerVerifier {
    provider: Arc<CryptoProvider>,
    trust: TrustBundle,
    expect: SpiffeId,
}

struct NodeClientVerifier {
    provider: Arc<CryptoProvider>,
    trust: TrustBundle,
}

impl std::fmt::Debug for CoordServerVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoordServerVerifier")
            .field("expect", &self.expect.as_uri())
            .finish()
    }
}

impl std::fmt::Debug for NodeClientVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NodeClientVerifier")
    }
}

fn verify_signature(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    tls13: bool,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    if tls13 {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    } else {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }
}

fn schemes(provider: &CryptoProvider) -> Vec<SignatureScheme> {
    provider
        .signature_verification_algorithms
        .supported_schemes()
}

impl ServerCertVerifier for CoordServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let id = self
            .trust
            .authenticate_leaf(end_entity.as_ref(), system_time(now), &DenySet::empty())
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        if id != self.expect {
            return Err(rustls::Error::General(
                "The coordinator SVID is not the expected SVID.".to_string(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(&self.provider, message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(&self.provider, message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes(&self.provider)
    }
}

impl ClientCertVerifier for NodeClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let id = self
            .trust
            .authenticate_leaf(end_entity.as_ref(), system_time(now), &DenySet::empty())
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        if id.kind() != WorkloadKind::Node {
            return Err(rustls::Error::General(
                "The client SVID is not a node SVID.".to_string(),
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(&self.provider, message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(&self.provider, message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes(&self.provider)
    }
}
