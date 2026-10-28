use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use gyeol_identity::{decode_certificate_pem, DenySet, SpiffeId, TrustBundle};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::sync::mpsc;

use crate::framing::expect_seq;
use crate::{encode_length_prefixed, is_ipv4_packet, Frame, HelloError, PeerGate};

const ALPN: &[u8] = b"gyeol-hello";
const SERVER_NAME: &str = "gyeol.local";
const PEER_REJECT_CODE: u32 = 1;

/// Leaf material and the trust bundle for one hello-quic endpoint.
pub struct HelloConfig {
    /// PEM certificate for this endpoint.
    pub certificate_pem: String,
    /// PEM private key for this endpoint.
    pub private_key_pem: String,
    /// Roots that can authenticate the peer leaf.
    pub trust: TrustBundle,
    /// `ticket_hash` value for outbound DATA frames.
    pub ticket_hash: [u8; 16],
    /// Deny list for leaf authentication.
    pub deny: DenySet,
}

impl HelloConfig {
    /// Build a config from an issued SVID.
    #[must_use]
    pub fn from_issued(
        certificate_pem: &str,
        private_key_pem: &str,
        trust: TrustBundle,
        ticket_hash: [u8; 16],
    ) -> Self {
        Self {
            certificate_pem: certificate_pem.to_string(),
            private_key_pem: private_key_pem.to_string(),
            trust,
            ticket_hash,
            deny: DenySet::empty(),
        }
    }
}

struct Auth {
    trust: TrustBundle,
    ticket_hash: [u8; 16],
    deny: DenySet,
}

/// A Quinn endpoint that speaks hello-quic.
pub struct HelloEndpoint {
    endpoint: quinn::Endpoint,
    auth: Arc<Auth>,
}

impl HelloEndpoint {
    /// Bind a server socket.
    ///
    /// Call this function inside a Tokio runtime.
    pub fn bind_server(config: HelloConfig, listen: SocketAddr) -> Result<Self, HelloError> {
        let (rustls_config, auth) = server_rustls(&config)?;
        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|err| HelloError::Tls(err.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
        server.transport_config(transport_config());
        let endpoint = quinn::Endpoint::server(server, listen).map_err(io_error)?;
        Ok(Self {
            endpoint,
            auth: Arc::new(auth),
        })
    }

    /// Bind a client socket.
    ///
    /// Call this function inside a Tokio runtime.
    pub fn bind_client(config: HelloConfig, bind: SocketAddr) -> Result<Self, HelloError> {
        let (rustls_config, auth) = client_rustls(&config)?;
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
            .map_err(|err| HelloError::Tls(err.to_string()))?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic));
        client.transport_config(transport_config());
        let mut endpoint = quinn::Endpoint::client(bind).map_err(io_error)?;
        endpoint.set_default_client_config(client);
        Ok(Self {
            endpoint,
            auth: Arc::new(auth),
        })
    }

    /// Return the local UDP address.
    pub fn local_addr(&self) -> Result<SocketAddr, HelloError> {
        self.endpoint.local_addr().map_err(io_error)
    }

    /// Accept one peer and one bidirectional stream.
    pub async fn accept_one(&self) -> Result<HelloSession, HelloError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| HelloError::Quic("The endpoint is closed.".to_string()))?;
        let connection = incoming
            .await
            .map_err(|err| HelloError::Quic(err.to_string()))?;
        bind_session(connection, &self.auth, StreamRole::Server).await
    }

    /// Build an endpoint on a socket the caller already owns.
    ///
    /// Call this function inside a Tokio runtime.
    /// The function sets the socket to nonblocking mode.
    /// N-Edge uses this after a hole punch so QUIC keeps the same UDP socket.
    pub fn from_std_socket(
        config: HelloConfig,
        socket: std::net::UdpSocket,
        role: HelloSocketRole,
    ) -> Result<Self, HelloError> {
        let _ = socket.set_read_timeout(None);
        socket.set_nonblocking(true).map_err(io_error)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| HelloError::Quic("The call is outside a Tokio runtime.".to_string()))?;
        let (endpoint, auth) = match role {
            HelloSocketRole::Server => {
                let (rustls_config, auth) = server_rustls(&config)?;
                let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
                    .map_err(|err| HelloError::Tls(err.to_string()))?;
                let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
                server.transport_config(transport_config());
                let endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server),
                    socket,
                    runtime,
                )
                .map_err(io_error)?;
                (endpoint, auth)
            }
            HelloSocketRole::Client { .. } => {
                let (rustls_config, auth) = client_rustls(&config)?;
                let quic = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                    .map_err(|err| HelloError::Tls(err.to_string()))?;
                let mut client = quinn::ClientConfig::new(Arc::new(quic));
                client.transport_config(transport_config());
                let mut endpoint =
                    quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
                        .map_err(io_error)?;
                endpoint.set_default_client_config(client);
                (endpoint, auth)
            }
        };
        Ok(Self {
            endpoint,
            auth: Arc::new(auth),
        })
    }

    /// Connect to `peer` and open one bidirectional stream.
    pub async fn connect_one(&self, peer: SocketAddr) -> Result<HelloSession, HelloError> {
        let connecting = self
            .endpoint
            .connect(peer, SERVER_NAME)
            .map_err(|err| HelloError::Quic(err.to_string()))?;
        let connection = connecting
            .await
            .map_err(|err| HelloError::Quic(err.to_string()))?;
        bind_session(connection, &self.auth, StreamRole::Client).await
    }

    async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

/// The role for one hello-quic proof on an existing UDP socket.
pub enum HelloSocketRole {
    /// Accept one peer on this socket.
    Server,
    /// Connect to `peer` from this socket.
    Client {
        /// The nominated peer socket.
        peer: SocketAddr,
    },
}

/// Open hello-quic on `socket`, exchange one IPv4 packet, and close.
///
/// The server echoes the packet.
/// The client sends `packet` and returns the echo.
/// The function creates a Tokio runtime.
/// Do not call it from inside a runtime.
/// The function returns an error when `timeout` elapses.
pub fn prove_hello_socket(
    config: HelloConfig,
    socket: std::net::UdpSocket,
    role: HelloSocketRole,
    packet: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, HelloError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    runtime.block_on(async {
        match tokio::time::timeout(timeout, prove_hello_async(config, socket, role, packet)).await {
            Ok(result) => result,
            Err(_) => Err(HelloError::Quic("The QUIC proof timed out.".to_string())),
        }
    })
}

async fn prove_hello_async(
    config: HelloConfig,
    socket: std::net::UdpSocket,
    role: HelloSocketRole,
    packet: &[u8],
) -> Result<Vec<u8>, HelloError> {
    match role {
        HelloSocketRole::Server => {
            let endpoint = HelloEndpoint::from_std_socket(config, socket, HelloSocketRole::Server)?;
            let mut session = endpoint.accept_one().await?;
            let got = session.recv_ipv4().await?;
            session.send_ipv4(&got).await?;
            session.wait_closed().await;
            endpoint.wait_idle().await;
            Ok(got)
        }
        HelloSocketRole::Client { peer } => {
            let endpoint =
                HelloEndpoint::from_std_socket(config, socket, HelloSocketRole::Client { peer })?;
            let mut session = endpoint.connect_one(peer).await?;
            session.send_ipv4(packet).await?;
            let got = session.recv_ipv4().await?;
            drop(session);
            endpoint.wait_idle().await;
            Ok(got)
        }
    }
}

enum StreamRole {
    Server,
    Client,
}

/// One authenticated hello-quic session.
pub struct HelloSession {
    connection: quinn::Connection,
    sender: HelloSender,
    receiver: HelloReceiver,
}

impl HelloSession {
    /// Return the bound peer SPIFFE ID.
    #[must_use]
    pub fn peer_id(&self) -> &SpiffeId {
        self.sender.peer()
    }

    /// Return the local session id.
    #[must_use]
    pub fn session_id(&self) -> u32 {
        self.sender.session_id
    }

    /// Send one IPv4 packet as a DATA frame.
    pub async fn send_ipv4(&mut self, packet: &[u8]) -> Result<(), HelloError> {
        self.sender.send_ipv4(packet).await
    }

    /// Read one DATA frame.
    pub async fn recv_data_frame(&mut self) -> Result<Frame, HelloError> {
        self.receiver.recv_data_frame().await
    }

    /// Read one IPv4 packet from a DATA frame.
    pub async fn recv_ipv4(&mut self) -> Result<Vec<u8>, HelloError> {
        self.receiver.recv_ipv4().await
    }

    /// Wait until the connection closes.
    pub async fn wait_closed(&self) {
        self.connection.closed().await;
    }

    /// Split the session into a sender and a receiver.
    #[must_use]
    pub fn split(self) -> (HelloSender, HelloReceiver) {
        (self.sender, self.receiver)
    }
}

/// The send half of a hello-quic session.
pub struct HelloSender {
    send: quinn::SendStream,
    session_id: u32,
    next_seq: u64,
    ticket_hash: [u8; 16],
    peer: SpiffeId,
    gate: PeerGate,
}

impl HelloSender {
    /// Return the bound peer SPIFFE ID.
    #[must_use]
    pub fn peer(&self) -> &SpiffeId {
        &self.peer
    }

    /// Send one IPv4 packet as a DATA frame.
    pub async fn send_ipv4(&mut self, packet: &[u8]) -> Result<(), HelloError> {
        let frame =
            self.gate
                .encode_data(self.session_id, self.next_seq, self.ticket_hash, packet)?;
        let bytes = encode_length_prefixed(&frame)?;
        self.send
            .write_all(&bytes)
            .await
            .map_err(|err| HelloError::Quic(err.to_string()))?;
        self.next_seq = self.next_seq.checked_add(1).ok_or(HelloError::BadSeq)?;
        Ok(())
    }
}

/// The receive half of a hello-quic session.
pub struct HelloReceiver {
    recv: quinn::RecvStream,
    next_seq: u64,
    gate: PeerGate,
}

impl HelloReceiver {
    /// Read one DATA frame.
    pub async fn recv_data_frame(&mut self) -> Result<Frame, HelloError> {
        let frame = read_frame(&mut self.recv).await?;
        self.next_seq = expect_seq(self.next_seq, frame.seq)?;
        self.gate.payload_from_data(&frame)?;
        Ok(frame)
    }

    /// Read one IPv4 packet from a DATA frame.
    pub async fn recv_ipv4(&mut self) -> Result<Vec<u8>, HelloError> {
        let frame = self.recv_data_frame().await?;
        Ok(frame.payload)
    }
}

/// Move IPv4 packets between a device channel and one session.
///
/// The function reads and writes on separate tasks.
/// Each direction runs one frame operation to completion.
pub async fn pump_packets(
    session: HelloSession,
    mut from_device: mpsc::Receiver<Vec<u8>>,
    to_device: mpsc::Sender<Vec<u8>>,
) -> Result<(), HelloError> {
    let (mut sender, mut receiver) = session.split();
    let send_loop = async {
        while let Some(packet) = from_device.recv().await {
            if !is_ipv4_packet(&packet) {
                continue;
            }
            sender.send_ipv4(&packet).await?;
        }
        Ok(())
    };
    let recv_loop = async {
        loop {
            match receiver.recv_ipv4().await {
                Ok(packet) => {
                    to_device
                        .send(packet)
                        .await
                        .map_err(|_| HelloError::DeviceClosed)?;
                }
                Err(HelloError::StreamClosed) => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    };
    tokio::select! {
        result = send_loop => result,
        result = recv_loop => result,
    }
}

async fn bind_session(
    connection: quinn::Connection,
    auth: &Auth,
    role: StreamRole,
) -> Result<HelloSession, HelloError> {
    let leaf = match peer_leaf(&connection) {
        Ok(leaf) => leaf,
        Err(err) => {
            reject(&connection);
            return Err(err);
        }
    };
    let mut gate = PeerGate::new();
    if let Err(err) = gate.bind_leaf(&auth.trust, &leaf, SystemTime::now(), &auth.deny) {
        reject(&connection);
        return Err(err);
    }
    let peer = gate.peer().cloned().ok_or(HelloError::PeerNotBound)?;
    let (send, recv) = open_stream(&connection, role).await?;
    let bound = PeerGate::bound(peer.clone());
    Ok(HelloSession {
        connection,
        sender: HelloSender {
            send,
            session_id: random_session_id(),
            next_seq: 0,
            ticket_hash: auth.ticket_hash,
            peer,
            gate: bound.clone(),
        },
        receiver: HelloReceiver {
            recv,
            next_seq: 0,
            gate: bound,
        },
    })
}

async fn open_stream(
    connection: &quinn::Connection,
    role: StreamRole,
) -> Result<(quinn::SendStream, quinn::RecvStream), HelloError> {
    match role {
        StreamRole::Server => connection
            .accept_bi()
            .await
            .map_err(|err| HelloError::Quic(err.to_string())),
        StreamRole::Client => connection
            .open_bi()
            .await
            .map_err(|err| HelloError::Quic(err.to_string())),
    }
}

fn reject(connection: &quinn::Connection) {
    connection.close(
        quinn::VarInt::from_u32(PEER_REJECT_CODE),
        b"peer leaf rejected",
    );
}

fn peer_leaf(connection: &quinn::Connection) -> Result<Vec<u8>, HelloError> {
    let identity = connection.peer_identity().ok_or(HelloError::PeerRejected)?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| HelloError::PeerRejected)?;
    let leaf = chain.first().ok_or(HelloError::PeerRejected)?;
    Ok(leaf.as_ref().to_vec())
}

async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Frame, HelloError> {
    let mut prefix = [0u8; 4];
    read_exact(recv, &mut prefix).await?;
    let len =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| HelloError::BadFrameLength)?;
    if !(crate::HEADER_LEN..=crate::MAX_FRAME_LEN).contains(&len) {
        return Err(HelloError::BadFrameLength);
    }
    let mut body = vec![0u8; len];
    read_exact(recv, &mut body).await?;
    Frame::decode(&body).map_err(HelloError::Frame)
}

async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<(), HelloError> {
    match recv.read_exact(buf).await {
        Ok(()) => Ok(()),
        Err(quinn::ReadExactError::FinishedEarly(_)) => Err(HelloError::StreamClosed),
        Err(quinn::ReadExactError::ReadError(err)) => Err(HelloError::Quic(err.to_string())),
    }
}

fn random_session_id() -> u32 {
    let mut bytes = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    u32::from_ne_bytes(bytes)
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    if let Ok(idle) = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)) {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    Arc::new(transport)
}

fn server_rustls(config: &HelloConfig) -> Result<(rustls::ServerConfig, Auth), HelloError> {
    let provider = crypto_provider();
    let verifier = Arc::new(PresentedLeafVerifier {
        provider: Arc::clone(&provider),
    });
    let (chain, key) = identity_parts(config)?;
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| HelloError::Tls(err.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|err| HelloError::Tls(err.to_string()))?;
    server.alpn_protocols = vec![ALPN.to_vec()];
    Ok((server, auth_from(config)))
}

fn client_rustls(config: &HelloConfig) -> Result<(rustls::ClientConfig, Auth), HelloError> {
    let provider = crypto_provider();
    let verifier = Arc::new(PresentedLeafVerifier {
        provider: Arc::clone(&provider),
    });
    let (chain, key) = identity_parts(config)?;
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| HelloError::Tls(err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)
        .map_err(|err| HelloError::Tls(err.to_string()))?;
    client.alpn_protocols = vec![ALPN.to_vec()];
    Ok((client, auth_from(config)))
}

fn auth_from(config: &HelloConfig) -> Auth {
    Auth {
        trust: config.trust.clone(),
        ticket_hash: config.ticket_hash,
        deny: config.deny.clone(),
    }
}

fn identity_parts(
    config: &HelloConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), HelloError> {
    let der = decode_certificate_pem(&config.certificate_pem).map_err(HelloError::Identity)?;
    let key = private_key(&config.private_key_pem)?;
    Ok((vec![CertificateDer::from(der)], key))
}

fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>, HelloError> {
    let mut cursor = Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|err| HelloError::Tls(err.to_string()))?
        .ok_or_else(|| HelloError::Tls("The private key PEM is empty.".to_string()))
}

fn crypto_provider() -> Arc<CryptoProvider> {
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();
    Arc::new(rustls::crypto::ring::default_provider())
}

fn io_error(err: std::io::Error) -> HelloError {
    HelloError::Io(err.to_string())
}

/// Accept a presented leaf during the QUIC handshake.
///
/// The verifier checks the handshake signature.
/// The session then calls `PeerGate::bind_leaf`.
/// DATA stays rejected until that check succeeds.
struct PresentedLeafVerifier {
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for PresentedLeafVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PresentedLeafVerifier")
    }
}

impl PresentedLeafVerifier {
    fn verify_signature(
        &self,
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
                &self.provider.signature_verification_algorithms,
            )
        } else {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }
    }
}

fn require_leaf(end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
    if end_entity.is_empty() {
        return Err(rustls::Error::NoCertificatesPresented);
    }
    Ok(())
}

impl ServerCertVerifier for PresentedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        require_leaf(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for PresentedLeafVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        require_leaf(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
