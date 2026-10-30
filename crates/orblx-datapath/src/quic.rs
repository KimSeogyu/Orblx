use std::collections::HashSet;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use orblx_crypto::TicketRing;
use orblx_identity::{decode_certificate_pem, leaf_not_after, DenySet, SpiffeId, TrustBundle};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tokio::sync::mpsc;

use crate::framing::expect_seq;
use crate::{
    encode_length_prefixed, is_ipv4_packet, Frame, FrameType, HelloError, PeerGate, FLAG_REKEY_REQ,
};

const ALPN: &[u8] = b"orblx-hello";
const SERVER_NAME: &str = "orblx.local";
const PEER_REJECT_CODE: u32 = 1;
const TICKET_REJECT_CODE: u32 = 2;
const TICKET_MAC_LEN: usize = 32;

/// Leaf material and the capability ticket for one hello-quic endpoint.
///
/// `ticket_bytes` are the identity version-1 ticket bytes this endpoint presents.
/// `ticket_mac` is the HMAC tag from `orblx_crypto::ticket_mac` over those bytes.
/// `ticket_ring` verifies the peer ticket.
#[derive(Clone)]
pub struct HelloConfig {
    /// PEM certificate for this endpoint.
    pub certificate_pem: String,
    /// PEM private key for this endpoint.
    pub private_key_pem: String,
    /// Roots that can authenticate the peer leaf.
    pub trust: TrustBundle,
    /// Identity version-1 ticket bytes for this endpoint.
    pub ticket_bytes: Vec<u8>,
    /// HMAC-SHA256 tag over `ticket_bytes`.
    pub ticket_mac: [u8; 32],
    /// Ticket keys for the peer ticket check.
    pub ticket_ring: TicketRing,
    /// Deny list for the leaf check and the ticket check.
    pub deny: DenySet,
}

impl HelloConfig {
    /// Build a config from an issued SVID and a presented capability ticket.
    #[must_use]
    pub fn from_issued(
        certificate_pem: &str,
        private_key_pem: &str,
        trust: TrustBundle,
        ticket_bytes: Vec<u8>,
        ticket_mac: [u8; 32],
        ticket_ring: TicketRing,
    ) -> Self {
        Self {
            certificate_pem: certificate_pem.to_string(),
            private_key_pem: private_key_pem.to_string(),
            trust,
            ticket_bytes,
            ticket_mac,
            ticket_ring,
            deny: DenySet::empty(),
        }
    }
}

struct Auth {
    trust: TrustBundle,
    deny: SharedDeny,
    allow: SharedAllow,
    ticket_bytes: Vec<u8>,
    ticket_mac: [u8; 32],
    ticket_ring: TicketRing,
}

type SharedDeny = Arc<Mutex<DenySet>>;

/// The SPIFFE IDs that may open a session. None allows every trusted leaf.
type SharedAllow = Arc<Mutex<Option<HashSet<String>>>>;

fn allowed(allow: &SharedAllow, peer: &str) -> bool {
    allow
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .as_ref()
        .is_none_or(|set| set.contains(peer))
}

fn deny_now(deny: &SharedDeny) -> DenySet {
    deny.lock().unwrap_or_else(|err| err.into_inner()).clone()
}

/// A Quinn endpoint that speaks hello-quic.
pub struct HelloEndpoint {
    endpoint: quinn::Endpoint,
    auth: Arc<Auth>,
    /// The leaf used for the next outbound handshake.
    ///
    /// Quinn stores this value on the endpoint object.
    /// A shared endpoint cannot replace it through `&self`.
    client_config: Mutex<Option<quinn::ClientConfig>>,
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
        Ok(Self::assemble(endpoint, auth, None))
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
        endpoint.set_default_client_config(client.clone());
        Ok(Self::assemble(endpoint, auth, Some(client)))
    }

    /// Bind one UDP socket that accepts peers and dials peers.
    ///
    /// Call this function inside a Tokio runtime.
    /// The node daemon uses this socket for every peer.
    pub fn bind_node(config: HelloConfig, listen: SocketAddr) -> Result<Self, HelloError> {
        let (server_config, auth) = server_rustls(&config)?;
        let (client_config, _) = client_rustls(&config)?;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
            .map_err(|err| HelloError::Tls(err.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server.transport_config(transport_config());
        let mut endpoint = quinn::Endpoint::server(server, listen).map_err(io_error)?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
            .map_err(|err| HelloError::Tls(err.to_string()))?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic_client));
        client.transport_config(transport_config());
        endpoint.set_default_client_config(client.clone());
        Ok(Self::assemble(endpoint, auth, Some(client)))
    }

    /// Install a new leaf for later handshakes.
    ///
    /// Open sessions keep the previous leaf until the node reconnects.
    pub fn install_identity(&self, config: &HelloConfig) -> Result<(), HelloError> {
        let (server_config, _) = server_rustls(config)?;
        let (client_config, _) = client_rustls(config)?;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
            .map_err(|err| HelloError::Tls(err.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server.transport_config(transport_config());
        self.endpoint.set_server_config(Some(server));
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
            .map_err(|err| HelloError::Tls(err.to_string()))?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic_client));
        client.transport_config(transport_config());
        *self
            .client_config
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Some(client);
        Ok(())
    }

    fn assemble(
        endpoint: quinn::Endpoint,
        auth: Auth,
        client: Option<quinn::ClientConfig>,
    ) -> Self {
        Self {
            endpoint,
            auth: Arc::new(auth),
            client_config: Mutex::new(client),
        }
    }

    /// Return the local UDP address.
    pub fn local_addr(&self) -> Result<SocketAddr, HelloError> {
        self.endpoint.local_addr().map_err(io_error)
    }

    /// Replace the deny set used by new sessions and open sessions.
    pub fn replace_deny(&self, deny: DenySet) {
        let mut slot = self.auth.deny.lock().unwrap_or_else(|err| err.into_inner());
        *slot = deny;
    }

    /// True when the deny list of the endpoint revokes the peer SVID (W24).
    #[must_use]
    pub fn denies(&self, peer: &SpiffeId) -> bool {
        let slot = self.auth.deny.lock().unwrap_or_else(|err| err.into_inner());
        slot.reject_uri(peer).is_err()
    }

    /// Replace the peer allow list for new sessions (W23-1 node lock).
    ///
    /// None allows every peer with a trusted leaf. With a set, the endpoint closes
    /// a new connection from a peer outside the set before the ticket exchange.
    pub fn replace_allow(&self, allow: Option<HashSet<String>>) {
        let mut slot = self
            .auth
            .allow
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *slot = allow;
    }

    /// Close the UDP socket.
    ///
    /// Open connections stop.
    /// `accept_one` returns [`HelloError::EndpointClosed`].
    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"node down");
    }

    /// Accept one peer and one bidirectional stream.
    pub async fn accept_one(&self) -> Result<HelloSession, HelloError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(HelloError::EndpointClosed)?;
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
        let (endpoint, auth, client) = match role {
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
                (endpoint, auth, None)
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
                endpoint.set_default_client_config(client.clone());
                (endpoint, auth, Some(client))
            }
        };
        Ok(Self::assemble(endpoint, auth, client))
    }

    /// Connect to `peer` and open one bidirectional stream.
    pub async fn connect_one(&self, peer: SocketAddr) -> Result<HelloSession, HelloError> {
        let config = self
            .client_config
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
            .ok_or_else(|| HelloError::Quic("The endpoint has no client identity.".to_string()))?;
        let connecting = self
            .endpoint
            .connect_with(config, peer, SERVER_NAME)
            .map_err(|err| HelloError::Quic(err.to_string()))?;
        let connection = connecting
            .await
            .map_err(|err| HelloError::Quic(err.to_string()))?;
        bind_session(connection, &self.auth, StreamRole::Client).await
    }

    /// Connect to `peer`. Start one more attempt each `probe_every` until one attempt ends.
    ///
    /// QUIC sends the Initial packet of an attempt again only after a backoff (about 1 s, then 2 s).
    /// When the peer starts to listen after the first Initial, a single attempt can wait for seconds.
    /// The earlier attempts stay open, so a slow handshake on a long path can still finish.
    /// The function starts at most [`MAX_CONNECT_PROBES`] attempts.
    /// The first session or the first error ends the call and drops the other attempts.
    /// The caller sets the time limit.
    pub async fn connect_probed(
        self: &Arc<Self>,
        peer: SocketAddr,
        probe_every: Duration,
    ) -> Result<HelloSession, HelloError> {
        self.connect_probed_limited(peer, probe_every, || true)
            .await
    }

    /// Connect to `peer` as [`Self::connect_probed`] does, but ask `allow` before each attempt.
    ///
    /// When `allow` returns false, the function does not start the attempt and asks again
    /// after `probe_every`. A node uses this to share one probe budget between its peers (W25-28).
    pub async fn connect_probed_limited(
        self: &Arc<Self>,
        peer: SocketAddr,
        probe_every: Duration,
        mut allow: impl FnMut() -> bool,
    ) -> Result<HelloSession, HelloError> {
        let mut attempts = tokio::task::JoinSet::new();
        let mut next = tokio::time::Instant::now();
        let mut started = 0usize;
        loop {
            if started < MAX_CONNECT_PROBES && tokio::time::Instant::now() >= next {
                if allow() {
                    let endpoint = Arc::clone(self);
                    attempts.spawn(async move { endpoint.connect_one(peer).await });
                    started += 1;
                }
                next += probe_every;
            }
            let more = started < MAX_CONNECT_PROBES;
            tokio::select! {
                Some(done) = attempts.join_next() => match done {
                    Ok(result) => return result,
                    Err(err) => return Err(HelloError::Quic(err.to_string())),
                },
                () = tokio::time::sleep_until(next), if more => {}
            }
        }
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

#[derive(Clone, Copy)]
enum StreamRole {
    Server,
    Client,
}

/// One authenticated hello-quic session.
pub struct HelloSession {
    connection: quinn::Connection,
    sender: HelloSender,
    receiver: HelloReceiver,
    peer_not_after: u64,
}

impl HelloSession {
    /// Return the bound peer SPIFFE ID.
    #[must_use]
    pub fn peer_id(&self) -> &SpiffeId {
        self.sender.peer()
    }

    /// Return the peer leaf `not_after` time as Unix seconds.
    #[must_use]
    pub fn peer_not_after(&self) -> u64 {
        self.peer_not_after
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

    /// Read one IPv4 packet.
    ///
    /// CTRL frames stay on the session and are skipped.
    async fn recv_overlay(&mut self) -> Result<Vec<u8>, HelloError> {
        loop {
            match self.receiver.recv_event().await? {
                SessionEvent::Packet(packet) => return Ok(packet),
                SessionEvent::Keepalive | SessionEvent::Rekey => {}
            }
        }
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

    /// Send one CTRL frame.
    ///
    /// `flags` may include [`FLAG_REKEY_REQ`].
    pub(crate) async fn send_ctrl(&mut self, flags: u8) -> Result<(), HelloError> {
        let frame = Frame {
            frame_type: FrameType::Ctrl,
            flags,
            session_id: self.session_id,
            seq: self.next_seq,
            ticket_hash: self.ticket_hash,
            payload: Vec::new(),
        };
        let bytes = encode_length_prefixed(&frame)?;
        self.send
            .write_all(&bytes)
            .await
            .map_err(|err| HelloError::Quic(err.to_string()))?;
        self.next_seq = self.next_seq.checked_add(1).ok_or(HelloError::BadSeq)?;
        Ok(())
    }
}

/// One frame from an open session.
pub(crate) enum SessionEvent {
    /// An IPv4 packet.
    Packet(Vec<u8>),
    /// A CTRL frame with no rekey flag.
    Keepalive,
    /// A CTRL frame that requests a new handshake.
    Rekey,
}

/// The receive half of a hello-quic session.
pub struct HelloReceiver {
    recv: quinn::RecvStream,
    next_seq: u64,
    gate: PeerGate,
    deny: SharedDeny,
}

impl HelloReceiver {
    /// Read one DATA frame.
    ///
    /// The function rejects the frame when the capability ticket check fails.
    pub async fn recv_data_frame(&mut self) -> Result<Frame, HelloError> {
        let frame = read_frame(&mut self.recv).await?;
        self.next_seq = expect_seq(self.next_seq, frame.seq)?;
        let deny = deny_now(&self.deny);
        self.gate
            .payload_from_data(&frame, SystemTime::now(), &deny)?;
        Ok(frame)
    }

    /// Read one IPv4 packet from a DATA frame.
    pub async fn recv_ipv4(&mut self) -> Result<Vec<u8>, HelloError> {
        let frame = self.recv_data_frame().await?;
        Ok(frame.payload)
    }

    /// Read one DATA or CTRL frame.
    pub(crate) async fn recv_event(&mut self) -> Result<SessionEvent, HelloError> {
        let frame = read_frame(&mut self.recv).await?;
        self.next_seq = expect_seq(self.next_seq, frame.seq)?;
        match frame.frame_type {
            FrameType::Data => {
                let deny = deny_now(&self.deny);
                let payload = self
                    .gate
                    .payload_from_data(&frame, SystemTime::now(), &deny)?
                    .to_vec();
                Ok(SessionEvent::Packet(payload))
            }
            FrameType::Ctrl => {
                let deny = deny_now(&self.deny);
                self.gate.accept_ctrl(&frame, SystemTime::now(), &deny)?;
                if frame.flags & FLAG_REKEY_REQ != 0 {
                    Ok(SessionEvent::Rekey)
                } else {
                    Ok(SessionEvent::Keepalive)
                }
            }
            FrameType::Ticket => Err(HelloError::NotData),
        }
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
    let deny = deny_now(&auth.deny);
    if let Err(err) = gate.bind_leaf(&auth.trust, &leaf, SystemTime::now(), &deny) {
        reject(&connection);
        return Err(err);
    }
    let peer = gate.peer().cloned().ok_or(HelloError::PeerNotBound)?;
    if !allowed(&auth.allow, peer.as_uri()) {
        reject(&connection);
        return Err(HelloError::NodeLock(peer.as_uri().to_string()));
    }
    let peer_not_after = leaf_not_after(&leaf).map_err(HelloError::Identity)?;
    let (mut send, mut recv) = open_stream(&connection, role).await?;
    if let Err(err) = exchange_ticket(&mut send, &mut recv, role, auth, &mut gate).await {
        reject_ticket(&connection);
        return Err(err);
    }
    let local_hash = orblx_crypto::ticket_hash(&auth.ticket_bytes);
    let sender_gate = PeerGate::bound(peer.clone());
    Ok(HelloSession {
        connection,
        sender: HelloSender {
            send,
            session_id: random_session_id(),
            next_seq: 0,
            ticket_hash: local_hash,
            peer,
            gate: sender_gate,
        },
        receiver: HelloReceiver {
            recv,
            next_seq: 0,
            gate,
            deny: Arc::clone(&auth.deny),
        },
        peer_not_after,
    })
}

async fn exchange_ticket(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    role: StreamRole,
    auth: &Auth,
    gate: &mut PeerGate,
) -> Result<(), HelloError> {
    match role {
        StreamRole::Client => {
            write_presented(send, auth).await?;
            read_presented(recv, auth, gate).await
        }
        StreamRole::Server => {
            read_presented(recv, auth, gate).await?;
            write_presented(send, auth).await
        }
    }
}

async fn write_presented(send: &mut quinn::SendStream, auth: &Auth) -> Result<(), HelloError> {
    let frame = presented_frame(&auth.ticket_bytes, &auth.ticket_mac);
    let bytes = encode_length_prefixed(&frame)?;
    send.write_all(&bytes)
        .await
        .map_err(|err| HelloError::Quic(err.to_string()))?;
    Ok(())
}

async fn read_presented(
    recv: &mut quinn::RecvStream,
    auth: &Auth,
    gate: &mut PeerGate,
) -> Result<(), HelloError> {
    let frame = match read_frame(recv).await {
        Ok(frame) => frame,
        Err(HelloError::StreamClosed) => return Err(HelloError::TicketMissing),
        Err(err) => return Err(err),
    };
    match frame.frame_type {
        FrameType::Ticket => {}
        FrameType::Data | FrameType::Ctrl => return Err(HelloError::TicketMissing),
    }
    let (ticket_bytes, mac) = split_presented(&frame.payload)?;
    let deny = deny_now(&auth.deny);
    let admitted = gate.admit_ticket(
        &auth.ticket_ring,
        ticket_bytes,
        &mac,
        SystemTime::now(),
        &deny,
    )?;
    if frame.ticket_hash != admitted {
        return Err(HelloError::TicketHash);
    }
    Ok(())
}

/// Build one TICKET frame.
///
/// The payload is the 32-byte HMAC tag and then the identity ticket bytes.
/// `ticket_hash` covers only the identity ticket bytes.
/// The function does not compute a MAC.
fn presented_frame(ticket_bytes: &[u8], mac: &[u8; 32]) -> Frame {
    let mut payload = Vec::with_capacity(TICKET_MAC_LEN + ticket_bytes.len());
    payload.extend_from_slice(mac);
    payload.extend_from_slice(ticket_bytes);
    Frame {
        frame_type: FrameType::Ticket,
        flags: 0,
        session_id: 0,
        seq: 0,
        ticket_hash: orblx_crypto::ticket_hash(ticket_bytes),
        payload,
    }
}

fn split_presented(payload: &[u8]) -> Result<(&[u8], [u8; 32]), HelloError> {
    if payload.len() <= TICKET_MAC_LEN {
        return Err(HelloError::TicketMissing);
    }
    let (mac_bytes, ticket_bytes) = payload.split_at(TICKET_MAC_LEN);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(mac_bytes);
    Ok((ticket_bytes, mac))
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

fn reject_ticket(connection: &quinn::Connection) {
    connection.close(
        quinn::VarInt::from_u32(TICKET_REJECT_CODE),
        b"ticket rejected",
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

/// The most attempts that [`HelloEndpoint::connect_probed`] starts.
pub const MAX_CONNECT_PROBES: usize = 12;

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
        deny: Arc::new(Mutex::new(config.deny.clone())),
        allow: Arc::new(Mutex::new(None)),
        ticket_bytes: config.ticket_bytes.clone(),
        ticket_mac: config.ticket_mac,
        ticket_ring: config.ticket_ring.clone(),
    }
}

const PING_IDENT: u16 = 1;
const PING_SEQ: u16 = 1;

/// Open one hello-quic session, exchange one ICMP echo, and return the elapsed time.
///
/// The time starts after the handshake.
/// The function skips packets that are not the echo reply from `dst` with the same ident and sequence.
///
/// The function binds an ephemeral UDP socket.
/// The function does not open a TUN device.
/// `src` and `dst` are the overlay addresses in the echo request.
pub fn measure_hello_rtt(
    config: HelloConfig,
    peer: SocketAddr,
    timeout: Duration,
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
) -> Result<Duration, HelloError> {
    let packet = crate::ipv4::icmp_echo_request(src, dst, PING_IDENT, PING_SEQ, b"orblx")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    runtime.block_on(async {
        let endpoint = HelloEndpoint::bind_client(
            config,
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        )?;
        let exchange = async {
            let mut session = endpoint.connect_one(peer).await?;
            let started = tokio::time::Instant::now();
            session.send_ipv4(&packet).await?;
            loop {
                let packet = session.recv_overlay().await?;
                if crate::ipv4::is_icmp_echo_reply(&packet, dst, src, PING_IDENT, PING_SEQ) {
                    return Ok(started.elapsed());
                }
            }
        };
        let elapsed = tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| HelloError::Quic("The ping timed out.".to_string()))??;
        endpoint.close();
        Ok(elapsed)
    })
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
/// The session then checks the capability ticket.
/// DATA stays rejected until both checks succeed.
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
