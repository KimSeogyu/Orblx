use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use orblx_datapath::{ipv4_packet, prove_hello_socket, HelloError, HelloSocketRole};
use orblx_relay::{
    framing_name, RelayError, RelayPipe, RelayPreference, RelayServer, RelaySessionId,
    RelayTransport, ServerConfig, RELAY_PORT,
};

use crate::direct::issue_direct_pair;
use crate::{
    DirectIdentity, DirectPhase, DirectRequest, DirectRole, EdgeError, EndpointCandidate,
    LabStunServer, MemoryCandidateSink, PathId, PathMachine, PathState, RelayPhase, StunClient,
    DIRECT_QUIC_PORT, STICK_AND_UPGRADE,
};

/// Plaintext bytes inside the QUIC probe packet.
///
/// The Relay audit needle is this value.
/// A hit means the bytes were visible on the Relay.
pub const RELAY_PROOF_PAYLOAD: &[u8] = b"orblx-w6-relay-probe";

/// The longest time that a bridge blocks before it checks the stop flag.
const BRIDGE_WAIT: Duration = Duration::from_millis(50);
const LAB_DIRECT_BUDGET: Duration = Duration::from_millis(200);
const LAB_QUIC_BUDGET: Duration = Duration::from_secs(8);
const LAB_UDP_TIMEOUT: Duration = Duration::from_secs(2);
const LAB_UDP_BLOCK_TIMEOUT: Duration = Duration::from_millis(400);
const LAB_TCP_TIMEOUT: Duration = Duration::from_secs(2);
const SERVER_HEAD_START: Duration = Duration::from_millis(80);

/// Which in-process Relay lab to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySmokeMode {
    /// Direct fails, then both peers use the Relay over UDP.
    Udp,
    /// The Relay UDP socket does not answer, so the peers use TCP.
    Tcp,
}

/// Inputs for one Relay attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRequest {
    /// The routing session id.
    ///
    /// The Relay does not mint this value.
    pub session_id: RelaySessionId,
    /// The Relay UDP socket.
    pub udp: SocketAddr,
    /// The Relay TCP socket.
    pub tcp: SocketAddr,
    /// UDP only, TCP only, or UDP then TCP.
    pub preference: RelayPreference,
    /// How long to wait for a UDP ATTACH reply.
    pub udp_timeout: Duration,
    /// How long to wait for a TCP ATTACH reply.
    pub tcp_timeout: Duration,
    /// The budget for attach plus the QUIC proof.
    pub budget: Duration,
}

/// One attached Relay path before the QUIC proof.
///
/// Quinn stays on a loopback socket.
/// The Relay socket carries opaque QUIC packets.
#[derive(Debug)]
pub struct RelayLink {
    stop: Arc<AtomicBool>,
    bridge: Option<JoinHandle<()>>,
    quinn: Option<UdpSocket>,
    face_addr: SocketAddr,
    transport: RelayTransport,
    session_id: RelaySessionId,
    started: Instant,
    budget: Duration,
}

impl Drop for RelayLink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.bridge.take() {
            let _ = handle.join();
        }
    }
}

/// Evidence from one Relay QUIC proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayProof {
    /// UDP or TCP.
    pub transport: RelayTransport,
    /// The routing session id.
    pub session_id: RelaySessionId,
    /// The opaque path id.
    pub path_id: PathId,
    /// The time from the start of the Relay attempt to QUIC up.
    pub elapsed: Duration,
    /// The echoed IPv4 probe.
    pub echoed: Vec<u8>,
    /// `udp-datagram` or `quic-style`.
    pub framing: &'static str,
}

/// Evidence from the in-process Relay lab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLabReport {
    /// `udp` or `tcp`.
    pub lab: &'static str,
    /// True when the lab called Direct before Relay.
    pub direct_attempted: bool,
    /// True when Direct ended in Failed.
    pub direct_failed: bool,
    /// True when the UDP ATTACH did not get a reply.
    pub udp_blocked: bool,
    /// The transport that carried QUIC.
    pub transport: RelayTransport,
    /// The framing used on that transport.
    pub framing: &'static str,
    /// The ADR 0003 port.
    pub policy_port: u16,
    /// The bound Relay UDP port.
    ///
    /// Zero means the lab did not bind UDP.
    pub relay_udp_port: u16,
    /// The bound Relay TCP port.
    ///
    /// Zero means the lab did not bind TCP.
    pub relay_tcp_port: u16,
    /// The server Relay flag.
    pub server_relay_is_up: bool,
    /// The client Relay flag.
    pub client_relay_is_up: bool,
    /// The server Direct flag.
    pub server_direct_is_up: bool,
    /// The client Direct flag.
    pub client_direct_is_up: bool,
    /// Hole-punch datagrams the server sent before Relay.
    pub server_direct_packets: u32,
    /// Hole-punch datagrams the client sent before Relay.
    pub client_direct_packets: u32,
    /// The QUIC probe echoed on both peers.
    pub echo_ok: bool,
    /// Forwarded payloads that contained the probe text.
    pub plaintext_hits: u64,
    /// Payloads the Relay delivered.
    pub forwards: u64,
    /// The routing session id.
    pub session_id: RelaySessionId,
    /// The server path id.
    pub path_id_server: PathId,
    /// The client path id.
    pub path_id_client: PathId,
    /// The slower peer's elapsed time.
    pub elapsed: Duration,
    /// Stick and upgrade status.
    pub stick: &'static str,
}

impl RelayLabReport {
    /// Return true when the Relay saw ciphertext and not the probe text.
    #[must_use]
    pub fn payload_opaque(&self) -> bool {
        self.echo_ok && self.forwards > 0 && self.plaintext_hits == 0
    }

    /// Return the lab lines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("relay lab {}", self.lab),
            format!("direct_attempted {}", self.direct_attempted),
            format!("direct_failed {}", self.direct_failed),
            format!("udp_blocked {}", self.udp_blocked),
            format!("transport {}", self.transport),
            format!("framing {}", self.framing),
            format!("policy port {}", self.policy_port),
            format!("relay udp port {}", self.relay_udp_port),
            format!("relay tcp port {}", self.relay_tcp_port),
            format!("server relay_is_up {}", self.server_relay_is_up),
            format!("client relay_is_up {}", self.client_relay_is_up),
            format!("server direct_is_up {}", self.server_direct_is_up),
            format!("client direct_is_up {}", self.client_direct_is_up),
            format!("server direct packets {}", self.server_direct_packets),
            format!("client direct packets {}", self.client_direct_packets),
            format!("echo ok {}", self.echo_ok),
            format!("plaintext_hits {}", self.plaintext_hits),
            format!("forwards {}", self.forwards),
            format!("payload_opaque {}", self.payload_opaque()),
            format!("session_id {}", self.session_id),
            format!("server path_id {}", self.path_id_server.to_hex()),
            format!("client path_id {}", self.path_id_client.to_hex()),
            format!("elapsed_ms {}", self.elapsed.as_millis()),
            format!("stick {STICK_AND_UPGRADE}"),
            "tcp framing quic-style".to_string(),
        ]
    }
}

impl PathMachine {
    /// Attach to the Relay.
    ///
    /// The machine must be in Allocate Ready or Direct Failed.
    /// The function tries UDP first when the preference is Auto or UDP.
    /// When UDP fails and the preference is Auto, the function uses TCP.
    /// The function does not punch a direct path.
    /// `retry_direct` is the later Direct attempt while Relay is up.
    pub fn begin_relay(&mut self, request: RelayRequest) -> Result<RelayLink, EdgeError> {
        let candidate = self.candidate_for_relay()?;
        let started = Instant::now();
        let pipe = match request.preference {
            RelayPreference::Tcp => {
                self.enter_attach(candidate, RelayTransport::Tcp, request.session_id);
                connect_tcp(&request, started)?
            }
            RelayPreference::Udp => {
                self.enter_attach(candidate, RelayTransport::Udp, request.session_id);
                match connect_udp(&request, started) {
                    Ok(pipe) => pipe,
                    Err(error) => {
                        self.fail_relay(candidate, request.session_id);
                        return Err(error);
                    }
                }
            }
            RelayPreference::Auto => {
                self.enter_attach(candidate, RelayTransport::Udp, request.session_id);
                match connect_udp(&request, started) {
                    Ok(pipe) => pipe,
                    Err(_) => {
                        if started.elapsed() > request.budget {
                            self.fail_relay(candidate, request.session_id);
                            return Err(EdgeError::RelayBudget);
                        }
                        self.enter_attach(candidate, RelayTransport::Tcp, request.session_id);
                        match connect_tcp(&request, started) {
                            Ok(pipe) => pipe,
                            Err(error) => {
                                self.fail_relay(candidate, request.session_id);
                                return Err(error);
                            }
                        }
                    }
                }
            }
        };
        if started.elapsed() > request.budget {
            self.fail_relay(candidate, request.session_id);
            return Err(EdgeError::RelayBudget);
        }
        let transport = pipe.transport();
        RelayLink::start(pipe, request.session_id, transport, started, request.budget)
    }

    /// Prove QUIC through an attached Relay link.
    ///
    /// The server echoes one IPv4 packet.
    /// The client checks the echo.
    /// The Relay does not see the packet as plaintext.
    pub fn finish_relay(
        &mut self,
        mut link: RelayLink,
        role: DirectRole,
        identity: &DirectIdentity,
    ) -> Result<RelayProof, EdgeError> {
        let (candidate, transport, session_id) = self.relay_attach()?;
        if transport != link.transport || session_id != link.session_id {
            self.fail_relay(candidate, session_id);
            return Err(EdgeError::WrongState);
        }
        let socket = match link.quinn.take() {
            Some(socket) => socket,
            None => {
                self.fail_relay(candidate, session_id);
                return Err(EdgeError::Relay("The QUIC socket is missing.".to_string()));
            }
        };
        let remaining = link.budget.saturating_sub(link.started.elapsed());
        if remaining.is_zero() {
            self.fail_relay(candidate, session_id);
            return Err(EdgeError::RelayBudget);
        }
        let socket_role = match role {
            DirectRole::Server => HelloSocketRole::Server,
            DirectRole::Client => HelloSocketRole::Client {
                peer: link.face_addr,
            },
        };
        let echoed = match prove_quic(identity, socket, socket_role, remaining) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.fail_relay(candidate, session_id);
                return Err(error);
            }
        };
        let elapsed = link.started.elapsed();
        if elapsed > link.budget {
            self.fail_relay(candidate, session_id);
            return Err(EdgeError::RelayBudget);
        }
        let path_id = PathId::allocate()?;
        self.move_to(PathState::Relay {
            phase: RelayPhase::Up {
                transport,
                session_id,
                path_id,
            },
            candidate,
        });
        self.arm_direct_retry(Instant::now());
        Ok(RelayProof {
            transport,
            session_id,
            path_id,
            elapsed,
            echoed,
            framing: framing_name(transport),
        })
    }

    fn enter_attach(
        &mut self,
        candidate: EndpointCandidate,
        transport: RelayTransport,
        session_id: RelaySessionId,
    ) {
        self.move_to(PathState::Relay {
            phase: RelayPhase::Attach {
                transport,
                session_id,
            },
            candidate,
        });
    }

    fn fail_relay(&mut self, candidate: EndpointCandidate, session_id: RelaySessionId) {
        self.move_to(PathState::Relay {
            phase: RelayPhase::Failed { session_id },
            candidate,
        });
    }

    fn relay_attach(
        &self,
    ) -> Result<(EndpointCandidate, RelayTransport, RelaySessionId), EdgeError> {
        match self.state() {
            PathState::Relay {
                phase:
                    RelayPhase::Attach {
                        transport,
                        session_id,
                    },
                candidate,
            } => Ok((candidate, transport, session_id)),
            PathState::Allocate { .. } | PathState::Direct { .. } | PathState::Relay { .. } => {
                Err(EdgeError::WrongState)
            }
        }
    }
}

impl RelayLink {
    fn start(
        pipe: RelayPipe,
        session_id: RelaySessionId,
        transport: RelayTransport,
        started: Instant,
        budget: Duration,
    ) -> Result<Self, EdgeError> {
        let quinn = UdpSocket::bind(loopback()).map_err(crate::error::io_error)?;
        let face = UdpSocket::bind(loopback()).map_err(crate::error::io_error)?;
        let quinn_addr = quinn.local_addr().map_err(crate::error::io_error)?;
        let face_addr = face.local_addr().map_err(crate::error::io_error)?;
        face.connect(quinn_addr).map_err(crate::error::io_error)?;
        let stop = Arc::new(AtomicBool::new(false));
        let bridge = spawn_bridge(pipe, face, Arc::clone(&stop));
        Ok(Self {
            stop,
            bridge: Some(bridge),
            quinn: Some(quinn),
            face_addr,
            transport,
            session_id,
            started,
            budget,
        })
    }
}

fn connect_udp(request: &RelayRequest, started: Instant) -> Result<RelayPipe, EdgeError> {
    if started.elapsed() > request.budget {
        return Err(EdgeError::RelayBudget);
    }
    RelayPipe::connect_udp(request.udp, request.session_id, request.udp_timeout).map_err(map_relay)
}

fn connect_tcp(request: &RelayRequest, started: Instant) -> Result<RelayPipe, EdgeError> {
    if started.elapsed() > request.budget {
        return Err(EdgeError::RelayBudget);
    }
    RelayPipe::connect_tcp(request.tcp, request.session_id, request.tcp_timeout).map_err(map_relay)
}

fn map_relay(err: RelayError) -> EdgeError {
    match err {
        RelayError::UdpBlocked | RelayError::Timeout => EdgeError::RelayBudget,
        other => EdgeError::Relay(other.to_string()),
    }
}

fn prove_quic(
    identity: &DirectIdentity,
    socket: UdpSocket,
    role: HelloSocketRole,
    timeout: Duration,
) -> Result<Vec<u8>, EdgeError> {
    let config = identity.to_hello()?;
    let packet = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(10, 8, 0, 2),
        RELAY_PROOF_PAYLOAD,
    )
    .map_err(|err| EdgeError::Quic(err.to_string()))?;
    let echoed = prove_hello_socket(config, socket, role, &packet, timeout).map_err(map_hello)?;
    if echoed != packet {
        return Err(EdgeError::EchoMismatch);
    }
    Ok(echoed)
}

fn map_hello(err: HelloError) -> EdgeError {
    let text = err.to_string();
    if text.contains("timed out") {
        EdgeError::RelayBudget
    } else {
        EdgeError::Quic(text)
    }
}

fn spawn_bridge(mut pipe: RelayPipe, face: UdpSocket, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = face.set_nonblocking(true);
        let mut buf = [0u8; 65_535];
        while !stop.load(Ordering::Relaxed) {
            let mut idle = true;
            match face.recv(&mut buf) {
                Ok(size) => {
                    idle = false;
                    if pipe.send_opaque(&buf[..size]).is_err() {
                        break;
                    }
                }
                Err(err) if is_idle(&err) => {}
                Err(_) => break,
            }
            loop {
                match pipe.recv_opaque() {
                    Ok(Some(payload)) => {
                        idle = false;
                        if !send_face(&face, &payload) {
                            pipe.detach();
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        pipe.detach();
                        return;
                    }
                }
            }
            if idle {
                // Block until the face or the Relay has data. The limit sets the stop check.
                if pipe.wait_readable_or(&face, BRIDGE_WAIT).is_err() {
                    break;
                }
            }
        }
        pipe.detach();
    })
}

fn send_face(face: &UdpSocket, payload: &[u8]) -> bool {
    let started = Instant::now();
    loop {
        match face.send(payload) {
            Ok(size) if size == payload.len() => return true,
            Ok(_) => return false,
            Err(err) if is_idle(&err) => {
                if started.elapsed() > Duration::from_millis(200) {
                    return false;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return false,
        }
    }
}

fn is_idle(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Run one in-process Relay lab.
///
/// `bind` sets the Relay UDP and TCP socket.
/// `None` uses an ephemeral port on loopback.
/// The UDP lab forces Direct to fail, then uses UDP.
/// The TCP lab leaves Direct unattempted and discards UDP.
pub fn run_relay_smoke(
    mode: RelaySmokeMode,
    bind: Option<SocketAddr>,
) -> Result<RelayLabReport, EdgeError> {
    let listen = bind.unwrap_or_else(loopback);
    let udp_discard = matches!(mode, RelaySmokeMode::Tcp);
    let mut server = RelayServer::spawn(ServerConfig {
        udp_bind: Some(listen),
        tcp_bind: Some(listen),
        audit_absent: Some(RELAY_PROOF_PAYLOAD.to_vec()),
        audit_path: None,
        udp_discard,
    })
    .map_err(map_relay)?;
    let udp = server
        .udp_addr()
        .ok_or_else(|| EdgeError::Relay("The Relay UDP socket did not bind.".to_string()))?;
    let tcp = server
        .tcp_addr()
        .ok_or_else(|| EdgeError::Relay("The Relay TCP socket did not bind.".to_string()))?;
    let session_id = RelaySessionId::generate().map_err(map_relay)?;
    let material = issue_direct_pair(SystemTime::now())?;
    let direct_attempted = matches!(mode, RelaySmokeMode::Udp);
    let (server_machine, server_packets) = prepare_peer(direct_attempted)?;
    let (client_machine, client_packets) = prepare_peer(direct_attempted)?;
    let preference = match mode {
        RelaySmokeMode::Udp => RelayPreference::Udp,
        RelaySmokeMode::Tcp => RelayPreference::Auto,
    };
    let udp_timeout = match mode {
        RelaySmokeMode::Udp => LAB_UDP_TIMEOUT,
        RelaySmokeMode::Tcp => LAB_UDP_BLOCK_TIMEOUT,
    };
    let request = RelayRequest {
        session_id,
        udp,
        tcp,
        preference,
        udp_timeout,
        tcp_timeout: LAB_TCP_TIMEOUT,
        budget: LAB_QUIC_BUDGET,
    };
    let server_identity = material.server.clone();
    let client_identity = material.client.clone();
    let server_request = request;
    let client_request = request;

    let server_begin = thread::spawn(move || begin_owned(server_machine, server_request));
    let client_begin = thread::spawn(move || begin_owned(client_machine, client_request));
    let (server_machine, server_link) = join_lab(server_begin)??;
    let (client_machine, client_link) = join_lab(client_begin)??;

    let server_finish = thread::spawn(move || {
        finish_owned(
            server_machine,
            server_link,
            DirectRole::Server,
            server_identity,
        )
    });
    thread::sleep(SERVER_HEAD_START);
    let client_finish = thread::spawn(move || {
        finish_owned(
            client_machine,
            client_link,
            DirectRole::Client,
            client_identity,
        )
    });
    let (server_proof, server_machine) = join_lab(server_finish)??;
    let (client_proof, client_machine) = join_lab(client_finish)??;
    if server_proof.transport != client_proof.transport {
        return Err(EdgeError::Relay(
            "The peers used different Relay transports.".to_string(),
        ));
    }
    let stats = server.stats();
    server.shutdown();

    let echo_ok = server_proof.echoed == client_proof.echoed
        && server_proof
            .echoed
            .windows(RELAY_PROOF_PAYLOAD.len())
            .any(|window| window == RELAY_PROOF_PAYLOAD);
    Ok(RelayLabReport {
        lab: match mode {
            RelaySmokeMode::Udp => "udp",
            RelaySmokeMode::Tcp => "tcp",
        },
        direct_attempted,
        direct_failed: direct_attempted,
        udp_blocked: udp_discard,
        transport: server_proof.transport,
        framing: server_proof.framing,
        policy_port: DIRECT_QUIC_PORT,
        relay_udp_port: udp.port(),
        relay_tcp_port: tcp.port(),
        server_relay_is_up: server_machine.relay_is_up(),
        client_relay_is_up: client_machine.relay_is_up(),
        server_direct_is_up: server_machine.direct_is_up(),
        client_direct_is_up: client_machine.direct_is_up(),
        server_direct_packets: server_packets,
        client_direct_packets: client_packets,
        echo_ok,
        plaintext_hits: stats.plaintext_hits,
        forwards: stats.forwards,
        session_id,
        path_id_server: server_proof.path_id,
        path_id_client: client_proof.path_id,
        elapsed: server_proof.elapsed.max(client_proof.elapsed),
        stick: STICK_AND_UPGRADE,
    })
}

fn begin_owned(
    mut machine: PathMachine,
    request: RelayRequest,
) -> Result<(PathMachine, RelayLink), EdgeError> {
    let link = machine.begin_relay(request)?;
    Ok((machine, link))
}

fn finish_owned(
    mut machine: PathMachine,
    link: RelayLink,
    role: DirectRole,
    identity: DirectIdentity,
) -> Result<(RelayProof, PathMachine), EdgeError> {
    let proof = machine.finish_relay(link, role, &identity)?;
    Ok((proof, machine))
}

fn prepare_peer(fail_direct: bool) -> Result<(PathMachine, u32), EdgeError> {
    let stun = LabStunServer::bind(loopback())?;
    let stun_addr = stun.local_addr()?;
    let stun_thread = thread::spawn(move || stun.serve_one(Duration::from_secs(3)));
    let client = StunClient::bind(loopback())?;
    let mut machine = PathMachine::start_allocate();
    let mut sink = MemoryCandidateSink::default();
    machine.gather_reflexive(&client, stun_addr, Duration::from_secs(2), &mut sink)?;
    join_lab(stun_thread)??;
    if !fail_direct {
        return Ok((machine, 0));
    }
    let remote = EndpointCandidate {
        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        reflexive: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
    };
    let error = machine.establish_direct(DirectRequest {
        role: DirectRole::Server,
        remote,
        token: crate::PunchToken::generate()?,
        socket: client.into_socket(),
        identity: empty_identity(),
        budget: LAB_DIRECT_BUDGET,
    });
    match error {
        Err(EdgeError::DirectBudget) => {}
        Ok(_) => {
            return Err(EdgeError::Relay(
                "Direct came up. The Relay lab needs Direct to fail.".to_string(),
            ))
        }
        Err(error) => return Err(error),
    }
    let packets = match machine.state() {
        PathState::Direct {
            phase: DirectPhase::Failed { packets_sent, .. },
            ..
        } => packets_sent,
        PathState::Allocate { .. } | PathState::Direct { .. } | PathState::Relay { .. } => 0,
    };
    Ok((machine, packets))
}

fn empty_identity() -> DirectIdentity {
    DirectIdentity::blank()
}

fn join_lab<T>(handle: JoinHandle<T>) -> Result<T, EdgeError> {
    handle.join().map_err(|_| EdgeError::LabThread)
}

/// Return the Relay policy port.
///
/// The port is 443 for UDP and for TCP.
#[must_use]
pub fn relay_policy_port() -> u16 {
    RELAY_PORT
}
