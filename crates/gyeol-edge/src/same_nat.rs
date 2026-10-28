use std::net::{Ipv4Addr, SocketAddr};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use crate::direct::issue_direct_pair;
use crate::lab::LabUdpNat;
use crate::{
    DirectProof, DirectRequest, DirectRole, EdgeError, EndpointCandidate, LabStunServer,
    MemoryCandidateSink, PathId, PathMachine, PunchToken, StunClient, DIRECT_ATTEMPT_BUDGET,
    DIRECT_QUIC_PORT,
};

const LAB_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Evidence for two peers behind one NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SameNatReport {
    /// The server host socket.
    pub server_local: SocketAddr,
    /// The server reflexive socket.
    pub server_reflexive: SocketAddr,
    /// The client host socket.
    pub client_local: SocketAddr,
    /// The client reflexive socket.
    pub client_reflexive: SocketAddr,
    /// Hole-punch datagrams the server sent.
    pub server_packets_sent: u32,
    /// Hole-punch datagrams the server received.
    pub server_packets_received: u32,
    /// Hole-punch datagrams the client sent.
    pub client_packets_sent: u32,
    /// Hole-punch datagrams the client received.
    pub client_packets_received: u32,
    /// The UDP port of the QUIC server.
    pub quic_port: u16,
    /// The ADR 0003 policy port.
    pub policy_port: u16,
    /// The server Direct flag.
    pub server_direct_is_up: bool,
    /// The client Direct flag.
    pub client_direct_is_up: bool,
    /// The server path id.
    pub server_path_id: PathId,
    /// The client path id.
    pub client_path_id: PathId,
    /// The server Direct elapsed time.
    pub server_elapsed: Duration,
    /// The client Direct elapsed time.
    pub client_elapsed: Duration,
    /// The QUIC probe echoed on both peers.
    pub echo_ok: bool,
}

impl SameNatReport {
    /// Return the lab lines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let elapsed = self.server_elapsed.max(self.client_elapsed);
        vec![
            format!("same-nat {}", self.same_nat()),
            format!("server local {}", self.server_local),
            format!("server reflexive {}", self.server_reflexive),
            format!("client local {}", self.client_local),
            format!("client reflexive {}", self.client_reflexive),
            format!("server punch packets {}", self.server_packets_sent),
            format!("server punch received {}", self.server_packets_received),
            format!("client punch packets {}", self.client_packets_sent),
            format!("client punch received {}", self.client_packets_received),
            format!("policy port {}", self.policy_port),
            format!("quic port {}", self.quic_port),
            format!("server direct_is_up {}", self.server_direct_is_up),
            format!("client direct_is_up {}", self.client_direct_is_up),
            format!("server path_id {}", self.server_path_id.to_hex()),
            format!("client path_id {}", self.client_path_id.to_hex()),
            format!("elapsed_ms {}", as_millis(elapsed)),
            format!("budget_ms {}", as_millis(DIRECT_ATTEMPT_BUDGET)),
            format!("echo ok {}", self.echo_ok),
        ]
    }

    /// Return true when both reflexive addresses share one IP.
    #[must_use]
    pub fn same_nat(&self) -> bool {
        self.server_reflexive.ip() == self.client_reflexive.ip()
            && self.server_reflexive != self.client_reflexive
            && self.server_local != self.server_reflexive
            && self.client_local != self.client_reflexive
    }
}

fn as_millis(duration: Duration) -> u128 {
    duration.as_millis()
}

/// Run Allocate, the hole punch, and QUIC for two peers behind one lab NAT.
///
/// The server bind tries UDP port 443.
/// When that bind is not permitted, the server uses an ephemeral port.
/// The function does not use an external network.
pub fn run_same_nat_direct() -> Result<SameNatReport, EdgeError> {
    let server = match StunClient::bind(localhost(DIRECT_QUIC_PORT)) {
        Ok(client) => client,
        Err(EdgeError::Io(_)) => StunClient::bind(localhost(0))?,
        Err(error) => return Err(error),
    };
    run_same_nat_with_server(server)
}

/// Run the same-NAT lab with an explicit server socket.
pub fn run_same_nat_bound(server_bind: SocketAddr) -> Result<SameNatReport, EdgeError> {
    let server = StunClient::bind(server_bind)?;
    run_same_nat_with_server(server)
}

fn run_same_nat_with_server(server: StunClient) -> Result<SameNatReport, EdgeError> {
    let server_ip = match server.local_addr()? {
        SocketAddr::V4(addr) => *addr.ip(),
        SocketAddr::V6(_) => {
            return Err(EdgeError::Io(
                "The same-NAT lab uses an IPv4 server socket.".to_string(),
            ))
        }
    };
    let client = StunClient::bind(SocketAddr::from((server_ip, 0)))?;
    let material = issue_material()?;
    let token = PunchToken::generate()?;

    let stun = LabStunServer::bind(localhost(0))?;
    let stun_addr = stun.local_addr()?;
    let nat_server = LabUdpNat::bind(localhost(0), stun_addr)?;
    let nat_client = LabUdpNat::bind(localhost(0), stun_addr)?;
    let nat_server_addr = nat_server.local_addr()?;
    let nat_client_addr = nat_client.local_addr()?;

    let stun_thread = thread::spawn(move || stun.serve_many(2, LAB_SETUP_TIMEOUT));
    let nat_server_thread = thread::spawn(move || nat_server.forward_one(LAB_SETUP_TIMEOUT));
    let nat_client_thread = thread::spawn(move || nat_client.forward_one(LAB_SETUP_TIMEOUT));

    let gathered = gather_pair(&server, &client, nat_server_addr, nat_client_addr);
    let stun_outcome = join_lab(stun_thread)?;
    let nat_server_outcome = join_lab(nat_server_thread)?;
    let nat_client_outcome = join_lab(nat_client_thread)?;
    let (server_machine, server_candidate, client_machine, client_candidate) = gathered?;
    stun_outcome?;
    nat_server_outcome?;
    nat_client_outcome?;

    let server_socket = server.into_socket();
    let client_socket = client.into_socket();
    let server_remote = client_candidate;
    let client_remote = server_candidate;
    let server_identity = material.server;
    let client_identity = material.client;

    let server_thread = thread::spawn(move || {
        finish_direct(
            server_machine,
            DirectRequest {
                role: DirectRole::Server,
                remote: server_remote,
                token,
                socket: server_socket,
                identity: server_identity,
                budget: DIRECT_ATTEMPT_BUDGET,
            },
        )
    });
    let client_thread = thread::spawn(move || {
        finish_direct(
            client_machine,
            DirectRequest {
                role: DirectRole::Client,
                remote: client_remote,
                token,
                socket: client_socket,
                identity: client_identity,
                budget: DIRECT_ATTEMPT_BUDGET,
            },
        )
    });

    let server_result = join_lab(server_thread)?;
    let client_result = join_lab(client_thread)?;
    let server_side = server_result?;
    let client_side = client_result?;
    report_from(server_candidate, client_candidate, server_side, client_side)
}

struct DirectSide {
    proof: DirectProof,
    direct_is_up: bool,
}

fn finish_direct(
    mut machine: PathMachine,
    request: DirectRequest,
) -> Result<DirectSide, EdgeError> {
    let proof = machine.establish_direct(request)?;
    let direct_is_up = machine.direct_is_up() && machine.path_id() == Some(proof.path_id);
    Ok(DirectSide {
        proof,
        direct_is_up,
    })
}

fn gather_pair(
    server: &StunClient,
    client: &StunClient,
    nat_server: SocketAddr,
    nat_client: SocketAddr,
) -> Result<
    (
        PathMachine,
        EndpointCandidate,
        PathMachine,
        EndpointCandidate,
    ),
    EdgeError,
> {
    let mut server_machine = PathMachine::start_allocate();
    let mut server_sink = MemoryCandidateSink::default();
    let server_candidate =
        server_machine.gather_reflexive(server, nat_server, LAB_SETUP_TIMEOUT, &mut server_sink)?;
    let mut client_machine = PathMachine::start_allocate();
    let mut client_sink = MemoryCandidateSink::default();
    let client_candidate =
        client_machine.gather_reflexive(client, nat_client, LAB_SETUP_TIMEOUT, &mut client_sink)?;
    Ok((
        server_machine,
        server_candidate,
        client_machine,
        client_candidate,
    ))
}

fn report_from(
    server_candidate: EndpointCandidate,
    client_candidate: EndpointCandidate,
    server_side: DirectSide,
    client_side: DirectSide,
) -> Result<SameNatReport, EdgeError> {
    let server_proof = server_side.proof;
    let client_proof = client_side.proof;
    if server_proof.quic_port != client_proof.quic_port {
        return Err(EdgeError::Quic(
            "The peers do not agree on the QUIC port.".to_string(),
        ));
    }
    let echo_ok = server_proof.echoed == client_proof.echoed && !server_proof.echoed.is_empty();
    Ok(SameNatReport {
        server_local: server_candidate.local,
        server_reflexive: server_candidate.reflexive,
        client_local: client_candidate.local,
        client_reflexive: client_candidate.reflexive,
        server_packets_sent: server_proof.packets_sent,
        server_packets_received: server_proof.packets_received,
        client_packets_sent: client_proof.packets_sent,
        client_packets_received: client_proof.packets_received,
        quic_port: server_proof.quic_port,
        policy_port: DIRECT_QUIC_PORT,
        server_direct_is_up: server_side.direct_is_up,
        client_direct_is_up: client_side.direct_is_up,
        server_path_id: server_proof.path_id,
        client_path_id: client_proof.path_id,
        server_elapsed: server_proof.elapsed,
        client_elapsed: client_proof.elapsed,
        echo_ok,
    })
}

fn issue_material() -> Result<crate::direct::DirectMaterial, EdgeError> {
    issue_direct_pair(SystemTime::now())
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn join_lab<T>(handle: JoinHandle<T>) -> Result<T, EdgeError> {
    handle.join().map_err(|_| EdgeError::LabThread)
}
