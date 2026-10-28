use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use gyeol_datapath::{ipv4_packet, prove_hello_socket, HelloConfig, HelloError, HelloSocketRole};
use gyeol_identity::{ticket_hash, DenySet, MiniCa, SpiffeId, TrustBundle};

use crate::error::io_error;
use crate::punch::{exchange, punch_plan, PunchCounts, PunchToken};
use crate::{DirectPhase, EdgeError, EndpointCandidate, PathId, PathMachine, PathState};

/// Ticket bytes for the lab hello-quic proof.
///
/// The hash of these bytes is the frame `ticket_hash`.
/// The bytes are not a signed capability ticket.
pub const LAB_TICKET_BYTES: &[u8] = b"gyeol-w5-direct";

const PROOF_PAYLOAD: &[u8] = b"direct";

/// The QUIC role for one Direct attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRole {
    /// Accept QUIC on the punched socket.
    Server,
    /// Connect QUIC to the nominated peer.
    Client,
}

/// Leaf material for the lab QUIC proof.
///
/// C-Key owns the handshake and AEAD.
/// This material follows the hello-quic leaf check.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectIdentity {
    /// PEM certificate for this peer.
    pub certificate_pem: String,
    /// PEM private key for this peer.
    pub private_key_pem: String,
    /// PEM trust bundle.
    pub trust_pem: String,
    /// Frame ticket hash.
    pub ticket_hash: [u8; 16],
}

/// Issued leaves for one server and one client.
pub struct DirectMaterial {
    /// The QUIC server leaf.
    pub server: DirectIdentity,
    /// The QUIC client leaf.
    pub client: DirectIdentity,
    /// The bytes whose hash is `ticket_hash`.
    pub ticket_bytes: Vec<u8>,
}

/// Issue one mini-CA pair for the Direct lab.
///
/// The function does not contact an OIDC provider.
pub fn issue_direct_pair(now: SystemTime) -> Result<DirectMaterial, EdgeError> {
    let ca = MiniCa::generate(now).map_err(identity_error)?;
    let deny = DenySet::empty();
    let ttl = Duration::from_secs(300);
    let server_id = SpiffeId::user("w5-server").map_err(identity_error)?;
    let client_id = SpiffeId::user("w5-client").map_err(identity_error)?;
    let server = ca
        .issue(&server_id, now, ttl, &deny)
        .map_err(identity_error)?;
    let client = ca
        .issue(&client_id, now, ttl, &deny)
        .map_err(identity_error)?;
    let hash = ticket_hash(LAB_TICKET_BYTES);
    let trust_pem = ca.certificate_pem().to_string();
    Ok(DirectMaterial {
        server: DirectIdentity {
            certificate_pem: server.certificate_pem,
            private_key_pem: server.private_key_pem,
            trust_pem: trust_pem.clone(),
            ticket_hash: hash,
        },
        client: DirectIdentity {
            certificate_pem: client.certificate_pem,
            private_key_pem: client.private_key_pem,
            trust_pem,
            ticket_hash: hash,
        },
        ticket_bytes: LAB_TICKET_BYTES.to_vec(),
    })
}

impl DirectIdentity {
    fn to_hello(&self) -> Result<HelloConfig, EdgeError> {
        let trust = TrustBundle::from_pem(&self.trust_pem).map_err(identity_error)?;
        Ok(HelloConfig {
            certificate_pem: self.certificate_pem.clone(),
            private_key_pem: self.private_key_pem.clone(),
            trust,
            ticket_hash: self.ticket_hash,
            deny: DenySet::empty(),
        })
    }
}

/// Inputs for one Direct attempt.
pub struct DirectRequest {
    /// Server or client.
    pub role: DirectRole,
    /// The remote unsigned candidate.
    pub remote: EndpointCandidate,
    /// The shared punch token.
    pub token: PunchToken,
    /// The Allocate socket.
    pub socket: UdpSocket,
    /// The leaf for this peer.
    pub identity: DirectIdentity,
    /// The Direct budget.
    ///
    /// Use `DIRECT_ATTEMPT_BUDGET` for the ADR 0003 limit.
    pub budget: Duration,
}

/// Evidence from one successful Direct attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectProof {
    /// Hole-punch datagrams this peer sent.
    pub packets_sent: u32,
    /// Hole-punch datagrams this peer received.
    pub packets_received: u32,
    /// The QUIC server UDP port.
    pub quic_port: u16,
    /// The opaque path id.
    pub path_id: PathId,
    /// The nominated peer socket.
    pub peer: SocketAddr,
    /// The time from the start of Direct to QUIC up.
    pub elapsed: Duration,
    /// The echoed IPv4 probe.
    pub echoed: Vec<u8>,
}

impl PathMachine {
    /// Punch, then prove QUIC on the same UDP socket.
    ///
    /// The machine must be in Allocate Ready.
    /// The socket must be the Allocate socket.
    /// The function sends hole-punch datagrams.
    /// The function does not use Relay.
    /// The candidate stays unsigned.
    pub fn establish_direct(&mut self, request: DirectRequest) -> Result<DirectProof, EdgeError> {
        let local_candidate = self.ready_candidate()?;
        let bound = request.socket.local_addr().map_err(io_error)?;
        if bound != local_candidate.local {
            return Err(EdgeError::SocketMismatch);
        }
        let (preferred, targets) = punch_plan(local_candidate, request.remote);
        let quic_port = match request.role {
            DirectRole::Server => bound.port(),
            DirectRole::Client => preferred.port(),
        };
        self.move_to(PathState::Direct {
            phase: DirectPhase::Punching {
                budget: request.budget,
                quic_port,
            },
            candidate: local_candidate,
        });

        let started = Instant::now();
        let deadline = started + request.budget;
        let socket = request.socket;
        let punched = match exchange(&socket, &targets, preferred, request.token, deadline) {
            Ok(outcome) => outcome,
            Err(failure) => {
                self.mark_failed(local_candidate, request.budget, quic_port, failure.counts);
                return Err(failure.error);
            }
        };

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            self.mark_failed(local_candidate, request.budget, quic_port, punched.counts);
            return Err(EdgeError::DirectBudget);
        }

        let quic_port = match request.role {
            DirectRole::Server => quic_port,
            DirectRole::Client => punched.peer.port(),
        };
        let echoed = match prove_quic(
            request.role,
            &request.identity,
            socket,
            punched.peer,
            remaining,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.mark_failed(local_candidate, request.budget, quic_port, punched.counts);
                return Err(error);
            }
        };
        let elapsed = started.elapsed();
        if elapsed > request.budget {
            self.mark_failed(local_candidate, request.budget, quic_port, punched.counts);
            return Err(EdgeError::DirectBudget);
        }

        let path_id = PathId::allocate()?;
        self.move_to(PathState::Direct {
            phase: DirectPhase::Up {
                budget: request.budget,
                quic_port,
                packets_sent: punched.counts.packets_sent,
                packets_received: punched.counts.packets_received,
                path_id,
            },
            candidate: local_candidate,
        });
        Ok(DirectProof {
            packets_sent: punched.counts.packets_sent,
            packets_received: punched.counts.packets_received,
            quic_port,
            path_id,
            peer: punched.peer,
            elapsed,
            echoed,
        })
    }

    fn mark_failed(
        &mut self,
        candidate: EndpointCandidate,
        budget: Duration,
        quic_port: u16,
        counts: PunchCounts,
    ) {
        self.move_to(PathState::Direct {
            phase: DirectPhase::Failed {
                budget,
                quic_port,
                packets_sent: counts.packets_sent,
                packets_received: counts.packets_received,
            },
            candidate,
        });
    }
}

fn prove_quic(
    role: DirectRole,
    identity: &DirectIdentity,
    socket: UdpSocket,
    peer: SocketAddr,
    timeout: Duration,
) -> Result<Vec<u8>, EdgeError> {
    let config = identity.to_hello()?;
    let packet = proof_packet()?;
    let socket_role = match role {
        DirectRole::Server => HelloSocketRole::Server,
        DirectRole::Client => HelloSocketRole::Client { peer },
    };
    let echoed =
        prove_hello_socket(config, socket, socket_role, &packet, timeout).map_err(map_hello)?;
    if echoed != packet {
        return Err(EdgeError::EchoMismatch);
    }
    Ok(echoed)
}

fn identity_error(err: impl std::fmt::Display) -> EdgeError {
    EdgeError::Identity(err.to_string())
}

fn proof_packet() -> Result<Vec<u8>, EdgeError> {
    ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(10, 8, 0, 2),
        PROOF_PAYLOAD,
    )
    .map_err(|err| EdgeError::Quic(err.to_string()))
}

fn map_hello(err: HelloError) -> EdgeError {
    let text = err.to_string();
    if text.contains("timed out") {
        EdgeError::DirectBudget
    } else {
        EdgeError::Quic(text)
    }
}
