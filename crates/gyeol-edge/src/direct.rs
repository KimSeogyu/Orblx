use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gyeol_crypto::{mac_input, ticket_mac, TicketKey, TicketRing};
use gyeol_datapath::{ipv4_packet, prove_hello_socket, HelloConfig, HelloError, HelloSocketRole};
use gyeol_identity::{
    sign_ticket, DenySet, MiniCa, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
    TicketVerifier, TrustBundle,
};

use crate::error::io_error;
use crate::punch::{exchange, punch_plan, PunchCounts, PunchToken};
use crate::{DirectPhase, EdgeError, EndpointCandidate, PathId, PathMachine, PathState};

const PROOF_PAYLOAD: &[u8] = b"direct";
const TICKET_LIFETIME: Duration = Duration::from_secs(600);
const TICKET_KEY_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

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
/// The ticket bytes are an identity version-1 capability ticket.
/// The HMAC tag comes from `gyeol_crypto::ticket_mac`.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectIdentity {
    /// PEM certificate for this peer.
    pub certificate_pem: String,
    /// PEM private key for this peer.
    pub private_key_pem: String,
    /// PEM trust bundle.
    pub trust_pem: String,
    /// Identity version-1 ticket bytes for this peer.
    pub ticket_bytes: Vec<u8>,
    /// HMAC-SHA256 tag over `ticket_bytes`.
    pub ticket_mac: [u8; 32],
    /// PEM public key for the ticket signer.
    pub ticket_verifier_pem: String,
    /// HMAC key for the ticket tag.
    pub ticket_mac_key: [u8; 32],
    /// Start of the ticket key window.
    pub ticket_not_before: SystemTime,
    /// End of the ticket key window.
    pub ticket_not_after: SystemTime,
    /// Raw Ed25519 public key of the SVID CA.
    pub svid_ca_public: [u8; 32],
}

/// Issued leaves for one server and one client.
pub struct DirectMaterial {
    /// The QUIC server leaf and ticket.
    pub server: DirectIdentity,
    /// The QUIC client leaf and ticket.
    pub client: DirectIdentity,
}

/// Issue one mini-CA pair for the Direct lab.
///
/// Each peer gets one capability ticket.
/// The ticket subject is that peer.
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
    let signer = TicketSigner::generate();
    if signer.public_key() == *ca.public_key() {
        return Err(EdgeError::Identity(
            "The ticket key matches the SVID CA key.".to_string(),
        ));
    }
    let mac_key = random_mac_key()?;
    let not_before = now;
    let not_after = now + TICKET_KEY_LIFETIME;
    let trust_pem = ca.certificate_pem().to_string();
    let ca_public = *ca.public_key();
    let key = TicketKeyMaterial {
        signer: &signer,
        mac_key: &mac_key,
        not_before,
        not_after,
        svid_ca_public: ca_public,
    };
    let server_identity = identity_for(
        server.certificate_pem,
        server.private_key_pem,
        trust_pem.clone(),
        &key,
        &server_id,
        now,
    )?;
    let client_identity = identity_for(
        client.certificate_pem,
        client.private_key_pem,
        trust_pem,
        &key,
        &client_id,
        now,
    )?;
    Ok(DirectMaterial {
        server: server_identity,
        client: client_identity,
    })
}

impl DirectIdentity {
    /// Build material that cannot pass the ticket check.
    ///
    /// The punch budget test uses this value.
    /// QUIC does not start.
    #[must_use]
    pub fn blank() -> Self {
        Self {
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            trust_pem: String::new(),
            ticket_bytes: Vec::new(),
            ticket_mac: [0; 32],
            ticket_verifier_pem: String::new(),
            ticket_mac_key: [0; 32],
            ticket_not_before: UNIX_EPOCH,
            ticket_not_after: UNIX_EPOCH,
            svid_ca_public: [0xff; 32],
        }
    }

    pub(crate) fn to_hello(&self) -> Result<HelloConfig, EdgeError> {
        let trust = TrustBundle::from_pem(&self.trust_pem).map_err(identity_error)?;
        let verifier =
            TicketVerifier::from_public_pem(&self.ticket_verifier_pem).map_err(identity_error)?;
        let key = TicketKey::new(
            verifier,
            self.ticket_mac_key,
            self.ticket_not_before,
            self.ticket_not_after,
        )
        .map_err(|err| EdgeError::Identity(err.to_string()))?;
        let ring = TicketRing::single(key, &self.svid_ca_public)
            .map_err(|err| EdgeError::Identity(err.to_string()))?;
        Ok(HelloConfig {
            certificate_pem: self.certificate_pem.clone(),
            private_key_pem: self.private_key_pem.clone(),
            trust,
            ticket_bytes: self.ticket_bytes.clone(),
            ticket_mac: self.ticket_mac,
            ticket_ring: ring,
            deny: DenySet::empty(),
        })
    }
}

struct TicketKeyMaterial<'a> {
    signer: &'a TicketSigner,
    mac_key: &'a [u8; 32],
    not_before: SystemTime,
    not_after: SystemTime,
    svid_ca_public: [u8; 32],
}

fn identity_for(
    certificate_pem: String,
    private_key_pem: String,
    trust_pem: String,
    key: &TicketKeyMaterial<'_>,
    subject: &SpiffeId,
    now: SystemTime,
) -> Result<DirectIdentity, EdgeError> {
    let now_unix = unix_secs(now)?;
    let claims = TicketClaims {
        issuer: SpiffeId::coord("1").map_err(identity_error)?,
        subject: subject.clone(),
        not_before: now_unix,
        expires: now_unix + TICKET_LIFETIME.as_secs(),
        dst_cidr: "10.8.0.0/24".to_string(),
        proto: 6,
        dst_port: 443,
        flags: TicketFlags::none(),
    };
    let signed = sign_ticket(key.signer, &claims).map_err(identity_error)?;
    let mac = ticket_mac(key.mac_key, mac_input(&signed.bytes))
        .map_err(|err| EdgeError::Identity(err.to_string()))?;
    Ok(DirectIdentity {
        certificate_pem,
        private_key_pem,
        trust_pem,
        ticket_bytes: signed.bytes,
        ticket_mac: mac,
        ticket_verifier_pem: key.signer.public_key_pem(),
        ticket_mac_key: *key.mac_key,
        ticket_not_before: key.not_before,
        ticket_not_after: key.not_after,
        svid_ca_public: key.svid_ca_public,
    })
}

fn unix_secs(now: SystemTime) -> Result<u64, EdgeError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| EdgeError::Identity("The time value is not valid.".to_string()))
}

fn random_mac_key() -> Result<[u8; 32], EdgeError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|err| EdgeError::Io(err.to_string()))?;
    Ok(bytes)
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
