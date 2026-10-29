use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::io_error;
use crate::{
    DirectPhase, EdgeError, LabStunServer, MemoryCandidateSink, PathMachine, PathState, StunClient,
};

const LAB_SERVER_TIMEOUT: Duration = Duration::from_secs(5);
const LAB_CLIENT_TIMEOUT: Duration = Duration::from_secs(3);

/// A lab UDP forwarder.
///
/// The forwarder sends the client datagram from its own socket.
/// The STUN server sees that socket as the source.
/// This type is not the orblx Relay.
/// This type is not a carrier NAT.
#[derive(Debug)]
pub(crate) struct LabUdpNat {
    socket: UdpSocket,
    upstream: SocketAddr,
}

impl LabUdpNat {
    pub(crate) fn bind(local: SocketAddr, upstream: SocketAddr) -> Result<Self, EdgeError> {
        let socket = UdpSocket::bind(local).map_err(io_error)?;
        Ok(Self { socket, upstream })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, EdgeError> {
        self.socket.local_addr().map_err(io_error)
    }

    /// Forward one request to the STUN server.
    /// Forward one response to the client.
    pub(crate) fn forward_one(&self, timeout: Duration) -> Result<(), EdgeError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(io_error)?;
        let mut buf = [0u8; 2048];
        let (size, client) = recv(&self.socket, &mut buf)?;
        self.socket
            .send_to(&buf[..size], self.upstream)
            .map_err(io_error)?;
        let (size, from) = recv(&self.socket, &mut buf)?;
        if from != self.upstream {
            return Err(EdgeError::Io(
                "The lab NAT received a datagram from an unexpected socket.".to_string(),
            ));
        }
        self.socket
            .send_to(&buf[..size], client)
            .map_err(io_error)?;
        Ok(())
    }
}

fn recv(socket: &UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr), EdgeError> {
    loop {
        match socket.recv_from(buf) {
            Ok(packet) => return Ok(packet),
            Err(err) if is_timeout(&err) => return Err(EdgeError::Timeout),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(io_error(err)),
        }
    }
}

fn is_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

/// The result of the in-process lab smoke.
///
/// The smoke uses a local STUN server and a userspace UDP NAT.
/// The reflexive address is the NAT socket.
/// The Direct state is the stub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeReport {
    /// The lab STUN server socket.
    pub stun: SocketAddr,
    /// The lab NAT socket.
    pub nat: SocketAddr,
    /// The client bind socket.
    pub local: SocketAddr,
    /// The server-reflexive socket.
    pub reflexive: SocketAddr,
    /// The state after Allocate.
    pub after_allocate: PathState,
    /// The state after the Direct stub.
    pub after_direct: PathState,
    /// Week 4 leaves this flag false.
    pub direct_is_up: bool,
    /// The sink stored the unsigned candidate.
    pub stored_candidate: bool,
}

impl SmokeReport {
    /// Return the smoke lines.
    ///
    /// Each line states one observed fact.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("lab stun {}", self.stun),
            format!("lab nat {}", self.nat),
            format!("local {}", self.local),
            format!("reflexive {}", self.reflexive),
            format!("allocate {}", self.after_allocate),
            format!("direct {}", self.after_direct),
            format!("hole-punch complete {}", self.direct_is_up),
            format!("candidate stored {}", self.stored_candidate),
        ];
        if let PathState::Direct {
            phase: DirectPhase::Stub { budget, quic_port },
            ..
        } = self.after_direct
        {
            lines.push(format!("direct budget {}s", budget.as_secs()));
            lines.push(format!("direct quic port {quic_port}"));
        }
        lines
    }
}

/// Run the Allocate step through a lab STUN server and a userspace NAT.
///
/// The function then enters the Direct stub.
/// The function does not send hole-punch packets.
/// The function does not use an external network.
pub fn run_edge_smoke() -> Result<SmokeReport, EdgeError> {
    let server = LabStunServer::bind(localhost())?;
    let stun = server.local_addr()?;
    let nat = LabUdpNat::bind(localhost(), stun)?;
    let nat_addr = nat.local_addr()?;
    let server_thread = thread::spawn(move || server.serve_one(LAB_SERVER_TIMEOUT));
    let nat_thread = thread::spawn(move || nat.forward_one(LAB_SERVER_TIMEOUT));

    let outcome = smoke_client(stun, nat_addr);
    let server_outcome = join_lab(server_thread)?;
    let nat_outcome = join_lab(nat_thread)?;
    let report = outcome?;
    server_outcome?;
    nat_outcome?;
    Ok(report)
}

fn smoke_client(stun: SocketAddr, nat_addr: SocketAddr) -> Result<SmokeReport, EdgeError> {
    let client = StunClient::bind(localhost())?;
    let mut machine = PathMachine::start_allocate();
    let mut sink = MemoryCandidateSink::default();
    let candidate = machine.gather_reflexive(&client, nat_addr, LAB_CLIENT_TIMEOUT, &mut sink)?;
    let after_allocate = machine.state();
    machine.begin_direct_stub()?;
    Ok(SmokeReport {
        stun,
        nat: nat_addr,
        local: candidate.local,
        reflexive: candidate.reflexive,
        after_allocate,
        after_direct: machine.state(),
        direct_is_up: machine.direct_is_up(),
        stored_candidate: sink.stored.is_some(),
    })
}

fn localhost() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn join_lab<T>(handle: JoinHandle<T>) -> Result<T, EdgeError> {
    handle.join().map_err(|_| EdgeError::LabThread)
}

#[cfg(test)]
mod tests {
    use super::run_edge_smoke;
    use crate::{AllocatePhase, DirectPhase, PathState, DIRECT_ATTEMPT_BUDGET, DIRECT_QUIC_PORT};

    #[test]
    fn smoke_reflexive_address_is_the_nat_socket() {
        let report = run_edge_smoke().unwrap();
        assert_eq!(report.reflexive, report.nat);
        assert_ne!(report.local, report.reflexive);
        assert!(matches!(
            report.after_allocate,
            PathState::Allocate {
                phase: AllocatePhase::Ready,
                candidate: Some(candidate),
            } if candidate.local == report.local && candidate.reflexive == report.reflexive
        ));
        assert!(matches!(
            report.after_direct,
            PathState::Direct {
                phase: DirectPhase::Stub { budget, quic_port },
                ..
            } if budget == DIRECT_ATTEMPT_BUDGET && quic_port == DIRECT_QUIC_PORT
        ));
        assert!(!report.direct_is_up);
        assert!(report.stored_candidate);
        let text = report.lines().join("\n");
        assert!(text.contains("hole-punch complete false"));
        assert!(text.contains("Direct Stub"));
    }
}
