use std::net::SocketAddr;
use std::time::Duration;

use crate::{CandidateSink, EdgeError, EndpointCandidate, StunClient, UnsignedCandidateSet};

/// The Direct attempt budget from ADR 0003.
///
/// The timer starts in `establish_direct`.
/// The attempt fails when the budget elapses.
pub const DIRECT_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);

/// The UDP port for a direct QUIC session.
///
/// The policy port is 443.
/// A lab that cannot bind port 443 uses another server port.
/// The netns lab binds this port.
pub const DIRECT_QUIC_PORT: u16 = 443;

/// The Allocate phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatePhase {
    /// The machine has no reflexive address.
    Gather,
    /// The machine has one unsigned candidate.
    Ready,
}

/// Opaque path identifier allocated by N-Edge.
///
/// D-Path does not parse these bytes.
/// D-Path owns send and recv on the active path_id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId([u8; 16]);

impl PathId {
    /// Allocate 16 random bytes.
    pub fn allocate() -> Result<Self, crate::EdgeError> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|err| crate::EdgeError::Io(err.to_string()))?;
        Ok(Self(bytes))
    }

    /// Return the opaque bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Return the bytes as lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl std::fmt::Debug for PathId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PathId({})", self.to_hex())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// The Direct phase.
///
/// `Stub` records the budget and does not send a packet.
/// `Punching` is the hole-punch attempt.
/// `Up` means the hole punch and the QUIC proof succeeded.
/// `Failed` means the attempt stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPhase {
    /// The attempt is recorded.
    /// No hole-punch packet was sent.
    Stub {
        /// The later failure budget.
        budget: Duration,
        /// The later QUIC UDP port.
        quic_port: u16,
    },
    /// The peers are sending hole-punch packets.
    Punching {
        /// The failure budget.
        budget: Duration,
        /// The QUIC server UDP port for this attempt.
        quic_port: u16,
    },
    /// The hole punch and the QUIC proof succeeded.
    Up {
        /// The failure budget.
        budget: Duration,
        /// The QUIC server UDP port.
        quic_port: u16,
        /// Hole-punch datagrams this peer sent.
        packets_sent: u32,
        /// Hole-punch datagrams this peer received.
        packets_received: u32,
        /// The opaque path id.
        path_id: PathId,
    },
    /// The Direct attempt stopped before QUIC was up.
    Failed {
        /// The failure budget.
        budget: Duration,
        /// The QUIC server UDP port for this attempt.
        quic_port: u16,
        /// Hole-punch datagrams this peer sent.
        packets_sent: u32,
        /// Hole-punch datagrams this peer received.
        packets_received: u32,
    },
}

/// The path states that this crate implements.
///
/// Allocate gathers one reflexive address.
/// Direct punches and then proves QUIC.
/// This crate does not implement Relay.
/// This crate does not implement Stick and upgrade.
/// This crate does not implement TCP port 443.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// The Allocate state.
    Allocate {
        /// The Allocate phase.
        phase: AllocatePhase,
        /// The candidate, when the phase is Ready.
        candidate: Option<EndpointCandidate>,
    },
    /// The Direct state.
    Direct {
        /// The Direct phase.
        phase: DirectPhase,
        /// The candidate from Allocate.
        candidate: EndpointCandidate,
    },
}

impl std::fmt::Display for PathState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allocate { phase, .. } => write!(formatter, "Allocate {phase}"),
            Self::Direct { phase, .. } => write!(formatter, "Direct {phase}"),
        }
    }
}

impl std::fmt::Display for AllocatePhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gather => formatter.write_str("Gather"),
            Self::Ready => formatter.write_str("Ready"),
        }
    }
}

impl std::fmt::Display for DirectPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stub { .. } => formatter.write_str("Stub"),
            Self::Punching { .. } => formatter.write_str("Punch"),
            Self::Up { .. } => formatter.write_str("Up"),
            Self::Failed { .. } => formatter.write_str("Failed"),
        }
    }
}

/// The Allocate to Direct stub.
///
/// The machine starts in Allocate Gather.
/// `gather_reflexive` stores one unsigned candidate and enters Allocate Ready.
/// `begin_direct_stub` enters Direct Stub.
/// The machine does not send hole-punch packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMachine {
    state: PathState,
}

impl PathMachine {
    /// Start in Allocate Gather.
    #[must_use]
    pub fn start_allocate() -> Self {
        Self {
            state: PathState::Allocate {
                phase: AllocatePhase::Gather,
                candidate: None,
            },
        }
    }

    /// Return the current state.
    #[must_use]
    pub fn state(&self) -> PathState {
        self.state
    }

    /// Return the candidate when Allocate or Direct has one.
    #[must_use]
    pub fn candidate(&self) -> Option<EndpointCandidate> {
        match self.state {
            PathState::Allocate { candidate, .. } => candidate,
            PathState::Direct { candidate, .. } => Some(candidate),
        }
    }

    /// Report whether Direct has a QUIC path.
    ///
    /// The function returns true only after the hole punch and the QUIC proof.
    #[must_use]
    pub fn direct_is_up(&self) -> bool {
        match self.state {
            PathState::Allocate { .. } => false,
            PathState::Direct { phase, .. } => match phase {
                DirectPhase::Stub { .. }
                | DirectPhase::Punching { .. }
                | DirectPhase::Failed { .. } => false,
                DirectPhase::Up { .. } => true,
            },
        }
    }

    /// Return the opaque path id when Direct is up.
    #[must_use]
    pub fn path_id(&self) -> Option<PathId> {
        match self.state {
            PathState::Direct {
                phase: DirectPhase::Up { path_id, .. },
                ..
            } => Some(path_id),
            PathState::Allocate { .. } => None,
            PathState::Direct {
                phase:
                    DirectPhase::Stub { .. } | DirectPhase::Punching { .. } | DirectPhase::Failed { .. },
                ..
            } => None,
        }
    }

    pub(crate) fn ready_candidate(&self) -> Result<EndpointCandidate, EdgeError> {
        match self.state {
            PathState::Allocate {
                phase: AllocatePhase::Ready,
                candidate: Some(candidate),
            } => Ok(candidate),
            PathState::Allocate { .. } | PathState::Direct { .. } => Err(EdgeError::WrongState),
        }
    }

    pub(crate) fn move_to(&mut self, state: PathState) {
        self.state = state;
    }

    /// Gather one reflexive address and store an unsigned candidate.
    ///
    /// The function sends one STUN Binding request.
    /// The function moves the phase to Ready.
    /// The function does not sign the candidate.
    /// The sink failure leaves the phase at Gather.
    pub fn gather_reflexive<S: CandidateSink>(
        &mut self,
        client: &StunClient,
        server: SocketAddr,
        timeout: Duration,
        sink: &mut S,
    ) -> Result<EndpointCandidate, EdgeError> {
        match self.state {
            PathState::Allocate {
                phase: AllocatePhase::Gather,
                candidate: None,
            } => {}
            PathState::Allocate { .. } | PathState::Direct { .. } => {
                return Err(EdgeError::WrongState);
            }
        }
        let reflexive = client.gather(server, timeout)?;
        let local = client.local_addr()?;
        let candidate = EndpointCandidate { local, reflexive };
        let set = UnsignedCandidateSet { candidate };
        sink.store_unsigned(&set)?;
        self.state = PathState::Allocate {
            phase: AllocatePhase::Ready,
            candidate: Some(candidate),
        };
        Ok(candidate)
    }

    /// Move from Allocate Ready to the Direct stub.
    ///
    /// The function does not send a packet.
    /// The function does not open a QUIC session.
    /// `establish_direct` sends the hole-punch packets.
    pub fn begin_direct_stub(&mut self) -> Result<(), EdgeError> {
        let candidate = match self.state {
            PathState::Allocate {
                phase: AllocatePhase::Ready,
                candidate: Some(candidate),
            } => candidate,
            PathState::Allocate { .. } | PathState::Direct { .. } => {
                return Err(EdgeError::WrongState);
            }
        };
        self.state = PathState::Direct {
            phase: DirectPhase::Stub {
                budget: DIRECT_ATTEMPT_BUDGET,
                quic_port: DIRECT_QUIC_PORT,
            },
            candidate,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::thread;
    use std::time::Duration;

    use super::{
        AllocatePhase, DirectPhase, PathMachine, PathState, DIRECT_ATTEMPT_BUDGET, DIRECT_QUIC_PORT,
    };
    use crate::{
        CandidateSink, EdgeError, LabStunServer, MemoryCandidateSink, StunClient,
        UnsignedCandidateSet,
    };

    struct RejectSink;

    impl CandidateSink for RejectSink {
        fn store_unsigned(&mut self, _set: &UnsignedCandidateSet) -> Result<(), EdgeError> {
            Err(EdgeError::CandidateRejected)
        }
    }

    #[test]
    fn direct_stub_requires_a_reflexive_address() {
        let mut machine = PathMachine::start_allocate();
        assert_eq!(machine.state().to_string(), "Allocate Gather");
        assert_eq!(machine.begin_direct_stub(), Err(EdgeError::WrongState));
        assert!(!machine.direct_is_up());
        assert!(machine.candidate().is_none());
    }

    #[test]
    fn allocate_ready_enters_the_direct_stub() {
        let server = LabStunServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve_one(Duration::from_secs(3)));
        let client = StunClient::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut machine = PathMachine::start_allocate();
        let mut sink = MemoryCandidateSink::default();
        let candidate = machine
            .gather_reflexive(&client, server_addr, Duration::from_secs(2), &mut sink)
            .unwrap();
        handle.join().unwrap().unwrap();
        assert_eq!(candidate.reflexive, candidate.local);
        assert_eq!(sink.stored.unwrap().candidate, candidate);
        assert!(matches!(
            machine.state(),
            PathState::Allocate {
                phase: AllocatePhase::Ready,
                candidate: Some(stored),
            } if stored == candidate
        ));
        machine.begin_direct_stub().unwrap();
        assert!(matches!(
            machine.state(),
            PathState::Direct {
                phase: DirectPhase::Stub { budget, quic_port },
                candidate: stored,
            } if budget == DIRECT_ATTEMPT_BUDGET
                && quic_port == DIRECT_QUIC_PORT
                && stored == candidate
        ));
        assert!(!machine.direct_is_up());
        assert_eq!(machine.state().to_string(), "Direct Stub");
        assert_eq!(machine.begin_direct_stub(), Err(EdgeError::WrongState));
        assert_eq!(
            machine.gather_reflexive(&client, server_addr, Duration::from_secs(1), &mut sink),
            Err(EdgeError::WrongState)
        );
    }

    #[test]
    fn sink_rejection_keeps_allocate_gather() {
        let server = LabStunServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve_one(Duration::from_secs(3)));
        let client = StunClient::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let mut machine = PathMachine::start_allocate();
        let mut sink = RejectSink;
        let err = machine
            .gather_reflexive(&client, server_addr, Duration::from_secs(2), &mut sink)
            .unwrap_err();
        handle.join().unwrap().unwrap();
        assert_eq!(err, EdgeError::CandidateRejected);
        assert!(matches!(
            machine.state(),
            PathState::Allocate {
                phase: AllocatePhase::Gather,
                candidate: None,
            }
        ));
    }
}
