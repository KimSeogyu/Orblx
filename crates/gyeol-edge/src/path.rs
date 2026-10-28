use std::net::SocketAddr;
use std::time::Duration;

use crate::{CandidateSink, EdgeError, EndpointCandidate, StunClient, UnsignedCandidateSet};

/// The Direct attempt budget from ADR 0003.
///
/// Week 4 stores the budget.
/// Week 4 does not start the timer.
/// Week 5 uses the budget for the hole punch.
pub const DIRECT_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);

/// The UDP port for a later direct QUIC session.
///
/// Week 4 stores the port.
/// Week 4 does not open the QUIC session.
pub const DIRECT_QUIC_PORT: u16 = 443;

/// The Allocate phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatePhase {
    /// The machine has no reflexive address.
    Gather,
    /// The machine has one unsigned candidate.
    Ready,
}

/// The Direct phase.
///
/// Week 4 has only the stub.
/// Week 5 adds the hole punch.
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
}

/// The path states that Week 4 implements.
///
/// Allocate gathers one reflexive address.
/// Direct records a hole-punch stub.
/// Week 4 does not implement Relay.
/// Week 4 does not implement Stick and upgrade.
/// Week 4 does not implement TCP port 443.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// The Allocate state.
    Allocate {
        /// The Allocate phase.
        phase: AllocatePhase,
        /// The candidate, when the phase is Ready.
        candidate: Option<EndpointCandidate>,
    },
    /// The Direct stub.
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
    /// Week 4 does not complete the hole punch.
    /// The function returns false.
    #[must_use]
    pub fn direct_is_up(&self) -> bool {
        match self.state {
            PathState::Allocate { .. } => false,
            PathState::Direct { phase, .. } => match phase {
                DirectPhase::Stub { .. } => false,
            },
        }
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
    /// Week 5 sends the hole-punch packets.
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
