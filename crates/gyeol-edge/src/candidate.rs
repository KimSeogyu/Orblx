use std::net::SocketAddr;

use crate::EdgeError;

/// One local endpoint after STUN.
///
/// `local` is the socket the client bound.
/// `reflexive` is the server-reflexive socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointCandidate {
    /// The socket the client bound.
    pub local: SocketAddr,
    /// The server-reflexive socket.
    pub reflexive: SocketAddr,
}

/// An unsigned candidate set for a later Coordinator exchange.
///
/// ADR 0003 leaves the freeze, sign, and verify owner open.
/// This type does not sign the bytes.
/// This type does not verify the bytes.
/// This type does not choose the Coordinator owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedCandidateSet {
    /// The local candidate.
    pub candidate: EndpointCandidate,
}

/// A sink for an unsigned candidate set.
///
/// The sink does not freeze a Coordinator blob.
pub trait CandidateSink {
    /// Store one unsigned candidate set.
    ///
    /// The function does not sign the set.
    fn store_unsigned(&mut self, set: &UnsignedCandidateSet) -> Result<(), EdgeError>;
}

/// An in-memory sink for tests and the lab smoke.
///
/// The sink stores the set.
/// The sink does not sign the set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryCandidateSink {
    /// The last stored set.
    pub stored: Option<UnsignedCandidateSet>,
}

impl CandidateSink for MemoryCandidateSink {
    fn store_unsigned(&mut self, set: &UnsignedCandidateSet) -> Result<(), EdgeError> {
        self.stored = Some(*set);
        Ok(())
    }
}
