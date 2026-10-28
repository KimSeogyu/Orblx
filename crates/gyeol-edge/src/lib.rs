//! Own STUN and the Allocate to Direct path stub.
//!
//! The client sends a Binding request.
//! The client reads a Binding success response.
//! Allocate stores the reflexive address.
//! The candidate set is unsigned.
//! ADR 0003 does not name the owner of the Coordinator blob.
//! Direct records a hole-punch stub.
//! Week 5 completes the hole punch.
//! This crate does not implement Relay.
//! This crate does not implement Stick and upgrade.

mod candidate;
mod error;
mod lab;
mod path;
mod stun;

pub use candidate::{CandidateSink, EndpointCandidate, MemoryCandidateSink, UnsignedCandidateSet};
pub use error::EdgeError;
pub use lab::{run_edge_smoke, SmokeReport};
pub use path::{
    AllocatePhase, DirectPhase, PathMachine, PathState, DIRECT_ATTEMPT_BUDGET, DIRECT_QUIC_PORT,
};
pub use stun::{LabStunServer, StunClient};

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "gyeol-edge"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "gyeol-edge");
    }
}
