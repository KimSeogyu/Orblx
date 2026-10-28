//! Own STUN and the Allocate to Direct path.
//!
//! The client sends a Binding request.
//! The client reads a Binding success response.
//! Allocate stores the reflexive address.
//! The candidate set is unsigned.
//! ADR 0003 does not name the owner of the Coordinator blob.
//! Direct sends hole-punch datagrams.
//! Direct then proves QUIC on the same UDP socket.
//! The Direct attempt uses the 3 second budget.
//! This crate does not implement Relay.
//! This crate does not implement Stick and upgrade.

mod candidate;
mod direct;
mod error;
mod lab;
mod path;
mod punch;
mod same_nat;
mod stun;

pub use candidate::{
    decode_candidate, encode_candidate, CandidateSink, EndpointCandidate, MemoryCandidateSink,
    UnsignedCandidateSet,
};
pub use direct::{
    issue_direct_pair, DirectIdentity, DirectMaterial, DirectProof, DirectRequest, DirectRole,
    LAB_TICKET_BYTES,
};
pub use error::EdgeError;
pub use lab::{run_edge_smoke, SmokeReport};
pub use path::{
    AllocatePhase, DirectPhase, PathId, PathMachine, PathState, DIRECT_ATTEMPT_BUDGET,
    DIRECT_QUIC_PORT,
};
pub use punch::PunchToken;
pub use same_nat::{run_same_nat_bound, run_same_nat_direct, SameNatReport};
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
