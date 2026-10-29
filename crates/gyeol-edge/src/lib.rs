//! Own STUN, the Allocate to Direct path, and the gyeol Relay path.
//!
//! The client sends a Binding request.
//! The client reads a Binding success response.
//! Allocate stores the reflexive address.
//! The candidate set is unsigned.
//! `endpoint_sign_payload` is the byte string the coordinator signs.
//! ADR 0003 does not name the owner of the Coordinator blob.
//! Direct sends hole-punch datagrams.
//! Direct then proves QUIC on the same UDP socket.
//! The Direct attempt uses the 3 second budget.
//! Relay routes by session id through the gyeol Relay.
//! The Relay payload stays opaque.
//! UDP port 443 is preferred.
//! TCP port 443 uses a QUIC-style length prefix when UDP is blocked.
//! Stick holds the Relay path and retries Direct.
//! A successful retry reconnects hello-quic on the direct socket.
//! The process does not restart.
//! The NAT feed records one JSON object per path event.

mod candidate;
mod direct;
mod error;
mod lab;
mod nat_feed;
mod nat_smash;
mod path;
mod punch;
mod relay;
mod same_nat;
mod stick;
mod stun;

pub use candidate::{
    decode_candidate, encode_candidate, endpoint_sign_payload, CandidateSink, EndpointCandidate,
    MemoryCandidateSink, UnsignedCandidateSet,
};
pub use direct::{
    issue_direct_pair, DirectIdentity, DirectMaterial, DirectProof, DirectRequest, DirectRole,
    DirectUpgrade,
};
pub use error::EdgeError;
pub use lab::{run_edge_smoke, SmokeReport};
pub use nat_feed::{
    nat_inject_armed, NatDifficulty, NatEventLog, NatInjectMode, NatLevel, PathKind, PhaseName,
    KIND_NAT_INJECT, KIND_NAT_PROBE, KIND_PATH_ALLOCATE, KIND_PATH_DIRECT, KIND_PATH_DOWN,
    KIND_PATH_RELAY, KIND_PATH_SWITCH, KIND_PATH_UP, KIND_RELAY_HOP, LAB_OVERLAY_IP,
    NAT_EVENT_VERSION, NAT_FEED_SOURCE,
};
pub use nat_smash::{run_nat_smash, NatSmash, NatSmashReport};
pub use path::{
    AllocatePhase, DirectPhase, PathId, PathMachine, PathState, RelayPhase, DIRECT_ATTEMPT_BUDGET,
    DIRECT_QUIC_PORT, DIRECT_RETRY_INTERVAL, STICK_AND_UPGRADE,
};
pub use punch::PunchToken;
pub use relay::{
    relay_policy_port, run_relay_smoke, RelayLabReport, RelayLink, RelayProof, RelayRequest,
    RelaySmokeMode, RELAY_PROOF_PAYLOAD,
};
pub use same_nat::{run_same_nat_bound, run_same_nat_direct, SameNatReport};
pub use stick::{run_stick_upgrade, StickNatKind, StickReport};
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
