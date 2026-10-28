use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use gyeol_edge::{
    run_edge_smoke, AllocatePhase, DirectPhase, LabStunServer, MemoryCandidateSink, PathMachine,
    PathState, StunClient, DIRECT_ATTEMPT_BUDGET, DIRECT_QUIC_PORT,
};

#[test]
fn lab_nat_smoke_stops_at_the_direct_stub() {
    let report = run_edge_smoke().expect("the lab smoke failed");
    assert_eq!(report.reflexive.ip(), report.nat.ip());
    assert_eq!(report.reflexive.port(), report.nat.port());
    assert_ne!(report.local.port(), report.reflexive.port());
    assert!(matches!(
        report.after_allocate,
        PathState::Allocate {
            phase: AllocatePhase::Ready,
            ..
        }
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
    assert!(text.contains("Allocate Ready"));
    assert!(text.contains("Direct Stub"));
}

#[test]
fn stun_without_nat_reports_the_local_socket() {
    let server = LabStunServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_addr = server.local_addr().unwrap();
    let handle = thread::spawn(move || server.serve_one(Duration::from_secs(3)));
    let client = StunClient::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let mut machine = PathMachine::start_allocate();
    let mut sink = MemoryCandidateSink::default();
    let candidate = machine
        .gather_reflexive(&client, server_addr, Duration::from_secs(2), &mut sink)
        .unwrap();
    let observed = handle.join().unwrap().unwrap();
    assert_eq!(candidate.reflexive, observed);
    assert_eq!(candidate.reflexive, candidate.local);
    assert_eq!(machine.state().to_string(), "Allocate Ready");
    machine.begin_direct_stub().unwrap();
    assert!(!machine.direct_is_up());
}
