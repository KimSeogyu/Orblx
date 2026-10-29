use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use orblx_edge::{
    run_same_nat_direct, AllocatePhase, DirectIdentity, DirectPhase, DirectRequest, DirectRole,
    EdgeError, EndpointCandidate, LabStunServer, MemoryCandidateSink, PathMachine, PathState,
    PunchToken, StunClient, DIRECT_ATTEMPT_BUDGET, DIRECT_QUIC_PORT,
};

#[test]
fn same_nat_peers_send_punch_packets_and_mark_direct_up() {
    let report = run_same_nat_direct().expect("the same-NAT lab failed");
    assert!(report.same_nat());
    assert!(report.server_direct_is_up);
    assert!(report.client_direct_is_up);
    assert!(report.echo_ok);
    assert!(report.server_packets_sent >= 1);
    assert!(report.client_packets_sent >= 1);
    assert!(report.server_packets_received >= 1);
    assert!(report.client_packets_received >= 1);
    assert!(report.server_elapsed <= DIRECT_ATTEMPT_BUDGET);
    assert!(report.client_elapsed <= DIRECT_ATTEMPT_BUDGET);
    assert_eq!(report.policy_port, DIRECT_QUIC_PORT);
    assert_eq!(report.quic_port, report.server_local.port());
    assert_ne!(report.server_local, report.server_reflexive);
    assert_ne!(report.client_local, report.client_reflexive);
    assert_eq!(report.server_reflexive.ip(), report.client_reflexive.ip());
    assert_eq!(report.server_path_id.as_bytes().len(), 16);
    assert_eq!(report.client_path_id.as_bytes().len(), 16);
    let text = report.lines().join("\n");
    assert!(text.contains("same-nat true"));
    assert!(text.contains("server direct_is_up true"));
    assert!(text.contains("client direct_is_up true"));
    assert!(text.contains("echo ok true"));
    assert!(text.contains("policy port 443"));
}

#[test]
fn direct_budget_sends_punch_packets_and_stays_down() {
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
    assert!(matches!(
        machine.state(),
        PathState::Allocate {
            phase: AllocatePhase::Ready,
            ..
        }
    ));

    let remote = EndpointCandidate {
        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        reflexive: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
    };
    assert_eq!(candidate.reflexive.ip(), remote.reflexive.ip());
    let started = Instant::now();
    let error = machine
        .establish_direct(DirectRequest {
            role: DirectRole::Server,
            remote,
            token: PunchToken::generate().unwrap(),
            socket: client.into_socket(),
            identity: empty_identity(),
            budget: DIRECT_ATTEMPT_BUDGET,
        })
        .unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(error, EdgeError::DirectBudget);
    assert!(elapsed >= DIRECT_ATTEMPT_BUDGET);
    assert!(elapsed < DIRECT_ATTEMPT_BUDGET + Duration::from_secs(2));
    assert!(!machine.direct_is_up());
    assert!(machine.path_id().is_none());
    match machine.state() {
        PathState::Direct {
            phase:
                DirectPhase::Failed {
                    packets_sent,
                    quic_port,
                    budget,
                    ..
                },
            ..
        } => {
            assert!(packets_sent >= 1);
            assert_eq!(quic_port, candidate.local.port());
            assert_eq!(budget, DIRECT_ATTEMPT_BUDGET);
        }
        other => panic!("the state is {other}"),
    }
}

fn empty_identity() -> DirectIdentity {
    DirectIdentity::blank()
}
