use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use gyeol_edge::{
    relay_policy_port, run_relay_smoke, PathMachine, RelaySmokeMode, DIRECT_QUIC_PORT,
    STICK_AND_UPGRADE,
};
use gyeol_relay::{framing_name, RelayPreference, RelayTransport, RELAY_PORT};

#[test]
fn relay_policy_port_is_443() {
    assert_eq!(RELAY_PORT, 443);
    assert_eq!(relay_policy_port(), DIRECT_QUIC_PORT);
    assert_eq!(framing_name(RelayTransport::Tcp), "quic-style");
    assert_eq!(framing_name(RelayTransport::Udp), "udp-datagram");
    assert_eq!(STICK_AND_UPGRADE, "deferred");
    assert_eq!(RelayPreference::Auto.to_string(), "auto");
}

#[test]
fn relay_from_allocate_gather_is_rejected() {
    let mut machine = PathMachine::start_allocate();
    let error = machine
        .begin_relay(gyeol_edge::RelayRequest {
            session_id: gyeol_relay::RelaySessionId::from_bytes([7; 16]),
            udp: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            tcp: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            preference: RelayPreference::Udp,
            udp_timeout: Duration::from_millis(50),
            tcp_timeout: Duration::from_millis(50),
            budget: Duration::from_secs(1),
        })
        .unwrap_err();
    assert_eq!(error, gyeol_edge::EdgeError::WrongState);
    assert!(!machine.relay_is_up());
    assert!(machine.path_id().is_none());
}

#[test]
fn udp_relay_comes_up_after_direct_fails() {
    let report = run_relay_smoke(RelaySmokeMode::Udp, None).expect("the UDP Relay lab failed");
    assert!(report.direct_attempted);
    assert!(report.direct_failed);
    assert!(!report.udp_blocked);
    assert_eq!(report.transport, RelayTransport::Udp);
    assert_eq!(report.framing, "udp-datagram");
    assert!(report.server_relay_is_up);
    assert!(report.client_relay_is_up);
    assert!(!report.server_direct_is_up);
    assert!(!report.client_direct_is_up);
    assert!(report.server_direct_packets >= 1);
    assert!(report.client_direct_packets >= 1);
    assert!(report.echo_ok);
    assert!(report.payload_opaque());
    assert_eq!(report.plaintext_hits, 0);
    assert!(report.forwards >= 1);
    assert_eq!(report.policy_port, 443);
    assert_eq!(report.stick, "deferred");
    assert_ne!(report.path_id_server, report.path_id_client);
    let text = report.lines().join("\n");
    assert!(text.contains("relay lab udp"));
    assert!(text.contains("payload_opaque true"));
    assert!(text.contains("tcp framing quic-style"));
    assert!(text.contains("stick deferred"));
}

#[test]
fn tcp_fallback_comes_up_when_udp_is_blocked() {
    let report = run_relay_smoke(RelaySmokeMode::Tcp, None).expect("the TCP Relay lab failed");
    assert!(!report.direct_attempted);
    assert!(report.udp_blocked);
    assert_eq!(report.transport, RelayTransport::Tcp);
    assert_eq!(report.framing, "quic-style");
    assert!(report.server_relay_is_up);
    assert!(report.client_relay_is_up);
    assert!(!report.server_direct_is_up);
    assert!(report.echo_ok);
    assert!(report.payload_opaque());
    assert_eq!(report.plaintext_hits, 0);
    assert!(report.forwards >= 1);
    assert_eq!(report.server_direct_packets, 0);
    assert_eq!(report.policy_port, 443);
    let text = report.lines().join("\n");
    assert!(text.contains("relay lab tcp"));
    assert!(text.contains("transport tcp"));
    assert!(text.contains("framing quic-style"));
    assert!(text.contains("udp_blocked true"));
    assert!(text.contains("payload_opaque true"));
}
