use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gyeol_identity::{decode_certificate_pem, ticket_hash, DenySet, MiniCa, SpiffeId, TrustBundle};
use tokio::sync::mpsc;

use crate::quic::pump_packets;
use crate::{
    ipv4_packet, tun_capability_note, HelloConfig, HelloEndpoint, HelloError, PeerGate,
    DEFAULT_UDP_PORT,
};

const FIXTURE_UNIX: u64 = 1_793_196_196;
const TICKET_VALID: &[u8] = include_bytes!("../../gyeol-identity/fixtures/ticket-valid.bin");
const USER_SVID_PEM: &str = include_str!("../../gyeol-identity/fixtures/user-svid.pem");
const TRUST_BUNDLE_PEM: &str = include_str!("../../gyeol-identity/fixtures/trust-bundle.pem");
const CA_PEM: &str = include_str!("../../gyeol-identity/fixtures/ca.pem");

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn sample_packet() -> Vec<u8> {
    ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(10, 8, 0, 2),
        b"ping",
    )
    .unwrap()
}

fn fixture_hash() -> [u8; 16] {
    ticket_hash(TICKET_VALID)
}

struct IssuedPair {
    server: HelloConfig,
    client: HelloConfig,
    server_id: SpiffeId,
    client_id: SpiffeId,
}

fn issue_pair(now: SystemTime) -> (MiniCa, IssuedPair) {
    let ca = MiniCa::generate(now).unwrap();
    let deny = DenySet::empty();
    let ttl = Duration::from_secs(300);
    let server_id = SpiffeId::user("w3-server").unwrap();
    let client_id = SpiffeId::user("w3-client").unwrap();
    let server = ca.issue(&server_id, now, ttl, &deny).unwrap();
    let client = ca.issue(&client_id, now, ttl, &deny).unwrap();
    let hash = fixture_hash();
    let trust = ca.trust_bundle().clone();
    let pair = IssuedPair {
        server: HelloConfig::from_issued(
            &server.certificate_pem,
            &server.private_key_pem,
            trust.clone(),
            hash,
        ),
        client: HelloConfig::from_issued(
            &client.certificate_pem,
            &client.private_key_pem,
            trust,
            hash,
        ),
        server_id,
        client_id,
    };
    (ca, pair)
}

fn assert_identity_error(err: HelloError) {
    assert!(
        matches!(err, HelloError::Identity(_)),
        "the peer leaf was not rejected: {err}"
    );
}

#[test]
fn default_udp_port_is_443() {
    assert_eq!(DEFAULT_UDP_PORT, 443);
}

#[test]
fn tun_note_names_the_capability() {
    assert!(tun_capability_note().contains("CAP_NET_ADMIN"));
}

#[test]
fn workspace_lock_has_no_forbidden_crates() {
    let lock = include_str!("../../../Cargo.lock");
    for name in [
        "wireguard",
        "boringtun",
        "defguard",
        "headscale",
        "tailscale",
        "derp",
    ] {
        let needle = format!("name = \"{name}");
        assert!(
            !lock.contains(&needle),
            "the lock contains a forbidden crate {name}"
        );
    }
}

#[test]
fn fixture_leaf_binds_and_unbound_gate_rejects_data() {
    let bundle = TrustBundle::from_pem(TRUST_BUNDLE_PEM).unwrap();
    let leaf = decode_certificate_pem(USER_SVID_PEM).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(FIXTURE_UNIX);
    let packet = sample_packet();
    let hash = fixture_hash();

    let unbound = PeerGate::new();
    let err = unbound.encode_data(1, 0, hash, &packet).unwrap_err();
    assert!(matches!(err, HelloError::PeerNotBound));
    assert!(err.to_string().contains("rejects DATA"));

    let mut gate = PeerGate::new();
    let id = gate
        .bind_leaf(&bundle, &leaf, now, &DenySet::empty())
        .unwrap();
    assert_eq!(id.as_uri(), "spiffe://gyeol.local/user/seogyu-dev");
    let ca_bundle = TrustBundle::from_pem(CA_PEM).unwrap();
    let mut ca_gate = PeerGate::new();
    let ca_id = ca_gate
        .bind_leaf(&ca_bundle, &leaf, now, &DenySet::empty())
        .unwrap();
    assert_eq!(ca_id.as_uri(), id.as_uri());
    let frame = gate.encode_data(7, 0, hash, &packet).unwrap();
    assert_eq!(frame.ticket_hash, hash);
    assert_eq!(frame.seq, 0);
    assert_eq!(gate.payload_from_data(&frame).unwrap(), packet.as_slice());

    let mut control = frame.clone();
    control.frame_type = crate::FrameType::Ctrl;
    assert!(matches!(
        gate.payload_from_data(&control).unwrap_err(),
        HelloError::NotData
    ));

    let other = MiniCa::generate(now).unwrap();
    let mut other_gate = PeerGate::new();
    let rejected = other_gate.bind_leaf(other.trust_bundle(), &leaf, now, &DenySet::empty());
    assert_identity_error(rejected.unwrap_err());
}

#[tokio::test]
async fn quic_frame_round_trip_uses_the_fixture_ticket_hash() {
    let result = tokio::time::timeout(Duration::from_secs(10), round_trip()).await;
    result.expect("the round trip timed out").unwrap();
}

async fn round_trip() -> Result<(), HelloError> {
    let now = SystemTime::now();
    let (_ca, pair) = issue_pair(now);
    let server = HelloEndpoint::bind_server(pair.server, loopback(0))?;
    let addr = server.local_addr()?;
    let packet = sample_packet();
    let reply = ipv4_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(10, 8, 0, 1),
        b"pong",
    )?;
    let reply_for_server = reply.clone();
    let server_id = pair.server_id.clone();
    let client_id = pair.client_id.clone();
    let hash = fixture_hash();
    let packet_for_server = packet.clone();

    let server_task = tokio::spawn(async move {
        let mut session = server.accept_one().await.unwrap();
        assert_eq!(session.peer_id(), &client_id);
        let frame = session.recv_data_frame().await.unwrap();
        assert_eq!(frame.ticket_hash, hash);
        assert_eq!(frame.seq, 0);
        assert_eq!(frame.payload, packet_for_server);
        let client_session_from_frame = frame.session_id;
        session.send_ipv4(&reply_for_server).await.unwrap();
        let second = session.recv_data_frame().await.unwrap();
        assert_eq!(second.seq, 1);
        assert_eq!(second.session_id, client_session_from_frame);
        (session.session_id(), client_session_from_frame)
    });

    let client = HelloEndpoint::bind_client(pair.client, loopback(0))?;
    let mut session = client.connect_one(addr).await?;
    assert_eq!(session.peer_id(), &server_id);
    let client_session_id = session.session_id();
    session.send_ipv4(&packet).await?;
    let got = session.recv_data_frame().await?;
    assert_eq!(got.payload, reply);
    assert_eq!(got.ticket_hash, hash);
    assert_eq!(got.seq, 0);
    session.send_ipv4(&packet).await?;
    let (server_session_id, client_session_from_frame) = server_task.await.unwrap();
    assert_eq!(got.session_id, server_session_id);
    assert_eq!(client_session_from_frame, client_session_id);
    Ok(())
}

#[tokio::test]
async fn quic_pump_moves_packets_without_a_tun_device() {
    let result = tokio::time::timeout(Duration::from_secs(10), pump_round_trip()).await;
    result.expect("the pump timed out").unwrap();
}

async fn pump_round_trip() -> Result<(), HelloError> {
    let now = SystemTime::now();
    let (_ca, pair) = issue_pair(now);
    let server = HelloEndpoint::bind_server(pair.server, loopback(0))?;
    let addr = server.local_addr()?;
    let packet = sample_packet();
    let server_task = tokio::spawn(async move {
        let mut session = server.accept_one().await.unwrap();
        let got = session.recv_ipv4().await.unwrap();
        session.send_ipv4(&got).await.unwrap();
        session.wait_closed().await;
    });

    let client = HelloEndpoint::bind_client(pair.client, loopback(0))?;
    let session = client.connect_one(addr).await?;
    let (ingress_tx, ingress_rx) = mpsc::channel(2);
    let (egress_tx, mut egress_rx) = mpsc::channel(2);
    let pump = tokio::spawn(async move { pump_packets(session, ingress_rx, egress_tx).await });
    ingress_tx.send(b"not-ipv4".to_vec()).await.unwrap();
    ingress_tx.send(packet.clone()).await.unwrap();
    let echoed = egress_rx.recv().await.unwrap();
    assert_eq!(echoed, packet);
    drop(ingress_tx);
    pump.await.unwrap()?;
    server_task.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn server_rejects_a_peer_without_a_valid_leaf() {
    tokio::time::timeout(Duration::from_secs(10), reject_bad_client())
        .await
        .expect("the reject test timed out");
}

async fn reject_bad_client() {
    let now = SystemTime::now();
    let (ca, pair) = issue_pair(now);
    let other = MiniCa::generate(now).unwrap();
    let bad_id = SpiffeId::user("w3-bad").unwrap();
    let bad = other
        .issue(&bad_id, now, Duration::from_secs(300), &DenySet::empty())
        .unwrap();
    let bad_client = HelloConfig::from_issued(
        &bad.certificate_pem,
        &bad.private_key_pem,
        ca.trust_bundle().clone(),
        fixture_hash(),
    );
    let server = HelloEndpoint::bind_server(pair.server, loopback(0)).unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move { server.accept_one().await });
    let client = HelloEndpoint::bind_client(bad_client, loopback(0)).unwrap();
    let client_task = tokio::spawn(async move { client.connect_one(addr).await });
    let server_result = server_task.await.unwrap();
    let Err(err) = server_result else {
        panic!("the server accepted a bad leaf");
    };
    assert_identity_error(err);
    client_task.abort();
}

#[tokio::test]
async fn client_rejects_a_peer_without_a_valid_leaf() {
    tokio::time::timeout(Duration::from_secs(10), reject_bad_server())
        .await
        .expect("the reject test timed out");
}

async fn reject_bad_server() {
    let now = SystemTime::now();
    let (ca, pair) = issue_pair(now);
    let other = MiniCa::generate(now).unwrap();
    let bad_id = SpiffeId::user("w3-bad-server").unwrap();
    let bad = other
        .issue(&bad_id, now, Duration::from_secs(300), &DenySet::empty())
        .unwrap();
    let bad_server = HelloConfig::from_issued(
        &bad.certificate_pem,
        &bad.private_key_pem,
        ca.trust_bundle().clone(),
        fixture_hash(),
    );
    let server = HelloEndpoint::bind_server(bad_server, loopback(0)).unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = server.accept_one().await;
    });
    let client = HelloEndpoint::bind_client(pair.client, loopback(0)).unwrap();
    let client_result = client.connect_one(addr).await;
    let Err(err) = client_result else {
        panic!("the client accepted a bad leaf");
    };
    assert_identity_error(err);
    server_task.abort();
}
