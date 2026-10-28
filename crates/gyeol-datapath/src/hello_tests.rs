use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gyeol_crypto::{mac_input, ticket_hash, ticket_mac, CryptoError, TicketKey, TicketRing};
use gyeol_identity::{
    decode_certificate_pem, sign_ticket, DenySet, IdentityError, MiniCa, SpiffeId, TicketClaims,
    TicketFlags, TicketSigner, TrustBundle,
};
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

struct IssuedPair {
    server: HelloConfig,
    client: HelloConfig,
    server_id: SpiffeId,
    client_id: SpiffeId,
    signer: TicketSigner,
    mac_key: [u8; 32],
}

struct Presented {
    bytes: Vec<u8>,
    mac: [u8; 32],
    nonce: [u8; 16],
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn ticket_claims(now: SystemTime, subject: &SpiffeId, lifetime: u64) -> TicketClaims {
    let start = unix(now);
    TicketClaims {
        issuer: SpiffeId::coord("1").unwrap(),
        subject: subject.clone(),
        not_before: start,
        expires: start + lifetime,
        dst_cidr: "10.8.0.0/24".to_string(),
        proto: 6,
        dst_port: 443,
        flags: TicketFlags::none(),
    }
}

fn present(
    signer: &TicketSigner,
    mac_key: &[u8; 32],
    now: SystemTime,
    subject: &SpiffeId,
    lifetime: u64,
) -> Presented {
    let signed = sign_ticket(signer, &ticket_claims(now, subject, lifetime)).unwrap();
    let mac = ticket_mac(mac_key, mac_input(&signed.bytes)).unwrap();
    Presented {
        bytes: signed.bytes,
        mac,
        nonce: signed.nonce,
    }
}

fn ring_for(ca: &MiniCa, signer: &TicketSigner, mac_key: [u8; 32], now: SystemTime) -> TicketRing {
    assert_ne!(signer.public_key(), *ca.public_key());
    let key = TicketKey::new(
        signer.verifier(),
        mac_key,
        now - Duration::from_secs(60),
        now + Duration::from_secs(86_400),
    )
    .unwrap();
    TicketRing::single(key, ca.public_key()).unwrap()
}

fn config_for(
    certificate_pem: &str,
    private_key_pem: &str,
    trust: TrustBundle,
    presented: &Presented,
    ring: &TicketRing,
) -> HelloConfig {
    HelloConfig::from_issued(
        certificate_pem,
        private_key_pem,
        trust,
        presented.bytes.clone(),
        presented.mac,
        ring.clone(),
    )
}

fn issue_pair(now: SystemTime) -> (MiniCa, IssuedPair) {
    let ca = MiniCa::generate(now).unwrap();
    let deny = DenySet::empty();
    let ttl = Duration::from_secs(300);
    let server_id = SpiffeId::user("w3-server").unwrap();
    let client_id = SpiffeId::user("w3-client").unwrap();
    let server = ca.issue(&server_id, now, ttl, &deny).unwrap();
    let client = ca.issue(&client_id, now, ttl, &deny).unwrap();
    let signer = TicketSigner::generate();
    let mac_key = [0x24; 32];
    let ring = ring_for(&ca, &signer, mac_key, now);
    let server_ticket = present(&signer, &mac_key, now, &server_id, 600);
    let client_ticket = present(&signer, &mac_key, now, &client_id, 600);
    let trust = ca.trust_bundle().clone();
    let pair = IssuedPair {
        server: config_for(
            &server.certificate_pem,
            &server.private_key_pem,
            trust.clone(),
            &server_ticket,
            &ring,
        ),
        client: config_for(
            &client.certificate_pem,
            &client.private_key_pem,
            trust,
            &client_ticket,
            &ring,
        ),
        server_id,
        client_id,
        signer,
        mac_key,
    };
    (ca, pair)
}

fn ticket_failure(err: HelloError) -> CryptoError {
    match err {
        HelloError::Ticket(err) => err,
        other => panic!("the ticket check did not fail: {other}"),
    }
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
    let hash = ticket_hash(TICKET_VALID);

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
    assert!(matches!(
        gate.payload_from_data(&frame, now, &DenySet::empty())
            .unwrap_err(),
        HelloError::TicketMissing
    ));

    let mut control = frame.clone();
    control.frame_type = crate::FrameType::Ctrl;
    assert!(matches!(
        gate.payload_from_data(&control, now, &DenySet::empty())
            .unwrap_err(),
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
    let client_hash = ticket_hash(&pair.client.ticket_bytes);
    let server_hash = ticket_hash(&pair.server.ticket_bytes);
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
    let packet_for_server = packet.clone();

    let server_task = tokio::spawn(async move {
        let mut session = server.accept_one().await.unwrap();
        assert_eq!(session.peer_id(), &client_id);
        let frame = session.recv_data_frame().await.unwrap();
        assert_eq!(frame.ticket_hash, client_hash);
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
    assert_eq!(got.ticket_hash, server_hash);
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
        pair.client.ticket_bytes.clone(),
        pair.client.ticket_mac,
        pair.client.ticket_ring.clone(),
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
        pair.server.ticket_bytes.clone(),
        pair.server.ticket_mac,
        pair.server.ticket_ring.clone(),
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

#[test]
fn ticket_acl_drops_bad_tickets_and_allows_a_valid_ticket() {
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let ca = MiniCa::generate(now).unwrap();
    let peer = SpiffeId::user("seogyu-dev").unwrap();
    let issued = ca
        .issue(&peer, now, Duration::from_secs(300), &DenySet::empty())
        .unwrap();
    let signer = TicketSigner::generate();
    let mac_key = [0x42; 32];
    let ring = ring_for(&ca, &signer, mac_key, now);
    let good = present(&signer, &mac_key, now, &peer, 600);
    let hash = ticket_hash(&good.bytes);

    let mut gate = PeerGate::new();
    let unbound = gate
        .admit_ticket(&ring, &good.bytes, &good.mac, now, &DenySet::empty())
        .unwrap_err();
    assert!(matches!(unbound, HelloError::PeerNotBound));

    gate.bind_leaf(
        ca.trust_bundle(),
        &issued.certificate_der,
        now,
        &DenySet::empty(),
    )
    .unwrap();
    let packet = sample_packet();
    let frame = gate.encode_data(1, 0, hash, &packet).unwrap();
    assert!(matches!(
        gate.payload_from_data(&frame, now, &DenySet::empty())
            .unwrap_err(),
        HelloError::TicketMissing
    ));
    assert!(matches!(
        gate.admit_ticket(&ring, &[], &good.mac, now, &DenySet::empty())
            .unwrap_err(),
        HelloError::TicketMissing
    ));

    let mut wrong = good.bytes.clone();
    let last = wrong.len() - 1;
    wrong[last] ^= 0xff;
    assert_eq!(
        ticket_failure(
            gate.admit_ticket(&ring, &wrong, &good.mac, now, &DenySet::empty())
                .unwrap_err()
        ),
        CryptoError::Identity(IdentityError::Signature)
    );

    let mut bad_mac = good.mac;
    bad_mac[0] ^= 0xff;
    assert_eq!(
        ticket_failure(
            gate.admit_ticket(&ring, &good.bytes, &bad_mac, now, &DenySet::empty())
                .unwrap_err()
        ),
        CryptoError::TicketMac
    );

    let other = SpiffeId::user("other-user").unwrap();
    let other_ticket = present(&signer, &mac_key, now, &other, 600);
    assert_eq!(
        ticket_failure(
            gate.admit_ticket(
                &ring,
                &other_ticket.bytes,
                &other_ticket.mac,
                now,
                &DenySet::empty()
            )
            .unwrap_err()
        ),
        CryptoError::TicketSubject
    );

    let expired_claims = TicketClaims {
        issuer: SpiffeId::coord("1").unwrap(),
        subject: peer.clone(),
        not_before: unix(now) - 10_000,
        expires: unix(now) - 120,
        dst_cidr: "10.8.0.0/24".to_string(),
        proto: 6,
        dst_port: 443,
        flags: TicketFlags::none(),
    };
    let expired = sign_ticket(&signer, &expired_claims).unwrap();
    let expired_mac = ticket_mac(&mac_key, mac_input(&expired.bytes)).unwrap();
    assert_eq!(
        ticket_failure(
            gate.admit_ticket(&ring, &expired.bytes, &expired_mac, now, &DenySet::empty())
                .unwrap_err()
        ),
        CryptoError::Identity(IdentityError::Expired)
    );

    let admitted = gate
        .admit_ticket(&ring, &good.bytes, &good.mac, now, &DenySet::empty())
        .unwrap();
    assert_eq!(admitted, hash);
    assert_eq!(
        gate.payload_from_data(&frame, now, &DenySet::empty())
            .unwrap(),
        packet.as_slice()
    );

    let mut mismatched = frame.clone();
    mismatched.ticket_hash[0] ^= 0xff;
    assert!(matches!(
        gate.payload_from_data(&mismatched, now, &DenySet::empty())
            .unwrap_err(),
        HelloError::TicketHash
    ));

    let late = now + Duration::from_secs(800);
    assert_eq!(
        ticket_failure(
            gate.payload_from_data(&frame, late, &DenySet::empty())
                .unwrap_err()
        ),
        CryptoError::Identity(IdentityError::Expired)
    );
    assert_eq!(
        gate.payload_from_data(&frame, now, &DenySet::empty())
            .unwrap(),
        packet.as_slice()
    );

    let mut deny = DenySet::empty();
    let document = format!(
        r#"{{"version":1,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":["{nonce}"]}}"#,
        nonce = hex(&good.nonce)
    );
    deny.apply_json(document.as_bytes()).unwrap();
    assert_eq!(
        ticket_failure(gate.payload_from_data(&frame, now, &deny).unwrap_err()),
        CryptoError::Identity(IdentityError::Revoked)
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn quic_receiver_drops_a_bad_ticket_and_allows_a_valid_ticket() {
    tokio::time::timeout(Duration::from_secs(30), ticket_accept_cases())
        .await
        .expect("the ticket accept test timed out");
}

async fn ticket_accept_cases() {
    let now = SystemTime::now();
    let (ca, pair) = issue_pair(now);
    let client_leaf = pair.client.certificate_pem.clone();
    let client_key = pair.client.private_key_pem.clone();
    let server_leaf = pair.server.certificate_pem.clone();
    let server_key = pair.server.private_key_pem.clone();
    let trust = ca.trust_bundle().clone();
    let ring = pair.client.ticket_ring.clone();

    let missing = HelloConfig::from_issued(
        &client_leaf,
        &client_key,
        trust.clone(),
        Vec::new(),
        pair.client.ticket_mac,
        ring.clone(),
    );
    let server_err = receiver_error(pair.server.clone(), missing).await;
    assert!(
        matches!(server_err, HelloError::TicketMissing),
        "a missing ticket was accepted: {server_err}"
    );

    let mut wrong_bytes = pair.client.ticket_bytes.clone();
    let last = wrong_bytes.len() - 1;
    wrong_bytes[last] ^= 0xff;
    let wrong = HelloConfig::from_issued(
        &client_leaf,
        &client_key,
        trust.clone(),
        wrong_bytes,
        pair.client.ticket_mac,
        ring.clone(),
    );
    let server_err = receiver_error(pair.server.clone(), wrong).await;
    assert_eq!(
        ticket_failure(server_err),
        CryptoError::Identity(IdentityError::Signature)
    );

    let mut bad_mac = pair.client.ticket_mac;
    bad_mac[0] ^= 0xff;
    let bad = HelloConfig::from_issued(
        &client_leaf,
        &client_key,
        trust.clone(),
        pair.client.ticket_bytes.clone(),
        bad_mac,
        ring.clone(),
    );
    let server_err = receiver_error(pair.server.clone(), bad).await;
    assert_eq!(ticket_failure(server_err), CryptoError::TicketMac);

    let expired = present(
        &pair.signer,
        &pair.mac_key,
        now - Duration::from_secs(10_000),
        &pair.client_id,
        100,
    );
    let expired_config = HelloConfig::from_issued(
        &client_leaf,
        &client_key,
        trust.clone(),
        expired.bytes,
        expired.mac,
        ring.clone(),
    );
    let server_err = receiver_error(pair.server.clone(), expired_config).await;
    assert_eq!(
        ticket_failure(server_err),
        CryptoError::Identity(IdentityError::Expired)
    );

    let other = SpiffeId::user("other-user").unwrap();
    let other_ticket = present(&pair.signer, &pair.mac_key, now, &other, 600);
    let other_config = HelloConfig::from_issued(
        &client_leaf,
        &client_key,
        trust.clone(),
        other_ticket.bytes,
        other_ticket.mac,
        ring.clone(),
    );
    let server_err = receiver_error(pair.server.clone(), other_config).await;
    assert_eq!(ticket_failure(server_err), CryptoError::TicketSubject);

    let expired_server = present(
        &pair.signer,
        &pair.mac_key,
        now - Duration::from_secs(10_000),
        &pair.server_id,
        100,
    );
    let bad_server = HelloConfig::from_issued(
        &server_leaf,
        &server_key,
        trust,
        expired_server.bytes,
        expired_server.mac,
        ring,
    );
    let client_err = connector_error(bad_server, pair.client.clone()).await;
    assert_eq!(
        ticket_failure(client_err),
        CryptoError::Identity(IdentityError::Expired)
    );
}

async fn receiver_error(server: HelloConfig, client: HelloConfig) -> HelloError {
    let server = HelloEndpoint::bind_server(server, loopback(0)).unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move { server.accept_one().await });
    let client = HelloEndpoint::bind_client(client, loopback(0)).unwrap();
    let client_task = tokio::spawn(async move { client.connect_one(addr).await });
    let server_result = server_task.await.unwrap();
    client_task.abort();
    match server_result {
        Err(err) => err,
        Ok(_) => panic!("the receiver accepted the ticket"),
    }
}

async fn connector_error(server: HelloConfig, client: HelloConfig) -> HelloError {
    let server = HelloEndpoint::bind_server(server, loopback(0)).unwrap();
    let addr = server.local_addr().unwrap();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let result = server.accept_one().await;
        let _ = release_rx.await;
        result
    });
    let client = HelloEndpoint::bind_client(client, loopback(0)).unwrap();
    let client_result = client.connect_one(addr).await;
    let _ = release_tx.send(());
    let _ = server_task.await;
    match client_result {
        Err(err) => err,
        Ok(_) => panic!("the connector accepted the ticket"),
    }
}
