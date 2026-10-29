use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_crypto::{
    mac_input, ticket_hash, ticket_mac, verify_ticket, CipherSuite, CryptoError, Handshake,
    HandshakePhase, KeySchedule, Role, SessionLimit, TicketKey, TicketRing, X25519Shared,
};
use orblx_identity::{
    sign_ticket, DenySet, IdentityError, MiniCa, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
    WorkloadKind, MAX_AGENT_TTL, MAX_USER_TTL,
};

const TICKET_VALID: &[u8] = include_bytes!("../../orblx-identity/fixtures/ticket-valid.bin");

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn claims(now: SystemTime, subject: &SpiffeId) -> TicketClaims {
    TicketClaims {
        issuer: SpiffeId::coord("1").unwrap(),
        subject: subject.clone(),
        not_before: unix(now),
        expires: unix(now) + 600,
        dst_cidr: "10.8.0.10/32".to_string(),
        proto: 6,
        dst_port: 443,
        flags: TicketFlags::none(),
    }
}

#[test]
fn fixture_ticket_hash_matches_the_identity_vector() {
    assert_eq!(
        hex(&ticket_hash(TICKET_VALID)),
        "44f62776f5ddb2c2a259539c36db2cc4"
    );
}

#[test]
fn provisional_mac_input_waits_for_the_frame_freeze() {
    // TODO(frame-freeze): replace this input when Datapath freezes the canonical ticket bytes.
    let ticket = b"identity-ticket-bytes";
    assert_eq!(mac_input(ticket), ticket);
}

#[test]
fn handshake_exposes_the_peer_uri_and_binds_the_ticket() {
    let now = at(1_700_000_000);
    let ca = MiniCa::generate(now).unwrap();
    let peer = SpiffeId::user("seogyu-dev").unwrap();
    let issued = ca
        .issue(&peer, now, MAX_USER_TTL, &DenySet::empty())
        .unwrap();

    let mut handshake = Handshake::server();
    assert_eq!(handshake.role(), Role::Server);
    assert_eq!(handshake.phase(), HandshakePhase::Start);
    assert_eq!(handshake.peer_spiffe_uri().unwrap_err(), CryptoError::Phase);
    assert_eq!(
        handshake
            .note_certificate_verified(&issued.certificate_der)
            .unwrap_err(),
        CryptoError::Phase
    );
    assert_eq!(Handshake::client().role(), Role::Client);

    assert_eq!(
        hex(&handshake.transcript_hash()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    handshake.record_message(b"client-hello").unwrap();
    let hello_hash = handshake.transcript_hash();
    handshake
        .select_suite(CipherSuite::ChaCha20Poly1305Sha256)
        .unwrap();
    assert_eq!(
        handshake
            .select_suite(CipherSuite::Aes128GcmSha256)
            .unwrap_err(),
        CryptoError::Phase
    );
    assert_eq!(
        handshake
            .note_certificate_verified(b"not-a-certificate")
            .unwrap_err(),
        CryptoError::Identity(IdentityError::Certificate)
    );
    handshake
        .note_certificate_verified(&issued.certificate_der)
        .unwrap();
    assert_eq!(handshake.phase(), HandshakePhase::CertificateVerify);
    assert_eq!(handshake.peer_spiffe_uri().unwrap_err(), CryptoError::Phase);

    handshake.record_message(b"server-finished").unwrap();
    let finished_hash = handshake.transcript_hash();
    assert_eq!(
        handshake.note_finished().unwrap(),
        "spiffe://orblx.local/user/seogyu-dev"
    );
    assert_eq!(handshake.phase(), HandshakePhase::Finished);
    assert_eq!(handshake.transcript_hash(), finished_hash);
    assert_eq!(
        handshake.record_message(b"data").unwrap_err(),
        CryptoError::Phase
    );
    assert_eq!(
        handshake
            .authorize_data(
                &SessionLimit::open(
                    now,
                    WorkloadKind::User,
                    UNIX_EPOCH + Duration::from_secs(issued.not_after)
                )
                .unwrap(),
                now,
                &[0u8; 16]
            )
            .unwrap_err(),
        CryptoError::Phase
    );

    let signer = TicketSigner::generate();
    assert_ne!(signer.public_key(), *ca.public_key());
    let mac_key = [0x7; 32];
    let signed = sign_ticket(&signer, &claims(now, &peer)).unwrap();
    let mac = ticket_mac(&mac_key, mac_input(&signed.bytes)).unwrap();
    let ring = TicketRing::single(
        TicketKey::new(
            signer.verifier(),
            mac_key,
            now,
            now + Duration::from_secs(3600),
        )
        .unwrap(),
        ca.public_key(),
    )
    .unwrap();
    let proof = verify_ticket(&ring, &signed.bytes, &mac, &peer, now, &DenySet::empty()).unwrap();
    let other = SpiffeId::user("other-user").unwrap();
    let other_signed = sign_ticket(&signer, &claims(now, &other)).unwrap();
    let other_mac = ticket_mac(&mac_key, mac_input(&other_signed.bytes)).unwrap();
    let other_proof = verify_ticket(
        &ring,
        &other_signed.bytes,
        &other_mac,
        &other,
        now,
        &DenySet::empty(),
    )
    .unwrap();
    assert_eq!(
        handshake.bind_ticket(&other_proof).unwrap_err(),
        CryptoError::TicketSubject
    );
    handshake.bind_ticket(&proof).unwrap();
    assert_eq!(handshake.phase(), HandshakePhase::Bound);
    assert_eq!(handshake.ticket_hash().unwrap(), proof.hash());
    assert_eq!(handshake.peer_spiffe_uri().unwrap(), peer.as_uri());

    let limit = SessionLimit::open(
        now,
        WorkloadKind::User,
        UNIX_EPOCH + Duration::from_secs(issued.not_after),
    )
    .unwrap();
    let mut bad_hash = *proof.hash();
    bad_hash[0] ^= 0xff;
    assert_eq!(
        handshake
            .authorize_data(&limit, now, &bad_hash)
            .unwrap_err(),
        CryptoError::TicketHash
    );
    handshake.authorize_data(&limit, now, proof.hash()).unwrap();
    let agent_limit = SessionLimit::open(now, WorkloadKind::Agent, now + MAX_AGENT_TTL).unwrap();
    assert_eq!(
        handshake
            .authorize_data(&agent_limit, now, proof.hash())
            .unwrap_err(),
        CryptoError::PeerUri
    );
    let due = limit.deadline().unwrap();
    assert_eq!(
        handshake
            .authorize_data(&limit, due, proof.hash())
            .unwrap_err(),
        CryptoError::Rehandshake
    );

    let shared = X25519Shared::new([0x11; 32]).unwrap();
    let schedule = KeySchedule::derive(
        CipherSuite::ChaCha20Poly1305Sha256,
        &shared,
        &hello_hash,
        &finished_hash,
    )
    .unwrap();
    let binding = handshake.policy_binding().unwrap();
    assert_eq!(binding.peer_spiffe_uri(), peer.as_uri());
    assert_eq!(binding.ticket_hash(), proof.hash());
    assert_eq!(binding.transcript_hash(), &finished_hash);
    let binder = schedule.export_binding(&binding).unwrap();
    assert_eq!(binder.len(), 32);
    let other_schedule = KeySchedule::derive(
        CipherSuite::ChaCha20Poly1305Sha256,
        &X25519Shared::new([0x12; 32]).unwrap(),
        &hello_hash,
        &finished_hash,
    )
    .unwrap();
    assert_ne!(binder, other_schedule.export_binding(&binding).unwrap());

    let nonce = hex(&signed.nonce);
    let document = format!(
        "{{\"version\":1,\"generated_at\":{},\"revoked_uris\":[],\"revoked_ticket_nonces\":[\"{nonce}\"]}}",
        unix(now)
    );
    let mut deny = DenySet::empty();
    deny.apply_json(document.as_bytes()).unwrap();
    assert_eq!(
        verify_ticket(&ring, &signed.bytes, &mac, &peer, now, &deny).unwrap_err(),
        CryptoError::Identity(IdentityError::Revoked)
    );

    handshake.close();
    assert_eq!(handshake.phase(), HandshakePhase::Closed);
    assert_eq!(handshake.peer_spiffe_uri().unwrap_err(), CryptoError::Phase);
    handshake.close();
    assert_eq!(handshake.phase(), HandshakePhase::Closed);
}
