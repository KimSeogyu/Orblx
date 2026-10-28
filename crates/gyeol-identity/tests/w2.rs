use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gyeol_identity::{
    decode_certificate_pem, extract_spiffe_id, sign_ticket, ticket_hash, verify_ticket, DenyApply,
    DenySet, IdentityError, IssueGate, MiniCa, MockOidc, SpiffeId, TicketClaims, TicketFlags,
    TicketSigner, TicketVerifier, WorkloadKind, MAX_AGENT_TTL, MAX_USER_TTL, MOCK_OIDC_ISSUER,
    OIDC_AUDIENCE, TRUST_DOMAIN,
};

fn fixed_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// First 16 bytes of SHA-256 over `fixtures/ticket-valid.bin`.
///
/// W4 freezes this value. Datapath checks the same bytes.
const TICKET_VALID_HASH: [u8; 16] = [
    0xf6, 0x09, 0x53, 0x41, 0x15, 0x57, 0xe1, 0xfd, 0x44, 0x3f, 0x38, 0x4a, 0x85, 0x92, 0xba, 0xd3,
];

fn gate_at(now: SystemTime) -> (MockOidc, IssueGate) {
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let ca = MiniCa::generate(now).unwrap();
    let gate = IssueGate::new(ca, &oidc).unwrap();
    (oidc, gate)
}

#[test]
fn spiffe_uri_accepts_the_four_paths() {
    let user = SpiffeId::parse("spiffe://gyeol.local/user/seogyu-dev").unwrap();
    assert_eq!(user.kind(), WorkloadKind::User);
    assert_eq!(user.name(), "seogyu-dev");
    assert_eq!(user.as_uri(), "spiffe://gyeol.local/user/seogyu-dev");
    assert_eq!(TRUST_DOMAIN, "gyeol.local");
    assert!(SpiffeId::parse("spiffe://GYEOL.local/user/seogyu-dev").is_err());
    assert!(SpiffeId::parse("spiffe://gyeol.local/user/a/b").is_err());
    assert!(SpiffeId::parse("spiffe://gyeol.local/other/seogyu-dev").is_err());
    assert!(SpiffeId::user("").is_err());
    assert!(SpiffeId::user("..").is_err());
}

#[test]
fn mock_oidc_issues_a_human_svid_with_one_uri_san() {
    let now = fixed_now();
    let (oidc, gate) = gate_at(now);
    let token = oidc
        .issue_id_token("seogyu-dev", now, Duration::from_secs(10 * 60))
        .unwrap();
    let svid = gate
        .issue_human_svid(&token, now, &DenySet::empty())
        .unwrap();

    assert_eq!(
        svid.spiffe_id.as_uri(),
        "spiffe://gyeol.local/user/seogyu-dev"
    );
    let extracted = extract_spiffe_id(&svid.certificate_der).unwrap();
    assert_eq!(extracted, svid.spiffe_id);
    assert!(svid.not_after > svid.not_before);
    assert!(svid.not_after - svid.not_before <= MAX_USER_TTL.as_secs());
    assert!(svid.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert!(svid.private_key_pem.contains("BEGIN PRIVATE KEY"));

    let authed = gate
        .trust_bundle()
        .authenticate_leaf(&svid.certificate_der, now, &DenySet::empty())
        .unwrap();
    assert_eq!(authed.as_uri(), "spiffe://gyeol.local/user/seogyu-dev");
    assert_eq!(OIDC_AUDIENCE, "gyeol-issue");
}

#[test]
fn bad_audience_and_expiry_are_rejected() {
    let now = fixed_now();
    let (oidc, gate) = gate_at(now);
    let bad_audience = oidc
        .issue_id_token_for_audience("seogyu-dev", "other-app", now, Duration::from_secs(300))
        .unwrap();
    assert_eq!(
        gate.issue_human_svid(&bad_audience, now, &DenySet::empty())
            .unwrap_err(),
        IdentityError::Audience
    );

    let past = now.checked_sub(Duration::from_secs(180)).unwrap();
    let expired = oidc
        .issue_id_token("seogyu-dev", past, Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        gate.issue_human_svid(&expired, now, &DenySet::empty())
            .unwrap_err(),
        IdentityError::Expired
    );

    let future = now.checked_add(Duration::from_secs(180)).unwrap();
    let early = oidc
        .issue_id_token("seogyu-dev", future, Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        gate.issue_human_svid(&early, now, &DenySet::empty())
            .unwrap_err(),
        IdentityError::NotYetValid
    );

    let mut token = oidc
        .issue_id_token("seogyu-dev", now, Duration::from_secs(300))
        .unwrap();
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    let mut signature = parts[2].clone().into_bytes();
    signature[0] = if signature[0] == b'A' { b'B' } else { b'A' };
    parts[2] = String::from_utf8(signature).unwrap();
    token = parts.join(".");
    assert_eq!(
        gate.issue_human_svid(&token, now, &DenySet::empty())
            .unwrap_err(),
        IdentityError::Signature
    );
}

#[test]
fn ttl_limits_follow_the_leaf_profile() {
    let now = fixed_now();
    let ca = MiniCa::generate(now).unwrap();
    let user = SpiffeId::user("seogyu-dev").unwrap();
    assert!(ca
        .issue(&user, now, MAX_USER_TTL, &DenySet::empty())
        .is_ok());
    assert_eq!(
        ca.issue(
            &user,
            now,
            MAX_USER_TTL + Duration::from_secs(1),
            &DenySet::empty()
        )
        .unwrap_err(),
        IdentityError::Time
    );

    let agent = SpiffeId::agent("worker-1").unwrap();
    let issued = ca
        .issue(&agent, now, MAX_AGENT_TTL, &DenySet::empty())
        .unwrap();
    assert_eq!(
        issued.not_after - issued.not_before,
        MAX_AGENT_TTL.as_secs()
    );
    assert_eq!(
        ca.issue(
            &agent,
            now,
            MAX_AGENT_TTL + Duration::from_secs(1),
            &DenySet::empty()
        )
        .unwrap_err(),
        IdentityError::Time
    );
    assert!(ca
        .issue(
            &SpiffeId::node("n1").unwrap(),
            now,
            MAX_USER_TTL,
            &DenySet::empty()
        )
        .is_ok());
    assert!(ca
        .issue(
            &SpiffeId::coord("1").unwrap(),
            now,
            MAX_USER_TTL,
            &DenySet::empty()
        )
        .is_ok());
}

#[test]
fn ticket_round_trip_hash_and_bad_signature() {
    let signer = TicketSigner::generate();
    let claims = TicketClaims {
        issuer: SpiffeId::coord("1").unwrap(),
        subject: SpiffeId::user("seogyu-dev").unwrap(),
        not_before: unix(fixed_now()),
        expires: unix(fixed_now()) + 600,
        dst_cidr: "10.8.0.10/32".to_string(),
        proto: 6,
        dst_port: 443,
        flags: TicketFlags::new(false, true),
    };
    let signed = sign_ticket(&signer, &claims).unwrap();
    let verified = verify_ticket(
        &signer.verifier(),
        &signed.bytes,
        fixed_now(),
        &DenySet::empty(),
    )
    .unwrap();
    assert_eq!(verified.hash, signed.hash);
    assert_eq!(verified.hash, ticket_hash(&signed.bytes));
    assert_eq!(signed.hash_hex(), hex(&signed.hash));
    assert_eq!(verified.subject, claims.subject);
    assert_eq!(verified.issuer, claims.issuer);
    assert_eq!(verified.dst_cidr, claims.dst_cidr);
    assert_eq!(verified.proto, 6);
    assert_eq!(verified.dst_port, 443);
    assert!(verified.flags.one_shot());
    assert!(!verified.flags.agent_jit());
    assert_eq!(verified.nonce, signed.nonce);

    let mut bad = signed.bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xff;
    assert_eq!(
        verify_ticket(&signer.verifier(), &bad, fixed_now(), &DenySet::empty()).unwrap_err(),
        IdentityError::Signature
    );

    let early = UNIX_EPOCH + Duration::from_secs(claims.not_before - 61);
    assert_eq!(
        verify_ticket(&signer.verifier(), &signed.bytes, early, &DenySet::empty()).unwrap_err(),
        IdentityError::NotYetValid
    );
    let late = UNIX_EPOCH + Duration::from_secs(claims.expires + 61);
    assert_eq!(
        verify_ticket(&signer.verifier(), &signed.bytes, late, &DenySet::empty()).unwrap_err(),
        IdentityError::Expired
    );
    let inside_skew = UNIX_EPOCH + Duration::from_secs(claims.not_before - 60);
    assert!(verify_ticket(
        &signer.verifier(),
        &signed.bytes,
        inside_skew,
        &DenySet::empty()
    )
    .is_ok());
}

#[test]
fn agent_jit_requires_one_host_and_one_port() {
    let signer = TicketSigner::generate();
    let mut claims = TicketClaims {
        issuer: SpiffeId::coord("1").unwrap(),
        subject: SpiffeId::agent("worker-1").unwrap(),
        not_before: unix(fixed_now()),
        expires: unix(fixed_now()) + 60,
        dst_cidr: "10.8.0.0/24".to_string(),
        proto: 6,
        dst_port: 443,
        flags: TicketFlags::new(true, false),
    };
    assert!(sign_ticket(&signer, &claims).is_err());
    claims.dst_cidr = "10.8.0.10/32".to_string();
    claims.dst_port = 0;
    assert!(sign_ticket(&signer, &claims).is_err());
    claims.dst_port = 443;
    assert!(sign_ticket(&signer, &claims).is_ok());
    claims.dst_cidr = "10.8.0.11/24".to_string();
    assert!(sign_ticket(&signer, &claims).is_err());
}

#[test]
fn ticket_key_is_not_the_svid_ca() {
    let now = fixed_now();
    let ca = MiniCa::generate(now).unwrap();
    let signer = TicketSigner::generate();
    assert_ne!(ca.public_key().as_slice(), signer.public_key().as_slice());
    let restored = TicketVerifier::from_public_pem(&signer.public_key_pem()).unwrap();
    assert_eq!(restored.public_key(), signer.public_key());
}

#[test]
fn revoked_uri_fails_issue_and_authenticate() {
    let now = fixed_now();
    let (oidc, gate) = gate_at(now);
    let token = oidc
        .issue_id_token("seogyu-dev", now, Duration::from_secs(300))
        .unwrap();
    let svid = gate
        .issue_human_svid(&token, now, &DenySet::empty())
        .unwrap();

    let mut deny = DenySet::empty();
    let document = format!(
        r#"{{"version":1,"generated_at":{generated},"revoked_uris":["spiffe://gyeol.local/user/seogyu-dev"],"revoked_ticket_nonces":[]}}"#,
        generated = unix(now)
    );
    assert_eq!(
        deny.apply_json(document.as_bytes()).unwrap(),
        DenyApply::Applied
    );
    assert_eq!(
        gate.issue_human_svid(&token, now, &deny).unwrap_err(),
        IdentityError::Revoked
    );
    assert_eq!(
        gate.trust_bundle()
            .authenticate_leaf(&svid.certificate_der, now, &deny)
            .unwrap_err(),
        IdentityError::Revoked
    );

    let stale = r#"{"version":1,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":[]}"#;
    assert_eq!(
        deny.apply_json(stale.as_bytes()).unwrap(),
        DenyApply::IgnoredOlder
    );
    assert!(deny.apply_json(b"{").is_err());
    assert_eq!(
        gate.issue_human_svid(&token, now, &deny).unwrap_err(),
        IdentityError::Revoked
    );

    let clear = format!(
        r#"{{"version":2,"generated_at":{generated},"revoked_uris":[],"revoked_ticket_nonces":[]}}"#,
        generated = unix(now)
    );
    assert_eq!(
        deny.apply_json(clear.as_bytes()).unwrap(),
        DenyApply::Applied
    );
    assert!(gate.issue_human_svid(&token, now, &deny).is_ok());
}

#[test]
fn revoked_ticket_nonce_fails() {
    let signer = TicketSigner::generate();
    let now = fixed_now();
    let claims = TicketClaims {
        issuer: SpiffeId::coord("1").unwrap(),
        subject: SpiffeId::user("seogyu-dev").unwrap(),
        not_before: unix(now),
        expires: unix(now) + 60,
        dst_cidr: "10.8.0.10/32".to_string(),
        proto: 17,
        dst_port: 53,
        flags: TicketFlags::none(),
    };
    let signed = sign_ticket(&signer, &claims).unwrap();
    let mut deny = DenySet::empty();
    let document = format!(
        r#"{{"version":7,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":["{nonce}"]}}"#,
        nonce = hex(&signed.nonce)
    );
    assert_eq!(
        deny.apply_json(document.as_bytes()).unwrap(),
        DenyApply::Applied
    );
    assert_eq!(
        verify_ticket(&signer.verifier(), &signed.bytes, now, &deny).unwrap_err(),
        IdentityError::Revoked
    );
}

#[test]
fn draft_fixtures_match_the_locked_profile() {
    let meta = include_str!("../fixtures/META.json");
    assert!(meta.contains("spiffe://gyeol.local/user/seogyu-dev"));
    assert!(meta.contains("f60953411557e1fd443f384a8592bad3"));

    let ticket = include_bytes!("../fixtures/ticket-valid.bin");
    assert_eq!(ticket_hash(ticket), TICKET_VALID_HASH);
    assert_eq!(hex(&TICKET_VALID_HASH), "f60953411557e1fd443f384a8592bad3");
    let verifier =
        TicketVerifier::from_public_pem(include_str!("../fixtures/ticket-pub.pem")).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_793_196_196);
    let verified = verify_ticket(&verifier, ticket, now, &DenySet::empty()).unwrap();
    assert_eq!(
        verified.subject.as_uri(),
        "spiffe://gyeol.local/user/seogyu-dev"
    );
    assert_eq!(verified.issuer.as_uri(), "spiffe://gyeol.local/coord/1");
    assert_eq!(verified.dst_cidr, "10.8.0.10/32");
    assert_eq!(verified.proto, 6);
    assert_eq!(verified.dst_port, 443);
    assert_eq!(verified.not_before, 1_793_196_196);
    assert_eq!(verified.expires, 1_793_196_796);

    let broken = include_bytes!("../fixtures/ticket-invalid.bin");
    assert_eq!(
        verify_ticket(&verifier, broken, now, &DenySet::empty()).unwrap_err(),
        IdentityError::Signature
    );

    let leaf = decode_certificate_pem(include_str!("../fixtures/user-svid.pem")).unwrap();
    let id = extract_spiffe_id(&leaf).unwrap();
    assert_eq!(id.as_uri(), "spiffe://gyeol.local/user/seogyu-dev");
    let bundle =
        gyeol_identity::TrustBundle::from_pem(include_str!("../fixtures/trust-bundle.pem"))
            .unwrap();
    let authed = bundle
        .authenticate_leaf(&leaf, now, &DenySet::empty())
        .unwrap();
    assert_eq!(authed, id);
    let from_ca =
        gyeol_identity::TrustBundle::from_pem(include_str!("../fixtures/ca.pem")).unwrap();
    assert!(from_ca.to_pem().contains("BEGIN CERTIFICATE"));
}

#[test]
fn ticket_valid_hash_matches_the_frozen_datapath_fixture() {
    let ticket = include_bytes!("../fixtures/ticket-valid.bin");
    assert_eq!(ticket_hash(ticket), TICKET_VALID_HASH);
    let listed = include_str!("../../gyeol-datapath/testdata/ticket-valid-hash.hex");
    let listed: String = listed
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    assert_eq!(listed, hex(&TICKET_VALID_HASH));
}
