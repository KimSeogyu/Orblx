use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gyeol_identity::{
    allow_agent_jit, sign_agent_jit_ticket, sign_ticket, verify_ticket, DenySet, IdentityError,
    Ipv4Destination, IssueGate, MiniCa, MockOidc, SpiffeId, TicketClaims, TicketFlags,
    TicketSigner, WorkloadKind, MAX_AGENT_TTL, MOCK_OIDC_ISSUER,
};

fn fixed_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn gate_at(now: SystemTime) -> (MockOidc, IssueGate) {
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let ca = MiniCa::generate(now).unwrap();
    let gate = IssueGate::new(ca, &oidc).unwrap();
    (oidc, gate)
}

fn app_a() -> Ipv4Destination {
    Ipv4Destination {
        addr: Ipv4Addr::new(10, 8, 0, 10),
        proto: 6,
        port: 443,
    }
}

fn app_b() -> Ipv4Destination {
    Ipv4Destination {
        addr: Ipv4Addr::new(10, 8, 0, 11),
        proto: 6,
        port: 443,
    }
}

#[test]
fn parent_human_attests_an_agent_svid_for_at_most_five_minutes() {
    let now = fixed_now();
    let (oidc, gate) = gate_at(now);
    let parent_token = oidc
        .issue_id_token("seogyu-dev", now, Duration::from_secs(10 * 60))
        .unwrap();
    let issued = gate
        .issue_agent_svid(
            &parent_token,
            "worker-1",
            now,
            MAX_AGENT_TTL,
            &DenySet::empty(),
        )
        .unwrap();

    assert_eq!(
        issued.parent.as_uri(),
        "spiffe://gyeol.local/user/seogyu-dev"
    );
    assert_eq!(
        issued.svid.spiffe_id.as_uri(),
        "spiffe://gyeol.local/agent/worker-1"
    );
    assert_eq!(issued.svid.spiffe_id.kind(), WorkloadKind::Agent);
    assert_ne!(issued.parent, issued.svid.spiffe_id);
    assert_eq!(
        issued.svid.not_after - issued.svid.not_before,
        MAX_AGENT_TTL.as_secs()
    );
    assert!(issued.svid.not_after - issued.svid.not_before <= 300);
    let authed = gate
        .trust_bundle()
        .authenticate_leaf(&issued.svid.certificate_der, now, &DenySet::empty())
        .unwrap();
    assert_eq!(authed, issued.svid.spiffe_id);

    assert_eq!(
        gate.issue_agent_svid(
            &parent_token,
            "worker-1",
            now,
            MAX_AGENT_TTL + Duration::from_secs(1),
            &DenySet::empty(),
        )
        .unwrap_err(),
        IdentityError::Time
    );
    let short_parent = oidc
        .issue_id_token("seogyu-dev", now, Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        gate.issue_agent_svid(
            &short_parent,
            "worker-1",
            now,
            MAX_AGENT_TTL,
            &DenySet::empty(),
        )
        .unwrap_err(),
        IdentityError::Time
    );
    assert!(SpiffeId::agent("worker/1").is_err());
    assert_eq!(
        gate.issue_agent_svid(
            &parent_token,
            "worker/1",
            now,
            MAX_AGENT_TTL,
            &DenySet::empty()
        )
        .unwrap_err(),
        IdentityError::SpiffeId
    );
}

#[test]
fn a_bad_parent_token_does_not_issue_an_agent_svid() {
    let now = fixed_now();
    let (oidc, gate) = gate_at(now);
    let bad_audience = oidc
        .issue_id_token_for_audience("seogyu-dev", "other-app", now, Duration::from_secs(300))
        .unwrap();
    assert_eq!(
        gate.issue_agent_svid(
            &bad_audience,
            "worker-1",
            now,
            Duration::from_secs(60),
            &DenySet::empty(),
        )
        .unwrap_err(),
        IdentityError::Audience
    );

    let mut deny = DenySet::empty();
    let document = format!(
        r#"{{"version":1,"generated_at":{generated},"revoked_uris":["spiffe://gyeol.local/user/seogyu-dev"],"revoked_ticket_nonces":[]}}"#,
        generated = unix(now)
    );
    deny.apply_json(document.as_bytes()).unwrap();
    let parent_token = oidc
        .issue_id_token("seogyu-dev", now, Duration::from_secs(300))
        .unwrap();
    assert_eq!(
        gate.issue_agent_svid(
            &parent_token,
            "worker-1",
            now,
            Duration::from_secs(60),
            &deny,
        )
        .unwrap_err(),
        IdentityError::Revoked
    );
}

#[test]
fn agent_jit_ticket_allows_one_destination_and_denies_the_other() {
    let now = fixed_now();
    let (oidc, gate) = gate_at(now);
    let parent_token = oidc
        .issue_id_token("seogyu-dev", now, Duration::from_secs(10 * 60))
        .unwrap();
    let issued = gate
        .issue_agent_svid(
            &parent_token,
            "worker-1",
            now,
            MAX_AGENT_TTL,
            &DenySet::empty(),
        )
        .unwrap();
    let signer = TicketSigner::generate();
    assert_ne!(signer.public_key(), *gate.ca_public_key());
    let issuer = SpiffeId::coord("1").unwrap();
    let signed = sign_agent_jit_ticket(
        &signer,
        &issuer,
        &issued.svid.spiffe_id,
        now,
        Duration::from_secs(60),
        app_a(),
    )
    .unwrap();
    let verified =
        verify_ticket(&signer.verifier(), &signed.bytes, now, &DenySet::empty()).unwrap();
    assert_eq!(verified.subject, issued.svid.spiffe_id);
    assert_ne!(verified.subject, issued.parent);
    assert!(verified.flags.agent_jit());
    assert_eq!(verified.dst_cidr, "10.8.0.10/32");
    assert_eq!(verified.dst_port, 443);
    assert!(verified.expires - verified.not_before <= MAX_AGENT_TTL.as_secs());
    allow_agent_jit(
        verified.flags,
        &verified.dst_cidr,
        verified.proto,
        verified.dst_port,
        app_a(),
    )
    .unwrap();
    assert_eq!(
        allow_agent_jit(
            verified.flags,
            &verified.dst_cidr,
            verified.proto,
            verified.dst_port,
            app_b(),
        )
        .unwrap_err(),
        IdentityError::Denied
    );

    let human = issued.parent.clone();
    assert_eq!(
        sign_agent_jit_ticket(
            &signer,
            &issuer,
            &human,
            now,
            Duration::from_secs(60),
            app_a()
        )
        .unwrap_err(),
        IdentityError::SpiffeId
    );
    assert_eq!(
        sign_agent_jit_ticket(
            &signer,
            &issuer,
            &issued.svid.spiffe_id,
            now,
            MAX_AGENT_TTL + Duration::from_secs(1),
            app_a(),
        )
        .unwrap_err(),
        IdentityError::Time
    );

    let broad = sign_ticket(
        &signer,
        &TicketClaims {
            issuer,
            subject: issued.svid.spiffe_id.clone(),
            not_before: unix(now),
            expires: unix(now) + 60,
            dst_cidr: "10.8.0.0/24".to_string(),
            proto: 6,
            dst_port: 443,
            flags: TicketFlags::none(),
        },
    )
    .unwrap();
    let broad = verify_ticket(&signer.verifier(), &broad.bytes, now, &DenySet::empty()).unwrap();
    assert!(!broad.flags.agent_jit());
    assert_eq!(
        allow_agent_jit(
            broad.flags,
            &broad.dst_cidr,
            broad.proto,
            broad.dst_port,
            app_a()
        )
        .unwrap_err(),
        IdentityError::Denied
    );
    assert_eq!(
        allow_agent_jit(
            broad.flags,
            &broad.dst_cidr,
            broad.proto,
            broad.dst_port,
            app_b()
        )
        .unwrap_err(),
        IdentityError::Denied
    );
}
