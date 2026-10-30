//! The gateway checks one request with a grant proof, a nonce, and a path scope.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use orblx_agent::{
    check_request, parse_request, plain_http_request, seal_http_request, sign_grant, AgentGrant,
    GatewayDecision, GrantFiles, GuardConfig, GuardCore, GRANT_VERSION,
};
use orblx_audit::{verify_config_file, ConfigAction};
use orblx_identity::{
    sign_agent_jit_ticket, ticket_hash, DenySet, Ipv4Destination, MiniCa, SpiffeId, TicketSigner,
};

const ADDR: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
const PORT: u16 = 8080;
const EMPTY_DENY: &str =
    r#"{"version":1,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":[]}"#;

struct Fixture {
    ca: MiniCa,
    signer: TicketSigner,
    netmap: SigningKey,
    node: SpiffeId,
    files: GrantFiles,
    start: SystemTime,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixture(ttl: u64) -> Fixture {
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let ca = MiniCa::generate(start).unwrap();
    let signer = TicketSigner::generate();
    let netmap = SigningKey::from_bytes(&[9u8; 32]);
    let node = SpiffeId::node("b").unwrap();
    let agent = SpiffeId::agent("bot").unwrap();
    let coord = SpiffeId::coord("coord").unwrap();
    let svid = ca
        .issue(&agent, start, Duration::from_secs(ttl), &DenySet::empty())
        .unwrap();
    let dest = Ipv4Destination {
        addr: ADDR,
        proto: 6,
        port: PORT,
    };
    let ticket = sign_agent_jit_ticket(
        &signer,
        &coord,
        &agent,
        start,
        Duration::from_secs(ttl),
        dest,
    )
    .unwrap();
    let now = start.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let grant = AgentGrant {
        version: GRANT_VERSION,
        id: "fedcba9876543210".to_string(),
        agent: agent.as_uri().to_string(),
        requester: SpiffeId::node("a").unwrap().as_uri().to_string(),
        approver: SpiffeId::node("owner").unwrap().as_uri().to_string(),
        node: node.as_uri().to_string(),
        addr: ADDR.to_string(),
        service: "api".to_string(),
        port: PORT,
        path_prefix: "/api".to_string(),
        not_before: now,
        expires: now + ttl,
        ticket_hash: hex(&ticket_hash(&ticket.bytes)),
    };
    let signed = sign_grant(&netmap, &grant).unwrap();
    Fixture {
        files: GrantFiles {
            cert_pem: svid.certificate_pem,
            key_pem: svid.private_key_pem,
            ticket: ticket.bytes,
            grant: signed,
        },
        ca,
        signer,
        netmap,
        node,
        start,
    }
}

fn after(fixture: &Fixture, millis: u64) -> SystemTime {
    fixture.start + Duration::from_millis(millis)
}

fn core(fixture: &Fixture, name: &str) -> (GuardCore, PathBuf) {
    let dir = std::env::temp_dir().join(format!("orblx-gw-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("gateway-audit.jsonl");
    (open_core(fixture, &audit).unwrap(), audit)
}

fn open_core(
    fixture: &Fixture,
    audit: &std::path::Path,
) -> Result<GuardCore, orblx_agent::AgentError> {
    let config = GuardConfig {
        listen: SocketAddr::from((ADDR, PORT)),
        service: "api".to_string(),
        target: SocketAddr::from(([127, 0, 0, 1], 9)),
        node: fixture.node.clone(),
        bundle: fixture.ca.trust_bundle().clone(),
        verifier: fixture.signer.verifier(),
        netmap_public: fixture.netmap.verifying_key().to_bytes(),
        audit_path: audit.to_path_buf(),
        nonce_path: Some(nonce_path(audit)),
        poll: Duration::from_millis(200),
        stale_after: Duration::from_secs(2),
    };
    GuardCore::new(&config)
}

fn nonce_path(audit: &std::path::Path) -> PathBuf {
    audit.with_file_name("gateway-nonces.log")
}

fn peer() -> SocketAddr {
    SocketAddr::from(([100, 64, 0, 2], 40000))
}

fn to() -> SocketAddr {
    SocketAddr::from((ADDR, PORT))
}

fn sealed(
    fixture: &Fixture,
    service: &str,
    method: &str,
    target: &str,
    nonce: u8,
    at: SystemTime,
) -> Vec<u8> {
    sealed_with(fixture, service, method, target, &[], nonce, at)
}

fn sealed_with(
    fixture: &Fixture,
    service: &str,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    nonce: u8,
    at: SystemTime,
) -> Vec<u8> {
    seal_http_request(
        &fixture.files,
        to(),
        &fixture.node,
        service,
        method,
        target,
        headers,
        b"",
        [nonce; 16],
        at,
    )
    .unwrap()
}

fn decide(core: &GuardCore, bytes: &[u8], at: SystemTime) -> GatewayDecision {
    let (head, body) = parse_request(bytes).unwrap();
    check_request(core, &head, &body, "api", PORT, peer(), at).unwrap()
}

#[test]
fn the_gateway_admits_scope_and_refuses_the_rest() {
    let fixture = fixture(30);
    let (core, audit) = core(&fixture, "all");
    let at = after(&fixture, 1000);
    core.apply_deny(EMPTY_DENY, at).unwrap();

    let ok = sealed(&fixture, "api", "GET", "/api/items?q=1", 1, at);
    assert!(matches!(
        decide(&core, &ok, at),
        GatewayDecision::Forward(_, _)
    ));
    // The same bytes again: replay.
    assert_eq!(
        decide(&core, &ok, at),
        GatewayDecision::Refuse(403, "replay")
    );
    // No proof.
    let plain = plain_http_request(to(), "GET", "/api/items", b"");
    assert_eq!(
        decide(&core, &plain, at),
        GatewayDecision::Refuse(403, "missing")
    );
    // Path out of scope, and a dot part.
    for (nonce, target) in [(2u8, "/admin"), (3, "/apix"), (4, "/api/../admin")] {
        let bytes = sealed(&fixture, "api", "GET", target, nonce, at);
        assert_eq!(
            decide(&core, &bytes, at),
            GatewayDecision::Refuse(403, "path")
        );
    }
    // A proof for another service.
    let other = sealed(&fixture, "db", "GET", "/api/items", 5, at);
    assert_eq!(
        decide(&core, &other, at),
        GatewayDecision::Refuse(403, "ticket")
    );
    // A changed method or path does not match the signed request.
    let mut changed = sealed(&fixture, "api", "GET", "/api/items", 6, at);
    changed[..3].copy_from_slice(b"PUT");
    assert_eq!(
        decide(&core, &changed, at),
        GatewayDecision::Refuse(403, "ticket")
    );
    // At the end time: expired.
    let end = after(&fixture, 30_000);
    core.apply_deny(EMPTY_DENY, end).unwrap();
    let late = sealed(&fixture, "api", "GET", "/api/items", 7, end);
    assert_eq!(
        decide(&core, &late, end),
        GatewayDecision::Refuse(403, "expired")
    );
    core.tick(end).unwrap();

    let verified = verify_config_file(&audit).unwrap();
    let text = std::fs::read_to_string(&audit).unwrap();
    for action in [
        ConfigAction::AgentGrant,
        ConfigAction::AgentUse,
        ConfigAction::AgentDeny,
        ConfigAction::AgentExpire,
    ] {
        assert!(text.contains(&format!("\"{}\"", action.as_str())));
    }
    // 1 grant, 1 use, 8 deny, 1 expire.
    assert_eq!(verified.records.len(), 11);
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains(&hex(&fixture.files.ticket)));
    assert!(!text.contains("q=1"));
}

#[test]
fn a_bad_nonce_is_refused_and_recorded() {
    let fixture = fixture(30);
    let (core, audit) = core(&fixture, "nonce");
    let at = after(&fixture, 1000);
    core.apply_deny(EMPTY_DENY, at).unwrap();
    let bytes = sealed(&fixture, "api", "GET", "/api", 1, at);
    let text = String::from_utf8(bytes).unwrap();
    let start = text.find("orblx-agent-nonce: ").unwrap() + "orblx-agent-nonce: ".len();
    let mut changed = text.clone();
    changed.replace_range(start..start + 32, "zz");
    assert_eq!(
        decide(&core, changed.as_bytes(), at),
        GatewayDecision::Refuse(403, "nonce")
    );
    // Another valid nonce breaks the signature.
    let mut other = text.clone();
    other.replace_range(start..start + 32, &"02".repeat(16));
    assert_eq!(
        decide(&core, other.as_bytes(), at),
        GatewayDecision::Refuse(403, "ticket")
    );
    assert_eq!(verify_config_file(&audit).unwrap().records.len(), 2);
}

#[test]
fn a_restart_keeps_the_used_nonces() {
    let fixture = fixture(60);
    let (first, audit) = core(&fixture, "restart");
    let at = after(&fixture, 1000);
    first.apply_deny(EMPTY_DENY, at).unwrap();
    let bytes = sealed(&fixture, "api", "GET", "/api/items", 1, at);
    assert!(matches!(
        decide(&first, &bytes, at),
        GatewayDecision::Forward(_, _)
    ));
    drop(first);
    // A new process reads the use records from the chain. The nonce file is
    // gone here, so this checks the W22-1 chain path alone.
    std::fs::remove_file(nonce_path(&audit)).unwrap();
    let second = open_core(&fixture, &audit).unwrap();
    assert_eq!(second.seen_count(), 1);
    let later = after(&fixture, 5000);
    second.apply_deny(EMPTY_DENY, later).unwrap();
    assert_eq!(
        decide(&second, &bytes, later),
        GatewayDecision::Refuse(403, "replay")
    );
    // A new nonce still works.
    let fresh = sealed(&fixture, "api", "GET", "/api/items", 2, later);
    assert!(matches!(
        decide(&second, &fresh, later),
        GatewayDecision::Forward(_, _)
    ));
    drop(second);
    assert!(verify_config_file(&audit).is_ok());
    // A changed chain stops the start.
    let text = std::fs::read_to_string(&audit).unwrap();
    std::fs::write(&audit, text.replacen("agent-use", "agent-deny", 1)).unwrap();
    assert!(open_core(&fixture, &audit).is_err());
}

#[test]
fn a_restart_without_the_audit_file_keeps_the_used_nonces() {
    let fixture = fixture(60);
    let (first, audit) = core(&fixture, "noaudit");
    let at = after(&fixture, 1000);
    first.apply_deny(EMPTY_DENY, at).unwrap();
    let bytes = sealed(&fixture, "api", "GET", "/api/items", 1, at);
    assert!(matches!(
        decide(&first, &bytes, at),
        GatewayDecision::Forward(_, _)
    ));
    drop(first);
    std::fs::remove_file(&audit).unwrap();
    let nonces = std::fs::read_to_string(nonce_path(&audit)).unwrap();
    assert_eq!(nonces.lines().count(), 1);
    assert!(!nonces.contains(&hex(&fixture.files.ticket)));
    // A new process with a new, empty chain reads the nonce file.
    let second = open_core(&fixture, &audit).unwrap();
    assert_eq!(second.seen_count(), 1);
    let later = after(&fixture, 5000);
    second.apply_deny(EMPTY_DENY, later).unwrap();
    assert_eq!(
        decide(&second, &bytes, later),
        GatewayDecision::Refuse(403, "replay")
    );
    drop(second);
    // A bad nonce file stops the start (fail closed).
    std::fs::write(nonce_path(&audit), "not valid\n").unwrap();
    assert!(open_core(&fixture, &audit).is_err());
}

#[test]
fn a_changed_header_is_refused() {
    let fixture = fixture(30);
    let (core, _audit) = core(&fixture, "header");
    let at = after(&fixture, 1000);
    core.apply_deny(EMPTY_DENY, at).unwrap();
    let kind = vec![("X-Kind".to_string(), "read".to_string())];
    let base = |nonce: u8| {
        String::from_utf8(sealed_with(
            &fixture,
            "api",
            "GET",
            "/api/items",
            &kind,
            nonce,
            at,
        ))
        .unwrap()
    };
    let cases: [(u8, &dyn Fn(String) -> String); 5] = [
        (1, &|text| text.replace("x-kind: read", "x-kind: write")),
        (2, &|text| text.replace("x-kind: read\r\n", "")),
        (3, &|text| {
            text.replace("x-kind: read\r\n", "x-kind: read\r\nx-extra: 1\r\n")
        }),
        (4, &|text| text.replacen("host: 100.", "host: 101.", 1)),
        (5, &|text| text.replacen("HTTP/1.1", "HTTP/1.0", 1)),
    ];
    for (nonce, change) in cases {
        let original = base(nonce);
        let changed = change(original.clone());
        assert_ne!(changed, original);
        assert_eq!(
            decide(&core, changed.as_bytes(), at),
            GatewayDecision::Refuse(403, "ticket")
        );
    }
    // The bytes as sealed pass, and a name case change keeps the meaning.
    let ok = base(6).replace("x-kind: read", "X-KIND: read");
    assert!(matches!(
        decide(&core, ok.as_bytes(), at),
        GatewayDecision::Forward(_, _)
    ));
}
