//! The guard checks one proof per connection and writes the audit chain.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use orblx_agent::{
    open_use, seal_use, sign_grant, AgentGrant, GrantFiles, GuardConfig, GuardCore, GuardDecision,
    SignedAgentGrant, UseTarget, UseTrust, GRANT_VERSION,
};
use orblx_audit::{verify_config_file, ConfigAction, DenyReason};
use orblx_identity::{
    sign_agent_jit_ticket, ticket_hash, DenySet, Ipv4Destination, MiniCa, SpiffeId, TicketSigner,
};

const ADDR: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const PORT: u16 = 8080;

struct Fixture {
    ca: MiniCa,
    signer: TicketSigner,
    netmap: SigningKey,
    node: SpiffeId,
    files: GrantFiles,
    start: SystemTime,
    nonce_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixture(ttl: u64) -> Fixture {
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let ca = MiniCa::generate(start).unwrap();
    let signer = TicketSigner::generate();
    let netmap = SigningKey::from_bytes(&[7u8; 32]);
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
        id: "0123456789abcdef".to_string(),
        agent: agent.as_uri().to_string(),
        requester: SpiffeId::node("a").unwrap().as_uri().to_string(),
        approver: SpiffeId::node("owner").unwrap().as_uri().to_string(),
        node: node.as_uri().to_string(),
        addr: ADDR.to_string(),
        service: "web".to_string(),
        port: PORT,
        path_prefix: "/".to_string(),
        not_before: now,
        expires: now + ttl,
        ticket_hash: hex(&ticket_hash(&ticket.bytes)),
    };
    let signed: SignedAgentGrant = sign_grant(&netmap, &grant).unwrap();
    Fixture {
        nonce_hex: hex(&ticket.nonce),
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

fn seal(fixture: &Fixture, service: &str, port: u16, at: SystemTime) -> String {
    let target = UseTarget {
        node: &fixture.node,
        addr: ADDR,
        service,
        port,
    };
    seal_use(
        &fixture.files.key_pem,
        &fixture.files.cert_pem,
        &fixture.files.ticket,
        &fixture.files.grant,
        target,
        &[],
        at,
    )
    .unwrap()
}

fn open(
    fixture: &Fixture,
    line: &str,
    service: &str,
    port: u16,
    deny: &DenySet,
    at: SystemTime,
) -> Result<(), DenyReason> {
    let verifier = fixture.signer.verifier();
    let public = fixture.netmap.verifying_key().to_bytes();
    let target = UseTarget {
        node: &fixture.node,
        addr: ADDR,
        service,
        port,
    };
    let trust = UseTrust {
        bundle: fixture.ca.trust_bundle(),
        verifier: &verifier,
        netmap_public: &public,
        deny,
    };
    open_use(line, target, trust, &[], at)
        .map(|_| ())
        .map_err(|refused| refused.reason)
}

fn after(fixture: &Fixture, millis: u64) -> SystemTime {
    fixture.start + Duration::from_millis(millis)
}

#[test]
fn a_valid_proof_is_admitted() {
    let fixture = fixture(30);
    let at = after(&fixture, 1000);
    let line = seal(&fixture, "web", PORT, at);
    assert_eq!(
        open(&fixture, &line, "web", PORT, &DenySet::empty(), at),
        Ok(())
    );
}

#[test]
fn another_port_or_service_is_refused() {
    let fixture = fixture(30);
    let at = after(&fixture, 1000);
    let other_port = seal(&fixture, "web", 5432, at);
    assert_eq!(
        open(&fixture, &other_port, "web", 5432, &DenySet::empty(), at),
        Err(DenyReason::Destination)
    );
    let other_service = seal(&fixture, "db", PORT, at);
    assert_eq!(
        open(&fixture, &other_service, "db", PORT, &DenySet::empty(), at),
        Err(DenyReason::Destination)
    );
    // A proof for the granted port does not pass on a guard for another port.
    let granted = seal(&fixture, "web", PORT, at);
    assert!(open(&fixture, &granted, "web", 5432, &DenySet::empty(), at).is_err());
}

#[test]
fn the_end_time_is_strict_in_milliseconds() {
    let fixture = fixture(30);
    let last = after(&fixture, 29_999);
    let line = seal(&fixture, "web", PORT, last);
    assert_eq!(
        open(&fixture, &line, "web", PORT, &DenySet::empty(), last),
        Ok(())
    );
    let end = after(&fixture, 30_000);
    let line = seal(&fixture, "web", PORT, end);
    assert_eq!(
        open(&fixture, &line, "web", PORT, &DenySet::empty(), end),
        Err(DenyReason::Expired)
    );
}

#[test]
fn a_revoked_agent_or_nonce_is_refused() {
    let fixture = fixture(30);
    let at = after(&fixture, 1000);
    let line = seal(&fixture, "web", PORT, at);
    let mut by_uri = DenySet::empty();
    by_uri
        .apply_json(
            br#"{"version":1,"generated_at":1,"revoked_uris":["spiffe://orblx.local/agent/bot"],"revoked_ticket_nonces":[]}"#,
        )
        .unwrap();
    assert_eq!(
        open(&fixture, &line, "web", PORT, &by_uri, at),
        Err(DenyReason::Revoked)
    );
    let mut by_nonce = DenySet::empty();
    let text = format!(
        r#"{{"version":1,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":["{}"]}}"#,
        fixture.nonce_hex
    );
    by_nonce.apply_json(text.as_bytes()).unwrap();
    assert!(open(&fixture, &line, "web", PORT, &by_nonce, at).is_err());
}

#[test]
fn a_bad_line_is_missing_and_a_changed_grant_is_refused() {
    let fixture = fixture(30);
    let at = after(&fixture, 1000);
    assert_eq!(
        open(&fixture, "", "web", PORT, &DenySet::empty(), at),
        Err(DenyReason::Missing)
    );
    let mut changed = fixture.files.grant.clone();
    changed.grant.port = 5432;
    let changed_fixture = Fixture {
        files: GrantFiles {
            grant: changed,
            cert_pem: fixture.files.cert_pem.clone(),
            key_pem: fixture.files.key_pem.clone(),
            ticket: fixture.files.ticket.clone(),
        },
        ca: fixture.ca,
        signer: fixture.signer,
        netmap: fixture.netmap,
        node: fixture.node,
        start: fixture.start,
        nonce_hex: fixture.nonce_hex,
    };
    let line = seal(&changed_fixture, "web", 5432, at);
    assert_eq!(
        open(&changed_fixture, &line, "web", 5432, &DenySet::empty(), at),
        Err(DenyReason::Ticket)
    );
}

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orblx-agent-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("agent-audit.jsonl")
}

fn core(fixture: &Fixture, audit: PathBuf) -> GuardCore {
    let config = GuardConfig {
        listen: SocketAddr::from((ADDR, PORT)),
        service: "web".to_string(),
        target: SocketAddr::from(([127, 0, 0, 1], 9)),
        node: fixture.node.clone(),
        bundle: fixture.ca.trust_bundle().clone(),
        verifier: fixture.signer.verifier(),
        netmap_public: fixture.netmap.verifying_key().to_bytes(),
        audit_path: audit,
        nonce_path: None,
        poll: Duration::from_millis(200),
        stale_after: Duration::from_secs(2),
    };
    GuardCore::new(&config).unwrap()
}

const EMPTY_DENY: &str =
    r#"{"version":1,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":[]}"#;

fn peer() -> SocketAddr {
    SocketAddr::from(([100, 64, 0, 1], 40000))
}

#[test]
fn the_guard_logs_grant_use_deny_expiry_and_revoke() {
    let fixture = fixture(30);
    let audit = temp_path("chain");
    let core = core(&fixture, audit.clone());
    let at = after(&fixture, 1000);
    core.apply_deny(EMPTY_DENY, at).unwrap();
    let line = seal(&fixture, "web", PORT, at);
    let decision = core.admit(&line, "web", PORT, &[], peer(), at).unwrap();
    assert!(matches!(decision, GuardDecision::Admit(_)));
    let decision = core.admit("", "web", PORT, &[], peer(), at).unwrap();
    assert!(matches!(decision, GuardDecision::Refuse("missing")));
    let revoke_at = after(&fixture, 2000);
    let revoke = format!(
        r#"{{"version":2,"generated_at":2,"revoked_uris":["spiffe://orblx.local/agent/bot"],"revoked_ticket_nonces":["{}"]}}"#,
        fixture.nonce_hex
    );
    core.apply_deny(&revoke, revoke_at).unwrap();
    let line = seal(&fixture, "web", PORT, revoke_at);
    let decision = core
        .admit(&line, "web", PORT, &[], peer(), revoke_at)
        .unwrap();
    assert!(matches!(decision, GuardDecision::Refuse("revoked")));
    let end = after(&fixture, 30_000);
    core.apply_deny(&revoke, end).unwrap();
    core.tick(end).unwrap();
    let verified = verify_config_file(&audit).unwrap();
    let text = std::fs::read_to_string(&audit).unwrap();
    for action in [
        ConfigAction::AgentGrant,
        ConfigAction::AgentUse,
        ConfigAction::AgentDeny,
        ConfigAction::AgentExpire,
        ConfigAction::AgentRevoke,
    ] {
        assert!(
            text.contains(&format!("\"{}\"", action.as_str())),
            "the chain has no {} record",
            action.as_str()
        );
    }
    assert!(verified.records.len() >= 6);
    // The chain holds no key or ticket bytes.
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains(&hex(&fixture.files.ticket)));
}

#[test]
fn a_stale_deny_set_refuses_each_use() {
    let fixture = fixture(30);
    let core = core(&fixture, temp_path("stale"));
    let at = after(&fixture, 1000);
    let line = seal(&fixture, "web", PORT, at);
    // No deny read yet.
    let decision = core.admit(&line, "web", PORT, &[], peer(), at).unwrap();
    assert!(matches!(decision, GuardDecision::Refuse("stale")));
    core.apply_deny(EMPTY_DENY, at).unwrap();
    let later = after(&fixture, 3500);
    let line = seal(&fixture, "web", PORT, later);
    let decision = core.admit(&line, "web", PORT, &[], peer(), later).unwrap();
    assert!(matches!(decision, GuardDecision::Refuse("stale")));
}
