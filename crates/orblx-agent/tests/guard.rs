//! The guard checks one proof per connection and writes the audit chain.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use orblx_agent::{
    open_use, seal_use, sign_grant, AgentGrant, GrantDir, GrantFiles, GrantRefresh, GuardConfig,
    GuardCore, GuardDecision, NodeDeny, SignedAgentGrant, UseTarget, UseTrust, GRANT_VERSION,
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
    fixture_signed(ttl, TicketSigner::generate())
}

fn fixture_signed(ttl: u64, signer: TicketSigner) -> Fixture {
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let ca = MiniCa::generate(start).unwrap();
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

/// The ticket seed of the grant sets in the grant directory tests.
const DIR_SEED: [u8; 32] = [5u8; 32];

/// One grant set with a new id and, when given, a new service.
/// It returns the set and its ticket nonce in hex.
fn grant_set(ttl: u64, id: &str, service: Option<&str>) -> (GrantFiles, String) {
    let fixture = fixture_signed(ttl, TicketSigner::from_seed(&DIR_SEED));
    let mut grant = fixture.files.grant.grant.clone();
    grant.id = id.to_string();
    if let Some(service) = service {
        grant.service = service.to_string();
    }
    let files = GrantFiles {
        grant: sign_grant(&fixture.netmap, &grant).unwrap(),
        ..fixture.files
    };
    (files, fixture.nonce_hex)
}

/// A node state directory with a ticket verifier and a deny list.
fn node_state(name: &str, nonces: &[&str]) -> PathBuf {
    let state = temp_path(name).parent().unwrap().to_path_buf();
    std::fs::write(
        state.join("ticket-verifier.pem"),
        TicketSigner::from_seed(&DIR_SEED).public_key_pem(),
    )
    .unwrap();
    write_deny(&state, nonces);
    state
}

fn write_deny(state: &std::path::Path, nonces: &[&str]) {
    let list: Vec<String> = nonces.iter().map(|nonce| format!("\"{nonce}\"")).collect();
    let text = format!(
        r#"{{"version":{},"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":[{}]}}"#,
        nonces.len() + 1,
        list.join(",")
    );
    std::fs::write(state.join("deny.json"), text).unwrap();
}

#[test]
fn a_grant_dir_takes_only_a_complete_newer_grant_with_the_same_scope() {
    let dir = temp_path("grant-dir").with_file_name("grant");
    let state = node_state("grant-dir-state", &[]);
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_001);
    let (first, _) = grant_set(30, "00000000000000a1", None);
    first.write(&dir).unwrap();
    let mut grants = GrantDir::open(&dir, NodeDeny::new(&state)).unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Same);

    // A newer grant with the same scope replaces the current grant.
    let (second, _) = grant_set(60, "00000000000000a2", None);
    second.write(&dir).unwrap();
    assert_eq!(
        grants.refresh_at(now),
        GrantRefresh::Switched {
            from: "00000000000000a1".to_string(),
            to: "00000000000000a2".to_string(),
        }
    );
    assert_eq!(grants.refresh_at(now), GrantRefresh::Same);

    // A mixed set (a write that is not complete) does not replace it.
    let (third, _) = grant_set(90, "00000000000000a3", None);
    third.write(&dir).unwrap();
    std::fs::write(dir.join("ticket.bin"), &second.ticket).unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Kept("incomplete"));
    assert!(GrantFiles::load(&dir).is_err());
    third.write(&dir).unwrap();
    std::fs::write(dir.join("agent.key.pem"), &second.key_pem).unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Kept("incomplete"));
    assert_eq!(grants.files().grant.grant.id, "00000000000000a2");

    // When the write is complete, the agent takes the grant.
    third.write(&dir).unwrap();
    assert!(matches!(
        grants.refresh_at(now),
        GrantRefresh::Switched { .. }
    ));
    assert_eq!(grants.files().grant.grant.id, "00000000000000a3");

    // Another scope or an earlier end does not replace the current grant.
    grant_set(120, "00000000000000b1", Some("db"))
        .0
        .write(&dir)
        .unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Kept("scope"));
    grant_set(40, "00000000000000b2", None)
        .0
        .write(&dir)
        .unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Kept("older"));
    assert_eq!(grants.files().grant.grant.id, "00000000000000a3");
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    let _ = std::fs::remove_dir_all(&state);
}

/// W25-30 gate: a revoked next grant is never taken, and the check fails closed.
#[test]
fn a_grant_dir_never_takes_a_revoked_next_grant() {
    let dir = temp_path("grant-revoked").with_file_name("grant");
    let state = node_state("grant-revoked-state", &[]);
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_001);
    let (first, _) = grant_set(30, "00000000000000c1", None);
    first.write(&dir).unwrap();
    let mut grants = GrantDir::open(&dir, NodeDeny::new(&state)).unwrap();

    // The deny list holds the ticket nonce of the next grant.
    let (revoked, nonce) = grant_set(60, "00000000000000c2", None);
    write_deny(&state, &[&nonce]);
    revoked.write(&dir).unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Kept("revoked"));
    assert_eq!(grants.refresh_at(now), GrantRefresh::Same);
    assert_eq!(grants.files().grant.grant.id, "00000000000000c1");

    // With no deny list, the agent keeps the current grant and checks again later.
    std::fs::remove_file(state.join("deny.json")).unwrap();
    let (next, _) = grant_set(90, "00000000000000c3", None);
    next.write(&dir).unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Kept("deny-unknown"));
    assert_eq!(grants.files().grant.grant.id, "00000000000000c1");

    // A ticket from another signer is not taken.
    write_deny(&state, &[]);
    let (other, _) = fixture_with_other_signer(120, "00000000000000c4");
    other.write(&dir).unwrap();
    assert_eq!(grants.refresh_at(now), GrantRefresh::Kept("ticket"));

    // A good grant after the deny list is back is taken.
    next.write(&dir).unwrap();
    assert!(matches!(
        grants.refresh_at(now),
        GrantRefresh::Switched { .. }
    ));
    assert_eq!(grants.files().grant.grant.id, "00000000000000c3");
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    let _ = std::fs::remove_dir_all(&state);
}

fn fixture_with_other_signer(ttl: u64, id: &str) -> (GrantFiles, String) {
    let fixture = fixture(ttl);
    let mut grant = fixture.files.grant.grant.clone();
    grant.id = id.to_string();
    let files = GrantFiles {
        grant: sign_grant(&fixture.netmap, &grant).unwrap(),
        ..fixture.files
    };
    (files, fixture.nonce_hex)
}

fn percentile_line(name: &str, values: &mut [f64]) -> String {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |p: f64| {
        let index = ((p / 100.0) * values.len() as f64).ceil() as usize;
        values[index.clamp(1, values.len()) - 1]
    };
    format!(
        "admit_cost {name}_ms p50 {:.3} p90 {:.3} p99 {:.3} max {:.3} n {}",
        pick(50.0),
        pick(90.0),
        pick(99.0),
        values[values.len() - 1],
        values.len()
    )
}

/// W25-39 diagnostic: the cost of each part of one guard admit, in this build profile.
///
/// Run: `ORBLX_ADMIT_COST_DIR=DIR cargo test [--release] -p orblx-agent --test guard admit_cost -- --ignored --nocapture`.
/// DIR must be on the disk under test. The test deletes only its own files in DIR.
#[test]
#[ignore = "diagnostic measurement"]
fn admit_cost() {
    const ROUNDS: usize = 300;
    let base = std::env::var_os("ORBLX_ADMIT_COST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("orblx-admit-cost-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let fixture = fixture(30);
    let core = core(&fixture, base.join("agent-audit.jsonl"));
    let at = after(&fixture, 1000);
    core.apply_deny(EMPTY_DENY, at).unwrap();
    let (mut seal_ms, mut open_ms, mut admit_ms, mut sync_data_ms, mut sync_all_ms) =
        (vec![], vec![], vec![], vec![], vec![]);
    let ms = |start: std::time::Instant| start.elapsed().as_secs_f64() * 1000.0;
    for _ in 0..ROUNDS {
        let start = std::time::Instant::now();
        let line = seal(&fixture, "web", PORT, at);
        seal_ms.push(ms(start));
        let start = std::time::Instant::now();
        open(&fixture, &line, "web", PORT, &DenySet::empty(), at).unwrap();
        open_ms.push(ms(start));
        let start = std::time::Instant::now();
        let decision = core.admit(&line, "web", PORT, &[], peer(), at).unwrap();
        admit_ms.push(ms(start));
        assert!(matches!(decision, GuardDecision::Admit(_)));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(base.join("sync-probe"))
        .unwrap();
    for _ in 0..ROUNDS {
        use std::io::Write as _;
        file.write_all(&[b'x'; 200]).unwrap();
        let start = std::time::Instant::now();
        file.sync_data().unwrap();
        sync_data_ms.push(ms(start));
        file.write_all(&[b'y'; 200]).unwrap();
        let start = std::time::Instant::now();
        file.sync_all().unwrap();
        sync_all_ms.push(ms(start));
    }
    let thirds: Vec<String> = admit_ms
        .chunks(ROUNDS / 3)
        .map(|part| format!("{:.3}", part.iter().sum::<f64>() / part.len() as f64))
        .collect();
    println!("admit_cost admit_mean_ms_by_third {}", thirds.join(" "));
    println!(
        "admit_cost profile {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("{}", percentile_line("seal", &mut seal_ms));
    println!("{}", percentile_line("open_use", &mut open_ms));
    println!("{}", percentile_line("admit", &mut admit_ms));
    println!("{}", percentile_line("sync_data", &mut sync_data_ms));
    println!("{}", percentile_line("sync_all", &mut sync_all_ms));
    std::fs::remove_dir_all(&base).unwrap();
}
