//! W25-1 node sharing on the coordinator state.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use orblx_audit::{verify_config_file, ConfigAction, EMPTY_DIGEST};
use orblx_identity::{DenySet, IssueGate, MiniCa, MockOidc, SpiffeId, MOCK_OIDC_ISSUER};

use crate::state::{Coordinator, OidcConfig, CONFIG_AUDIT_FILE};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orblx-share-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const SHARED: &str = r#"{
  "guests": ["oidc:bob"],
  "acls": [
    {"action": "accept", "src": ["spiffe://orblx.local/node/a"], "dst": ["spiffe://orblx.local/node/b:*", "spiffe://orblx.local/node/g:*"]},
    {"action": "accept", "src": ["spiffe://orblx.local/node/g"], "dst": ["spiffe://orblx.local/node/g2:*"]},
  ],
  "shares": [
    {"dst": "spiffe://orblx.local/node/b:8080", "proto": "tcp", "with": ["oidc:bob"]},
  ],
}"#;

fn peers(coord: &Coordinator, name: &str) -> Vec<String> {
    let view = coord.netmap_for(name).unwrap();
    let mut names: Vec<String> = view
        .signed_netmap
        .netmap
        .peers
        .iter()
        .map(|peer| peer.name.clone())
        .collect();
    names.sort();
    names
}

fn deny_for(coord: &Coordinator, name: &str) -> DenySet {
    let text = crate::admin::deny_json_for(coord, name, SystemTime::now()).unwrap();
    let mut deny = DenySet::empty();
    deny.apply_json(text.as_bytes()).unwrap();
    deny
}

fn denied(deny: &DenySet, name: &str) -> bool {
    deny.reject_uri(&SpiffeId::node(name).unwrap()).is_err()
}

#[test]
fn a_guest_sees_only_the_shared_node_and_each_share_change_writes_one_record() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    fs::write(scratch.0.join("policy.hujson"), SHARED).unwrap();
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
    coord.enable_config_audit().unwrap();
    for name in ["a", "b"] {
        let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        coord
            .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
            .unwrap();
    }
    let id_token = oidc
        .issue_id_token("bob", now, Duration::from_secs(600))
        .unwrap();
    coord
        .approve_user_by("oidc:bob", "spiffe://orblx.local/node/owner", now)
        .unwrap();
    for name in ["g", "g2"] {
        coord
            .enroll_oidc(name, &id_token, None, &[format!("{name}:443")], &[], now)
            .unwrap();
    }

    // Gate 1 and 2: the guest sees the shared node and its own nodes only.
    assert_eq!(peers(&coord, "g"), vec!["b", "g2"]);
    assert_eq!(peers(&coord, "a"), vec!["b"]);
    assert_eq!(peers(&coord, "b"), vec!["a", "g", "g2"]);
    let g_view = coord.netmap_for("g").unwrap();
    let g_grants = &g_view.signed_grants.grants;
    assert!(g_grants
        .reach
        .contains(&"spiffe://orblx.local/node/b".to_string()));
    assert!(!g_grants.reach.iter().any(|dst| dst.ends_with("/node/a")));
    let b_grants = coord.netmap_for("b").unwrap().signed_grants.grants;
    let b_from_g: Vec<_> = b_grants
        .grants
        .iter()
        .filter(|grant| grant.src.ends_with("/node/g"))
        .collect();
    assert_eq!(b_from_g.len(), 1);
    assert_eq!(
        (
            b_from_g[0].proto,
            b_from_g[0].port_start,
            b_from_g[0].port_end
        ),
        (6, 8080, 8080)
    );
    // W25-1b: each node guards the peers of another tenant that it sees.
    // Their packets need a grant also when the policy has no `acls` list.
    let uri = |name: &str| format!("spiffe://orblx.local/node/{name}");
    assert_eq!(b_grants.guarded, vec![uri("g"), uri("g2")]);
    assert_eq!(g_grants.guarded, vec![uri("b")]);
    assert!(coord
        .netmap_for("a")
        .unwrap()
        .signed_grants
        .grants
        .guarded
        .is_empty());
    // Gate 3: the acl a -> g gives no grant, because g is not shared with a.
    // The acl g -> g2 stays, because g and g2 are in the same tenant.
    let g2_grants = coord.netmap_for("g2").unwrap().signed_grants.grants;
    assert!(g2_grants
        .grants
        .iter()
        .any(|grant| grant.src.ends_with("/node/g")));
    assert!(g_grants
        .grants
        .iter()
        .all(|grant| !grant.src.ends_with("/node/a")));
    let a_view = coord.netmap_for("a").unwrap();
    assert!(!a_view
        .signed_grants
        .grants
        .reach
        .iter()
        .any(|dst| dst.ends_with("/node/g")));

    let g_deny = deny_for(&coord, "g");
    assert!(denied(&g_deny, "a"));
    assert!(!denied(&g_deny, "b"));
    assert!(!denied(&g_deny, "g2"));
    let a_deny = deny_for(&coord, "a");
    assert!(denied(&a_deny, "g") && denied(&a_deny, "g2"));
    assert!(!denied(&a_deny, "b"));
    let b_deny = deny_for(&coord, "b");
    assert!(!denied(&b_deny, "g"));
    let b_version = b_deny.version();

    // Unshare: one record. b now denies g, a and b still work, g and g2 still work.
    let path = scratch.0.join(CONFIG_AUDIT_FILE);
    let before = verify_config_file(&path).unwrap().records.len();
    let unshared = SHARED.replace(
        r#"{"dst": "spiffe://orblx.local/node/b:8080", "proto": "tcp", "with": ["oidc:bob"]},"#,
        "",
    );
    fs::write(scratch.0.join("policy.hujson"), &unshared).unwrap();
    let b_deny = deny_for(&coord, "b");
    assert!(b_deny.version() > b_version);
    assert!(denied(&b_deny, "g") && denied(&b_deny, "g2"));
    assert!(!denied(&b_deny, "a"));
    assert!(!denied(&deny_for(&coord, "g"), "g2"));
    assert_eq!(peers(&coord, "g"), vec!["g2"]);
    assert!(coord
        .netmap_for("g")
        .unwrap()
        .signed_grants
        .grants
        .guarded
        .is_empty());
    let checked = verify_config_file(&path).unwrap();
    assert_eq!(checked.records.len(), before + 1);
    let unshare = &checked.records.last().unwrap().event;
    assert_eq!(unshare.action, ConfigAction::Unshare);
    assert_eq!(unshare.target, "spiffe://orblx.local/node/b");
    assert_eq!(
        unshare.detail,
        "spiffe://orblx.local/node/b tcp 8080 with oidc:bob"
    );
    assert_eq!(unshare.after, EMPTY_DIGEST);

    // Share again: one record.
    fs::write(scratch.0.join("policy.hujson"), SHARED).unwrap();
    assert_eq!(peers(&coord, "g"), vec!["b", "g2"]);
    let checked = verify_config_file(&path).unwrap();
    assert_eq!(checked.records.len(), before + 2);
    let share = &checked.records.last().unwrap().event;
    assert_eq!(share.action, ConfigAction::Share);
    assert_eq!(share.before, EMPTY_DIGEST);
    assert_eq!(share.after, unshare.before);

    // A rule change writes one policy-replace record and no share record.
    let rules = SHARED.replace("node/g2:*", "node/g2:22");
    fs::write(scratch.0.join("policy.hujson"), &rules).unwrap();
    let _ = coord.node_list().unwrap();
    let checked = verify_config_file(&path).unwrap();
    assert_eq!(checked.records.len(), before + 3);
    assert_eq!(
        checked.records.last().unwrap().event.action,
        ConfigAction::PolicyReplace
    );
    let report = crate::admin::audit(&coord, None).unwrap();
    assert_eq!(report["verify"]["ok"], true);
}

#[test]
fn share_back_lets_one_owner_node_reach_one_guest_node() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let policy = SHARED.replace(
        r#"  ],
}"#,
        r#"    {"dst": "spiffe://orblx.local/node/g:22", "proto": "tcp", "with": ["spiffe://orblx.local/node/a"]},
  ],
}"#,
    );
    fs::write(scratch.0.join("policy.hujson"), &policy).unwrap();
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
    coord.enable_config_audit().unwrap();
    let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    coord
        .enroll_token("a", &token.secret, &["a:443".to_string()], &[], now)
        .unwrap();
    let id_token = oidc
        .issue_id_token("bob", now, Duration::from_secs(600))
        .unwrap();
    coord
        .approve_user_by("oidc:bob", "spiffe://orblx.local/node/owner", now)
        .unwrap();
    for name in ["g", "g2"] {
        coord
            .enroll_oidc(name, &id_token, None, &[format!("{name}:443")], &[], now)
            .unwrap();
    }
    assert_eq!(peers(&coord, "a"), vec!["g"]);
    assert_eq!(peers(&coord, "g"), vec!["a", "g2"]);
    assert_eq!(peers(&coord, "g2"), vec!["g"]);
    let g_grants = coord.netmap_for("g").unwrap().signed_grants.grants;
    let from_a: Vec<_> = g_grants
        .grants
        .iter()
        .filter(|grant| grant.src.ends_with("/node/a"))
        .map(|grant| (grant.proto, grant.port_start, grant.port_end))
        .collect();
    // The acl a -> g:* does not cross the tenant. Only the share-back port is granted.
    assert_eq!(from_a, vec![(6, 22, 22)]);
    assert!(denied(&deny_for(&coord, "g2"), "a"));
}

/// A config record that does not change the revoked set must not publish a new deny document.
///
/// `revoke_all` writes `deny.json` and then the audit record. `stamp_tick` wakes on
/// either file. The served version used to add the audit length, so the waiter saw
/// version N and then N+1 with the same URIs, nonces, and `generated_at`.
#[test]
fn a_config_record_keeps_the_deny_document_when_the_set_is_the_same() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    coord
        .enroll_token("a", &token.secret, &["a:443".to_string()], &[], now)
        .unwrap();
    let first = crate::admin::deny_json_for(&coord, "a", now).unwrap();
    coord
        .record_change(
            "spiffe://orblx.local/node/owner",
            ConfigAction::Revoke,
            "spiffe://orblx.local/node/a",
            EMPTY_DIGEST,
            EMPTY_DIGEST,
            "record only",
        )
        .unwrap();
    let second = crate::admin::deny_json_for(&coord, "a", now).unwrap();
    assert_eq!(first, second);
}

/// A restart serves a deny version that is at least as high as every version served before it.
///
/// Each served version is at most `deny.json` version plus the audit length. The audit
/// length is `next_index`. The chain has no prune and no rotation, so the length does
/// not fall. Both values are on disk. A new process has an empty cache and serves that
/// sum, so the version is at least as high as every version served before the restart.
#[test]
fn a_restart_serves_a_deny_version_at_least_as_high() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    coord
        .enroll_token("a", &token.secret, &["a:443".to_string()], &[], now)
        .unwrap();
    let first = deny_version(&crate::admin::deny_json_for(&coord, "a", now).unwrap());
    coord
        .record_change(
            "spiffe://orblx.local/node/owner",
            ConfigAction::Revoke,
            "spiffe://orblx.local/node/a",
            EMPTY_DIGEST,
            EMPTY_DIGEST,
            "record only",
        )
        .unwrap();
    let second = deny_version(&crate::admin::deny_json_for(&coord, "a", now).unwrap());
    drop(coord);
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    let restarted = deny_version(&crate::admin::deny_json_for(&coord, "a", now).unwrap());
    assert!(restarted >= first);
    assert!(restarted >= second);
}

fn deny_version(text: &str) -> u64 {
    let mut deny = DenySet::empty();
    deny.apply_json(text.as_bytes()).unwrap();
    deny.version().unwrap()
}

fn enroll_named(coord: &Coordinator, name: &str, now: SystemTime) {
    let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    coord
        .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
        .unwrap();
}

fn audit_len(dir: &std::path::Path) -> u64 {
    let text = fs::read_to_string(dir.join(CONFIG_AUDIT_FILE)).unwrap_or_default();
    text.lines().filter(|line| !line.is_empty()).count() as u64
}

fn deny_document(version: u64, uris: &[&str]) -> String {
    serde_json::json!({
        "version": version,
        "generated_at": 1,
        "revoked_uris": uris,
        "revoked_ticket_nonces": [],
    })
    .to_string()
}

/// Crypto scratch case. A fresh read serves 5. A later stale read serves 8 on
/// the old rule. After a restart, revoke of c serves 7, and a node that kept 8
/// does not install c.
#[test]
fn a_stale_read_cannot_hide_the_revoke_that_follows_a_restart() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    for name in ["a", "b", "c"] {
        enroll_named(&coord, name, now);
    }
    let v0 = crate::admin::deny_json_for(&coord, "a", now).unwrap();
    assert_eq!(deny_version(&v0), 3);
    crate::admin::revoke_all(&coord, "b", "spiffe://orblx.local/node/owner", now).unwrap();
    let fresh = crate::admin::deny_json_for(&coord, "a", now).unwrap();
    assert_eq!(deny_version(&fresh), 5);
    let mut node = DenySet::empty();
    node.apply_json(v0.as_bytes()).unwrap();
    node.apply_json(fresh.as_bytes()).unwrap();
    let stale_sets: [&[&str]; 3] = [
        &[],
        &["spiffe://orblx.local/node/stale-1"],
        &["spiffe://orblx.local/node/stale-2"],
    ];
    for uris in stale_sets {
        let version = coord
            .served_deny_version(
                "a",
                0,
                uris.iter().map(|uri| (*uri).to_string()).collect(),
                vec![],
                vec![],
            )
            .unwrap();
        node.apply_json(deny_document(version, uris).as_bytes())
            .unwrap();
    }
    let highest = node.version().unwrap();
    drop(coord);
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    crate::admin::revoke_all(&coord, "c", "spiffe://orblx.local/node/owner", now).unwrap();
    let revoked = crate::admin::deny_json_for(&coord, "a", now).unwrap();
    let c_version = deny_version(&revoked);
    assert!(
        c_version > highest,
        "revoke c served {c_version} but the node kept {highest}"
    );
    node.apply_json(revoked.as_bytes()).unwrap();
    assert!(node.reject_uri(&SpiffeId::node("c").unwrap()).is_err());
}

/// A stale reply that follows a fresh reply has a lower version. A node that
/// holds the fresh set ignores the stale reply.
#[test]
fn a_stale_reply_is_older_than_the_fresh_reply() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    for name in ["a", "b"] {
        enroll_named(&coord, name, now);
    }
    crate::admin::revoke_all(&coord, "b", "spiffe://orblx.local/node/owner", now).unwrap();
    let fresh = crate::admin::deny_json_for(&coord, "a", now).unwrap();
    let fresh_version = deny_version(&fresh);
    let stale_version = coord
        .served_deny_version("a", 0, Vec::new(), Vec::new(), Vec::new())
        .unwrap();
    assert!(
        stale_version < fresh_version,
        "stale {stale_version} fresh {fresh_version}"
    );
    let mut node = DenySet::empty();
    node.apply_json(fresh.as_bytes()).unwrap();
    let apply = node
        .apply_json(deny_document(stale_version, &[]).as_bytes())
        .unwrap();
    assert_eq!(apply, orblx_identity::DenyApply::IgnoredOlder);
    assert_eq!(node.version(), Some(fresh_version));
}

/// The served version is never above `deny.json` version plus the audit length.
#[test]
fn a_served_deny_version_never_exceeds_the_file_plus_the_audit() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    enroll_named(&coord, "a", now);
    let file_version = 4u64;
    let uris = vec!["spiffe://orblx.local/node/b".to_string()];
    let served = coord
        .served_deny_version("a", file_version, uris.clone(), Vec::new(), Vec::new())
        .unwrap();
    let audit = audit_len(&scratch.0);
    assert!(
        served <= file_version + audit,
        "served {served} file {file_version} audit {audit}"
    );
    let stale = coord
        .served_deny_version(
            "a",
            0,
            vec!["spiffe://orblx.local/node/z".to_string()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
    let audit = audit_len(&scratch.0);
    assert!(stale <= audit, "served {stale} file 0 audit {audit}");
    let error = coord
        .served_deny_version("a", 0, uris, Vec::new(), Vec::new())
        .unwrap_err();
    assert!(matches!(error, crate::error::CoordError::State));
}
