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
    let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    coord
        .enroll_token("a", &token.secret, &["a:443".to_string()], &[], now)
        .unwrap();
    let id_token = oidc
        .issue_id_token("bob", now, Duration::from_secs(600))
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
