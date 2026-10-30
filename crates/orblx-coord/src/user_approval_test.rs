//! OIDC user approval on the coordinator state (W25-15).

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use orblx_audit::{verify_config_file, ConfigAction};
use orblx_identity::{IssueGate, MiniCa, MockOidc, OidcIssuer, OidcJwks, MOCK_OIDC_ISSUER};
use orblx_test_idp::{jwks_json, mint, KeyAlg, MintSpec, TestKey};

use crate::error::CoordError;
use crate::state::{Coordinator, OidcConfig, CONFIG_AUDIT_FILE};
use crate::store::UserState;

const OWNER: &str = "spiffe://orblx.local/node/owner";
const ISSUER: &str = "https://idp.test:8443";
const CLIENT: &str = "orblx-test";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orblx-users-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn records(&self) -> Vec<ConfigAction> {
        let path = self.0.join(CONFIG_AUDIT_FILE);
        if !path.exists() {
            return Vec::new();
        }
        verify_config_file(&path)
            .unwrap()
            .records
            .into_iter()
            .map(|record| record.event.action)
            .collect()
    }

    fn count(&self, action: ConfigAction) -> usize {
        self.records()
            .into_iter()
            .filter(|item| *item == action)
            .count()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mock(scratch: &Scratch, now: SystemTime) -> (Coordinator, MockOidc) {
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
    coord.enable_config_audit().unwrap();
    (coord, oidc)
}

fn id_token(oidc: &MockOidc, subject: &str, now: SystemTime) -> String {
    oidc.issue_id_token(subject, now, Duration::from_secs(600))
        .unwrap()
}

fn enroll(
    coord: &Coordinator,
    name: &str,
    token: &str,
    now: SystemTime,
) -> Result<crate::state::EnrollResult, CoordError> {
    coord.enroll_oidc(name, token, None, &[format!("{name}:443")], &[], now)
}

fn state_of(coord: &Coordinator, user: &str) -> Option<UserState> {
    let (users, _) = coord.user_list().unwrap();
    users
        .into_iter()
        .find(|stored| stored.user == user)
        .map(|stored| stored.state)
}

#[test]
fn a_new_user_is_pending_and_gets_no_svid_until_the_owner_approves() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let (coord, oidc) = mock(&scratch, now);
    let token = id_token(&oidc, "nina", now);

    for _ in 0..3 {
        assert!(matches!(
            enroll(&coord, "nina-laptop", &token, now),
            Err(CoordError::UserPending)
        ));
    }
    let (users, nodes) = coord.user_list().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].user, "oidc:nina");
    assert_eq!(users[0].state, UserState::Pending);
    assert!(nodes.is_empty(), "a pending user has no node");
    let store = fs::read_to_string(scratch.0.join("nodes.json")).unwrap();
    assert!(!store.contains("nina-laptop"));
    assert!(!store.contains(&token));
    assert_eq!(scratch.count(ConfigAction::UserApprove), 0);

    let before = scratch.records().len();
    coord.approve_user_by("oidc:nina", OWNER, now).unwrap();
    let after = scratch.records();
    assert_eq!(after.len(), before + 1);
    assert_eq!(after.last(), Some(&ConfigAction::UserApprove));

    let result = enroll(&coord, "nina-laptop", &token, now).unwrap();
    assert_eq!(result.svid, "spiffe://orblx.local/node/nina-laptop");
    assert_eq!(
        result.overlay_ip, "100.64.0.1",
        "a refused try uses no address"
    );
    assert!(result.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(state_of(&coord, "oidc:nina"), Some(UserState::Approved));
    assert!(matches!(
        coord.approve_user_by("oidc:nina", OWNER, now),
        Err(CoordError::Protocol(_))
    ));
    assert_eq!(scratch.count(ConfigAction::UserApprove), 1);
    let checked = verify_config_file(&scratch.0.join(CONFIG_AUDIT_FILE)).unwrap();
    assert!(!checked.records.is_empty());
}

#[test]
fn a_rejected_user_stays_blocked_and_reject_writes_one_record() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let (coord, oidc) = mock(&scratch, now);
    let token = id_token(&oidc, "rex", now);
    assert!(matches!(
        enroll(&coord, "rex-pc", &token, now),
        Err(CoordError::UserPending)
    ));
    let before = scratch.records().len();
    coord.reject_user_by("oidc:rex", OWNER, now).unwrap();
    assert_eq!(scratch.records().len(), before + 1);
    assert_eq!(scratch.count(ConfigAction::UserReject), 1);
    for _ in 0..3 {
        assert!(matches!(
            enroll(&coord, "rex-pc", &token, now),
            Err(CoordError::UserRejected)
        ));
    }
    assert_eq!(state_of(&coord, "oidc:rex"), Some(UserState::Rejected));
    assert!(coord.node_list().unwrap().is_empty());
    assert!(matches!(
        coord.reject_user_by("oidc:rex", OWNER, now),
        Err(CoordError::Protocol(_))
    ));
    assert_eq!(scratch.count(ConfigAction::UserReject), 1);
    // The owner can change the decision. That is one more record.
    coord.approve_user_by("oidc:rex", OWNER, now).unwrap();
    enroll(&coord, "rex-pc", &token, now).unwrap();
    // An approved user is not rejected. The owner expires or revokes the nodes.
    assert!(coord.reject_user_by("oidc:rex", OWNER, now).is_err());
    let checked = verify_config_file(&scratch.0.join(CONFIG_AUDIT_FILE)).unwrap();
    assert!(!checked.records.is_empty());
}

#[test]
fn users_approved_before_the_change_still_enroll_with_no_action() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let (coord, oidc) = mock(&scratch, now);
    let alice = id_token(&oidc, "alice", now);
    coord.approve_user_by("oidc:alice", OWNER, now).unwrap();
    enroll(&coord, "laptop", &alice, now).unwrap();

    // Make the store look like a store from before W25-15: no user list.
    let path = scratch.0.join("nodes.json");
    let mut disk: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    disk.as_object_mut().unwrap().remove("users").unwrap();
    fs::write(&path, serde_json::to_string_pretty(&disk).unwrap()).unwrap();
    let records = scratch.records().len();

    // The next call opens the store and approves each OIDC node owner.
    assert_eq!(state_of(&coord, "oidc:alice"), Some(UserState::Approved));
    let migrated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(migrated["users"][0]["user"], "oidc:alice");
    assert_eq!(migrated["users"][0]["state"], "approved");
    enroll(&coord, "desk", &alice, now).unwrap();
    assert_eq!(
        scratch.records().len(),
        records + 1,
        "only the enroll record"
    );
    // A user with no node in the old store is a new user.
    let bob = id_token(&oidc, "bob", now);
    assert!(matches!(
        enroll(&coord, "bob-pc", &bob, now),
        Err(CoordError::UserPending)
    ));
}

#[test]
fn the_owner_user_is_never_pending_and_a_token_enroll_needs_no_user() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    fs::write(
        scratch.0.join("policy.hujson"),
        r#"{"userApproval": {"ownerUsers": ["oidc:olivia"]}}"#,
    )
    .unwrap();
    let (coord, oidc) = mock(&scratch, now);
    let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    coord
        .enroll_token(
            "server",
            &token.secret,
            &["server:443".to_string()],
            &[],
            now,
        )
        .unwrap();
    assert!(coord.user_list().unwrap().0.is_empty());

    let olivia = id_token(&oidc, "olivia", now);
    enroll(&coord, "olivia-laptop", &olivia, now).unwrap();
    assert_eq!(state_of(&coord, "oidc:olivia"), Some(UserState::Approved));
    assert_eq!(scratch.count(ConfigAction::UserApprove), 1);
    enroll(&coord, "olivia-desk", &olivia, now).unwrap();
    assert_eq!(scratch.count(ConfigAction::UserApprove), 1);
    assert!(matches!(
        coord.reject_user_by("oidc:olivia", OWNER, now),
        Err(CoordError::Protocol(_))
    ));
    assert_eq!(scratch.count(ConfigAction::UserReject), 0);
}

fn issuer_coord(scratch: &Scratch, now: SystemTime) -> (Coordinator, TestKey) {
    let issuer = OidcIssuer::new(ISSUER, CLIENT, &[], &[]).unwrap();
    let coord = Coordinator::open(
        &scratch.0,
        "coord",
        OidcConfig::Issuer {
            issuer: Box::new(issuer),
            extra_roots_pem: None,
        },
    )
    .unwrap();
    coord.enable_config_audit().unwrap();
    let key = TestKey::generate("rs1", KeyAlg::RS256).unwrap();
    let jwks = OidcJwks::from_json(&jwks_json(std::slice::from_ref(&key))).unwrap();
    coord.install_issuer_jwks(jwks, now).unwrap();
    (coord, key)
}

fn email_token(key: &TestKey, subject: &str, email: &str, verified: bool) -> String {
    let mut spec = MintSpec::now(ISSUER, CLIENT, subject, 600);
    spec.email = Some(email.to_string());
    spec.email_verified = verified;
    mint(key, &spec, None).unwrap()
}

#[test]
fn auto_approve_is_off_by_default_and_needs_a_verified_domain() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let (coord, key) = issuer_coord(&scratch, now);
    let ann = email_token(&key, "ann", "ann@example.com", true);
    assert!(matches!(
        enroll(&coord, "ann-pc", &ann, now),
        Err(CoordError::UserPending)
    ));

    fs::write(
        scratch.0.join("policy.hujson"),
        r#"{"userApproval": {"autoApproveDomains": ["example.com"]}}"#,
    )
    .unwrap();
    let ben = email_token(&key, "ben", "ben@example.com", false);
    assert!(matches!(
        enroll(&coord, "ben-pc", &ben, now),
        Err(CoordError::UserPending)
    ));
    let cat = email_token(&key, "cat", "cat@other.test", true);
    assert!(matches!(
        enroll(&coord, "cat-pc", &cat, now),
        Err(CoordError::UserPending)
    ));
    let before = scratch.count(ConfigAction::UserApprove);
    enroll(&coord, "ann-pc", &ann, now).unwrap();
    assert_eq!(scratch.count(ConfigAction::UserApprove), before + 1);
    let (users, _) = coord.user_list().unwrap();
    let ann_user = users.iter().find(|user| user.user == "oidc:ann").unwrap();
    assert_eq!(ann_user.state, UserState::Approved);
    let ben_user = users.iter().find(|user| user.user == "oidc:ben").unwrap();
    assert_eq!(
        ben_user.email, None,
        "an email that is not verified is not stored"
    );
}

#[test]
fn a_user_change_needs_the_config_chain() {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
    assert!(coord.approve_user_by("oidc:zed", OWNER, now).is_err());
    assert!(coord.reject_user_by("oidc:zed", OWNER, now).is_err());
    assert!(coord.user_list().unwrap().0.is_empty());
}
