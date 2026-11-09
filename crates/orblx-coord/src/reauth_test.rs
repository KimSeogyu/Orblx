//! W25-47 re-auth tests. Release proofs a, b, and f stay in scripts/proof/w25-47-reauth.sh.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_identity::{
    decode_certificate_pem, leaf_key_id, leaf_not_after, sign_ticket, verify_ticket, DenySet,
    IssueGate, MiniCa, MockOidc, SpiffeId, TicketClaims, TicketFlags, TicketSigner, TrustBundle,
    MAX_USER_TTL, MOCK_OIDC_ISSUER,
};
use serde_json::Value;

use crate::preauth::{self, CreateAsk};
use crate::reauth::{self, legacy_wait_secs};
use crate::state::{Coordinator, OidcConfig};
use crate::store::LiveLeafKey;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orblx-w25-47-{name}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn audits(coord: &Coordinator) -> Vec<Value> {
    coord
        .config_audit_text()
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn count_action(lines: &[Value], action: &str) -> usize {
    lines.iter().filter(|line| line["action"] == action).count()
}

fn count_reason(lines: &[Value], reason: &str) -> usize {
    lines
        .iter()
        .filter(|line| {
            line["action"] == "reauth-deny"
                && line["detail"].as_str().unwrap_or("").contains(reason)
        })
        .count()
}

fn same_record(before: &crate::store::StoredNode, after: &crate::store::StoredNode) {
    assert_eq!(after.name, before.name);
    assert_eq!(after.overlay_ip, before.overlay_ip);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.routes, before.routes);
    assert_eq!(after.tags, before.tags);
    assert_eq!(after.grant_bound, before.grant_bound);
}

struct Lab {
    dir: PathBuf,
    coord: Coordinator,
    oidc: MockOidc,
    now: SystemTime,
}

impl Lab {
    fn open(name: &str) -> Self {
        let dir = scratch(name);
        let now = SystemTime::now();
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
        let coord = Coordinator::open(&dir, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
        coord.enable_config_audit().unwrap();
        let policy = dir.join("policy.hujson");
        fs::write(&policy, r#"{"owners":["spiffe://orblx.local/node/owner"]}"#).unwrap();
        coord.set_policy_file(&policy).unwrap();
        coord.note_serving(now).unwrap();
        coord
            .approve_user_by("oidc:ada", "spiffe://orblx.local/node/owner", now)
            .unwrap();
        Self {
            dir,
            coord,
            oidc,
            now,
        }
    }

    fn token(&self, subject: &str) -> String {
        self.oidc
            .issue_id_token(subject, self.now, Duration::from_secs(600))
            .unwrap()
    }

    fn enroll_oidc(&self, name: &str, subject: &str) -> crate::state::EnrollResult {
        let token = self.token(subject);
        self.coord
            .enroll_oidc(name, &token, None, &[format!("{name}:443")], &[], self.now)
            .unwrap()
    }

    fn node(&self, name: &str) -> crate::store::StoredNode {
        self.coord
            .node_list()
            .unwrap()
            .into_iter()
            .find(|node| node.name == name)
            .unwrap()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn key_of(result: &crate::state::EnrollResult) -> (String, u64) {
    let der = decode_certificate_pem(&result.certificate_pem).unwrap();
    (leaf_key_id(&der).unwrap(), leaf_not_after(&der).unwrap())
}

#[test]
fn the_marker_keeps_the_first_wall_second() {
    let dir = scratch("marker");
    let now = SystemTime::now();
    let first = reauth::ensure_rc3_start(&dir, now).unwrap();
    assert_ne!(first, 0);
    assert_eq!(reauth::ensure_rc3_start(&dir, now).unwrap(), first);
    reauth::testing_write_rc3_start(&dir, "1700000000\n");
    assert_eq!(reauth::ensure_rc3_start(&dir, now).unwrap(), 1_700_000_000);
    reauth::testing_write_rc3_start(&dir, "0\n");
    let again = reauth::ensure_rc3_start(&dir, now).unwrap();
    assert_ne!(again, 0);
    assert_ne!(again, 1_700_000_000);
    reauth::testing_write_rc3_start(&dir, "bad\n");
    let rewritten = reauth::ensure_rc3_start(&dir, now).unwrap();
    assert_ne!(rewritten, 0);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn used_tokens_prune_with_the_check_clock_and_the_verified_issuer() {
    let dir = scratch("used");
    let iss = MOCK_OIDC_ISSUER;
    assert!(reauth::take_used_token(&dir, iss, "ada", "", 100, 50).unwrap());
    assert!(!reauth::take_used_token(&dir, iss, "ada", "", 100, 50).unwrap());
    assert!(reauth::take_used_token(&dir, iss, "ada", "", 100, 101).unwrap());
    let text = fs::read_to_string(dir.join("reauth-used.json")).unwrap();
    assert!(text.contains(iss));
    assert!(!text.contains("PRIVATE KEY"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn legacy_wait_is_the_existing_ttl_plus_skew() {
    assert_eq!(legacy_wait_secs(), MAX_USER_TTL.as_secs() + 60);
}

#[test]
fn an_absent_leaf_list_waits_and_an_empty_list_does_not_use_that_rule() {
    let now = unix(SystemTime::now());
    assert!(reauth::legacy_wait_blocks(true, now, now, now));
    assert!(!reauth::legacy_wait_blocks(false, now, now, now));
    assert!(reauth::legacy_wait_blocks(false, now - 10, now, now));
    assert!(!reauth::legacy_wait_blocks(
        true,
        now,
        now,
        now + legacy_wait_secs()
    ));
}

#[test]
fn live_leaf_keys_fill_runs_only_when_the_field_is_absent() {
    let lab = Lab::open("fill");
    let enrolled = lab.enroll_oidc("laptop", "ada");
    let (old_key, old_end) = key_of(&enrolled);
    lab.coord.testing_set_live_keys("laptop", None).unwrap();
    let renewed = lab
        .coord
        .renew_node("laptop", &old_key, old_end, lab.now)
        .unwrap();
    let keys = lab.node("laptop").live_leaf_keys.unwrap();
    assert!(keys.iter().any(|item| item.key_id == old_key));
    let (new_key, new_end) = key_of(&renewed);
    assert!(keys.iter().any(|item| item.key_id == new_key));
    assert_ne!(old_key, new_key);
    lab.coord
        .testing_set_live_keys("laptop", Some(Vec::new()))
        .unwrap();
    assert!(lab
        .coord
        .renew_node("laptop", &new_key, new_end, lab.now)
        .is_err());
}

#[test]
fn oidc_reauth_keeps_the_record_and_writes_one_reauth_line() {
    let lab = Lab::open("oidc");
    let enrolled = lab.enroll_oidc("laptop", "ada");
    let before = lab.node("laptop");
    let (old_key, _) = key_of(&enrolled);
    let token = lab.token("ada");
    let again = lab
        .coord
        .reauth_oidc("laptop", &token, None, lab.now)
        .unwrap();
    let after = lab.node("laptop");
    assert_eq!(after.name, before.name);
    assert_eq!(after.overlay_ip, before.overlay_ip);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.routes, before.routes);
    assert_eq!(after.tags, before.tags);
    assert_eq!(after.grant_bound, before.grant_bound);
    let (new_key, _) = key_of(&again);
    assert_ne!(new_key, old_key);
    let lines = audits(&lab.coord);
    assert_eq!(count_action(&lines, "reauth"), 1);
    assert_eq!(count_action(&lines, "enroll"), 1);
    let detail = lines
        .iter()
        .find(|line| line["action"] == "reauth")
        .unwrap()["detail"]
        .as_str()
        .unwrap();
    assert!(detail.contains(&before.svid));
    assert!(detail.contains(&old_key));
    assert!(detail.contains(&new_key));
    assert!(detail.contains("authorizer oidc"));
    let used = fs::read_to_string(lab.dir.join("reauth-used.json")).unwrap();
    assert!(used.contains(MOCK_OIDC_ISSUER));
    assert!(!used.contains(&token));
}

#[test]
fn the_same_id_token_is_replay_and_a_foreign_subject_is_owner() {
    let lab = Lab::open("replay");
    lab.enroll_oidc("laptop", "ada");
    let token = lab.token("ada");
    lab.coord
        .reauth_oidc("laptop", &token, None, lab.now)
        .unwrap();
    assert!(lab
        .coord
        .reauth_oidc("laptop", &token, None, lab.now)
        .is_err());
    let lines = audits(&lab.coord);
    let kept = lab.node("laptop");
    assert_eq!(count_reason(&lines, "reason replay"), 1);
    assert_eq!(count_action(&lines, "reauth"), 1);
    same_record(&kept, &lab.node("laptop"));
    lab.coord
        .approve_user_by("oidc:bob", "spiffe://orblx.local/node/owner", lab.now)
        .unwrap();
    let other = lab.token("bob");
    assert!(lab
        .coord
        .reauth_oidc("laptop", &other, None, lab.now)
        .is_err());
    let lines = audits(&lab.coord);
    assert_eq!(count_reason(&lines, "reason owner"), 1);
    same_record(&kept, &lab.node("laptop"));
}

#[test]
fn an_absent_list_waits_and_a_revoked_or_removed_node_stays_refused() {
    let lab = Lab::open("wait");
    lab.enroll_oidc("laptop", "ada");
    lab.coord.testing_set_live_keys("laptop", None).unwrap();
    let before = lab.node("laptop");
    let token = lab.token("ada");
    assert!(lab
        .coord
        .reauth_oidc("laptop", &token, None, lab.now)
        .is_err());
    assert_eq!(count_reason(&audits(&lab.coord), "reason legacy-wait"), 1);
    same_record(&before, &lab.node("laptop"));
    let early = unix(lab.now).saturating_sub(legacy_wait_secs());
    reauth::testing_write_rc3_start(&lab.dir, &format!("{early}\n"));
    lab.coord
        .reauth_oidc("laptop", &token, None, lab.now)
        .unwrap();

    let lab = Lab::open("revoked");
    lab.enroll_oidc("laptop", "ada");
    for _ in 0..10 {
        crate::admin::revoke(
            &lab.coord,
            "laptop",
            "spiffe://orblx.local/node/owner",
            lab.now,
        )
        .unwrap();
        let token = lab.token("ada");
        assert!(lab
            .coord
            .reauth_oidc("laptop", &token, None, lab.now)
            .is_err());
    }
    let deny = fs::read_to_string(lab.dir.join("deny.json")).unwrap();
    assert!(deny.contains("spiffe://orblx.local/node/laptop"));
    assert_eq!(count_reason(&audits(&lab.coord), "reason revoked"), 10);

    let lab = Lab::open("removed");
    lab.enroll_oidc("laptop", "ada");
    lab.coord.testing_set_removed("laptop", true).unwrap();
    let kept = lab.node("laptop");
    assert!(lab
        .coord
        .reauth_oidc("laptop", &lab.token("ada"), None, lab.now)
        .is_err());
    assert_eq!(count_reason(&audits(&lab.coord), "reason revoked"), 1);
    same_record(&kept, &lab.node("laptop"));
}

#[test]
fn an_enroll_token_for_the_same_name_writes_exists_token() {
    let dir = scratch("token");
    let now = SystemTime::now();
    let coord = Coordinator::open(&dir, "coord", OidcConfig::TokenOnly).unwrap();
    coord.enable_config_audit().unwrap();
    let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    coord
        .enroll_token(
            "laptop",
            &token.secret,
            &["laptop:443".to_string()],
            &[],
            now,
        )
        .unwrap();
    let again = coord.create_token_at(Duration::from_secs(60), now).unwrap();
    let kept = coord
        .node_list()
        .unwrap()
        .into_iter()
        .find(|node| node.name == "laptop")
        .unwrap();
    let err = crate::server::enroll_token_dispatch(
        &coord,
        "laptop",
        &again.secret,
        &["laptop:443".to_string()],
        &[],
        now,
    )
    .unwrap_err();
    assert!(matches!(err, crate::error::CoordError::Exists));
    let err = crate::server::enroll_token_dispatch(
        &coord,
        "laptop",
        &again.secret,
        &["laptop:443".to_string()],
        &[],
        now,
    )
    .unwrap_err();
    assert!(matches!(err, crate::error::CoordError::Exists));
    let lines = audits(&coord);
    assert_eq!(count_reason(&lines, "reason exists-token"), 1);
    assert_eq!(count_action(&lines, "reauth"), 0);
    let after = coord
        .node_list()
        .unwrap()
        .into_iter()
        .find(|node| node.name == "laptop")
        .unwrap();
    same_record(&kept, &after);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn preauth_reauth_uses_the_key_once_and_scope_failures_do_not() {
    let lab = Lab::open("preauth");
    lab.enroll_oidc("laptop", "ada");
    let owner = "spiffe://orblx.local/node/owner";
    let ask = CreateAsk {
        ttl_secs: 60,
        max_uses: 1,
        ephemeral: false,
        tags: Vec::new(),
        grant: None,
        nodes: vec!["laptop".to_string()],
    };
    let created = preauth::create(&lab.coord, &ask, owner, lab.now).unwrap();
    let secret = created["key"].as_str().unwrap();
    let before = count_action(&audits(&lab.coord), "preauth-use");
    preauth::enroll(
        &lab.coord,
        "laptop",
        secret,
        &["laptop:443".to_string()],
        &[],
        lab.now,
    )
    .unwrap();
    let lines = audits(&lab.coord);
    assert_eq!(count_action(&lines, "reauth"), 1);
    assert_eq!(count_action(&lines, "preauth-use"), before);
    assert!(lines.iter().any(|line| {
        line["action"] == "reauth"
            && line["detail"]
                .as_str()
                .unwrap_or("")
                .contains("authorizer preauth")
    }));
    let listed = preauth::list(&lab.coord, lab.now).unwrap();
    assert_eq!(listed["keys"][0]["uses"], 1);

    let empty = CreateAsk {
        nodes: Vec::new(),
        ..ask.clone()
    };
    let created = preauth::create(&lab.coord, &empty, owner, lab.now).unwrap();
    let secret = created["key"].as_str().unwrap();
    let before_scope = lab.node("laptop");
    assert!(preauth::enroll(
        &lab.coord,
        "laptop",
        secret,
        &["laptop:443".to_string()],
        &[],
        lab.now,
    )
    .is_err());
    assert_eq!(count_reason(&audits(&lab.coord), "reason scope"), 1);
    same_record(&before_scope, &lab.node("laptop"));

    lab.coord.testing_set_enrolled_unix("laptop", 1).unwrap();
    assert!(lab
        .coord
        .reauth_oidc("laptop", &lab.token("ada"), None, lab.now)
        .is_err());
    lab.coord
        .testing_set_grant(
            "laptop",
            Some(crate::store::NodeGrantBound {
                node: "laptop".to_string(),
                service: "svc".to_string(),
                port: 80,
                path_prefix: "/".to_string(),
                max_ttl_secs: 60,
            }),
        )
        .unwrap();
    let ceiling = CreateAsk {
        nodes: vec!["laptop".to_string()],
        max_uses: 1,
        ..ask.clone()
    };
    let created = preauth::create(&lab.coord, &ceiling, owner, lab.now).unwrap();
    assert!(preauth::enroll(
        &lab.coord,
        "laptop",
        created["key"].as_str().unwrap(),
        &["laptop:443".to_string()],
        &[],
        lab.now,
    )
    .is_err());
    lab.coord
        .testing_set_tags("laptop", vec!["tag:bot".to_string()])
        .unwrap();
    let tagged = CreateAsk {
        nodes: vec!["laptop".to_string()],
        max_uses: 1,
        ..ask
    };
    let created = preauth::create(&lab.coord, &tagged, owner, lab.now).unwrap();
    assert!(preauth::enroll(
        &lab.coord,
        "laptop",
        created["key"].as_str().unwrap(),
        &["laptop:443".to_string()],
        &[],
        lab.now,
    )
    .is_err());
    assert_eq!(count_reason(&audits(&lab.coord), "reason scope"), 3);
    assert_eq!(count_reason(&audits(&lab.coord), "reason legacy-wait"), 1);
}

#[test]
fn a_crash_after_deny_and_a_crash_after_nodes_match_the_audit_rule() {
    let lab = Lab::open("crash");
    let enrolled = lab.enroll_oidc("laptop", "ada");
    let (old_key, _) = key_of(&enrolled);
    reauth::arm_crash(1);
    assert!(lab
        .coord
        .reauth_oidc("laptop", &lab.token("ada"), None, lab.now)
        .is_err());
    let deny = fs::read_to_string(lab.dir.join("deny.json")).unwrap();
    assert!(deny.contains(&old_key));
    assert_eq!(count_action(&audits(&lab.coord), "reauth"), 0);

    let lab = Lab::open("crash-nodes");
    lab.enroll_oidc("laptop", "ada");
    reauth::arm_crash(2);
    assert!(lab
        .coord
        .reauth_oidc("laptop", &lab.token("ada"), None, lab.now)
        .is_err());
    assert_eq!(count_action(&audits(&lab.coord), "reauth"), 0);
    let stored = lab.node("laptop").live_leaf_keys.unwrap();
    assert_eq!(stored.len(), 1);
    let stranded = stored[0].key_id.clone();
    // The crashed call recorded the first token. A later token has a new `exp`.
    let later = lab.now + Duration::from_secs(601);
    let token = lab
        .oidc
        .issue_id_token("ada", later, Duration::from_secs(600))
        .unwrap();
    let again = lab
        .coord
        .reauth_oidc("laptop", &token, None, later)
        .unwrap();
    let (new_key, _) = key_of(&again);
    let detail = audits(&lab.coord)
        .into_iter()
        .find(|line| line["action"] == "reauth")
        .unwrap();
    let text = detail["detail"].as_str().unwrap();
    assert!(text.contains(&stranded));
    assert!(text.contains(&new_key));
    assert!(text.contains("old "));
}

#[test]
fn renew_after_reauth_does_not_issue_the_old_leaf() {
    let lab = Lab::open("race");
    let enrolled = lab.enroll_oidc("laptop", "ada");
    let (old_key, old_end) = key_of(&enrolled);
    let (ready, go) = reauth::arm_renew_wait();
    let coord = lab.coord.clone();
    let key = old_key.clone();
    let now = lab.now;
    let worker = std::thread::spawn(move || {
        reauth::mark_renew_wait();
        coord.renew_node("laptop", &key, old_end, now)
    });
    ready.recv().unwrap();
    lab.coord
        .reauth_oidc("laptop", &lab.token("ada"), None, lab.now)
        .unwrap();
    go.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());
    let keys = lab.node("laptop").live_leaf_keys.unwrap();
    assert!(!keys.iter().any(|item| item.key_id == old_key));
    let deny = fs::read_to_string(lab.dir.join("deny.json")).unwrap();
    assert!(deny.contains(&old_key));
    assert_eq!(count_action(&audits(&lab.coord), "reauth"), 1);
    let _ = LiveLeafKey {
        key_id: old_key,
        not_after: old_end,
    };
}

#[test]
fn certificate_grace_and_ticket_end_stay_unchanged() {
    let now_unix = 1_700_000_000u64;
    let now = UNIX_EPOCH + Duration::from_secs(now_unix);
    let ca = MiniCa::generate(now).unwrap();
    let id = SpiffeId::node("a").unwrap();
    let issued = ca
        .issue(&id, now, Duration::from_secs(900), &DenySet::empty())
        .unwrap();
    let der = decode_certificate_pem(&issued.certificate_pem).unwrap();
    let trust: TrustBundle = ca.trust_bundle().clone();
    let end = issued.not_after;
    let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(secs);
    assert!(trust
        .authenticate_leaf(&der, at(end + 60), &DenySet::empty())
        .is_ok());
    let err = trust
        .authenticate_leaf(&der, at(end + 61), &DenySet::empty())
        .unwrap_err();
    assert_eq!(err.to_string(), "The end time has passed.");
    let signer = TicketSigner::generate();
    let claims = TicketClaims {
        issuer: SpiffeId::coord("coord").unwrap(),
        subject: id,
        not_before: end - 10,
        expires: end,
        dst_cidr: "0.0.0.0/0".to_string(),
        proto: 0,
        dst_port: 0,
        flags: TicketFlags::none(),
    };
    let signed = sign_ticket(&signer, &claims).unwrap();
    assert!(verify_ticket(
        &signer.verifier(),
        &signed.bytes,
        at(end),
        &DenySet::empty()
    )
    .is_ok());
    assert!(verify_ticket(
        &signer.verifier(),
        &signed.bytes,
        at(end + 1),
        &DenySet::empty()
    )
    .is_err());
    let key = leaf_key_id(&der).unwrap();
    let mut deny = DenySet::empty();
    let doc = format!(
        r#"{{"version":1,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":[],"revoked_leaf_keys":[{{"key_id":"{key}","not_after":{end}}}]}}"#
    );
    deny.apply_json(doc.as_bytes()).unwrap();
    assert!(trust.authenticate_leaf(&der, now, &deny).is_err());
}

#[test]
fn open_does_not_write_the_marker() {
    let dir = scratch("open-marker");
    let now = SystemTime::now();
    let coord = Coordinator::open(&dir, "coord", OidcConfig::TokenOnly).unwrap();
    assert!(!dir.join("rc3-start").exists());
    coord.note_serving(now).unwrap();
    assert!(dir.join("rc3-start").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_admin_revoke_keeps_the_reauth_deny() {
    let lab = Lab::open("interleave");
    let enrolled = lab.enroll_oidc("laptop", "ada");
    let (old_key, _) = key_of(&enrolled);
    let (ready, go) = reauth::arm_deny_wait();
    let coord = lab.coord.clone();
    let token = lab.token("ada");
    let now = lab.now;
    let worker = std::thread::spawn(move || {
        reauth::mark_deny_wait();
        coord.reauth_oidc("laptop", &token, None, now)
    });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    let coord = lab.coord.clone();
    let revoke_now = lab.now;
    let revoker = std::thread::spawn(move || {
        crate::admin::revoke(
            &coord,
            "laptop",
            "spiffe://orblx.local/node/owner",
            revoke_now,
        )
    });
    std::thread::sleep(Duration::from_millis(100));
    go.send(()).unwrap();
    worker.join().unwrap().unwrap();
    let reply = revoker.join().unwrap().unwrap();
    assert_eq!(reply["deny_version"], 2);
    let text = fs::read_to_string(lab.dir.join("deny.json")).unwrap();
    assert!(text.contains(&old_key));
    assert!(text.contains("spiffe://orblx.local/node/laptop"));
    let set = lab
        .coord
        .deny_handle()
        .unwrap()
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    assert!(set.reject_uri(&SpiffeId::node("laptop").unwrap()).is_err());
    assert!(set.reject_leaf_key_hex(&old_key, unix(lab.now)).is_err());
}

#[test]
fn revoke_undo_updates_the_cache_without_a_restart() {
    let lab = Lab::open("undo");
    lab.enroll_oidc("laptop", "ada");
    crate::admin::revoke(
        &lab.coord,
        "laptop",
        "spiffe://orblx.local/node/owner",
        lab.now,
    )
    .unwrap();
    let set = lab
        .coord
        .deny_handle()
        .unwrap()
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    assert!(set.reject_uri(&SpiffeId::node("laptop").unwrap()).is_err());
    crate::admin::revoke_undo(
        &lab.coord,
        "laptop",
        "spiffe://orblx.local/node/owner",
        lab.now,
    )
    .unwrap();
    let set = lab
        .coord
        .deny_handle()
        .unwrap()
        .read()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    assert!(set.reject_uri(&SpiffeId::node("laptop").unwrap()).is_ok());
    let text = fs::read_to_string(lab.dir.join("deny.json")).unwrap();
    assert!(!text.contains("spiffe://orblx.local/node/laptop"));
}

#[test]
fn a_failure_after_issue_denies_the_new_leaf() {
    let lab = Lab::open("issue-fail");
    let enrolled = lab.enroll_oidc("laptop", "ada");
    let (old_key, _) = key_of(&enrolled);
    reauth::arm_crash(3);
    assert!(lab
        .coord
        .reauth_oidc("laptop", &lab.token("ada"), None, lab.now)
        .is_err());
    let text = fs::read_to_string(lab.dir.join("deny.json")).unwrap();
    assert!(text.contains(&old_key));
    let file: Value = serde_json::from_str(&text).unwrap();
    let keys = file["revoked_leaf_keys"].as_array().unwrap();
    assert!(keys.len() >= 2, "{text}");
    assert_eq!(count_action(&audits(&lab.coord), "reauth"), 0);
    let stored = lab.node("laptop").live_leaf_keys.unwrap();
    assert!(stored.iter().any(|item| item.key_id == old_key));
}

#[test]
fn a_rejected_user_cannot_reauth() {
    let lab = Lab::open("rejected");
    let enrolled = lab.enroll_oidc("laptop", "ada");
    let (old_key, _) = key_of(&enrolled);
    let before = lab.node("laptop");
    lab.coord.testing_reject_user("oidc:ada", lab.now).unwrap();
    assert!(lab
        .coord
        .reauth_oidc("laptop", &lab.token("ada"), None, lab.now)
        .is_err());
    assert_eq!(count_reason(&audits(&lab.coord), "reason owner"), 1);
    same_record(&before, &lab.node("laptop"));
    let stored = lab.node("laptop").live_leaf_keys.unwrap();
    assert!(stored.iter().any(|item| item.key_id == old_key));
}

#[test]
fn release_notes_keep_the_rc1_sentence_and_the_rc3_step() {
    const RC3: &str = include_str!("../../../docs/rc3-release-notes.md");
    const NOTES: &str = include_str!("../../../docs/release-notes/0.1.0-rc.3.md");
    const SENTENCE: &str = "rc.1/rc.2: A node that sleeps or pauses longer than its SVID life plus 1 min (about 16 min by default) cannot reconnect, and a restart does not help. Enroll it again under a new node name with a new enroll token (orblx coord token create, then orblx coord enroll). The old node name cannot be enrolled again in this release. Policy rules and grants for the old name do not apply to the new name: update them, and revoke the old node (orblx admin revoke OLD_NAME --coord ADDR).";
    for text in [RC3, NOTES] {
        assert!(text.contains(SENTENCE));
        assert!(!text.contains("Re-enroll the node."));
        assert!(text.contains("Automatic recovery after a long sleep is not supported"));
        assert!(text.contains("orblx login"));
        assert!(text.contains("Upgrade all nodes before you use re-auth."));
        assert!(text.contains(
            "If the old coordinator wall clock was ahead and was set back before rc.3 start, a legacy leaf can outlive the wait."
        ));
    }
}
