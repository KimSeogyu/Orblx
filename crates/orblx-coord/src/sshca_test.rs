//! SSH user certificates on the coordinator state (W25-31).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use orblx_audit::{verify_config_file, ConfigAction};
use orblx_identity::{IssueGate, MiniCa, MockOidc, Policy, SpiffeId, MOCK_OIDC_ISSUER};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{Certificate, PrivateKey, PublicKey};

use crate::proto::SshCertAsk;
use crate::sshca::{
    decide, sign_request, IssueFacts, SshDeny, SSH_CERT_MAX_LIFE_SECS, SSH_EXPORTER_LEN,
};
use crate::state::{Coordinator, OidcConfig, SshIssueError, CONFIG_AUDIT_FILE};
use crate::store::{StoredNode, UserState};

const OWNER: &str = "spiffe://orblx.local/node/owner";

const POLICY: &str = r#"{
  "ssh": [
    {
      "src": ["spiffe://orblx.local/user/alice"],
      "dst": ["spiffe://orblx.local/node/b"],
      "users": ["alice"],
      "checkPeriod": "30s",
    },
    {
      "src": ["spiffe://orblx.local/user/sam"],
      "dst": ["spiffe://orblx.local/node/b"],
      "users": ["sam"],
      "checkPeriod": "30s",
    },
  ],
}"#;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orblx-sshca-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn ssh_records(&self) -> Vec<String> {
        verify_config_file(&self.0.join(CONFIG_AUDIT_FILE))
            .unwrap()
            .records
            .into_iter()
            .filter(|record| record.event.action == ConfigAction::SshCert)
            .map(|record| record.event.detail)
            .collect()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Lab {
    scratch: Scratch,
    coord: Coordinator,
    oidc: MockOidc,
    now: SystemTime,
}

fn lab() -> Lab {
    let scratch = Scratch::new();
    let now = SystemTime::now();
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
    coord.enable_config_audit().unwrap();
    let policy = scratch.0.join("policy.hujson");
    fs::write(&policy, POLICY).unwrap();
    coord.set_policy_file(&policy).unwrap();
    Lab {
        scratch,
        coord,
        oidc,
        now,
    }
}

impl Lab {
    /// Approve the user and enroll one node that the user owns.
    fn node_of(&self, user: &str, node: &str) -> SpiffeId {
        let _ = self
            .coord
            .approve_user_by(&format!("oidc:{user}"), OWNER, self.now);
        let token = self
            .oidc
            .issue_id_token(user, self.now, Duration::from_secs(600))
            .unwrap();
        self.coord
            .enroll_oidc(node, &token, None, &[format!("{node}:443")], &[], self.now)
            .unwrap();
        SpiffeId::node(node).unwrap()
    }

    fn issue(
        &self,
        peer: &SpiffeId,
        connection: u64,
        key: &PrivateKey,
    ) -> Result<crate::sshca::IssuedCert, SshIssueError> {
        let exporter = exporter(connection);
        let nonce = self.coord.ssh_nonce(connection).unwrap();
        let ask = ask_for(key, &exporter, &nonce);
        self.coord
            .ssh_issue(peer, far(), connection, &exporter, &ask, SystemTime::now())
    }
}

fn far() -> u64 {
    crate::sshca::unix_secs(SystemTime::now()).unwrap() + 86_400
}

fn exporter(connection: u64) -> [u8; SSH_EXPORTER_LEN] {
    let mut out = [0u8; SSH_EXPORTER_LEN];
    out[..8].copy_from_slice(&connection.to_be_bytes());
    out[8] = 0x5a;
    out
}

fn new_key() -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&rand::random::<[u8; 32]>()))
}

fn ask_for(key: &PrivateKey, exporter: &[u8; SSH_EXPORTER_LEN], nonce: &[u8; 32]) -> SshCertAsk {
    SshCertAsk {
        public_key: key.public_key().to_openssh().unwrap(),
        sshsig: sign_request(key, exporter, nonce).unwrap(),
        nonce: crate::netmap::encode_hex(nonce),
    }
}

fn deny_of(result: Result<crate::sshca::IssuedCert, SshIssueError>) -> SshDeny {
    match result {
        Err(SshIssueError::Deny(deny)) => deny,
        Err(SshIssueError::Coord(err)) => panic!("coordinator error: {err:?}"),
        Ok(_) => panic!("the coordinator issued a certificate"),
    }
}

fn parse(text: &str) -> Certificate {
    Certificate::from_openssh(text).unwrap()
}

#[test]
fn an_owner_node_gets_one_short_user_cert_for_its_owner_only() {
    let lab = lab();
    let peer = lab.node_of("alice", "alice-laptop");
    let key = new_key();
    let issued = lab.issue(&peer, 7, &key).unwrap();
    let cert = parse(&issued.text);

    assert_eq!(cert.cert_type(), ssh_key::certificate::CertType::User);
    assert_eq!(cert.valid_principals(), ["oidc:alice".to_string()]);
    let life = cert.valid_before() - cert.valid_after();
    assert!(life <= SSH_CERT_MAX_LIFE_SECS + 60, "life {life}");
    assert!(cert.valid_before() <= crate::sshca::unix_secs(SystemTime::now()).unwrap() + 900);
    assert_eq!(cert.extensions().len(), 1);
    assert!(cert.extensions().contains_key("permit-pty"));
    assert_eq!(cert.critical_options().len(), 1);
    assert_eq!(
        cert.critical_options()
            .get("source-address")
            .map(String::as_str),
        Some("100.64.0.1/32")
    );
    assert_eq!(
        cert.key_id(),
        format!(
            "orblx-ssh node={} owner=oidc:alice serial={}",
            peer.as_uri(),
            cert.serial()
        )
    );
    assert_eq!(cert.public_key(), key.public_key().key_data());
    // The signer is the current CA key in the netmap set.
    let set = lab.coord.ssh_user_ca().unwrap();
    assert_eq!(set.len(), 2);
    let signer = PublicKey::new(cert.signature_key().clone(), "")
        .to_openssh()
        .unwrap();
    assert_eq!(signer, set[0]);
    assert_eq!(
        lab.coord
            .ssh_live_serials(peer.as_uri(), "oidc:alice")
            .unwrap(),
        vec![cert.serial()]
    );
}

#[test]
fn the_cert_ends_with_the_node_svid_when_the_svid_ends_first() {
    let lab = lab();
    let peer = lab.node_of("alice", "alice-laptop");
    let key = new_key();
    let exporter = exporter(1);
    let nonce = lab.coord.ssh_nonce(1).unwrap();
    let now = crate::sshca::unix_secs(SystemTime::now()).unwrap();
    let issued = lab
        .coord
        .ssh_issue(
            &peer,
            now + 120,
            1,
            &exporter,
            &ask_for(&key, &exporter, &nonce),
            SystemTime::now(),
        )
        .unwrap();
    assert_eq!(parse(&issued.text).valid_before(), now + 120);
}

#[test]
fn mallory_without_an_ssh_rule_gets_no_cert_and_one_deny_record() {
    let lab = lab();
    let peer = lab.node_of("mallory", "mallory-laptop");
    assert_eq!(deny_of(lab.issue(&peer, 3, &new_key())), SshDeny::NoGrant);
    let records = lab.scratch.ssh_records();
    assert_eq!(records.len(), 1);
    assert!(records[0].contains("decision deny reason no-grant"));
    assert!(records[0].contains("principal oidc:mallory"));
}

#[test]
fn a_pending_or_rejected_owner_gets_no_cert() {
    let node = StoredNode {
        name: "nina-laptop".to_string(),
        overlay_ip: "100.64.0.9".to_string(),
        svid: "spiffe://orblx.local/node/nina-laptop".to_string(),
        owner: "oidc:nina".to_string(),
        endpoints: Vec::new(),
        routes: Vec::new(),
        exit_node: false,
        approved: true,
        expired: false,
    };
    let policy = Policy::from_hujson(
        br#"{"ssh":[{"src":["spiffe://orblx.local/user/nina"],"dst":["spiffe://orblx.local/node/b"],"users":["nina"],"checkPeriod":"30s"}]}"#,
    )
    .unwrap();
    let peer = SpiffeId::node("nina-laptop").unwrap();
    let revoked = BTreeSet::new();
    let nodes = vec![node.clone()];
    for (state, want) in [
        (Some(UserState::Pending), Err(SshDeny::UserPending)),
        (None, Err(SshDeny::UserPending)),
        (Some(UserState::Rejected), Err(SshDeny::UserRejected)),
    ] {
        let user_state = move |_: &str| state;
        let facts = IssueFacts {
            nodes: &nodes,
            user_state: &user_state,
            revoked_uris: &revoked,
            policy: &policy,
        };
        assert_eq!(decide(&peer, &facts).map(|granted| granted.owner), want);
    }
    let approved = |_: &str| Some(UserState::Approved);
    let facts = IssueFacts {
        nodes: &nodes,
        user_state: &approved,
        revoked_uris: &revoked,
        policy: &policy,
    };
    assert_eq!(
        decide(&peer, &facts).map(|granted| granted.owner),
        Ok("oidc:nina".to_string())
    );
    // A token node has no user owner.
    let token_nodes = vec![StoredNode {
        owner: "token:abc".to_string(),
        ..node
    }];
    let facts = IssueFacts {
        nodes: &token_nodes,
        user_state: &approved,
        revoked_uris: &revoked,
        policy: &policy,
    };
    assert_eq!(
        decide(&peer, &facts).map(|granted| granted.owner),
        Err(SshDeny::NoOwner)
    );
}

#[test]
fn a_revoked_node_or_user_gets_no_new_cert_and_its_live_serials_go_to_the_netmap() {
    let lab = lab();
    let alice = lab.node_of("alice", "alice-laptop");
    let sam = lab.node_of("sam", "sam-laptop");
    let first = parse(&lab.issue(&alice, 1, &new_key()).unwrap().text);
    let second = parse(&lab.issue(&sam, 2, &new_key()).unwrap().text);

    crate::admin::revoke(&lab.coord, "alice-laptop", OWNER, lab.now).unwrap();
    assert_eq!(
        deny_of(lab.issue(&alice, 3, &new_key())),
        SshDeny::NodeRevoked
    );
    let view = lab.coord.netmap_for("b-missing").err();
    assert!(view.is_some(), "an unknown node gets no view");

    crate::admin::revoke_all(&lab.coord, "spiffe://orblx.local/user/sam", OWNER, lab.now).unwrap();
    assert_eq!(
        deny_of(lab.issue(&sam, 4, &new_key())),
        SshDeny::UserRevoked
    );

    assert!(lab.coord.ssh_tick(SystemTime::now()).unwrap());
    let carol = lab.node_of("alice", "alice-desk");
    let view = lab.coord.netmap_for("alice-desk").unwrap();
    let netmap = view.signed_netmap.netmap;
    let serials: Vec<u64> = netmap.ssh_revoked.iter().map(|item| item.serial).collect();
    assert!(serials.contains(&first.serial()), "{serials:?}");
    assert!(serials.contains(&second.serial()), "{serials:?}");
    assert!(netmap
        .ssh_revoked
        .iter()
        .any(|item| item.key_id == first.key_id()));
    assert_eq!(netmap.ssh_user_ca, lab.coord.ssh_user_ca().unwrap());
    // The other node of alice is not revoked.
    assert!(lab.issue(&carol, 5, &new_key()).is_ok());
}

#[test]
fn a_revoked_user_gets_no_cert_from_a_node_that_is_not_revoked() {
    let lab = lab();
    let alice = lab.node_of("alice", "alice-laptop");
    // Revoke only the user SVID of alice. The node SVID stays.
    let deny = serde_json::json!({
        "version": 1,
        "generated_at": 0,
        "revoked_uris": ["spiffe://orblx.local/user/alice"],
        "revoked_ticket_nonces": [],
    });
    fs::write(lab.scratch.0.join("deny.json"), deny.to_string()).unwrap();
    assert_eq!(
        deny_of(lab.issue(&alice, 1, &new_key())),
        SshDeny::UserRevoked
    );
}

#[test]
fn agent_coord_and_user_svids_get_no_cert_and_each_deny_is_audited() {
    let lab = lab();
    for (peer, want) in [
        (SpiffeId::agent("helper").unwrap(), SshDeny::AgentSvid),
        (SpiffeId::coord("coord").unwrap(), SshDeny::CoordSvid),
        (SpiffeId::user("alice").unwrap(), SshDeny::UserSvid),
        (SpiffeId::node("ghost").unwrap(), SshDeny::NodeUnknown),
    ] {
        assert_eq!(deny_of(lab.issue(&peer, 9, &new_key())), want);
    }
    let records = lab.scratch.ssh_records();
    assert_eq!(records.len(), 4);
    for (record, reason) in
        records
            .iter()
            .zip(["agent-svid", "coord-svid", "user-svid", "node-unknown"])
    {
        assert!(
            record.contains(&format!("decision deny reason {reason}")),
            "{record}"
        );
    }
}

#[test]
fn a_nonce_replay_or_a_nonce_from_another_connection_gets_deny() {
    let lab = lab();
    let peer = lab.node_of("alice", "alice-laptop");
    let key = new_key();
    let exporter_a = exporter(1);
    let nonce = lab.coord.ssh_nonce(1).unwrap();
    let ask = ask_for(&key, &exporter_a, &nonce);
    assert!(lab
        .coord
        .ssh_issue(&peer, far(), 1, &exporter_a, &ask, SystemTime::now())
        .is_ok());
    // The same nonce again on the same connection.
    assert_eq!(
        deny_of(
            lab.coord
                .ssh_issue(&peer, far(), 1, &exporter_a, &ask, SystemTime::now())
        ),
        SshDeny::Nonce
    );
    // A nonce of connection 1 on connection 2.
    let nonce = lab.coord.ssh_nonce(1).unwrap();
    let exporter_b = exporter(2);
    let ask = ask_for(&key, &exporter_b, &nonce);
    assert_eq!(
        deny_of(
            lab.coord
                .ssh_issue(&peer, far(), 2, &exporter_b, &ask, SystemTime::now())
        ),
        SshDeny::Nonce
    );
    // An unknown nonce.
    let ask = ask_for(&key, &exporter_a, &[7u8; 32]);
    assert_eq!(
        deny_of(
            lab.coord
                .ssh_issue(&peer, far(), 1, &exporter_a, &ask, SystemTime::now())
        ),
        SshDeny::Nonce
    );
}

#[test]
fn an_sshsig_over_the_exporter_of_another_connection_gets_deny() {
    let lab = lab();
    let peer = lab.node_of("alice", "alice-laptop");
    let key = new_key();
    let nonce = lab.coord.ssh_nonce(1).unwrap();
    // The node signed the exporter of connection 2, but asks on connection 1.
    let ask = ask_for(&key, &exporter(2), &nonce);
    assert_eq!(
        deny_of(
            lab.coord
                .ssh_issue(&peer, far(), 1, &exporter(1), &ask, SystemTime::now())
        ),
        SshDeny::Signature
    );
    // The SSHSIG is by a different key than the key in the request.
    let nonce = lab.coord.ssh_nonce(1).unwrap();
    let mut ask = ask_for(&key, &exporter(1), &nonce);
    ask.public_key = new_key().public_key().to_openssh().unwrap();
    assert_eq!(
        deny_of(
            lab.coord
                .ssh_issue(&peer, far(), 1, &exporter(1), &ask, SystemTime::now())
        ),
        SshDeny::Signature
    );
}

#[test]
fn a_sharee_gets_only_the_sharee_principal_and_cannot_ask_for_the_sharer() {
    let lab = lab();
    let _alice = lab.node_of("alice", "alice-laptop");
    let sam = lab.node_of("sam", "sam-laptop");
    let cert = parse(&lab.issue(&sam, 1, &new_key()).unwrap().text);
    assert_eq!(cert.valid_principals(), ["oidc:sam".to_string()]);
    assert!(cert.key_id().contains("owner=oidc:sam"));
    // The request has no principal field. A request that names the sharer is refused.
    let named = serde_json::json!({
        "public_key": "ssh-ed25519 AAAA",
        "sshsig": "x",
        "nonce": "00",
        "principal": "oidc:alice",
    });
    assert!(serde_json::from_value::<SshCertAsk>(named).is_err());
}

#[test]
fn each_issue_decision_writes_exactly_one_audit_record() {
    let lab = lab();
    let alice = lab.node_of("alice", "alice-laptop");
    let mallory = lab.node_of("mallory", "mallory-laptop");
    let issued = lab.issue(&alice, 1, &new_key()).unwrap();
    let _ = lab.issue(&mallory, 2, &new_key());
    let _ = lab.issue(&alice, 3, &new_key()).unwrap();
    let records = lab.scratch.ssh_records();
    assert_eq!(records.len(), 3);
    let first = &records[0];
    assert!(first.contains("decision allow"));
    assert!(first.contains(&format!("serial {}", issued.serial)));
    assert!(first.contains(&format!("fp {}", issued.fingerprint)));
    assert!(first.contains("node spiffe://orblx.local/node/alice-laptop"));
    assert!(first.contains("principal oidc:alice"));
    assert!(first.contains(&format!("valid_before {}", issued.valid_before)));
    assert!(first.contains("rule 0"));
    assert!(records[1].contains("decision deny reason no-grant"));
}

#[test]
fn a_rotation_moves_next_to_current_and_drops_the_old_ca_from_the_netmap() {
    let lab = lab();
    let peer = lab.node_of("alice", "alice-laptop");
    let before = lab.coord.ssh_user_ca().unwrap();
    let cert = parse(&lab.issue(&peer, 1, &new_key()).unwrap().text);
    lab.coord.ssh_rotate(SystemTime::now()).unwrap();
    let after = lab.coord.ssh_user_ca().unwrap();
    assert_eq!(after.len(), 2);
    assert_eq!(after[0], before[1]);
    assert!(!after.contains(&before[0]));
    let signer = PublicKey::new(cert.signature_key().clone(), "")
        .to_openssh()
        .unwrap();
    assert!(!after.contains(&signer), "the old CA left the set");
    // The keys stay after a restart.
    drop(lab.coord);
    let gate = IssueGate::new(MiniCa::generate(lab.now).unwrap(), &lab.oidc).unwrap();
    let again =
        Coordinator::open(&lab.scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
    assert_eq!(again.ssh_user_ca().unwrap(), after);
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &fs::metadata(lab.scratch.0.join(crate::sshca::SSH_CA_FILE))
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_rotation_is_due_after_24_hours_only() {
    let scratch = Scratch::new();
    let mut ca = crate::sshca::SshCa::open(&scratch.0, 1_000).unwrap();
    assert!(!ca.rotate_due(&scratch.0, 1_000 + 86_399).unwrap());
    assert!(ca.rotate_due(&scratch.0, 1_000 + 86_400).unwrap());
    assert!(!ca.rotate_due(&scratch.0, 1_000 + 86_401).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mtls_path_binds_the_sshsig_to_the_same_connection() {
    use std::net::{Ipv4Addr, SocketAddr};
    let lab = lab();
    let node_dir = Scratch::new();
    let _ = lab.coord.approve_user_by("oidc:alice", OWNER, lab.now);
    let token = lab
        .oidc
        .issue_id_token("alice", lab.now, Duration::from_secs(600))
        .unwrap();
    let enrolled = lab
        .coord
        .enroll_oidc(
            "alice-laptop",
            &token,
            None,
            &["127.0.0.1:443".to_string()],
            &[],
            lab.now,
        )
        .unwrap();
    enrolled.write_state(&node_dir.0).unwrap();
    let (addr, handle) =
        crate::server::spawn(&lab.coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
    let bundle = fs::read_to_string(lab.scratch.0.join("trust-bundle.pem")).unwrap();

    let key = new_key();
    let material = crate::state::read_node_material(&node_dir.0).unwrap();
    let ask_key = key.clone();
    let text = crate::client::ssh_cert_request(addr, "coord", &bundle, material, move |e, n| {
        Ok(ask_for(&ask_key, e, n))
    })
    .await
    .unwrap();
    assert_eq!(parse(&text).valid_principals(), ["oidc:alice".to_string()]);

    // An SSHSIG over an exporter that is not the exporter of this connection.
    let material = crate::state::read_node_material(&node_dir.0).unwrap();
    let ask_key = key.clone();
    let err = crate::client::ssh_cert_request(addr, "coord", &bundle, material, move |_, n| {
        Ok(ask_for(&ask_key, &[0u8; SSH_EXPORTER_LEN], n))
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("reason signature"), "{err}");

    // A nonce from an earlier connection on a new connection.
    let material = crate::state::read_node_material(&node_dir.0).unwrap();
    let old_nonce = std::sync::Arc::new(std::sync::Mutex::new(None));
    let keep = old_nonce.clone();
    let ask_key = key.clone();
    let _ = crate::client::ssh_cert_request(addr, "coord", &bundle, material, move |e, n| {
        *keep.lock().unwrap() = Some(*n);
        Ok(ask_for(&ask_key, e, n))
    })
    .await
    .unwrap();
    let replay = old_nonce.lock().unwrap().unwrap();
    let material = crate::state::read_node_material(&node_dir.0).unwrap();
    let err = crate::client::ssh_cert_request(addr, "coord", &bundle, material, move |e, _| {
        Ok(ask_for(&key, e, &replay))
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("reason nonce"), "{err}");
    assert_eq!(lab.scratch.ssh_records().len(), 4);
    handle.abort();
}
