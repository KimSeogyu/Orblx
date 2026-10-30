//! Generic OIDC issuer enrollment on the coordinator state.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use orblx_identity::{OidcIssuer, OidcJwks};
use orblx_test_idp::{jwks_json, mint, tamper_signature, unix_now, KeyAlg, MintSpec, TestKey};

use crate::error::CoordError;
use crate::state::{Coordinator, OidcConfig, ISSUER_JWKS_TTL_SECS, ISSUER_REFETCH_SECS};

const ISSUER: &str = "https://idp.test:8443";
const CLIENT: &str = "orblx-test";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orblx-issuer-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open(scratch: &Scratch, domains: &[&str]) -> Coordinator {
    let domains: Vec<String> = domains.iter().map(|v| v.to_string()).collect();
    let issuer = OidcIssuer::new(ISSUER, CLIENT, &domains, &[]).unwrap();
    Coordinator::open(
        &scratch.0,
        "coord",
        OidcConfig::Issuer {
            issuer: Box::new(issuer),
            extra_roots_pem: None,
        },
    )
    .unwrap()
}

fn spec(subject: &str) -> MintSpec {
    let mut spec = MintSpec::now(ISSUER, CLIENT, subject, 600);
    spec.email = Some(format!("{subject}@example.com"));
    spec
}

#[test]
fn a_generic_issuer_token_enrolls_a_node_and_bad_tokens_fail() {
    let scratch = Scratch::new();
    let coord = open(&scratch, &["example.com"]);
    let rs = TestKey::generate("rs1", KeyAlg::RS256).unwrap();
    let es = TestKey::generate("es1", KeyAlg::ES256).unwrap();
    let now = SystemTime::now();

    let token = mint(&rs, &spec("alice"), None).unwrap();
    assert!(matches!(
        coord.enroll_oidc("laptop", &token, None, &[], &[], now),
        Err(CoordError::Oidc)
    ));

    let jwks = OidcJwks::from_json(&jwks_json(&[rs.clone(), es.clone()])).unwrap();
    coord.install_issuer_jwks(jwks, now).unwrap();
    let result = coord
        .enroll_oidc(
            "laptop",
            &token,
            None,
            &["laptop:443".to_string()],
            &[],
            now,
        )
        .unwrap();
    assert_eq!(result.svid, "spiffe://orblx.local/node/laptop");
    let es_token = mint(&es, &spec("bob"), None).unwrap();
    coord
        .enroll_oidc("desk", &es_token, None, &["desk:443".to_string()], &[], now)
        .unwrap();

    let mut wrong_issuer = spec("carol");
    wrong_issuer.issuer = "https://evil.test".to_string();
    let mut wrong_audience = spec("carol");
    wrong_audience.audience = "other".to_string();
    let mut expired = spec("carol");
    expired.issued_at = unix_now() - 7200;
    expired.expires_at = unix_now() - 3600;
    let mut other_domain = spec("carol");
    other_domain.email = Some("carol@other.test".to_string());
    let bad = [
        mint(&es, &wrong_issuer, None).unwrap(),
        mint(&es, &wrong_audience, None).unwrap(),
        mint(&es, &expired, None).unwrap(),
        tamper_signature(&mint(&es, &spec("carol"), None).unwrap()),
        mint(&es, &spec("carol"), Some("es9")).unwrap(),
        mint(&es, &other_domain, None).unwrap(),
    ];
    for token in bad {
        assert!(matches!(
            coord.enroll_oidc("carol", &token, None, &["carol:443".to_string()], &[], now),
            Err(CoordError::Oidc)
        ));
    }
    let nodes = std::fs::read_to_string(scratch.0.join("nodes.json")).unwrap();
    assert!(nodes.contains("oidc:alice"));
    assert!(nodes.contains("oidc:bob"));
    assert!(!nodes.contains("carol"));
    assert!(!nodes.contains(&token));
}

#[test]
fn the_jwks_cache_fetches_first_stale_and_unknown_kid() {
    let scratch = Scratch::new();
    let coord = open(&scratch, &[]);
    let rs = TestKey::generate("rs1", KeyAlg::RS256).unwrap();
    let start = SystemTime::now();
    let at = |secs: u64| start + Duration::from_secs(secs);

    let plan = coord
        .issuer_fetch_plan(Some("rs1"), at(0))
        .unwrap()
        .unwrap();
    assert_eq!(plan.reason, "first");
    assert_eq!(
        plan.issuer.discovery_url(),
        "https://idp.test:8443/.well-known/openid-configuration"
    );
    // A failed first fetch waits for the refetch gap.
    assert!(coord
        .issuer_fetch_plan(Some("rs1"), at(1))
        .unwrap()
        .is_none());
    let plan = coord
        .issuer_fetch_plan(Some("rs1"), at(ISSUER_REFETCH_SECS))
        .unwrap()
        .unwrap();
    assert_eq!(plan.reason, "first");

    let jwks = OidcJwks::from_json(&jwks_json(&[rs])).unwrap();
    coord.install_issuer_jwks(jwks, at(20)).unwrap();
    assert!(coord
        .issuer_fetch_plan(Some("rs1"), at(21))
        .unwrap()
        .is_none());
    let plan = coord
        .issuer_fetch_plan(Some("es2"), at(30))
        .unwrap()
        .unwrap();
    assert_eq!(plan.reason, "unknown-kid");
    assert!(coord
        .issuer_fetch_plan(Some("es3"), at(31))
        .unwrap()
        .is_none());
    let plan = coord
        .issuer_fetch_plan(Some("rs1"), at(20 + ISSUER_JWKS_TTL_SECS))
        .unwrap()
        .unwrap();
    assert_eq!(plan.reason, "stale");
}
