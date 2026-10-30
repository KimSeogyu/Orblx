//! Generic OIDC issuer checks with RS256 and ES256 test keys.

use std::time::SystemTime;

use orblx_identity::{token_kid, OidcIssuer, OidcJwks, OidcReject};
use orblx_test_idp::{
    discovery_json, jwks_json, mint, tamper_signature, unix_now, KeyAlg, MintSpec, TestKey,
};

const ISSUER: &str = "https://idp.test:8443";
const CLIENT: &str = "orblx-test";

struct Keys {
    rs: TestKey,
    es: TestKey,
}

fn keys() -> Keys {
    Keys {
        rs: TestKey::generate("rs1", KeyAlg::RS256).unwrap(),
        es: TestKey::generate("es1", KeyAlg::ES256).unwrap(),
    }
}

fn issuer(domains: &[&str], emails: &[&str]) -> OidcIssuer {
    let domains: Vec<String> = domains.iter().map(|v| v.to_string()).collect();
    let emails: Vec<String> = emails.iter().map(|v| v.to_string()).collect();
    OidcIssuer::new(ISSUER, CLIENT, &domains, &emails).unwrap()
}

fn spec() -> MintSpec {
    MintSpec::now(ISSUER, CLIENT, "alice", 600)
}

fn check(jwks: &OidcJwks, token: &str, issuer: &OidcIssuer) -> Result<String, OidcReject> {
    jwks.verify(token, issuer, None, SystemTime::now())
        .map(|claims| claims.subject)
}

#[test]
fn rs256_and_es256_tokens_pass() {
    let keys = keys();
    let jwks = OidcJwks::from_json(&jwks_json(&[keys.rs.clone(), keys.es.clone()])).unwrap();
    assert_eq!(jwks.kids(), vec!["rs1", "es1"]);
    let issuer = issuer(&[], &[]);
    for key in [&keys.rs, &keys.es] {
        let token = mint(key, &spec(), None).unwrap();
        assert_eq!(token_kid(&token).as_deref(), Some(key.kid.as_str()));
        assert_eq!(check(&jwks, &token, &issuer).unwrap(), "alice");
    }
}

#[test]
fn each_bad_token_has_its_own_reason() {
    let keys = keys();
    let jwks = OidcJwks::from_json(&jwks_json(&[keys.rs.clone(), keys.es.clone()])).unwrap();
    let issuer = issuer(&[], &[]);
    for key in [&keys.rs, &keys.es] {
        let mut wrong_issuer = spec();
        wrong_issuer.issuer = "https://evil.test".to_string();
        let token = mint(key, &wrong_issuer, None).unwrap();
        assert_eq!(check(&jwks, &token, &issuer), Err(OidcReject::Issuer));

        let mut wrong_audience = spec();
        wrong_audience.audience = "other-client".to_string();
        let token = mint(key, &wrong_audience, None).unwrap();
        assert_eq!(check(&jwks, &token, &issuer), Err(OidcReject::Audience));

        let mut expired = spec();
        expired.issued_at = unix_now() - 3600;
        expired.expires_at = unix_now() - 600;
        let token = mint(key, &expired, None).unwrap();
        assert_eq!(check(&jwks, &token, &issuer), Err(OidcReject::Expired));

        let mut future = spec();
        future.issued_at = unix_now() + 3600;
        future.expires_at = unix_now() + 7200;
        let token = mint(key, &future, None).unwrap();
        assert_eq!(check(&jwks, &token, &issuer), Err(OidcReject::NotYetValid));

        let token = tamper_signature(&mint(key, &spec(), None).unwrap());
        assert_eq!(check(&jwks, &token, &issuer), Err(OidcReject::Signature));

        let token = mint(key, &spec(), Some("gone")).unwrap();
        assert_eq!(check(&jwks, &token, &issuer), Err(OidcReject::UnknownKey));
    }
}

#[test]
fn a_key_from_an_other_issuer_fails_the_signature_check() {
    let keys = keys();
    let jwks = OidcJwks::from_json(&jwks_json(std::slice::from_ref(&keys.es))).unwrap();
    let stranger = TestKey::generate("es1", KeyAlg::ES256).unwrap();
    let token = mint(&stranger, &spec(), None).unwrap();
    assert_eq!(
        check(&jwks, &token, &issuer(&[], &[])),
        Err(OidcReject::Signature)
    );
}

#[test]
fn a_kid_with_the_wrong_algorithm_is_rejected() {
    let keys = keys();
    let jwks = OidcJwks::from_json(&jwks_json(std::slice::from_ref(&keys.rs))).unwrap();
    let token = mint(&keys.es, &spec(), Some("rs1")).unwrap();
    assert_eq!(
        check(&jwks, &token, &issuer(&[], &[])),
        Err(OidcReject::Algorithm)
    );
}

#[test]
fn the_nonce_must_match() {
    let keys = keys();
    let jwks = OidcJwks::from_json(&jwks_json(std::slice::from_ref(&keys.rs))).unwrap();
    let issuer = issuer(&[], &[]);
    let mut with_nonce = spec();
    with_nonce.nonce = Some("00112233445566778899aabbccddeeff".to_string());
    let token = mint(&keys.rs, &with_nonce, None).unwrap();
    let now = SystemTime::now();
    assert!(jwks
        .verify(
            &token,
            &issuer,
            Some("00112233445566778899aabbccddeeff"),
            now
        )
        .is_ok());
    assert_eq!(
        jwks.verify(
            &token,
            &issuer,
            Some("ffeeddccbbaa99887766554433221100"),
            now
        ),
        Err(OidcReject::Nonce)
    );
    assert_eq!(
        jwks.verify(&token, &issuer, None, now),
        Err(OidcReject::Nonce)
    );
}

#[test]
fn allowed_domains_and_emails_gate_the_subject() {
    let keys = keys();
    let jwks = OidcJwks::from_json(&jwks_json(std::slice::from_ref(&keys.es))).unwrap();
    let gate = issuer(&["example.com"], &["bob@partner.test"]);
    let mut alice = spec();
    alice.email = Some("Alice@Example.com".to_string());
    let token = mint(&keys.es, &alice, None).unwrap();
    let claims = jwks.verify(&token, &gate, None, SystemTime::now()).unwrap();
    assert_eq!(claims.email.as_deref(), Some("alice@example.com"));

    let mut bob = spec();
    bob.subject = "bob".to_string();
    bob.email = Some("bob@partner.test".to_string());
    assert!(check(&jwks, &mint(&keys.es, &bob, None).unwrap(), &gate).is_ok());

    let mut eve = spec();
    eve.email = Some("eve@other.test".to_string());
    assert_eq!(
        check(&jwks, &mint(&keys.es, &eve, None).unwrap(), &gate),
        Err(OidcReject::Email)
    );

    let mut unverified = alice.clone();
    unverified.email_verified = false;
    assert_eq!(
        check(&jwks, &mint(&keys.es, &unverified, None).unwrap(), &gate),
        Err(OidcReject::Email)
    );

    assert_eq!(
        check(&jwks, &mint(&keys.es, &spec(), None).unwrap(), &gate),
        Err(OidcReject::Email)
    );
}

#[test]
fn discovery_gives_the_jwks_uri_and_checks_the_issuer() {
    let gate = issuer(&[], &[]);
    assert_eq!(
        gate.discovery_url(),
        "https://idp.test:8443/.well-known/openid-configuration"
    );
    assert_eq!(
        gate.jwks_uri_from_discovery(&discovery_json(ISSUER))
            .unwrap(),
        "https://idp.test:8443/jwks"
    );
    assert!(gate
        .jwks_uri_from_discovery(&discovery_json("https://evil.test"))
        .is_err());
    let plain = discovery_json(ISSUER).replace("https://idp.test:8443/jwks", "http://idp/jwks");
    assert!(gate.jwks_uri_from_discovery(&plain).is_err());
}

#[test]
fn the_issuer_config_is_checked() {
    let none: Vec<String> = Vec::new();
    assert!(OidcIssuer::new("http://idp.test", CLIENT, &none, &none).is_err());
    assert!(OidcIssuer::new("https://idp.test?x=1", CLIENT, &none, &none).is_err());
    assert!(OidcIssuer::new("https://user@idp.test", CLIENT, &none, &none).is_err());
    assert!(OidcIssuer::new(ISSUER, "", &none, &none).is_err());
    assert!(OidcIssuer::new(ISSUER, "a b", &none, &none).is_err());
    assert!(OidcIssuer::new(ISSUER, CLIENT, &["bad domain".to_string()], &none).is_err());
    assert!(OidcIssuer::new(ISSUER, CLIENT, &none, &["no-at".to_string()]).is_err());
}

#[test]
fn a_jwks_without_a_usable_key_is_rejected() {
    assert!(OidcJwks::from_json(r#"{"keys":[]}"#).is_err());
    let keys = keys();
    let mut enc = keys.rs.clone();
    enc.jwk["use"] = serde_json::json!("enc");
    assert!(OidcJwks::from_json(&jwks_json(&[enc])).is_err());
    let twice = jwks_json(&[keys.rs.clone(), keys.rs.clone()]);
    assert!(OidcJwks::from_json(&twice).is_err());
}
