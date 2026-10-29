//! Google ID token checks and the short human SVID.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use gyeol_identity::{
    DenySet, GoogleClient, GoogleJwks, GoogleTokenRequest, IdentityError, IssueGate, MiniCa,
    MockOidc, OidcMode, GOOGLE_AUTHORIZE_ENDPOINT, GOOGLE_CLIENT_ID_ENV, GOOGLE_CLIENT_SECRET_ENV,
    GOOGLE_ISSUER, GOOGLE_JWKS_URL, GOOGLE_REDIRECT_LOCALHOST, GOOGLE_REDIRECT_LOOPBACK,
    GOOGLE_TOKEN_ENDPOINT, MAX_USER_TTL, MOCK_OIDC_ISSUER, OIDC_AUDIENCE, OIDC_MODE_ENV,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};

const CLIENT_ID: &str = "100-test.apps.googleusercontent.com";
const REGISTERED_CLIENT_ID: &str =
    "949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com";
const SECRET: &str = "test-secret-value";
const NONCE: &str = "00112233445566778899aabbccddeeff";
const STATE: &str = "ffeeddccbbaa99887766554433221100";
const SUBJECT: &str = "110169484474386276334";
const KID: &str = "test-key-1";

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    encoding: EncodingKey,
    other: EncodingKey,
    jwks: String,
}

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn fixture() -> Fixture {
    let (encoding, n, e) = rsa_key();
    let (other, _, _) = rsa_key();
    let jwks = format!(
        r#"{{"keys":[
            {{"kty":"RSA","alg":"RS256","use":"sig","kid":"{KID}","n":"{n}","e":"{e}"}},
            {{"kty":"RSA","alg":"RS256","use":"enc","kid":"enc-key","n":"{n}","e":"{e}"}}
        ]}}"#
    );
    Fixture {
        encoding,
        other,
        jwks,
    }
}

fn rsa_key() -> (EncodingKey, String, String) {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    let modulus = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
    let exponent = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
    (encoding, modulus, exponent)
}

fn token(encoding: &EncodingKey, mut claims: Value) -> String {
    if claims.get("iss").is_none() {
        claims["iss"] = json!(GOOGLE_ISSUER);
    }
    if claims.get("sub").is_none() {
        claims["sub"] = json!(SUBJECT);
    }
    if claims.get("aud").is_none() {
        claims["aud"] = json!(CLIENT_ID);
    }
    if claims.get("iat").is_none() {
        claims["iat"] = json!(unix(now()));
    }
    if claims.get("exp").is_none() {
        claims["exp"] = json!(unix(now()) + 3600);
    }
    if claims.get("nonce").is_none() {
        claims["nonce"] = json!(NONCE);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    encode(&header, &claims, encoding).unwrap()
}

fn gate(jwks: &str) -> IssueGate {
    let parsed = GoogleJwks::from_json(jwks).unwrap();
    let ca = MiniCa::generate(now()).unwrap();
    IssueGate::from_google(ca, CLIENT_ID, parsed).unwrap()
}

#[test]
fn the_default_mode_is_google() {
    assert_eq!(OidcMode::parse(None).unwrap(), OidcMode::Google);
    assert_eq!(OidcMode::parse(Some("")).unwrap(), OidcMode::Google);
    assert_eq!(OidcMode::parse(Some("google")).unwrap(), OidcMode::Google);
    assert_eq!(OidcMode::parse(Some("MOCK")).unwrap(), OidcMode::Mock);
    assert_eq!(
        OidcMode::parse(Some("local")).unwrap_err(),
        IdentityError::Config
    );
}

#[test]
fn the_env_selects_google_unless_mock_is_set() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let previous = std::env::var(OIDC_MODE_ENV).ok();
    std::env::remove_var(OIDC_MODE_ENV);
    assert_eq!(OidcMode::from_env().unwrap(), OidcMode::Google);
    std::env::set_var(OIDC_MODE_ENV, "mock");
    assert_eq!(OidcMode::from_env().unwrap(), OidcMode::Mock);
    std::env::set_var(OIDC_MODE_ENV, "google");
    assert_eq!(OidcMode::from_env().unwrap(), OidcMode::Google);
    match previous {
        Some(value) => std::env::set_var(OIDC_MODE_ENV, value),
        None => std::env::remove_var(OIDC_MODE_ENV),
    }
}

#[test]
fn the_registered_client_builds_an_authorize_url() {
    let client = GoogleClient::new(REGISTERED_CLIENT_ID, SECRET).unwrap();
    assert_eq!(client.client_id(), REGISTERED_CLIENT_ID);
    let url = client
        .authorize_url(GOOGLE_REDIRECT_LOOPBACK, STATE, NONCE)
        .unwrap();
    assert!(url.starts_with(GOOGLE_AUTHORIZE_ENDPOINT));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("scope=openid"));
    assert!(url.contains("prompt=select_account"));
    assert!(url.contains(REGISTERED_CLIENT_ID));
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8787%2Foidc%2Fcallback"));
    assert!(url.contains(&format!("state={STATE}")));
    assert!(url.contains(&format!("nonce={NONCE}")));
    assert!(!url.contains(SECRET));
    assert!(!format!("{client:?}").contains(SECRET));
    let local = client
        .authorize_url(GOOGLE_REDIRECT_LOCALHOST, STATE, NONCE)
        .unwrap();
    assert!(local.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8787%2Foidc%2Fcallback"));
    assert_eq!(
        client
            .authorize_url("http://127.0.0.1:8790/oidc/callback", STATE, NONCE)
            .unwrap_err(),
        IdentityError::Config
    );
    assert_eq!(
        client
            .authorize_url("https://evil.example/oidc/callback", STATE, NONCE)
            .unwrap_err(),
        IdentityError::Config
    );
}

#[test]
fn the_token_request_carries_the_secret_and_debug_hides_it() {
    let client = GoogleClient::new(CLIENT_ID, SECRET).unwrap();
    let request = client
        .token_request("4/auth-code", GOOGLE_REDIRECT_LOOPBACK)
        .unwrap();
    assert_eq!(request.endpoint(), GOOGLE_TOKEN_ENDPOINT);
    assert_eq!(
        GoogleTokenRequest::CONTENT_TYPE,
        "application/x-www-form-urlencoded"
    );
    assert!(request.body().contains("grant_type=authorization_code"));
    assert!(request.body().contains("code=4%2Fauth-code"));
    assert!(request.body().contains(&format!("client_secret={SECRET}")));
    assert!(!format!("{request:?}").contains(SECRET));
    let id_token = "aaa.bbb.ccc";
    let body = json!({"id_token": id_token, "access_token": "hidden"}).to_string();
    assert_eq!(
        GoogleTokenRequest::id_token_from_response(&body).unwrap(),
        id_token
    );
    assert!(GoogleTokenRequest::id_token_from_response(r#"{"error":"invalid_grant"}"#).is_err());
}

#[test]
fn the_client_reads_both_env_vars() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let saved_id = std::env::var(GOOGLE_CLIENT_ID_ENV).ok();
    let saved_secret = std::env::var(GOOGLE_CLIENT_SECRET_ENV).ok();
    std::env::remove_var(GOOGLE_CLIENT_SECRET_ENV);
    std::env::set_var(GOOGLE_CLIENT_ID_ENV, REGISTERED_CLIENT_ID);
    assert_eq!(GoogleClient::from_env().unwrap_err(), IdentityError::Config);
    std::env::set_var(GOOGLE_CLIENT_SECRET_ENV, SECRET);
    let client = GoogleClient::from_env().unwrap();
    assert_eq!(client.client_id(), REGISTERED_CLIENT_ID);
    assert!(!format!("{client:?}").contains(SECRET));
    restore(GOOGLE_CLIENT_ID_ENV, saved_id);
    restore(GOOGLE_CLIENT_SECRET_ENV, saved_secret);
}

#[test]
fn a_google_id_token_issues_a_short_human_svid() {
    let keys = fixture();
    let issued = gate(&keys.jwks);
    assert_eq!(issued.mode(), OidcMode::Google);
    assert_eq!(issued.client_id(), Some(CLIENT_ID));
    let id_token = token(&keys.encoding, json!({}));
    let svid = issued
        .issue_google_human_svid(&id_token, NONCE, now(), &DenySet::empty())
        .unwrap();
    assert_eq!(
        svid.spiffe_id.as_uri(),
        format!("spiffe://gyeol.local/user/{SUBJECT}")
    );
    assert!(svid.not_after - svid.not_before <= MAX_USER_TTL.as_secs());
    assert_eq!(svid.not_after - svid.not_before, MAX_USER_TTL.as_secs());
    let short = token(&keys.encoding, json!({"exp": unix(now()) + 30}));
    let short_svid = issued
        .issue_google_human_svid(&short, NONCE, now(), &DenySet::empty())
        .unwrap();
    assert_eq!(short_svid.not_after - short_svid.not_before, 30);
    assert_eq!(
        issued
            .issue_human_svid(&id_token, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::Token
    );
    assert_eq!(
        issued
            .issue_agent_svid(
                &id_token,
                "worker",
                now(),
                Duration::from_secs(60),
                &DenySet::empty()
            )
            .unwrap_err(),
        IdentityError::Token
    );
    assert_eq!(
        GOOGLE_JWKS_URL,
        "https://www.googleapis.com/oauth2/v3/certs"
    );
}

#[test]
fn google_rejects_a_bad_token() {
    let keys = fixture();
    let issued = gate(&keys.jwks);
    let bad_aud = token(
        &keys.encoding,
        json!({"aud": "200-other.apps.googleusercontent.com"}),
    );
    assert_eq!(
        issued
            .issue_google_human_svid(&bad_aud, NONCE, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::Audience
    );
    let bad_iss = token(&keys.encoding, json!({"iss": "https://oidc.gyeol.local"}));
    assert!(issued
        .issue_google_human_svid(&bad_iss, NONCE, now(), &DenySet::empty())
        .is_err());
    let bad_nonce = token(&keys.encoding, json!({"nonce": "0011223344556677"}));
    assert_eq!(
        issued
            .issue_google_human_svid(&bad_nonce, NONCE, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::Token
    );
    let expired = token(
        &keys.encoding,
        json!({"exp": unix(now()) - 120, "iat": unix(now()) - 180}),
    );
    assert_eq!(
        issued
            .issue_google_human_svid(&expired, NONCE, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::Expired
    );
    let other = token(&keys.other, json!({}));
    assert_eq!(
        issued
            .issue_google_human_svid(&other, NONCE, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::Signature
    );
    let bad_sub = token(&keys.encoding, json!({"sub": "bad/name"}));
    assert_eq!(
        issued
            .issue_google_human_svid(&bad_sub, NONCE, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::SpiffeId
    );
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.to_string());
    let hs = encode(
        &header,
        &json!({"iss": GOOGLE_ISSUER, "sub": SUBJECT, "aud": CLIENT_ID, "exp": unix(now()) + 60, "iat": unix(now()), "nonce": NONCE}),
        &EncodingKey::from_secret(b"not-the-google-key"),
    )
    .unwrap();
    assert_eq!(
        issued
            .issue_google_human_svid(&hs, NONCE, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::Token
    );
}

#[test]
fn google_accepts_one_audience_list_when_azp_matches() {
    let keys = fixture();
    let issued = gate(&keys.jwks);
    let id_token = token(
        &keys.encoding,
        json!({
            "aud": [CLIENT_ID, "200-other.apps.googleusercontent.com"],
            "azp": CLIENT_ID
        }),
    );
    let svid = issued
        .issue_google_human_svid(&id_token, NONCE, now(), &DenySet::empty())
        .unwrap();
    assert!(svid.spiffe_id.as_uri().ends_with(SUBJECT));
    let missing_azp = token(
        &keys.encoding,
        json!({"aud": [CLIENT_ID, "200-other.apps.googleusercontent.com"]}),
    );
    assert_eq!(
        issued
            .issue_google_human_svid(&missing_azp, NONCE, now(), &DenySet::empty())
            .unwrap_err(),
        IdentityError::Audience
    );
}

#[test]
fn a_mock_gate_does_not_accept_the_google_method() {
    let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
    let ca = MiniCa::generate(now()).unwrap();
    let gate = IssueGate::new(ca, &oidc).unwrap();
    assert_eq!(gate.mode(), OidcMode::Mock);
    assert_eq!(gate.client_id(), None);
    assert_eq!(OIDC_AUDIENCE, "gyeol-issue");
    let err = gate
        .issue_google_human_svid("a.b.c", NONCE, now(), &DenySet::empty())
        .unwrap_err();
    assert_eq!(err, IdentityError::Token);
}

#[test]
fn a_jwks_document_rejects_a_repeated_kid() {
    let (_encoding, n, e) = rsa_key();
    let text = format!(
        r#"{{"keys":[
            {{"kty":"RSA","alg":"RS256","use":"sig","kid":"{KID}","n":"{n}","e":"{e}"}},
            {{"kty":"RSA","alg":"RS256","use":"sig","kid":"{KID}","n":"{n}","e":"{e}"}}
        ]}}"#
    );
    assert_eq!(
        GoogleJwks::from_json(&text).unwrap_err(),
        IdentityError::Token
    );
}

fn restore(name: &str, value: Option<String>) {
    match value {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
}
