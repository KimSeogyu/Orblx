//! Google authorization-code OIDC for a human SVID.
//!
//! The default mode is Google.
//! Mock mode is only for CI and the harness.
//! This module does not open a network connection.
//! The harness fetches the JWKS document and posts the token request.

use std::fmt;
use std::time::SystemTime;

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::clock::{in_window, unix_time, MAX_SKEW_SECS};
use crate::error::IdentityError;
use crate::spiffe::SpiffeId;

/// The Google issuer for an ID token.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The Google JWKS document.
///
/// The harness sends `GET` to this URL.
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// The Google authorization endpoint.
pub const GOOGLE_AUTHORIZE_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// The Google token endpoint.
///
/// The harness sends `POST` to this URL.
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// The environment variable for the Google OAuth client id.
pub const GOOGLE_CLIENT_ID_ENV: &str = "ORBLX_GOOGLE_CLIENT_ID";

/// The environment variable for the Google OAuth client secret.
///
/// Do not write this value in the repository, the logs, or the docs.
pub const GOOGLE_CLIENT_SECRET_ENV: &str = "ORBLX_GOOGLE_CLIENT_SECRET";

/// The environment variable that selects Google or the mock IdP.
///
/// An absent value selects Google.
/// `google` selects Google.
/// `mock` selects the mock IdP for CI and the harness.
pub const OIDC_MODE_ENV: &str = "ORBLX_OIDC_MODE";

/// The registered loopback redirect URI.
pub const GOOGLE_REDIRECT_LOOPBACK: &str = "http://127.0.0.1:8787/oidc/callback";

/// The registered localhost redirect URI.
pub const GOOGLE_REDIRECT_LOCALHOST: &str = "http://localhost:8787/oidc/callback";

const CLIENT_ID_SUFFIX: &str = ".apps.googleusercontent.com";
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_KEYS: usize = 8;

/// The IdP for a human sign-in.
///
/// City Breeze uses [`OidcMode::Google`] unless the operator selects mock mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcMode {
    /// Real Google authorization-code OIDC.
    Google,
    /// The built-in mock IdP.
    ///
    /// Use this mode only for CI and the harness.
    Mock,
}

impl OidcMode {
    /// Parse one mode value.
    ///
    /// `None` and an empty string select Google.
    pub fn parse(value: Option<&str>) -> Result<Self, IdentityError> {
        let Some(value) = value.map(str::trim).filter(|text| !text.is_empty()) else {
            return Ok(Self::Google);
        };
        if value.eq_ignore_ascii_case("google") {
            Ok(Self::Google)
        } else if value.eq_ignore_ascii_case("mock") {
            Ok(Self::Mock)
        } else {
            Err(IdentityError::Config)
        }
    }

    /// Read [`OIDC_MODE_ENV`].
    ///
    /// A missing variable selects Google.
    pub fn from_env() -> Result<Self, IdentityError> {
        match std::env::var(OIDC_MODE_ENV) {
            Ok(value) => Self::parse(Some(&value)),
            Err(std::env::VarError::NotPresent) => Ok(Self::Google),
            Err(std::env::VarError::NotUnicode(_)) => Err(IdentityError::Config),
        }
    }
}

/// The Google OAuth Web client.
///
/// The secret stays in memory for the token request.
/// Debug output redacts the secret.
#[derive(Clone)]
pub struct GoogleClient {
    client_id: String,
    client_secret: String,
}

impl fmt::Debug for GoogleClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleClient")
            .field("client_id", &self.client_id)
            .field("client_secret", &"redacted")
            .finish()
    }
}

impl GoogleClient {
    /// Build a client from an id and a secret.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        let client_id = client_id.into();
        let client_secret = client_secret.into();
        require_client_id(&client_id)?;
        require_secret(&client_secret)?;
        Ok(Self {
            client_id,
            client_secret,
        })
    }

    /// Read the client id and the client secret from the environment.
    ///
    /// The function does not fall back to the mock IdP when a variable is missing.
    pub fn from_env() -> Result<Self, IdentityError> {
        let client_id = read_env(GOOGLE_CLIENT_ID_ENV)?;
        let client_secret = read_env(GOOGLE_CLIENT_SECRET_ENV)?;
        Self::new(client_id, client_secret)
    }

    /// The public OAuth client id.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Build the Google authorization URL.
    ///
    /// `redirect_uri` must be one of the two registered callback URIs.
    /// `state` and `nonce` are 16 to 128 lowercase hex characters.
    /// The URL sets `prompt=select_account` so Google shows the account chooser.
    pub fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
    ) -> Result<String, IdentityError> {
        require_redirect(redirect_uri)?;
        require_hex(state)?;
        require_hex(nonce)?;
        let mut url = String::from(GOOGLE_AUTHORIZE_ENDPOINT);
        append_pair(&mut url, "client_id", &self.client_id, true);
        append_pair(&mut url, "redirect_uri", redirect_uri, false);
        append_pair(&mut url, "response_type", "code", false);
        append_pair(&mut url, "scope", "openid", false);
        append_pair(&mut url, "state", state, false);
        append_pair(&mut url, "nonce", nonce, false);
        append_pair(&mut url, "prompt", "select_account", false);
        Ok(url)
    }

    /// Build the token-endpoint request.
    ///
    /// The body contains the client secret.
    /// The harness must not write the body to a log.
    pub fn token_request(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<GoogleTokenRequest, IdentityError> {
        require_code(code)?;
        require_redirect(redirect_uri)?;
        let mut body = String::new();
        append_pair(&mut body, "grant_type", "authorization_code", true);
        append_pair(&mut body, "code", code, false);
        append_pair(&mut body, "client_id", &self.client_id, false);
        append_pair(&mut body, "client_secret", &self.client_secret, false);
        append_pair(&mut body, "redirect_uri", redirect_uri, false);
        Ok(GoogleTokenRequest { body })
    }
}

/// A `POST` body for the Google token endpoint.
///
/// Debug output redacts the body because the body contains the client secret.
pub struct GoogleTokenRequest {
    body: String,
}

impl fmt::Debug for GoogleTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleTokenRequest")
            .field("endpoint", &GOOGLE_TOKEN_ENDPOINT)
            .field("content_type", &Self::CONTENT_TYPE)
            .field("body", &"redacted")
            .finish()
    }
}

impl GoogleTokenRequest {
    /// The `Content-Type` value for the token request.
    pub const CONTENT_TYPE: &'static str = "application/x-www-form-urlencoded";

    /// The token endpoint URL.
    pub fn endpoint(&self) -> &'static str {
        GOOGLE_TOKEN_ENDPOINT
    }

    /// The form body.
    ///
    /// This value contains the client secret.
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Read `id_token` from a token-endpoint JSON body.
    pub fn id_token_from_response(body: &str) -> Result<String, IdentityError> {
        if body.len() > MAX_TOKEN_BYTES {
            return Err(IdentityError::Token);
        }
        let parsed: TokenResponse = serde_json::from_str(body).map_err(|_| IdentityError::Token)?;
        if parsed.error.is_some() {
            return Err(IdentityError::Token);
        }
        let Some(token) = parsed.id_token else {
            return Err(IdentityError::Token);
        };
        if token.is_empty()
            || token.len() > MAX_TOKEN_BYTES
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
            || token.matches('.').count() != 2
        {
            return Err(IdentityError::Token);
        }
        Ok(token)
    }
}

/// Claims from a verified Google ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleIdClaims {
    /// The Google `sub` claim.
    pub subject: String,
    /// The issuer.
    ///
    /// The value is `https://accounts.google.com`.
    pub issuer: String,
    /// The token expiry as Unix seconds.
    pub expires_at: u64,
    /// The token issue time as Unix seconds.
    pub issued_at: u64,
}

/// Google signing keys from one JWKS document.
pub struct GoogleJwks {
    keys: Vec<GooglePublicKey>,
}

struct GooglePublicKey {
    kid: String,
    decoding: DecodingKey,
}

impl fmt::Debug for GoogleJwks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kids: Vec<&str> = self.keys.iter().map(|key| key.kid.as_str()).collect();
        formatter
            .debug_struct("GoogleJwks")
            .field("kids", &kids)
            .finish()
    }
}

impl GoogleJwks {
    /// Parse a Google JWKS document.
    ///
    /// The function keeps RSA `RS256` signature keys.
    /// The function rejects a document with no usable key.
    /// The function rejects a repeated `kid`.
    pub fn from_json(text: &str) -> Result<Self, IdentityError> {
        if text.is_empty() || text.len() > MAX_JWKS_BYTES {
            return Err(IdentityError::Token);
        }
        let document: JwksDocument =
            serde_json::from_str(text).map_err(|_| IdentityError::Token)?;
        if document.keys.is_empty() || document.keys.len() > MAX_KEYS {
            return Err(IdentityError::Token);
        }
        let mut keys = Vec::new();
        for jwk in document.keys {
            let Some(key) = accept_key(jwk)? else {
                continue;
            };
            if keys
                .iter()
                .any(|saved: &GooglePublicKey| saved.kid == key.kid)
            {
                return Err(IdentityError::Token);
            }
            keys.push(key);
        }
        if keys.is_empty() {
            return Err(IdentityError::Token);
        }
        Ok(Self { keys })
    }

    /// Verify one Google ID token.
    ///
    /// `client_id` is the OAuth audience.
    /// `nonce` must match the token `nonce` claim.
    /// The subject must be a valid SPIFFE user name.
    pub fn verify(
        &self,
        id_token: &str,
        client_id: &str,
        nonce: &str,
        now: SystemTime,
    ) -> Result<GoogleIdClaims, IdentityError> {
        require_client_id(client_id)?;
        require_hex(nonce)?;
        if id_token.len() > MAX_TOKEN_BYTES || id_token.matches('.').count() != 2 {
            return Err(IdentityError::Token);
        }
        let header = decode_header(id_token).map_err(map_jwt)?;
        if header.alg != Algorithm::RS256 {
            return Err(IdentityError::Token);
        }
        if header.jwk.is_some()
            || header.jku.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.crit.is_some()
        {
            return Err(IdentityError::Token);
        }
        let Some(kid) = header.kid.as_deref() else {
            return Err(IdentityError::Token);
        };
        let Some(key) = self.keys.iter().find(|key| key.kid == kid) else {
            return Err(IdentityError::Token);
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[GOOGLE_ISSUER]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let data =
            decode::<GoogleTokenClaims>(id_token, &key.decoding, &validation).map_err(map_jwt)?;
        let claims = data.claims;
        if claims.iss != GOOGLE_ISSUER || !claims.aud.contains(client_id) {
            return Err(IdentityError::Audience);
        }
        match claims.azp.as_deref() {
            Some(azp) if azp == client_id => {}
            None if claims.aud.count() == 1 => {}
            _ => return Err(IdentityError::Audience),
        }
        match claims.nonce.as_deref() {
            Some(value) if value == nonce => {}
            _ => return Err(IdentityError::Token),
        }
        let _subject = SpiffeId::user(&claims.sub)?;
        let now_unix = unix_time(now)?;
        if claims.iat > now_unix.saturating_add(MAX_SKEW_SECS) {
            return Err(IdentityError::NotYetValid);
        }
        let not_before = claims.nbf.unwrap_or(claims.iat);
        if claims.exp < not_before {
            return Err(IdentityError::Token);
        }
        in_window(now_unix, not_before, claims.exp)?;
        Ok(GoogleIdClaims {
            subject: claims.sub,
            issuer: claims.iss,
            expires_at: claims.exp,
            issued_at: claims.iat,
        })
    }
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenClaims {
    iss: String,
    sub: String,
    aud: GoogleAudience,
    exp: u64,
    iat: u64,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    azp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum GoogleAudience {
    One(String),
    Many(Vec<String>),
}

impl GoogleAudience {
    fn contains(&self, client_id: &str) -> bool {
        match self {
            Self::One(value) => value == client_id,
            Self::Many(values) => values.iter().any(|value| value == client_id),
        }
    }

    fn count(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
        }
    }
}

fn accept_key(jwk: Jwk) -> Result<Option<GooglePublicKey>, IdentityError> {
    if let Some(use_of_key) = &jwk.common.public_key_use {
        if *use_of_key != PublicKeyUse::Signature {
            return Ok(None);
        }
    }
    if let Some(algorithm) = jwk.common.key_algorithm {
        if algorithm != KeyAlgorithm::RS256 {
            return Ok(None);
        }
    }
    if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {
        return Ok(None);
    }
    let Some(kid) = jwk.common.key_id.clone() else {
        return Err(IdentityError::Token);
    };
    if !kid_ok(&kid) {
        return Err(IdentityError::Token);
    }
    let decoding = DecodingKey::from_jwk(&jwk).map_err(|_| IdentityError::Token)?;
    Ok(Some(GooglePublicKey { kid, decoding }))
}

fn kid_ok(kid: &str) -> bool {
    (1..=128).contains(&kid.len())
        && kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn require_client_id(value: &str) -> Result<(), IdentityError> {
    if value.len() <= CLIENT_ID_SUFFIX.len()
        || value.len() > 200
        || !value.ends_with(CLIENT_ID_SUFFIX)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IdentityError::Config);
    }
    Ok(())
}

fn require_secret(value: &str) -> Result<(), IdentityError> {
    if !(8..=256).contains(&value.len()) || !printable_ascii(value) {
        return Err(IdentityError::Config);
    }
    Ok(())
}

fn require_code(value: &str) -> Result<(), IdentityError> {
    if !(1..=1024).contains(&value.len()) || !printable_ascii(value) {
        return Err(IdentityError::Config);
    }
    Ok(())
}

fn printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn require_redirect(value: &str) -> Result<(), IdentityError> {
    if value == GOOGLE_REDIRECT_LOOPBACK || value == GOOGLE_REDIRECT_LOCALHOST {
        Ok(())
    } else {
        Err(IdentityError::Config)
    }
}

fn require_hex(value: &str) -> Result<(), IdentityError> {
    if (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(IdentityError::Config)
    }
}

fn read_env(name: &str) -> Result<String, IdentityError> {
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent | std::env::VarError::NotUnicode(_)) => {
            Err(IdentityError::Config)
        }
    }
}

fn append_pair(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push('&');
    } else if out.starts_with("https://") {
        out.push('?');
    }
    out.push_str(key);
    out.push('=');
    out.push_str(&percent_encode(value));
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

fn map_jwt(err: jsonwebtoken::errors::Error) -> IdentityError {
    match err.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidAudience => IdentityError::Audience,
        jsonwebtoken::errors::ErrorKind::InvalidIssuer => IdentityError::Token,
        jsonwebtoken::errors::ErrorKind::InvalidSignature => IdentityError::Signature,
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => IdentityError::Expired,
        jsonwebtoken::errors::ErrorKind::ImmatureSignature => IdentityError::NotYetValid,
        _ => IdentityError::Token,
    }
}
