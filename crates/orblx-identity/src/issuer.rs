//! Generic OIDC issuer: discovery, JWKS, and ID token checks.
//!
//! The operator sets an issuer URL and a client id.
//! The coordinator reads `{issuer}/.well-known/openid-configuration`.
//! The discovery document gives the `jwks_uri`.
//! The coordinator keeps the JWKS in a cache and fetches it again for an unknown `kid`.
//! This module accepts `RS256` and `ES256` signatures.
//! This module does not open a network connection.

use std::fmt;
use std::time::SystemTime;

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::clock::{in_window, unix_time, MAX_SKEW_SECS};
use crate::error::IdentityError;
use crate::spiffe::SpiffeId;

/// The discovery path under the issuer URL.
pub const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

const MAX_URL: usize = 256;
const MAX_DOC_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_KEYS: usize = 16;
const MAX_ALLOW: usize = 64;

/// The reason that an ID token check failed.
///
/// The text does not contain the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcReject {
    /// The token shape or a claim is not valid.
    Malformed,
    /// The signature algorithm is not `RS256` or `ES256`, or it does not match the key.
    Algorithm,
    /// The JWKS does not contain the token `kid`.
    UnknownKey,
    /// The signature check failed.
    Signature,
    /// The `iss` claim does not match the issuer.
    Issuer,
    /// The `aud` or `azp` claim does not match the client id.
    Audience,
    /// The token end time has passed.
    Expired,
    /// The token start time is in the future.
    NotYetValid,
    /// The `nonce` claim does not match.
    Nonce,
    /// The email is not on the allowed list.
    Email,
}

impl OidcReject {
    /// A short stable token for logs and proofs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Algorithm => "algorithm",
            Self::UnknownKey => "unknown-kid",
            Self::Signature => "bad-signature",
            Self::Issuer => "wrong-issuer",
            Self::Audience => "wrong-audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not-yet-valid",
            Self::Nonce => "nonce",
            Self::Email => "email-not-allowed",
        }
    }
}

impl fmt::Display for OidcReject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<OidcReject> for IdentityError {
    fn from(value: OidcReject) -> Self {
        match value {
            OidcReject::Audience => IdentityError::Audience,
            OidcReject::Signature => IdentityError::Signature,
            OidcReject::Expired => IdentityError::Expired,
            OidcReject::NotYetValid => IdentityError::NotYetValid,
            _ => IdentityError::Token,
        }
    }
}

/// One generic OIDC issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIssuer {
    issuer: String,
    client_id: String,
    allowed_domains: Vec<String>,
    allowed_emails: Vec<String>,
}

impl OidcIssuer {
    /// Check and keep one issuer configuration.
    ///
    /// The issuer must be an `https://` URL with no query and no fragment.
    /// When both lists are empty, every subject from the issuer is allowed.
    /// When a list is not empty, the token must have a verified `email` claim on a list.
    pub fn new(
        issuer: &str,
        client_id: &str,
        allowed_domains: &[String],
        allowed_emails: &[String],
    ) -> Result<Self, IdentityError> {
        require_https_url(issuer)?;
        if client_id.is_empty()
            || client_id.len() > 200
            || !client_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(IdentityError::Config);
        }
        if allowed_domains.len() > MAX_ALLOW || allowed_emails.len() > MAX_ALLOW {
            return Err(IdentityError::Config);
        }
        let mut domains = Vec::new();
        for domain in allowed_domains {
            let domain = domain.trim().to_ascii_lowercase();
            if !domain_ok(&domain) {
                return Err(IdentityError::Config);
            }
            domains.push(domain);
        }
        let mut emails = Vec::new();
        for email in allowed_emails {
            let email = email.trim().to_ascii_lowercase();
            match email.split_once('@') {
                Some((local, domain))
                    if !local.is_empty()
                        && local.len() <= 64
                        && local
                            .bytes()
                            .all(|b| (0x21..=0x7e).contains(&b) && b != b'@')
                        && domain_ok(domain) => {}
                _ => return Err(IdentityError::Config),
            }
            emails.push(email);
        }
        Ok(Self {
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            allowed_domains: domains,
            allowed_emails: emails,
        })
    }

    /// The issuer URL.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The OAuth client id. The coordinator uses it as the audience.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The allowed email domains.
    pub fn allowed_domains(&self) -> &[String] {
        &self.allowed_domains
    }

    /// The allowed email addresses.
    pub fn allowed_emails(&self) -> &[String] {
        &self.allowed_emails
    }

    /// The discovery document URL.
    pub fn discovery_url(&self) -> String {
        format!("{}{}", self.issuer.trim_end_matches('/'), DISCOVERY_PATH)
    }

    /// Read `jwks_uri` from a discovery document.
    ///
    /// The document `issuer` must equal the configured issuer.
    /// The `jwks_uri` must be an `https://` URL.
    pub fn jwks_uri_from_discovery(&self, text: &str) -> Result<String, IdentityError> {
        if text.is_empty() || text.len() > MAX_DOC_BYTES {
            return Err(IdentityError::Config);
        }
        let document: Discovery = serde_json::from_str(text).map_err(|_| IdentityError::Config)?;
        if document.issuer != self.issuer {
            return Err(IdentityError::Config);
        }
        if let Some(algs) = &document.id_token_signing_alg_values_supported {
            if !algs.iter().any(|alg| alg == "RS256" || alg == "ES256") {
                return Err(IdentityError::Config);
            }
        }
        require_https_url(&document.jwks_uri)?;
        Ok(document.jwks_uri)
    }

    fn email_allowed(&self, email: &str) -> bool {
        if self.allowed_emails.iter().any(|allowed| allowed == email) {
            return true;
        }
        match email.rsplit_once('@') {
            Some((_, domain)) => self.allowed_domains.iter().any(|allowed| allowed == domain),
            None => false,
        }
    }

    fn has_allow_list(&self) -> bool {
        !self.allowed_domains.is_empty() || !self.allowed_emails.is_empty()
    }
}

/// Claims from a verified ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdClaims {
    /// The `sub` claim.
    pub subject: String,
    /// The lowercase `email` claim, when the token has one.
    pub email: Option<String>,
    /// The token expiry as Unix seconds.
    pub expires_at: u64,
}

/// Signing keys from one JWKS document.
pub struct OidcJwks {
    keys: Vec<IssuerKey>,
}

struct IssuerKey {
    kid: String,
    algorithm: Algorithm,
    decoding: DecodingKey,
}

impl fmt::Debug for OidcJwks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcJwks")
            .field("kids", &self.kids())
            .finish()
    }
}

impl OidcJwks {
    /// Parse a JWKS document.
    ///
    /// The function keeps RSA keys for `RS256` and P-256 keys for `ES256`.
    /// The function skips a key for encryption or for a different algorithm.
    /// The function rejects a document with no usable key and a repeated `kid`.
    pub fn from_json(text: &str) -> Result<Self, IdentityError> {
        if text.is_empty() || text.len() > MAX_DOC_BYTES {
            return Err(IdentityError::Token);
        }
        let document: JwksDocument =
            serde_json::from_str(text).map_err(|_| IdentityError::Token)?;
        if document.keys.is_empty() || document.keys.len() > MAX_KEYS {
            return Err(IdentityError::Token);
        }
        let mut keys: Vec<IssuerKey> = Vec::new();
        for jwk in document.keys {
            let Some(key) = accept_key(&jwk)? else {
                continue;
            };
            if keys.iter().any(|saved| saved.kid == key.kid) {
                return Err(IdentityError::Token);
            }
            keys.push(key);
        }
        if keys.is_empty() {
            return Err(IdentityError::Token);
        }
        Ok(Self { keys })
    }

    /// The key ids in this document.
    pub fn kids(&self) -> Vec<&str> {
        self.keys.iter().map(|key| key.kid.as_str()).collect()
    }

    /// Return true when this document has `kid`.
    pub fn has_kid(&self, kid: &str) -> bool {
        self.keys.iter().any(|key| key.kid == kid)
    }

    /// Verify one ID token for `issuer`.
    ///
    /// `nonce` must match the token `nonce` claim.
    /// When the caller sends no nonce, the token must not have a `nonce` claim.
    /// The subject must be a valid SPIFFE user name.
    pub fn verify(
        &self,
        id_token: &str,
        issuer: &OidcIssuer,
        nonce: Option<&str>,
        now: SystemTime,
    ) -> Result<OidcIdClaims, OidcReject> {
        if id_token.is_empty()
            || id_token.len() > MAX_TOKEN_BYTES
            || id_token.matches('.').count() != 2
        {
            return Err(OidcReject::Malformed);
        }
        let header = decode_header(id_token).map_err(|_| OidcReject::Malformed)?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
            return Err(OidcReject::Algorithm);
        }
        if header.jwk.is_some()
            || header.jku.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.crit.is_some()
        {
            return Err(OidcReject::Malformed);
        }
        let Some(kid) = header.kid.as_deref() else {
            return Err(OidcReject::Malformed);
        };
        let Some(key) = self.keys.iter().find(|key| key.kid == kid) else {
            return Err(OidcReject::UnknownKey);
        };
        if key.algorithm != header.alg {
            return Err(OidcReject::Algorithm);
        }
        let mut validation = Validation::new(key.algorithm);
        validation.set_audience(&[issuer.client_id()]);
        validation.set_issuer(&[issuer.issuer()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let data = decode::<TokenClaims>(id_token, &key.decoding, &validation).map_err(map_jwt)?;
        let claims = data.claims;
        if claims.iss != issuer.issuer() {
            return Err(OidcReject::Issuer);
        }
        if !claims.aud.contains(issuer.client_id()) {
            return Err(OidcReject::Audience);
        }
        match claims.azp.as_deref() {
            Some(azp) if azp == issuer.client_id() => {}
            None if claims.aud.count() == 1 => {}
            _ => return Err(OidcReject::Audience),
        }
        match (nonce, claims.nonce.as_deref()) {
            (Some(sent), Some(claim)) if sent == claim => {}
            (None, None) => {}
            _ => return Err(OidcReject::Nonce),
        }
        SpiffeId::user(&claims.sub).map_err(|_| OidcReject::Malformed)?;
        let now_unix = unix_time(now).map_err(|_| OidcReject::Malformed)?;
        if claims.iat > now_unix.saturating_add(MAX_SKEW_SECS) {
            return Err(OidcReject::NotYetValid);
        }
        let not_before = claims.nbf.unwrap_or(claims.iat);
        if claims.exp < not_before {
            return Err(OidcReject::Malformed);
        }
        in_window(now_unix, not_before, claims.exp).map_err(|err| match err {
            IdentityError::NotYetValid => OidcReject::NotYetValid,
            IdentityError::Expired => OidcReject::Expired,
            _ => OidcReject::Malformed,
        })?;
        let email = claims.email.map(|value| value.to_ascii_lowercase());
        if issuer.has_allow_list() {
            let Some(address) = email.as_deref() else {
                return Err(OidcReject::Email);
            };
            if claims.email_verified != Some(true) || !issuer.email_allowed(address) {
                return Err(OidcReject::Email);
            }
        }
        Ok(OidcIdClaims {
            subject: claims.sub,
            email,
            expires_at: claims.exp,
        })
    }
}

/// Read the `kid` from a token header without a signature check.
///
/// The coordinator uses the value only to decide if it must fetch the JWKS again.
pub fn token_kid(id_token: &str) -> Option<String> {
    if id_token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let header = decode_header(id_token).ok()?;
    header.kid.filter(|kid| kid_ok(kid))
}

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct TokenClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
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

fn accept_key(jwk: &Jwk) -> Result<Option<IssuerKey>, IdentityError> {
    if let Some(use_of_key) = &jwk.common.public_key_use {
        if *use_of_key != PublicKeyUse::Signature {
            return Ok(None);
        }
    }
    let algorithm = match (&jwk.algorithm, jwk.common.key_algorithm) {
        (AlgorithmParameters::RSA(_), None | Some(KeyAlgorithm::RS256)) => Algorithm::RS256,
        (AlgorithmParameters::EllipticCurve(params), None | Some(KeyAlgorithm::ES256))
            if params.curve == EllipticCurve::P256 =>
        {
            Algorithm::ES256
        }
        _ => return Ok(None),
    };
    let Some(kid) = jwk.common.key_id.clone() else {
        return Err(IdentityError::Token);
    };
    if !kid_ok(&kid) {
        return Err(IdentityError::Token);
    }
    let decoding = DecodingKey::from_jwk(jwk).map_err(|_| IdentityError::Token)?;
    Ok(Some(IssuerKey {
        kid,
        algorithm,
        decoding,
    }))
}

fn kid_ok(kid: &str) -> bool {
    (1..=128).contains(&kid.len())
        && kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn domain_ok(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// Check an `https://host[:port][/path]` URL with no query, fragment, or user info.
pub(crate) fn require_https_url(url: &str) -> Result<(), IdentityError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(IdentityError::Config);
    };
    if url.len() > MAX_URL
        || rest.is_empty()
        || !url.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        || url.contains(['?', '#', '@', '\\'])
    {
        return Err(IdentityError::Config);
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err(IdentityError::Config);
    }
    Ok(())
}

fn map_jwt(err: jsonwebtoken::errors::Error) -> OidcReject {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::InvalidAudience => OidcReject::Audience,
        ErrorKind::InvalidIssuer => OidcReject::Issuer,
        ErrorKind::InvalidSignature => OidcReject::Signature,
        ErrorKind::ExpiredSignature => OidcReject::Expired,
        ErrorKind::ImmatureSignature => OidcReject::NotYetValid,
        ErrorKind::InvalidAlgorithm => OidcReject::Algorithm,
        _ => OidcReject::Malformed,
    }
}
