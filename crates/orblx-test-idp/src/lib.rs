//! A small OIDC test issuer.
//!
//! CI and the [C] proofs use this crate.
//! The crate signs ID tokens with `RS256` or `ES256` test keys.
//! The keys are throwaway keys. Do not use this crate in production.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The signature algorithm of a test key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlg {
    /// RSA PKCS#1 v1.5 with SHA-256.
    RS256,
    /// ECDSA P-256 with SHA-256.
    ES256,
}

impl KeyAlg {
    /// Parse `RS256` or `ES256`.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "RS256" => Some(Self::RS256),
            "ES256" => Some(Self::ES256),
            _ => None,
        }
    }

    fn jwt(self) -> Algorithm {
        match self {
            Self::RS256 => Algorithm::RS256,
            Self::ES256 => Algorithm::ES256,
        }
    }
}

/// One signing key with its public JWK.
///
/// The private PEM stays in the issuer directory.
#[derive(Clone, Serialize, Deserialize)]
pub struct TestKey {
    /// The key id.
    pub kid: String,
    /// The algorithm.
    pub alg: KeyAlg,
    /// The PKCS#8 private key PEM.
    private_pem: String,
    /// The public JWK.
    pub jwk: Value,
}

impl std::fmt::Debug for TestKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("private_pem", &"redacted")
            .finish()
    }
}

impl TestKey {
    /// Generate a new key.
    pub fn generate(kid: &str, alg: KeyAlg) -> Result<Self, String> {
        match alg {
            KeyAlg::RS256 => {
                let mut rng = rand::thread_rng();
                let key = RsaPrivateKey::new(&mut rng, 2048).map_err(|err| err.to_string())?;
                let pem = key
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|err| err.to_string())?
                    .to_string();
                let jwk = json!({
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": kid,
                    "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                    "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
                });
                Ok(Self {
                    kid: kid.to_string(),
                    alg,
                    private_pem: pem,
                    jwk,
                })
            }
            KeyAlg::ES256 => {
                let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                    .map_err(|err| err.to_string())?;
                let raw = key.public_key_raw();
                if raw.len() != 65 || raw[0] != 4 {
                    return Err("The P-256 public key is not valid.".to_string());
                }
                let jwk = json!({
                    "kty": "EC",
                    "alg": "ES256",
                    "use": "sig",
                    "crv": "P-256",
                    "kid": kid,
                    "x": URL_SAFE_NO_PAD.encode(&raw[1..33]),
                    "y": URL_SAFE_NO_PAD.encode(&raw[33..65]),
                });
                Ok(Self {
                    kid: kid.to_string(),
                    alg,
                    private_pem: key.serialize_pem(),
                    jwk,
                })
            }
        }
    }

    fn encoding(&self) -> Result<EncodingKey, String> {
        match self.alg {
            KeyAlg::RS256 => EncodingKey::from_rsa_pem(self.private_pem.as_bytes()),
            KeyAlg::ES256 => EncodingKey::from_ec_pem(self.private_pem.as_bytes()),
        }
        .map_err(|err| err.to_string())
    }
}

/// The claims for one test ID token.
#[derive(Debug, Clone)]
pub struct MintSpec {
    /// The `iss` claim.
    pub issuer: String,
    /// The `aud` claim.
    pub audience: String,
    /// The `sub` claim.
    pub subject: String,
    /// The `email` claim.
    pub email: Option<String>,
    /// The `email_verified` claim.
    pub email_verified: bool,
    /// The `nonce` claim.
    pub nonce: Option<String>,
    /// The `iat` claim as Unix seconds.
    pub issued_at: u64,
    /// The `exp` claim as Unix seconds.
    pub expires_at: u64,
}

impl MintSpec {
    /// A token that is valid for `ttl` seconds from now.
    pub fn now(issuer: &str, audience: &str, subject: &str, ttl: u64) -> Self {
        let now = unix_now();
        Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            subject: subject.to_string(),
            email: None,
            email_verified: true,
            nonce: None,
            issued_at: now,
            expires_at: now + ttl,
        }
    }
}

/// Sign one ID token.
///
/// `header_kid` replaces the header `kid` when it is set.
pub fn mint(key: &TestKey, spec: &MintSpec, header_kid: Option<&str>) -> Result<String, String> {
    let mut header = Header::new(key.alg.jwt());
    header.kid = Some(header_kid.unwrap_or(&key.kid).to_string());
    let mut claims = json!({
        "iss": spec.issuer,
        "aud": spec.audience,
        "sub": spec.subject,
        "iat": spec.issued_at,
        "exp": spec.expires_at,
    });
    if let Some(email) = &spec.email {
        claims["email"] = json!(email);
        claims["email_verified"] = json!(spec.email_verified);
    }
    if let Some(nonce) = &spec.nonce {
        claims["nonce"] = json!(nonce);
    }
    encode(&header, &claims, &key.encoding()?).map_err(|err| err.to_string())
}

/// Change one byte of the signature part.
///
/// The token keeps a valid shape.
pub fn tamper_signature(token: &str) -> String {
    let Some(dot) = token.rfind('.') else {
        return token.to_string();
    };
    let mut bytes = token.as_bytes().to_vec();
    let index = dot + 1 + (bytes.len() - dot - 1) / 2;
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap_or_default()
}

/// The JWKS document for `keys`.
pub fn jwks_json(keys: &[TestKey]) -> String {
    let list: Vec<&Value> = keys.iter().map(|key| &key.jwk).collect();
    json!({ "keys": list }).to_string()
}

/// The discovery document for `issuer`.
pub fn discovery_json(issuer: &str) -> String {
    let base = issuer.trim_end_matches('/');
    json!({
        "issuer": issuer,
        "jwks_uri": format!("{base}/jwks"),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
    })
    .to_string()
}

/// The current Unix time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}
