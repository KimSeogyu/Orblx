use std::time::{Duration, SystemTime};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rcgen::{KeyPair, PKCS_ED25519};
use serde::{Deserialize, Serialize};

use crate::ca::MiniCa;
use crate::cert::TrustBundle;
use crate::clock::{in_window, unix_time, whole_seconds, MAX_USER_TTL};
use crate::deny::DenySet;
use crate::error::IdentityError;
use crate::spiffe::SpiffeId;

/// The required OIDC audience for a human SVID.
pub const OIDC_AUDIENCE: &str = "gyeol-issue";

/// The issuer string for the built-in mock IdP.
pub const MOCK_OIDC_ISSUER: &str = "https://oidc.gyeol.local";

/// A mock OIDC issuer that signs Ed25519 ID tokens.
pub struct MockOidc {
    issuer: String,
    encoding: EncodingKey,
    public_pem: String,
}

impl MockOidc {
    /// Generate a new Ed25519 signing key for the mock issuer.
    pub fn generate(issuer: impl Into<String>) -> Result<Self, IdentityError> {
        let issuer = issuer.into();
        if issuer.is_empty() || issuer.len() > 200 {
            return Err(IdentityError::Token);
        }
        let key = KeyPair::generate_for(&PKCS_ED25519).map_err(|_| IdentityError::Token)?;
        let private_pem = key.serialize_pem();
        let public_pem = key.public_key_pem();
        let encoding =
            EncodingKey::from_ed_pem(private_pem.as_bytes()).map_err(|_| IdentityError::Token)?;
        // Build the decoding key once so a bad PEM fails at setup.
        let _decoding =
            DecodingKey::from_ed_pem(public_pem.as_bytes()).map_err(|_| IdentityError::Token)?;
        Ok(Self {
            issuer,
            encoding,
            public_pem,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn public_key_pem(&self) -> &str {
        &self.public_pem
    }

    /// Issue an ID token for `gyeol-issue`.
    pub fn issue_id_token(
        &self,
        subject: &str,
        now: SystemTime,
        ttl: Duration,
    ) -> Result<String, IdentityError> {
        self.issue_id_token_for_audience(subject, OIDC_AUDIENCE, now, ttl)
    }

    /// Issue an ID token for a caller-selected audience.
    ///
    /// The issue gate still accepts only `gyeol-issue`.
    pub fn issue_id_token_for_audience(
        &self,
        subject: &str,
        audience: &str,
        now: SystemTime,
        ttl: Duration,
    ) -> Result<String, IdentityError> {
        let _id = SpiffeId::user(subject)?;
        if audience.is_empty() {
            return Err(IdentityError::Audience);
        }
        let ttl_secs = whole_seconds(ttl)?;
        let now_unix = unix_time(now)?;
        let expires = now_unix.checked_add(ttl_secs).ok_or(IdentityError::Time)?;
        let claims = OidcClaims {
            iss: self.issuer.clone(),
            sub: subject.to_string(),
            aud: audience.to_string(),
            exp: expires,
            iat: now_unix,
            nbf: now_unix,
        };
        encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
            .map_err(|_| IdentityError::Token)
    }
}

/// The gate that turns a mock OIDC token into a human SVID.
pub struct IssueGate {
    ca: MiniCa,
    issuer: String,
    decoding: DecodingKey,
}

impl IssueGate {
    pub fn new(ca: MiniCa, oidc: &MockOidc) -> Result<Self, IdentityError> {
        let decoding = DecodingKey::from_ed_pem(oidc.public_key_pem().as_bytes())
            .map_err(|_| IdentityError::Token)?;
        Ok(Self {
            ca,
            issuer: oidc.issuer().to_string(),
            decoding,
        })
    }

    pub fn trust_bundle(&self) -> &TrustBundle {
        self.ca.trust_bundle()
    }

    pub fn trust_bundle_pem(&self) -> &str {
        self.ca.trust_bundle_pem()
    }

    /// Verify the ID token and issue `spiffe://gyeol.local/user/{sub}`.
    pub fn issue_human_svid(
        &self,
        id_token: &str,
        now: SystemTime,
        deny: &DenySet,
    ) -> Result<crate::ca::IssuedSvid, IdentityError> {
        let claims = self.verify_token(id_token, now)?;
        let id = SpiffeId::user(&claims.sub)?;
        let now_unix = unix_time(now)?;
        if claims.exp <= now_unix {
            return Err(IdentityError::Expired);
        }
        let remaining = claims.exp - now_unix;
        let ttl_secs = remaining.min(MAX_USER_TTL.as_secs());
        self.ca.issue(&id, now, Duration::from_secs(ttl_secs), deny)
    }

    fn verify_token(&self, id_token: &str, now: SystemTime) -> Result<OidcClaims, IdentityError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[OIDC_AUDIENCE]);
        validation.set_issuer(&[&self.issuer]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let data = decode::<OidcClaims>(id_token, &self.decoding, &validation).map_err(map_jwt)?;
        let now_unix = unix_time(now)?;
        if data.claims.exp < data.claims.nbf {
            return Err(IdentityError::Token);
        }
        in_window(now_unix, data.claims.nbf, data.claims.exp)?;
        Ok(data.claims)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nbf: u64,
}

fn map_jwt(err: jsonwebtoken::errors::Error) -> IdentityError {
    match err.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidAudience => IdentityError::Audience,
        jsonwebtoken::errors::ErrorKind::InvalidSignature => IdentityError::Signature,
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => IdentityError::Expired,
        jsonwebtoken::errors::ErrorKind::ImmatureSignature => IdentityError::NotYetValid,
        _ => IdentityError::Token,
    }
}
