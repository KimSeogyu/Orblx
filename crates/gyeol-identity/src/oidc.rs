use std::time::{Duration, SystemTime};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rcgen::{KeyPair, PKCS_ED25519};
use serde::{Deserialize, Serialize};

use crate::ca::MiniCa;
use crate::cert::TrustBundle;
use crate::clock::{in_window, unix_time, whole_seconds, MAX_AGENT_TTL, MAX_USER_TTL};
use crate::deny::DenySet;
use crate::error::IdentityError;
use crate::google::{GoogleIdClaims, GoogleJwks, OidcMode};
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

/// The gate that turns an ID token into a human SVID.
///
/// [`IssueGate::new`] trusts the mock IdP.
/// [`IssueGate::from_google`] trusts a Google ID token.
pub struct IssueGate {
    ca: MiniCa,
    idp: IdpKey,
}

enum IdpKey {
    Mock {
        issuer: String,
        decoding: DecodingKey,
    },
    Google {
        client_id: String,
        jwks: GoogleJwks,
    },
}

impl IssueGate {
    /// Trust the mock IdP.
    ///
    /// CI and the harness use this constructor when [`OidcMode`] is mock.
    /// City Breeze does not use this constructor by default.
    pub fn new(ca: MiniCa, oidc: &MockOidc) -> Result<Self, IdentityError> {
        let decoding = DecodingKey::from_ed_pem(oidc.public_key_pem().as_bytes())
            .map_err(|_| IdentityError::Token)?;
        Ok(Self {
            ca,
            idp: IdpKey::Mock {
                issuer: oidc.issuer().to_string(),
                decoding,
            },
        })
    }

    /// Trust Google JWKS for one OAuth client id.
    ///
    /// The human SVID subject is the Google `sub` claim.
    pub fn from_google(
        ca: MiniCa,
        client_id: &str,
        jwks: GoogleJwks,
    ) -> Result<Self, IdentityError> {
        crate::google::require_client_id(client_id)?;
        Ok(Self {
            ca,
            idp: IdpKey::Google {
                client_id: client_id.to_string(),
                jwks,
            },
        })
    }

    /// The IdP this gate trusts.
    pub fn mode(&self) -> OidcMode {
        match &self.idp {
            IdpKey::Mock { .. } => OidcMode::Mock,
            IdpKey::Google { .. } => OidcMode::Google,
        }
    }

    /// The Google client id, when this gate trusts Google.
    pub fn client_id(&self) -> Option<&str> {
        match &self.idp {
            IdpKey::Mock { .. } => None,
            IdpKey::Google { client_id, .. } => Some(client_id),
        }
    }

    pub fn trust_bundle(&self) -> &TrustBundle {
        self.ca.trust_bundle()
    }

    pub fn trust_bundle_pem(&self) -> &str {
        self.ca.trust_bundle_pem()
    }

    /// Return the raw Ed25519 public key of the SVID CA.
    pub fn ca_public_key(&self) -> &[u8; 32] {
        self.ca.public_key()
    }

    /// Verify a mock ID token and issue `spiffe://gyeol.local/user/{sub}`.
    ///
    /// This method accepts only the mock IdP.
    /// A Google gate returns [`IdentityError::Token`].
    pub fn issue_human_svid(
        &self,
        id_token: &str,
        now: SystemTime,
        deny: &DenySet,
    ) -> Result<crate::ca::IssuedSvid, IdentityError> {
        let claims = self.verify_token(id_token, now)?;
        self.mint_human(&claims.sub, claims.exp, now, deny)
    }

    /// Verify a Google ID token and issue a short human SVID.
    ///
    /// The subject is the Google `sub` claim.
    /// The SVID life is the remaining token life, at most 15 minutes.
    /// `nonce` must match the ID token.
    /// This method accepts only a Google gate.
    pub fn issue_google_human_svid(
        &self,
        id_token: &str,
        nonce: &str,
        now: SystemTime,
        deny: &DenySet,
    ) -> Result<crate::ca::IssuedSvid, IdentityError> {
        let IdpKey::Google { client_id, jwks } = &self.idp else {
            return Err(IdentityError::Token);
        };
        let claims: GoogleIdClaims = jwks.verify(id_token, client_id, nonce, now)?;
        self.mint_human(&claims.subject, claims.expires_at, now, deny)
    }

    /// Verify a parent mock ID token and issue `spiffe://gyeol.local/agent/{name}`.
    ///
    /// The parent token must pass the same checks as a mock human SVID.
    /// A Google gate returns [`IdentityError::Token`].
    /// `ttl` must be at most 5 minutes.
    /// `ttl` must not exceed the remaining life of the parent token.
    /// The function returns the SVID in memory.
    /// The function does not write a PEM file.
    pub fn issue_agent_svid(
        &self,
        parent_id_token: &str,
        agent_name: &str,
        now: SystemTime,
        ttl: Duration,
        deny: &DenySet,
    ) -> Result<AgentSvid, IdentityError> {
        let claims = self.verify_token(parent_id_token, now)?;
        let parent = SpiffeId::user(&claims.sub)?;
        deny.reject_uri(&parent)?;
        let now_unix = unix_time(now)?;
        if claims.exp <= now_unix {
            return Err(IdentityError::Expired);
        }
        let remaining = claims.exp - now_unix;
        let ttl_secs = whole_seconds(ttl)?;
        if ttl > MAX_AGENT_TTL || ttl_secs > remaining {
            return Err(IdentityError::Time);
        }
        let agent = SpiffeId::agent(agent_name)?;
        let svid = self.ca.issue(&agent, now, ttl, deny)?;
        Ok(AgentSvid { parent, svid })
    }

    /// Return the human owner subject for one node enrollment.
    ///
    /// A mock gate checks a mock ID token.
    /// A Google gate checks a Google ID token.
    /// `nonce` is required for a Google gate.
    /// The function does not issue an SVID.
    pub fn owner_subject(
        &self,
        id_token: &str,
        nonce: Option<&str>,
        now: SystemTime,
    ) -> Result<String, IdentityError> {
        match &self.idp {
            IdpKey::Mock { .. } => Ok(self.verify_token(id_token, now)?.sub),
            IdpKey::Google { client_id, jwks } => {
                let nonce = nonce.ok_or(IdentityError::Token)?;
                Ok(jwks.verify(id_token, client_id, nonce, now)?.subject)
            }
        }
    }

    fn mint_human(
        &self,
        subject: &str,
        exp: u64,
        now: SystemTime,
        deny: &DenySet,
    ) -> Result<crate::ca::IssuedSvid, IdentityError> {
        let id = SpiffeId::user(subject)?;
        let now_unix = unix_time(now)?;
        if exp <= now_unix {
            return Err(IdentityError::Expired);
        }
        let remaining = exp - now_unix;
        let ttl_secs = remaining.min(MAX_USER_TTL.as_secs());
        self.ca.issue(&id, now, Duration::from_secs(ttl_secs), deny)
    }

    fn verify_token(&self, id_token: &str, now: SystemTime) -> Result<OidcClaims, IdentityError> {
        let IdpKey::Mock { issuer, decoding } = &self.idp else {
            return Err(IdentityError::Token);
        };
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[OIDC_AUDIENCE]);
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let data = decode::<OidcClaims>(id_token, decoding, &validation).map_err(map_jwt)?;
        let now_unix = unix_time(now)?;
        if data.claims.exp < data.claims.nbf {
            return Err(IdentityError::Token);
        }
        in_window(now_unix, data.claims.nbf, data.claims.exp)?;
        Ok(data.claims)
    }
}

/// An agent SVID and the parent human SPIFFE ID that attested it.
#[derive(Debug)]
pub struct AgentSvid {
    /// The human SPIFFE ID from the parent ID token.
    pub parent: SpiffeId,
    /// The agent leaf.
    ///
    /// The life is at most 5 minutes.
    pub svid: crate::ca::IssuedSvid,
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
