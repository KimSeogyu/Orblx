//! The local mock IdP for the harness UI.
//!
//! The browser opens a sign-in page.
//! Sign in returns a one-time code.
//! The callback turns that code into a human SVID.

use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, SystemTime};

use gyeol_identity::{MockOidc, MOCK_OIDC_ISSUER, OIDC_AUDIENCE};

use crate::envelope::hex_encode;
use crate::sim::HUMAN_NAME;

/// The OIDC client id for the harness page.
pub(crate) const CLIENT_ID: &str = "gyeol-sim";

/// The callback path on this harness.
pub(crate) const CALLBACK_PATH: &str = "/oidc/callback";

const RESPONSE_TYPE: &str = "code";
const SCOPE: &str = "openid";
const CODE_TTL: Duration = Duration::from_secs(120);
const MAX_PENDING: usize = 32;

const LOGIN_HTML: &str = include_str!("../static/oidc-login.html");

/// The authorize request from the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizeRequest {
    /// OIDC client id.
    pub client_id: String,
    /// OIDC response type.
    pub response_type: String,
    /// Callback URL.
    pub redirect_uri: String,
    /// Browser state value.
    pub state: String,
    /// OIDC scope.
    pub scope: String,
}

struct PendingLogin {
    subject: String,
    state: String,
    expires: SystemTime,
}

/// The in-process mock IdP.
pub(crate) struct Idp {
    oidc: MockOidc,
    pending: HashMap<String, PendingLogin>,
    order: Vec<String>,
}

impl AuthorizeRequest {
    /// Check the authorize fields.
    ///
    /// `host` is the request Host header.
    /// A relative callback does not need a host.
    pub(crate) fn check(&self, host: Option<&str>) -> Result<(), String> {
        if self.client_id != CLIENT_ID {
            return Err("The mock IdP client is not valid.".to_string());
        }
        if self.response_type != RESPONSE_TYPE {
            return Err("The mock IdP response type is not valid.".to_string());
        }
        if self.scope != SCOPE {
            return Err("The mock IdP scope is not valid.".to_string());
        }
        if !state_ok(&self.state) {
            return Err("The mock IdP state is not valid.".to_string());
        }
        if !redirect_ok(&self.redirect_uri, host) {
            return Err("The mock IdP redirect is not valid.".to_string());
        }
        Ok(())
    }
}

impl Idp {
    /// Open the mock IdP and generate its signing key.
    pub(crate) fn open() -> Result<Self, String> {
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).map_err(|err| err.to_string())?;
        Ok(Self {
            oidc,
            pending: HashMap::new(),
            order: Vec::new(),
        })
    }

    /// The signer that minted the browser ID token.
    pub(crate) fn oidc(&self) -> &MockOidc {
        &self.oidc
    }

    /// Accept a sign-in and return the callback location.
    pub(crate) fn begin(
        &mut self,
        request: &AuthorizeRequest,
        subject: &str,
        now: SystemTime,
        host: Option<&str>,
    ) -> Result<String, String> {
        request.check(host)?;
        if subject != HUMAN_NAME {
            return Err("The mock IdP subject is not valid.".to_string());
        }
        self.drop_expired(now);
        while self.order.len() >= MAX_PENDING {
            let old = self.order.remove(0);
            self.pending.remove(&old);
        }
        let code = fresh_code()?;
        let expires = now
            .checked_add(CODE_TTL)
            .ok_or_else(|| "The mock IdP code time overflowed.".to_string())?;
        self.order.push(code.clone());
        self.pending.insert(
            code.clone(),
            PendingLogin {
                subject: subject.to_string(),
                state: request.state.clone(),
                expires,
            },
        );
        Ok(format!(
            "{CALLBACK_PATH}?code={code}&state={}",
            request.state
        ))
    }

    /// Consume a one-time code and return the subject.
    pub(crate) fn consume(
        &mut self,
        code: &str,
        state: &str,
        now: SystemTime,
    ) -> Result<String, String> {
        if code.len() > 128 || state.len() > 128 {
            return Err("The mock IdP code is not valid.".to_string());
        }
        let Some(pending) = self.pending.remove(code) else {
            return Err("The mock IdP code is not valid.".to_string());
        };
        self.order.retain(|item| item != code);
        if now >= pending.expires {
            return Err("The mock IdP code expired.".to_string());
        }
        if pending.state != state {
            return Err("The mock IdP state check failed.".to_string());
        }
        Ok(pending.subject)
    }

    fn drop_expired(&mut self, now: SystemTime) {
        self.pending.retain(|_, pending| now < pending.expires);
        self.order.retain(|code| self.pending.contains_key(code));
    }
}

pub(crate) fn random_hex(nbytes: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; nbytes];
    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|_| "The sign-in path did not open the random source.".to_string())?;
    file.read_exact(&mut bytes)
        .map_err(|_| "The sign-in path did not read the random source.".to_string())?;
    Ok(hex_encode(&bytes))
}

fn fresh_code() -> Result<String, String> {
    random_hex(32)
}

/// Render the sign-in page for one authorize request.
pub(crate) fn login_page(request: &AuthorizeRequest) -> String {
    LOGIN_HTML
        .replace("__ISSUER__", &escape(MOCK_OIDC_ISSUER))
        .replace("__AUDIENCE__", &escape(OIDC_AUDIENCE))
        .replace("__SUBJECT__", &escape(HUMAN_NAME))
        .replace("__CLIENT_ID__", &escape(&request.client_id))
        .replace("__RESPONSE_TYPE__", &escape(&request.response_type))
        .replace("__REDIRECT_URI__", &escape(&request.redirect_uri))
        .replace("__STATE__", &escape(&request.state))
        .replace("__SCOPE__", &escape(&request.scope))
}

fn state_ok(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'))
}

fn redirect_ok(redirect_uri: &str, host: Option<&str>) -> bool {
    if redirect_uri.is_empty() || redirect_uri.len() > 200 {
        return false;
    }
    if !redirect_uri
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | ':' | '.' | '-'))
    {
        return false;
    }
    if redirect_uri == CALLBACK_PATH {
        return true;
    }
    let Some(rest) = redirect_uri
        .strip_prefix("http://")
        .or_else(|| redirect_uri.strip_prefix("https://"))
    else {
        return false;
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if path != "oidc/callback" {
        return false;
    }
    match host {
        Some(host) => authority.eq_ignore_ascii_case(host),
        None => false,
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{login_page, AuthorizeRequest, Idp, CALLBACK_PATH};
    use crate::sim::HUMAN_NAME;
    use gyeol_identity::{MOCK_OIDC_ISSUER, OIDC_AUDIENCE};

    fn sample() -> AuthorizeRequest {
        AuthorizeRequest {
            client_id: "gyeol-sim".to_string(),
            response_type: "code".to_string(),
            redirect_uri: CALLBACK_PATH.to_string(),
            state: "0011223344556677".to_string(),
            scope: "openid".to_string(),
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn code_from(location: &str) -> String {
        let query = location.split_once('?').unwrap().1;
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("code=") {
                return value.to_string();
            }
        }
        panic!("The location has no code.");
    }

    #[test]
    fn the_login_page_names_the_mock_issuer() {
        let page = login_page(&sample());
        assert!(page.contains("Sign in"));
        assert!(page.contains(MOCK_OIDC_ISSUER));
        assert!(page.contains(OIDC_AUDIENCE));
        assert!(page.contains("Subject: ada"));
        assert!(page.contains("value=\"ada\""));
        assert!(page.contains("value=\"/oidc/callback\""));
        assert!(!page.contains("@keyframes"));
        assert!(!page.contains("__ISSUER__"));
        assert_eq!(HUMAN_NAME, "ada");
    }

    #[test]
    fn a_code_works_once() {
        let mut idp = Idp::open().unwrap();
        let request = sample();
        let location = idp.begin(&request, "ada", now(), None).unwrap();
        assert!(location.starts_with("/oidc/callback?code="));
        let code = code_from(&location);
        assert_eq!(idp.consume(&code, &request.state, now()).unwrap(), "ada");
        let err = idp.consume(&code, &request.state, now()).unwrap_err();
        assert!(err.contains("code"));
    }

    #[test]
    fn a_bad_redirect_fails() {
        let mut idp = Idp::open().unwrap();
        let mut request = sample();
        request.redirect_uri = "https://evil.example/oidc/callback".to_string();
        let err = idp
            .begin(&request, "ada", now(), Some("127.0.0.1:8787"))
            .unwrap_err();
        assert!(err.contains("redirect"));
    }

    #[test]
    fn a_local_absolute_callback_is_accepted() {
        let mut idp = Idp::open().unwrap();
        let mut request = sample();
        request.redirect_uri = "http://127.0.0.1:8787/oidc/callback".to_string();
        let location = idp
            .begin(&request, "ada", now(), Some("127.0.0.1:8787"))
            .unwrap();
        assert!(location.starts_with("/oidc/callback?code="));
        assert!(location.contains("&state=0011223344556677"));
    }

    #[test]
    fn an_expired_code_fails() {
        let mut idp = Idp::open().unwrap();
        let request = sample();
        let location = idp.begin(&request, "ada", now(), None).unwrap();
        let code = code_from(&location);
        let later = now() + Duration::from_secs(121);
        let err = idp.consume(&code, &request.state, later).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn a_state_mismatch_fails() {
        let mut idp = Idp::open().unwrap();
        let request = sample();
        let location = idp.begin(&request, "ada", now(), None).unwrap();
        let code = code_from(&location);
        let err = idp.consume(&code, "ff00112233445566", now()).unwrap_err();
        assert!(err.contains("state"));
    }

    #[test]
    fn a_wrong_subject_fails() {
        let mut idp = Idp::open().unwrap();
        let err = idp.begin(&sample(), "bob", now(), None).unwrap_err();
        assert!(err.contains("subject"));
    }
}
