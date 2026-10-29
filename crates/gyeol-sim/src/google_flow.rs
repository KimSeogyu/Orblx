//! Google authorization-code sign-in for the harness.
//!
//! The default mode reads `OidcMode::from_env`.
//! The browser goes to `GoogleClient::authorize_url`.
//! The callback posts `token_request` and calls `IssueGate`.
//! `ORBLX_OIDC_MODE=mock` keeps the local IdP off the default path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use gyeol_identity::{
    GoogleClient, GoogleTokenRequest, OidcMode, GOOGLE_JWKS_URL, GOOGLE_REDIRECT_LOCALHOST,
    GOOGLE_REDIRECT_LOOPBACK,
};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::oidc_flow::{random_hex, Idp};

const PENDING_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 32;

/// The sign-in front for one process.
pub(crate) enum SignIn {
    /// Google client from the environment.
    Google(GoogleSession),
    /// Google mode without a client id and a secret.
    Unconfigured,
    /// Local IdP. This arm is `ORBLX_OIDC_MODE=mock`.
    Mock(Idp),
}

struct PendingAuth {
    nonce: String,
    redirect_uri: String,
    expires: SystemTime,
}

enum Transport {
    Live(Arc<rustls::ClientConfig>),
    #[cfg(test)]
    Scripted {
        jwks: String,
        pem: String,
        subject: String,
    },
}

/// One Google client and its pending browser states.
pub(crate) struct GoogleSession {
    client: GoogleClient,
    pending: HashMap<String, PendingAuth>,
    order: Vec<String>,
    transport: Transport,
}

/// Values the callback passes to `IssueGate`.
pub(crate) struct GoogleReady {
    pub client_id: String,
    pub jwks: String,
    pub id_token: String,
    pub nonce: String,
}

pub(crate) struct PendingExchange {
    client: GoogleClient,
    redirect_uri: String,
    nonce: String,
    code: String,
    transport: Transport,
}

impl SignIn {
    /// Read the mode and the Google client.
    ///
    /// Google mode does not open the mock IdP.
    /// A missing client id or secret stays on the Google path.
    pub(crate) fn open() -> Result<Self, String> {
        match OidcMode::from_env().map_err(|err| err.to_string())? {
            OidcMode::Google => match GoogleClient::from_env() {
                Ok(client) => Ok(Self::Google(GoogleSession::live(client)?)),
                Err(_) => Ok(Self::Unconfigured),
            },
            OidcMode::Mock => Ok(Self::Mock(Idp::open()?)),
        }
    }

    #[cfg(test)]
    pub(crate) fn mock() -> Result<Self, String> {
        Ok(Self::Mock(Idp::open()?))
    }

    #[cfg(test)]
    pub(crate) fn google(session: GoogleSession) -> Self {
        Self::Google(session)
    }
}

impl GoogleSession {
    fn live(client: GoogleClient) -> Result<Self, String> {
        Ok(Self {
            client,
            pending: HashMap::new(),
            order: Vec::new(),
            transport: Transport::Live(google_tls()?),
        })
    }

    /// Sign the ID token in the test. The test does not call Google.
    #[cfg(test)]
    pub(crate) fn scripted(
        client_id: &str,
        client_secret: &str,
        jwks: &str,
        pem: &str,
        subject: &str,
    ) -> Result<Self, String> {
        let client = GoogleClient::new(client_id, client_secret).map_err(|err| err.to_string())?;
        Ok(Self {
            client,
            pending: HashMap::new(),
            order: Vec::new(),
            transport: Transport::Scripted {
                jwks: jwks.to_string(),
                pem: pem.to_string(),
                subject: subject.to_string(),
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn from_client(client: GoogleClient) -> Result<Self, String> {
        Self::live(client)
    }

    /// Store state and return the Google authorize URL.
    pub(crate) fn begin(&mut self, host: &str, now: SystemTime) -> Result<String, String> {
        let redirect = redirect_for_host(host)?;
        self.drop_expired(now);
        while self.order.len() >= MAX_PENDING {
            let old = self.order.remove(0);
            self.pending.remove(&old);
        }
        let state = random_hex(32)?;
        let nonce = random_hex(32)?;
        let expires = now
            .checked_add(PENDING_TTL)
            .ok_or_else(|| "The sign-in time overflowed.".to_string())?;
        let url = self
            .client
            .authorize_url(redirect, &state, &nonce)
            .map_err(|err| err.to_string())?;
        self.order.push(state.clone());
        self.pending.insert(
            state,
            PendingAuth {
                nonce,
                redirect_uri: redirect.to_string(),
                expires,
            },
        );
        Ok(url)
    }

    /// Take one callback. The state cannot be used again.
    pub(crate) fn take(
        &mut self,
        code: &str,
        state: &str,
        now: SystemTime,
    ) -> Result<PendingExchange, String> {
        if code.is_empty() || state.is_empty() {
            return Err("The Google callback is missing a code or a state.".to_string());
        }
        let Some(pending) = self.pending.remove(state) else {
            return Err("The Google state is not valid.".to_string());
        };
        self.order.retain(|item| item != state);
        if now >= pending.expires {
            return Err("The Google state expired.".to_string());
        }
        let transport = match &self.transport {
            Transport::Live(config) => Transport::Live(Arc::clone(config)),
            #[cfg(test)]
            Transport::Scripted { jwks, pem, subject } => Transport::Scripted {
                jwks: jwks.clone(),
                pem: pem.clone(),
                subject: subject.clone(),
            },
        };
        Ok(PendingExchange {
            client: self.client.clone(),
            redirect_uri: pending.redirect_uri,
            nonce: pending.nonce,
            code: code.to_string(),
            transport,
        })
    }

    fn drop_expired(&mut self, now: SystemTime) {
        self.pending.retain(|_, pending| now < pending.expires);
        self.order.retain(|state| self.pending.contains_key(state));
    }
}

impl PendingExchange {
    /// Exchange the code. Do not log the token request body.
    pub(crate) async fn run(self) -> Result<GoogleReady, String> {
        let (jwks, id_token) = match &self.transport {
            Transport::Live(config) => live_exchange(config, &self).await?,
            #[cfg(test)]
            Transport::Scripted { jwks, pem, subject } => {
                let id_token = scripted::mint(pem, subject, self.client.client_id(), &self.nonce)?;
                (jwks.clone(), id_token)
            }
        };
        Ok(GoogleReady {
            client_id: self.client.client_id().to_string(),
            jwks,
            id_token,
            nonce: self.nonce,
        })
    }
}

fn redirect_for_host(host: &str) -> Result<&'static str, String> {
    if host.eq_ignore_ascii_case("127.0.0.1:8787") {
        Ok(GOOGLE_REDIRECT_LOOPBACK)
    } else if host.eq_ignore_ascii_case("localhost:8787") {
        Ok(GOOGLE_REDIRECT_LOCALHOST)
    } else {
        Err("The redirect host must be 127.0.0.1:8787 or localhost:8787.".to_string())
    }
}

fn google_tls() -> Result<Arc<rustls::ClientConfig>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if roots.is_empty() {
        return Err("The TLS trust store is empty.".to_string());
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HTTP_BYTES: usize = 1_048_576;

async fn live_exchange(
    config: &Arc<rustls::ClientConfig>,
    exchange: &PendingExchange,
) -> Result<(String, String), String> {
    let request = exchange
        .client
        .token_request(&exchange.code, &exchange.redirect_uri)
        .map_err(|err| err.to_string())?;
    let token_body = https_exchange(
        config,
        request.endpoint(),
        "POST",
        Some((GoogleTokenRequest::CONTENT_TYPE, request.body())),
    )
    .await
    .map_err(|err| match err {
        HttpsFail::Transport => "The token endpoint did not answer.".to_string(),
        HttpsFail::Status => "The token endpoint rejected the code.".to_string(),
        HttpsFail::Body => "The token response is not valid.".to_string(),
    })?;
    let id_token = GoogleTokenRequest::id_token_from_response(&token_body)
        .map_err(|_| "The token response has no ID token.".to_string())?;
    let jwks = https_exchange(config, GOOGLE_JWKS_URL, "GET", None)
        .await
        .map_err(|err| match err {
            HttpsFail::Transport => "The JWKS endpoint did not answer.".to_string(),
            HttpsFail::Status => "The JWKS endpoint rejected the request.".to_string(),
            HttpsFail::Body => "The JWKS response is not valid.".to_string(),
        })?;
    Ok((jwks, id_token))
}

#[derive(Debug)]
enum HttpsFail {
    Transport,
    Status,
    Body,
}

struct HttpsUrl {
    host: String,
    path: String,
}

fn parse_https(url: &str) -> Result<HttpsUrl, HttpsFail> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(HttpsFail::Transport);
    };
    let Some((host, path)) = rest.split_once('/') else {
        return Err(HttpsFail::Transport);
    };
    if host.is_empty() || host.contains(':') || host.contains('@') || path.contains(' ') {
        return Err(HttpsFail::Transport);
    }
    Ok(HttpsUrl {
        host: host.to_string(),
        path: format!("/{path}"),
    })
}

async fn https_exchange(
    config: &Arc<rustls::ClientConfig>,
    url: &str,
    method: &str,
    content: Option<(&str, &str)>,
) -> Result<String, HttpsFail> {
    let target = parse_https(url)?;
    let body = content.map(|(_, value)| value).unwrap_or("");
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n",
        path = target.path,
        host = target.host,
    );
    if let Some((content_type, _)) = content {
        request.push_str(&format!(
            "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(body);
    let host = target.host.clone();
    let config = Arc::clone(config);
    let outcome = timeout(EXCHANGE_TIMEOUT, async move {
        write_https(&config, &host, request.as_bytes()).await
    })
    .await
    .map_err(|_| HttpsFail::Transport)?;
    outcome
}

async fn write_https(
    config: &Arc<rustls::ClientConfig>,
    host: &str,
    request: &[u8],
) -> Result<String, HttpsFail> {
    let tcp = TcpStream::connect((host, 443))
        .await
        .map_err(|_| HttpsFail::Transport)?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(host.to_string()).map_err(|_| HttpsFail::Transport)?;
    let connector = TlsConnector::from(Arc::clone(config));
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|_| HttpsFail::Transport)?;
    complete_exchange(&mut tls, request).await
}

async fn complete_exchange<S>(tls: &mut S, request: &[u8]) -> Result<String, HttpsFail>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    tls.write_all(request)
        .await
        .map_err(|_| HttpsFail::Transport)?;
    // rustls does not promise that write_all sends the last record.
    tls.flush().await.map_err(|_| HttpsFail::Transport)?;
    let mut bytes = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tls.read(&mut tmp).await {
            Ok(0) => break,
            Ok(size) => {
                if bytes.len().saturating_add(size) > MAX_HTTP_BYTES {
                    return Err(HttpsFail::Body);
                }
                bytes.extend_from_slice(&tmp[..size]);
            }
            // Google and some egress paths omit close_notify after Connection: close.
            // Bytes already read are the HTTP response. An empty read stays a transport failure.
            Err(_) if !bytes.is_empty() => break,
            Err(_) => return Err(HttpsFail::Transport),
        }
    }
    parse_http_body(&bytes)
}

fn parse_http_body(bytes: &[u8]) -> Result<String, HttpsFail> {
    let text = std::str::from_utf8(bytes).map_err(|_| HttpsFail::Body)?;
    let Some((head, raw_body)) = text.split_once("\r\n\r\n") else {
        return Err(HttpsFail::Body);
    };
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpsFail::Body)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or(HttpsFail::Body)?;
    if status != "200" {
        return Err(HttpsFail::Status);
    }
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().ok();
        }
    }
    let body = if chunked {
        decode_chunks(raw_body)?
    } else if let Some(length) = length {
        let bytes = raw_body.as_bytes();
        if bytes.len() < length {
            return Err(HttpsFail::Body);
        }
        std::str::from_utf8(&bytes[..length])
            .map_err(|_| HttpsFail::Body)?
            .to_string()
    } else {
        raw_body.to_string()
    };
    Ok(body)
}

fn decode_chunks(raw: &str) -> Result<String, HttpsFail> {
    let mut rest = raw;
    let mut out = Vec::new();
    loop {
        let Some((size_line, after)) = rest.split_once("\r\n") else {
            return Err(HttpsFail::Body);
        };
        let size_text = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| HttpsFail::Body)?;
        if size == 0 {
            break;
        }
        let bytes = after.as_bytes();
        if bytes.len() < size + 2 {
            return Err(HttpsFail::Body);
        }
        out.extend_from_slice(&bytes[..size]);
        if &bytes[size..size + 2] != b"\r\n" {
            return Err(HttpsFail::Body);
        }
        rest = std::str::from_utf8(&bytes[size + 2..]).map_err(|_| HttpsFail::Body)?;
        if out.len() > MAX_HTTP_BYTES {
            return Err(HttpsFail::Body);
        }
    }
    String::from_utf8(out).map_err(|_| HttpsFail::Body)
}

#[cfg(test)]
mod scripted {
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::Serialize;

    const GOOGLE_ISSUER: &str = "https://accounts.google.com";

    #[derive(Serialize)]
    struct Mint {
        iss: &'static str,
        sub: String,
        aud: String,
        exp: u64,
        iat: u64,
        nonce: String,
    }

    pub(super) fn mint(
        pem: &str,
        subject: &str,
        client_id: &str,
        nonce: &str,
    ) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "The sign-in clock is not valid.".to_string())?
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("orblx-test".to_string());
        let claims = Mint {
            iss: GOOGLE_ISSUER,
            sub: subject.to_string(),
            aud: client_id.to_string(),
            exp: now.saturating_add(3600),
            iat: now,
            nonce: nonce.to_string(),
        };
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|_| "The test key is not valid.".to_string())?;
        encode(&header, &claims, &encoding)
            .map_err(|_| "The test token was not signed.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use super::{
        complete_exchange, redirect_for_host, GoogleSession, GOOGLE_REDIRECT_LOCALHOST,
        GOOGLE_REDIRECT_LOOPBACK,
    };
    use gyeol_identity::GoogleClient;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::RootCertStore;
    use rustls_pemfile::{certs, private_key};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    const CLIENT_ID: &str =
        "949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com";

    #[test]
    fn begin_uses_the_google_client() {
        let client = GoogleClient::new(CLIENT_ID, "test-secret-value").unwrap();
        let mut session = GoogleSession::from_client(client).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let url = session.begin("127.0.0.1:8787", now).unwrap();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains(&format!("client_id={CLIENT_ID}")));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8787%2Foidc%2Fcallback"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=openid"));
        assert!(url.contains("state="));
        assert!(url.contains("nonce="));
        assert!(!url.contains("oidc.gyeol.local"));
        assert!(!url.contains("test-secret-value"));
        assert_eq!(
            redirect_for_host("localhost:8787").unwrap(),
            GOOGLE_REDIRECT_LOCALHOST
        );
        assert_eq!(
            redirect_for_host("127.0.0.1:8787").unwrap(),
            GOOGLE_REDIRECT_LOOPBACK
        );
        assert!(redirect_for_host("evil.example").is_err());
    }

    #[test]
    fn http_body_reads_length_and_chunks() {
        let length = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(super::parse_http_body(length).unwrap(), "hello");
        let chunks =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(super::parse_http_body(chunks).unwrap(), "hello");
        let rejected = b"HTTP/1.1 400 Bad\r\nContent-Length: 2\r\n\r\nno";
        assert!(super::parse_http_body(rejected).is_err());
    }

    #[tokio::test]
    async fn the_tls_client_flushes_the_token_request() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = KeyPair::generate().expect("The test key did not generate.");
        let params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("The test certificate parameters were rejected.");
        let certificate = params
            .self_signed(&key)
            .expect("The test certificate was not signed.");
        let cert = load_cert(&certificate.pem());
        let private = load_key(&key.serialize_pem());
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], private)
            .expect("The test server certificate was rejected.");
        let mut roots = RootCertStore::empty();
        roots
            .add(cert)
            .expect("The test trust anchor was rejected.");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("The test listener did not bind.");
        let address = listener
            .local_addr()
            .expect("The test listener has no address.");
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener
                .accept()
                .await
                .expect("The test server did not accept.");
            let mut tls = acceptor
                .accept(tcp)
                .await
                .expect("The test server handshake failed.");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let size = tls
                    .read(&mut tmp)
                    .await
                    .expect("The test server did not read the request.");
                if size == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..size]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(buf
                .windows(b"POST /token".len())
                .any(|window| window == b"POST /token"));
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            tls.write_all(response)
                .await
                .expect("The test server did not write the response.");
            tls.flush()
                .await
                .expect("The test server did not flush the response.");
            // Drop the socket. Do not send a TLS close_notify.
        });
        let tcp = TcpStream::connect(address)
            .await
            .expect("The test client did not connect.");
        let name = ServerName::try_from("localhost".to_string())
            .expect("The test server name is not valid.");
        let mut tls = TlsConnector::from(Arc::new(client))
            .connect(name, tcp)
            .await
            .expect("The test client handshake failed.");
        let request = b"POST /token HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx";
        let answered = timeout(Duration::from_secs(2), complete_exchange(&mut tls, request)).await;
        let body = answered.expect("The TLS exchange did not finish.");
        assert_eq!(body.expect("The TLS response is not valid."), "ok");
        server_task.await.expect("The test server stopped.");
    }

    fn load_cert(pem: &str) -> CertificateDer<'static> {
        certs(&mut Cursor::new(pem.as_bytes()))
            .next()
            .expect("The test certificate PEM is empty.")
            .expect("The test certificate PEM did not parse.")
    }

    fn load_key(pem: &str) -> PrivateKeyDer<'static> {
        private_key(&mut Cursor::new(pem.as_bytes()))
            .expect("The test key PEM did not parse.")
            .expect("The test key PEM is empty.")
    }
}
