//! The local web UI.
//!
//! The server binds one TCP port.
//! The default page is the game.
//! The game reads feed JSON.
//! `GET /events` sends that JSON as server-sent events.
//! The engineering panels stay hidden until the player opens them.
//! The server does not open a Unix socket.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use futures::stream::Stream;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::difficulty::Difficulty;
use crate::event::HarnessEvent;
use crate::google_flow::{GoogleReady, PendingExchange, SignIn};
use crate::harness::{Harness, Smash, Snapshot};
use crate::level::LevelId;
use crate::oidc_flow::{login_page, random_hex, AuthorizeRequest, CALLBACK_PATH, CLIENT_ID};

/// The default TCP port.
pub const DEFAULT_PORT: u16 = 8787;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const APP_CSS: &str = include_str!("../static/style.css");

/// A harness server error.
#[derive(Debug)]
pub enum SimError {
    /// The listen address did not parse.
    BadAddress {
        /// The address text.
        text: String,
    },
    /// The socket did not bind.
    Bind {
        /// The I/O detail.
        detail: String,
    },
    /// The runtime did not start.
    Runtime {
        /// The runtime detail.
        detail: String,
    },
    /// The server stopped.
    Serve {
        /// The server detail.
        detail: String,
    },
    /// The mock IdP did not open.
    Idp {
        /// The IdP detail.
        detail: String,
    },
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadAddress { text } => write!(f, "The address {text} is not valid."),
            Self::Bind { detail } => write!(f, "The harness did not bind the socket. {detail}"),
            Self::Runtime { detail } => {
                write!(f, "The harness did not start the runtime. {detail}")
            }
            Self::Serve { detail } => write!(f, "The harness server stopped. {detail}"),
            Self::Idp { detail } => write!(f, "The sign-in path did not open. {detail}"),
        }
    }
}

impl std::error::Error for SimError {}

/// The default listen address.
#[must_use]
pub fn default_listen() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_PORT))
}

/// Parse a listen address.
pub fn parse_listen(text: &str) -> Result<SocketAddr, SimError> {
    text.parse::<SocketAddr>()
        .map_err(|_| SimError::BadAddress {
            text: text.to_string(),
        })
}

/// Bind the listen address and serve the UI.
pub async fn serve(listen: SocketAddr) -> Result<(), SimError> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|err| SimError::Bind {
            detail: err.to_string(),
        })?;
    let local = listener.local_addr().map_err(|err| SimError::Bind {
        detail: err.to_string(),
    })?;
    println!("The Orblx game is ready.");
    println!("Open http://{local}");
    println!("The default page is the game.");
    println!("City Breeze opens Google sign-in.");
    println!("The redirect URI is http://127.0.0.1:8787/oidc/callback.");
    println!("Select Medium or Hard on the game board.");
    println!("The event stream is http://{local}/events");
    serve_listener(listener).await
}

/// Serve the UI on a bound listener.
pub fn serve_blocking(listen: SocketAddr) -> Result<(), SimError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| SimError::Runtime {
            detail: err.to_string(),
        })?;
    runtime.block_on(serve(listen))
}

async fn serve_listener(listener: TcpListener) -> Result<(), SimError> {
    let sign_in = SignIn::open().map_err(|detail| SimError::Idp { detail })?;
    serve_with(listener, sign_in).await
}

async fn serve_with(listener: TcpListener, sign_in: SignIn) -> Result<(), SimError> {
    axum::serve(listener, router(sign_in)?)
        .await
        .map_err(|err| SimError::Serve {
            detail: err.to_string(),
        })
}

fn router(sign_in: SignIn) -> Result<Router, SimError> {
    Ok(Router::new()
        .route("/", get(index))
        .route("/app.js", get(script))
        .route("/style.css", get(style))
        .route("/favicon.ico", get(favicon))
        .route("/oidc/authorize", get(get_authorize).post(post_authorize))
        .route("/oidc/callback", get(get_callback))
        .route("/api/state", get(get_state))
        .route("/api/level", post(post_level))
        .route("/api/difficulty", post(post_difficulty))
        .route("/api/smash", post(post_smash))
        .route("/events", get(events))
        .route("/v0/events", get(events))
        .with_state(AppState::open(sign_in)))
}

#[derive(Clone)]
struct AppState {
    harness: Arc<Mutex<Harness>>,
    events: broadcast::Sender<String>,
    sign_in: Arc<Mutex<SignIn>>,
}

impl AppState {
    fn open(sign_in: SignIn) -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            harness: Arc::new(Mutex::new(Harness::new())),
            events,
            sign_in: Arc::new(Mutex::new(sign_in)),
        }
    }
}

fn lock_sign_in(state: &AppState) -> MutexGuard<'_, SignIn> {
    state
        .sign_in
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct IdRequest {
    id: String,
}

#[derive(Debug, Default, Deserialize)]
struct AuthorizeQuery {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    scope: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizeForm {
    client_id: String,
    response_type: String,
    redirect_uri: String,
    state: String,
    scope: String,
    subject: String,
}

#[derive(Debug, Default, Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
}

fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
}

async fn index() -> impl IntoResponse {
    asset("text/html; charset=utf-8", INDEX_HTML)
}

async fn script() -> impl IntoResponse {
    asset("text/javascript; charset=utf-8", APP_JS)
}

async fn style() -> impl IntoResponse {
    asset("text/css; charset=utf-8", APP_CSS)
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn get_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    let mut sign_in = lock_sign_in(&state);
    match &mut *sign_in {
        SignIn::Google(session) => {
            let host = request_host(&headers).unwrap_or("127.0.0.1:8787");
            let location = session
                .begin(host, SystemTime::now())
                .map_err(ApiError::bad)?;
            Ok(see_other(&location))
        }
        SignIn::Unconfigured => Err(ApiError::bad(
            "Set ORBLX_GOOGLE_CLIENT_ID and ORBLX_GOOGLE_CLIENT_SECRET.",
        )),
        SignIn::Mock(_) => {
            let request = mock_authorize_request(query).map_err(ApiError::bad)?;
            request
                .check(request_host(&headers))
                .map_err(ApiError::bad)?;
            Ok(html_page(login_page(&request)).into_response())
        }
    }
}

fn mock_authorize_request(query: AuthorizeQuery) -> Result<AuthorizeRequest, String> {
    if query.client_id.is_empty() {
        return Ok(AuthorizeRequest {
            client_id: CLIENT_ID.to_string(),
            response_type: "code".to_string(),
            redirect_uri: CALLBACK_PATH.to_string(),
            state: random_hex(16)?,
            scope: "openid".to_string(),
        });
    }
    Ok(authorize_from(
        query.client_id,
        query.response_type,
        query.redirect_uri,
        query.state,
        query.scope,
    ))
}

async fn post_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeForm>,
) -> Result<Response, ApiError> {
    let mut sign_in = lock_sign_in(&state);
    match &mut *sign_in {
        SignIn::Mock(idp) => {
            let request = authorize_from(
                form.client_id,
                form.response_type,
                form.redirect_uri,
                form.state,
                form.scope,
            );
            let location = idp
                .begin(
                    &request,
                    &form.subject,
                    SystemTime::now(),
                    request_host(&headers),
                )
                .map_err(ApiError::bad)?;
            Ok(see_other(&location))
        }
        SignIn::Google(_) | SignIn::Unconfigured => {
            Err(ApiError::bad("Google sign-in does not use the local form."))
        }
    }
}

enum CallbackWork {
    Ready(Vec<String>),
    Google(PendingExchange),
}

async fn get_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let work = {
        let mut sign_in = lock_sign_in(&state);
        match &mut *sign_in {
            SignIn::Unconfigured => {
                return Err(ApiError::bad(
                    "Set ORBLX_GOOGLE_CLIENT_ID and ORBLX_GOOGLE_CLIENT_SECRET.",
                ));
            }
            SignIn::Google(session) => {
                if !query.error.is_empty() {
                    return Err(ApiError::bad("Google did not complete sign-in."));
                }
                let exchange = session
                    .take(&query.code, &query.state, SystemTime::now())
                    .map_err(ApiError::bad)?;
                CallbackWork::Google(exchange)
            }
            SignIn::Mock(idp) => {
                let subject = idp
                    .consume(&query.code, &query.state, SystemTime::now())
                    .map_err(ApiError::bad)?;
                let (_snapshot, lines) = apply(&state, |harness| {
                    harness.complete_oidc_city(idp.oidc(), &subject);
                });
                CallbackWork::Ready(lines)
            }
        }
    };
    let lines = match work {
        CallbackWork::Ready(lines) => lines,
        CallbackWork::Google(exchange) => {
            let ready = exchange.run().await.map_err(ApiError::bad)?;
            let (_snapshot, lines) = apply_google(&state, ready);
            lines
        }
    };
    write_log(&lines);
    Ok(see_other("/"))
}

fn apply_google(state: &AppState, ready: GoogleReady) -> (Snapshot, Vec<String>) {
    apply(state, |harness| {
        harness.complete_google_city(&ready.client_id, &ready.jwks, &ready.id_token, &ready.nonce);
    })
}

fn authorize_from(
    client_id: String,
    response_type: String,
    redirect_uri: String,
    state: String,
    scope: String,
) -> AuthorizeRequest {
    AuthorizeRequest {
        client_id,
        response_type,
        redirect_uri,
        state,
        scope,
    }
}

fn request_host(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
}

fn html_page(body: String) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
}

fn see_other(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
        ],
        "The browser follows the redirect.",
    )
        .into_response()
}

async fn get_state(State(state): State<AppState>) -> Json<Snapshot> {
    let (snapshot, lines) = apply(&state, Harness::poll_feeds);
    write_log(&lines);
    Json(snapshot)
}

async fn post_level(
    State(state): State<AppState>,
    Json(request): Json<IdRequest>,
) -> Result<Json<Snapshot>, ApiError> {
    let id = LevelId::parse(&request.id).map_err(ApiError::bad)?;
    let (snapshot, lines) = apply(&state, |harness| harness.select_level(id));
    write_log(&lines);
    Ok(Json(snapshot))
}

async fn post_difficulty(
    State(state): State<AppState>,
    Json(request): Json<IdRequest>,
) -> Result<Json<Snapshot>, ApiError> {
    let difficulty = Difficulty::parse(&request.id).map_err(ApiError::bad)?;
    let (snapshot, lines) = apply(&state, |harness| harness.select_difficulty(difficulty));
    write_log(&lines);
    Ok(Json(snapshot))
}

async fn post_smash(
    State(state): State<AppState>,
    Json(request): Json<IdRequest>,
) -> Result<Json<Snapshot>, ApiError> {
    let action = Smash::parse(&request.id).map_err(ApiError::bad)?;
    let (snapshot, lines) = apply(&state, |harness| harness.smash(action));
    write_log(&lines);
    Ok(Json(snapshot))
}

fn apply(state: &AppState, body: impl FnOnce(&mut Harness)) -> (Snapshot, Vec<String>) {
    let mut harness = state
        .harness
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let start = harness.events().len();
    body(&mut harness);
    let fresh = &harness.events()[start..];
    for event in fresh {
        let _ = state.events.send(event.detail.clone());
    }
    let lines = fresh.iter().map(HarnessEvent::log_line).collect();
    (harness.snapshot(), lines)
}

async fn events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(line) => return Some((Ok(Event::default().data(line)), rx)),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

fn write_log(lines: &[String]) {
    for line in lines {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use orblx_identity::GoogleClient;
    use rand::thread_rng;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    use super::{default_listen, parse_listen, serve_listener, serve_with, SignIn, DEFAULT_PORT};
    use crate::google_flow::GoogleSession;
    use crate::http::{APP_CSS, APP_JS, INDEX_HTML};

    const PLAY_CLIENT_ID: &str =
        "949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com";
    const PLAY_SUBJECT: &str = "104821234567890123456";

    #[test]
    fn the_default_port_is_8787() {
        assert_eq!(DEFAULT_PORT, 8787);
        assert_eq!(default_listen().port(), 8787);
        assert_eq!(default_listen().ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn parse_listen_rejects_a_bad_address() {
        let err = parse_listen("not-an-address").unwrap_err();
        assert!(err.to_string().contains("not valid"));
        assert_eq!(parse_listen("127.0.0.1:9").unwrap().port(), 9);
    }

    #[test]
    fn the_page_shell_names_the_panels_and_smash_buttons() {
        assert!(INDEX_HTML.contains("id=\"game\""));
        assert!(INDEX_HTML.contains("id=\"eng\" hidden"));
        assert!(INDEX_HTML.contains("Play City Breeze"));
        assert!(INDEX_HTML.contains("Play Agent JIT"));
        assert!(INDEX_HTML.contains("Play Radioactive NAT"));
        assert!(INDEX_HTML.contains("Peers"));
        assert!(INDEX_HTML.contains("Packets"));
        assert!(INDEX_HTML.contains("QUIC path"));
        assert!(INDEX_HTML.contains("SVID"));
        assert!(INDEX_HTML.contains("Ticket"));
        assert!(INDEX_HTML.contains("Event log"));
        assert!(INDEX_HTML.contains("id=\"smash-revoke\""));
        assert!(INDEX_HTML.contains("UDP block"));
        assert!(INDEX_HTML.contains("Spawn agent"));
        assert!(INDEX_HTML.contains(">Revoke<"));
        assert!(!INDEX_HTML.contains("@keyframes"));
        assert!(!APP_CSS.contains("@keyframes"));
        assert!(!APP_JS.contains("requestAnimationFrame"));
        assert!(APP_JS.contains("new EventSource(\"/events\")"));
        assert!(APP_JS.contains("applyFeed"));
        assert!(!APP_JS.contains("Mbps"));
        assert!(APP_JS.contains("/api/smash"));
        assert!(APP_JS.contains("/api/level"));
        assert!(APP_JS.contains("/api/difficulty"));
        assert!(APP_JS.contains("window.location.assign(\"/oidc/authorize\")"));
        assert!(!INDEX_HTML.to_ascii_lowercase().contains("mock idp"));
        assert!(!INDEX_HTML.contains("ada"));
        assert!(!APP_JS.contains("ada"));
        assert!(!APP_JS.contains("orblx-sim"));
        assert!(INDEX_HTML.contains("Google sign-in"));
        assert!(INDEX_HTML.contains("id=\"curve\""));
        assert!(INDEX_HTML.contains("id=\"runbar\""));
        assert!(INDEX_HTML.contains("id=\"inspector\""));
        assert!(INDEX_HTML.contains("id=\"toolbox\""));
        assert!(INDEX_HTML.contains("id=\"endcard\""));
        assert!(INDEX_HTML.contains("Next Level"));
        assert!(INDEX_HTML.contains("data-state=\"idle\""));
        assert!(APP_JS.contains("RUN_MS = 35000"));
        assert!(APP_JS.contains("Soft win"));
        assert!(APP_JS.contains("Soft loss"));
        assert!(!APP_JS.contains("@keyframes"));
    }

    #[tokio::test]
    async fn the_server_returns_levels_and_a_stub_smash() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            serve_listener(listener).await.unwrap();
        });

        let state = exchange(addr, "GET /api/state HTTP/1.1", "").await;
        assert!(state.contains("HTTP/1.1 200"));
        assert!(state.contains("City Breeze"));
        assert!(state.contains("Agent JIT"));
        assert!(state.contains("Radioactive NAT"));
        assert!(state.contains("\"armed\":false"));
        assert!(state.contains("\"skeleton\":false"));

        let page = exchange(addr, "GET / HTTP/1.1", "").await;
        assert!(page.contains("HTTP/1.1 200"));
        assert!(page.contains("id=\"game\""));
        assert!(page.contains("City Breeze"));
        assert!(page.contains("id=\"eng\" hidden"));

        let smash = exchange(addr, "POST /api/smash HTTP/1.1", "{\"id\":\"revoke\"}").await;
        assert!(smash.contains("HTTP/1.1 200"));
        assert!(smash.contains("svid.revoked"));
        assert!(smash.contains("session.dropped"));
        assert!(smash.contains("within_s"));
        assert!(smash.contains("\"state\":\"revoked\""));

        let bad = exchange(addr, "POST /api/smash HTTP/1.1", "{\"id\":\"nope\"}").await;
        assert!(bad.contains("HTTP/1.1 400"));
        assert!(bad.contains("not valid"));
    }

    #[tokio::test]
    async fn the_mock_idp_login_issues_a_city_breeze_svid() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let sign_in = SignIn::mock().unwrap();
            serve_with(listener, sign_in).await.unwrap();
        });

        let state_value = "00112233445566778899aabbccddeeff";
        let login = exchange(
            addr,
            &format!(
                "GET /oidc/authorize?client_id=orblx-sim&response_type=code&redirect_uri=%2Foidc%2Fcallback&state={state_value}&scope=openid HTTP/1.1"
            ),
            "",
        )
        .await;
        assert!(login.contains("HTTP/1.1 200"));
        assert!(login.contains("Sign in"));
        assert!(login.contains("https://oidc.orblx.local"));
        assert!(login.contains("orblx-issue"));
        assert!(login.contains("Subject: ada"));
        assert!(!login.contains("@keyframes"));

        let form = format!(
            "subject=ada&client_id=orblx-sim&response_type=code&redirect_uri=%2Foidc%2Fcallback&state={state_value}&scope=openid"
        );
        let posted = exchange_typed(
            addr,
            "localhost",
            "POST /oidc/authorize HTTP/1.1",
            "application/x-www-form-urlencoded",
            &form,
        )
        .await;
        assert!(posted.contains("HTTP/1.1 303"));
        let location = header_value(&posted, "location").expect("location");
        assert!(location.starts_with("/oidc/callback?code="));
        assert!(location.contains(&format!("state={state_value}")));

        let callback = exchange(addr, &format!("GET {location} HTTP/1.1"), "").await;
        assert!(callback.contains("HTTP/1.1 303"));
        assert_eq!(header_value(&callback, "location"), Some("/"));

        let state = exchange(addr, "GET /api/state HTTP/1.1", "").await;
        assert!(state.contains("HTTP/1.1 200"));
        assert!(state.contains("svid.issued"));
        assert!(state.contains("ticket.verified"));
        assert!(state.contains("app-a.orblx.test"));
        assert!(state.contains("app-b.orblx.test"));
        assert!(state.contains("connector_https"));
        assert!(state.contains("\"state\":\"up\""));
        assert!(state.contains("The mock IdP callback issued a token"));

        let reused = exchange(addr, &format!("GET {location} HTTP/1.1"), "").await;
        assert!(reused.contains("HTTP/1.1 400"));
        assert!(reused.contains("code"));

        let evil = exchange_typed(
            addr,
            "localhost",
            "POST /oidc/authorize HTTP/1.1",
            "application/x-www-form-urlencoded",
            "subject=ada&client_id=orblx-sim&response_type=code&redirect_uri=https%3A%2F%2Fevil.example%2Foidc%2Fcallback&state=00112233445566778899aabbccddeeff&scope=openid",
        )
        .await;
        assert!(evil.contains("HTTP/1.1 400"));
        assert!(evil.contains("redirect"));
    }

    #[tokio::test]
    async fn google_authorize_redirects_to_accounts() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = GoogleClient::new(PLAY_CLIENT_ID, "test-secret-value").unwrap();
        let session = GoogleSession::from_client(client).unwrap();
        tokio::spawn(async move {
            serve_with(listener, SignIn::google(session)).await.unwrap();
        });
        let response =
            exchange_host(addr, "127.0.0.1:8787", "GET /oidc/authorize HTTP/1.1", "").await;
        assert!(response.contains("HTTP/1.1 303"));
        let location = header_value(&response, "location").unwrap();
        assert!(location.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(location.contains(PLAY_CLIENT_ID));
        assert!(location.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8787%2Foidc%2Fcallback"));
        assert!(!location.contains("test-secret-value"));
        assert!(!response.to_ascii_lowercase().contains("mock idp"));
    }

    #[tokio::test]
    async fn an_unconfigured_google_path_does_not_open_the_mock_page() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            serve_with(listener, SignIn::Unconfigured).await.unwrap();
        });
        let response = exchange(addr, "GET /oidc/authorize HTTP/1.1", "").await;
        assert!(response.contains("HTTP/1.1 400"));
        assert!(response.contains("ORBLX_GOOGLE_CLIENT_ID"));
        assert!(response.contains("ORBLX_GOOGLE_CLIENT_SECRET"));
        assert!(!response.to_ascii_lowercase().contains("mock idp"));
        assert!(!response.contains("Subject: ada"));
    }

    #[tokio::test]
    async fn the_google_callback_issues_a_city_breeze_svid() {
        let (jwks, pem) = test_rsa();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let session = GoogleSession::scripted(
            PLAY_CLIENT_ID,
            "test-secret-value",
            &jwks,
            &pem,
            PLAY_SUBJECT,
        )
        .unwrap();
        tokio::spawn(async move {
            serve_with(listener, SignIn::google(session)).await.unwrap();
        });
        let started =
            exchange_host(addr, "127.0.0.1:8787", "GET /oidc/authorize HTTP/1.1", "").await;
        let location = header_value(&started, "location").unwrap();
        let state = query_value(location, "state");
        let callback = exchange(
            addr,
            &format!("GET /oidc/callback?code=abcd&state={state} HTTP/1.1"),
            "",
        )
        .await;
        assert!(callback.contains("HTTP/1.1 303"));
        assert_eq!(header_value(&callback, "location"), Some("/"));
        let state_body = exchange(addr, "GET /api/state HTTP/1.1", "").await;
        assert!(state_body.contains("Google issued the human ID token"));
        assert!(state_body.contains(&format!("user/{PLAY_SUBJECT}")));
        assert!(state_body.contains("\"state\":\"up\""));
        assert!(state_body.contains("app-a.orblx.test"));
        assert!(state_body.contains("app-b.orblx.test"));
        assert!(!state_body.contains("mock IdP"));
        assert!(!state_body.contains("user/ada"));
        let reused = exchange(
            addr,
            &format!("GET /oidc/callback?code=abcd&state={state} HTTP/1.1"),
            "",
        )
        .await;
        assert!(reused.contains("HTTP/1.1 400"));
    }

    fn test_rsa() -> (String, String) {
        let mut rng = thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
        let jwks = format!(
            r#"{{"keys":[{{"kty":"RSA","alg":"RS256","use":"sig","kid":"orblx-test","n":"{n}","e":"{e}"}}]}}"#
        );
        (jwks, pem)
    }

    fn query_value(url: &str, key: &str) -> String {
        let query = url.split_once('?').unwrap().1;
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix(&format!("{key}=")) {
                return value.to_string();
            }
        }
        panic!("missing {key}");
    }

    async fn exchange(addr: std::net::SocketAddr, head: &str, body: &str) -> String {
        exchange_host(addr, "localhost", head, body).await
    }

    async fn exchange_host(
        addr: std::net::SocketAddr,
        host: &str,
        head: &str,
        body: &str,
    ) -> String {
        let content_type = if body.is_empty() {
            ""
        } else {
            "application/json"
        };
        exchange_typed(addr, host, head, content_type, body).await
    }

    async fn exchange_typed(
        addr: std::net::SocketAddr,
        host: &str,
        head: &str,
        content_type: &str,
        body: &str,
    ) -> String {
        let mut stream = connect_retry(addr).await;
        let request = if body.is_empty() {
            format!("{head}\r\nHost: {host}\r\nConnection: close\r\n\r\n")
        } else {
            format!(
                "{head}\r\nHost: {host}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    async fn connect_retry(addr: std::net::SocketAddr) -> TcpStream {
        let mut last = String::new();
        for _ in 0..50 {
            match TcpStream::connect(addr).await {
                Ok(stream) => return stream,
                Err(err) => {
                    last = err.to_string();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
        panic!("The test did not connect. {last}");
    }

    fn header_value<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
        let prefix = format!("{name}:");
        for line in raw.lines() {
            if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(&prefix) {
                return Some(line[prefix.len()..].trim());
            }
        }
        None
    }
}
