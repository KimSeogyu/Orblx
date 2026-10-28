//! The local web UI.
//!
//! The server binds one TCP port.
//! The server reads and writes harness state.
//! The server does not open a QUIC socket.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use tokio::net::TcpListener;

use crate::difficulty::Difficulty;
use crate::event::HarnessEvent;
use crate::harness::{Harness, Smash, Snapshot};
use crate::level::LevelId;

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
    println!("The gyeol sim harness is ready.");
    println!("Open http://{local}");
    println!("The harness is a skeleton. The harness does not run the stack.");
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
    axum::serve(listener, router())
        .await
        .map_err(|err| SimError::Serve {
            detail: err.to_string(),
        })
}

fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(script))
        .route("/style.css", get(style))
        .route("/favicon.ico", get(favicon))
        .route("/api/state", get(get_state))
        .route("/api/level", post(post_level))
        .route("/api/difficulty", post(post_difficulty))
        .route("/api/smash", post(post_smash))
        .with_state(AppState::new())
}

#[derive(Clone)]
struct AppState {
    harness: Arc<Mutex<Harness>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            harness: Arc::new(Mutex::new(Harness::new())),
        }
    }
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
    let lines = harness.events()[start..]
        .iter()
        .map(HarnessEvent::log_line)
        .collect();
    (harness.snapshot(), lines)
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

    use super::{default_listen, parse_listen, serve_listener, DEFAULT_PORT};
    use crate::http::{APP_CSS, APP_JS, INDEX_HTML};

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
        assert!(APP_JS.contains("/api/smash"));
        assert!(APP_JS.contains("/api/level"));
        assert!(APP_JS.contains("/api/difficulty"));
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
        assert!(state.contains("\"skeleton\":true"));

        let page = exchange(addr, "GET / HTTP/1.1", "").await;
        assert!(page.contains("HTTP/1.1 200"));
        assert!(page.contains("gyeol sim"));

        let smash = exchange(addr, "POST /api/smash HTTP/1.1", "{\"id\":\"revoke\"}").await;
        assert!(smash.contains("HTTP/1.1 200"));
        assert!(smash.contains("did not revoke"));
        assert!(smash.contains("\"state\":\"none\""));

        let bad = exchange(addr, "POST /api/smash HTTP/1.1", "{\"id\":\"nope\"}").await;
        assert!(bad.contains("HTTP/1.1 400"));
        assert!(bad.contains("not valid"));
    }

    async fn exchange(addr: std::net::SocketAddr, head: &str, body: &str) -> String {
        let mut stream = connect_retry(addr).await;
        let request = if body.is_empty() {
            format!("{head}\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        } else {
            format!(
                "{head}\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
}
