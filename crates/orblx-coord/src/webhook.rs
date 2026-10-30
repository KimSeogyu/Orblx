//! Audit webhooks (W25-7) and SIEM sinks (W25-13): one delivery queue.
//!
//! The coordinator posts each config audit record to each URL in the policy field
//! `auditWebhooks`, and streams each record to each sink in `auditSinks`.
//!
//! - The outbox is the config audit chain (`config-audit.jsonl`). The chain write
//!   uses fsync before the admin reply, so a record is durable before delivery starts.
//! - One task for each target reads the chain from its cursor and sends the records in
//!   chain order. A webhook gets one record in each POST. A sink gets a batch.
//!   A failed send is sent again with a backoff from 250 ms to 4 s.
//!   The task does not skip a record.
//! - The cursor (the next sequence number) is in `audit-webhooks/<key>.json`.
//!   The task writes it with fsync after each good send. After a restart the task
//!   starts at the cursor, so a delivered record is not sent again.
//!   A crash between the good send and the cursor write can send one batch again.
//!   The receiver uses the record id to remove that copy.
//! - A new webhook starts at the policy record that added it. A new sink starts at
//!   record 0, so the SIEM gets the full chain and can check it.
//! - When a sink starts to fail, the task writes one `sink-error` record. It writes no
//!   other record until the sink works again.
//! - The delivery runs on its own thread and its own runtime. An admin request only
//!   writes the chain. It never waits for a webhook or a sink.
//! - The body signature is HMAC-SHA256 with a secret from
//!   `ORBLX_AUDIT_WEBHOOK_SECRET_FILE` or `ORBLX_AUDIT_WEBHOOK_SECRET`.
//!   Sink credentials are files in `ORBLX_AUDIT_SINK_DIR`.
//!   The coordinator never writes a secret to a log, a record, or a body.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use orblx_audit::{
    webhook_body, webhook_secret, webhook_signature, WebhookBody, WEBHOOK_SIGNATURE_HEADER,
};
use orblx_identity::AuditSink;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::CoordError;
use crate::sink::SinkSender;
use crate::state::{Coordinator, CONFIG_AUDIT_FILE};

/// The env var with the path of the webhook secret file.
pub const SECRET_FILE_ENV: &str = "ORBLX_AUDIT_WEBHOOK_SECRET_FILE";
/// The env var with the webhook secret text.
pub const SECRET_ENV: &str = "ORBLX_AUDIT_WEBHOOK_SECRET";
/// The directory in the state directory with one cursor file for each target.
pub const CURSOR_DIR: &str = "audit-webhooks";

const POLL: Duration = Duration::from_millis(100);
const URL_POLL: Duration = Duration::from_millis(500);
const FIRST_RETRY: Duration = Duration::from_millis(250);
const MAX_RETRY: Duration = Duration::from_secs(4);
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REPLY_HEAD: usize = 4096;

/// Read the webhook secret from the env.
///
/// The file env var wins over the text env var.
/// `Ok(None)` means that no secret is set. The error text does not hold the secret.
pub fn secret_from_env() -> Result<Option<Vec<u8>>, String> {
    if let Some(path) = std::env::var_os(SECRET_FILE_ENV) {
        let bytes = std::fs::read(&path).map_err(|_| {
            format!(
                "The audit webhook secret file {} did not open.",
                Path::new(&path).display()
            )
        })?;
        return webhook_secret(&bytes).map(Some).map_err(str::to_string);
    }
    if let Some(text) = std::env::var_os(SECRET_ENV) {
        let text = text
            .into_string()
            .map_err(|_| "The audit webhook secret is not UTF-8.".to_string())?;
        return webhook_secret(text.as_bytes())
            .map(Some)
            .map_err(str::to_string);
    }
    Ok(None)
}

/// Start the audit delivery thread.
///
/// The thread reads the webhook URLs and the sinks from the loaded policy.
/// A failure here does not stop the coordinator.
pub fn start(coord: &Coordinator) {
    let secret = match secret_from_env() {
        Ok(secret) => secret,
        Err(sentence) => {
            println!("audit webhook secret error: {sentence} Webhook delivery is off.");
            None
        }
    };
    start_with(coord, secret);
}

/// Start the audit delivery thread with `secret`.
pub(crate) fn start_with(coord: &Coordinator, secret: Option<Vec<u8>>) {
    let coord = coord.clone();
    let spawned = std::thread::Builder::new()
        .name("orblx-audit-webhook".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => {
                    println!("audit webhook runtime did not start");
                    return;
                }
            };
            runtime.block_on(manage(coord, secret.map(Arc::new)));
        });
    if spawned.is_err() {
        println!("audit webhook thread did not start");
    }
}

/// One delivery target.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Spec {
    Webhook(String),
    Sink(AuditSink),
}

impl Spec {
    /// The cursor key. A webhook uses its URL. A sink uses its name, so a changed
    /// sink keeps its place in the chain.
    fn key(&self) -> String {
        match self {
            Self::Webhook(url) => url.clone(),
            Self::Sink(sink) => format!("sink:{}", sink.name),
        }
    }

    /// The start of a new cursor.
    fn start(&self) -> Start {
        match self {
            Self::Webhook(_) => Start::LastPolicy,
            Self::Sink(_) => Start::Zero,
        }
    }

    /// The log kind: `audit webhook` or `audit sink`.
    fn kind(&self) -> &'static str {
        match self {
            Self::Webhook(_) => "audit webhook",
            Self::Sink(_) => "audit sink",
        }
    }

    /// The log name. A URL path is not in a log line.
    fn name(&self) -> String {
        match self {
            Self::Webhook(url) => url_label(url),
            Self::Sink(sink) => sink.name.clone(),
        }
    }

    /// The log prefix.
    fn label(&self) -> String {
        format!("{} {}", self.kind(), self.name())
    }
}

/// The host name in syslog and HEC objects.
fn host_name() -> String {
    orblx_audit::syslog_host(&std::env::var("HOSTNAME").unwrap_or_default())
}

/// Keep one delivery task for each webhook URL and each sink in the policy.
async fn manage(coord: Coordinator, secret: Option<Arc<Vec<u8>>>) {
    let Ok(state_dir) = coord.state_dir() else {
        println!("audit webhook stopped: no state directory");
        return;
    };
    let sink_dir = std::env::var_os(crate::sink::SINK_DIR_ENV).map(PathBuf::from);
    let host = host_name();
    let web_tls = match web_client_config() {
        Ok(config) => config,
        Err(_) => {
            println!("audit webhook stopped: the TLS setup failed");
            return;
        }
    };
    let mut tasks: BTreeMap<String, (Spec, tokio::task::JoinHandle<()>)> = BTreeMap::new();
    let mut said_no_secret = false;
    loop {
        let mut want: BTreeMap<String, Spec> = BTreeMap::new();
        let urls = coord.audit_webhook_urls().unwrap_or_default();
        if secret.is_some() {
            for url in urls {
                let spec = Spec::Webhook(url);
                want.insert(spec.key(), spec);
            }
        } else if !urls.is_empty() && !said_no_secret {
            println!(
                "audit webhook off: the policy has {} URLs and no secret is set ({SECRET_FILE_ENV} or {SECRET_ENV})",
                urls.len()
            );
            said_no_secret = true;
        }
        for sink in coord.audit_sinks().unwrap_or_default() {
            let spec = Spec::Sink(sink);
            want.insert(spec.key(), spec);
        }
        let stale: Vec<String> = tasks
            .iter()
            .filter(|(key, (spec, _))| want.get(*key) != Some(spec))
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale {
            if let Some((spec, task)) = tasks.remove(&key) {
                task.abort();
                if !want.contains_key(&key) {
                    let _ = std::fs::remove_file(cursor_path(&state_dir, &key));
                    println!("{} removed {}", spec.kind(), spec.name());
                }
            }
        }
        for (key, spec) in want {
            if tasks.contains_key(&key) {
                continue;
            }
            let label = spec.label();
            let target = match Target::open(&state_dir, &key, spec.start()) {
                Ok(target) => target,
                Err(err) => {
                    println!("{label} did not start: {err}");
                    continue;
                }
            };
            let transport = match &spec {
                Spec::Webhook(url) => {
                    let (Some(secret), Ok(url)) = (&secret, WebhookUrl::parse(url)) else {
                        println!("{label} did not start: the URL is not valid");
                        continue;
                    };
                    Transport::Webhook {
                        url,
                        secret: Arc::clone(secret),
                        tls: Arc::clone(&web_tls),
                    }
                }
                Spec::Sink(sink) => Transport::Sink(SinkSender::new(
                    sink.clone(),
                    sink_dir.clone(),
                    host.clone(),
                )),
            };
            println!(
                "{} added {} next_seq {}",
                spec.kind(),
                spec.name(),
                target.next
            );
            let task = tokio::spawn(deliver(target, transport, label, Some(coord.clone())));
            tasks.insert(key, (spec, task));
        }
        tokio::time::sleep(URL_POLL).await;
    }
}

/// The TLS client setup with the public web roots.
pub(crate) fn web_client_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config(roots)
}

/// A TLS client setup (TLS 1.3 and 1.2) that checks the server certificate with `roots`.
pub(crate) fn client_config(
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    let config = rustls::ClientConfig::builder_with_provider(crate::tlsutil::crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// One failed send: the step and the HTTP status (0 when there is no status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Failure {
    pub step: &'static str,
    pub status: u16,
}

impl Failure {
    pub(crate) fn step(step: &'static str) -> Self {
        Self { step, status: 0 }
    }
}

/// How one target sends records.
enum Transport {
    Webhook {
        url: WebhookUrl,
        secret: Arc<Vec<u8>>,
        tls: Arc<rustls::ClientConfig>,
    },
    Sink(SinkSender),
}

impl Transport {
    fn batch_limits(&self) -> (usize, usize) {
        match self {
            Self::Webhook { .. } => (1, usize::MAX),
            Self::Sink(_) => (crate::sink::MAX_BATCH, crate::sink::MAX_BATCH_BYTES),
        }
    }

    fn sink_name(&self) -> Option<&str> {
        match self {
            Self::Webhook { .. } => None,
            Self::Sink(sender) => Some(sender.name()),
        }
    }

    async fn send(&mut self, bodies: &[WebhookBody]) -> Result<(), Failure> {
        match self {
            Self::Webhook { url, secret, tls } => {
                for body in bodies {
                    let signature = webhook_signature(secret, body.json.as_bytes());
                    let headers = format!(
                        "{WEBHOOK_SIGNATURE_HEADER}: {signature}\r\nX-Orblx-Event-Id: {}\r\nX-Orblx-Seq: {}\r\n",
                        body.id, body.seq
                    );
                    let status = post(url, &headers, "application/json", &body.json, tls).await?;
                    if !(200..300).contains(&status) {
                        return Err(Failure {
                            step: "status",
                            status,
                        });
                    }
                }
                Ok(())
            }
            Self::Sink(sender) => sender.send(bodies).await,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CursorFile {
    version: u8,
    /// The target key: the webhook URL, or `sink:NAME`.
    url: String,
    next: u64,
    /// True after a `sink-error` record, until the next good send.
    #[serde(default)]
    failing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Start {
    LastPolicy,
    Zero,
}

/// One target and its delivery cursor.
struct Target {
    key: String,
    cursor_path: PathBuf,
    chain_path: PathBuf,
    next: u64,
    failing: bool,
}

impl Target {
    /// Load the cursor, or make a new cursor at `start`.
    fn open(state_dir: &Path, key: &str, start: Start) -> Result<Self, CoordError> {
        let cursor_path = cursor_path(state_dir, key);
        let chain_path = state_dir.join(CONFIG_AUDIT_FILE);
        if cursor_path.exists() {
            let text = crate::files::read_text(&cursor_path)?;
            let cursor: CursorFile = serde_json::from_str(&text)
                .map_err(|_| CoordError::Protocol("The webhook cursor is not valid.".into()))?;
            if cursor.url != key {
                return Err(CoordError::Protocol(
                    "The webhook cursor is for a different URL.".into(),
                ));
            }
            return Ok(Self {
                key: key.to_string(),
                cursor_path,
                chain_path,
                next: cursor.next,
                failing: cursor.failing,
            });
        }
        let next = match start {
            Start::LastPolicy => last_policy_index(&chain_path)?,
            Start::Zero => 0,
        };
        let target = Self {
            key: key.to_string(),
            cursor_path,
            chain_path,
            next,
            failing: false,
        };
        target.save()?;
        Ok(target)
    }

    fn save(&self) -> Result<(), CoordError> {
        let text = serde_json::to_string(&CursorFile {
            version: 1,
            url: self.key.clone(),
            next: self.next,
            failing: self.failing,
        })
        .map_err(|_| CoordError::Protocol("The webhook cursor did not encode.".into()))?;
        crate::files::write_text(&self.cursor_path, &text, 0o600)
    }
}

fn cursor_path(state_dir: &Path, key: &str) -> PathBuf {
    let digest = orblx_audit::sha256_digest(key.as_bytes());
    let key = orblx_audit::digest_hex(&digest);
    state_dir
        .join(CURSOR_DIR)
        .join(format!("{}.json", &key[..16]))
}

/// Return the index of the last policy-load or policy-replace record.
///
/// A new URL starts at the record of the policy that added the URL.
/// The value is the chain length when the chain has no policy record.
fn last_policy_index(chain_path: &Path) -> Result<u64, CoordError> {
    let text = match std::fs::read_to_string(chain_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(CoordError::io(err)),
    };
    let mut count = 0u64;
    let mut last = None;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if let Ok(body) = webhook_body(line) {
            if body.action == "policy-load" || body.action == "policy-replace" {
                last = Some(body.seq);
            }
        }
        count = count.saturating_add(1);
    }
    Ok(last.unwrap_or(count))
}

/// Read the complete chain lines from a byte offset.
struct Tail {
    path: PathBuf,
    offset: u64,
    next_index: u64,
    lines: std::collections::VecDeque<(u64, String)>,
}

impl Tail {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            next_index: 0,
            lines: std::collections::VecDeque::new(),
        }
    }

    /// Read new complete lines. Keep only the lines at `keep_from` and later.
    fn read_new(&mut self, keep_from: u64) -> Result<(), CoordError> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(CoordError::io(err)),
        };
        let len = file.metadata().map_err(CoordError::io)?.len();
        if len < self.offset {
            return Err(CoordError::Protocol(
                "The config audit chain became shorter.".into(),
            ));
        }
        if len == self.offset {
            return Ok(());
        }
        file.seek(SeekFrom::Start(self.offset))
            .map_err(CoordError::io)?;
        let mut bytes = Vec::new();
        file.take(len - self.offset)
            .read_to_end(&mut bytes)
            .map_err(CoordError::io)?;
        let Some(end) = bytes.iter().rposition(|byte| *byte == b'\n') else {
            return Ok(());
        };
        let text = std::str::from_utf8(&bytes[..=end])
            .map_err(|_| CoordError::Protocol("The config audit chain is not UTF-8.".into()))?;
        for line in text.split('\n').filter(|line| !line.trim().is_empty()) {
            if self.next_index >= keep_from {
                self.lines.push_back((self.next_index, line.to_string()));
            }
            self.next_index = self.next_index.saturating_add(1);
        }
        self.offset = self.offset.saturating_add(end as u64 + 1);
        Ok(())
    }

    /// Return the lines from `from` in order: at most `max` lines and about `max_bytes` bytes.
    /// The first line is always in the batch.
    fn batch(&mut self, from: u64, max: usize, max_bytes: usize) -> Vec<String> {
        while self.lines.front().is_some_and(|(at, _)| *at < from) {
            self.lines.pop_front();
        }
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut want = from;
        for (at, line) in &self.lines {
            if *at != want || out.len() >= max {
                break;
            }
            if !out.is_empty() && bytes.saturating_add(line.len()) > max_bytes {
                break;
            }
            bytes = bytes.saturating_add(line.len());
            out.push(line.clone());
            want = want.saturating_add(1);
        }
        out
    }
}

/// Deliver the records of one target in chain order.
async fn deliver(
    mut target: Target,
    mut transport: Transport,
    label: String,
    coord: Option<Coordinator>,
) {
    let mut tail = Tail::new(target.chain_path.clone());
    let mut backoff = FIRST_RETRY;
    let mut failing = false;
    let (max, max_bytes) = transport.batch_limits();
    loop {
        if let Err(err) = tail.read_new(target.next) {
            println!("{label} read error: {err}");
            tokio::time::sleep(MAX_RETRY).await;
            continue;
        }
        let lines = tail.batch(target.next, max, max_bytes);
        if lines.is_empty() {
            tokio::time::sleep(POLL).await;
            continue;
        }
        let mut bodies = Vec::with_capacity(lines.len());
        for line in &lines {
            let want = target.next.saturating_add(bodies.len() as u64);
            match webhook_body(line) {
                Ok(body) if body.seq == want => bodies.push(body),
                _ => {
                    println!("{label} stopped: record {want} is not valid");
                    return;
                }
            }
        }
        let first = bodies[0].seq;
        let last = bodies[bodies.len() - 1].seq;
        match transport.send(&bodies).await {
            Ok(()) => {
                target.next = last.saturating_add(1);
                target.failing = false;
                if let Err(err) = target.save() {
                    println!("{label} cursor write error: {err}");
                }
                if failing {
                    println!("{label} recovered seq {first}");
                    failing = false;
                }
                backoff = FIRST_RETRY;
            }
            Err(failure) => {
                println!(
                    "{label} seq {first} failed step {} status {} retry_ms {}",
                    failure.step,
                    failure.status,
                    backoff.as_millis()
                );
                failing = true;
                if let (Some(coord), Some(name)) = (&coord, transport.sink_name()) {
                    if !target.failing {
                        let detail = format!(
                            "step {} status {} seq {first}",
                            failure.step, failure.status
                        );
                        match coord.record_sink_error(name, &detail) {
                            Ok(()) => {
                                target.failing = true;
                                if let Err(err) = target.save() {
                                    println!("{label} cursor write error: {err}");
                                }
                            }
                            Err(err) => println!("{label} sink-error record failed: {err}"),
                        }
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_RETRY);
            }
        }
    }
}

/// Return `scheme://host:port` for a log line. A URL path is not in a log line.
fn url_label(url: &str) -> String {
    match WebhookUrl::parse(url) {
        Ok(parsed) => format!(
            "{}://{}:{}",
            if parsed.tls { "https" } else { "http" },
            parsed.host,
            parsed.port
        ),
        Err(_) => "invalid-url".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebhookUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl WebhookUrl {
    pub(crate) fn parse(url: &str) -> Result<Self, ()> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(());
        };
        if rest.contains(['?', '#', '@', '\\']) || rest.bytes().any(|b| !(0x21..=0x7e).contains(&b))
        {
            return Err(());
        }
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().map_err(|_| ())?),
            None => (authority, if tls { 443 } else { 80 }),
        };
        if host.is_empty() || port == 0 {
            return Err(());
        }
        Ok(Self {
            tls,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    fn host_header(&self) -> String {
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Connect to `host:port` with TLS and check the server certificate.
pub(crate) async fn tls_connect(
    host: &str,
    port: u16,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Failure> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| Failure::step("connect-timeout"))?
        .map_err(|_| Failure::step("connect"))?;
    let _ = tcp.set_nodelay(true);
    let connector = TlsConnector::from(Arc::clone(tls));
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| Failure::step("server-name"))?;
    tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Failure::step("tls-timeout"))?
        .map_err(|_| Failure::step("tls"))
}

/// Post one body and return the HTTP status.
///
/// `headers` holds extra header lines, each with `\r\n`.
pub(crate) async fn post(
    url: &WebhookUrl,
    headers: &str,
    content_type: &str,
    body: &str,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<u16, Failure> {
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: orblx-coord\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}",
        url.path,
        url.host_header(),
        body.len()
    );
    if !url.tls {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((url.host.as_str(), url.port)),
        )
        .await
        .map_err(|_| Failure::step("connect-timeout"))?
        .map_err(|_| Failure::step("connect"))?;
        let _ = tcp.set_nodelay(true);
        return tokio::time::timeout(REPLY_TIMEOUT, exchange(tcp, request.as_bytes()))
            .await
            .map_err(|_| Failure::step("reply-timeout"))?;
    }
    let stream = tls_connect(&url.host, url.port, tls).await?;
    tokio::time::timeout(REPLY_TIMEOUT, exchange(stream, request.as_bytes()))
        .await
        .map_err(|_| Failure::step("reply-timeout"))?
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
) -> Result<u16, Failure> {
    stream
        .write_all(request)
        .await
        .map_err(|_| Failure::step("write"))?;
    stream.flush().await.map_err(|_| Failure::step("write"))?;
    let mut head = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        if let Some(end) = head.windows(2).position(|pair| pair == b"\r\n") {
            let line = std::str::from_utf8(&head[..end]).map_err(|_| Failure::step("reply"))?;
            return status_of(line).ok_or(Failure::step("reply"));
        }
        if head.len() > MAX_REPLY_HEAD {
            return Err(Failure::step("reply"));
        }
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|_| Failure::step("read"))?;
        if read == 0 {
            return Err(Failure::step("reply"));
        }
        head.extend_from_slice(&buf[..read]);
    }
}

fn status_of(line: &str) -> Option<u16> {
    let mut parts = line.split(' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_url_parser_reads_the_parts() {
        let url = WebhookUrl::parse("http://receiver:9000/hook").unwrap();
        assert_eq!(
            url,
            WebhookUrl {
                tls: false,
                host: "receiver".into(),
                port: 9000,
                path: "/hook".into()
            }
        );
        assert_eq!(url.host_header(), "receiver:9000");
        let url = WebhookUrl::parse("https://siem.example.com").unwrap();
        assert_eq!((url.port, url.path.as_str()), (443, "/"));
        assert_eq!(url.host_header(), "siem.example.com");
        assert!(WebhookUrl::parse("http://u:p@receiver/").is_err());
        assert!(WebhookUrl::parse("http://receiver/?k=1").is_err());
        assert!(WebhookUrl::parse("ftp://receiver/").is_err());
        assert_eq!(
            url_label("http://receiver:9000/secret-path"),
            "http://receiver:9000"
        );
    }

    fn test_transport(url: &str) -> Transport {
        Transport::Webhook {
            url: WebhookUrl::parse(url).unwrap(),
            secret: Arc::new(vec![9u8; 32]),
            tls: web_client_config().unwrap(),
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orblx-webhook-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn append(log: &mut orblx_audit::ConfigLog, action: orblx_audit::ConfigAction, target: &str) {
        log.append(orblx_audit::ConfigEvent {
            actor: "spiffe://orblx.local/node/owner".into(),
            at_unix: 1_700_000_000,
            action,
            target: target.into(),
            before: [0; 32],
            after: [1; 32],
            detail: String::new(),
        })
        .unwrap();
    }

    /// Read one request. Reply 500 to the first `fail_first` requests, then 200.
    async fn receiver(
        listener: tokio::net::TcpListener,
        fail_first: usize,
        want: usize,
    ) -> Vec<(u64, String, bool)> {
        let secret = [9u8; 32];
        let mut got = Vec::new();
        let mut served = 0usize;
        while got.len() < want {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let (head_end, length) = loop {
                let read = stream.read(&mut buf).await.unwrap();
                raw.extend_from_slice(&buf[..read]);
                if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&raw[..end]).to_string();
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while raw.len() < head_end + length {
                let read = stream.read(&mut buf).await.unwrap();
                raw.extend_from_slice(&buf[..read]);
            }
            let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
            let body = &raw[head_end..head_end + length];
            let sig = head
                .lines()
                .find_map(|line| line.strip_prefix("X-Orblx-Signature: "))
                .unwrap()
                .to_string();
            served += 1;
            if served <= fail_first {
                stream.write_all(b"HTTP/1.1 500 No\r\n\r\n").await.unwrap();
                continue;
            }
            stream.write_all(b"HTTP/1.1 204 OK\r\n\r\n").await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(body).unwrap();
            got.push((
                value["seq"].as_u64().unwrap(),
                value["id"].as_str().unwrap().to_string(),
                orblx_audit::webhook_signature_ok(&secret, body, &sig),
            ));
        }
        got
    }

    #[tokio::test]
    async fn delivery_is_in_order_after_failures_and_resumes_at_the_cursor() {
        let dir = scratch("order");
        let chain = dir.join(CONFIG_AUDIT_FILE);
        let mut log = orblx_audit::ConfigLog::open(&chain).unwrap();
        append(&mut log, orblx_audit::ConfigAction::Enroll, "a");
        append(
            &mut log,
            orblx_audit::ConfigAction::PolicyLoad,
            "policy.hujson",
        );
        append(&mut log, orblx_audit::ConfigAction::Revoke, "a");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let target = Target::open(&dir, &url, Start::LastPolicy).unwrap();
        // A new URL starts at the last policy record.
        assert_eq!(target.next, 1);
        let recv = tokio::spawn(receiver(listener, 2, 3));
        let task = tokio::spawn(deliver(target, test_transport(&url), "t".into(), None));
        tokio::time::sleep(Duration::from_millis(200)).await;
        append(&mut log, orblx_audit::ConfigAction::TokenDeny, "t1");
        let got = tokio::time::timeout(Duration::from_secs(10), recv)
            .await
            .unwrap()
            .unwrap();
        // Wait for the cursor write after the last 2xx reply.
        for _ in 0..100 {
            if Target::open(&dir, &url, Start::LastPolicy).unwrap().next == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.abort();
        let seqs: Vec<u64> = got.iter().map(|(seq, _, _)| *seq).collect();
        assert_eq!(seqs, [1, 2, 3]);
        assert!(got.iter().all(|(_, _, ok)| *ok));
        let text = std::fs::read_to_string(&chain).unwrap();
        for (seq, id, _) in &got {
            let line = text.lines().nth(usize::try_from(*seq).unwrap()).unwrap();
            assert_eq!(&orblx_audit::webhook_body(line).unwrap().id, id);
        }
        // A restart reads the cursor and sends only the new record.
        let again = Target::open(&dir, &url, Start::LastPolicy).unwrap();
        assert_eq!(again.next, 4);
        append(&mut log, orblx_audit::ConfigAction::LockInit, "node-lock");
        let listener = tokio::net::TcpListener::bind(
            url.trim_start_matches("http://").trim_end_matches("/hook"),
        )
        .await
        .unwrap();
        let recv = tokio::spawn(receiver(listener, 0, 1));
        let task = tokio::spawn(deliver(again, test_transport(&url), "t".into(), None));
        let got = tokio::time::timeout(Duration::from_secs(10), recv)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_status_line_parser_reads_the_code() {
        assert_eq!(status_of("HTTP/1.1 204 No Content"), Some(204));
        assert_eq!(status_of("HTTP/1.0 500"), Some(500));
        assert_eq!(status_of("SSH-2.0 x"), None);
        assert_eq!(status_of("HTTP/1.1 20"), None);
    }
}
