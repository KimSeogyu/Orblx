//! The HTTP gateway for agent grants.
//!
//! The gateway listens on `overlay:port` for one service. It reads one
//! HTTP/1.x request per connection. The request must carry a use proof in the
//! `Orblx-Agent-Proof` header and a 16-byte nonce in the `Orblx-Agent-Nonce`
//! header. The proof is the W19 style proof from [`crate::seal_use`]. Its
//! `extra` field binds the method, the request target, the nonce, and the
//! SHA-256 of the body. The gateway refuses a second use of the same nonce
//! with the same ticket, and a path outside the grant path prefix.
//! The gateway removes the proof headers before it forwards the request.
//! It does not log a header value or the query text.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use orblx_audit::sha256_digest;
use orblx_identity::SpiffeId;

use crate::client::GrantFiles;
use crate::grant::AgentGrant;
use crate::guard::{spawn_poll, DenyFetch, GuardConfig, GuardCore, GuardDecision, RequestCheck};
use crate::hex::{decode_hex, encode_hex};
use crate::proof::{seal_use, UseTarget};
use crate::AgentError;

/// The header that holds the use proof.
pub const PROOF_HEADER: &str = "orblx-agent-proof";
/// The header that holds the request nonce in hex.
pub const NONCE_HEADER: &str = "orblx-agent-nonce";
const EXTRA_LABEL: &[u8] = b"orblx-gateway-v1\n";
const MAX_HEAD: usize = 48 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const MAX_TARGET: usize = 2048;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// One parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// Method, for example `GET`.
    pub method: String,
    /// Request target, with the query.
    pub target: String,
    /// HTTP version text.
    pub version: String,
    /// Headers in order. Names are lowercase.
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    /// The path part of the target, without the query.
    #[must_use]
    pub fn path(&self) -> &str {
        path_of(&self.target)
    }

    fn header(&self, name: &str) -> Result<Option<&str>, ()> {
        let mut found = None;
        for (key, value) in &self.headers {
            if key == name {
                if found.is_some() {
                    return Err(());
                }
                found = Some(value.as_str());
            }
        }
        Ok(found)
    }
}

fn path_of(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or("")
}

/// Return the bytes that the proof binds for one request.
#[must_use]
pub fn http_extra(method: &str, target: &str, nonce: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut out = EXTRA_LABEL.to_vec();
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(target.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(encode_hex(nonce).as_bytes());
    out.push(b'\n');
    out.extend_from_slice(encode_hex(&sha256_digest(body)).as_bytes());
    out
}

/// Return true when `path` is inside `prefix`.
///
/// The path must start with `/`, must not have `.` or `..` parts, and must not
/// have a percent sign or a backslash. A prefix matches on a part boundary.
#[must_use]
pub fn path_in_scope(path: &str, prefix: &str) -> bool {
    if !path.starts_with('/')
        || path.contains('%')
        || path.contains('\\')
        || path.split('/').any(|part| part == "." || part == "..")
    {
        return false;
    }
    if prefix == "/" {
        return true;
    }
    let base = prefix.trim_end_matches('/');
    path == base || path.starts_with(&format!("{base}/"))
}

/// Build one HTTP request with a use proof.
///
/// The result holds the proof. The caller must not log it.
#[allow(clippy::too_many_arguments)]
pub fn seal_http_request(
    files: &GrantFiles,
    to: SocketAddr,
    node: &SpiffeId,
    service: &str,
    method: &str,
    target: &str,
    body: &[u8],
    nonce: [u8; 16],
    now: SystemTime,
) -> Result<Vec<u8>, AgentError> {
    let IpAddr::V4(addr) = to.ip() else {
        return Err(AgentError::Io("The target is not IPv4.".to_string()));
    };
    let use_target = UseTarget {
        node,
        addr,
        service,
        port: to.port(),
    };
    let extra = http_extra(method, target, &nonce, body);
    let proof = seal_use(
        &files.key_pem,
        &files.cert_pem,
        &files.ticket,
        &files.grant,
        use_target,
        &extra,
        now,
    )?;
    let mut out = format!(
        "{method} {target} HTTP/1.1\r\nHost: {to}\r\nConnection: close\r\nContent-Length: {}\r\n{PROOF_HEADER}: {proof}\r\n{NONCE_HEADER}: {}\r\n\r\n",
        body.len(),
        encode_hex(&nonce)
    )
    .into_bytes();
    out.extend_from_slice(body);
    Ok(out)
}

/// Return a new random request nonce.
#[must_use]
pub fn new_nonce() -> [u8; 16] {
    rand::random()
}

/// Build one HTTP request without a proof.
#[must_use]
pub fn plain_http_request(to: SocketAddr, method: &str, target: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "{method} {target} HTTP/1.1\r\nHost: {to}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// One gateway reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    /// HTTP status code.
    pub status: u16,
    /// First line of the body.
    pub first_body_line: String,
}

/// Send one request and read the full reply.
pub fn send_http(to: SocketAddr, bytes: &[u8], timeout: Duration) -> std::io::Result<HttpReply> {
    let mut stream = TcpStream::connect_timeout(&to, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.write_all(bytes)?;
    let mut raw = Vec::new();
    stream.take(1024 * 1024).read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let first_body_line = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.lines().next().unwrap_or("").to_string())
        .unwrap_or_default();
    Ok(HttpReply {
        status,
        first_body_line,
    })
}

/// Run the HTTP gateway until the process stops.
pub fn run_gateway(config: GuardConfig, fetch: DenyFetch) -> Result<(), AgentError> {
    let core = Arc::new(GuardCore::new(&config)?);
    let listener =
        TcpListener::bind(config.listen).map_err(|err| AgentError::Io(err.to_string()))?;
    spawn_poll(Arc::clone(&core), fetch, config.poll);
    println!(
        "agent gateway service {} listen {} target {} nonces_loaded {}",
        config.service,
        config.listen,
        config.target,
        core.seen_count()
    );
    let service = Arc::new(config.service.clone());
    let port = config.listen.port();
    let target = config.target;
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let core = Arc::clone(&core);
        let service = Arc::clone(&service);
        thread::spawn(move || {
            if let Err(err) = serve_request(&core, stream, &service, port, target) {
                eprintln!("agent gateway request failed. {err}");
            }
        });
    }
    Ok(())
}

/// The result of one gateway check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayDecision {
    /// Forward the request. The values are the agent URI and the grant id.
    Forward(String, String),
    /// Refuse the request with this status and reason token.
    Refuse(u16, &'static str),
}

/// Check one parsed request against the core, and record the decision.
pub fn check_request(
    core: &GuardCore,
    head: &RequestHead,
    body: &[u8],
    service: &str,
    port: u16,
    peer: SocketAddr,
    now: SystemTime,
) -> Result<GatewayDecision, AgentError> {
    let note = format!("method {} path {}", head.method, head.path());
    let (Ok(proof), Ok(nonce_text)) = (head.header(PROOF_HEADER), head.header(NONCE_HEADER)) else {
        core.record_early_deny("request", service, port, &note, peer, now)?;
        return Ok(GatewayDecision::Refuse(400, "request"));
    };
    let proof = proof.unwrap_or("");
    let nonce = match nonce_text {
        Some(text) => match decode_hex(text)
            .ok()
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
        {
            Some(nonce) => Some(nonce),
            None => {
                core.record_early_deny("nonce", service, port, &note, peer, now)?;
                return Ok(GatewayDecision::Refuse(403, "nonce"));
            }
        },
        None if proof.is_empty() => None,
        None => {
            core.record_early_deny("nonce", service, port, &note, peer, now)?;
            return Ok(GatewayDecision::Refuse(403, "nonce"));
        }
    };
    let extra = http_extra(
        &head.method,
        &head.target,
        &nonce.unwrap_or([0u8; 16]),
        body,
    );
    let path = head.path().to_string();
    let scope = move |grant: &AgentGrant| {
        if path_in_scope(&path, &grant.path_prefix) {
            Ok(())
        } else {
            Err("path")
        }
    };
    let check = RequestCheck {
        // A request without a proof fails the proof check with `missing`.
        nonce: Some(nonce.unwrap_or([0u8; 16])),
        scope: &scope,
        note: &note,
    };
    match core.admit_request(proof, service, port, &extra, &check, peer, now)? {
        GuardDecision::Admit(admitted) => Ok(GatewayDecision::Forward(
            admitted.agent.as_uri().to_string(),
            admitted.grant.id.clone(),
        )),
        GuardDecision::Refuse("stale") => Ok(GatewayDecision::Refuse(503, "stale")),
        GuardDecision::Refuse(reason) => Ok(GatewayDecision::Refuse(403, reason)),
    }
}

fn serve_request(
    core: &GuardCore,
    stream: TcpStream,
    service: &str,
    port: u16,
    target: SocketAddr,
) -> Result<(), AgentError> {
    let io = |err: std::io::Error| AgentError::Io(err.to_string());
    let peer = stream.peer_addr().map_err(io)?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).map_err(io)?;
    let mut writer = stream.try_clone().map_err(io)?;
    let mut reader = BufReader::new(stream);
    let parsed = read_head(&mut reader).and_then(|head| {
        let body = read_body(&mut reader, &head)?;
        Ok((head, body))
    });
    let (head, body) = match parsed {
        Ok(parts) => parts,
        Err(()) => {
            core.record_early_deny("request", service, port, "", peer, SystemTime::now())?;
            refuse(&mut writer, 400, "request");
            return Ok(());
        }
    };
    match check_request(core, &head, &body, service, port, peer, SystemTime::now())? {
        GatewayDecision::Refuse(status, reason) => {
            refuse(&mut writer, status, reason);
            Ok(())
        }
        GatewayDecision::Forward(agent, grant_id) => {
            let mut upstream = match TcpStream::connect_timeout(&target, DIAL_TIMEOUT) {
                Ok(upstream) => upstream,
                Err(_) => {
                    refuse(&mut writer, 502, "upstream");
                    return Ok(());
                }
            };
            upstream
                .write_all(&forward_bytes(&head, &body, &agent, &grant_id))
                .map_err(io)?;
            let _ = upstream.shutdown(Shutdown::Write);
            let _ = std::io::copy(&mut upstream, &mut writer);
            let _ = writer.shutdown(Shutdown::Both);
            Ok(())
        }
    }
}

fn refuse(writer: &mut TcpStream, status: u16, reason: &str) {
    let text = match status {
        400 => "Bad Request",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Forbidden",
    };
    let body = format!("orblx-deny {reason}\n");
    let reply = format!(
        "HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = writer.write_all(reply.as_bytes());
    let _ = writer.shutdown(Shutdown::Both);
}

/// Build the upstream request. It drops the proof, the nonce, hop headers,
/// and each `x-orblx-` header from the client.
#[must_use]
pub fn forward_bytes(head: &RequestHead, body: &[u8], agent: &str, grant_id: &str) -> Vec<u8> {
    let mut out = format!("{} {} {}\r\n", head.method, head.target, head.version);
    for (name, value) in &head.headers {
        let drop = name == PROOF_HEADER
            || name == NONCE_HEADER
            || name.starts_with("x-orblx-")
            || matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "te"
                    | "upgrade"
                    | "content-length"
            );
        if !drop {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    out.push_str(&format!(
        "x-orblx-agent: {agent}\r\nx-orblx-grant: {grant_id}\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
        body.len()
    ));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Parse one full request from `bytes`.
pub fn parse_request(bytes: &[u8]) -> Result<(RequestHead, Vec<u8>), AgentError> {
    let bad = |()| AgentError::Io("The HTTP request is not valid.".to_string());
    let mut reader = BufReader::new(bytes);
    let head = read_head(&mut reader).map_err(bad)?;
    let body = read_body(&mut reader, &head).map_err(bad)?;
    Ok((head, body))
}

/// Parse one request head from `reader`.
pub(crate) fn read_head<R: Read>(reader: &mut BufReader<R>) -> Result<RequestHead, ()> {
    let mut lines = Vec::new();
    let mut total = 0usize;
    loop {
        let mut raw = Vec::new();
        let limit = u64::try_from(MAX_HEAD - total).unwrap_or(0);
        let read = reader
            .by_ref()
            .take(limit)
            .read_until(b'\n', &mut raw)
            .map_err(|_| ())?;
        if read == 0 || !raw.ends_with(b"\n") {
            return Err(());
        }
        total += read;
        let line = String::from_utf8(raw).map_err(|_| ())?;
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }
    let mut iter = lines.into_iter();
    let first = iter.next().ok_or(())?;
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(());
    };
    if method.is_empty()
        || method.len() > 16
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !target.starts_with('/')
        || target.len() > MAX_TARGET
        || !target.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        || !(version == "HTTP/1.1" || version == "HTTP/1.0")
    {
        return Err(());
    }
    let mut headers = Vec::new();
    for line in iter {
        let (name, value) = line.split_once(':').ok_or(())?;
        let name = name.to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(());
        }
        let value = value.trim();
        if value.bytes().any(|byte| byte < 0x20 && byte != b'\t') {
            return Err(());
        }
        headers.push((name, value.to_string()));
    }
    Ok(RequestHead {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers,
    })
}

fn read_body<R: Read>(reader: &mut BufReader<R>, head: &RequestHead) -> Result<Vec<u8>, ()> {
    if head.header("transfer-encoding")?.is_some() {
        return Err(());
    }
    let len = match head.header("content-length")? {
        Some(text) => text.parse::<usize>().map_err(|_| ())?,
        None => 0,
    };
    if len > MAX_BODY {
        return Err(());
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).map_err(|_| ())?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{forward_bytes, path_in_scope, read_head};
    use std::io::BufReader;

    #[test]
    fn path_scope_uses_part_boundaries() {
        assert!(path_in_scope("/api", "/api"));
        assert!(path_in_scope("/api/x", "/api"));
        assert!(path_in_scope("/api/x", "/api/"));
        assert!(path_in_scope("/anything", "/"));
        assert!(!path_in_scope("/apix", "/api"));
        assert!(!path_in_scope("/admin", "/api"));
        assert!(!path_in_scope("/api/../admin", "/api"));
        assert!(!path_in_scope("/api/./x", "/api"));
        assert!(!path_in_scope("/api/%2e%2e/admin", "/api"));
        assert!(!path_in_scope("/api\\..\\admin", "/api"));
        assert!(!path_in_scope("api", "/"));
    }

    #[test]
    fn head_parse_refuses_bad_input() {
        let ok = b"GET /api/x?q=1 HTTP/1.1\r\nHost: h\r\nOrblx-Agent-Nonce: 00\r\n\r\n";
        let head = read_head(&mut BufReader::new(&ok[..])).expect("head");
        assert_eq!(head.method, "GET");
        assert_eq!(head.path(), "/api/x");
        assert_eq!(head.headers[1].0, "orblx-agent-nonce");
        for bad in [
            &b"GET /x HTTP/2\r\n\r\n"[..],
            b"get /x HTTP/1.1\r\n\r\n",
            b"GET x HTTP/1.1\r\n\r\n",
            b"GET /x HTTP/1.1\r\nno colon\r\n\r\n",
            b"GET /x HTTP/1.1\r\n",
        ] {
            assert!(read_head(&mut BufReader::new(bad)).is_err());
        }
    }

    #[test]
    fn forward_drops_the_proof_and_client_orblx_headers() {
        let raw = b"POST /api HTTP/1.1\r\nHost: h\r\nOrblx-Agent-Proof: secret-proof\r\nOrblx-Agent-Nonce: 01\r\nX-Orblx-Agent: spoof\r\nContent-Length: 2\r\n\r\n";
        let head = read_head(&mut BufReader::new(&raw[..])).expect("head");
        let out = String::from_utf8(forward_bytes(
            &head,
            b"hi",
            "spiffe://orblx.local/agent/bot",
            "0123456789abcdef",
        ))
        .expect("utf8");
        assert!(!out.contains("secret-proof"));
        assert!(!out.contains("orblx-agent-nonce"));
        assert!(!out.contains("spoof"));
        assert!(out.contains("x-orblx-agent: spiffe://orblx.local/agent/bot\r\n"));
        assert!(out.ends_with("content-length: 2\r\n\r\nhi"));
    }
}
