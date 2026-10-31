//! The agent side of one grant use.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ed25519_dalek::SigningKey;
use orblx_identity::{
    decode_certificate_pem, ed25519_public_key_from_certificate_pem, ed25519_seed_from_private_pem,
    extract_spiffe_id, ticket_hash, verify_ticket, DenySet, SpiffeId, TicketVerifier,
};

use crate::grant::{AgentGrant, SignedAgentGrant};
use crate::hex::encode_hex;
use crate::proof::{seal_use, UseTarget};
use crate::AgentError;

const CERT_FILE: &str = "agent.crt.pem";
const KEY_FILE: &str = "agent.key.pem";
const TICKET_FILE: &str = "ticket.bin";
const GRANT_FILE: &str = "grant.json";
const DENY_FILE: &str = "deny.json";
const VERIFIER_FILE: &str = "ticket-verifier.pem";
const MAX_REPLY: u64 = 256;

/// The files of one issued grant.
///
/// Debug output elides the key and the ticket.
#[derive(Clone)]
pub struct GrantFiles {
    /// Agent SVID certificate PEM.
    pub cert_pem: String,
    /// Agent SVID private key PEM.
    pub key_pem: String,
    /// Agent JIT ticket bytes.
    pub ticket: Vec<u8>,
    /// Signed grant document.
    pub grant: SignedAgentGrant,
}

impl std::fmt::Debug for GrantFiles {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrantFiles")
            .field("grant", &self.grant.grant.id)
            .field("key_pem", &"[elided]")
            .field("ticket", &"[elided]")
            .finish()
    }
}

impl GrantFiles {
    /// Read the grant files from `dir`.
    ///
    /// The function reads `grant.json` before and after the other files.
    /// `fetch` writes `grant.json` last. The function refuses a mixed set:
    /// the two `grant.json` reads must match, the ticket must match the
    /// ticket hash of the grant, and the key must match the certificate.
    pub fn load(dir: &Path) -> Result<Self, AgentError> {
        let io = |err: std::io::Error| AgentError::Io(err.to_string());
        let before = fs::read(dir.join(GRANT_FILE)).map_err(io)?;
        let cert_pem = fs::read_to_string(dir.join(CERT_FILE)).map_err(io)?;
        let key_pem = fs::read_to_string(dir.join(KEY_FILE)).map_err(io)?;
        let ticket = fs::read(dir.join(TICKET_FILE)).map_err(io)?;
        let after = fs::read(dir.join(GRANT_FILE)).map_err(io)?;
        if before != after {
            return Err(AgentError::Grant);
        }
        let grant: SignedAgentGrant =
            serde_json::from_slice(&after).map_err(|_| AgentError::Grant)?;
        let files = Self {
            cert_pem,
            key_pem,
            ticket,
            grant,
        };
        files.check_set()?;
        Ok(files)
    }

    /// Check that the four files come from one issue.
    fn check_set(&self) -> Result<(), AgentError> {
        if encode_hex(&ticket_hash(&self.ticket)) != self.grant.grant.ticket_hash {
            return Err(AgentError::Grant);
        }
        let seed = ed25519_seed_from_private_pem(&self.key_pem).map_err(|_| AgentError::Key)?;
        let cert_key =
            ed25519_public_key_from_certificate_pem(&self.cert_pem).map_err(|_| AgentError::Key)?;
        if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != cert_key {
            return Err(AgentError::Key);
        }
        Ok(())
    }

    /// Write the grant files to `dir`.
    ///
    /// The key and the ticket get mode 0600.
    pub fn write(&self, dir: &Path) -> Result<(), AgentError> {
        let io = |err: std::io::Error| AgentError::Io(err.to_string());
        fs::create_dir_all(dir).map_err(io)?;
        let grant = serde_json::to_string(&self.grant).map_err(|_| AgentError::Grant)?;
        write_file(&dir.join(CERT_FILE), self.cert_pem.as_bytes(), 0o644)?;
        write_file(&dir.join(KEY_FILE), self.key_pem.as_bytes(), 0o600)?;
        write_file(&dir.join(TICKET_FILE), &self.ticket, 0o600)?;
        write_file(&dir.join(GRANT_FILE), grant.as_bytes(), 0o644)?;
        Ok(())
    }
}

/// The result of one [`GrantDir::refresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRefresh {
    /// The directory holds the current grant.
    Same,
    /// The directory holds a new grant with the same scope and a later end.
    /// The fields are the old and the new grant id.
    Switched {
        /// The grant id before the switch.
        from: String,
        /// The grant id after the switch.
        to: String,
    },
    /// The directory holds a new grant that the agent does not use.
    /// The text is a short reason: `incomplete`, `scope`, `older`,
    /// `revoked`, `ticket`, or `deny-unknown`.
    Kept(&'static str),
}

/// The deny check of a new grant before the agent takes it (W25-30).
///
/// The check reads two files that `orblx up` keeps in the node state
/// directory: `deny.json` (the deny list of the coordinator) and
/// `ticket-verifier.pem`. It does no network call. The check fails closed:
/// when it cannot read a file, the agent keeps the current grant.
#[derive(Debug, Clone)]
pub struct NodeDeny {
    state: PathBuf,
}

impl NodeDeny {
    /// Use the deny list and the ticket verifier in the node state `state`.
    #[must_use]
    pub fn new(state: &Path) -> Self {
        Self {
            state: state.to_path_buf(),
        }
    }

    /// Check the ticket of `files` and the deny list at `now`.
    ///
    /// The error is a short reason: `deny-unknown` (a file is missing or not
    /// valid), `ticket` (the ticket signature or time is not valid), or
    /// `revoked` (the deny list holds the ticket nonce or the agent URI).
    pub fn check(&self, files: &GrantFiles, now: SystemTime) -> Result<(), &'static str> {
        let Ok(pem) = fs::read_to_string(self.state.join(VERIFIER_FILE)) else {
            return Err("deny-unknown");
        };
        let Ok(verifier) = TicketVerifier::from_public_pem(&pem) else {
            return Err("deny-unknown");
        };
        let Ok(text) = fs::read(self.state.join(DENY_FILE)) else {
            return Err("deny-unknown");
        };
        let mut deny = DenySet::empty();
        if deny.apply_json(&text).is_err() {
            return Err("deny-unknown");
        }
        let Ok(ticket) = verify_ticket(&verifier, &files.ticket, now, &DenySet::empty()) else {
            return Err("ticket");
        };
        let Ok(agent) =
            decode_certificate_pem(&files.cert_pem).and_then(|der| extract_spiffe_id(&der))
        else {
            return Err("ticket");
        };
        if deny.reject_nonce(&ticket.nonce).is_err() || deny.reject_uri(&agent).is_err() {
            return Err("revoked");
        }
        Ok(())
    }
}

/// A grant directory that a long-running agent reads again.
///
/// A grant is single-use and ends at its end time. To keep access, the agent
/// requests a new grant, the owner approves it, and `orblx agent grant fetch`
/// writes it to the same directory before the current grant ends.
/// [`GrantDir::refresh`] then takes the new grant with no restart.
/// It never takes a grant with a different scope, an earlier end, or a
/// ticket that the node deny list revokes ([`NodeDeny`]).
/// The grant policy, the grant check, and the proof do not change.
#[derive(Debug)]
pub struct GrantDir {
    dir: PathBuf,
    files: GrantFiles,
    raw: Vec<u8>,
    deny: NodeDeny,
}

impl GrantDir {
    /// Read the grant files from `dir`. `deny` checks each new grant.
    pub fn open(dir: &Path, deny: NodeDeny) -> Result<Self, AgentError> {
        let raw = fs::read(dir.join(GRANT_FILE)).map_err(|err| AgentError::Io(err.to_string()))?;
        let files = GrantFiles::load(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            files,
            raw,
            deny,
        })
    }

    /// The grant files in use.
    #[must_use]
    pub fn files(&self) -> &GrantFiles {
        &self.files
    }

    /// Read the directory again and take a newer grant.
    ///
    /// The function takes the new grant only when the set is complete,
    /// the scope is the same, the new grant ends later, and the node deny
    /// list does not revoke it. In each other case the current grant stays in use.
    pub fn refresh(&mut self) -> GrantRefresh {
        self.refresh_at(SystemTime::now())
    }

    /// [`GrantDir::refresh`] with the ticket time check at `now`.
    pub fn refresh_at(&mut self, now: SystemTime) -> GrantRefresh {
        let Ok(raw) = fs::read(self.dir.join(GRANT_FILE)) else {
            return GrantRefresh::Kept("incomplete");
        };
        if raw == self.raw {
            return GrantRefresh::Same;
        }
        let Ok(files) = GrantFiles::load(&self.dir) else {
            return GrantRefresh::Kept("incomplete");
        };
        let (old, new) = (&self.files.grant.grant, &files.grant.grant);
        // A complete set is read one time only. The next refresh reads it
        // again only when `grant.json` changes.
        if !same_scope(old, new) {
            self.raw = raw;
            return GrantRefresh::Kept("scope");
        }
        if new.expires <= old.expires {
            self.raw = raw;
            return GrantRefresh::Kept("older");
        }
        match self.deny.check(&files, now) {
            Ok(()) => {}
            // The deny list can arrive late. Check the same set again next time.
            Err(reason @ "deny-unknown") => return GrantRefresh::Kept(reason),
            Err(reason) => {
                self.raw = raw;
                return GrantRefresh::Kept(reason);
            }
        }
        let from = old.id.clone();
        let to = new.id.clone();
        self.raw = raw;
        self.files = files;
        GrantRefresh::Switched { from, to }
    }
}

fn same_scope(old: &AgentGrant, new: &AgentGrant) -> bool {
    old.agent == new.agent
        && old.node == new.node
        && old.addr == new.addr
        && old.service == new.service
        && old.port == new.port
        && old.path_prefix == new.path_prefix
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AgentError> {
    let io = |err: std::io::Error| AgentError::Io(err.to_string());
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut file = options.open(&tmp).map_err(io)?;
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
    }
    fs::rename(&tmp, path).map_err(io)
}

/// A failed grant connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The guard refused the use. The text is the reason token.
    Denied(String),
    /// A local or socket error.
    Failed(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(reason) => {
                write!(formatter, "The guard refused the grant. reason {reason}")
            }
            Self::Failed(text) => write!(formatter, "The grant connection failed. {text}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Open one guarded TCP connection.
///
/// `node` and `service` name the target that the proof covers.
/// The result is a stream to the local service on the target node.
pub fn connect(
    files: &GrantFiles,
    to: SocketAddr,
    node: &SpiffeId,
    service: &str,
    timeout: Duration,
) -> Result<TcpStream, ConnectError> {
    connect_timed(
        files,
        to,
        node,
        service,
        timeout,
        &mut ConnectTiming::default(),
    )
}

/// The time of each step of one guarded connection (W25-39).
///
/// Each value is the Unix time in microseconds. A value of 0 means that the step did not occur.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectTiming {
    /// The use proof is signed.
    pub seal_us: u64,
    /// The TCP connection to the guard is open.
    pub tcp_us: u64,
    /// The use proof line is written to the socket.
    pub sent_us: u64,
    /// The guard reply line is read.
    pub reply_us: u64,
    /// The local TCP port of the connection. 0 if no connection is open.
    pub local_port: u16,
}

/// Unix time now in microseconds.
pub fn unix_micros_now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| u64::try_from(value.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Open one guarded TCP connection and record the time of each step in `timing`.
///
/// The behavior is the same as [`connect`].
pub fn connect_timed(
    files: &GrantFiles,
    to: SocketAddr,
    node: &SpiffeId,
    service: &str,
    timeout: Duration,
    timing: &mut ConnectTiming,
) -> Result<TcpStream, ConnectError> {
    let IpAddr::V4(addr) = to.ip() else {
        return Err(ConnectError::Failed("The target is not IPv4.".to_string()));
    };
    let target = UseTarget {
        node,
        addr,
        service,
        port: to.port(),
    };
    let line = seal_use(
        &files.key_pem,
        &files.cert_pem,
        &files.ticket,
        &files.grant,
        target,
        &[],
        SystemTime::now(),
    )
    .map_err(|err| ConnectError::Failed(err.to_string()))?;
    timing.seal_us = unix_micros_now();
    let failed = |err: std::io::Error| ConnectError::Failed(err.to_string());
    let mut stream = TcpStream::connect_timeout(&to, timeout).map_err(failed)?;
    timing.tcp_us = unix_micros_now();
    timing.local_port = stream.local_addr().map(|addr| addr.port()).unwrap_or(0);
    stream.set_read_timeout(Some(timeout)).map_err(failed)?;
    send_request(&mut stream, &line).map_err(failed)?;
    timing.sent_us = unix_micros_now();
    let reply = read_reply(&stream).map_err(failed)?;
    timing.reply_us = unix_micros_now();
    stream.set_read_timeout(None).map_err(failed)?;
    if reply == "orblx-ok" {
        return Ok(stream);
    }
    match reply.strip_prefix("orblx-deny ") {
        Some(reason) => Err(ConnectError::Denied(reason.to_string())),
        None if reply.is_empty() => Err(ConnectError::Denied("closed".to_string())),
        None => Err(ConnectError::Failed(
            "The guard reply is not valid.".to_string(),
        )),
    }
}

/// Send the use proof line and its newline in one write, with Nagle off (W25-39).
///
/// The line is longer than one TCP segment. With Nagle on, the kernel holds the last part of the
/// line until the peer acknowledges the first segment. A separate newline write adds one more
/// round trip.
fn send_request(stream: &mut TcpStream, line: &str) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    write_request(stream, line)
}

/// Write `line` and a newline to `writer` with one `write_all` call.
fn write_request(writer: &mut impl Write, line: &str) -> std::io::Result<()> {
    let mut bytes = Vec::with_capacity(line.len() + 1);
    bytes.extend_from_slice(line.as_bytes());
    bytes.push(b'\n');
    writer.write_all(&bytes)?;
    writer.flush()
}

fn read_reply(stream: &TcpStream) -> std::io::Result<String> {
    // Read one byte at a time so that no service byte stays in a local buffer.
    let mut raw = Vec::new();
    let mut reader = BufReader::with_capacity(1, stream.take(MAX_REPLY));
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let byte = buf[0];
        reader.consume(1);
        if byte == b'\n' {
            break;
        }
        raw.push(byte);
    }
    Ok(String::from_utf8_lossy(&raw).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Records each write call.
    #[derive(Default)]
    struct WriteLog {
        writes: Vec<Vec<u8>>,
    }

    impl Write for WriteLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_request_line_and_its_newline_go_in_one_write() {
        let line = "x".repeat(1628);
        let mut log = WriteLog::default();
        write_request(&mut log, &line).unwrap();
        assert_eq!(log.writes.len(), 1);
        let mut expected = line.into_bytes();
        expected.push(b'\n');
        assert_eq!(log.writes[0], expected);
    }

    #[test]
    fn the_request_socket_has_nagle_off_and_the_peer_reads_the_full_line() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let line = "y".repeat(1628);
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        send_request(&mut client, &line).unwrap();
        assert!(client.nodelay().unwrap());
        let mut got = String::new();
        BufReader::new(server).read_line(&mut got).unwrap();
        assert_eq!(got, format!("{line}\n"));
    }
}
