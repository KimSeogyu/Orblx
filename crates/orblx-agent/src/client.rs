//! The agent side of one grant use.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, SystemTime};

use orblx_identity::SpiffeId;

use crate::grant::SignedAgentGrant;
use crate::proof::{seal_use, UseTarget};
use crate::AgentError;

const CERT_FILE: &str = "agent.crt.pem";
const KEY_FILE: &str = "agent.key.pem";
const TICKET_FILE: &str = "ticket.bin";
const GRANT_FILE: &str = "grant.json";
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
    pub fn load(dir: &Path) -> Result<Self, AgentError> {
        let io = |err: std::io::Error| AgentError::Io(err.to_string());
        let cert_pem = fs::read_to_string(dir.join(CERT_FILE)).map_err(io)?;
        let key_pem = fs::read_to_string(dir.join(KEY_FILE)).map_err(io)?;
        let ticket = fs::read(dir.join(TICKET_FILE)).map_err(io)?;
        let text = fs::read_to_string(dir.join(GRANT_FILE)).map_err(io)?;
        let grant = serde_json::from_str(&text).map_err(|_| AgentError::Grant)?;
        Ok(Self {
            cert_pem,
            key_pem,
            ticket,
            grant,
        })
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
    let failed = |err: std::io::Error| ConnectError::Failed(err.to_string());
    let mut stream = TcpStream::connect_timeout(&to, timeout).map_err(failed)?;
    stream.set_read_timeout(Some(timeout)).map_err(failed)?;
    stream.write_all(line.as_bytes()).map_err(failed)?;
    stream.write_all(b"\n").map_err(failed)?;
    let reply = read_reply(&stream).map_err(failed)?;
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
