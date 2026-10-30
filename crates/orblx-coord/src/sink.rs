//! SIEM sink transports (W25-13).
//!
//! The delivery queue is the W25-7 queue in `webhook.rs`. This module only sends one
//! batch to one sink:
//!
//! - `https`: one POST with an NDJSON, Splunk HEC, or Datadog body.
//! - `syslog-tls`: RFC 5424 messages in RFC 5425 octet-counting frames on one TLS
//!   connection. The batch is delivered when the server closes the TLS session
//!   cleanly (close_notify) after it read the frames.
//!
//! The credential and the CA bundle are files in `ORBLX_AUDIT_SINK_DIR`.
//! The policy names the files. It does not hold a secret.
//! The credential is not in a log line, a record, or a body.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use orblx_audit::WebhookBody;
use orblx_identity::{AuditSink, SinkFormat, SinkTarget};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::webhook::{client_config, post, tls_connect, web_client_config, Failure, WebhookUrl};

/// The env var with the directory of the sink credential and CA files.
pub const SINK_DIR_ENV: &str = "ORBLX_AUDIT_SINK_DIR";
/// The maximum number of records in one batch.
pub const MAX_BATCH: usize = 500;
/// The approximate maximum number of chain bytes in one batch.
pub const MAX_BATCH_BYTES: usize = 1 << 20;
const MAX_CREDENTIAL: usize = 4096;

/// The files of one sink, loaded one time.
struct Ready {
    tls: Arc<rustls::ClientConfig>,
    /// The auth header line with `\r\n`, or an empty string.
    auth: String,
}

/// Send batches to one sink.
pub(crate) struct SinkSender {
    sink: AuditSink,
    dir: Option<PathBuf>,
    host: String,
    ready: Option<Ready>,
}

impl SinkSender {
    pub(crate) fn new(sink: AuditSink, dir: Option<PathBuf>, host: String) -> Self {
        Self {
            sink,
            dir,
            host,
            ready: None,
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.sink.name
    }

    /// Load the files. A failure is tried again at the next send.
    fn ready(&mut self) -> Result<&Ready, Failure> {
        if self.ready.is_none() {
            let tls = match &self.sink.ca_file {
                Some(name) => {
                    let pem = read_sink_file(self.dir.as_deref(), name, "ca")?;
                    client_config(roots_of(&pem)?).map_err(|_| Failure::step("tls-config"))?
                }
                None => web_client_config().map_err(|_| Failure::step("tls-config"))?,
            };
            let auth = match &self.sink.credential_file {
                Some(name) => {
                    let bytes = read_sink_file(self.dir.as_deref(), name, "credential")?;
                    let credential = credential_of(&bytes).ok_or(Failure::step("credential"))?;
                    match &self.sink.target {
                        SinkTarget::Https { format, .. } => auth_header(*format, &credential),
                        SinkTarget::SyslogTls { .. } => String::new(),
                    }
                }
                None => String::new(),
            };
            self.ready = Some(Ready { tls, auth });
        }
        self.ready.as_ref().ok_or(Failure::step("credential"))
    }

    /// Send one batch. `Ok` means that the sink accepted every record in it.
    pub(crate) async fn send(&mut self, bodies: &[WebhookBody]) -> Result<(), Failure> {
        let host = self.host.clone();
        let target = self.sink.target.clone();
        let ready = self.ready()?;
        match target {
            SinkTarget::Https { url, format } => {
                let url = WebhookUrl::parse(&url).map_err(|_| Failure::step("url"))?;
                let (body, content_type) = match format {
                    SinkFormat::Ndjson => {
                        (orblx_audit::ndjson_batch(bodies), "application/x-ndjson")
                    }
                    SinkFormat::SplunkHec => (
                        orblx_audit::splunk_hec_batch(bodies, &host)
                            .map_err(|_| Failure::step("encode"))?,
                        "application/json",
                    ),
                    SinkFormat::Datadog => (
                        orblx_audit::datadog_batch(bodies, &host)
                            .map_err(|_| Failure::step("encode"))?,
                        "application/json",
                    ),
                };
                let first = bodies.first().map_or(0, |body| body.seq);
                let headers = format!(
                    "{}X-Orblx-First-Seq: {first}\r\nX-Orblx-Count: {}\r\n",
                    ready.auth,
                    bodies.len()
                );
                let status = post(&url, &headers, content_type, &body, &ready.tls).await?;
                if (200..300).contains(&status) {
                    Ok(())
                } else {
                    Err(Failure {
                        step: "status",
                        status,
                    })
                }
            }
            SinkTarget::SyslogTls { host: server, port } => {
                let mut frames = String::new();
                for body in bodies {
                    frames.push_str(&orblx_audit::syslog_frame(body, &host));
                }
                let tls = Arc::clone(&ready.tls);
                tokio::time::timeout(
                    crate::webhook::REPLY_TIMEOUT,
                    syslog_send(&server, port, &tls, frames.as_bytes()),
                )
                .await
                .map_err(|_| Failure::step("ack-timeout"))?
            }
        }
    }
}

/// Write the frames, send close_notify, and wait for the clean close of the server.
async fn syslog_send(
    host: &str,
    port: u16,
    tls: &Arc<rustls::ClientConfig>,
    frames: &[u8],
) -> Result<(), Failure> {
    let mut stream = tls_connect(host, port, tls).await?;
    stream
        .write_all(frames)
        .await
        .map_err(|_| Failure::step("write"))?;
    stream.flush().await.map_err(|_| Failure::step("write"))?;
    stream
        .shutdown()
        .await
        .map_err(|_| Failure::step("write"))?;
    let mut buf = [0u8; 256];
    loop {
        match stream.read(&mut buf).await {
            // The server sent close_notify after it read every frame.
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            // A TCP close without close_notify is not an ack.
            Err(_) => return Err(Failure::step("ack")),
        }
    }
}

/// Read one file of the sink directory. The name is a plain file name.
fn read_sink_file(dir: Option<&Path>, name: &str, step: &'static str) -> Result<Vec<u8>, Failure> {
    let dir = dir.ok_or(Failure::step("sink-dir"))?;
    if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
        return Err(Failure::step(step));
    }
    std::fs::read(dir.join(name)).map_err(|_| Failure::step(step))
}

/// Return the credential: printable ASCII with no space, with one line end removed.
fn credential_of(bytes: &[u8]) -> Option<String> {
    let bytes = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    if bytes.is_empty()
        || bytes.len() > MAX_CREDENTIAL
        || bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
    {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

/// The auth header line for a sink format.
fn auth_header(format: SinkFormat, credential: &str) -> String {
    match format {
        SinkFormat::SplunkHec => format!("Authorization: Splunk {credential}\r\n"),
        SinkFormat::Datadog => format!("DD-API-KEY: {credential}\r\n"),
        SinkFormat::Ndjson => format!("Authorization: Bearer {credential}\r\n"),
    }
}

/// The root store of a PEM CA bundle. A bundle with no certificate is an error.
fn roots_of(pem: &[u8]) -> Result<rustls::RootCertStore, Failure> {
    let mut roots = rustls::RootCertStore::empty();
    let mut reader = pem;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|_| Failure::step("ca"))?;
        roots.add(cert).map_err(|_| Failure::step("ca"))?;
    }
    if roots.is_empty() {
        return Err(Failure::step("ca"));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_credential_is_one_printable_token() {
        assert_eq!(credential_of(b"abc-123\n").as_deref(), Some("abc-123"));
        assert_eq!(credential_of(b"abc\r\n").as_deref(), Some("abc"));
        assert_eq!(credential_of(b"a b"), None);
        assert_eq!(credential_of(b"a\nb\n"), None);
        assert_eq!(credential_of(b"\n"), None);
    }

    #[test]
    fn each_format_has_its_auth_header() {
        assert_eq!(
            auth_header(SinkFormat::SplunkHec, "t"),
            "Authorization: Splunk t\r\n"
        );
        assert_eq!(auth_header(SinkFormat::Datadog, "t"), "DD-API-KEY: t\r\n");
        assert_eq!(
            auth_header(SinkFormat::Ndjson, "t"),
            "Authorization: Bearer t\r\n"
        );
    }

    #[test]
    fn a_sink_file_name_cannot_leave_the_directory() {
        let dir = std::env::temp_dir();
        assert_eq!(
            read_sink_file(Some(&dir), "../etc/passwd", "ca"),
            Err(Failure::step("ca"))
        );
        assert_eq!(
            read_sink_file(None, "ca.pem", "ca"),
            Err(Failure::step("sink-dir"))
        );
        assert_eq!(roots_of(b"no pem").err(), Some(Failure::step("ca")));
    }
}
