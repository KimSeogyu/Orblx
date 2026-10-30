//! SIEM audit sinks (W25-13).
//!
//! The policy names SIEM sinks in `auditSinks`. The coordinator streams each config
//! audit record to each sink, through the same outbox and cursors as `auditWebhooks`.
//!
//! ```hujson
//! "auditSinks": [
//!   {"name": "splunk", "type": "https", "url": "https://splunk.example:8088/services/collector/event",
//!    "format": "splunk-hec", "credentialFile": "splunk-hec.token"},
//!   {"name": "datadog", "type": "https", "url": "https://http-intake.logs.example/api/v2/logs",
//!    "format": "datadog", "credentialFile": "datadog.key"},
//!   {"name": "syslog", "type": "syslog-tls", "address": "syslog.example:6514", "caFile": "siem-ca.pem"},
//! ],
//! ```
//!
//! - The policy holds no secret. `credentialFile` and `caFile` are file names in the
//!   coordinator sink directory (`ORBLX_AUDIT_SINK_DIR`). A name is not a path.
//! - Each sink uses TLS and checks the server certificate. Without `caFile`, the
//!   coordinator uses the public web roots.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::policy::PolicyError;

/// The most sinks in one policy.
pub const MAX_AUDIT_SINKS: usize = 8;
const MAX_SINK_NAME: usize = 32;
const MAX_FILE_NAME: usize = 64;
const MAX_URL: usize = 256;

/// The body format of an HTTPS sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkFormat {
    /// One event JSON object on each line (`application/x-ndjson`).
    /// The credential, if set, is sent as `Authorization: Bearer`.
    Ndjson,
    /// Splunk HTTP Event Collector: one `{"time","source","sourcetype","event"}` object on each line.
    /// The credential is sent as `Authorization: Splunk`.
    SplunkHec,
    /// Datadog-style HTTP log intake: one JSON array of log objects.
    /// The credential is sent as `DD-API-KEY`.
    Datadog,
}

impl SinkFormat {
    /// The stable format word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ndjson => "ndjson",
            Self::SplunkHec => "splunk-hec",
            Self::Datadog => "datadog",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Ndjson, Self::SplunkHec, Self::Datadog]
            .into_iter()
            .find(|format| format.as_str() == text)
    }
}

/// Where a sink sends the records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkTarget {
    /// An HTTPS batch POST.
    Https {
        /// The `https://` URL. It has no user part, query, or fragment.
        url: String,
        /// The body format.
        format: SinkFormat,
    },
    /// RFC 5424 syslog over TCP and TLS (RFC 5425 octet-counting frames).
    SyslogTls {
        /// The server host name. The server certificate must name it.
        host: String,
        /// The server TCP port.
        port: u16,
    },
}

/// One SIEM sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSink {
    /// A unique sink name. The delivery cursor uses it.
    pub name: String,
    /// The transport.
    pub target: SinkTarget,
    /// The credential file name in the sink directory, or none.
    pub credential_file: Option<String>,
    /// The CA bundle file name in the sink directory, or none (public web roots).
    pub ca_file: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditSinkFile {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default, rename = "credentialFile")]
    credential_file: Option<String>,
    #[serde(default, rename = "caFile")]
    ca_file: Option<String>,
}

/// Check the `auditSinks` field.
pub(crate) fn compile_audit_sinks(files: &[AuditSinkFile]) -> Result<Vec<AuditSink>, PolicyError> {
    if files.len() > MAX_AUDIT_SINKS {
        return Err(PolicyError::new(format!(
            "The policy has more than {MAX_AUDIT_SINKS} audit sinks."
        )));
    }
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        let sink = compile_sink(file)?;
        if !names.insert(sink.name.clone()) {
            return Err(PolicyError::new(format!(
                "The audit sink name {} is used two times.",
                sink.name
            )));
        }
        out.push(sink);
    }
    Ok(out)
}

fn compile_sink(file: &AuditSinkFile) -> Result<AuditSink, PolicyError> {
    if !word_ok(&file.name, MAX_SINK_NAME) {
        return Err(PolicyError::new("An audit sink name is not valid."));
    }
    let bad = |what: &str| PolicyError::new(format!("The audit sink {} {what}", file.name));
    let target = match file.kind.as_str() {
        "https" => {
            if file.address.is_some() {
                return Err(bad("of type https has an address. Use url."));
            }
            let url = file.url.clone().ok_or_else(|| bad("has no url."))?;
            if parse_https_url(&url).is_none() {
                return Err(bad("has a url that is not a plain https URL."));
            }
            let format = match &file.format {
                None => SinkFormat::Ndjson,
                Some(text) => SinkFormat::parse(text)
                    .ok_or_else(|| bad("has an unknown format (ndjson, splunk-hec, datadog)."))?,
            };
            SinkTarget::Https { url, format }
        }
        "syslog-tls" => {
            if file.url.is_some() || file.format.is_some() {
                return Err(bad(
                    "of type syslog-tls has a url or a format. Use address.",
                ));
            }
            let address = file
                .address
                .as_deref()
                .ok_or_else(|| bad("has no address."))?;
            let (host, port) =
                host_port(address).ok_or_else(|| bad("has an address that is not host:port."))?;
            SinkTarget::SyslogTls { host, port }
        }
        _ => return Err(bad("has an unknown type (https, syslog-tls).")),
    };
    for name in [&file.credential_file, &file.ca_file].into_iter().flatten() {
        if !file_name_ok(name) {
            return Err(bad("names a file that is not a plain file name."));
        }
    }
    if file.credential_file.is_some() && matches!(target, SinkTarget::SyslogTls { .. }) {
        return Err(bad("of type syslog-tls cannot have a credential file."));
    }
    Ok(AuditSink {
        name: file.name.clone(),
        target,
        credential_file: file.credential_file.clone(),
        ca_file: file.ca_file.clone(),
    })
}

/// Split a plain `https://host[:port][/path]` URL into the host, the port, and the path.
///
/// The URL has no user part, no query, and no fragment.
#[must_use]
pub fn parse_https_url(url: &str) -> Option<(String, u16, String)> {
    if url.len() > MAX_URL
        || url.contains(['?', '#', '@', '\\'])
        || url.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return None;
    }
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = if authority.contains(':') {
        host_port(authority)?
    } else {
        if !host_ok(authority) {
            return None;
        }
        (authority.to_string(), 443)
    };
    Some((host, port, path.to_string()))
}

fn host_port(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    host_ok(host).then(|| (host.to_string(), port))
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn word_ok(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn file_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_NAME
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Result<Vec<AuditSink>, PolicyError> {
        let files: Vec<AuditSinkFile> = serde_json::from_str(text).unwrap();
        compile_audit_sinks(&files)
    }

    #[test]
    fn sinks_accept_https_and_syslog_tls_only() {
        let sinks = one(
            r#"[{"name":"hec","type":"https","url":"https://splunk:8088/services/collector/event","format":"splunk-hec","credentialFile":"hec.token","caFile":"ca.pem"},
                {"name":"sys","type":"syslog-tls","address":"syslog:6514"}]"#,
        )
        .unwrap();
        assert_eq!(sinks.len(), 2);
        assert_eq!(
            sinks[0].target,
            SinkTarget::Https {
                url: "https://splunk:8088/services/collector/event".into(),
                format: SinkFormat::SplunkHec
            }
        );
        assert_eq!(sinks[0].credential_file.as_deref(), Some("hec.token"));
        assert_eq!(
            sinks[1].target,
            SinkTarget::SyslogTls {
                host: "syslog".into(),
                port: 6514
            }
        );
        for bad in [
            r#"[{"name":"a","type":"https","url":"http://plain/hook"}]"#,
            r#"[{"name":"a","type":"https","url":"https://u:p@host/hook"}]"#,
            r#"[{"name":"a","type":"https","url":"https://host/hook?token=x"}]"#,
            r#"[{"name":"a","type":"https","url":"https://host/","format":"elastic"}]"#,
            r#"[{"name":"a","type":"syslog-tls","address":"host"}]"#,
            r#"[{"name":"a","type":"syslog-tls","address":"host:0"}]"#,
            r#"[{"name":"a","type":"syslog-tls","address":"host:6514","credentialFile":"k"}]"#,
            r#"[{"name":"a","type":"udp","address":"host:514"}]"#,
            r#"[{"name":"a","type":"https","url":"https://host/","credentialFile":"../etc/shadow"}]"#,
            r#"[{"name":"a","type":"https","url":"https://host/","caFile":".hidden"}]"#,
            r#"[{"name":"a b","type":"https","url":"https://host/"}]"#,
            r#"[{"name":"a","type":"https","url":"https://host/"},{"name":"a","type":"https","url":"https://other/"}]"#,
        ] {
            assert!(one(bad).is_err(), "{bad}");
        }
    }
}
