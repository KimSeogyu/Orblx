//! SIEM encodings of config audit records (W25-13).
//!
//! Each encoding carries the full event body of [`crate::webhook_body`]:
//! `{"type":"orblx.config-audit","version":1,"id":HASH,"seq":INDEX,"record":{...}}`.
//! The record holds `index`, `prev_hash`, and `hash`, so a SIEM can check the hash chain
//! with only the sink output (`scripts/siem/orblx-siem-verify.py`).
//!
//! - NDJSON: one event body on each line.
//! - Splunk HEC: one `{"time","host","source","sourcetype","event"}` object on each line.
//! - Datadog-style intake: one JSON array. `message` holds the event body text.
//! - Syslog: RFC 5424 messages in RFC 5425 octet-counting frames.

use serde::Serialize;

use crate::webhook::WebhookBody;
use crate::AuditError;

/// The `source` value in Splunk HEC and Datadog objects.
pub const SIEM_SOURCE: &str = "orblx-coord";
/// The Splunk `sourcetype` value.
pub const SIEM_SOURCETYPE: &str = "orblx:config-audit";
/// The syslog APP-NAME.
pub const SYSLOG_APP_NAME: &str = "orblx-coord";
/// The syslog MSGID.
pub const SYSLOG_MSG_ID: &str = "config-audit";
/// The syslog PRI: facility 13 (log audit) and severity 6 (informational).
pub const SYSLOG_PRI: u8 = 13 * 8 + 6;
/// The SD-ID of the structured data. 32473 is the documentation enterprise number (RFC 5612).
pub const SYSLOG_SD_ID: &str = "orblx@32473";

/// Return `host` when it is a valid syslog HOSTNAME (printable ASCII, 1 to 255 bytes), else `-`.
#[must_use]
pub fn syslog_host(host: &str) -> String {
    if !host.is_empty()
        && host.len() <= 255
        && host.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        host.to_string()
    } else {
        "-".to_string()
    }
}

/// Encode the bodies as NDJSON. Each line ends with `\n`.
#[must_use]
pub fn ndjson_batch(bodies: &[WebhookBody]) -> String {
    let mut out = String::new();
    for body in bodies {
        out.push_str(&body.json);
        out.push('\n');
    }
    out
}

/// Encode the bodies as Splunk HEC events, one object on each line.
///
/// The `event` value is the event body text as is.
pub fn splunk_hec_batch(bodies: &[WebhookBody], host: &str) -> Result<String, AuditError> {
    let host = serde_json::to_string(host).map_err(|_| AuditError::Export)?;
    let mut out = String::new();
    for body in bodies {
        out.push_str(&format!(
            "{{\"time\":{},\"host\":{host},\"source\":\"{SIEM_SOURCE}\",\"sourcetype\":\"{SIEM_SOURCETYPE}\",\"event\":{}}}\n",
            body.at_unix, body.json
        ));
    }
    Ok(out)
}

#[derive(Serialize)]
struct DatadogOut<'a> {
    ddsource: &'static str,
    service: &'static str,
    hostname: &'a str,
    ddtags: String,
    message: &'a str,
}

/// Encode the bodies as one Datadog-style JSON array.
pub fn datadog_batch(bodies: &[WebhookBody], host: &str) -> Result<String, AuditError> {
    let items: Vec<DatadogOut<'_>> = bodies
        .iter()
        .map(|body| DatadogOut {
            ddsource: "orblx",
            service: SIEM_SOURCE,
            hostname: host,
            ddtags: format!("action:{},seq:{}", body.action, body.seq),
            message: &body.json,
        })
        .collect();
    serde_json::to_string(&items).map_err(|_| AuditError::Export)
}

/// Encode one body as an RFC 5424 message in an RFC 5425 frame (`LEN SP MSG`).
#[must_use]
pub fn syslog_frame(body: &WebhookBody, host: &str) -> String {
    let message = format!(
        "<{SYSLOG_PRI}>1 {} {} {SYSLOG_APP_NAME} - {SYSLOG_MSG_ID} [{SYSLOG_SD_ID} seq=\"{}\" id=\"{}\" action=\"{}\"] {}",
        body.at_utc,
        syslog_host(host),
        body.seq,
        body.id,
        sd_value(&body.action),
        body.json
    );
    format!("{} {message}", message.len())
}

/// Escape `"`, `\`, and `]` in an SD-PARAM value (RFC 5424 section 6.3.3).
fn sd_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{webhook_body, ConfigAction, ConfigEvent, ConfigLog};

    fn bodies(tag: &str) -> Vec<WebhookBody> {
        let dir = std::env::temp_dir().join(format!("orblx-siem-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut log = ConfigLog::open(&dir.join("c.jsonl")).unwrap();
        let mut out = Vec::new();
        for target in ["a", "b"] {
            let record = log
                .append(ConfigEvent {
                    actor: "spiffe://orblx.local/node/owner".to_string(),
                    at_unix: 1_793_318_399,
                    action: ConfigAction::Revoke,
                    target: target.to_string(),
                    before: [1; 32],
                    after: [2; 32],
                    detail: "note \"x\"".to_string(),
                })
                .unwrap();
            out.push(webhook_body(&record.to_json_line().unwrap()).unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn event_of(value: &serde_json::Value) -> (u64, String) {
        (
            value["seq"].as_u64().unwrap(),
            value["record"]["hash"].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn every_encoding_keeps_the_full_event_body() {
        let bodies = bodies("enc");
        let want: Vec<(u64, String)> = bodies.iter().map(|b| (b.seq, b.id.clone())).collect();
        let nd: Vec<(u64, String)> = ndjson_batch(&bodies)
            .lines()
            .map(|line| event_of(&serde_json::from_str(line).unwrap()))
            .collect();
        assert_eq!(nd, want);
        let hec = splunk_hec_batch(&bodies, "coord").unwrap();
        let hec: Vec<(u64, String)> = hec
            .lines()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(value["time"], 1_793_318_399);
                assert_eq!(value["sourcetype"], SIEM_SOURCETYPE);
                event_of(&value["event"])
            })
            .collect();
        assert_eq!(hec, want);
        let dd: serde_json::Value =
            serde_json::from_str(&datadog_batch(&bodies, "coord").unwrap()).unwrap();
        let dd: Vec<(u64, String)> = dd
            .as_array()
            .unwrap()
            .iter()
            .map(|item| event_of(&serde_json::from_str(item["message"].as_str().unwrap()).unwrap()))
            .collect();
        assert_eq!(dd, want);
    }

    #[test]
    fn the_syslog_frame_is_rfc5424_with_an_octet_count() {
        let body = &bodies("syslog")[1];
        let frame = syslog_frame(body, "coord");
        let (count, message) = frame.split_once(' ').unwrap();
        assert_eq!(count.parse::<usize>().unwrap(), message.len());
        let head = format!(
            "<110>1 2026-10-29T23:59:59Z coord orblx-coord - config-audit [orblx@32473 seq=\"1\" id=\"{}\" action=\"revoke\"] ",
            body.id
        );
        assert!(message.starts_with(&head), "{message}");
        assert_eq!(&message[head.len()..], body.json);
        assert_eq!(syslog_host("bad host"), "-");
        assert_eq!(sd_value("a\"b]c\\"), "a\\\"b\\]c\\\\");
    }
}
