//! Feed JSON version 1.
//!
//! `StackFeed::drain` returns one object per string.
//! The HTTP server sends the same object on `/events`.

use serde_json::{Map, Value};

use crate::difficulty::Difficulty;
use crate::event::EventSource;
use crate::level::LevelId;

/// One JSON line for the event bus and for SSE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedLine {
    /// The stack area that produced the line.
    pub source: EventSource,
    /// One JSON object.
    pub body: String,
}

/// The fields of one version-1 feed object.
pub struct FeedParts<'a> {
    /// Feed sequence number.
    pub seq: u64,
    /// Unix time in milliseconds.
    pub now_ms: u64,
    /// The producer.
    pub source: EventSource,
    /// The active level.
    pub level: LevelId,
    /// The active difficulty.
    pub difficulty: Difficulty,
    /// The event name.
    pub kind: &'a str,
    /// Hex session id.
    pub session_id: &'a str,
    /// Ticket hash when the event has a ticket.
    pub ticket_hash: Option<&'a [u8; 16]>,
    /// Path name when the level has one.
    pub path: Option<&'a str>,
    /// Extra kind fields.
    pub extra: Map<String, Value>,
}

/// Build one version-1 feed object.
///
/// `ticket_hash` is omitted when the event has no ticket.
/// `path` is omitted when the caller passes no path.
#[must_use]
pub fn feed_json(parts: FeedParts<'_>) -> String {
    let mut value = parts.extra;
    value.insert("v".to_string(), Value::from(1_u64));
    value.insert("ts_ms".to_string(), Value::from(parts.now_ms));
    value.insert("source".to_string(), Value::from(source_name(parts.source)));
    value.insert("level".to_string(), Value::from(level_name(parts.level)));
    value.insert(
        "difficulty".to_string(),
        Value::from(difficulty_name(parts.difficulty)),
    );
    value.insert("kind".to_string(), Value::from(parts.kind));
    value.insert("session_id".to_string(), Value::from(parts.session_id));
    value.insert("seq".to_string(), Value::from(parts.seq));
    if let Some(hash) = parts.ticket_hash {
        value.insert("ticket_hash".to_string(), Value::from(hex_encode(hash)));
    } else {
        value.remove("ticket_hash");
    }
    if let Some(path) = parts.path {
        value.insert("path".to_string(), Value::from(path));
    } else {
        value.remove("path");
    }
    Value::Object(value).to_string()
}

/// Lowercase hex.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 16 hex characters for one datapath session id.
#[must_use]
pub fn session_hex_u64(value: u64) -> String {
    format!("{value:016x}")
}

pub(crate) fn source_name(source: EventSource) -> &'static str {
    match source {
        EventSource::Harness => "harness",
        EventSource::Identity => "identity",
        EventSource::EdgeNat => "edge_nat",
        EventSource::Datapath => "datapath",
    }
}

pub(crate) fn level_name(level: LevelId) -> &'static str {
    match level {
        LevelId::CityBreeze => "city_breeze",
        LevelId::AgentJit => "agent_jit",
        LevelId::RadioactiveNat => "radioactive_nat",
    }
}

pub(crate) fn difficulty_name(difficulty: Difficulty) -> &'static str {
    match difficulty {
        Difficulty::Easy => "easy",
        Difficulty::Medium => "medium",
        Difficulty::Hard => "hard",
    }
}

pub(crate) fn path_name(level: LevelId) -> &'static str {
    match level {
        LevelId::CityBreeze => "connector",
        LevelId::AgentJit => "agent",
        LevelId::RadioactiveNat => "nat_relay",
    }
}

#[cfg(test)]
mod tests {
    use super::{feed_json, FeedParts};
    use crate::difficulty::Difficulty;
    use crate::event::EventSource;
    use crate::level::LevelId;
    use serde_json::{json, Map};

    #[test]
    fn the_object_uses_version_1_and_omits_an_empty_ticket() {
        let text = feed_json(FeedParts {
            seq: 4,
            now_ms: 10,
            source: EventSource::Datapath,
            level: LevelId::CityBreeze,
            difficulty: Difficulty::Easy,
            kind: "quic_hello",
            session_id: "0000000000000007",
            ticket_hash: None,
            path: Some("connector"),
            extra: Map::new(),
        });
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["v"], json!(1));
        assert_eq!(value["source"], json!("datapath"));
        assert_eq!(value["level"], json!("city_breeze"));
        assert_eq!(value["difficulty"], json!("easy"));
        assert_eq!(value["kind"], json!("quic_hello"));
        assert_eq!(value["session_id"], json!("0000000000000007"));
        assert_eq!(value["path"], json!("connector"));
        assert!(value.get("ticket_hash").is_none());
    }
}
