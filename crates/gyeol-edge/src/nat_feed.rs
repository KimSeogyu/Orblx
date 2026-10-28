//! JSON events for the Radioactive NAT feed.
//!
//! Each recorded line is one JSON object.
//! ShipPlatform can return `drain` from the sim feed.
//! The smash runner drives `PathMachine` and calls these builders.
//! This feed does not record a stick retry.
//!
//! ```
//! use gyeol_edge::{
//!     NatDifficulty, NatEventLog, NatInjectMode, NatLevel, PathId, KIND_NAT_INJECT,
//! };
//!
//! let path_id = PathId::allocate().expect("path id");
//! let mut log = NatEventLog::start(NatLevel::RadioactiveNat, NatDifficulty::Hard, path_id);
//! log.push_inject(NatInjectMode::UdpBlock);
//! let line = log.drain().remove(0);
//! assert!(line.contains(KIND_NAT_INJECT));
//! ```

use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::{EdgeError, PathId};

/// Envelope version for every NAT feed object.
pub const NAT_EVENT_VERSION: u64 = 1;

/// `source` value on every NAT feed object.
pub const NAT_FEED_SOURCE: &str = "edge_nat";

/// Fixture overlay address for `path.allocate`.
///
/// The edge crate does not allocate overlay addresses.
/// ADR 0003 does not name the Coordinator owner.
/// The Direct QUIC probe uses this IPv4 address as the source.
pub const LAB_OVERLAY_IP: &str = "10.8.0.1";

/// `nat.inject`
pub const KIND_NAT_INJECT: &str = "nat.inject";

/// `path.allocate`
pub const KIND_PATH_ALLOCATE: &str = "path.allocate";

/// `path.direct`
pub const KIND_PATH_DIRECT: &str = "path.direct";

/// `path.relay`
pub const KIND_PATH_RELAY: &str = "path.relay";

/// `path.switch`
pub const KIND_PATH_SWITCH: &str = "path.switch";

/// `nat.probe`
pub const KIND_NAT_PROBE: &str = "nat.probe";

/// `relay.hop`
pub const KIND_RELAY_HOP: &str = "relay.hop";

/// `path.up`
pub const KIND_PATH_UP: &str = "path.up";

/// `path.down`
pub const KIND_PATH_DOWN: &str = "path.down";

/// Fault-injection difficulty for the NAT feed.
///
/// The slugs match the sim difficulty ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatDifficulty {
    /// A light fault set.
    Easy,
    /// A mixed fault set.
    Medium,
    /// A heavy fault set.
    Hard,
}

impl NatDifficulty {
    /// The envelope slug.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Easy => "easy",
            Self::Medium => "medium",
            Self::Hard => "hard",
        }
    }

    /// Parse a sim difficulty id.
    pub fn parse(text: &str) -> Result<Self, EdgeError> {
        match text {
            "easy" => Ok(Self::Easy),
            "medium" => Ok(Self::Medium),
            "hard" => Ok(Self::Hard),
            _ => Err(EdgeError::BadNatFeed(format!(
                "The difficulty {text} is not valid."
            ))),
        }
    }
}

/// Harness level for the NAT feed envelope.
///
/// The slugs match the sim level ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatLevel {
    /// Human OIDC level.
    CityBreeze,
    /// Agent JIT level.
    AgentJit,
    /// UDP block, symmetric NAT, Allocate, Direct, and Relay.
    RadioactiveNat,
}

impl NatLevel {
    /// The envelope slug.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CityBreeze => "city_breeze",
            Self::AgentJit => "agent_jit",
            Self::RadioactiveNat => "radioactive_nat",
        }
    }

    /// Parse a sim level id.
    pub fn parse(text: &str) -> Result<Self, EdgeError> {
        match text {
            "city_breeze" => Ok(Self::CityBreeze),
            "agent_jit" => Ok(Self::AgentJit),
            "radioactive_nat" => Ok(Self::RadioactiveNat),
            _ => Err(EdgeError::BadNatFeed(format!(
                "The level {text} is not valid."
            ))),
        }
    }
}

/// The NAT fault an operator injects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatInjectMode {
    /// Drop UDP. Direct fails. Relay uses TCP.
    UdpBlock,
    /// Symmetric NAT. Direct fails. Relay uses UDP.
    Symmetric,
}

impl NatInjectMode {
    /// The `mode` slug on `nat.inject`.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::UdpBlock => "udp_block",
            Self::Symmetric => "symmetric",
        }
    }

    /// Parse an inject mode.
    pub fn parse(text: &str) -> Result<Self, EdgeError> {
        match text {
            "udp_block" => Ok(Self::UdpBlock),
            "symmetric" => Ok(Self::Symmetric),
            _ => Err(EdgeError::BadNatFeed(format!(
                "The inject mode {text} is not valid."
            ))),
        }
    }
}

/// A phase name on `path.switch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseName {
    /// The Allocate phase.
    Allocate,
    /// The Direct phase.
    Direct,
    /// The Relay phase.
    Relay,
}

impl PhaseName {
    /// The `from` or `to` slug.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Allocate => "allocate",
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// The path name on `path.up` and `path.down`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// The Direct path.
    Direct,
    /// The Relay path.
    Relay,
}

impl PathKind {
    /// The `path` slug.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// Report whether the feed arms a NAT inject.
///
/// The feed arms the inject when the difficulty is Hard.
/// The feed arms the inject when the level is Radioactive NAT.
#[must_use]
pub const fn nat_inject_armed(level: NatLevel, difficulty: NatDifficulty) -> bool {
    match (level, difficulty) {
        (NatLevel::RadioactiveNat, _) => true,
        (
            NatLevel::CityBreeze | NatLevel::AgentJit,
            NatDifficulty::Easy | NatDifficulty::Medium,
        ) => false,
        (NatLevel::CityBreeze | NatLevel::AgentJit, NatDifficulty::Hard) => true,
    }
}

/// One in-memory NAT event log.
///
/// `drain` returns one JSON object per string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatEventLog {
    level: NatLevel,
    difficulty: NatDifficulty,
    session_id: String,
    next_seq: u64,
    events: Vec<String>,
}

impl NatEventLog {
    /// Start a log for one path attempt.
    ///
    /// `path_id` is the session id for Allocate and Direct.
    /// Call `set_session_id` with the Relay session id when Relay attaches.
    #[must_use]
    pub fn start(level: NatLevel, difficulty: NatDifficulty, path_id: PathId) -> Self {
        Self {
            level,
            difficulty,
            session_id: path_id.to_hex(),
            next_seq: 1,
            events: Vec::new(),
        }
    }

    /// The session id copied into later events.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Replace the session id used by later events.
    ///
    /// The value is 32 lowercase hex characters.
    /// Events already recorded keep their session id.
    pub fn set_session_id(&mut self, session_id: &str) -> Result<(), EdgeError> {
        if !is_session_hex(session_id) {
            return Err(EdgeError::BadNatFeed(
                "The session id is not 32 lowercase hex characters.".to_string(),
            ));
        }
        self.session_id = session_id.to_string();
        Ok(())
    }

    /// The recorded JSON objects in order.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.events
    }

    /// Take the recorded JSON objects.
    ///
    /// Each string is one JSON object.
    /// The sequence counter continues after this call.
    #[must_use]
    pub fn drain(&mut self) -> Vec<String> {
        mem::take(&mut self.events)
    }

    /// Record `nat.inject`.
    ///
    /// `armed` is true.
    pub fn push_inject(&mut self, mode: NatInjectMode) {
        self.push_fields(
            KIND_NAT_INJECT,
            vec![
                field("mode", Value::from(mode.slug())),
                field("armed", Value::from(true)),
            ],
        );
    }

    /// Record `path.allocate`.
    ///
    /// `reflexive` is omitted when Allocate has no candidate.
    pub fn push_allocate(&mut self, overlay_ip: &str, reflexive: Option<&str>) {
        let mut extra = vec![field("overlay_ip", Value::from(overlay_ip))];
        if let Some(reflexive) = reflexive {
            extra.push(field("reflexive", Value::from(reflexive)));
        }
        self.push_fields(KIND_PATH_ALLOCATE, extra);
    }

    /// Record `path.direct`.
    pub fn push_direct(&mut self, ok: bool, rtt_ms: Option<u64>) {
        self.push_fields(KIND_PATH_DIRECT, ok_rtt(ok, rtt_ms));
    }

    /// Record `path.switch`.
    pub fn push_switch(&mut self, from: PhaseName, to: PhaseName) {
        self.push_fields(
            KIND_PATH_SWITCH,
            vec![
                field("from", Value::from(from.slug())),
                field("to", Value::from(to.slug())),
            ],
        );
    }

    /// Record `nat.probe`.
    pub fn push_probe(&mut self, ok: bool, rtt_ms: u64) {
        self.push_fields(KIND_NAT_PROBE, ok_and_rtt(ok, rtt_ms));
    }

    /// Record `relay.hop`.
    pub fn push_hop(&mut self, ok: bool, rtt_ms: u64) {
        self.push_fields(KIND_RELAY_HOP, ok_and_rtt(ok, rtt_ms));
    }

    /// Record `path.relay`.
    ///
    /// `hop` is `udp` or `tcp` when the transport is known.
    pub fn push_relay(&mut self, ok: bool, hop: Option<&str>) {
        let mut extra = vec![field("ok", Value::from(ok))];
        if let Some(hop) = hop {
            extra.push(field("hop", Value::from(hop)));
        }
        self.push_fields(KIND_PATH_RELAY, extra);
    }

    /// Record `path.up`.
    pub fn push_up(&mut self, path: PathKind, peer_uri: Option<&str>) {
        self.push_fields(KIND_PATH_UP, path_fields(path, peer_uri));
    }

    /// Record `path.down`.
    pub fn push_down(&mut self, path: PathKind, peer_uri: Option<&str>) {
        self.push_fields(KIND_PATH_DOWN, path_fields(path, peer_uri));
    }

    fn push_fields(&mut self, kind: &'static str, extra: Vec<(String, Value)>) {
        let mut object = Map::new();
        object.insert("v".to_string(), Value::from(NAT_EVENT_VERSION));
        object.insert("ts_ms".to_string(), Value::from(now_ms()));
        object.insert("source".to_string(), Value::from(NAT_FEED_SOURCE));
        object.insert("level".to_string(), Value::from(self.level.slug()));
        object.insert(
            "difficulty".to_string(),
            Value::from(self.difficulty.slug()),
        );
        object.insert("kind".to_string(), Value::from(kind));
        object.insert(
            "session_id".to_string(),
            Value::from(self.session_id.clone()),
        );
        object.insert("seq".to_string(), Value::from(self.next_seq));
        self.next_seq = self.next_seq.saturating_add(1);
        for (key, value) in extra {
            object.insert(key, value);
        }
        self.events.push(Value::Object(object).to_string());
    }
}

fn field(key: &str, value: Value) -> (String, Value) {
    (key.to_string(), value)
}

fn ok_rtt(ok: bool, rtt_ms: Option<u64>) -> Vec<(String, Value)> {
    let mut extra = vec![field("ok", Value::from(ok))];
    if let Some(rtt_ms) = rtt_ms {
        extra.push(field("rtt_ms", Value::from(rtt_ms)));
    }
    extra
}

fn ok_and_rtt(ok: bool, rtt_ms: u64) -> Vec<(String, Value)> {
    vec![
        field("ok", Value::from(ok)),
        field("rtt_ms", Value::from(rtt_ms)),
    ]
}

fn path_fields(path: PathKind, peer_uri: Option<&str>) -> Vec<(String, Value)> {
    let mut extra = vec![field("path", Value::from(path.slug()))];
    if let Some(peer_uri) = peer_uri {
        extra.push(field("peer_uri", Value::from(peer_uri)));
    }
    extra
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn is_session_hex(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::{
        nat_inject_armed, NatDifficulty, NatEventLog, NatInjectMode, NatLevel, PathKind, PhaseName,
        KIND_NAT_INJECT, KIND_NAT_PROBE, KIND_PATH_ALLOCATE, KIND_PATH_DIRECT, KIND_PATH_DOWN,
        KIND_PATH_RELAY, KIND_PATH_SWITCH, KIND_PATH_UP, KIND_RELAY_HOP, LAB_OVERLAY_IP,
        NAT_EVENT_VERSION, NAT_FEED_SOURCE,
    };
    use crate::{EdgeError, PathId};
    use gyeol_relay::RelaySessionId;
    use serde_json::Value;

    fn log() -> (NatEventLog, String) {
        let path_id = PathId::allocate().unwrap();
        let hex = path_id.to_hex();
        let log = NatEventLog::start(NatLevel::RadioactiveNat, NatDifficulty::Hard, path_id);
        (log, hex)
    }

    fn object(line: &str) -> Value {
        let value: Value = serde_json::from_str(line).unwrap();
        assert!(value.as_object().is_some());
        value
    }

    fn assert_envelope(value: &Value, session_id: &str, seq: u64, kind: &str) {
        let object = value.as_object().unwrap();
        assert_eq!(object.get("v").unwrap().as_u64(), Some(NAT_EVENT_VERSION));
        assert!(object.get("ts_ms").unwrap().as_u64().unwrap() > 1_700_000_000_000);
        assert_eq!(
            object.get("source").unwrap().as_str(),
            Some(NAT_FEED_SOURCE)
        );
        assert_eq!(
            object.get("level").unwrap().as_str(),
            Some(NatLevel::RadioactiveNat.slug())
        );
        assert_eq!(
            object.get("difficulty").unwrap().as_str(),
            Some(NatDifficulty::Hard.slug())
        );
        assert_eq!(object.get("kind").unwrap().as_str(), Some(kind));
        assert_eq!(object.get("session_id").unwrap().as_str(), Some(session_id));
        assert_eq!(object.get("seq").unwrap().as_u64(), Some(seq));
    }

    fn keys_of(value: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn inject_arms_for_hard_and_for_radioactive_nat() {
        assert!(nat_inject_armed(
            NatLevel::RadioactiveNat,
            NatDifficulty::Easy
        ));
        assert!(nat_inject_armed(
            NatLevel::RadioactiveNat,
            NatDifficulty::Medium
        ));
        assert!(nat_inject_armed(
            NatLevel::RadioactiveNat,
            NatDifficulty::Hard
        ));
        assert!(nat_inject_armed(NatLevel::CityBreeze, NatDifficulty::Hard));
        assert!(nat_inject_armed(NatLevel::AgentJit, NatDifficulty::Hard));
        assert!(!nat_inject_armed(NatLevel::CityBreeze, NatDifficulty::Easy));
        assert!(!nat_inject_armed(
            NatLevel::CityBreeze,
            NatDifficulty::Medium
        ));
        assert!(!nat_inject_armed(NatLevel::AgentJit, NatDifficulty::Easy));
        assert!(!nat_inject_armed(NatLevel::AgentJit, NatDifficulty::Medium));
    }

    #[test]
    fn parse_accepts_the_sim_ids() {
        assert_eq!(NatDifficulty::parse("hard").unwrap(), NatDifficulty::Hard);
        assert_eq!(
            NatLevel::parse("radioactive_nat").unwrap(),
            NatLevel::RadioactiveNat
        );
        assert_eq!(
            NatInjectMode::parse("udp_block").unwrap(),
            NatInjectMode::UdpBlock
        );
        assert_eq!(
            NatInjectMode::parse("symmetric").unwrap(),
            NatInjectMode::Symmetric
        );
        assert!(matches!(
            NatLevel::parse("city-breeze"),
            Err(EdgeError::BadNatFeed(_))
        ));
        assert_eq!(LAB_OVERLAY_IP, "10.8.0.1");
    }

    #[test]
    fn builders_emit_one_object_per_kind() {
        let (mut log, path_hex) = log();
        log.push_inject(NatInjectMode::UdpBlock);
        log.push_allocate(LAB_OVERLAY_IP, Some("127.0.0.1:9"));
        log.push_direct(false, Some(200));
        log.push_probe(false, 200);
        log.push_down(PathKind::Direct, Some("udp://127.0.0.1:9"));
        log.push_switch(PhaseName::Direct, PhaseName::Relay);
        let relay_hex = RelaySessionId::from_bytes([0xab; 16]).to_hex();
        log.set_session_id(&relay_hex).unwrap();
        log.push_hop(true, 400);
        log.push_relay(true, Some("tcp"));
        log.push_up(PathKind::Relay, Some("tcp://127.0.0.1:443"));

        let lines = log.lines();
        assert_eq!(lines.len(), 9);
        let kinds = [
            KIND_NAT_INJECT,
            KIND_PATH_ALLOCATE,
            KIND_PATH_DIRECT,
            KIND_NAT_PROBE,
            KIND_PATH_DOWN,
            KIND_PATH_SWITCH,
            KIND_RELAY_HOP,
            KIND_PATH_RELAY,
            KIND_PATH_UP,
        ];
        for (index, kind) in kinds.iter().enumerate() {
            let value = object(&lines[index]);
            let session = if index < 6 {
                path_hex.as_str()
            } else {
                relay_hex.as_str()
            };
            assert_envelope(&value, session, u64::try_from(index + 1).unwrap(), kind);
            assert!(!value
                .get("kind")
                .unwrap()
                .as_str()
                .unwrap()
                .contains("stick"));
            assert!(!value
                .get("kind")
                .unwrap()
                .as_str()
                .unwrap()
                .contains("upgrade"));
        }

        let inject = object(&lines[0]);
        assert_eq!(inject.get("mode").unwrap().as_str(), Some("udp_block"));
        assert_eq!(inject.get("armed").unwrap().as_bool(), Some(true));
        assert_eq!(
            keys_of(&inject),
            sorted(&[
                "armed",
                "difficulty",
                "kind",
                "level",
                "mode",
                "seq",
                "session_id",
                "source",
                "ts_ms",
                "v",
            ])
        );

        let allocate = object(&lines[1]);
        assert_eq!(
            allocate.get("overlay_ip").unwrap().as_str(),
            Some(LAB_OVERLAY_IP)
        );
        assert_eq!(
            allocate.get("reflexive").unwrap().as_str(),
            Some("127.0.0.1:9")
        );

        let direct = object(&lines[2]);
        assert_eq!(direct.get("ok").unwrap().as_bool(), Some(false));
        assert_eq!(direct.get("rtt_ms").unwrap().as_u64(), Some(200));

        let switch = object(&lines[5]);
        assert_eq!(switch.get("from").unwrap().as_str(), Some("direct"));
        assert_eq!(switch.get("to").unwrap().as_str(), Some("relay"));

        let hop = object(&lines[6]);
        assert_eq!(hop.get("ok").unwrap().as_bool(), Some(true));
        assert_eq!(hop.get("rtt_ms").unwrap().as_u64(), Some(400));

        let relay = object(&lines[7]);
        assert_eq!(relay.get("hop").unwrap().as_str(), Some("tcp"));

        let up = object(&lines[8]);
        assert_eq!(up.get("path").unwrap().as_str(), Some("relay"));
        assert_eq!(
            up.get("peer_uri").unwrap().as_str(),
            Some("tcp://127.0.0.1:443")
        );

        let drained = log.drain();
        assert_eq!(drained.len(), 9);
        assert!(log.drain().is_empty());
        assert!(serde_json::from_str::<Value>(&drained[0]).is_ok());
    }

    #[test]
    fn optional_fields_are_omitted() {
        let (mut log, _) = log();
        log.push_allocate(LAB_OVERLAY_IP, None);
        log.push_direct(true, None);
        log.push_relay(false, None);
        log.push_up(PathKind::Direct, None);
        let lines = log.lines();
        assert!(object(&lines[0]).get("reflexive").is_none());
        assert!(object(&lines[1]).get("rtt_ms").is_none());
        assert_eq!(object(&lines[1]).get("ok").unwrap().as_bool(), Some(true));
        assert!(object(&lines[2]).get("hop").is_none());
        assert!(object(&lines[3]).get("peer_uri").is_none());
        assert_eq!(
            object(&lines[3]).get("path").unwrap().as_str(),
            Some("direct")
        );
    }

    #[test]
    fn session_id_rejects_bad_hex() {
        let (mut log, hex) = log();
        assert_eq!(log.session_id(), hex);
        assert!(matches!(
            log.set_session_id("abcd"),
            Err(EdgeError::BadNatFeed(_))
        ));
        assert!(log.set_session_id(&"AB".repeat(16)).is_err());
        assert_eq!(log.session_id(), hex);
    }

    fn sorted<'a>(keys: &[&'a str]) -> Vec<&'a str> {
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        keys
    }
}
