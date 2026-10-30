//! Control-plane audit hash chain.
//!
//! The coordinator writes one record for each control-plane change.
//! A record holds the actor, the UTC time, the action, the target,
//! the state digest before the change, and the state digest after the change.
//! Each record stores the previous SHA-256 hash.
//! The hash covers the previous hash and the canonical record bytes.
//! The chain file is JSONL. Each line is one record.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chain::GENESIS_HASH;
use crate::hexutil::{decode_hex_array, encode_hex};
use crate::AuditError;

/// Canonical config record version.
pub const CONFIG_EVENT_VERSION: u8 = 1;

/// The longest actor, target, or detail text in bytes.
pub const MAX_CONFIG_TEXT: usize = 512;

/// The digest of an absent state.
pub const EMPTY_DIGEST: [u8; 32] = [0u8; 32];

/// One control-plane change class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAction {
    /// The coordinator loaded a policy file at start.
    PolicyLoad,
    /// A new policy file replaced the last good policy.
    PolicyReplace,
    /// The coordinator refused a policy file and kept the last good policy.
    PolicyReject,
    /// An owner approved a node.
    Approve,
    /// An owner revoked a node.
    Revoke,
    /// An owner expired a node key.
    Expire,
    /// A node changed its advertised subnet routes.
    Routes,
    /// A node changed its exit-node offer.
    ExitNode,
    /// A node enrolled.
    Enroll,
    /// An agent JIT grant was requested, or a guard saw a new grant.
    AgentGrant,
    /// An owner approved an agent JIT grant.
    AgentApprove,
    /// A guard admitted one connection or one request with a grant.
    AgentUse,
    /// A guard refused one connection or one request.
    AgentDeny,
    /// An agent JIT grant reached its end time.
    AgentExpire,
    /// An owner revoked an agent JIT grant.
    AgentRevoke,
    /// A node turned serve on or changed the serve ports.
    Serve,
    /// A node turned serve off.
    ServeOff,
    /// A node turned funnel on. The outside listener opens.
    FunnelOn,
    /// A node turned funnel off. The outside listener closes.
    FunnelOff,
    /// An owner set up node lock with the first trusted owner keys.
    LockInit,
    /// An owner signed one node for node lock.
    LockSign,
    /// An owner key replaced itself with a new owner key.
    LockRotate,
    /// An owner key removed one owner key.
    LockRemove,
    /// A node stored a file from an allowed sender (W23-3).
    FileReceive,
    /// A node refused a file or the file failed its checks (W23-3).
    FileDeny,
    /// An owner created a scoped admin API token (W25-3).
    TokenCreate,
    /// The admin API accepted one call with an API token (W25-3).
    TokenUse,
    /// The admin API refused one call with an API token (W25-3).
    TokenDeny,
    /// An owner revoked an admin API token (W25-3).
    TokenRevoke,
    /// The policy shared one node with a guest (W25-1). One record for each share.
    Share,
    /// The policy removed one share (W25-1). One record for each share.
    Unshare,
    /// The node packet filter dropped packets that no grant allows (W24).
    ///
    /// The node writes a sample of the drops. The detail counts the drops it did not write.
    PacketDeny,
    /// An owner removed the SVID deny entry of one principal (W25-2 revoke undo).
    Unrevoke,
    /// The delivery to one SIEM sink started to fail (W25-13).
    ///
    /// The coordinator writes one record for each run of failures, not one for each try.
    SinkError,
    /// A client moved an HA subnet route to another router (W25-10).
    RouteFailover,
}

impl ConfigAction {
    /// Every action in code order.
    pub const ALL: [Self; 35] = [
        Self::PolicyLoad,
        Self::PolicyReplace,
        Self::PolicyReject,
        Self::Approve,
        Self::Revoke,
        Self::Expire,
        Self::Routes,
        Self::ExitNode,
        Self::Enroll,
        Self::AgentGrant,
        Self::AgentApprove,
        Self::AgentUse,
        Self::AgentDeny,
        Self::AgentExpire,
        Self::AgentRevoke,
        Self::Serve,
        Self::ServeOff,
        Self::FunnelOn,
        Self::FunnelOff,
        Self::LockInit,
        Self::LockSign,
        Self::LockRotate,
        Self::LockRemove,
        Self::FileReceive,
        Self::FileDeny,
        Self::TokenCreate,
        Self::TokenUse,
        Self::TokenDeny,
        Self::TokenRevoke,
        Self::Share,
        Self::Unshare,
        Self::PacketDeny,
        Self::Unrevoke,
        Self::SinkError,
        Self::RouteFailover,
    ];

    /// Return the stable action token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyLoad => "policy-load",
            Self::PolicyReplace => "policy-replace",
            Self::PolicyReject => "policy-reject",
            Self::Approve => "approve",
            Self::Revoke => "revoke",
            Self::Expire => "expire",
            Self::Routes => "routes",
            Self::ExitNode => "exit-node",
            Self::Enroll => "enroll",
            Self::AgentGrant => "agent-grant",
            Self::AgentApprove => "agent-approve",
            Self::AgentUse => "agent-use",
            Self::AgentDeny => "agent-deny",
            Self::AgentExpire => "agent-expire",
            Self::AgentRevoke => "agent-revoke",
            Self::Serve => "serve",
            Self::ServeOff => "serve-off",
            Self::FunnelOn => "funnel-on",
            Self::FunnelOff => "funnel-off",
            Self::LockInit => "lock-init",
            Self::LockSign => "lock-sign",
            Self::LockRotate => "lock-rotate",
            Self::LockRemove => "lock-remove",
            Self::FileReceive => "file-receive",
            Self::FileDeny => "file-deny",
            Self::TokenCreate => "token-create",
            Self::TokenUse => "token-use",
            Self::TokenDeny => "token-deny",
            Self::TokenRevoke => "token-revoke",
            Self::Share => "share",
            Self::Unshare => "unshare",
            Self::PacketDeny => "packet-deny",
            Self::Unrevoke => "unrevoke",
            Self::SinkError => "sink-error",
            Self::RouteFailover => "route-failover",
        }
    }

    /// Parse a stable action token.
    pub fn parse(text: &str) -> Result<Self, AuditError> {
        Self::ALL
            .into_iter()
            .find(|action| action.as_str() == text)
            .ok_or(AuditError::BadKind)
    }

    fn code(self) -> u8 {
        match self {
            Self::PolicyLoad => 1,
            Self::PolicyReplace => 2,
            Self::PolicyReject => 3,
            Self::Approve => 4,
            Self::Revoke => 5,
            Self::Expire => 6,
            Self::Routes => 7,
            Self::ExitNode => 8,
            Self::Enroll => 9,
            Self::AgentGrant => 10,
            Self::AgentApprove => 11,
            Self::AgentUse => 12,
            Self::AgentDeny => 13,
            Self::AgentExpire => 14,
            Self::AgentRevoke => 15,
            Self::Serve => 16,
            Self::ServeOff => 17,
            Self::FunnelOn => 18,
            Self::FunnelOff => 19,
            Self::LockInit => 20,
            Self::LockSign => 21,
            Self::LockRotate => 22,
            Self::LockRemove => 23,
            Self::FileReceive => 24,
            Self::FileDeny => 25,
            Self::TokenCreate => 26,
            Self::TokenUse => 27,
            Self::TokenDeny => 28,
            Self::TokenRevoke => 29,
            Self::Share => 30,
            Self::Unshare => 31,
            Self::PacketDeny => 32,
            Self::Unrevoke => 33,
            Self::SinkError => 34,
            Self::RouteFailover => 35,
        }
    }

    /// Return true for the three policy actions.
    #[must_use]
    pub fn is_policy(self) -> bool {
        matches!(
            self,
            Self::PolicyLoad | Self::PolicyReplace | Self::PolicyReject
        )
    }
}

/// One control-plane change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEvent {
    /// Who made the change.
    ///
    /// An admin change uses the caller SPIFFE ID.
    pub actor: String,
    /// Unix time in seconds (UTC).
    pub at_unix: u64,
    /// The change class.
    pub action: ConfigAction,
    /// The node name or the policy file name.
    pub target: String,
    /// SHA-256 of the state before the change.
    pub before: [u8; 32],
    /// SHA-256 of the state after the change.
    pub after: [u8; 32],
    /// A short note. The note does not hold secrets.
    pub detail: String,
}

/// One linked config record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRecord {
    /// Zero-based position in the chain.
    pub index: u64,
    /// Hash of the previous record.
    pub prev_hash: [u8; 32],
    /// SHA-256 over `prev_hash` and the canonical record bytes.
    pub hash: [u8; 32],
    /// The change.
    pub event: ConfigEvent,
}

impl ConfigRecord {
    /// Encode the record as one JSON line without the line end.
    pub fn to_json_line(&self) -> Result<String, AuditError> {
        serde_json::to_string(&ConfigExport::from_record(self)).map_err(|_| AuditError::Export)
    }
}

/// The result of one successful config chain check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct VerifiedConfig {
    /// The checked records in chain order.
    pub records: Vec<ConfigRecord>,
    /// The hash of the last record.
    pub tip: [u8; 32],
}

impl VerifiedConfig {
    /// Return the tip as lowercase hex.
    #[must_use]
    pub fn tip_hex(&self) -> String {
        encode_hex(&self.tip)
    }
}

/// An append-only config chain in a JSONL file.
#[derive(Debug)]
pub struct ConfigLog {
    path: PathBuf,
    next_index: u64,
    tip: [u8; 32],
    last_policy: Option<[u8; 32]>,
}

impl ConfigLog {
    /// Open the chain file at `path`.
    ///
    /// The function checks the full chain.
    /// A file that fails the check is refused.
    /// An absent file is an empty chain.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let checked = if path.exists() {
            verify_config_file(path)?
        } else {
            VerifiedConfig {
                records: Vec::new(),
                tip: GENESIS_HASH,
            }
        };
        let last_policy = checked
            .records
            .iter()
            .rev()
            .find(|record| {
                matches!(
                    record.event.action,
                    ConfigAction::PolicyLoad | ConfigAction::PolicyReplace
                )
            })
            .map(|record| record.event.after);
        Ok(Self {
            path: path.to_path_buf(),
            next_index: u64::try_from(checked.records.len()).map_err(|_| AuditError::Export)?,
            tip: checked.tip,
            last_policy,
        })
    }

    /// Return the chain file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the number of records.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.next_index
    }

    /// Return true when the chain has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// Return the hash of the last record.
    #[must_use]
    pub fn tip(&self) -> [u8; 32] {
        self.tip
    }

    /// Return the policy digest of the last good policy record.
    #[must_use]
    pub fn last_policy_digest(&self) -> Option<[u8; 32]> {
        self.last_policy
    }

    /// Append one record and flush it to disk.
    pub fn append(&mut self, event: ConfigEvent) -> Result<ConfigRecord, AuditError> {
        check_text(&event.actor, false)?;
        check_text(&event.target, false)?;
        check_text(&event.detail, true)?;
        let prev_hash = self.tip;
        let hash = config_hash(&prev_hash, &event)?;
        let record = ConfigRecord {
            index: self.next_index,
            prev_hash,
            hash,
            event,
        };
        let mut line = record.to_json_line()?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| AuditError::Io(err.to_string()))?;
        file.write_all(line.as_bytes())
            .map_err(|err| AuditError::Io(err.to_string()))?;
        file.sync_all()
            .map_err(|err| AuditError::Io(err.to_string()))?;
        self.next_index = self.next_index.saturating_add(1);
        self.tip = hash;
        if matches!(
            record.event.action,
            ConfigAction::PolicyLoad | ConfigAction::PolicyReplace
        ) {
            self.last_policy = Some(record.event.after);
        }
        Ok(record)
    }
}

/// Return SHA-256 of `bytes`.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Return `digest` as lowercase hex.
#[must_use]
pub fn digest_hex(digest: &[u8; 32]) -> String {
    encode_hex(digest)
}

/// Encode one config event for the hash.
///
/// The layout is version, action code, time, actor, target, before, after, and detail.
/// Each text has a big-endian u16 length before its bytes.
/// The time is big-endian.
pub fn config_canonical_bytes(event: &ConfigEvent) -> Result<Vec<u8>, AuditError> {
    let mut out = Vec::with_capacity(
        2 + 8 + 6 + event.actor.len() + event.target.len() + event.detail.len() + 64,
    );
    out.push(CONFIG_EVENT_VERSION);
    out.push(event.action.code());
    out.extend_from_slice(&event.at_unix.to_be_bytes());
    push_text(&mut out, &event.actor)?;
    push_text(&mut out, &event.target)?;
    out.extend_from_slice(&event.before);
    out.extend_from_slice(&event.after);
    push_text(&mut out, &event.detail)?;
    Ok(out)
}

/// Return SHA-256 over `prev` and the canonical config bytes.
pub fn config_hash(prev: &[u8; 32], event: &ConfigEvent) -> Result<[u8; 32], AuditError> {
    let bytes = config_canonical_bytes(event)?;
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

/// Check a JSONL config chain.
///
/// The function checks the index order, the previous hash, the UTC text, and SHA-256.
pub fn verify_config_jsonl(text: &str) -> Result<VerifiedConfig, AuditError> {
    let mut prev = GENESIS_HASH;
    let mut records = Vec::new();
    for (offset, raw) in text.split('\n').enumerate() {
        let line_no = offset + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let exported: ConfigExport =
            serde_json::from_str(raw).map_err(|_| AuditError::BadLine { line: line_no })?;
        let expect_index = u64::try_from(records.len()).map_err(|_| AuditError::Export)?;
        if exported.index != expect_index {
            return Err(AuditError::BadIndex { line: line_no });
        }
        let record = exported.to_record(line_no)?;
        if record.prev_hash != prev {
            return Err(AuditError::BadLink {
                index: record.index,
            });
        }
        let expect = config_hash(&prev, &record.event)?;
        if record.hash != expect {
            return Err(AuditError::BadHash {
                index: record.index,
            });
        }
        prev = record.hash;
        records.push(record);
    }
    Ok(VerifiedConfig { records, tip: prev })
}

/// Read a JSONL file and check the config chain.
pub fn verify_config_file(path: &Path) -> Result<VerifiedConfig, AuditError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| AuditError::Io(format!("{}: {err}", path.display())))?;
    verify_config_jsonl(&text)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn utc_text(at_unix: u64) -> String {
    let days = at_unix / 86_400;
    let rest = at_unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` as Unix seconds.
pub fn parse_utc_text(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u64> {
        let part = text.get(range)?;
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    if year < 1970
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let value = days * 86_400 + hour * 3600 + minute * 60 + second;
    if utc_text(value) != text {
        return None;
    }
    Some(value)
}

fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // Howard Hinnant civil_from_days, shifted to 0000-03-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn push_text(out: &mut Vec<u8>, text: &str) -> Result<(), AuditError> {
    let len = u16::try_from(text.len()).map_err(|_| AuditError::BadText)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn check_text(text: &str, allow_space: bool) -> Result<(), AuditError> {
    if text.len() > MAX_CONFIG_TEXT {
        return Err(AuditError::BadText);
    }
    if !allow_space && text.is_empty() {
        return Err(AuditError::BadText);
    }
    let ok = text.chars().all(|ch| {
        if ch.is_control() {
            return false;
        }
        allow_space || !ch.is_whitespace()
    });
    if ok {
        Ok(())
    } else {
        Err(AuditError::BadText)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConfigExport {
    index: u64,
    prev_hash: String,
    hash: String,
    at_unix: u64,
    at_utc: String,
    actor: String,
    action: String,
    target: String,
    before: String,
    after: String,
    detail: String,
}

impl ConfigExport {
    fn from_record(record: &ConfigRecord) -> Self {
        Self {
            index: record.index,
            prev_hash: encode_hex(&record.prev_hash),
            hash: encode_hex(&record.hash),
            at_unix: record.event.at_unix,
            at_utc: utc_text(record.event.at_unix),
            actor: record.event.actor.clone(),
            action: record.event.action.as_str().to_string(),
            target: record.event.target.clone(),
            before: encode_hex(&record.event.before),
            after: encode_hex(&record.event.after),
            detail: record.event.detail.clone(),
        }
    }

    fn to_record(&self, line: usize) -> Result<ConfigRecord, AuditError> {
        if utc_text(self.at_unix) != self.at_utc {
            return Err(AuditError::BadLine { line });
        }
        check_text(&self.actor, false).map_err(|_| AuditError::BadLine { line })?;
        check_text(&self.target, false).map_err(|_| AuditError::BadLine { line })?;
        check_text(&self.detail, true).map_err(|_| AuditError::BadLine { line })?;
        let hash32 = |text: &str| -> Result<[u8; 32], AuditError> {
            decode_hex_array::<32>(text).map_err(|_| AuditError::BadLine { line })
        };
        Ok(ConfigRecord {
            index: self.index,
            prev_hash: hash32(&self.prev_hash)?,
            hash: hash32(&self.hash)?,
            event: ConfigEvent {
                actor: self.actor.clone(),
                at_unix: self.at_unix,
                action: ConfigAction::parse(&self.action)
                    .map_err(|_| AuditError::BadLine { line })?,
                target: self.target.clone(),
                before: hash32(&self.before)?,
                after: hash32(&self.after)?,
                detail: self.detail.clone(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W25-13: the SIEM verifier script has the same action codes as the chain.
    #[test]
    fn the_siem_verifier_knows_each_action_code() {
        let script = include_str!("../../../scripts/siem/orblx-siem-verify.py");
        let start = script.find("ACTIONS = [").unwrap();
        let end = start + script[start..].find(']').unwrap();
        let names: Vec<&str> = script[start + "ACTIONS = [".len()..end]
            .split(',')
            .map(|name| name.trim().trim_matches('"'))
            .filter(|name| !name.is_empty())
            .collect();
        assert_eq!(names.len(), ConfigAction::ALL.len());
        for (at, action) in ConfigAction::ALL.iter().enumerate() {
            assert_eq!(usize::from(action.code()), at + 1, "{}", action.as_str());
            assert_eq!(names[at], action.as_str());
        }
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "orblx-config-audit-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn event(action: ConfigAction, at_unix: u64) -> ConfigEvent {
        ConfigEvent {
            actor: "spiffe://orblx.local/node/owner".to_string(),
            at_unix,
            action,
            target: "laptop".to_string(),
            before: sha256_digest(b"before"),
            after: sha256_digest(b"after"),
            detail: format!("detail {}", action.as_str()),
        }
    }

    fn full_chain(dir: &Path) -> (PathBuf, Vec<ConfigRecord>) {
        let path = dir.join("config-audit.jsonl");
        let mut log = ConfigLog::open(&path).unwrap();
        let mut out = Vec::new();
        for (offset, action) in ConfigAction::ALL.into_iter().enumerate() {
            out.push(
                log.append(event(action, 1_793_000_000 + offset as u64))
                    .unwrap(),
            );
        }
        (path, out)
    }

    #[test]
    fn every_record_kind_round_trips_and_verifies() {
        let scratch = Scratch::new("kinds");
        let (path, written) = full_chain(&scratch.0);
        let checked = verify_config_file(&path).unwrap();
        assert_eq!(checked.records, written);
        assert_eq!(checked.records.len(), ConfigAction::ALL.len());
        for (record, action) in checked.records.iter().zip(ConfigAction::ALL) {
            assert_eq!(record.event.action, action);
            assert_eq!(ConfigAction::parse(action.as_str()).unwrap(), action);
            assert_eq!(record.event.actor, "spiffe://orblx.local/node/owner");
            assert_eq!(record.event.before, sha256_digest(b"before"));
            assert_eq!(record.event.after, sha256_digest(b"after"));
        }
        assert_eq!(checked.tip, written.last().unwrap().hash);
        let reopened = ConfigLog::open(&path).unwrap();
        assert_eq!(reopened.len(), ConfigAction::ALL.len() as u64);
        assert_eq!(reopened.tip(), checked.tip);
        assert_eq!(reopened.last_policy_digest(), Some(sha256_digest(b"after")));
    }

    #[test]
    fn each_record_kind_has_its_own_line_and_utc_text() {
        let scratch = Scratch::new("lines");
        let (path, _) = full_chain(&scratch.0);
        let text = std::fs::read_to_string(&path).unwrap();
        for (line, action) in text.lines().zip(ConfigAction::ALL) {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["action"], action.as_str());
            let at_utc = value["at_utc"].as_str().unwrap();
            assert!(at_utc.ends_with('Z'));
            assert_eq!(
                parse_utc_text(at_utc),
                Some(value["at_unix"].as_u64().unwrap())
            );
        }
    }

    #[test]
    fn a_changed_byte_fails_the_check() {
        let scratch = Scratch::new("tamper");
        let (path, _) = full_chain(&scratch.0);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut found = 0;
        for target in ["laptop", "detail approve", "owner"] {
            let at = text.find(target).unwrap();
            let mut bytes = text.clone().into_bytes();
            bytes[at] ^= 0x01;
            let bad = String::from_utf8(bytes).unwrap();
            let err = verify_config_jsonl(&bad).unwrap_err();
            assert!(matches!(err, AuditError::BadHash { .. }), "{err:?}");
            found += 1;
        }
        assert_eq!(found, 3);
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(2);
        let dropped = lines.join("\n");
        assert!(verify_config_jsonl(&dropped).is_err());
        std::fs::write(&path, text.replacen("laptop", "laptoq", 1)).unwrap();
        assert!(ConfigLog::open(&path).is_err());
    }

    #[test]
    fn a_changed_digest_or_time_fails_the_check() {
        let scratch = Scratch::new("digest");
        let (path, written) = full_chain(&scratch.0);
        let text = std::fs::read_to_string(&path).unwrap();
        let after = encode_hex(&written[3].event.after);
        let mut flipped = after.clone().into_bytes();
        flipped[0] = if flipped[0] == b'0' { b'1' } else { b'0' };
        let bad = text.replacen(&after, std::str::from_utf8(&flipped).unwrap(), 1);
        assert!(verify_config_jsonl(&bad).is_err());
        let utc = utc_text(written[0].event.at_unix);
        let bad_time = text.replacen(&utc, &utc_text(written[0].event.at_unix + 1), 1);
        assert!(matches!(
            verify_config_jsonl(&bad_time).unwrap_err(),
            AuditError::BadLine { line: 1 }
        ));
    }

    #[test]
    fn append_refuses_bad_text() {
        let scratch = Scratch::new("text");
        let mut log = ConfigLog::open(&scratch.0.join("c.jsonl")).unwrap();
        let mut bad = event(ConfigAction::Approve, 1);
        bad.actor = "two words".to_string();
        assert_eq!(log.append(bad).unwrap_err(), AuditError::BadText);
        let mut bad = event(ConfigAction::Approve, 1);
        bad.detail = "line\nbreak".to_string();
        assert_eq!(log.append(bad).unwrap_err(), AuditError::BadText);
        assert!(log.is_empty());
    }

    #[test]
    fn utc_text_matches_known_values() {
        assert_eq!(utc_text(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_text(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_text(1_793_318_399), "2026-10-29T23:59:59Z");
        assert_eq!(parse_utc_text("2026-10-29T23:59:59Z"), Some(1_793_318_399));
        assert_eq!(parse_utc_text("2026-02-30T00:00:00Z"), None);
    }
}
