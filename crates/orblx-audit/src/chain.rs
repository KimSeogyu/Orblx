use std::path::Path;

use orblx_identity::SpiffeId;
use orblx_relay::RelaySessionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event::{DenyReason, EventKind, SessionEvent, SessionIds};
use crate::hexutil::{decode_hex_array, encode_hex};
use crate::metrics::SessionMetrics;
use crate::AuditError;

/// Canonical event version.
pub const EVENT_VERSION: u8 = 1;

/// The previous hash of the first record.
///
/// The value is 32 zero bytes.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// One linked record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRecord {
    /// Zero-based position in the chain.
    pub index: u64,
    /// Hash of the previous record.
    ///
    /// The first record uses `GENESIS_HASH`.
    pub prev_hash: [u8; 32],
    /// SHA-256 over `prev_hash` and the canonical event bytes.
    pub hash: [u8; 32],
    /// The session event.
    pub event: SessionEvent,
}

/// The result of one successful chain check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct VerifiedChain {
    /// Counters from the checked records.
    pub metrics: SessionMetrics,
    /// The number of records.
    pub records: u64,
    /// The hash of the last record.
    ///
    /// An empty chain uses `GENESIS_HASH`.
    pub tip: [u8; 32],
}

impl VerifiedChain {
    /// Return the tip as lowercase hex.
    #[must_use]
    pub fn tip_hex(&self) -> String {
        encode_hex(&self.tip)
    }
}

/// An append-only session hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct AuditLog {
    records: Vec<ChainRecord>,
    metrics: SessionMetrics,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    /// Create an empty chain.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            metrics: SessionMetrics::default(),
        }
    }

    /// Append one event.
    ///
    /// The new hash is SHA-256 over the previous hash and the event bytes.
    pub fn append(&mut self, event: SessionEvent) -> Result<&ChainRecord, AuditError> {
        let index = u64::try_from(self.records.len()).map_err(|_| AuditError::Export)?;
        let prev_hash = self.tip();
        let hash = event_hash(&prev_hash, &event)?;
        self.metrics.observe(event.kind());
        self.records.push(ChainRecord {
            index,
            prev_hash,
            hash,
            event,
        });
        let stored = self.records.len() - 1;
        Ok(&self.records[stored])
    }

    /// Return the records in chain order.
    #[must_use]
    pub fn records(&self) -> &[ChainRecord] {
        &self.records
    }

    /// Return the live counters.
    pub fn metrics(&self) -> SessionMetrics {
        self.metrics
    }

    /// Return the hash of the last record.
    #[must_use]
    pub fn tip(&self) -> [u8; 32] {
        self.records
            .last()
            .map(|record| record.hash)
            .unwrap_or(GENESIS_HASH)
    }

    /// Return the tip as lowercase hex.
    #[must_use]
    pub fn tip_hex(&self) -> String {
        encode_hex(&self.tip())
    }

    /// Encode the chain as JSONL.
    ///
    /// Each line is one record.
    /// The line ends with `\n`.
    pub fn export_jsonl(&self) -> Result<String, AuditError> {
        let mut out = String::new();
        for record in &self.records {
            let line =
                serde_json::to_string(&export_record(record)).map_err(|_| AuditError::Export)?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// Write the JSONL export to `path`.
    pub fn write_jsonl(&self, path: &Path) -> Result<(), AuditError> {
        let text = self.export_jsonl()?;
        std::fs::write(path, text).map_err(|err| AuditError::Io(err.to_string()))
    }
}

/// Encode one event for the hash.
///
/// The layout is version, kind, time, Relay session id, frame session id,
/// peer length, peer bytes, ticket hash, reason length, and reason bytes.
/// A record event then adds the file length, the file bytes, and the 32-byte SHA-256.
/// Lengths and the time are big-endian.
pub fn canonical_bytes(event: &SessionEvent) -> Result<Vec<u8>, AuditError> {
    let ids = event.ids();
    let peer = ids.peer.as_uri().as_bytes();
    let reason = event.reason().map(DenyReason::as_str).unwrap_or("");
    let reason_bytes = reason.as_bytes();
    let peer_len = u16::try_from(peer.len()).map_err(|_| AuditError::BadPeer)?;
    let reason_len = u16::try_from(reason_bytes.len()).map_err(|_| AuditError::BadReason)?;
    let mut out = Vec::with_capacity(2 + 8 + 16 + 4 + 2 + peer.len() + 16 + 2 + reason_bytes.len());
    out.push(EVENT_VERSION);
    out.push(event.kind().code());
    out.extend_from_slice(&event.at_unix().to_be_bytes());
    out.extend_from_slice(ids.relay.as_bytes());
    out.extend_from_slice(&ids.frame.to_be_bytes());
    out.extend_from_slice(&peer_len.to_be_bytes());
    out.extend_from_slice(peer);
    out.extend_from_slice(&ids.ticket_hash);
    out.extend_from_slice(&reason_len.to_be_bytes());
    out.extend_from_slice(reason_bytes);
    if let Some((file, sha256)) = event.recording() {
        let file_len = u16::try_from(file.len()).map_err(|_| AuditError::BadText)?;
        out.extend_from_slice(&file_len.to_be_bytes());
        out.extend_from_slice(file.as_bytes());
        out.extend_from_slice(sha256);
    }
    Ok(out)
}

/// Return SHA-256 over `prev` and the canonical event bytes.
pub fn event_hash(prev: &[u8; 32], event: &SessionEvent) -> Result<[u8; 32], AuditError> {
    let bytes = canonical_bytes(event)?;
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

/// Check a JSONL chain.
///
/// The function rebuilds each event.
/// The function checks the index order.
/// The function checks the previous hash.
/// The function checks SHA-256.
/// The counters come from the checked events.
pub fn verify_jsonl(text: &str) -> Result<VerifiedChain, AuditError> {
    let mut metrics = SessionMetrics::default();
    let mut prev = GENESIS_HASH;
    let mut count = 0u64;
    for (offset, raw) in text.lines().enumerate() {
        let line_no = offset + 1;
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let exported: ExportRecord =
            serde_json::from_str(raw).map_err(|_| AuditError::BadLine { line: line_no })?;
        if exported.index != count {
            return Err(AuditError::BadIndex { line: line_no });
        }
        let event = event_from_export(&exported)?;
        let got_prev = decode_hash(
            &exported.prev_hash,
            AuditError::BadLink {
                index: exported.index,
            },
        )?;
        if got_prev != prev {
            return Err(AuditError::BadLink {
                index: exported.index,
            });
        }
        let got_hash = decode_hash(
            &exported.hash,
            AuditError::BadHash {
                index: exported.index,
            },
        )?;
        let expect = event_hash(&prev, &event)?;
        if got_hash != expect {
            return Err(AuditError::BadHash {
                index: exported.index,
            });
        }
        metrics.observe(event.kind());
        prev = got_hash;
        count = count.saturating_add(1);
    }
    Ok(VerifiedChain {
        metrics,
        records: count,
        tip: prev,
    })
}

/// Read a JSONL file and check the chain.
///
/// The function also reads each recording that a record event names.
/// The path is relative to the chain file directory.
/// The SHA-256 of the file must match the SHA-256 in the chain.
pub fn verify_file(path: &Path) -> Result<VerifiedChain, AuditError> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| AuditError::Io(format!("{}: {err}", path.display())))?;
    let checked = verify_jsonl(&text)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    for raw in text.lines() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let exported: ExportRecord = serde_json::from_str(raw).map_err(|_| AuditError::Export)?;
        let event = event_from_export(&exported)?;
        if let Some((file, sha256)) = event.recording() {
            verify_recording(base, exported.index, file, sha256)?;
        }
    }
    Ok(checked)
}

/// Return true when `file` is a plain relative path with no `..` part.
#[must_use]
pub fn recording_path_ok(file: &str) -> bool {
    let path = Path::new(file);
    !file.is_empty()
        && path
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
}

fn verify_recording(
    base: &Path,
    index: u64,
    file: &str,
    sha256: &[u8; 32],
) -> Result<(), AuditError> {
    if !recording_path_ok(file) {
        return Err(AuditError::BadRecordingPath { index });
    }
    let bytes = std::fs::read(base.join(file)).map_err(|_| AuditError::BadRecording { index })?;
    let digest = Sha256::digest(&bytes);
    if digest.as_slice() != sha256.as_slice() {
        return Err(AuditError::BadRecording { index });
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExportRecord {
    index: u64,
    prev_hash: String,
    hash: String,
    kind: String,
    at_unix: u64,
    relay_session: String,
    frame_session: u32,
    peer: String,
    ticket_hash: String,
    reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    recording: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    recording_sha256: String,
}

fn export_record(record: &ChainRecord) -> ExportRecord {
    let ids = record.event.ids();
    let reason = record
        .event
        .reason()
        .map(DenyReason::as_str)
        .unwrap_or("")
        .to_string();
    let (recording, recording_sha256) = match record.event.recording() {
        Some((file, sha256)) => (file.to_string(), encode_hex(sha256)),
        None => (String::new(), String::new()),
    };
    ExportRecord {
        index: record.index,
        prev_hash: encode_hex(&record.prev_hash),
        hash: encode_hex(&record.hash),
        kind: record.event.kind().as_str().to_string(),
        at_unix: record.event.at_unix(),
        relay_session: ids.relay.to_hex(),
        frame_session: ids.frame,
        peer: ids.peer.as_uri().to_string(),
        ticket_hash: encode_hex(&ids.ticket_hash),
        reason,
        recording,
        recording_sha256,
    }
}

fn event_from_export(row: &ExportRecord) -> Result<SessionEvent, AuditError> {
    let relay_bytes =
        decode_hex_array::<16>(&row.relay_session).map_err(|_| AuditError::BadSession)?;
    let ids = SessionIds {
        relay: RelaySessionId::from_bytes(relay_bytes),
        frame: row.frame_session,
        peer: SpiffeId::parse(&row.peer).map_err(|_| AuditError::BadPeer)?,
        ticket_hash: decode_hex_array::<16>(&row.ticket_hash)?,
    };
    let at_unix = row.at_unix;
    let kind = EventKind::from_str(&row.kind)?;
    if kind != EventKind::Record && !(row.recording.is_empty() && row.recording_sha256.is_empty()) {
        return Err(AuditError::BadText);
    }
    match kind {
        EventKind::Start => {
            require_empty_reason(&row.reason)?;
            Ok(SessionEvent::Start { ids, at_unix })
        }
        EventKind::End => {
            require_empty_reason(&row.reason)?;
            Ok(SessionEvent::End { ids, at_unix })
        }
        EventKind::Deny => Ok(SessionEvent::Deny {
            ids,
            at_unix,
            reason: DenyReason::parse(&row.reason)?,
        }),
        EventKind::Record => {
            require_empty_reason(&row.reason)?;
            Ok(SessionEvent::Record {
                ids,
                at_unix,
                file: row.recording.clone(),
                sha256: decode_hex_array::<32>(&row.recording_sha256)
                    .map_err(|_| AuditError::BadText)?,
            })
        }
    }
}

fn require_empty_reason(reason: &str) -> Result<(), AuditError> {
    if reason.is_empty() {
        Ok(())
    } else {
        Err(AuditError::BadReason)
    }
}

fn decode_hash(text: &str, err: AuditError) -> Result<[u8; 32], AuditError> {
    decode_hex_array::<32>(text).map_err(|_| err)
}
