use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use gyeol_audit::{
    escape_demo, verify_file, verify_jsonl, AuditLog, DenyReason, EventKind, SessionEvent,
    SessionIds, SessionMetrics, DEMO_DENY_FRAME, DEMO_DENY_PEER, DEMO_OK_FRAME, DEMO_OK_PEER,
    GENESIS_HASH,
};
use gyeol_identity::{ticket_hash, SpiffeId};
use gyeol_relay::RelaySessionId;
use sha2::{Digest, Sha256};

#[test]
fn escape_tip_is_stable() {
    let log = escape_demo();
    assert_eq!(
        log.tip_hex(),
        "7292992ea22a6755b81526c80ae3adfdf601a8753c3a4303b9a3f8509b552e92"
    );
}

#[test]
fn escape_demo_links_one_deny_and_one_session() {
    let log = escape_demo();
    let records = log.records();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].prev_hash, GENESIS_HASH);
    assert_eq!(records[0].event.kind(), EventKind::Deny);
    assert_eq!(records[0].event.reason(), Some(DenyReason::Destination));
    assert_eq!(records[0].event.ids().peer.as_uri(), DEMO_DENY_PEER);
    assert_eq!(records[0].event.ids().frame, DEMO_DENY_FRAME);
    assert_eq!(records[1].prev_hash, records[0].hash);
    assert_eq!(records[1].event.kind(), EventKind::Start);
    assert_eq!(records[1].event.ids().peer.as_uri(), DEMO_OK_PEER);
    assert_eq!(records[1].event.ids().frame, DEMO_OK_FRAME);
    assert_eq!(records[2].prev_hash, records[1].hash);
    assert_eq!(records[2].event.kind(), EventKind::End);
    assert_eq!(records[2].event.ids().relay, records[1].event.ids().relay);
    assert_eq!(
        log.metrics(),
        SessionMetrics {
            start: 1,
            end: 1,
            deny: 1,
        }
    );
}

#[test]
fn hash_is_sha256_of_previous_hash_and_event_bytes() {
    let log = escape_demo();
    for record in log.records() {
        let bytes = gyeol_audit::canonical_bytes(&record.event).expect("the event encodes");
        assert_eq!(bytes[0], gyeol_audit::EVENT_VERSION);
        let mut hasher = Sha256::new();
        hasher.update(record.prev_hash);
        hasher.update(&bytes);
        let digest = hasher.finalize();
        assert_eq!(digest.as_slice(), &record.hash);
    }
}

#[test]
fn file_round_trip_verifies_without_the_datapath() {
    let log = escape_demo();
    let path = temp_chain("round");
    log.write_jsonl(&path)
        .expect("the chain file was not written");
    let text = fs::read_to_string(&path).expect("the chain file was not read");
    let checked = verify_jsonl(&text).expect("the chain text failed the check");
    let from_file = verify_file(&path).expect("the chain file failed the check");
    assert_eq!(checked, from_file);
    assert_eq!(from_file.metrics, log.metrics());
    assert_eq!(from_file.records, 3);
    assert_eq!(from_file.tip, log.tip());
    fs::remove_file(&path).expect("the chain file was not removed");
}

#[test]
fn a_changed_peer_fails_the_hash_check() {
    let log = escape_demo();
    let path = temp_chain("tamper");
    log.write_jsonl(&path)
        .expect("the chain file was not written");
    let text = fs::read_to_string(&path).expect("the chain file was not read");
    let bad = text.replace(DEMO_DENY_PEER, "spiffe://gyeol.local/agent/others");
    assert_ne!(text, bad);
    fs::write(&path, bad).expect("the chain file was not changed");
    let err = verify_file(&path).expect_err("a changed peer passed the check");
    assert_eq!(err, gyeol_audit::AuditError::BadHash { index: 0 });
    fs::remove_file(&path).expect("the chain file was not removed");
}

#[test]
fn a_broken_link_fails_the_check() {
    let text = escape_demo().export_jsonl().expect("the export failed");
    let mut rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("the line is json"))
        .collect();
    rows[1]["prev_hash"] = serde_json::Value::String("0".repeat(64));
    let broken = rows
        .iter()
        .map(|row| serde_json::to_string(row).expect("the row encodes"))
        .collect::<Vec<_>>()
        .join("\n");
    let err = verify_jsonl(&broken).expect_err("a broken link passed the check");
    assert_eq!(err, gyeol_audit::AuditError::BadLink { index: 1 });
}

#[test]
fn empty_chain_has_zero_counters() {
    let checked = verify_jsonl("").expect("an empty chain failed the check");
    assert_eq!(checked.records, 0);
    assert_eq!(checked.tip, GENESIS_HASH);
    assert_eq!(checked.metrics, SessionMetrics::default());
    assert_eq!(checked.metrics, AuditLog::new().metrics());
}

#[test]
fn uppercase_tip_fails_the_hash_check() {
    let text = escape_demo().export_jsonl().expect("the export failed");
    let tip = escape_demo().tip_hex();
    let bad = text.replace(&tip, &tip.to_ascii_uppercase());
    assert_ne!(text, bad);
    let err = verify_jsonl(&bad).expect_err("an uppercase hash passed the check");
    assert_eq!(err, gyeol_audit::AuditError::BadHash { index: 2 });
}

#[test]
fn custom_ids_use_relay_session_and_spiffe() {
    let mut log = AuditLog::new();
    let ids = SessionIds {
        relay: RelaySessionId::from_bytes([0x42; 16]),
        frame: 9,
        peer: SpiffeId::agent("probe").expect("the peer name is valid"),
        ticket_hash: ticket_hash(b"probe-ticket"),
    };
    log.append(SessionEvent::Deny {
        ids: ids.clone(),
        at_unix: 10,
        reason: DenyReason::Revoked,
    })
    .expect("the deny append failed");
    log.append(SessionEvent::Start {
        ids: ids.clone(),
        at_unix: 11,
    })
    .expect("the start append failed");
    log.append(SessionEvent::End { ids, at_unix: 12 })
        .expect("the end append failed");
    let checked = verify_jsonl(&log.export_jsonl().expect("the export failed"))
        .expect("the custom chain failed the check");
    assert_eq!(
        checked.metrics,
        SessionMetrics {
            start: 1,
            end: 1,
            deny: 1,
        }
    );
    assert_eq!(checked.records, 3);
}

fn temp_chain(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is valid")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "orblx-w10-{label}-{}-{nanos}.jsonl",
        std::process::id()
    ))
}
