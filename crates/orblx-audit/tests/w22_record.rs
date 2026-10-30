//! A record event links one recording file to the chain.

use std::fs;

use orblx_audit::{verify_file, AuditError, AuditLog, SessionEvent, SessionIds};
use orblx_identity::SpiffeId;
use sha2::{Digest, Sha256};

fn ids() -> SessionIds {
    SessionIds::receiver_acl(SpiffeId::user("alice").unwrap(), 4, [0u8; 16])
}

fn chain_with_recording(dir: &std::path::Path, file: &str, body: &[u8]) -> std::path::PathBuf {
    fs::create_dir_all(dir.join("recordings")).unwrap();
    fs::write(dir.join(file), body).unwrap();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&Sha256::digest(body));
    let mut log = AuditLog::new();
    log.append(SessionEvent::Start {
        ids: ids(),
        at_unix: 10,
    })
    .unwrap();
    log.append(SessionEvent::Record {
        ids: ids(),
        at_unix: 11,
        file: file.to_string(),
        sha256,
    })
    .unwrap();
    log.append(SessionEvent::End {
        ids: ids(),
        at_unix: 12,
    })
    .unwrap();
    let path = dir.join("ssh-audit.jsonl");
    log.write_jsonl(&path).unwrap();
    path
}

#[test]
fn verify_checks_the_recording_and_fails_after_one_changed_byte() {
    let dir = std::env::temp_dir().join(format!("orblx-w22-record-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let file = "recordings/ssh-1-4.cast";
    let path = chain_with_recording(&dir, file, b"{\"version\":2}\n[0.0,\"o\",\"hi\"]\n");
    let checked = verify_file(&path).unwrap();
    assert_eq!(checked.metrics.start, 1);
    assert_eq!(checked.metrics.record, 1);
    assert_eq!(checked.metrics.end, 1);
    assert_eq!(checked.records, 3);

    let mut bytes = fs::read(dir.join(file)).unwrap();
    bytes[3] ^= 0x01;
    fs::write(dir.join(file), &bytes).unwrap();
    assert_eq!(
        verify_file(&path).unwrap_err(),
        AuditError::BadRecording { index: 1 }
    );

    fs::remove_file(dir.join(file)).unwrap();
    assert_eq!(
        verify_file(&path).unwrap_err(),
        AuditError::BadRecording { index: 1 }
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_changed_recording_hash_in_the_chain_fails_the_link_check() {
    let dir = std::env::temp_dir().join(format!("orblx-w22-record-hash-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let file = "recordings/ssh-2-4.cast";
    let path = chain_with_recording(&dir, file, b"{\"version\":2}\n");
    let text = fs::read_to_string(&path).unwrap();
    let line = text.lines().nth(1).unwrap();
    let start = line.find("\"recording_sha256\":\"").unwrap() + 20;
    let old = &line[start..start + 1];
    let new = if old == "0" { "1" } else { "0" };
    let changed_line = format!("{}{new}{}", &line[..start], &line[start + 1..]);
    fs::write(&path, text.replacen(line, &changed_line, 1)).unwrap();
    assert_eq!(
        verify_file(&path).unwrap_err(),
        AuditError::BadHash { index: 1 }
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_recording_path_outside_the_chain_directory_is_refused() {
    assert!(orblx_audit::recording_path_ok("recordings/ssh-1-1.cast"));
    assert!(!orblx_audit::recording_path_ok("../key.pem"));
    assert!(!orblx_audit::recording_path_ok("/etc/passwd"));
    assert!(!orblx_audit::recording_path_ok(""));
}
