use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use orblx_audit::verify_config_file;
use orblx_identity::{DenySet, MiniCa, SpiffeId};

use super::*;

struct Lab {
    dir: PathBuf,
    ca: MiniCa,
    addr: SocketAddr,
    inbox: PathBuf,
    audit: PathBuf,
}

fn scratch(tag: &str) -> PathBuf {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    let dir = std::env::temp_dir().join(format!("orblx-file-{tag}-{}", hex(&bytes)));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn identity(ca: &MiniCa, name: &str) -> SendIdentity {
    let id = SpiffeId::node(name).unwrap();
    let issued = ca
        .issue(
            &id,
            SystemTime::now(),
            Duration::from_secs(600),
            &DenySet::empty(),
        )
        .unwrap();
    SendIdentity::from_pem(&issued.certificate_pem, &issued.private_key_pem).unwrap()
}

fn lab(tag: &str, allowed: &'static [&'static str]) -> Lab {
    let dir = scratch(tag);
    let ca = MiniCa::generate(SystemTime::now()).unwrap();
    let inbox = dir.join("inbox");
    let audit = dir.join(FILE_AUDIT_FILE);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = ReceiverConfig {
        self_id: SpiffeId::node("b").unwrap(),
        inbox: inbox.clone(),
        audit_path: audit.clone(),
        max_bytes: 1 << 20,
    };
    let bundle = ca.trust_bundle().clone();
    thread::spawn(move || {
        let _ = serve(listener, config, move || {
            Ok(Gate {
                bundle: bundle.clone(),
                deny: DenySet::empty(),
                permits: Box::new(|src: &SpiffeId| allowed.contains(&src.name())),
            })
        });
    });
    for _ in 0..50 {
        if inbox.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    Lab {
        dir,
        ca,
        addr,
        inbox,
        audit,
    }
}

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn inbox_names(inbox: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(inbox)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn wait_records(path: &Path, count: u64) -> String {
    for _ in 0..100 {
        if let Ok(checked) = verify_config_file(path) {
            if checked.records.len() as u64 >= count {
                return fs::read_to_string(path).unwrap();
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("the audit chain did not get {count} records");
}

fn dst() -> SpiffeId {
    SpiffeId::node("b").unwrap()
}

#[test]
fn allowed_sender_stores_the_same_digest_and_audits_it() {
    let lab = lab("ok", &["a"]);
    let body: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
    let src = write_file(&lab.dir, "src.bin", &body);
    let sender = identity(&lab.ca, "a");
    let report = send_file(
        lab.addr,
        &dst(),
        &sender,
        &src,
        "report.bin",
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(report.size, body.len() as u64);
    let stored = fs::read(lab.inbox.join("report.bin")).unwrap();
    assert_eq!(stored, body);
    assert_eq!(
        digest_file(&lab.inbox.join("report.bin")).unwrap().1,
        digest_file(&src).unwrap().1
    );
    assert_eq!(inbox_names(&lab.inbox), vec!["report.bin".to_string()]);
    let text = wait_records(&lab.audit, 1);
    assert!(text.contains("\"file-receive\""));
    assert!(text.contains("spiffe://orblx.local/node/a"));
    assert!(text.contains(&report.sha256));
    assert!(text.contains(&format!("size {}", body.len())));
    // The same name again is refused and the first file stays.
    let again = send_file(
        lab.addr,
        &dst(),
        &sender,
        &src,
        "report.bin",
        Duration::from_secs(5),
    );
    assert!(again.unwrap_err().0.contains("deny exists"));
    assert_eq!(fs::read(lab.inbox.join("report.bin")).unwrap(), body);
}

#[test]
fn denied_sender_leaves_no_file_and_is_audited() {
    let lab = lab("deny", &["a"]);
    let src = write_file(&lab.dir, "src.bin", b"secret plan");
    let sender = identity(&lab.ca, "c");
    let err = send_file(
        lab.addr,
        &dst(),
        &sender,
        &src,
        "plan.txt",
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(err.0.contains("deny acl"), "{err}");
    assert!(inbox_names(&lab.inbox).is_empty());
    let text = wait_records(&lab.audit, 1);
    assert!(text.contains("\"file-deny\""));
    assert!(text.contains("spiffe://orblx.local/node/c"));
    assert!(text.contains("reason acl"));
}

#[test]
fn offer_for_another_receiver_fails_the_signature() {
    let lab = lab("dst", &["a"]);
    let src = write_file(&lab.dir, "src.bin", b"x");
    let sender = identity(&lab.ca, "a");
    let other = SpiffeId::node("z").unwrap();
    let err = send_file(
        lab.addr,
        &other,
        &sender,
        &src,
        "x.txt",
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(err.0.contains("deny signature"), "{err}");
    assert!(inbox_names(&lab.inbox).is_empty());
}

#[test]
fn foreign_ca_leaf_is_refused() {
    let lab = lab("ca", &["a"]);
    let other_ca = MiniCa::generate(SystemTime::now()).unwrap();
    let src = write_file(&lab.dir, "src.bin", b"x");
    let sender = identity(&other_ca, "a");
    let err = send_file(
        lab.addr,
        &dst(),
        &sender,
        &src,
        "x.txt",
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(err.0.contains("deny identity"), "{err}");
    assert!(inbox_names(&lab.inbox).is_empty());
}

fn raw_send(lab: &Lab, offer: &Offer, body: &[u8]) -> (String, String) {
    let sender = identity(&lab.ca, "a");
    let header = encode_offer(&sender, &dst(), offer, SystemTime::now()).unwrap();
    let mut stream = TcpStream::connect(lab.addr).unwrap();
    stream.write_all(&header).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    stream.write_all(body).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut last = String::new();
    let _ = reader.read_line(&mut last);
    (first.trim().to_string(), last.trim().to_string())
}

#[test]
fn digest_mismatch_and_short_body_leave_no_part_file() {
    let lab = lab("bad", &["a"]);
    let bad = Offer {
        name: "bad.bin".to_string(),
        size: 4,
        sha256: [7u8; 32],
    };
    let (first, last) = raw_send(&lab, &bad, b"abcd");
    assert_eq!(first, "ok");
    assert_eq!(last, "fail digest");
    let short = Offer {
        name: "short.bin".to_string(),
        size: 10,
        sha256: [0u8; 32],
    };
    let (first, last) = raw_send(&lab, &short, b"abc");
    assert_eq!(first, "ok");
    assert_eq!(last, "fail short");
    assert!(inbox_names(&lab.inbox).is_empty());
    let text = wait_records(&lab.audit, 2);
    assert!(text.contains("reason digest"));
    assert!(text.contains("reason short"));
}

#[test]
fn bad_names_and_large_files_are_refused() {
    assert!(name_ok("report-1.tar.gz"));
    for name in ["", ".", "..", "../x", "a/b", ".orblx-part-x", "a b", "x\n"] {
        assert!(!name_ok(name), "{name:?}");
    }
    let lab = lab("size", &["a"]);
    let big = Offer {
        name: "big.bin".to_string(),
        size: (1 << 20) + 1,
        sha256: [0u8; 32],
    };
    let (first, _) = raw_send(&lab, &big, b"");
    assert_eq!(first, "deny size");
    assert!(inbox_names(&lab.inbox).is_empty());
}

#[test]
fn identity_debug_hides_the_key() {
    let ca = MiniCa::generate(SystemTime::now()).unwrap();
    let text = format!("{:?}", identity(&ca, "a"));
    assert!(text.starts_with("SendIdentity"));
    assert!(!text.contains("signing"));
}
