use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gyeol_identity::{
    decode_certificate_pem, decode_certificate_pem_file, extract_spiffe_id, DenySet, IdentityError,
    IssuedSvid, MiniCa, SpiffeId, TrustBundle, MAX_USER_TTL,
};

fn fixed_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is valid")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("orblx-w12-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("the temp directory was not created");
    dir
}

#[test]
fn fixture_pem_files_match_the_memory_decode() {
    let leaf_path = fixture("user-svid.pem");
    let leaf = decode_certificate_pem_file(&leaf_path).expect("the leaf PEM file did not load");
    let leaf_text = include_str!("../fixtures/user-svid.pem");
    assert_eq!(leaf, decode_certificate_pem(leaf_text).unwrap());
    let id = extract_spiffe_id(&leaf).unwrap();
    assert_eq!(id.as_uri(), "spiffe://gyeol.local/user/seogyu-dev");

    let bundle_path = fixture("trust-bundle.pem");
    let bundle = TrustBundle::from_pem_file(&bundle_path).expect("the trust bundle did not load");
    let memory = TrustBundle::from_pem(include_str!("../fixtures/trust-bundle.pem")).unwrap();
    assert_eq!(bundle, memory);
    let fixture_now = UNIX_EPOCH + Duration::from_secs(1_793_196_196);
    let authed = bundle
        .authenticate_leaf(&leaf, fixture_now, &DenySet::empty())
        .unwrap();
    assert_eq!(authed, id);

    let ca_path = fixture("ca.pem");
    let from_file = TrustBundle::from_pem_file(&ca_path).expect("the CA PEM file did not load");
    let from_text = TrustBundle::from_pem(include_str!("../fixtures/ca.pem")).unwrap();
    assert_eq!(from_file, from_text);
    let ca_der = decode_certificate_pem_file(&ca_path).expect("the CA certificate did not load");
    assert_eq!(
        ca_der,
        decode_certificate_pem(include_str!("../fixtures/ca.pem")).unwrap()
    );
}

#[test]
fn issued_svid_round_trip_reads_the_pem_files() {
    let now = fixed_now();
    let ca = MiniCa::generate(now).unwrap();
    let id = SpiffeId::user("seogyu-dev").unwrap();
    let issued = ca
        .issue(&id, now, MAX_USER_TTL, &DenySet::empty())
        .expect("the leaf was not issued");
    let dir = temp_dir("round-trip");
    let cert_path = dir.join("leaf.pem");
    let key_path = dir.join("leaf-key.pem");
    let bundle_path = dir.join("trust-bundle.pem");
    fs::write(&cert_path, &issued.certificate_pem).expect("the leaf file was not written");
    fs::write(&key_path, &issued.private_key_pem).expect("the key file was not written");
    fs::write(&bundle_path, ca.trust_bundle_pem()).expect("the bundle file was not written");

    let loaded =
        IssuedSvid::from_pem_files(&cert_path, &key_path).expect("the leaf files did not load");
    let memory = IssuedSvid::from_pem(&issued.certificate_pem, &issued.private_key_pem).unwrap();
    assert_eq!(loaded.spiffe_id, issued.spiffe_id);
    assert_eq!(loaded.spiffe_id, memory.spiffe_id);
    assert_eq!(loaded.certificate_pem, issued.certificate_pem);
    assert_eq!(loaded.certificate_der, issued.certificate_der);
    assert_eq!(loaded.certificate_der, memory.certificate_der);
    assert_eq!(loaded.private_key_pem, issued.private_key_pem);
    assert_eq!(loaded.not_before, issued.not_before);
    assert_eq!(loaded.not_after, issued.not_after);
    assert_eq!(
        decode_certificate_pem_file(&cert_path).unwrap(),
        issued.certificate_der
    );
    let bundle = TrustBundle::from_pem_file(&bundle_path).unwrap();
    assert_eq!(bundle, ca.trust_bundle().clone());
    let authed = bundle
        .authenticate_leaf(&loaded.certificate_der, now, &DenySet::empty())
        .unwrap();
    assert_eq!(authed, issued.spiffe_id);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_private_key_must_match_the_leaf() {
    let now = fixed_now();
    let ca = MiniCa::generate(now).unwrap();
    let first = ca
        .issue(
            &SpiffeId::user("seogyu-dev").unwrap(),
            now,
            MAX_USER_TTL,
            &DenySet::empty(),
        )
        .unwrap();
    let second = ca
        .issue(
            &SpiffeId::user("other-user").unwrap(),
            now,
            MAX_USER_TTL,
            &DenySet::empty(),
        )
        .unwrap();
    assert_eq!(
        IssuedSvid::from_pem(&first.certificate_pem, &second.private_key_pem).unwrap_err(),
        IdentityError::Certificate
    );

    let dir = temp_dir("mismatch");
    let cert_path = dir.join("leaf.pem");
    let key_path = dir.join("other-key.pem");
    fs::write(&cert_path, &first.certificate_pem).unwrap();
    fs::write(&key_path, &second.private_key_pem).unwrap();
    assert_eq!(
        IssuedSvid::from_pem_files(&cert_path, &key_path).unwrap_err(),
        IdentityError::Certificate
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn missing_pem_files_return_file_error() {
    let missing = fixture("missing-svid.pem");
    assert!(!missing.exists());
    assert_eq!(
        decode_certificate_pem_file(&missing).unwrap_err(),
        IdentityError::File
    );
    assert_eq!(
        TrustBundle::from_pem_file(&missing).unwrap_err(),
        IdentityError::File
    );
    assert_eq!(
        IssuedSvid::from_pem_files(&missing, &fixture("user-svid.pem")).unwrap_err(),
        IdentityError::File
    );
    assert_eq!(
        IssuedSvid::from_pem_files(&fixture("user-svid.pem"), &missing).unwrap_err(),
        IdentityError::File
    );
    assert_eq!(IdentityError::File.to_string(), "The file read failed.");
}

#[test]
fn bad_pem_files_return_certificate_error() {
    let bad = fixture("bad.pem");
    assert_eq!(
        decode_certificate_pem_file(&bad).unwrap_err(),
        IdentityError::Certificate
    );
    assert_eq!(
        TrustBundle::from_pem_file(&bad).unwrap_err(),
        IdentityError::Certificate
    );
    assert_eq!(
        IssuedSvid::from_pem_files(&bad, &bad).unwrap_err(),
        IdentityError::Certificate
    );
    assert_eq!(
        IssuedSvid::from_pem_files(&fixture("user-svid.pem"), &bad).unwrap_err(),
        IdentityError::Certificate
    );
}

#[test]
fn invalid_utf8_returns_file_error() {
    let dir = temp_dir("utf8");
    let path = dir.join("cert.pem");
    fs::write(&path, [0xff, 0xfe]).expect("the byte file was not written");
    assert_eq!(
        decode_certificate_pem_file(&path).unwrap_err(),
        IdentityError::File
    );
    assert_eq!(
        TrustBundle::from_pem_file(&path).unwrap_err(),
        IdentityError::File
    );
    let _ = fs::remove_dir_all(&dir);
}
