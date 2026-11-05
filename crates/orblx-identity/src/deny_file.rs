//! The deny file of a node state directory (W25-38).
//!
//! The node fails closed. An enrolled node refuses SSH logins, file receive, and new
//! sessions when `deny.json` is not valid, does not open, or is missing. A node that
//! was never enrolled (no `node-name` file) and has no `deny.json` uses an empty set.
//! That is the behavior of a lab node from `orblx issue`.
//!
//! The writer installs `deny.json` with an atomic rename. It writes a temp file in the
//! same directory, syncs the file, renames it, and syncs the directory. A crash during
//! the write leaves the old file, and the reader never sees a part file.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;

use crate::codec::decode_hex_array;
use crate::deny::{DenyApply, DenySet};
use crate::signed_deny::{verify_signed_deny, VerifiedDeny, DENY_FETCH_FILE};
use crate::{decode_certificate_pem, extract_spiffe_id};

/// The node refuses a deny list that is more than this far ahead of its clock (W25-34).
const DENY_MAX_SKEW_MS: u64 = 60_000;

/// The writer returns this text when the coordinator sent an unsigned deny list.
const OLD_COORDINATOR: &str = "version mismatch, upgrade: the coordinator is older than the node";

/// The name of the deny file in a node state directory.
pub const DENY_FILE: &str = "deny.json";

/// The file that only enroll writes. Its presence shows that the node is enrolled.
pub const ENROLL_MARKER_FILE: &str = "node-name";

/// The start of the temp file name for the atomic write.
const TEMP_PREFIX: &str = ".deny.json.tmp";

/// A deny file failure. Each failure refuses SSH, file receive, and new sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyFileError {
    /// The deny file is present, but the text is not a valid deny document.
    Invalid(PathBuf),
    /// The deny file did not open.
    Unreadable(PathBuf, ErrorKind),
    /// The node is enrolled, but the deny file is missing.
    MissingAfterEnroll(PathBuf),
}

impl fmt::Display for DenyFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const REFUSE: &str =
            "The node refuses SSH, file receive, and new sessions until it has a valid deny list.";
        match self {
            Self::Invalid(path) => write!(
                formatter,
                "The deny file {} is not valid. {REFUSE}",
                path.display()
            ),
            Self::Unreadable(path, kind) => write!(
                formatter,
                "The deny file {} did not open ({kind}). {REFUSE}",
                path.display()
            ),
            Self::MissingAfterEnroll(path) => write!(
                formatter,
                "The deny file {} is missing and the node is enrolled. {REFUSE}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for DenyFileError {}

/// Read the deny file bytes of a node state directory.
///
/// `Ok(None)` means that the file is missing and the node was never enrolled.
/// The caller then uses an empty set (the lab node behavior before W25-38).
pub fn read_deny_file(state_dir: &Path) -> Result<Option<Vec<u8>>, DenyFileError> {
    let path = state_dir.join(DENY_FILE);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if enrolled(state_dir) {
                Err(DenyFileError::MissingAfterEnroll(path))
            } else {
                Ok(None)
            }
        }
        Err(err) => Err(DenyFileError::Unreadable(path, err.kind())),
    }
}

/// Load the deny set of a node state directory. The function fails closed.
///
/// The function returns an error for a file that is not valid, a file that did not
/// open, and a missing file after enroll. It never replaces such a file with an empty
/// set. Use [`DenySet::refuse_all`] when a caller must keep a set after an error.
pub fn load_deny_file(state_dir: &Path) -> Result<DenySet, DenyFileError> {
    match read_deny_file(state_dir)? {
        None => Ok(DenySet::empty()),
        Some(bytes) => {
            let verified = verify_in_dir(state_dir, &bytes)?;
            let mut deny = DenySet::empty();
            deny.apply_verified(&verified)
                .map_err(|_| DenyFileError::Invalid(state_dir.join(DENY_FILE)))?;
            Ok(deny)
        }
    }
}

/// The result of [`store_deny_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyStore {
    /// The function installed the new text.
    Written,
    /// The file already has the same text.
    Same,
    /// The file has a valid document with the same or a higher version. The function
    /// kept it, so the deny list never moves back (the rule of [`DenySet::apply_json`]).
    KeptCurrent {
        /// The version in the file.
        current: u64,
        /// The version in the text that the function did not write.
        offered: u64,
    },
}

/// Write the deny file of a node state directory with an atomic rename.
///
/// The function refuses a text that is not a valid deny document, so the old file
/// stays. It does not write when the file already has the same text. It does not
/// write a document with a version that is not higher than the version in a valid
/// file. Thus the deny list never moves back. This is the same rule as a deny reload.
pub fn store_deny_file(state_dir: &Path, text: &str) -> io::Result<DenyStore> {
    store_deny_file_at(state_dir, text, unix_ms(SystemTime::now()))
}

/// [`store_deny_file`] with the node clock `now_ms`.
pub fn store_deny_file_at(state_dir: &Path, text: &str, now_ms: u64) -> io::Result<DenyStore> {
    if unsigned_offer(text) {
        return Err(io::Error::new(ErrorKind::InvalidData, OLD_COORDINATOR));
    }
    let offered = verify_in_dir(state_dir, text.as_bytes()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "The deny document is not valid. The node keeps the old deny file.",
        )
    })?;
    let path = state_dir.join(DENY_FILE);
    if let Ok(old) = fs::read(&path) {
        if let Ok(current) = verify_in_dir(state_dir, &old) {
            if current.key_id() == offered.key_id() {
                let decision = seq_decision(&current, &offered);
                if let Some(result) = decision {
                    if matches!(result, Ok(DenyStore::Same | DenyStore::KeptCurrent { .. })) {
                        record_deny_fetch(state_dir, now_ms)?;
                    }
                    return result;
                }
            }
        }
    }
    if offered.seq() > now_ms.saturating_add(DENY_MAX_SKEW_MS)
        || offered.issued_at_ms() > now_ms.saturating_add(DENY_MAX_SKEW_MS)
    {
        eprintln!(
            "deny refuse seq-future seq {} issued_at_ms {} now_ms {now_ms}",
            offered.seq(),
            offered.issued_at_ms()
        );
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "The deny list seq is in the future. The node keeps the old deny file.",
        ));
    }
    if offered.seq() > offered.issued_at_ms().saturating_add(DENY_MAX_SKEW_MS) {
        eprintln!(
            "ALERT deny refuse coord-clock-back seq {} issued_at_ms {}",
            offered.seq(),
            offered.issued_at_ms()
        );
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "The deny list seq is ahead of its issue time. The node keeps the old deny file.",
        ));
    }
    let temp = write_temp(state_dir, text.as_bytes())?;
    if let Err(err) = install(&temp, &path) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    record_deny_fetch(state_dir, now_ms)?;
    Ok(DenyStore::Written)
}

/// `Some` when the writer keeps the current file. `None` when it may write.
fn seq_decision(current: &VerifiedDeny, offered: &VerifiedDeny) -> Option<io::Result<DenyStore>> {
    if offered.seq() < current.seq() {
        eprintln!(
            "deny refuse seq-lower seq {} current {}",
            offered.seq(),
            current.seq()
        );
        return Some(Ok(DenyStore::KeptCurrent {
            current: current.version(),
            offered: offered.version(),
        }));
    }
    if offered.seq() == current.seq() {
        if offered.raw() == current.raw() {
            return Some(Ok(DenyStore::Same));
        }
        eprintln!("ALERT deny refuse seq-replay seq {}", offered.seq());
        return Some(Err(io::Error::new(
            ErrorKind::InvalidData,
            "ALERT deny refuse seq-replay. The node keeps the old deny file.",
        )));
    }
    if offered.version() < current.version() {
        eprintln!(
            "ALERT deny refuse version-lower version {} current {}",
            offered.version(),
            current.version()
        );
        return Some(Err(io::Error::new(
            ErrorKind::InvalidData,
            "ALERT deny refuse version-lower. The node keeps the old deny file.",
        )));
    }
    None
}

/// The result of one [`DenyCache`] reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReload {
    /// The set did not change.
    Same,
    /// The set changed. Apply it.
    Changed,
    /// The reload failed. The set keeps its last good entries and is stale, so it
    /// refuses each identifier and each nonce. `first` is true when the set was not
    /// stale before this reload.
    Stale {
        /// The reason of the failure.
        error: DenyFileError,
        /// True when this reload made the set stale.
        first: bool,
    },
}

/// The last good deny set of one reader (W25-38).
///
/// A failed reload keeps the last good set and marks it stale, as the agent guard
/// does. A stale set refuses each identifier and each nonce. The reader never uses
/// an empty set in place of a bad file. A valid file with a higher version, or the
/// same file again, makes the set current. A file with a lower version does not
/// change the set.
#[derive(Debug, Clone)]
pub struct DenyCache {
    set: DenySet,
    last_seq: Option<u64>,
    last_raw: Option<Vec<u8>>,
}

impl Default for DenyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DenyCache {
    /// A cache that refuses each identifier until the first good reload.
    pub fn new() -> Self {
        Self::with_set(DenySet::refuse_all())
    }

    /// A cache that starts with a set that the caller loaded.
    pub fn with_set(set: DenySet) -> Self {
        let last_seq = set.seq();
        let last_raw = set.signed_raw().map(<[u8]>::to_vec);
        Self {
            set,
            last_seq,
            last_raw,
        }
    }

    /// The current set. It refuses each identifier when it is stale.
    pub fn set(&self) -> &DenySet {
        &self.set
    }

    /// Read the deny file of the state directory again.
    pub fn reload(&mut self, state_dir: &Path) -> DenyReload {
        self.apply_read(state_dir, read_deny_file(state_dir))
    }

    /// Apply the result of [`read_deny_file`].
    pub fn apply_read(
        &mut self,
        state_dir: &Path,
        read: Result<Option<Vec<u8>>, DenyFileError>,
    ) -> DenyReload {
        let bytes = match read {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // The node was never enrolled and has no deny file: the behavior
                // before W25-38. A set with a version stays.
                self.last_seq = None;
                self.last_raw = None;
                if self.set.version().is_none() && self.set.refuses_all() {
                    self.set = DenySet::empty();
                    return DenyReload::Changed;
                }
                return DenyReload::Same;
            }
            Err(error) => return self.stale(error),
        };
        let verified = match verify_in_dir(state_dir, &bytes) {
            Ok(verified) => verified,
            Err(error) => return self.stale(error),
        };
        if let Some(result) = self.seq_gate(state_dir, &verified) {
            return result;
        }
        self.accept(verified)
    }

    /// Apply the in-memory seq table. `None` means the list may replace the set.
    fn seq_gate(&mut self, state_dir: &Path, verified: &VerifiedDeny) -> Option<DenyReload> {
        let last_seq = self.last_seq?;
        let invalid = DenyFileError::Invalid(state_dir.join(DENY_FILE));
        if verified.seq() < last_seq {
            eprintln!(
                "deny refuse seq-lower seq {} current {last_seq}",
                verified.seq()
            );
            return Some(self.stale(invalid));
        }
        if verified.seq() == last_seq {
            if self.last_raw.as_deref() == Some(verified.raw()) {
                return Some(self.accept_same(verified));
            }
            eprintln!("ALERT deny refuse seq-replay seq {}", verified.seq());
            return Some(self.stale(invalid));
        }
        if self
            .set
            .version()
            .is_some_and(|current| verified.version() < current)
        {
            eprintln!(
                "ALERT deny refuse version-lower version {} current {}",
                verified.version(),
                self.set.version().unwrap_or(0)
            );
            return Some(self.stale(invalid));
        }
        None
    }

    fn accept_same(&mut self, verified: &VerifiedDeny) -> DenyReload {
        match self.set.apply_verified(verified) {
            Ok(DenyApply::Applied) => DenyReload::Changed,
            Ok(DenyApply::IgnoredOlder) => DenyReload::Same,
            Err(_) => self.stale(DenyFileError::Invalid(PathBuf::from(DENY_FILE))),
        }
    }

    fn accept(&mut self, verified: VerifiedDeny) -> DenyReload {
        match self.set.apply_verified(&verified) {
            Ok(DenyApply::Applied) => {
                self.remember(&verified);
                DenyReload::Changed
            }
            Ok(DenyApply::IgnoredOlder) => {
                self.remember(&verified);
                DenyReload::Same
            }
            Err(_) => self.stale(DenyFileError::Invalid(PathBuf::from(DENY_FILE))),
        }
    }

    fn remember(&mut self, verified: &VerifiedDeny) {
        self.last_seq = Some(verified.seq());
        self.last_raw = Some(verified.raw().to_vec());
    }

    fn stale(&mut self, error: DenyFileError) -> DenyReload {
        let first = !self.set.refuses_all();
        self.set.mark_stale();
        DenyReload::Stale { error, first }
    }
}

fn verify_in_dir(state_dir: &Path, bytes: &[u8]) -> Result<VerifiedDeny, DenyFileError> {
    let invalid = || DenyFileError::Invalid(state_dir.join(DENY_FILE));
    let public = netmap_public(state_dir).ok_or_else(invalid)?;
    let uri = node_svid_uri(state_dir).ok_or_else(invalid)?;
    verify_signed_deny(bytes, &public, &uri).map_err(|_| invalid())
}

/// The netmap public key from `netmap.pub`. The function does not read `key_id`.
fn netmap_public(state_dir: &Path) -> Option<[u8; 32]> {
    let text = fs::read_to_string(state_dir.join("netmap.pub")).ok()?;
    let key = decode_hex_array::<32>(text.trim()).ok()?;
    VerifyingKey::from_bytes(&key).ok()?;
    Some(key)
}

/// The node SVID URI from the node leaf. The function reads the leaf on each call.
fn node_svid_uri(state_dir: &Path) -> Option<String> {
    let primary = state_dir.join("node.crt.pem");
    let path = if primary.exists() {
        primary
    } else {
        state_dir.join("cert.pem")
    };
    let pem = fs::read_to_string(path).ok()?;
    let der = decode_certificate_pem(&pem).ok()?;
    let id = extract_spiffe_id(&der).ok()?;
    Some(id.as_uri().to_string())
}

fn unsigned_offer(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object.contains_key("version") && !object.contains_key("sig")
}

fn unix_ms(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Write the time of one good deny fetch. The file holds no secret.
pub fn record_deny_fetch(state_dir: &Path, now_ms: u64) -> io::Result<()> {
    let path = state_dir.join(DENY_FETCH_FILE);
    let temp = state_dir.join(".deny-fetch-ok.tmp");
    fs::write(&temp, format!("{now_ms}\n"))?;
    fs::rename(&temp, &path)
}

/// Read the time of the last good deny fetch.
#[must_use]
pub fn read_deny_fetch_ok(state_dir: &Path) -> Option<u64> {
    let text = fs::read_to_string(state_dir.join(DENY_FETCH_FILE)).ok()?;
    text.trim().parse().ok()
}

fn enrolled(state_dir: &Path) -> bool {
    match fs::symlink_metadata(state_dir.join(ENROLL_MARKER_FILE)) {
        Ok(_) => true,
        Err(err) => err.kind() != ErrorKind::NotFound,
    }
}

/// Write and sync a new temp file in the state directory. Each call uses a new name,
/// so two writers do not share one temp file.
fn write_temp(state_dir: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let temp = state_dir.join(format!("{TEMP_PREFIX}.{}.{serial}", std::process::id()));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(err) = written {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    Ok(temp)
}

/// Rename the temp file onto the deny file and sync the directory.
fn install(temp: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp, path)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::signed_deny::{seal_deny, DenyObject};
    use crate::{MiniCa, MAX_USER_TTL};

    const UNSIGNED: &str = r#"{"version":1,"generated_at":10,"revoked_uris":["spiffe://orblx.local/node/b"],"revoked_ticket_nonces":[]}"#;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "orblx-w25-38-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn enroll(&self) {
            fs::write(self.0.join(ENROLL_MARKER_FILE), "a\n").unwrap();
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn node(name: &str) -> crate::SpiffeId {
        crate::SpiffeId::node(name).unwrap()
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[4u8; 32])
    }

    fn clock() -> u64 {
        unix_ms(SystemTime::now())
    }

    /// Write `netmap.pub` and the node leaf for node `a`.
    fn arm(dir: &Path) -> SigningKey {
        let key = key();
        let id = node("a");
        let now = SystemTime::now();
        let ca = MiniCa::generate(now).unwrap();
        let issued = ca.issue(&id, now, MAX_USER_TTL, &DenySet::empty()).unwrap();
        fs::write(dir.join("node.crt.pem"), issued.certificate_pem).unwrap();
        fs::write(
            dir.join("netmap.pub"),
            format!(
                "{}\n",
                crate::codec::encode_hex(key.verifying_key().as_bytes())
            ),
        )
        .unwrap();
        key
    }

    fn signed(key: &SigningKey, version: u64, peer: &str, seq: u64) -> String {
        let object = DenyObject {
            version,
            generated_at: version * 10,
            revoked_uris: vec![node(peer).as_uri().to_string()],
            revoked_ticket_nonces: Vec::new(),
            node_uri: node("a").as_uri().to_string(),
            seq,
            issued_at_ms: seq,
        };
        let raw = serde_json::to_vec(&object).unwrap();
        seal_deny(key, &raw).unwrap()
    }

    fn lists(dir: &Path) -> (String, String) {
        let key = arm(dir);
        let now = clock();
        (signed(&key, 1, "b", now), signed(&key, 2, "c", now + 1))
    }

    fn temp_files(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(TEMP_PREFIX))
            .collect()
    }

    #[test]
    fn w25_38_corrupt_deny_file_refuses() {
        let dir = Dir::new("corrupt");
        dir.enroll();
        fs::write(dir.0.join(DENY_FILE), b"not json {").unwrap();
        let err = load_deny_file(&dir.0).unwrap_err();
        assert!(matches!(err, DenyFileError::Invalid(_)));
        assert!(err.to_string().contains("is not valid"));
        assert!(err
            .to_string()
            .contains("refuses SSH, file receive, and new sessions"));
    }

    #[test]
    fn w25_38_corrupt_deny_file_refuses_when_never_enrolled() {
        // An invalid file is never an empty list, also on a lab node.
        let dir = Dir::new("corrupt-lab");
        fs::write(dir.0.join(DENY_FILE), b"{\"version\":").unwrap();
        assert!(matches!(
            load_deny_file(&dir.0),
            Err(DenyFileError::Invalid(_))
        ));
    }

    #[test]
    fn w25_38_truncated_deny_file_refuses() {
        let dir = Dir::new("truncated");
        dir.enroll();
        let (v1, _) = lists(&dir.0);
        for cut in [0, 1, v1.len() / 2, v1.len() - 1] {
            fs::write(dir.0.join(DENY_FILE), &v1.as_bytes()[..cut]).unwrap();
            assert!(
                matches!(load_deny_file(&dir.0), Err(DenyFileError::Invalid(_))),
                "cut {cut}"
            );
        }
        fs::write(dir.0.join(DENY_FILE), &v1).unwrap();
        let deny = load_deny_file(&dir.0).unwrap();
        assert!(deny.reject_uri(&node("b")).is_err());
        assert!(deny.reject_uri(&node("a")).is_ok());
    }

    #[test]
    fn w25_38_missing_deny_file_after_enroll_refuses() {
        let dir = Dir::new("missing");
        dir.enroll();
        let err = load_deny_file(&dir.0).unwrap_err();
        assert!(matches!(err, DenyFileError::MissingAfterEnroll(_)));
        assert!(err
            .to_string()
            .contains("is missing and the node is enrolled"));
        assert!(matches!(
            read_deny_file(&dir.0),
            Err(DenyFileError::MissingAfterEnroll(_))
        ));
    }

    #[test]
    fn w25_38_missing_deny_file_never_enrolled_keeps_empty() {
        let dir = Dir::new("lab");
        assert_eq!(read_deny_file(&dir.0), Ok(None));
        let deny = load_deny_file(&dir.0).unwrap();
        assert_eq!(deny, DenySet::empty());
        assert!(!deny.refuses_all());
    }

    #[test]
    fn w25_38_unreadable_deny_file_refuses() {
        // A directory at the deny file path does not open as a file.
        let dir = Dir::new("unreadable");
        fs::create_dir(dir.0.join(DENY_FILE)).unwrap();
        assert!(matches!(
            load_deny_file(&dir.0),
            Err(DenyFileError::Unreadable(_, _))
        ));
    }

    #[test]
    fn w25_38_crash_during_write_keeps_old_file() {
        let dir = Dir::new("crash");
        dir.enroll();
        let (v1, v2) = lists(&dir.0);
        assert_eq!(store_deny_file(&dir.0, &v1).unwrap(), DenyStore::Written);
        // The crash comes after the temp write and before the rename.
        // The temp file has only a part of the new text.
        let temp = write_temp(&dir.0, &v2.as_bytes()[..v2.len() / 2]).unwrap();
        assert!(temp.exists());
        let deny = load_deny_file(&dir.0).unwrap();
        assert_eq!(deny.version(), Some(1));
        assert!(deny.reject_uri(&node("b")).is_err());
        // The temp file is left. The next write installs the full new text.
        assert_eq!(store_deny_file(&dir.0, &v2).unwrap(), DenyStore::Written);
        let deny = load_deny_file(&dir.0).unwrap();
        assert_eq!(deny.version(), Some(2));
        assert!(deny.reject_uri(&node("c")).is_err());
        assert_eq!(temp_files(&dir.0).len(), 1);
    }

    #[test]
    fn w25_38_crash_during_first_write_after_enroll_refuses() {
        // No old file: the reader refuses and does not read the temp file.
        let dir = Dir::new("crash-first");
        dir.enroll();
        let (v1, _) = lists(&dir.0);
        write_temp(&dir.0, &v1.as_bytes()[..v1.len() / 2]).unwrap();
        assert!(matches!(
            load_deny_file(&dir.0),
            Err(DenyFileError::MissingAfterEnroll(_))
        ));
    }

    #[test]
    fn w25_38_store_refuses_invalid_text_and_keeps_old_file() {
        let dir = Dir::new("store-invalid");
        let (v1, v2) = lists(&dir.0);
        assert_eq!(store_deny_file(&dir.0, &v1).unwrap(), DenyStore::Written);
        let err = store_deny_file(&dir.0, &v2[..v2.len() - 3]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(dir.0.join(DENY_FILE)).unwrap(), v1);
        assert!(temp_files(&dir.0).is_empty());
    }

    #[test]
    fn w25_38_store_skips_same_text_and_leaves_no_temp() {
        let dir = Dir::new("store-same");
        let (v1, v2) = lists(&dir.0);
        assert_eq!(store_deny_file(&dir.0, &v1).unwrap(), DenyStore::Written);
        assert_eq!(store_deny_file(&dir.0, &v1).unwrap(), DenyStore::Same);
        assert_eq!(store_deny_file(&dir.0, &v2).unwrap(), DenyStore::Written);
        assert_eq!(fs::read_to_string(dir.0.join(DENY_FILE)).unwrap(), v2);
        assert!(temp_files(&dir.0).is_empty());
    }

    #[test]
    fn w25_38_refuse_all_set_refuses_each_identifier() {
        let deny = DenySet::refuse_all();
        assert!(deny.refuses_all());
        assert!(deny.reject_uri(&node("a")).is_err());
        assert!(deny.reject_nonce(&[0u8; 16]).is_err());
        let mut deny = deny;
        deny.apply_json(UNSIGNED.as_bytes()).unwrap();
        assert!(!deny.refuses_all());
        assert!(deny.reject_uri(&node("a")).is_ok());
    }

    #[test]
    fn w25_38_store_never_moves_the_deny_list_back() {
        let dir = Dir::new("store-back");
        let signing = arm(&dir.0);
        let now = clock();
        let v2 = signed(&signing, 2, "c", now);
        let v1 = signed(&signing, 1, "b", now - 1);
        assert_eq!(store_deny_file(&dir.0, &v2).unwrap(), DenyStore::Written);
        // A lower seq does not replace the file.
        assert_eq!(
            store_deny_file(&dir.0, &v1).unwrap(),
            DenyStore::KeptCurrent {
                current: 2,
                offered: 1
            }
        );
        // The same seq with other bytes is a replay.
        let replay = signed(&signing, 2, "b", now);
        let err = store_deny_file(&dir.0, &replay).unwrap_err();
        assert!(err.to_string().contains("seq-replay"));
        // A higher seq with a lower version does not replace the file.
        let back = signed(&signing, 1, "b", now + 2);
        let err = store_deny_file(&dir.0, &back).unwrap_err();
        assert!(err.to_string().contains("version-lower"));
        assert_eq!(fs::read_to_string(dir.0.join(DENY_FILE)).unwrap(), v2);
        // A file that is not valid does not block a new valid list.
        fs::write(dir.0.join(DENY_FILE), b"not json {").unwrap();
        assert_eq!(store_deny_file(&dir.0, &v1).unwrap(), DenyStore::Written);
        assert!(temp_files(&dir.0).is_empty());
    }

    #[test]
    fn w25_38_reload_failure_keeps_the_last_good_set_and_goes_stale() {
        let dir = Dir::new("cache");
        dir.enroll();
        let (v1, v2) = lists(&dir.0);
        let mut cache = DenyCache::new();
        assert!(cache.set().refuses_all(), "no read yet");
        fs::write(dir.0.join(DENY_FILE), &v2).unwrap();
        assert_eq!(cache.reload(&dir.0), DenyReload::Changed);
        assert_eq!(cache.reload(&dir.0), DenyReload::Same);
        assert!(cache.set().reject_uri(&node("a")).is_ok());

        let damage = |path: &Path, name: &str| match name {
            "corrupt" => fs::write(path, b"not json {").unwrap(),
            "truncated" => fs::write(path, &v2.as_bytes()[..v2.len() / 2]).unwrap(),
            "missing" => fs::remove_file(path).unwrap(),
            _ => {
                fs::remove_file(path).unwrap();
                fs::create_dir(path).unwrap();
            }
        };
        for name in ["corrupt", "truncated", "missing", "unreadable"] {
            let path = dir.0.join(DENY_FILE);
            damage(&path, name);
            let DenyReload::Stale { first, .. } = cache.reload(&dir.0) else {
                panic!("{name}: the reload did not go stale");
            };
            assert!(first, "{name}");
            assert!(matches!(
                cache.reload(&dir.0),
                DenyReload::Stale { first: false, .. }
            ));
            // The stale set keeps the last good version and refuses each identifier.
            assert_eq!(cache.set().version(), Some(2), "{name}");
            assert!(cache.set().reject_uri(&node("a")).is_err(), "{name}");
            assert!(cache.set().reject_nonce(&[0u8; 16]).is_err(), "{name}");
            // An older valid list does not make the set current.
            if path.is_dir() {
                fs::remove_dir(&path).unwrap();
            }
            fs::write(&path, &v1).unwrap();
            assert!(
                matches!(cache.reload(&dir.0), DenyReload::Stale { .. }),
                "{name}"
            );
            assert!(cache.set().reject_uri(&node("a")).is_err(), "{name}");
            // The last good list again makes the set current.
            fs::write(&path, &v2).unwrap();
            assert_eq!(cache.reload(&dir.0), DenyReload::Changed, "{name}");
            assert!(cache.set().reject_uri(&node("a")).is_ok(), "{name}");
            assert!(cache.set().reject_uri(&node("c")).is_err(), "{name}");
        }
    }

    #[test]
    fn w25_38_cache_of_a_never_enrolled_node_without_a_file_is_empty() {
        let dir = Dir::new("cache-lab");
        let mut cache = DenyCache::new();
        assert_eq!(cache.reload(&dir.0), DenyReload::Changed);
        assert_eq!(cache.set(), &DenySet::empty());
        assert_eq!(cache.reload(&dir.0), DenyReload::Same);
    }

    #[test]
    fn a_missing_or_unsigned_or_corrupt_deny_file_is_not_an_empty_list() {
        let dir = Dir::new("closed");
        dir.enroll();
        arm(&dir.0);
        assert!(matches!(
            load_deny_file(&dir.0),
            Err(DenyFileError::MissingAfterEnroll(_))
        ));
        fs::write(dir.0.join(DENY_FILE), UNSIGNED).unwrap();
        assert!(matches!(
            load_deny_file(&dir.0),
            Err(DenyFileError::Invalid(_))
        ));
        let err = store_deny_file(&dir.0, UNSIGNED).unwrap_err();
        assert!(err.to_string().contains("version mismatch, upgrade"));
        fs::write(dir.0.join(DENY_FILE), b"not json {").unwrap();
        assert!(matches!(
            load_deny_file(&dir.0),
            Err(DenyFileError::Invalid(_))
        ));
        let mut cache = DenyCache::new();
        assert!(matches!(cache.reload(&dir.0), DenyReload::Stale { .. }));
        assert!(cache.set().refuses_all());
        assert_ne!(cache.set(), &DenySet::empty());
    }

    #[test]
    fn a_node_uri_change_on_reload_is_picked_up() {
        let dir = Dir::new("uri");
        dir.enroll();
        let signing = arm(&dir.0);
        let now = clock();
        let for_a = signed(&signing, 1, "b", now);
        fs::write(dir.0.join(DENY_FILE), &for_a).unwrap();
        let mut cache = DenyCache::new();
        assert_eq!(cache.reload(&dir.0), DenyReload::Changed);
        assert!(cache.set().reject_uri(&node("b")).is_err());
        let now_time = SystemTime::now();
        let ca = MiniCa::generate(now_time).unwrap();
        let issued = ca
            .issue(&node("b"), now_time, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        fs::write(dir.0.join("node.crt.pem"), issued.certificate_pem).unwrap();
        assert!(matches!(cache.reload(&dir.0), DenyReload::Stale { .. }));
        assert!(cache.set().refuses_all());
        let for_b = {
            let object = DenyObject {
                version: 2,
                generated_at: 20,
                revoked_uris: vec![node("c").as_uri().to_string()],
                revoked_ticket_nonces: Vec::new(),
                node_uri: node("b").as_uri().to_string(),
                seq: now + 5,
                issued_at_ms: now + 5,
            };
            seal_deny(&signing, &serde_json::to_vec(&object).unwrap()).unwrap()
        };
        fs::write(dir.0.join(DENY_FILE), &for_b).unwrap();
        assert_eq!(cache.reload(&dir.0), DenyReload::Changed);
        assert!(cache.set().reject_uri(&node("c")).is_err());
        assert!(!cache.set().refuses_all());
    }

    #[test]
    fn a_seq_far_in_the_future_is_refused_with_the_given_clock() {
        let dir = Dir::new("future");
        let signing = arm(&dir.0);
        let now = clock();
        let far = signed(&signing, 1, "b", now + DENY_MAX_SKEW_MS + 5);
        let err = store_deny_file_at(&dir.0, &far, now).unwrap_err();
        assert!(err.to_string().contains("future"));
        assert!(!dir.0.join(DENY_FILE).exists());
        let ok = signed(&signing, 1, "b", now);
        assert_eq!(
            store_deny_file_at(&dir.0, &ok, now).unwrap(),
            DenyStore::Written
        );
    }
}
