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

use crate::deny::{DenyApply, DenySet};

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
        Some(bytes) => DenySet::from_json(&bytes)
            .map_err(|_| DenyFileError::Invalid(state_dir.join(DENY_FILE))),
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
    let Ok(offered) = DenySet::from_json(text.as_bytes()) else {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "The deny document is not valid. The node keeps the old deny file.",
        ));
    };
    let path = state_dir.join(DENY_FILE);
    if let Ok(old) = fs::read(&path) {
        if old == text.as_bytes() {
            return Ok(DenyStore::Same);
        }
        let current = DenySet::from_json(&old).ok().and_then(|set| set.version());
        if let (Some(current), Some(offered)) = (current, offered.version()) {
            if offered <= current {
                return Ok(DenyStore::KeptCurrent { current, offered });
            }
        }
    }
    let temp = write_temp(state_dir, text.as_bytes())?;
    if let Err(err) = install(&temp, &path) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    Ok(DenyStore::Written)
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
    last: Option<Vec<u8>>,
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
        Self { set, last: None }
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
                self.last = None;
                if self.set.version().is_none() && self.set.refuses_all() {
                    self.set = DenySet::empty();
                    return DenyReload::Changed;
                }
                return DenyReload::Same;
            }
            Err(error) => return self.stale(error),
        };
        if !self.set.refuses_all() && self.last.as_deref() == Some(bytes.as_slice()) {
            return DenyReload::Same;
        }
        match self.set.apply_json(&bytes) {
            Ok(DenyApply::Applied) => {
                self.last = Some(bytes);
                DenyReload::Changed
            }
            // A lower version does not change the set. A stale set stays stale.
            Ok(DenyApply::IgnoredOlder) => {
                self.last = Some(bytes);
                DenyReload::Same
            }
            Err(_) => self.stale(DenyFileError::Invalid(state_dir.join(DENY_FILE))),
        }
    }

    fn stale(&mut self, error: DenyFileError) -> DenyReload {
        let first = !self.set.refuses_all();
        self.set.mark_stale();
        self.last = None;
        DenyReload::Stale { error, first }
    }
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
    use super::*;

    const V1: &str = r#"{"version":1,"generated_at":10,"revoked_uris":["spiffe://orblx.local/node/b"],"revoked_ticket_nonces":[]}"#;
    const V2: &str = r#"{"version":2,"generated_at":20,"revoked_uris":["spiffe://orblx.local/node/c"],"revoked_ticket_nonces":[]}"#;

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
        for cut in [0, 1, V1.len() / 2, V1.len() - 1] {
            fs::write(dir.0.join(DENY_FILE), &V1.as_bytes()[..cut]).unwrap();
            assert!(
                matches!(load_deny_file(&dir.0), Err(DenyFileError::Invalid(_))),
                "cut {cut}"
            );
        }
        fs::write(dir.0.join(DENY_FILE), V1).unwrap();
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
        assert_eq!(store_deny_file(&dir.0, V1).unwrap(), DenyStore::Written);
        // The crash comes after the temp write and before the rename.
        // The temp file has only a part of the new text.
        let temp = write_temp(&dir.0, &V2.as_bytes()[..V2.len() / 2]).unwrap();
        assert!(temp.exists());
        let deny = load_deny_file(&dir.0).unwrap();
        assert_eq!(deny.version(), Some(1));
        assert!(deny.reject_uri(&node("b")).is_err());
        // The temp file is left. The next write installs the full new text.
        assert_eq!(store_deny_file(&dir.0, V2).unwrap(), DenyStore::Written);
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
        write_temp(&dir.0, &V1.as_bytes()[..V1.len() / 2]).unwrap();
        assert!(matches!(
            load_deny_file(&dir.0),
            Err(DenyFileError::MissingAfterEnroll(_))
        ));
    }

    #[test]
    fn w25_38_store_refuses_invalid_text_and_keeps_old_file() {
        let dir = Dir::new("store-invalid");
        assert_eq!(store_deny_file(&dir.0, V1).unwrap(), DenyStore::Written);
        let err = store_deny_file(&dir.0, &V2[..V2.len() - 3]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(dir.0.join(DENY_FILE)).unwrap(), V1);
        assert!(temp_files(&dir.0).is_empty());
    }

    #[test]
    fn w25_38_store_skips_same_text_and_leaves_no_temp() {
        let dir = Dir::new("store-same");
        assert_eq!(store_deny_file(&dir.0, V1).unwrap(), DenyStore::Written);
        assert_eq!(store_deny_file(&dir.0, V1).unwrap(), DenyStore::Same);
        assert_eq!(store_deny_file(&dir.0, V2).unwrap(), DenyStore::Written);
        assert_eq!(fs::read_to_string(dir.0.join(DENY_FILE)).unwrap(), V2);
        assert!(temp_files(&dir.0).is_empty());
    }

    #[test]
    fn w25_38_refuse_all_set_refuses_each_identifier() {
        let deny = DenySet::refuse_all();
        assert!(deny.refuses_all());
        assert!(deny.reject_uri(&node("a")).is_err());
        assert!(deny.reject_nonce(&[0u8; 16]).is_err());
        let mut deny = deny;
        deny.apply_json(V1.as_bytes()).unwrap();
        assert!(!deny.refuses_all());
        assert!(deny.reject_uri(&node("a")).is_ok());
    }

    #[test]
    fn w25_38_store_never_moves_the_deny_list_back() {
        let dir = Dir::new("store-back");
        assert_eq!(store_deny_file(&dir.0, V2).unwrap(), DenyStore::Written);
        // A lower version and the same version with other text do not replace the file.
        assert_eq!(
            store_deny_file(&dir.0, V1).unwrap(),
            DenyStore::KeptCurrent {
                current: 2,
                offered: 1
            }
        );
        let same_version = V2.replace("\"generated_at\":20", "\"generated_at\":21");
        assert_eq!(
            store_deny_file(&dir.0, &same_version).unwrap(),
            DenyStore::KeptCurrent {
                current: 2,
                offered: 2
            }
        );
        assert_eq!(fs::read_to_string(dir.0.join(DENY_FILE)).unwrap(), V2);
        // A file that is not valid does not block a new valid list.
        fs::write(dir.0.join(DENY_FILE), b"not json {").unwrap();
        assert_eq!(store_deny_file(&dir.0, V1).unwrap(), DenyStore::Written);
        assert!(temp_files(&dir.0).is_empty());
    }

    #[test]
    fn w25_38_reload_failure_keeps_the_last_good_set_and_goes_stale() {
        let dir = Dir::new("cache");
        dir.enroll();
        let mut cache = DenyCache::new();
        assert!(cache.set().refuses_all(), "no read yet");
        fs::write(dir.0.join(DENY_FILE), V2).unwrap();
        assert_eq!(cache.reload(&dir.0), DenyReload::Changed);
        assert_eq!(cache.reload(&dir.0), DenyReload::Same);
        assert!(cache.set().reject_uri(&node("a")).is_ok());

        let damage = |path: &Path, name: &str| match name {
            "corrupt" => fs::write(path, b"not json {").unwrap(),
            "truncated" => fs::write(path, &V2.as_bytes()[..V2.len() / 2]).unwrap(),
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
            fs::write(&path, V1).unwrap();
            assert_eq!(cache.reload(&dir.0), DenyReload::Same, "{name}");
            assert!(cache.set().reject_uri(&node("a")).is_err(), "{name}");
            // The last good list again makes the set current.
            fs::write(&path, V2).unwrap();
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
}
