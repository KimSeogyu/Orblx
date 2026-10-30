//! The gateway nonce file.
//!
//! The gateway keeps each used request nonce in a file that is apart from
//! the audit chain. Thus a restart refuses a replay when the audit chain file
//! is gone or new.
//!
//! The file is plain text with one entry on each line:
//!
//! ```text
//! orblx-nonce-v1 TICKET_HASH_HEX NONCE_HEX STAMP_SECS
//! ```
//!
//! The gateway appends the line and syncs the file before it forwards the
//! request. At start, the gateway reads the file and keeps the entries of the
//! last two proof windows. A line that is not valid stops the start (fail
//! closed). A last line without a line end is a write that did not complete.
//! The request of that line did not go to the upstream, so the gateway drops
//! the line. The gateway then writes the kept entries to a new file.
//! The file holds no key, no ticket, and no proof.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::hex::{decode_hex, encode_hex};
use crate::AgentError;

const LINE_TAG: &str = "orblx-nonce-v1";

/// One seen key: (ticket hash, nonce).
pub(crate) type SeenKey = ([u8; 16], [u8; 16]);
/// Seen request nonces: (ticket hash, nonce) to the proof stamp in Unix seconds.
pub(crate) type SeenSet = BTreeMap<SeenKey, u64>;

/// The append-only nonce file of one gateway.
pub(crate) struct NonceStore {
    path: PathBuf,
    file: File,
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> AgentError + '_ {
    move |err| AgentError::Io(format!("The nonce file {} failed. {err}", path.display()))
}

fn bad_line(path: &Path, number: usize) -> AgentError {
    AgentError::Io(format!(
        "The nonce file {} line {number} is not valid.",
        path.display()
    ))
}

fn parse_line(line: &str) -> Option<(SeenKey, u64)> {
    let mut words = line.split(' ');
    let (Some(tag), Some(hash), Some(nonce), Some(stamp), None) = (
        words.next(),
        words.next(),
        words.next(),
        words.next(),
        words.next(),
    ) else {
        return None;
    };
    if tag != LINE_TAG {
        return None;
    }
    let hash = <[u8; 16]>::try_from(decode_hex(hash).ok()?).ok()?;
    let nonce = <[u8; 16]>::try_from(decode_hex(nonce).ok()?).ok()?;
    let stamp = stamp.parse::<u64>().ok()?;
    Some(((hash, nonce), stamp))
}

fn format_line(key: &SeenKey, stamp: u64) -> String {
    format!(
        "{LINE_TAG} {} {} {stamp}\n",
        encode_hex(&key.0),
        encode_hex(&key.1)
    )
}

fn open_append(path: &Path) -> Result<File, AgentError> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io(path))
}

impl NonceStore {
    /// Open the file, load the entries with a stamp at or after `keep_after`,
    /// and write them to a new file.
    pub(crate) fn open(path: &Path, keep_after: u64) -> Result<(Self, SeenSet), AgentError> {
        let mut seen = SeenSet::new();
        if path.exists() {
            let bytes = fs::read(path).map_err(io(path))?;
            let text = String::from_utf8(bytes).map_err(|_| bad_line(path, 0))?;
            let complete = text.ends_with('\n') || text.is_empty();
            let lines: Vec<&str> = text.split_terminator('\n').collect();
            for (index, line) in lines.iter().enumerate() {
                let last = index + 1 == lines.len();
                match parse_line(line) {
                    Some((key, stamp)) => {
                        if stamp >= keep_after {
                            seen.insert(key, stamp);
                        }
                    }
                    // A last line without a line end did not complete.
                    None if last && !complete => {}
                    None => return Err(bad_line(path, index + 1)),
                }
            }
        }
        let tmp = path.with_extension("tmp");
        let _ = fs::remove_file(&tmp);
        {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp).map_err(io(&tmp))?;
            let mut out = String::new();
            for (key, stamp) in &seen {
                out.push_str(&format_line(key, *stamp));
            }
            file.write_all(out.as_bytes()).map_err(io(&tmp))?;
            file.sync_all().map_err(io(&tmp))?;
        }
        fs::rename(&tmp, path).map_err(io(path))?;
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            if let Ok(dir) = File::open(dir) {
                let _ = dir.sync_all();
            }
        }
        let file = open_append(path)?;
        Ok((
            Self {
                path: path.to_path_buf(),
                file,
            },
            seen,
        ))
    }

    /// Append one entry and sync the file.
    pub(crate) fn append(&mut self, key: &SeenKey, stamp: u64) -> Result<(), AgentError> {
        let line = format_line(key, stamp);
        self.file
            .write_all(line.as_bytes())
            .map_err(io(&self.path))?;
        self.file.sync_data().map_err(io(&self.path))
    }
}

/// The default nonce file for an audit chain file: `AUDIT.nonces`.
#[must_use]
pub fn default_nonce_path(audit: &Path) -> PathBuf {
    let mut name = audit.as_os_str().to_os_string();
    name.push(".nonces");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::{default_nonce_path, NonceStore};
    use std::fs;
    use std::path::Path;

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orblx-nonce-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("dir");
        dir
    }

    #[test]
    fn entries_persist_and_old_ones_drop() {
        let dir = dir();
        let path = dir.join("g.nonces");
        let (mut store, seen) = NonceStore::open(&path, 0).expect("open");
        assert!(seen.is_empty());
        store.append(&([1u8; 16], [2u8; 16]), 1000).expect("a");
        store.append(&([3u8; 16], [4u8; 16]), 50).expect("b");
        drop(store);
        let (_, seen) = NonceStore::open(&path, 100).expect("reopen");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen.get(&([1u8; 16], [2u8; 16])), Some(&1000));
        let text = fs::read_to_string(&path).expect("read");
        assert_eq!(text.lines().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bad_line_stops_the_start_and_a_torn_tail_drops() {
        let dir = dir();
        let path = dir.join("g.nonces");
        let good = format!(
            "orblx-nonce-v1 {} {} 500\n",
            "11".repeat(16),
            "22".repeat(16)
        );
        fs::write(&path, format!("{good}orblx-nonce-v1 12")).expect("write");
        let (_, seen) = NonceStore::open(&path, 0).expect("torn tail");
        assert_eq!(seen.len(), 1);
        fs::write(&path, format!("garbage\n{good}")).expect("write");
        assert!(NonceStore::open(&path, 0).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn default_path_is_next_to_the_audit_file() {
        assert_eq!(
            default_nonce_path(Path::new("/var/lib/orblx/api.jsonl")),
            Path::new("/var/lib/orblx/api.jsonl.nonces")
        );
    }
}
