//! The signed netmap sequence number and issue time (W25-34).
//!
//! The coordinator side gives each signed netmap a `seq` and an `issued_at_ms`.
//! `seq = max(last seq + 1, issued_at_ms)`. The coordinator writes and syncs the new `seq`
//! to disk before it signs the netmap, so a restart never gives a lower `seq`.
//! The coordinator gives a new stamp when the content of the netmap of a node changes, and
//! at least each [`HEARTBEAT_MS`] (the signed heartbeat).
//!
//! The node side accepts a signed netmap only when its `seq` is higher than the last
//! accepted `seq`. An equal `seq` with the same signed bytes is a no-op: the node changes
//! no state. An equal `seq` with different bytes is refused with an alert. A `seq` more than
//! 60 s in the future is refused. A `seq` more than 60 s above the signed issue time
//! (the coordinator clock went back) is refused until the clock passes it. There is no command or field that accepts a lower `seq`.
//! Only a local reset (new node state or a new enrollment) clears the last `seq`.
//!
//! Crypto review fixes (W25-34):
//! - Fix 2: the node always refuses a netmap with `issued_at_ms` more than 60 s old or
//!   more than 60 s ahead, with or without a `netmap.seq` file.
//! - Fix 3: a corrupt `netmap.seq` file is an ALERT. The node moves it aside and continues
//!   as if the file is missing. Fix 2 then limits the rollback to 60 s.
//! - Fix 4 (CLOCK-FORWARD): the coordinator refuses to sign or write a `seq` more than
//!   60 s ahead of its clock. The owner command `orblx admin netmap-seq-reset` (audit
//!   action `netmap-seq-reset`, code 41) sets the stored `seq` to the clock time, only when
//!   the stored `seq` is ahead of the clock. A stored `seq` above [`SEQ_MAX`] stops the load.
//! - Fix 5 (grants binding): the signed netmap carries the SHA-256 of the signed grants
//!   bytes. The node refuses a netmap that does not match its grants.
//! - A lock file (`netmap-seq.lock`) stops a second coordinator process that signs with the
//!   same state directory.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_datapath::{NETMAP_MAX_AGE_MS, NETMAP_MAX_SKEW_MS};
use sha2::{Digest, Sha256};

use crate::error::CoordError;
use crate::netmap::{encode_hex, SignedGrants, SignedNetmap};

/// The coordinator file with the last `seq`.
pub const COORD_SEQ_FILE: &str = "netmap-seq";

/// The node file with the last accepted `seq` and the SHA-256 of its signed bytes.
pub const NODE_SEQ_FILE: &str = "netmap.seq";

/// The coordinator lock file. One signing coordinator process holds it (W25-34).
pub const COORD_SEQ_LOCK_FILE: &str = "netmap-seq.lock";

/// The highest `seq` that the coordinator loads from disk (W25-34, Fix 4).
///
/// A Unix time in milliseconds is far below this value. A stored `seq` near `u64::MAX`
/// would stop all later netmaps, so the coordinator refuses to start with it.
pub const SEQ_MAX: u64 = u64::MAX / 2;

/// The coordinator signs a new stamp for a node netmap at least this often (W25-34).
///
/// Crypto requires 20 s or less. The policy-wait reply comes at the latest at this time.
pub const HEARTBEAT_MS: u64 = 15_000;

const _: () = assert!(
    HEARTBEAT_MS <= 20_000,
    "Crypto requires a heartbeat each 20 s or less."
);

/// The Unix time in milliseconds.
#[must_use]
pub fn unix_ms(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    content: [u8; 32],
    seq: u64,
    issued_at_ms: u64,
}

/// The coordinator `seq` allocator and the last stamp of each node.
#[derive(Debug)]
pub(crate) struct SeqBook {
    path: PathBuf,
    last: u64,
    memo: HashMap<String, Stamp>,
    /// The `seq` on disk at open (`None`: no file, for example an rc.2 state directory).
    /// The book logs the first `seq` after the start once.
    opened_with: Option<Option<u64>>,
    /// The open lock file. The book takes the lock before it writes the first `seq`.
    lock: Option<File>,
}

/// The books of this process, one for each state directory.
type BookMap = HashMap<PathBuf, Weak<Mutex<SeqBook>>>;

/// Give the one book of this process for `dir` (W25-34).
///
/// Two coordinators in one process with the same state directory (for example a restart in a
/// test) use the same book, so they never give the same `seq` to different content. A second
/// process gets an error from the lock file (see [`SeqBook::stamp`]).
pub(crate) fn shared_book(dir: &Path) -> Result<Arc<Mutex<SeqBook>>, CoordError> {
    static BOOKS: OnceLock<Mutex<BookMap>> = OnceLock::new();
    let key = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut books = BOOKS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| CoordError::State)?;
    books.retain(|_, book| book.strong_count() > 0);
    if let Some(book) = books.get(&key).and_then(Weak::upgrade) {
        return Ok(book);
    }
    let book = Arc::new(Mutex::new(SeqBook::open(dir)?));
    books.insert(key, Arc::downgrade(&book));
    Ok(book)
}

impl SeqBook {
    /// Open the book. A missing file gives 0. A file that is not valid stops the coordinator.
    pub(crate) fn open(dir: &Path) -> Result<Self, CoordError> {
        let path = dir.join(COORD_SEQ_FILE);
        let last = read_coord_seq(&path)?;
        let persisted = path.exists().then_some(last);
        Ok(Self {
            path,
            last,
            memo: HashMap::new(),
            opened_with: Some(persisted),
            lock: None,
        })
    }

    /// Take the lock file of the state directory, one time for each book.
    ///
    /// A second coordinator process with the same state directory gets an error, so two
    /// processes never give the same `seq` to different content.
    fn hold_lock(&mut self) -> Result<(), CoordError> {
        if self.lock.is_some() {
            return Ok(());
        }
        let path = self.path.with_file_name(COORD_SEQ_LOCK_FILE);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(CoordError::io)?;
        match file.try_lock() {
            Ok(()) => {
                self.lock = Some(file);
                Ok(())
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                eprintln!(
                    "ALERT netmap seq lock {} is held by another coordinator process",
                    path.display()
                );
                Err(CoordError::Protocol(
                    "Another coordinator process uses this state directory.".to_string(),
                ))
            }
            Err(std::fs::TryLockError::Error(err)) => Err(CoordError::io(err)),
        }
    }

    /// Return the stamp (`seq`, `issued_at_ms`) for the netmap content of one node.
    ///
    /// The same content within [`HEARTBEAT_MS`] gets the same stamp, so the signed bytes stay
    /// the same. Otherwise the book writes and syncs a new `seq` before it returns.
    pub(crate) fn stamp(
        &mut self,
        node: &str,
        content: [u8; 32],
        now_ms: u64,
    ) -> Result<(u64, u64), CoordError> {
        if let Some(old) = self.memo.get(node) {
            // A clock that goes back keeps the old stamp. This stops a reply loop.
            if old.content == content && now_ms < old.issued_at_ms.saturating_add(HEARTBEAT_MS) {
                return Ok((old.seq, old.issued_at_ms));
            }
        }
        self.hold_lock()?;
        // A restore or the reset command can change the file.
        self.last = self.last.max(read_coord_seq(&self.path)?);
        let next = self.last.saturating_add(1);
        // Fix 4 (CLOCK-FORWARD): never sign or write a seq that the nodes refuse.
        if next > now_ms.saturating_add(NETMAP_MAX_SKEW_MS) {
            eprintln!(
                "ALERT netmap seq refuse clock-forward: next seq {next} is more than 60 s \
                 ahead of the coordinator clock now_ms {now_ms}. The coordinator signs no \
                 netmap. Correct the clock, then run `orblx admin netmap-seq-reset`."
            );
            return Err(CoordError::Protocol(
                "The netmap seq is ahead of the coordinator clock.".to_string(),
            ));
        }
        let seq = next.max(now_ms);
        write_synced(&self.path, format!("{seq}\n").as_bytes())?;
        self.last = seq;
        if let Some(persisted) = self.opened_with.take() {
            let persisted = persisted.map_or_else(|| "none".to_string(), |value| value.to_string());
            println!(
                "netmap seq first after start: persisted {persisted} seq {seq} issued_at_ms {now_ms} \
                 (seq = max(persisted + 1, issued_at_ms))"
            );
        }
        self.memo.insert(
            node.to_string(),
            Stamp {
                content,
                seq,
                issued_at_ms: now_ms,
            },
        );
        Ok((seq, now_ms))
    }

    /// Set the stored `seq` to `now_ms` after a clock-forward error (W25-34, Fix 4).
    ///
    /// The call works only when the stored `seq` is ahead of `now_ms`. It never sets a value
    /// below `now_ms`. It returns the old and the new `seq`. The caller writes the audit
    /// record. The book forgets all stamps, so each node gets a new stamp.
    pub(crate) fn reset_to_now(&mut self, now_ms: u64) -> Result<(u64, u64), CoordError> {
        self.hold_lock()?;
        let old = self.last.max(read_coord_seq(&self.path)?);
        if old <= now_ms {
            return Err(CoordError::Protocol(
                "The stored netmap seq is not ahead of the coordinator clock. No change."
                    .to_string(),
            ));
        }
        write_synced(&self.path, format!("{now_ms}\n").as_bytes())?;
        self.last = now_ms;
        self.memo.clear();
        eprintln!("ALERT netmap seq reset from {old} to now_ms {now_ms}");
        Ok((old, now_ms))
    }

    /// The time until the stamp of one node needs a heartbeat.
    pub(crate) fn heartbeat_in(&self, node: &str, now_ms: u64) -> Duration {
        let due = self
            .memo
            .get(node)
            .map_or(0, |old| old.issued_at_ms.saturating_add(HEARTBEAT_MS));
        Duration::from_millis(due.saturating_sub(now_ms))
    }

    #[cfg(test)]
    pub(crate) fn last(&self) -> u64 {
        self.last
    }
}

fn read_coord_seq(path: &Path) -> Result<u64, CoordError> {
    let seq = match fs::read_to_string(path) {
        Ok(text) => text.trim().parse::<u64>().map_err(|_| {
            CoordError::Protocol(format!("The file {} is not valid.", path.display()))
        })?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(CoordError::io(err)),
    };
    // Fix 4: a seq near u64::MAX would stop all later netmaps.
    if seq > SEQ_MAX {
        eprintln!(
            "ALERT netmap seq refuse load: the file {} has seq {seq}, above the limit {SEQ_MAX}",
            path.display()
        );
        return Err(CoordError::Protocol(format!(
            "The file {} has a netmap seq that is too large.",
            path.display()
        )));
    }
    Ok(seq)
}

/// Write a file through a temp file, sync it, rename it, and sync the directory.
pub(crate) fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), CoordError> {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(CoordError::io)?;
        file.write_all(bytes).map_err(CoordError::io)?;
        file.sync_all().map_err(CoordError::io)?;
    }
    fs::rename(&tmp, path).map_err(CoordError::io)?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(CoordError::io)?;
    }
    Ok(())
}

/// The result of one netmap intake on a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intake {
    /// A higher `seq`. The node writes the netmap and the new `seq`.
    New,
    /// The same `seq` and the same signed bytes. The node changes no state.
    Same,
}

/// The SHA-256 of the signed netmap bytes in hex.
#[must_use]
pub fn signed_digest(signed: &SignedNetmap) -> String {
    encode_hex(&Sha256::digest(signed.signed_bytes()))
}

/// Decide if a node accepts one verified netmap (W25-34).
///
/// The caller checked the signature. The function does not write a file.
pub fn node_intake(dir: &Path, signed: &SignedNetmap, now_ms: u64) -> Result<Intake, CoordError> {
    let seq = signed.netmap.seq;
    if seq == 0 || signed.netmap.issued_at_ms == 0 {
        eprintln!("netmap refuse no-stamp");
        return Err(refused("The netmap has no signed seq."));
    }
    let limit = now_ms.saturating_add(NETMAP_MAX_SKEW_MS);
    // Fix 2: the issue time bounds every intake, with or without a netmap.seq file.
    if now_ms.saturating_sub(signed.netmap.issued_at_ms) > NETMAP_MAX_AGE_MS {
        eprintln!(
            "netmap refuse stale issued_at_ms {} now_ms {now_ms}",
            signed.netmap.issued_at_ms
        );
        return Err(refused("The netmap is more than 60 s old."));
    }
    if seq > limit || signed.netmap.issued_at_ms > limit {
        eprintln!("netmap refuse seq-future seq {seq} now_ms {now_ms}");
        return Err(refused("The netmap seq is in the future."));
    }
    // seq follows the coordinator clock. A seq more than 60 s above the signed issue time
    // means that the coordinator clock went back. Fail closed until the clock passes it.
    if seq
        > signed
            .netmap
            .issued_at_ms
            .saturating_add(NETMAP_MAX_SKEW_MS)
    {
        eprintln!(
            "ALERT netmap refuse coord-clock-back seq {seq} issued_at_ms {}",
            signed.netmap.issued_at_ms
        );
        return Err(refused("The coordinator clock is behind the netmap seq."));
    }
    let Some((last, digest)) = read_node_seq_or_set_aside(dir, now_ms)? else {
        return Ok(Intake::New);
    };
    if seq < last {
        eprintln!("netmap refuse seq-lower seq {seq} last {last}");
        return Err(refused("The netmap seq is lower than the last seq."));
    }
    if seq == last {
        if digest == signed_digest(signed) {
            return Ok(Intake::Same);
        }
        eprintln!("ALERT netmap refuse seq-replay seq {seq}: the same seq has different content");
        return Err(refused(
            "The netmap seq is the same, and the content is different.",
        ));
    }
    Ok(Intake::New)
}

/// Check that the signed netmap carries the digest of the signed grants (W25-34, Fix 5).
///
/// The caller checked both signatures. A fresh netmap with older grants is refused.
pub fn check_grants_binding(
    netmap: &SignedNetmap,
    grants: &SignedGrants,
) -> Result<(), CoordError> {
    let digest = grants.digest_hex();
    if netmap.netmap.grants_sha256 == digest {
        return Ok(());
    }
    eprintln!(
        "ALERT netmap refuse grants-mismatch seq {}: the netmap does not bind these grants",
        netmap.netmap.seq
    );
    Err(refused("The netmap does not match the grants."))
}

/// Read the last accepted `seq`. A corrupt file is an ALERT (W25-34, Fix 3).
///
/// The node moves a corrupt file aside to `netmap.seq.corrupt-NOW_MS` and continues as if
/// the file is missing. The 60 s `issued_at_ms` check in [`node_intake`] limits the rollback.
fn read_node_seq_or_set_aside(
    dir: &Path,
    now_ms: u64,
) -> Result<Option<(u64, String)>, CoordError> {
    match read_node_seq(dir) {
        Ok(value) => Ok(value),
        Err(CoordError::Protocol(_)) => {
            let path = dir.join(NODE_SEQ_FILE);
            let aside = dir.join(format!("{NODE_SEQ_FILE}.corrupt-{now_ms}"));
            fs::rename(&path, &aside).map_err(CoordError::io)?;
            eprintln!(
                "ALERT netmap seq file {} is corrupt. The node moved it to {} and accepts the \
                 next netmap that is less than 60 s old.",
                path.display(),
                aside.display()
            );
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// Write the last accepted `seq` and digest, synced (W25-34).
pub fn record_node_seq(dir: &Path, signed: &SignedNetmap) -> Result<(), CoordError> {
    let text = format!("{} {}\n", signed.netmap.seq, signed_digest(signed));
    write_synced(&dir.join(NODE_SEQ_FILE), text.as_bytes())
}

/// Read the last accepted `seq` and digest. A file that is not valid gives a protocol error.
pub fn read_node_seq(dir: &Path) -> Result<Option<(u64, String)>, CoordError> {
    let path = dir.join(NODE_SEQ_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
            return Err(CoordError::Protocol(format!(
                "The file {} is not valid.",
                path.display()
            )));
        }
        Err(err) => return Err(CoordError::io(err)),
    };
    let invalid = || CoordError::Protocol(format!("The file {} is not valid.", path.display()));
    let mut parts = text.split_whitespace();
    let seq = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(invalid)?;
    let digest = parts.next().ok_or_else(invalid)?.to_string();
    if parts.next().is_some() || digest.len() != 64 {
        return Err(invalid());
    }
    Ok(Some((seq, digest)))
}

/// Clear the last accepted `seq` for a new enrollment (the local reset).
pub fn reset_node_seq(dir: &Path) -> Result<(), CoordError> {
    match fs::remove_file(dir.join(NODE_SEQ_FILE)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CoordError::io(err)),
    }
}

fn refused(text: &str) -> CoordError {
    CoordError::Protocol(text.to_string())
}

#[cfg(test)]
mod tests {
    use orblx_datapath::{netmap_fresh, Netmap, NetmapPeer, NetmapSelf};

    use super::{node_intake, record_node_seq, reset_node_seq, Intake, SeqBook, HEARTBEAT_MS};
    use crate::netmap::{NetmapKey, SignedNetmap};

    const T0: u64 = 1_800_000_000_000;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orblx-seq-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn netmap(peer_ip: &str, seq: u64, issued_at_ms: u64) -> Netmap {
        Netmap {
            version: 1,
            self_node: NetmapSelf {
                name: "a".to_string(),
                overlay_ip: "100.64.0.1".to_string(),
                owner: String::new(),
            },
            peers: vec![NetmapPeer {
                name: "b".to_string(),
                overlay_ip: peer_ip.to_string(),
                svid: "spiffe://orblx.local/node/b".to_string(),
                endpoints: vec!["10.0.0.2:443".to_string()],
                routes: Vec::new(),
                exit_node: false,
                owner: String::new(),
                lock_sig: None,
            }],
            lock: Vec::new(),
            split_dns: Vec::new(),
            seq,
            issued_at_ms,
            grants_sha256: String::new(),
        }
    }

    fn signed(key: &NetmapKey, peer_ip: &str, seq: u64, issued_at_ms: u64) -> SignedNetmap {
        key.sign_netmap(&netmap(peer_ip, seq, issued_at_ms))
            .unwrap()
    }

    fn accept(dir: &std::path::Path, item: &SignedNetmap, now: u64) -> Result<Intake, String> {
        let intake = node_intake(dir, item, now).map_err(|err| err.to_string())?;
        if intake == Intake::New {
            record_node_seq(dir, item).unwrap();
        }
        Ok(intake)
    }

    #[test]
    fn seq_is_max_of_last_plus_one_and_issue_time() {
        let dir = temp_dir("max");
        let mut book = SeqBook::open(&dir).unwrap();
        assert_eq!(book.stamp("a", [1; 32], T0).unwrap(), (T0, T0));
        // A content change in the same millisecond gets last + 1.
        assert_eq!(book.stamp("a", [2; 32], T0).unwrap(), (T0 + 1, T0));
        assert_eq!(book.stamp("b", [2; 32], T0).unwrap(), (T0 + 2, T0));
        assert_eq!(book.last(), T0 + 2);
        let text = std::fs::read_to_string(dir.join(super::COORD_SEQ_FILE)).unwrap();
        assert_eq!(text.trim(), (T0 + 2).to_string());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn heartbeat_restamps_the_same_content() {
        let dir = temp_dir("beat");
        let mut book = SeqBook::open(&dir).unwrap();
        let first = book.stamp("a", [1; 32], T0).unwrap();
        assert_eq!(book.stamp("a", [1; 32], T0 + 14_999).unwrap(), first);
        assert_eq!(
            book.heartbeat_in("a", T0 + 10_000),
            std::time::Duration::from_millis(5_000)
        );
        let beat = book.stamp("a", [1; 32], T0 + HEARTBEAT_MS).unwrap();
        assert_eq!(beat, (T0 + HEARTBEAT_MS, T0 + HEARTBEAT_MS));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn seq_never_drops_on_restart_or_reload() {
        let dir = temp_dir("restart");
        let mut book = SeqBook::open(&dir).unwrap();
        for step in 0..5 {
            book.stamp("a", [step; 32], T0).unwrap();
        }
        let before = book.last();
        drop(book);
        // A restart with the same disk and a clock in the past still goes up.
        let mut again = SeqBook::open(&dir).unwrap();
        let (seq, _) = again.stamp("a", [9; 32], T0 - 1_000).unwrap();
        assert!(seq > before);
        // A state reload: another writer put a higher seq on disk.
        std::fs::write(dir.join(super::COORD_SEQ_FILE), format!("{}\n", seq + 500)).unwrap();
        let (next, _) = again.stamp("a", [10; 32], T0).unwrap();
        assert_eq!(next, seq + 501);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restart_with_empty_disk_gives_a_higher_seq() {
        let key = NetmapKey::generate();
        let old_dir = temp_dir("empty-old");
        let node = temp_dir("empty-node");
        let mut book = SeqBook::open(&old_dir).unwrap();
        let (seq, at) = book.stamp("a", [1; 32], T0).unwrap();
        accept(&node, &signed(&key, "100.64.0.2", seq, at), T0).unwrap();
        // The coordinator restarts with no state 1 s later.
        let new_dir = temp_dir("empty-new");
        let mut fresh = SeqBook::open(&new_dir).unwrap();
        let (seq2, at2) = fresh.stamp("a", [1; 32], T0 + 1_000).unwrap();
        assert!(seq2 > seq);
        assert_eq!(
            accept(&node, &signed(&key, "100.64.0.2", seq2, at2), T0 + 1_000),
            Ok(Intake::New)
        );
        for dir in [old_dir, new_dir, node] {
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn backup_restore_gives_a_higher_seq_with_no_operator_step() {
        let key = NetmapKey::generate();
        let dir = temp_dir("backup");
        let node = temp_dir("backup-node");
        let mut book = SeqBook::open(&dir).unwrap();
        let (pre, _) = book.stamp("a", [1; 32], T0).unwrap();
        let backup = std::fs::read(dir.join(super::COORD_SEQ_FILE)).unwrap();
        // The coordinator keeps working after the backup. The node gets those netmaps.
        let mut last = (0, 0);
        for step in 2..40 {
            last = book.stamp("a", [step; 32], T0 + 1_000).unwrap();
        }
        accept(
            &node,
            &signed(&key, "100.64.0.2", last.0, last.1),
            T0 + 1_000,
        )
        .unwrap();
        drop(book);
        // Restore the backup and start 2 s later.
        std::fs::write(dir.join(super::COORD_SEQ_FILE), backup).unwrap();
        let mut restored = SeqBook::open(&dir).unwrap();
        let (seq, at) = restored.stamp("a", [1; 32], T0 + 3_000).unwrap();
        assert!(seq > pre);
        assert!(seq > last.0);
        assert_eq!(
            accept(&node, &signed(&key, "100.64.0.2", seq, at), T0 + 3_000),
            Ok(Intake::New)
        );
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&node).unwrap();
    }

    #[test]
    fn node_refuses_lower_replay_and_future_seq() {
        let key = NetmapKey::generate();
        let node = temp_dir("intake");
        let first = signed(&key, "100.64.0.2", T0, T0);
        // No state: the first valid netmap is accepted.
        assert_eq!(accept(&node, &first, T0), Ok(Intake::New));
        // The same seq and the same bytes: a no-op.
        assert_eq!(accept(&node, &first, T0 + 50_000), Ok(Intake::Same));
        // The same seq and other content: refused.
        let other = signed(&key, "100.64.0.3", T0, T0);
        assert!(accept(&node, &other, T0).is_err());
        // A lower seq: refused.
        let lower = signed(&key, "100.64.0.3", T0 - 1, T0 - 1);
        assert!(accept(&node, &lower, T0).is_err());
        // A seq more than 60 s in the future: refused. 60 s exactly is accepted.
        let future = signed(&key, "100.64.0.3", T0 + 60_001, T0 + 60_001);
        assert!(accept(&node, &future, T0).is_err());
        let edge = signed(&key, "100.64.0.3", T0 + 60_000, T0 + 60_000);
        assert_eq!(accept(&node, &edge, T0), Ok(Intake::New));
        // No stamp: refused.
        let none = signed(&key, "100.64.0.3", 0, 0);
        assert!(accept(&node, &none, T0).is_err());
        // The seq file stays.
        let (seq, _) = super::read_node_seq(&node).unwrap().unwrap();
        assert_eq!(seq, T0 + 60_000);
        // Only a local reset accepts a lower seq.
        reset_node_seq(&node).unwrap();
        assert_eq!(accept(&node, &lower, T0), Ok(Intake::New));
        std::fs::remove_dir_all(&node).unwrap();
    }

    #[test]
    fn clock_back_more_than_60_s_fails_closed_until_the_clock_passes() {
        let key = NetmapKey::generate();
        let dir = temp_dir("clock");
        let node = temp_dir("clock-node");
        let mut book = SeqBook::open(&dir).unwrap();
        let (seq, at) = book.stamp("a", [1; 32], T0).unwrap();
        accept(&node, &signed(&key, "100.64.0.2", seq, at), T0).unwrap();
        // The coordinator clock goes back 10 min. The node clock is correct.
        // Fix 4: the coordinator signs nothing and writes nothing (fail closed, loud).
        let back = T0 - 600_000;
        assert!(book.stamp("a", [2; 32], back).is_err());
        assert_eq!(book.last(), seq);
        // A netmap with such a stamp (for example from an older coordinator) is refused:
        // seq is more than 60 s above the signed issue time.
        let (seq2, at2) = (seq + 1, back);
        assert!(accept(&node, &signed(&key, "100.64.0.3", seq2, at2), T0 + 1_000).is_err());
        assert!(!netmap_fresh(at2, T0 + 1_000));
        // A node that has the same wrong clock refuses it too.
        let node2 = temp_dir("clock-node2");
        assert!(accept(&node2, &signed(&key, "100.64.0.3", seq2, at2), back).is_err());
        // The coordinator clock passes the seq: the nodes accept again with no reset.
        let (seq3, at3) = book.stamp("a", [3; 32], T0 + 2_000).unwrap();
        assert_eq!(
            accept(&node, &signed(&key, "100.64.0.3", seq3, at3), T0 + 2_000),
            Ok(Intake::New)
        );
        for dir in [dir, node, node2] {
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Crypto Fix 2: the 60 s issue-time bounds apply with and without a seq file.
    #[test]
    fn intake_refuses_old_or_future_issue_time_with_or_without_seq_state() {
        let key = NetmapKey::generate();
        let node = temp_dir("fix2");
        // No netmap.seq file.
        let old = signed(&key, "100.64.0.2", T0 - 60_001, T0 - 60_001);
        assert!(accept(&node, &old, T0).is_err());
        let ahead = signed(&key, "100.64.0.2", T0 + 60_001, T0 + 60_001);
        assert!(accept(&node, &ahead, T0).is_err());
        let edge = signed(&key, "100.64.0.2", T0 - 60_000, T0 - 60_000);
        assert_eq!(accept(&node, &edge, T0), Ok(Intake::New));
        // With a netmap.seq file: a higher seq with an old issue time is refused.
        let high_old = signed(&key, "100.64.0.3", T0 + 1, T0 - 60_001);
        assert!(accept(&node, &high_old, T0).is_err());
        // The same bytes again after 60 s: refused (no refresh of freshness).
        assert!(accept(&node, &edge, T0 + 1).is_err());
        std::fs::remove_dir_all(&node).unwrap();
    }

    /// Crypto Fix 3: a corrupt seq file is moved aside and the node continues as with a
    /// missing file. The issue-time check still applies.
    #[test]
    fn corrupt_seq_file_is_set_aside_and_missing_file_is_accepted() {
        let key = NetmapKey::generate();
        // Missing file: the first fresh netmap is accepted.
        let missing = temp_dir("fix3-missing");
        let fresh = signed(&key, "100.64.0.2", T0, T0);
        assert_eq!(accept(&missing, &fresh, T0), Ok(Intake::New));
        for (label, bytes) in [
            (
                "text",
                b"not a seq
"
                .to_vec(),
            ),
            (
                "short",
                b"123 abc
"
                .to_vec(),
            ),
            ("binary", vec![0xff, 0xfe, 0x00, 0x41]),
            ("empty", Vec::new()),
        ] {
            let node = temp_dir(&format!("fix3-{label}"));
            let path = node.join(super::NODE_SEQ_FILE);
            std::fs::write(&path, &bytes).unwrap();
            // A stale netmap is still refused, and the file is moved aside.
            let stale = signed(&key, "100.64.0.2", T0 - 60_001, T0 - 60_001);
            assert!(accept(&node, &stale, T0).is_err(), "{label}");
            // A fresh netmap is accepted. The corrupt file is moved aside.
            assert_eq!(accept(&node, &fresh, T0), Ok(Intake::New), "{label}");
            let aside: Vec<_> = std::fs::read_dir(&node)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("netmap.seq.corrupt-")
                })
                .collect();
            assert_eq!(aside.len(), 1, "{label}");
            assert_eq!(std::fs::read(aside[0].path()).unwrap(), bytes, "{label}");
            let (seq, _) = super::read_node_seq(&node).unwrap().unwrap();
            assert_eq!(seq, T0, "{label}");
            std::fs::remove_dir_all(&node).unwrap();
        }
        std::fs::remove_dir_all(&missing).unwrap();
    }

    /// Crypto Fix 4: a clock jump forward, then back. The coordinator refuses to sign, and
    /// the reset command corrects the stored seq.
    #[test]
    fn clock_forward_then_back_refuses_to_sign_until_the_reset() {
        let key = NetmapKey::generate();
        let dir = temp_dir("fix4");
        let node = temp_dir("fix4-node");
        let mut book = SeqBook::open(&dir).unwrap();
        let (seq, at) = book.stamp("a", [1; 32], T0).unwrap();
        accept(&node, &signed(&key, "100.64.0.2", seq, at), T0).unwrap();
        // The coordinator clock jumps 1 day forward. The book signs at that time.
        // The node (correct clock) refuses that seq as more than 60 s in the future.
        let jump = T0 + 86_400_000;
        let (far, far_at) = book.stamp("a", [2; 32], jump).unwrap();
        assert_eq!(far, jump);
        assert!(accept(&node, &signed(&key, "100.64.0.3", far, far_at), T0 + 1_000).is_err());
        // The clock is corrected. The book refuses to sign and does not write the file.
        let path = dir.join(super::COORD_SEQ_FILE);
        let before = std::fs::read(&path).unwrap();
        assert!(book.stamp("a", [3; 32], T0 + 2_000).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // The reset sets the stored seq to the clock time, never lower.
        assert_eq!(book.reset_to_now(T0 + 3_000).unwrap(), (jump, T0 + 3_000));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            (T0 + 3_000).to_string()
        );
        // A second reset is refused: the stored seq is not ahead of the clock.
        assert!(book.reset_to_now(T0 + 3_000).is_err());
        assert!(book.reset_to_now(T0 + 4_000).is_err());
        // The book signs again, and the node accepts with no manual step.
        let (next, next_at) = book.stamp("a", [3; 32], T0 + 4_000).unwrap();
        assert_eq!(next, T0 + 4_000);
        assert_eq!(
            accept(
                &node,
                &signed(&key, "100.64.0.3", next, next_at),
                T0 + 4_000
            ),
            Ok(Intake::New)
        );
        for dir in [dir, node] {
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Crypto Fix 4: a stored seq near u64::MAX stops the load.
    #[test]
    fn stored_seq_near_u64_max_is_refused_at_load() {
        let dir = temp_dir("fix4-max");
        let path = dir.join(super::COORD_SEQ_FILE);
        std::fs::write(&path, format!("{}\n", u64::MAX)).unwrap();
        assert!(SeqBook::open(&dir).is_err());
        std::fs::write(&path, format!("{}\n", super::SEQ_MAX + 1)).unwrap();
        assert!(SeqBook::open(&dir).is_err());
        std::fs::write(&path, format!("{}\n", super::SEQ_MAX)).unwrap();
        assert!(SeqBook::open(&dir).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two coordinator processes cannot sign with the same state directory.
    #[test]
    fn a_second_book_on_the_same_dir_cannot_sign() {
        let dir = temp_dir("lock");
        let mut first = SeqBook::open(&dir).unwrap();
        first.stamp("a", [1; 32], T0).unwrap();
        let mut second = SeqBook::open(&dir).unwrap();
        assert!(second.stamp("a", [2; 32], T0).is_err());
        assert!(second.reset_to_now(T0).is_err());
        drop(first);
        assert!(second.stamp("a", [2; 32], T0).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two coordinators in one process with the same state directory share one book.
    #[test]
    fn one_process_shares_one_book_for_a_dir() {
        let dir = temp_dir("shared");
        let first = super::shared_book(&dir).unwrap();
        let second = super::shared_book(&dir).unwrap();
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        let (seq, _) = first.lock().unwrap().stamp("a", [1; 32], T0).unwrap();
        let (next, _) = second.lock().unwrap().stamp("a", [2; 32], T0).unwrap();
        assert!(next > seq);
        drop((first, second));
        let third = super::shared_book(&dir).unwrap();
        assert_eq!(third.lock().unwrap().last, next);
        drop(third);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Crypto Fix 5: a fresh netmap with older grants is refused.
    #[test]
    fn netmap_binds_the_signed_grants() {
        use orblx_identity::ReceiverGrants;
        let key = NetmapKey::generate();
        let grants = |reach: &str| {
            let text = format!(
                r#"{{"version":1,"receiver":"spiffe://orblx.local/node/a","grants":[],"reach":[{reach}]}}"#
            );
            key.sign_grants(&serde_json::from_str::<ReceiverGrants>(&text).unwrap())
                .unwrap()
        };
        let old_grants = grants(r#""spiffe://orblx.local/node/b""#);
        let new_grants = grants("");
        let mut payload = netmap("100.64.0.2", T0, T0);
        payload.grants_sha256 = new_grants.digest_hex();
        let bound = key.sign_netmap(&payload).unwrap();
        assert!(super::check_grants_binding(&bound, &new_grants).is_ok());
        assert!(super::check_grants_binding(&bound, &old_grants).is_err());
        // A netmap with no binding is refused.
        let unbound = signed(&key, "100.64.0.2", T0, T0);
        assert!(super::check_grants_binding(&unbound, &new_grants).is_err());
        // The field is inside the signature: a change fails the signature check.
        let mut wire: serde_json::Value = serde_json::to_value(bound.to_wire()).unwrap();
        wire["netmap"]["grants_sha256"] = serde_json::Value::String(old_grants.digest_hex());
        let wire: crate::netmap::SignedNetmapWire = serde_json::from_value(wire).unwrap();
        assert!(crate::netmap::verify_netmap_wire(&wire, &key.public()).is_err());
    }

    #[test]
    fn netmap_age_uses_the_signed_issue_time() {
        assert!(netmap_fresh(T0, T0 + 60_000));
        assert!(!netmap_fresh(T0, T0 + 60_001));
        assert!(netmap_fresh(T0 + 60_000, T0));
        assert!(!netmap_fresh(T0 + 60_001, T0));
        assert!(!netmap_fresh(0, T0));
    }
}
