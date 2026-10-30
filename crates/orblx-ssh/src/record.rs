//! SSH session recording.
//!
//! The format is asciicast version 2.
//! Line 1 is the header.
//! Each later line is `[seconds, "i", text]` or `[seconds, "o", text]`.
//! `i` is the command of this session. `o` is the output of this session.
//! One file holds one session. The file does not hold other sessions.
//! The recorder does not write the SVID proof, the ticket, or the environment.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// The recording directory name in the node state directory.
pub(crate) const RECORD_DIR: &str = "recordings";

/// The largest recording file in bytes.
///
/// A session that writes more output fails closed.
pub(crate) const MAX_RECORDING: u64 = 16 * 1024 * 1024;

/// One open session recording.
pub(crate) struct Recorder {
    file: File,
    path: PathBuf,
    relative: String,
    written: u64,
}

impl Recorder {
    /// Create a new recording file and write the header.
    ///
    /// The function fails when the directory is read-only or the disk fails.
    pub(crate) fn create(state_dir: &Path, frame: u32, user: &str) -> io::Result<Self> {
        let dir = state_dir.join(RECORD_DIR);
        fs::create_dir_all(&dir)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let name = format!("ssh-{}-{frame}.cast", now.as_nanos());
        let path = dir.join(&name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        let mut recorder = Self {
            file,
            path,
            relative: format!("{RECORD_DIR}/{name}"),
            written: 0,
        };
        let header = serde_json::json!({
            "version": 2,
            "width": 80,
            "height": 24,
            "timestamp": now.as_secs(),
            "env": { "ORBLX_SSH_USER": user },
        });
        recorder.line(&header.to_string())?;
        Ok(recorder)
    }

    /// Write one event.
    ///
    /// `code` is `i` for the command or `o` for output.
    /// Bytes that are not UTF-8 become U+FFFD in the file.
    pub(crate) fn event(&mut self, at: Duration, code: &str, data: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(data);
        let row = serde_json::json!([at.as_secs_f64(), code, text]);
        self.line(&row.to_string())
    }

    fn line(&mut self, text: &str) -> io::Result<()> {
        let size = u64::try_from(text.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if self.written.saturating_add(size) > MAX_RECORDING {
            return Err(io::Error::other("The recording is too large."));
        }
        self.file.write_all(text.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.written = self.written.saturating_add(size);
        Ok(())
    }

    /// Close the file and return its relative path and its SHA-256.
    ///
    /// The SHA-256 covers the bytes on disk after `sync_all`.
    pub(crate) fn finish(self) -> io::Result<(String, [u8; 32])> {
        self.file.sync_all()?;
        drop(self.file);
        let bytes = fs::read(&self.path)?;
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&Sha256::digest(&bytes));
        Ok((self.relative, sha256))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sha2::{Digest, Sha256};

    use super::{Recorder, RECORD_DIR};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("orblx-rec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_recording_holds_the_header_the_command_and_the_output() {
        let dir = temp_dir("ok");
        let mut recorder = Recorder::create(&dir, 7, "rec").unwrap();
        recorder.event(Duration::ZERO, "i", b"echo hi").unwrap();
        recorder
            .event(Duration::from_millis(15), "o", b"hi\n")
            .unwrap();
        let (relative, sha256) = recorder.finish().unwrap();
        assert!(relative.starts_with(&format!("{RECORD_DIR}/ssh-")));
        let bytes = std::fs::read(dir.join(&relative)).unwrap();
        assert_eq!(Sha256::digest(&bytes).as_slice(), sha256.as_slice());
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"version\":2"));
        assert!(lines[1].contains("\"i\"") && lines[1].contains("echo hi"));
        assert!(lines[2].contains("\"o\"") && lines[2].contains("hi\\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_recording_fails_when_the_directory_cannot_open() {
        let dir = temp_dir("bad");
        std::fs::write(dir.join(RECORD_DIR), b"not a directory").unwrap();
        assert!(Recorder::create(&dir, 1, "rec").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
