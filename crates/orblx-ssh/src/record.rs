//! SSH session recording.
//!
//! The format is asciicast version 2.
//! Line 1 is the header.
//! Each later line is `[seconds, code, text]`.
//! For an exec session, `i` is the command and `o` is the output.
//! For a PTY shell session, `i` is the input of the session user, `o` is the
//! terminal output, `r` is a terminal size change, and `m` marks input that the
//! recorder hides because the terminal echo is off (for example a password prompt).
//! The events are in time order.
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
        Self::create_sized(state_dir, frame, user, 80, 24, None)
    }

    /// Create a new recording file for a terminal of one size.
    ///
    /// `term` is the terminal type of a PTY session. An exec session has none.
    pub(crate) fn create_sized(
        state_dir: &Path,
        frame: u32,
        user: &str,
        width: u16,
        height: u16,
        term: Option<&str>,
    ) -> io::Result<Self> {
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
        let mut env = serde_json::Map::new();
        env.insert("ORBLX_SSH_USER".to_string(), user.into());
        if let Some(term) = term {
            env.insert("TERM".to_string(), term.into());
        }
        let header = serde_json::json!({
            "version": 2,
            "width": width,
            "height": height,
            "timestamp": now.as_secs(),
            "env": env,
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

    /// Write one event with text that is already UTF-8.
    /// The time is in seconds with microsecond steps, so it prints short.
    pub(crate) fn event_text(&mut self, at: Duration, code: &str, text: &str) -> io::Result<()> {
        let micros = u64::try_from(at.as_micros()).unwrap_or(u64::MAX);
        #[allow(clippy::cast_precision_loss)]
        let seconds = micros as f64 / 1_000_000.0;
        let row = serde_json::json!([seconds, code, text]);
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

/// Joins UTF-8 text that a read cut in two.
///
/// A PTY read can end in the middle of a character.
/// The carry keeps up to 3 bytes of an incomplete character for the next read.
#[derive(Default)]
pub(crate) struct Utf8Carry {
    tail: Vec<u8>,
}

impl Utf8Carry {
    /// Return the complete text and keep an incomplete last character.
    ///
    /// Bytes that are not UTF-8 become U+FFFD.
    pub(crate) fn take(&mut self, data: &[u8]) -> String {
        let mut bytes = std::mem::take(&mut self.tail);
        bytes.extend_from_slice(data);
        let mut text = String::new();
        let mut rest = bytes.as_slice();
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    text.push_str(valid);
                    break;
                }
                Err(err) => {
                    let (valid, after) = rest.split_at(err.valid_up_to());
                    text.push_str(std::str::from_utf8(valid).unwrap_or_default());
                    match err.error_len() {
                        Some(bad) => {
                            text.push('\u{FFFD}');
                            rest = &after[bad..];
                        }
                        None => {
                            self.tail = after.to_vec();
                            break;
                        }
                    }
                }
            }
        }
        text
    }
}

#[cfg(test)]
impl Recorder {
    /// Wrap a file that fails on write, for the fail-closed tests.
    pub(crate) fn from_file_for_test(file: File, path: PathBuf) -> Self {
        Self {
            file,
            path,
            relative: format!("{RECORD_DIR}/test.cast"),
            written: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sha2::{Digest, Sha256};

    use super::{Recorder, Utf8Carry, RECORD_DIR};

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

    #[test]
    fn the_carry_joins_a_character_that_a_read_cut_in_two() {
        let mut carry = Utf8Carry::default();
        let text = "a\u{d55c}b".as_bytes();
        assert_eq!(carry.take(&text[..2]), "a");
        assert_eq!(carry.take(&text[2..]), "\u{d55c}b");
        assert_eq!(carry.take(&[0xff, b'x']), "\u{FFFD}x");
    }

    #[test]
    fn a_pty_header_holds_the_size_and_the_terminal_type() {
        let dir = temp_dir("pty");
        let recorder = Recorder::create_sized(&dir, 3, "rec", 120, 40, Some("xterm")).unwrap();
        let (relative, _) = recorder.finish().unwrap();
        let text = std::fs::read_to_string(dir.join(relative)).unwrap();
        let header: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(header["width"], 120);
        assert_eq!(header["height"], 40);
        assert_eq!(header["env"]["TERM"], "xterm");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
