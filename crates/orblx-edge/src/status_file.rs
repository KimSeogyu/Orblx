//! The status file writer of a NAT node (W25-29).
//!
//! The router thread is the only reader of the TUN device. Before W25-29, it wrote the status
//! file itself each 500 ms. A slow file write (for example, a busy disk under the state volume)
//! then stopped the TUN reads, and the packets waited in the TUN queue.
//! Now the router thread only posts the newest text. One status thread writes the file.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// The name of the temporary file next to the status file.
const TMP_NAME: &str = "status.txt.tmp";

/// The newest status text that waits for the status thread.
pub(crate) struct StatusFile {
    path: PathBuf,
    tmp: PathBuf,
    pending: Mutex<Option<String>>,
    ready: Condvar,
}

impl StatusFile {
    /// A writer for `file_name` in `dir`.
    pub(crate) fn new(dir: &Path, file_name: &str) -> Self {
        Self {
            path: dir.join(file_name),
            tmp: dir.join(TMP_NAME),
            pending: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    /// Keep `text` for the status thread. The call does not touch the disk.
    ///
    /// A newer text replaces a text that the thread did not write yet.
    pub(crate) fn post(&self, text: String) {
        *self.lock() = Some(text);
        self.ready.notify_one();
    }

    /// Write `text` now, in the caller thread.
    pub(crate) fn write_now(&self, text: &str) {
        if fs::write(&self.tmp, text.as_bytes()).is_ok() {
            let _ = fs::rename(&self.tmp, &self.path);
        }
    }

    /// Write each posted text until `stopped` returns true.
    pub(crate) fn run(&self, stopped: impl Fn() -> bool) {
        while !stopped() {
            let text = {
                let mut pending = self.lock();
                if pending.is_none() {
                    pending = self
                        .ready
                        .wait_timeout(pending, Duration::from_millis(200))
                        .map_or_else(|err| err.into_inner().0, |(guard, _)| guard);
                }
                pending.take()
            };
            if let Some(text) = text {
                self.write_now(&text);
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<String>> {
        self.pending.lock().unwrap_or_else(|err| err.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::{StatusFile, TMP_NAME};
    use std::ffi::CString;
    use std::fs;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    struct Dir(PathBuf);

    impl Dir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "orblx-status-{label}-{}-{:?}",
                std::process::id(),
                thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Put a FIFO at the temporary file path. A write to it waits until a reader opens it.
    /// This is a disk write that does not end until the test lets it end.
    fn block_tmp(dir: &Path) -> PathBuf {
        let tmp = dir.join(TMP_NAME);
        let text = CString::new(tmp.as_os_str().as_bytes()).unwrap();
        // SAFETY: `text` is a valid C string that lives for the call.
        let made = unsafe { libc::mkfifo(text.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo failed");
        tmp
    }

    /// Open the FIFO for reading and read what the writer wrote.
    fn release(tmp: &Path) -> String {
        let mut text = String::new();
        fs::File::open(tmp)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        text
    }

    /// W25-29: a status write that does not end does not stop the caller of `post`.
    /// When the write ends, the status file gets the newest text.
    #[test]
    fn a_blocked_status_write_does_not_stop_the_poster() {
        let dir = Dir::new("post");
        let tmp = block_tmp(&dir.0);
        let file = Arc::new(StatusFile::new(&dir.0, "status.txt"));
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let file = Arc::clone(&file);
            let stop = Arc::clone(&stop);
            thread::spawn(move || file.run(|| stop.load(Ordering::Relaxed)))
        };
        file.post("path direct\n".to_string());
        // Give the status thread time to start the write that waits.
        thread::sleep(Duration::from_millis(100));
        let mut slowest = Duration::ZERO;
        for index in 0..100 {
            let started = Instant::now();
            file.post(format!("path relay {index}\n"));
            slowest = slowest.max(started.elapsed());
        }
        println!("status_post slowest_us {}", slowest.as_micros());
        assert!(
            slowest < Duration::from_millis(20),
            "one post took {} ms while the status write waited",
            slowest.as_millis()
        );
        assert_eq!(release(&tmp), "path direct\n");
        let path = dir.0.join("status.txt");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut last = String::new();
        while Instant::now() < deadline {
            if fs::metadata(&path).is_ok_and(|meta| meta.is_file()) {
                last = fs::read_to_string(&path).unwrap_or_default();
                if last == "path relay 99\n" {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        assert_eq!(last, "path relay 99\n");
    }

    /// The negative check: `write_now` in the caller thread waits as long as the disk write waits.
    /// The router thread did this before W25-29.
    #[test]
    fn a_blocked_status_write_stops_a_caller_that_writes_itself() {
        let dir = Dir::new("now");
        let tmp = block_tmp(&dir.0);
        let file = Arc::new(StatusFile::new(&dir.0, "status.txt"));
        let hold = Duration::from_millis(300);
        let reader = thread::spawn(move || {
            thread::sleep(hold);
            release(&tmp)
        });
        let started = Instant::now();
        file.write_now("path relay\n");
        let took = started.elapsed();
        assert_eq!(reader.join().unwrap(), "path relay\n");
        println!("status_write_now blocked_ms {}", took.as_millis());
        assert!(
            took >= hold,
            "write_now took {} ms, less than the hold",
            took.as_millis()
        );
    }
}
