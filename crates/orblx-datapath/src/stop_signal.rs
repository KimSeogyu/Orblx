//! A process stop flag that is set before the Tokio runtime exists.
//!
//! Tokio installs the SIGTERM handler and then subscribes a receiver.
//! A signal in that gap is broadcast to no receiver, and the registry ignores the send error.
//! This flag is set from the handler itself, so that signal still stops the node.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

static STOP: AtomicBool = AtomicBool::new(false);
static INSTALL: Once = Once::new();

/// Register SIGTERM and SIGINT. A later call does nothing.
///
/// The handler only stores `STOP`. That store is async-signal-safe.
pub fn install_stop_flag() {
    INSTALL.call_once(|| {
        // SAFETY: `set_stop` only stores an atomic bool. That is async-signal-safe.
        // `register` keeps the action for the life of the process.
        if let Err(err) = unsafe { signal_hook_registry::register(libc::SIGTERM, set_stop) } {
            eprintln!("The node did not register SIGTERM. {err}");
        }
        if let Err(err) = unsafe { signal_hook_registry::register(libc::SIGINT, set_stop) } {
            eprintln!("The node did not register SIGINT. {err}");
        }
    });
}

fn set_stop() {
    STOP.store(true, Ordering::SeqCst);
}

/// `true` after SIGTERM or SIGINT.
pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Make the SIGTERM and SIGINT streams. Call this inside a Tokio runtime.
///
/// SIGTERM and SIGINT are blocked on this thread while the streams are created.
/// A signal in that window stays pending and is delivered after both streams exist.
/// Delivery on this thread during `register` would wait on the registry lock.
pub(crate) fn open_stop_streams() -> (
    Option<tokio::signal::unix::Signal>,
    Option<tokio::signal::unix::Signal>,
) {
    let _mask = StopMask::block();
    // Let another thread run. A SIGTERM from that thread hits the handler
    // while this thread has the signal blocked, so `register` does not deadlock.
    std::thread::yield_now();
    let terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(stream) => Some(stream),
        Err(err) => {
            eprintln!("The node did not install the SIGTERM stream. {err}");
            None
        }
    };
    let interrupt = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        Ok(stream) => Some(stream),
        Err(err) => {
            eprintln!("The node did not install the SIGINT stream. {err}");
            None
        }
    };
    (terminate, interrupt)
}

struct StopMask {
    set: libc::sigset_t,
}

impl StopMask {
    fn block() -> Self {
        unsafe {
            let mut set = std::mem::zeroed();
            // SAFETY: `set` is a local sigset. The calls only change this thread's mask.
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::sigaddset(&mut set, libc::SIGINT);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            Self { set }
        }
    }
}

impl Drop for StopMask {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &self.set, std::ptr::null_mut());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tokio::runtime::Builder;

    use super::{install_stop_flag, stop_requested};
    use crate::node::wait_for_stop;

    const ITERATIONS: u32 = 50;

    #[test]
    fn term_before_streams_stops_within_5s() {
        if std::env::var("ORBLX_STOP_SIGNAL_CHILD").ok().as_deref() == Some("before") {
            child_before();
        }
        if std::env::var_os("ORBLX_STOP_SIGNAL_CHILD").is_some() {
            return;
        }
        let max_ms = run_children(
            "before",
            "stop_signal::tests::term_before_streams_stops_within_5s",
        );
        assert!(max_ms < 5_000, "max stop latency {max_ms} ms");
        println!("term_before_streams iterations {ITERATIONS} max_stop_latency_ms {max_ms}");
    }

    #[test]
    fn term_during_stream_setup_stops_within_5s() {
        if std::env::var("ORBLX_STOP_SIGNAL_CHILD").ok().as_deref() == Some("race") {
            child_race();
        }
        if std::env::var_os("ORBLX_STOP_SIGNAL_CHILD").is_some() {
            return;
        }
        let max_ms = run_children(
            "race",
            "stop_signal::tests::term_during_stream_setup_stops_within_5s",
        );
        assert!(max_ms < 5_000, "max stop latency {max_ms} ms");
        println!("term_during_streams iterations {ITERATIONS} max_stop_latency_ms {max_ms}");
    }

    fn child_before() -> ! {
        install_stop_flag();
        install_stop_flag();
        assert!(!stop_requested());
        // SAFETY: this process has a handler that only stores an atomic bool.
        unsafe { libc::raise(libc::SIGTERM) };
        assert!(stop_requested());
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let _enter = runtime.enter();
        let (terminate, interrupt) = super::open_stop_streams();
        let started = Instant::now();
        runtime.block_on(wait_for_stop(terminate, interrupt, None));
        println!("STOP_MS {}", started.elapsed().as_millis());
        std::process::exit(0);
    }

    fn child_race() -> ! {
        install_stop_flag();
        let pid = libc::pid_t::try_from(std::process::id()).expect("pid");
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        let sent = Arc::new(AtomicU64::new(0));
        let sent_flag = Arc::clone(&sent);
        let sender = thread::spawn(move || {
            while flag.load(Ordering::Relaxed) {
                // SAFETY: the pid is this process. The handler only stores an atomic bool.
                unsafe { libc::kill(pid, libc::SIGTERM) };
                sent_flag.fetch_add(1, Ordering::Relaxed);
                thread::yield_now();
            }
        });
        while sent.load(Ordering::Relaxed) == 0 {
            thread::yield_now();
        }
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let _enter = runtime.enter();
        let (terminate, interrupt) = super::open_stop_streams();
        running.store(false, Ordering::Relaxed);
        sender.join().expect("sender");
        let started = Instant::now();
        runtime.block_on(wait_for_stop(terminate, interrupt, None));
        println!("STOP_MS {}", started.elapsed().as_millis());
        std::process::exit(0);
    }

    fn run_children(mode: &str, test_name: &str) -> u128 {
        let exe = std::env::current_exe().expect("test executable");
        let mut max_ms = 0u128;
        for i in 0..ITERATIONS {
            let mut child = Command::new(&exe)
                .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
                .env("ORBLX_STOP_SIGNAL_CHILD", mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("child");
            let started = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().expect("child status") {
                    break status;
                }
                if started.elapsed() > Duration::from_secs(20) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("iteration {i} did not exit within 20 s");
                }
                thread::sleep(Duration::from_millis(20));
            };
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut out) = child.stdout.take() {
                out.read_to_string(&mut stdout).expect("stdout");
            }
            if let Some(mut err) = child.stderr.take() {
                err.read_to_string(&mut stderr).expect("stderr");
            }
            assert!(
                status.success(),
                "iteration {i} status {status} stderr {stderr} stdout {stdout}"
            );
            let ms = parse_stop_ms(&stdout).unwrap_or_else(|| {
                panic!("iteration {i} has no STOP_MS line in {stdout}");
            });
            assert!(ms < 5_000, "iteration {i} wait_for_stop took {ms} ms");
            max_ms = max_ms.max(ms);
        }
        max_ms
    }

    fn parse_stop_ms(text: &str) -> Option<u128> {
        let marker = "STOP_MS ";
        let start = text.find(marker)? + marker.len();
        let digits: String = text[start..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }
}
