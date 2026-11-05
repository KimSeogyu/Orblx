//! Soak traces for the datapath event loop (W25-42).
//!
//! Set `ORBLX_SOAK_TRACE=1` before the node starts.
//! The packet path reads one cached bool.
//! When the flag is off, that path does not read the clock, allocate, or format a log line.

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Return true when `ORBLX_SOAK_TRACE=1`.
///
/// The first call reads the environment. Later calls read the cached bool.
pub(crate) fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    match ON.get() {
        Some(on) => *on,
        None => *ON.get_or_init(read_flag),
    }
}

fn read_flag() -> bool {
    std::env::var("ORBLX_SOAK_TRACE").ok().as_deref() == Some("1")
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn log_at(unix_ms: u128, body: &str) {
    eprintln!("soak unix_ms={unix_ms} {body}");
}

fn log(body: &str) {
    log_at(unix_ms(), body);
}

/// Run `body` and, when the flag is on, log its duration.
pub(crate) fn span<T>(event: &str, body: impl FnOnce() -> T) -> T {
    if !enabled() {
        return body();
    }
    let start = Instant::now();
    let value = body();
    log(&format!("{event} dur_us={}", start.elapsed().as_micros()));
    value
}

/// Max `to_tun.send` wait for one link, logged once per second.
pub(crate) struct SendWait {
    max: Duration,
    window_ms: u128,
    samples: u64,
    peer: String,
}

impl SendWait {
    pub(crate) fn new() -> Self {
        Self {
            max: Duration::ZERO,
            window_ms: 0,
            samples: 0,
            peer: String::new(),
        }
    }

    fn note(&mut self, peer: &str, waited: Duration) {
        let now = unix_ms();
        if self.peer.is_empty() {
            self.peer.push_str(peer);
        }
        if self.window_ms == 0 {
            self.window_ms = now;
        }
        if now / 1000 != self.window_ms / 1000 {
            self.flush();
            self.window_ms = now;
        }
        self.samples = self.samples.saturating_add(1);
        if waited > self.max {
            self.max = waited;
        }
    }

    fn flush(&mut self) {
        if self.samples == 0 {
            return;
        }
        log_at(
            self.window_ms,
            &format!(
                "to_tun_send_wait peer={} max_us={}",
                self.peer,
                self.max.as_micros()
            ),
        );
        self.max = Duration::ZERO;
        self.samples = 0;
    }
}

impl Drop for SendWait {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Send one packet on the shared TUN queue.
///
/// `trace` is the cached flag for this link. The caller reads it once.
/// When `trace` is false, this function does not read the clock.
pub(crate) async fn forward_to_tun(
    to_tun: &mpsc::Sender<Vec<u8>>,
    packet: Vec<u8>,
    trace: bool,
    peer: &str,
    wait: &mut SendWait,
) -> bool {
    if !trace {
        return to_tun.send(packet).await.is_ok();
    }
    let start = Instant::now();
    let ok = to_tun.send(packet).await.is_ok();
    wait.note(peer, start.elapsed());
    ok
}

/// Per-write TUN timings for one writer thread. Build this only when the flag is on.
pub(crate) struct TunWriteStats {
    max: Duration,
    slow: u64,
    writes: u64,
    window_start: Option<Instant>,
}

impl TunWriteStats {
    pub(crate) fn new() -> Self {
        Self {
            max: Duration::ZERO,
            slow: 0,
            writes: 0,
            window_start: None,
        }
    }

    pub(crate) fn note(&mut self, dur: Duration) {
        let now = Instant::now();
        if self.window_start.is_none() {
            self.window_start = Some(now);
        }
        self.writes = self.writes.saturating_add(1);
        if dur > self.max {
            self.max = dur;
        }
        if dur > Duration::from_millis(10) {
            self.slow = self.slow.saturating_add(1);
            log(&format!("tun_write dur_us={}", dur.as_micros()));
        }
        let start = self.window_start.unwrap_or(now);
        if now.saturating_duration_since(start) >= Duration::from_secs(1) {
            self.flush_window();
            self.window_start = Some(now);
        }
    }

    fn flush_window(&mut self) {
        log(&format!(
            "tun_write_sec max_us={} slow_gt_10ms={} writes={}",
            self.max.as_micros(),
            self.slow,
            self.writes
        ));
        self.max = Duration::ZERO;
        self.slow = 0;
        self.writes = 0;
    }
}

impl Drop for TunWriteStats {
    fn drop(&mut self) {
        if self.writes > 0 {
            self.flush_window();
        }
    }
}

/// Sample the shared TUN queue every 100 ms. No task starts when the flag is off.
pub(crate) fn spawn_to_tun_probe(to_tun: mpsc::Sender<Vec<u8>>) -> Option<JoinHandle<()>> {
    if !enabled() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tick.tick().await;
            let cap = to_tun.max_capacity();
            let queued = cap.saturating_sub(to_tun.capacity());
            log(&format!("to_tun_queued={queued} cap={cap}"));
        }
    }))
}

/// Log when a 10 ms tick is late by more than 50 ms. No task starts when the flag is off.
pub(crate) fn spawn_runtime_watchdog() -> Option<JoinHandle<()>> {
    if !enabled() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        let mut last = Instant::now();
        loop {
            tick.tick().await;
            let now = Instant::now();
            let gap = now.saturating_duration_since(last);
            last = now;
            let late = gap.saturating_sub(Duration::from_millis(10));
            if late > Duration::from_millis(50) {
                log(&format!("runtime_tick_late late_us={}", late.as_micros()));
            }
        }
    }))
}
