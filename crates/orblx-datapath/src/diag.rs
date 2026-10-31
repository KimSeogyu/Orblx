//! W25-42 diagnostic only. This module is off unless `ORBLX_DIAG_FILE` is set.
//!
//! When it is on, a sampler thread writes one line each `ORBLX_DIAG_TICK_MS` (default 10 ms)
//! to `ORBLX_DIAG_FILE`:
//!
//! `d <unix_ms> <mono_us> tunr <n> tunw <n> rtin <n> rtsend <n> ptx <n> prx <n> pka <n>
//!  beat_age_ms <n> lag_max_ms <n> ev <n>`
//!
//! * `tunr`, `tunw`: packets that the TUN read and write threads moved.
//! * `rtin`, `rtsend`: packets that `read_tun` took from the TUN channel, and gave to a link.
//! * `ptx`, `prx`, `pka`: overlay packets sent to and taken from peers, and keepalives taken.
//! * `beat_age_ms`: time since the runtime probe task last ran (it ticks each 5 ms).
//! * `lag_max_ms`: the largest late wake of the probe task since the last line.
//! * `ev`: the count of file-apply events (deny list, netmap); each event also writes an
//!   `e <unix_ms> <mono_us> <text>` line.
//!
//! The counters are relaxed atomics. The module does no I/O on the packet path.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) static TUN_READ: AtomicU64 = AtomicU64::new(0);
pub(crate) static TUN_WRITE: AtomicU64 = AtomicU64::new(0);
pub(crate) static RT_IN: AtomicU64 = AtomicU64::new(0);
pub(crate) static RT_SEND: AtomicU64 = AtomicU64::new(0);
pub(crate) static PEER_TX: AtomicU64 = AtomicU64::new(0);
pub(crate) static PEER_RX: AtomicU64 = AtomicU64::new(0);
pub(crate) static PEER_KA: AtomicU64 = AtomicU64::new(0);
static BEAT_US: AtomicU64 = AtomicU64::new(0);
static LAG_MAX_US: AtomicU64 = AtomicU64::new(0);
static EVENTS: AtomicU64 = AtomicU64::new(0);
static STARTED: AtomicBool = AtomicBool::new(false);

struct Diag {
    origin: Instant,
    out: Mutex<std::io::BufWriter<std::fs::File>>,
}

static DIAG: OnceLock<Option<Diag>> = OnceLock::new();

fn diag() -> Option<&'static Diag> {
    DIAG.get_or_init(|| {
        let path = std::env::var_os("ORBLX_DIAG_FILE").filter(|p| !p.is_empty())?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        Some(Diag {
            origin: Instant::now(),
            out: Mutex::new(std::io::BufWriter::with_capacity(1 << 16, file)),
        })
    })
    .as_ref()
}

#[inline]
pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn mono_us(d: &Diag) -> u64 {
    u64::try_from(d.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Write one event line (a file apply). Rare, so the lock cost does not matter.
pub(crate) fn event(text: &str) {
    if let Some(d) = diag() {
        EVENTS.fetch_add(1, Ordering::Relaxed);
        let line = format!("e {} {} {text}\n", unix_ms(), mono_us(d));
        if let Ok(mut out) = d.out.lock() {
            let _ = out.write_all(line.as_bytes());
        }
    }
}

/// Start the runtime probe task and the sampler thread once. Call it inside the node runtime.
pub(crate) fn start() {
    let Some(d) = diag() else {
        return;
    };
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let tick_ms = std::env::var("ORBLX_DIAG_TICK_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| (1..=10).contains(v))
        .unwrap_or(10);
    BEAT_US.store(mono_us(d), Ordering::Relaxed);
    tokio::spawn(async move {
        let step = Duration::from_millis(5);
        loop {
            let before = Instant::now();
            tokio::time::sleep(step).await;
            let late = before.elapsed().saturating_sub(step);
            let late_us = u64::try_from(late.as_micros()).unwrap_or(u64::MAX);
            LAG_MAX_US.fetch_max(late_us, Ordering::Relaxed);
            BEAT_US.store(mono_us(d), Ordering::Relaxed);
        }
    });
    let _ = std::thread::Builder::new()
        .name("orblx-diag".to_string())
        .spawn(move || {
            let tick = Duration::from_millis(tick_ms);
            let mut next = Instant::now() + tick;
            let mut last_flush = Instant::now();
            loop {
                let now = Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                }
                next += tick;
                let now_us = mono_us(d);
                let beat_age_ms = now_us.saturating_sub(BEAT_US.load(Ordering::Relaxed)) / 1000;
                let lag_ms = LAG_MAX_US.swap(0, Ordering::Relaxed) / 1000;
                let line = format!(
                    "d {} {} tunr {} tunw {} rtin {} rtsend {} ptx {} prx {} pka {} beat_age_ms {} lag_max_ms {} ev {}\n",
                    unix_ms(),
                    now_us,
                    TUN_READ.load(Ordering::Relaxed),
                    TUN_WRITE.load(Ordering::Relaxed),
                    RT_IN.load(Ordering::Relaxed),
                    RT_SEND.load(Ordering::Relaxed),
                    PEER_TX.load(Ordering::Relaxed),
                    PEER_RX.load(Ordering::Relaxed),
                    PEER_KA.load(Ordering::Relaxed),
                    beat_age_ms,
                    lag_ms,
                    EVENTS.load(Ordering::Relaxed),
                );
                if let Ok(mut out) = d.out.lock() {
                    let _ = out.write_all(line.as_bytes());
                    if last_flush.elapsed() >= Duration::from_secs(1) {
                        let _ = out.flush();
                        last_flush = Instant::now();
                    }
                }
            }
        });
}
