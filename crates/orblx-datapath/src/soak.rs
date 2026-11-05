//! Soak traces for the datapath event loop (W25-42).
//!
//! Set `ORBLX_SOAK_TRACE=1` before the node starts.
//! The packet path reads one cached bool.
//! When the flag is off, that path does not read the clock, allocate, or format a log line.
//!
//! A per-link stall is one `to_tun.send` that is still waiting, or that just finished.
//! An open stall prints `to_tun_stall peer=NAME stall_ms=N` once per second after 1 s.
//! A finished stall of 100 ms or more prints that line once, with that wait.
//! The same finish prints `to_tun_stall_keepalive` with the inbound keepalive count.
//! A session end prints `session_close`.
//! `unix_ms` is the time the line is printed.
//! `stall_ms` is whole milliseconds, rounded down.
//! The same max wait for one second is also on `to_tun_send_wait` as `stall_ms`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
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
    #[cfg(test)]
    recorded_lines().push(body.to_string());
}

fn log(body: &str) {
    log_at(unix_ms(), body);
}

/// An open `to_tun.send` at or above this time prints `to_tun_stall` once per second.
const STALL_LOG_AFTER: Duration = Duration::from_secs(1);

/// A finished `to_tun.send` at or above this time prints one `to_tun_stall` line.
const FINISHED_STALL_MIN: Duration = Duration::from_millis(100);

fn send_wait_line(peer: &str, max: Duration) -> String {
    format!(
        "to_tun_send_wait peer={peer} max_us={} stall_ms={}",
        max.as_micros(),
        max.as_millis()
    )
}

fn stall_line(peer: &str, stall_ms: u128) -> String {
    format!("to_tun_stall peer={peer} stall_ms={stall_ms}")
}

fn stall_keepalive_line(peer: &str, inbound: u64) -> String {
    format!("to_tun_stall_keepalive peer={peer} inbound_keepalive_during_stall={inbound}")
}

fn session_close_line(peer: &str, reason: &str, during_stall: bool) -> String {
    format!(
        "session_close peer={peer} reason={reason} during_stall={}",
        u8::from(during_stall)
    )
}

fn log_finished_stall(peer: &str, waited: Duration, inbound: u64) {
    if waited < FINISHED_STALL_MIN {
        return;
    }
    log(&stall_line(peer, waited.as_millis()));
    log(&stall_keepalive_line(peer, inbound));
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
        log_at(self.window_ms, &send_wait_line(&self.peer, self.max));
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
    let mut open = OpenWait::start(peer);
    let ok = to_tun.send(packet).await.is_ok();
    let waited = open.finish();
    wait.note(peer, waited);
    ok
}

struct OpenSlot {
    id: u64,
    peer: String,
    start: Instant,
    next_log_at: Duration,
    inbound: u64,
}

fn open_slots() -> MutexGuard<'static, Vec<OpenSlot>> {
    static OPEN: Mutex<Vec<OpenSlot>> = Mutex::new(Vec::new());
    OPEN.lock().unwrap_or_else(|err| err.into_inner())
}

fn next_open_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// One in-flight `to_tun.send` while the soak flag is on for this link.
///
/// The 100 ms queue probe prints the wait once per second after [`STALL_LOG_AFTER`].
/// Drop of this guard removes the slot, including when the link task stops mid-send.
struct OpenWait {
    id: u64,
    done: bool,
}

impl OpenWait {
    fn start(peer: &str) -> Self {
        let id = next_open_id();
        open_slots().push(OpenSlot {
            id,
            peer: peer.to_string(),
            start: Instant::now(),
            next_log_at: STALL_LOG_AFTER,
            inbound: 0,
        });
        Self { id, done: false }
    }

    fn finish(&mut self) -> Duration {
        self.done = true;
        let Some(slot) = take_slot(self.id) else {
            return Duration::ZERO;
        };
        let waited = slot.start.elapsed();
        log_finished_stall(&slot.peer, waited, slot.inbound);
        waited
    }
}

impl Drop for OpenWait {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let Some(slot) = take_slot(self.id) else {
            return;
        };
        let waited = slot.start.elapsed();
        log_finished_stall(&slot.peer, waited, slot.inbound);
    }
}

fn take_slot(id: u64) -> Option<OpenSlot> {
    let mut slots = open_slots();
    let index = slots.iter().position(|slot| slot.id == id)?;
    Some(slots.swap_remove(index))
}

fn log_open_stalls() {
    let mut due = Vec::new();
    {
        let mut slots = open_slots();
        let now = Instant::now();
        for slot in slots.iter_mut() {
            let elapsed = now.saturating_duration_since(slot.start);
            if elapsed < slot.next_log_at {
                continue;
            }
            due.push((slot.peer.clone(), elapsed.as_millis()));
            slot.next_log_at = elapsed.saturating_add(Duration::from_secs(1));
        }
    }
    for (peer, stall_ms) in due {
        log(&stall_line(&peer, stall_ms));
    }
}

/// Count one inbound keepalive or control frame on a link whose `to_tun.send` is open.
///
/// The caller skips this function when the soak flag is off.
pub(crate) fn note_inbound_during_stall(peer: &str) {
    let mut slots = open_slots();
    for slot in slots.iter_mut() {
        if slot.peer == peer {
            slot.inbound = slot.inbound.saturating_add(1);
        }
    }
}

fn peer_has_open_stall(peer: &str) -> bool {
    open_slots().iter().any(|slot| slot.peer == peer)
}

/// One session end. Drop prints `session_close` when the link armed this value.
pub(crate) struct SessionEnd {
    /// Peer name.
    pub(crate) peer: String,
    /// Close reason token. No spaces.
    pub(crate) reason: String,
}

impl Drop for SessionEnd {
    fn drop(&mut self) {
        log_session_close(&self.peer, &self.reason);
    }
}

pub(crate) fn log_session_close(peer: &str, reason: &str) {
    let during = peer_has_open_stall(peer);
    log(&session_close_line(peer, reason, during));
}

/// Map a hello error to a `session_close` reason token.
pub(crate) fn session_reason(err: &crate::HelloError) -> String {
    match err {
        crate::HelloError::Quic(detail) if detail == "idle_timeout" => "idle_timeout".to_string(),
        crate::HelloError::Quic(detail) => sanitize_reason(detail),
        crate::HelloError::StreamClosed => "stream_closed".to_string(),
        other => sanitize_reason(&other.to_string()),
    }
}

fn sanitize_reason(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else if ch.is_ascii_whitespace() && !out.ends_with('_') {
            out.push('_');
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// Print the idle-timeout table once. No line when the flag is off.
pub(crate) fn log_idle_timeouts() {
    if !enabled() {
        return;
    }
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        for line in idle_timeout_lines() {
            log(line);
        }
    });
}

fn idle_timeout_lines() -> [&'static str; 4] {
    [
        "idle_timeout_ms=30000 src=crates/orblx-datapath/src/quic.rs:1023",
        "idle_timeout_ms=10000 src=crates/orblx-datapath/src/quic.rs:1026",
        "idle_timeout_ms=1000 src=crates/orblx-relay/src/server.rs:25",
        "idle_timeout_ms=60000 src=crates/orblx-coord/src/tlsutil.rs:208",
    ]
}

#[cfg(test)]
fn recorded_lines() -> MutexGuard<'static, Vec<String>> {
    static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    LINES.lock().unwrap_or_else(|err| err.into_inner())
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
    log_idle_timeouts();
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tick.tick().await;
            let cap = to_tun.max_capacity();
            let queued = cap.saturating_sub(to_tun.capacity());
            log(&format!("to_tun_queued={queued} cap={cap}"));
            log_open_stalls();
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

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use super::*;

    fn idle_waker() -> Waker {
        fn clone(ptr: *const ()) -> RawWaker {
            RawWaker::new(ptr, &VTABLE)
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        // SAFETY: the vtable does not read the pointer.
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    fn gate() -> MutexGuard<'static, ()> {
        static GATE: Mutex<()> = Mutex::new(());
        GATE.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn age_open(by: Duration) {
        let mut slots = open_slots();
        let slot = &mut slots[0];
        slot.start = slot
            .start
            .checked_sub(by)
            .expect("the test clock can move back");
    }

    #[test]
    fn stall_lines_use_whole_milliseconds() {
        assert_eq!(
            send_wait_line("a", Duration::from_millis(1_300)),
            "to_tun_send_wait peer=a max_us=1300000 stall_ms=1300"
        );
        assert_eq!(
            send_wait_line("a", Duration::from_micros(500)),
            "to_tun_send_wait peer=a max_us=500 stall_ms=0"
        );
        assert_eq!(
            stall_line("b", 30_000),
            "to_tun_stall peer=b stall_ms=30000"
        );
    }

    #[test]
    fn a_traced_send_on_a_full_queue_stays_open_until_one_read() {
        let _gate = gate();
        open_slots().clear();
        recorded_lines().clear();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(vec![1]).unwrap();
        let mut wait = SendWait::new();
        let mut send = Box::pin(forward_to_tun(&tx, vec![9], true, "peer-a", &mut wait));
        let waker = idle_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(send.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(open_slots().len(), 1);
        {
            let mut slots = open_slots();
            let slot = &mut slots[0];
            slot.start = slot
                .start
                .checked_sub(Duration::from_millis(1_500))
                .expect("the test clock can move back 1500 ms");
        }
        log_open_stalls();
        {
            let slots = open_slots();
            assert_eq!(slots.len(), 1);
            assert!(slots[0].next_log_at > Duration::from_millis(1_500));
        }
        let before = open_slots()[0].next_log_at;
        log_open_stalls();
        assert_eq!(open_slots()[0].next_log_at, before);

        rx.try_recv().unwrap();
        assert!(matches!(send.as_mut().poll(&mut cx), Poll::Ready(true)));
        drop(send);
        assert_eq!(wait.samples, 1);
        assert!(wait.max >= Duration::from_millis(1_500));
        assert!(open_slots().is_empty());

        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(vec![1]).unwrap();
        let mut quiet = SendWait::new();
        let mut quiet_send = Box::pin(forward_to_tun(&tx, vec![8], false, "peer-b", &mut quiet));
        assert!(matches!(quiet_send.as_mut().poll(&mut cx), Poll::Pending));
        assert!(open_slots().is_empty());
        rx.try_recv().unwrap();
        assert!(matches!(
            quiet_send.as_mut().poll(&mut cx),
            Poll::Ready(true)
        ));
        drop(quiet_send);
        assert_eq!(quiet.samples, 0);
        assert!(open_slots().is_empty());

        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        tx.try_send(vec![1]).unwrap();
        let mut dropped = SendWait::new();
        let mut dropped_send = Box::pin(forward_to_tun(&tx, vec![7], true, "peer-c", &mut dropped));
        assert!(matches!(dropped_send.as_mut().poll(&mut cx), Poll::Pending));
        {
            let mut slots = open_slots();
            let slot = &mut slots[0];
            slot.start = slot
                .start
                .checked_sub(STALL_LOG_AFTER)
                .expect("the test clock can move back 1 s");
        }
        drop(dropped_send);
        assert!(open_slots().is_empty());
        assert_eq!(dropped.samples, 0);
    }

    #[test]
    fn a_finished_stall_of_100_to_999_ms_prints_once() {
        let _gate = gate();
        open_slots().clear();
        recorded_lines().clear();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(vec![1]).unwrap();
        let mut wait = SendWait::new();
        let mut send = Box::pin(forward_to_tun(&tx, vec![9], true, "peer-a", &mut wait));
        let waker = idle_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(send.as_mut().poll(&mut cx), Poll::Pending));
        note_inbound_during_stall("peer-a");
        note_inbound_during_stall("peer-a");
        note_inbound_during_stall("other");
        age_open(Duration::from_millis(500));
        log_open_stalls();
        assert!(
            recorded_lines().is_empty(),
            "an open stall under 1 s does not print the per-second line"
        );
        rx.try_recv().unwrap();
        assert!(matches!(send.as_mut().poll(&mut cx), Poll::Ready(true)));
        drop(send);
        let stall_ms = wait.max.as_millis();
        assert!((100..1_000).contains(&stall_ms));
        let lines = recorded_lines();
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("to_tun_stall "))
                .count(),
            1
        );
        assert!(lines.contains(&stall_line("peer-a", stall_ms)));
        assert!(lines.contains(&stall_keepalive_line("peer-a", 2)));
        drop(lines);

        recorded_lines().clear();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(vec![1]).unwrap();
        let mut short = SendWait::new();
        let mut short_send = Box::pin(forward_to_tun(&tx, vec![4], true, "peer-d", &mut short));
        assert!(matches!(short_send.as_mut().poll(&mut cx), Poll::Pending));
        age_open(Duration::from_millis(50));
        rx.try_recv().unwrap();
        assert!(matches!(
            short_send.as_mut().poll(&mut cx),
            Poll::Ready(true)
        ));
        drop(short_send);
        assert!(short.max < FINISHED_STALL_MIN);
        assert!(recorded_lines()
            .iter()
            .all(|line| !line.starts_with("to_tun_stall ")));
    }

    #[test]
    fn a_session_close_records_the_reason_and_an_open_stall() {
        let _gate = gate();
        open_slots().clear();
        recorded_lines().clear();
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(vec![1]).unwrap();
        let mut wait = SendWait::new();
        let mut send = Box::pin(forward_to_tun(&tx, vec![9], true, "peer-a", &mut wait));
        let waker = idle_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(send.as_mut().poll(&mut cx), Poll::Pending));
        log_session_close("peer-a", "idle_timeout");
        assert!(recorded_lines().contains(&session_close_line("peer-a", "idle_timeout", true)));
        drop(send);
        recorded_lines().clear();
        log_session_close("peer-a", "cancel");
        assert!(recorded_lines().contains(&session_close_line("peer-a", "cancel", false)));

        let idle = crate::HelloError::Quic("idle_timeout".to_string());
        assert_eq!(session_reason(&idle), "idle_timeout");
        let lost = crate::quic::hello_from_read(quinn::ReadError::ConnectionLost(
            quinn::ConnectionError::TimedOut,
        ));
        assert_eq!(session_reason(&lost), "idle_timeout");
        let reset = crate::quic::hello_from_read(quinn::ReadError::ConnectionLost(
            quinn::ConnectionError::Reset,
        ));
        assert_eq!(session_reason(&reset), "connection_lost");
    }

    #[test]
    fn idle_timeout_lines_match_the_source() {
        let quic = include_str!("quic.rs");
        assert!(
            quic.lines().nth(1022).unwrap().contains("from_secs(30)"),
            "quic.rs:1023"
        );
        assert!(
            quic.lines().nth(1025).unwrap().contains("from_secs(10)"),
            "quic.rs:1026"
        );
        let relay = include_str!("../../orblx-relay/src/server.rs");
        assert!(
            relay.lines().nth(24).unwrap().contains("from_secs(1)"),
            "server.rs:25"
        );
        assert_eq!(orblx_relay::PEER_IDLE, Duration::from_secs(1));
        let coord = include_str!("../../orblx-coord/src/tlsutil.rs");
        assert!(
            coord.lines().nth(207).unwrap().contains("from_secs(60)"),
            "tlsutil.rs:208"
        );
        let lines = idle_timeout_lines();
        assert_eq!(
            lines[0],
            "idle_timeout_ms=30000 src=crates/orblx-datapath/src/quic.rs:1023"
        );
        assert_eq!(
            lines[1],
            "idle_timeout_ms=10000 src=crates/orblx-datapath/src/quic.rs:1026"
        );
        assert_eq!(
            lines[2],
            "idle_timeout_ms=1000 src=crates/orblx-relay/src/server.rs:25"
        );
        assert_eq!(
            lines[3],
            "idle_timeout_ms=60000 src=crates/orblx-coord/src/tlsutil.rs:208"
        );
    }
}
