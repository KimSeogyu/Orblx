//! Punch plans for hard NAT pairs.
//!
//! A node learns its NAT mapping kind from two STUN servers.
//! The node publishes both reflexive endpoints.
//! The coordinator signs each endpoint.
//! The peer reads the mapping kind from the two signed endpoints.
//!
//! An endpoint-independent NAT is "easy".
//! An endpoint-dependent (symmetric) NAT is "hard".
//!
//! - Easy to easy: plain punch to the signed endpoint.
//! - Easy to hard: the easy side sends probes to a bounded set of ports on the hard IP.
//!   The first probes go to the predicted ports after the two STUN ports.
//!   The next probes go to random ports.
//! - Hard to easy: the hard side opens [`BIRTHDAY_SOCKETS`] sockets.
//!   Each socket sends to the signed endpoint of the easy side.
//!   Each socket gets its own NAT mapping.
//!   A probe from the easy side that hits one of these mappings opens the path.
//! - Hard to hard, both allocations random: no punch. The node uses the relay.
//! - Hard to hard, one allocation predictable: both sides spray the predicted ports.
//!   A failed attempt waits, then tries again. The relay carries packets during the wait.
//!
//! Each send is rate-limited by [`RateGate`].
//! Each attempt has a fixed probe count and a fixed time limit.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::EdgeError;

/// Sockets that the hard side opens for one attempt.
pub const BIRTHDAY_SOCKETS: usize = 256;

/// The largest number of port probes that the easy side sends in one attempt.
pub const SPRAY_MAX: u32 = 2_048;

/// Probes that go to predicted ports before the random probes.
pub const PREDICT_COUNT: u32 = 32;

/// The largest send rate for birthday probes, in datagrams per second.
pub const PROBE_RATE: u32 = 200;

/// The largest burst for birthday probes.
pub const PROBE_BURST: u32 = 20;

/// The time limit for one birthday attempt.
pub const BIRTHDAY_WINDOW: Duration = Duration::from_secs(15);

/// Extra STUN sockets used to read the port allocation.
pub const ALLOC_SAMPLES: usize = 4;

/// Samples required before the allocation class is known.
pub const CLASSIFY_MIN: usize = 4;

/// A span at or below this value, with no fixed step, is a port block.
pub const PORT_BLOCK_SPAN: u16 = 512;

/// The smallest half-width of a port-block spray.
///
/// A 64-port block sits inside this window when the midpoint is inside the block.
pub const PORT_BLOCK_RADIUS: u16 = 63;

/// The first retry waits this long. Later retries double the wait.
pub const RETRY_MIN: Duration = Duration::from_secs(2);

/// The longest wait between predict attempts.
pub const RETRY_MAX: Duration = Duration::from_secs(60);

/// The hard side sends again on each socket after this time.
pub const SOCKET_REFRESH: Duration = Duration::from_secs(2);

/// The lowest port that a probe uses.
///
/// Most NATs map a source port of 1024 or more to a port of 1024 or more.
pub const PORT_MIN: u16 = 1_024;

/// The mapping kind of one NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingKind {
    /// The node did not measure the mapping.
    Unknown,
    /// One external port for all destinations.
    Easy,
    /// A new external port for each destination.
    Hard,
}

impl MappingKind {
    /// The status word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Easy => "endpoint-independent",
            Self::Hard => "endpoint-dependent",
        }
    }
}

/// The mapping kind from two STUN answers for one local socket.
#[must_use]
pub fn local_kind(primary: SocketAddr, alt: Option<SocketAddr>) -> MappingKind {
    match alt {
        None => MappingKind::Unknown,
        Some(alt) if alt == primary => MappingKind::Easy,
        Some(_) => MappingKind::Hard,
    }
}

/// The mapping kind from the signed endpoints of a peer.
///
/// The peer publishes two endpoints when it measured the mapping.
#[must_use]
pub fn peer_kind(endpoints: &[SocketAddr]) -> MappingKind {
    match endpoints {
        [first, second, ..] if first.ip() == second.ip() => {
            if first.port() == second.port() {
                MappingKind::Easy
            } else {
                MappingKind::Hard
            }
        }
        _ => MappingKind::Unknown,
    }
}

/// The punch plan for one pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Punch the signed endpoint.
    Plain,
    /// Send probes to many ports on the peer IP.
    Spray,
    /// Open many local sockets toward the signed endpoint.
    Sockets,
    /// Do not punch. Use the relay.
    RelayOnly,
    /// Spray the predicted ports of a hard peer.
    Predict,
}

impl Strategy {
    /// The log word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Spray => "port-spray",
            Self::Sockets => "birthday-sockets",
            Self::RelayOnly => "relay-only",
            Self::Predict => "predict-spray",
        }
    }
}

/// How a hard NAT picks the next external port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortAlloc {
    /// There are fewer than [`CLASSIFY_MIN`] samples.
    Unknown,
    /// Each new flow adds `step` to the previous port.
    ///
    /// `origin` is the highest sample.
    Sequential {
        /// The port step.
        step: u16,
        /// The highest sample.
        origin: u16,
    },
    /// The samples lie in a small window.
    PortBlock {
        /// The lowest sample.
        low: u16,
        /// The highest sample.
        high: u16,
    },
    /// The samples have no fixed step and the window is wide.
    Random,
}

impl PortAlloc {
    /// The status word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Sequential { .. } => "sequential",
            Self::PortBlock { .. } => "port-block",
            Self::Random => "random",
        }
    }

    /// Return true when a punch can aim at a bounded port set.
    #[must_use]
    pub const fn predictable(self) -> bool {
        matches!(self, Self::Sequential { .. } | Self::PortBlock { .. })
    }
}

impl fmt::Display for PortAlloc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Sequential { step, origin } => {
                write!(formatter, "{} step {step} origin {origin}", self.as_str())
            }
            Self::PortBlock { low, high } => {
                write!(formatter, "{} {low}-{high}", self.as_str())
            }
            Self::Unknown | Self::Random => formatter.write_str(self.as_str()),
        }
    }
}

/// The allocation class of `samples` in arrival order.
///
/// Four or more samples are required.
/// Equal positive steps are sequential.
/// Any other set that fits in [`PORT_BLOCK_SPAN`] is a port block.
/// A wider set is random.
#[must_use]
pub fn classify_ports(samples: &[u16]) -> PortAlloc {
    if samples.len() < CLASSIFY_MIN {
        return PortAlloc::Unknown;
    }
    if let Some((step, origin)) = equal_step(samples) {
        return PortAlloc::Sequential { step, origin };
    }
    let low = samples.iter().copied().min().unwrap_or(0);
    let high = samples.iter().copied().max().unwrap_or(low);
    if high.saturating_sub(low) <= PORT_BLOCK_SPAN {
        PortAlloc::PortBlock { low, high }
    } else {
        PortAlloc::Random
    }
}

/// Ports to spray for `alloc`.
///
/// Sequential allocation sprays the next [`PREDICT_COUNT`] ports.
/// A port block sprays a window around the midpoint.
/// Random and unknown allocations spray nothing.
#[must_use]
pub fn predict_targets(alloc: PortAlloc) -> Vec<u16> {
    match alloc {
        PortAlloc::Sequential { step, origin } => forward_ports(origin, step),
        PortAlloc::PortBlock { low, high } => cover_block(low, high),
        PortAlloc::Random | PortAlloc::Unknown => Vec::new(),
    }
}

/// The wait before predict attempt `attempt`.
///
/// Attempt 1 waits [`RETRY_MIN`]. Each later attempt doubles the wait.
/// The wait does not grow past [`RETRY_MAX`].
#[must_use]
pub fn retry_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(5);
    RETRY_MIN.saturating_mul(1_u32 << shift).min(RETRY_MAX)
}

/// Choose the punch plan.
///
/// Hard to hard uses [`Strategy::Predict`] when one allocation is predictable.
/// Two random hard NATs stay on [`Strategy::RelayOnly`].
#[must_use]
pub fn strategy_for(
    local: MappingKind,
    peer: MappingKind,
    local_alloc: PortAlloc,
    peer_alloc: PortAlloc,
) -> Strategy {
    match (local, peer) {
        (MappingKind::Hard, MappingKind::Hard)
            if local_alloc.predictable() || peer_alloc.predictable() =>
        {
            Strategy::Predict
        }
        (MappingKind::Hard, MappingKind::Hard) => Strategy::RelayOnly,
        _ => strategy(local, peer),
    }
}

/// Choose the punch plan from the mapping kinds alone.
///
/// Two hard NATs use the relay. Use [`strategy_for`] when the allocation class is known.
#[must_use]
pub fn strategy(local: MappingKind, peer: MappingKind) -> Strategy {
    match (local, peer) {
        (MappingKind::Easy, MappingKind::Hard) => Strategy::Spray,
        (MappingKind::Hard, MappingKind::Easy) => Strategy::Sockets,
        (MappingKind::Hard, MappingKind::Hard) => Strategy::RelayOnly,
        _ => Strategy::Plain,
    }
}

/// A token bucket for probe sends.
#[derive(Debug, Clone)]
pub struct RateGate {
    rate: u32,
    burst: u32,
    tokens: f64,
    last: Instant,
}

impl RateGate {
    /// A gate with `rate` sends per second and a burst of `burst`.
    #[must_use]
    pub fn new(rate: u32, burst: u32, now: Instant) -> Self {
        Self {
            rate,
            burst,
            tokens: f64::from(burst),
            last: now,
        }
    }

    /// The number of sends allowed at `now`, up to `want`.
    ///
    /// The function removes the allowed sends from the bucket.
    pub fn take(&mut self, now: Instant, want: u32) -> u32 {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * f64::from(self.rate)).min(f64::from(self.burst));
        let mut allowed = 0;
        while allowed < want && self.tokens >= 1.0 {
            self.tokens -= 1.0;
            allowed += 1;
        }
        allowed
    }
}

/// The port list for the easy side.
///
/// The value gives each port once at most.
#[derive(Debug, Clone)]
pub struct Spray {
    ip: IpAddr,
    predicted: Vec<u16>,
    sent: u32,
    started: Instant,
    gate: RateGate,
}

impl Spray {
    /// A spray toward `ip`.
    ///
    /// `seen` are the ports in the signed endpoints of the hard peer.
    #[must_use]
    pub fn new(ip: IpAddr, seen: &[u16], now: Instant) -> Self {
        Self {
            ip,
            predicted: predicted_ports(seen),
            sent: 0,
            started: now,
            gate: RateGate::new(PROBE_RATE, PROBE_BURST, now),
        }
    }

    /// Probes sent so far.
    #[must_use]
    pub fn sent(&self) -> u32 {
        self.sent
    }

    /// Return true after the probe count or the time limit.
    #[must_use]
    pub fn done(&self, now: Instant) -> bool {
        self.sent >= SPRAY_MAX || now.saturating_duration_since(self.started) >= BIRTHDAY_WINDOW
    }

    /// The targets for this tick.
    pub fn due(&mut self, now: Instant) -> Result<Vec<SocketAddr>, EdgeError> {
        if self.done(now) {
            return Ok(Vec::new());
        }
        let count = self.gate.take(now, SPRAY_MAX - self.sent);
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let index = self.sent as usize;
            let port = match self.predicted.get(index) {
                Some(port) => *port,
                None => random_port()?,
            };
            out.push(SocketAddr::new(self.ip, port));
            self.sent += 1;
        }
        Ok(out)
    }
}

/// The ports after the highest seen port, in the step between the seen ports.
///
/// A NAT that gives ports in order maps the next flow near the last port.
fn predicted_ports(seen: &[u16]) -> Vec<u16> {
    let Some(high) = seen.iter().copied().max() else {
        return Vec::new();
    };
    let low = seen.iter().copied().min().unwrap_or(high);
    let step = u32::from(high - low).clamp(1, 16);
    let mut out = Vec::new();
    for index in 1..=PREDICT_COUNT {
        let port = u32::from(high) + index * step;
        if port <= u32::from(u16::MAX) && port >= u32::from(PORT_MIN) {
            out.push(port as u16);
        }
    }
    out
}

fn equal_step(samples: &[u16]) -> Option<(u16, u16)> {
    let mut deltas = samples
        .windows(2)
        .map(|pair| i32::from(pair[1]) - i32::from(pair[0]));
    let first = deltas.next()?;
    if !(1..=64).contains(&first) {
        return None;
    }
    if deltas.any(|delta| delta != first) {
        return None;
    }
    let origin = samples.iter().copied().max()?;
    Some((u16::try_from(first).unwrap_or(1), origin))
}

fn forward_ports(origin: u16, step: u16) -> Vec<u16> {
    let step = u32::from(step.max(1));
    let mut port = u32::from(origin);
    let mut out = Vec::new();
    for _ in 0..PREDICT_COUNT {
        port = port.saturating_add(step);
        if port > u32::from(u16::MAX) || port < u32::from(PORT_MIN) {
            break;
        }
        out.push(u16::try_from(port).unwrap_or(u16::MAX));
    }
    out
}

fn cover_block(low: u16, high: u16) -> Vec<u16> {
    let low_u = u32::from(low);
    let high_u = u32::from(high);
    let mid = low_u.saturating_add(high_u) / 2;
    let span = high_u.saturating_sub(low_u);
    let radius = span.clamp(u32::from(PORT_BLOCK_RADIUS), 256);
    let start = mid.saturating_sub(radius).max(u32::from(PORT_MIN));
    let end = mid.saturating_add(radius).min(u32::from(u16::MAX));
    (start..=end)
        .filter_map(|port| u16::try_from(port).ok())
        .collect()
}

/// A spray that visits only the predicted ports.
///
/// The spray repeats the list until the probe cap or the time limit.
/// An empty list sends nothing and ends at the time limit.
#[derive(Debug, Clone)]
pub struct PredictSpray {
    ip: IpAddr,
    ports: Vec<u16>,
    index: usize,
    sent: u32,
    started: Instant,
    gate: RateGate,
}

impl PredictSpray {
    /// A spray of `ports` toward `ip`.
    #[must_use]
    pub fn new(ip: IpAddr, ports: Vec<u16>, now: Instant) -> Self {
        Self {
            ip,
            ports,
            index: 0,
            sent: 0,
            started: now,
            gate: RateGate::new(PROBE_RATE, PROBE_BURST, now),
        }
    }

    /// Replace the port list when the peer samples change.
    ///
    /// The probe count and the time limit stay in place.
    pub fn set_targets(&mut self, ip: IpAddr, ports: Vec<u16>) {
        self.ip = ip;
        if ports != self.ports {
            self.ports = ports;
            self.index = 0;
        }
    }

    /// Probes sent so far.
    #[must_use]
    pub fn sent(&self) -> u32 {
        self.sent
    }

    /// Return true after the probe count or the time limit.
    #[must_use]
    pub fn done(&self, now: Instant) -> bool {
        self.sent >= SPRAY_MAX || now.saturating_duration_since(self.started) >= BIRTHDAY_WINDOW
    }

    /// The targets for this tick.
    #[must_use]
    pub fn due(&mut self, now: Instant) -> Vec<SocketAddr> {
        if self.done(now) || self.ports.is_empty() {
            return Vec::new();
        }
        let room = SPRAY_MAX - self.sent;
        let count = self.gate.take(now, room);
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let port = self.ports[self.index % self.ports.len()];
            self.index += 1;
            out.push(SocketAddr::new(self.ip, port));
            self.sent += 1;
            if self.sent >= SPRAY_MAX {
                break;
            }
        }
        out
    }
}

fn random_port() -> Result<u16, EdgeError> {
    let mut bytes = [0u8; 2];
    getrandom::getrandom(&mut bytes).map_err(|err| EdgeError::Io(err.to_string()))?;
    let span = u32::from(u16::MAX - PORT_MIN) + 1;
    let value = u32::from(u16::from_be_bytes(bytes)) % span;
    Ok(PORT_MIN + value as u16)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use super::{
        classify_ports, local_kind, peer_kind, predict_targets, predicted_ports, retry_delay,
        strategy, strategy_for, MappingKind, PortAlloc, PredictSpray, RateGate, Spray, Strategy,
        BIRTHDAY_WINDOW, PORT_BLOCK_RADIUS, PORT_MIN, PREDICT_COUNT, PROBE_BURST, PROBE_RATE,
        RETRY_MAX, RETRY_MIN, SPRAY_MAX,
    };

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn kinds_come_from_two_endpoints() {
        let a = addr("198.51.100.1:443");
        let b = addr("198.51.100.1:5000");
        assert_eq!(local_kind(a, None), MappingKind::Unknown);
        assert_eq!(local_kind(a, Some(a)), MappingKind::Easy);
        assert_eq!(local_kind(a, Some(b)), MappingKind::Hard);
        assert_eq!(peer_kind(&[a]), MappingKind::Unknown);
        assert_eq!(peer_kind(&[a, a]), MappingKind::Easy);
        assert_eq!(peer_kind(&[a, b]), MappingKind::Hard);
        assert_eq!(
            peer_kind(&[a, addr("203.0.113.9:443")]),
            MappingKind::Unknown
        );
    }

    #[test]
    fn hard_to_hard_uses_the_relay() {
        assert_eq!(
            strategy(MappingKind::Easy, MappingKind::Easy),
            Strategy::Plain
        );
        assert_eq!(
            strategy(MappingKind::Easy, MappingKind::Hard),
            Strategy::Spray
        );
        assert_eq!(
            strategy(MappingKind::Hard, MappingKind::Easy),
            Strategy::Sockets
        );
        assert_eq!(
            strategy(MappingKind::Hard, MappingKind::Hard),
            Strategy::RelayOnly
        );
        assert_eq!(
            strategy(MappingKind::Unknown, MappingKind::Hard),
            Strategy::Plain
        );
    }

    #[test]
    fn the_rate_gate_limits_probes() {
        let start = Instant::now();
        let mut gate = RateGate::new(PROBE_RATE, PROBE_BURST, start);
        assert_eq!(gate.take(start, 1_000), PROBE_BURST);
        assert_eq!(gate.take(start, 1_000), 0);
        let later = start + Duration::from_millis(100);
        assert_eq!(gate.take(later, 1_000), PROBE_BURST);
        let much_later = later + Duration::from_secs(10);
        assert_eq!(gate.take(much_later, 1_000), PROBE_BURST);
    }

    #[test]
    fn the_spray_is_bounded() {
        let start = Instant::now();
        let ip = addr("198.51.100.1:1").ip();
        let mut spray = Spray::new(ip, &[30_000, 30_002], start);
        let mut total = Vec::new();
        let mut now = start;
        while !spray.done(now) {
            total.extend(spray.due(now).unwrap());
            now += Duration::from_millis(50);
        }
        assert!(total.len() as u32 <= SPRAY_MAX);
        assert_eq!(total.len() as u32, spray.sent());
        assert!(now - start <= BIRTHDAY_WINDOW + Duration::from_millis(50));
        assert!(total.iter().all(|target| target.ip() == ip));
        assert!(total.iter().all(|target| target.port() >= PORT_MIN));
        assert_eq!(total[0].port(), 30_004);
        assert!(spray.due(now).unwrap().is_empty());
    }

    #[test]
    fn hard_pair_plan_follows_the_allocation() {
        let sequential = PortAlloc::Sequential {
            step: 1,
            origin: 4_000,
        };
        let block = PortAlloc::PortBlock {
            low: 20_000,
            high: 20_040,
        };
        let random = PortAlloc::Random;
        assert_eq!(
            strategy_for(
                MappingKind::Hard,
                MappingKind::Hard,
                random,
                PortAlloc::Unknown
            ),
            Strategy::RelayOnly
        );
        assert_eq!(
            strategy_for(MappingKind::Hard, MappingKind::Hard, random, random),
            Strategy::RelayOnly
        );
        assert_eq!(
            strategy_for(MappingKind::Hard, MappingKind::Hard, sequential, random),
            Strategy::Predict
        );
        assert_eq!(
            strategy_for(MappingKind::Hard, MappingKind::Hard, random, block),
            Strategy::Predict
        );
        assert_eq!(
            strategy_for(MappingKind::Easy, MappingKind::Hard, sequential, random),
            Strategy::Spray
        );
        assert_eq!(
            strategy_for(MappingKind::Hard, MappingKind::Easy, random, sequential),
            Strategy::Sockets
        );
        assert_eq!(Strategy::Predict.as_str(), "predict-spray");
    }

    #[test]
    fn allocation_class_comes_from_the_samples() {
        assert_eq!(classify_ports(&[1, 2, 3]), PortAlloc::Unknown);
        assert_eq!(
            classify_ports(&[4_000, 4_001, 4_002, 4_003]),
            PortAlloc::Sequential {
                step: 1,
                origin: 4_003
            }
        );
        let block = classify_ports(&[20_010, 20_040, 20_003, 20_055, 20_021]);
        assert_eq!(
            block,
            PortAlloc::PortBlock {
                low: 20_003,
                high: 20_055
            }
        );
        assert!(classify_ports(&[2_000, 9_000, 20_000, 40_000, 60_000]) == PortAlloc::Random);
        assert_eq!(
            sequential_label(classify_ports(&[8, 9, 10, 11])),
            "sequential"
        );
        assert_eq!(block.as_str(), "port-block");
    }

    fn sequential_label(alloc: PortAlloc) -> &'static str {
        alloc.as_str()
    }

    #[test]
    fn predicted_ports_stay_in_a_bounded_set() {
        let sequential = predict_targets(PortAlloc::Sequential {
            step: 2,
            origin: 5_000,
        });
        assert_eq!(sequential.len(), PREDICT_COUNT as usize);
        assert_eq!(sequential[0], 5_002);
        assert_eq!(sequential[1], 5_004);
        let block = predict_targets(PortAlloc::PortBlock {
            low: 20_000,
            high: 20_063,
        });
        assert!(block.len() <= (PORT_BLOCK_RADIUS as usize) * 2 + 1);
        assert!(block.contains(&20_000));
        assert!(block.contains(&20_063));
        assert!(predict_targets(PortAlloc::Random).is_empty());
        assert!(predict_targets(PortAlloc::Unknown).is_empty());
    }

    #[test]
    fn the_predict_spray_uses_only_the_given_ports() {
        let start = Instant::now();
        let ip = addr("198.51.100.8:1").ip();
        let mut spray = PredictSpray::new(ip, vec![4_000, 4_001], start);
        let mut total = Vec::new();
        let mut now = start;
        while !spray.done(now) && total.len() < 10 {
            total.extend(spray.due(now));
            now += Duration::from_millis(50);
        }
        assert!(!total.is_empty());
        assert!(total
            .iter()
            .all(|target| target.port() == 4_000 || target.port() == 4_001));
        spray.set_targets(ip, vec![4_010]);
        let next = spray.due(now + Duration::from_secs(1));
        assert!(next.iter().all(|target| target.port() == 4_010));
        let mut idle = PredictSpray::new(ip, Vec::new(), start);
        assert!(idle.due(start).is_empty());
        assert!(!idle.done(start));
        assert!(idle.done(start + BIRTHDAY_WINDOW));
    }

    #[test]
    fn retry_delay_grows_and_then_stops() {
        assert_eq!(retry_delay(1), RETRY_MIN);
        assert_eq!(retry_delay(2), RETRY_MIN * 2);
        assert_eq!(retry_delay(3), RETRY_MIN * 4);
        assert_eq!(retry_delay(20), RETRY_MAX);
        assert!(retry_delay(6) <= RETRY_MAX);
    }

    #[test]
    fn prediction_follows_the_port_step() {
        let ports = predicted_ports(&[2_000, 2_001]);
        assert_eq!(ports.len() as u32, PREDICT_COUNT);
        assert_eq!(ports[0], 2_002);
        assert_eq!(ports[1], 2_003);
        assert!(predicted_ports(&[]).is_empty());
        assert!(predicted_ports(&[65_530]).len() < PREDICT_COUNT as usize);
    }
}
