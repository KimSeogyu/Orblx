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
//! - Hard to hard: no punch can predict two random ports. The node uses the relay.
//!
//! Each send is rate-limited by [`RateGate`].
//! Each attempt has a fixed probe count and a fixed time limit.

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
        }
    }
}

/// Choose the punch plan.
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
        local_kind, peer_kind, predicted_ports, strategy, MappingKind, RateGate, Spray, Strategy,
        BIRTHDAY_WINDOW, PORT_MIN, PREDICT_COUNT, PROBE_BURST, PROBE_RATE, SPRAY_MAX,
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
    fn prediction_follows_the_port_step() {
        let ports = predicted_ports(&[2_000, 2_001]);
        assert_eq!(ports.len() as u32, PREDICT_COUNT);
        assert_eq!(ports[0], 2_002);
        assert_eq!(ports[1], 2_003);
        assert!(predicted_ports(&[]).is_empty());
        assert!(predicted_ports(&[65_530]).len() < PREDICT_COUNT as usize);
    }
}
