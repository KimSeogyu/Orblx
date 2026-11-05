//! Test UDP ports that no other socket in this test process can take.
//!
//! A port from a probe socket on port 0 is free only until the probe socket drops. After
//! that, the OS can give the same port to the next bind on port 0: a second probe, a QUIC
//! dial socket, or a node in a parallel test. CI job 124484475182 shows this: `port_a` and
//! `port_b` were both 127.0.0.1:47900, so node b did not start its listener and node a
//! dialed its own socket.
//!
//! This module gives ports from a range below the ephemeral port range. A bind on port 0
//! never gets a port from this range. One counter for the full process gives each port one
//! time only, so two callers in this process never get the same port.

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

/// The first test port.
const FIRST: u32 = 20_000;
/// The number of test ports. The last test port is 29_999.
const SPAN: u32 = 10_000;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// Gives a UDP port on 127.0.0.1 that no other caller in this process gets.
///
/// The port is outside the ephemeral port range, so no bind on port 0 can take it.
/// A port that another process holds is not given.
pub(crate) fn free_port() -> u16 {
    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(check_ephemeral_range);
    // Two test processes start at different ports.
    let start = std::process::id() % SPAN;
    loop {
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(index < SPAN, "all {SPAN} test ports are used");
        let port = u16::try_from(FIRST + (start + index) % SPAN).unwrap();
        // No socket in this process holds this port. A bind fails only when another
        // process holds it, so the next port is used.
        if UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

/// Stops the test when the test port range is in the ephemeral port range.
fn check_ephemeral_range() {
    let (low, high) = ephemeral_range();
    let last = FIRST + SPAN - 1;
    assert!(
        last < low || FIRST > high,
        "the test ports {FIRST}-{last} are in the ephemeral port range {low}-{high}"
    );
}

#[cfg(target_os = "linux")]
fn ephemeral_range() -> (u32, u32) {
    let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .expect("the ephemeral port range did not read");
    let mut parts = text
        .split_whitespace()
        .map(|part| part.parse::<u32>().unwrap());
    (parts.next().unwrap(), parts.next().unwrap())
}

#[cfg(target_os = "macos")]
fn ephemeral_range() -> (u32, u32) {
    let read = |key: &str| {
        let out = std::process::Command::new("sysctl")
            .args(["-n", key])
            .output()
            .expect("sysctl did not run");
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    };
    (
        read("net.inet.ip.portrange.first"),
        read("net.inet.ip.portrange.last"),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ephemeral_range() -> (u32, u32) {
    panic!("the test ports have no ephemeral port range check for this OS")
}

#[test]
fn two_calls_never_give_the_same_port() {
    let ports: Vec<u16> = (0..64).map(|_| free_port()).collect();
    let mut sorted = ports.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ports.len(), "a test port was given two times");
    let (low, high) = ephemeral_range();
    for port in ports {
        let port = u32::from(port);
        assert!(port < low || port > high, "port {port} is ephemeral");
    }
}
