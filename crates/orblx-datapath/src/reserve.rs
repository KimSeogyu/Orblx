//! Reserve loopback sockets for tests.
//!
//! One call binds every socket before it returns a port.
//! The ports of that call are pairwise different.
//! Keep each socket until the node or the listener takes it.
//! A dropped socket releases the port. The next bind can reuse that port.

use std::collections::HashSet;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};

/// Bind `count` UDP sockets on 127.0.0.1.
///
/// The function binds every socket before it reads a port.
/// The ports are pairwise different.
#[must_use]
pub fn reserve_udp_sockets(count: usize) -> Vec<UdpSocket> {
    let sockets = (0..count)
        .map(|_| {
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("The test did not bind a UDP socket on 127.0.0.1.")
        })
        .collect::<Vec<_>>();
    let ports = sockets
        .iter()
        .map(|socket| {
            socket
                .local_addr()
                .expect("The UDP socket has no local port.")
                .port()
        })
        .collect::<Vec<_>>();
    assert_ports_differ(&ports);
    sockets
}

/// Bind `count` TCP listeners on 127.0.0.1.
///
/// The function binds every listener before it reads a port.
/// The ports are pairwise different.
#[must_use]
pub fn reserve_tcp_listeners(count: usize) -> Vec<TcpListener> {
    let listeners = (0..count)
        .map(|_| {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("The test did not bind a TCP listener on 127.0.0.1.")
        })
        .collect::<Vec<_>>();
    let ports = listeners
        .iter()
        .map(|listener| {
            listener
                .local_addr()
                .expect("The TCP listener has no local port.")
                .port()
        })
        .collect::<Vec<_>>();
    assert_ports_differ(&ports);
    listeners
}

fn assert_ports_differ(ports: &[u16]) {
    let mut seen = HashSet::with_capacity(ports.len());
    for port in ports {
        assert!(
            seen.insert(*port),
            "One allocation returned port {port} more than once. Ports: {ports:?}."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{reserve_tcp_listeners, reserve_udp_sockets};

    #[test]
    fn one_allocation_returns_pairwise_different_ports() {
        let sockets = reserve_udp_sockets(8);
        let udp_ports: Vec<u16> = sockets
            .iter()
            .map(|socket| socket.local_addr().unwrap().port())
            .collect();
        assert_pairwise(&udp_ports);

        let listeners = reserve_tcp_listeners(8);
        let tcp_ports: Vec<u16> = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect();
        assert_pairwise(&tcp_ports);
    }

    fn assert_pairwise(ports: &[u16]) {
        let mut unique = ports.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            ports.len(),
            "One allocation returned a port more than once. Ports: {ports:?}."
        );
    }
}
