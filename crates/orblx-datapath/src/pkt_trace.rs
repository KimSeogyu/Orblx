//! Opt-in TCP packet time trace at the TUN device (W25-39).
//!
//! When `ORBLX_DP_TRACE_FILE` and `ORBLX_DP_TRACE_PORTS` are set, the node writes one
//! line for each TCP packet that it reads from or writes to the TUN device, if the
//! source or the destination port is in the port list. The line holds the time in
//! microseconds, the addresses, the ports, the TCP flags, and the payload length.
//! The line holds no payload byte. When the variables are not set, the trace does nothing.
//!
//! W25-41: the same trace also marks the stages inside the node (channel hops, the
//! stream write, the frame read, the ticket check) with the TCP sequence number, and
//! it marks each UDP send and receive of the QUIC socket (the size and the count only).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

struct Tracer {
    file: Mutex<File>,
    ports: Vec<u16>,
}

static TRACER: OnceLock<Option<Tracer>> = OnceLock::new();

fn tracer() -> Option<&'static Tracer> {
    TRACER
        .get_or_init(|| {
            let path = std::env::var_os("ORBLX_DP_TRACE_FILE")?;
            let ports: Vec<u16> = std::env::var("ORBLX_DP_TRACE_PORTS")
                .ok()?
                .split(',')
                .filter_map(|text| text.trim().parse().ok())
                .collect();
            if ports.is_empty() {
                return None;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()?;
            Some(Tracer {
                file: Mutex::new(file),
                ports,
            })
        })
        .as_ref()
}

/// The fields of one TCP packet for the trace.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TcpFields {
    pub src: Ipv4Addr,
    pub src_port: u16,
    pub dst: Ipv4Addr,
    pub dst_port: u16,
    pub flags: u8,
    pub seq: u32,
    pub payload: usize,
}

/// Parse an IPv4 TCP packet. Other packets give `None`.
pub(crate) fn tcp_fields(packet: &[u8]) -> Option<TcpFields> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let tcp = packet.get(ihl..total.min(packet.len()))?;
    if tcp.len() < 20 {
        return None;
    }
    let offset = usize::from(tcp[12] >> 4) * 4;
    Some(TcpFields {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        flags: tcp[13],
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        payload: tcp.len().saturating_sub(offset),
    })
}

/// Return true when the trace is on.
pub(crate) fn enabled() -> bool {
    tracer().is_some()
}

fn now_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_micros())
        .unwrap_or(0)
}

/// Write one trace line for a packet at one stage.
///
/// `stage` is `read` (from the TUN device), `write` (to the TUN device), or the name
/// of a stage inside the node (W25-41).
pub(crate) fn trace_tun(stage: &str, packet: &[u8]) {
    let Some(tracer) = tracer() else {
        return;
    };
    let at_us = now_us();
    let Some(tcp) = tcp_fields(packet) else {
        return;
    };
    if !tracer.ports.contains(&tcp.src_port) && !tracer.ports.contains(&tcp.dst_port) {
        return;
    }
    if let Ok(mut file) = tracer.file.lock() {
        // A trace write error does not stop the datapath.
        let _ = writeln!(
            file,
            "dp {stage} at_us {at_us} src {}:{} dst {}:{} flags {:02x} len {} seq {}",
            tcp.src, tcp.src_port, tcp.dst, tcp.dst_port, tcp.flags, tcp.payload, tcp.seq
        );
    }
}

/// Write one trace line for a UDP send or receive of the QUIC socket (W25-41).
///
/// The line holds the byte count and the datagram count. It holds no byte of the datagram.
pub(crate) fn trace_udp(stage: &str, bytes: usize, datagrams: usize) {
    let Some(tracer) = tracer() else {
        return;
    };
    let at_us = now_us();
    if let Ok(mut file) = tracer.file.lock() {
        let _ = writeln!(
            file,
            "udp {stage} at_us {at_us} bytes {bytes} datagrams {datagrams}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tcp_syn_gives_the_ports_flags_and_no_payload() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
        packet[16..20].copy_from_slice(&[100, 64, 0, 3]);
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&8080u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x02;
        let fields = tcp_fields(&packet).unwrap();
        assert_eq!(fields.src, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(fields.src_port, 40000);
        assert_eq!(fields.dst_port, 8080);
        assert_eq!(fields.flags, 0x02);
        assert_eq!(fields.seq, 0);
        assert_eq!(fields.payload, 0);
    }

    #[test]
    fn a_udp_packet_is_not_traced() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        assert_eq!(tcp_fields(&packet), None);
    }
}
