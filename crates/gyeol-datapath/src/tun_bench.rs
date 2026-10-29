//! Local TUN round-trip bench.
//!
//! The bench opens one Linux TUN device with the in-tree path.
//! The bench sends IPv4 UDP packets to that device.
//! The bench wraps each packet in one ADR-0002 DATA frame.
//! The bench writes the packet back to the TUN device.
//! The bench does not use WireGuard, Headscale, or DERP.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::{Frame, FrameType};

/// IPv4 header length in bytes.
pub const BENCH_IPV4_HEADER_LEN: usize = 20;

/// UDP header length in bytes.
pub const BENCH_UDP_HEADER_LEN: usize = 8;

/// UDP payload length in bytes.
pub const BENCH_PAYLOAD_LEN: usize = 1400;

/// IPv4 packet length in bytes.
pub const BENCH_PACKET_LEN: usize =
    BENCH_IPV4_HEADER_LEN + BENCH_UDP_HEADER_LEN + BENCH_PAYLOAD_LEN;

/// Number of UDP payloads that complete a round trip.
pub const BENCH_ROUND_TRIPS: u64 = 50_000;

/// Number of UDP payloads in flight.
pub const BENCH_WINDOW: usize = 64;

/// Fill byte for the UDP payload after the sequence field.
pub const BENCH_PAYLOAD_FILL: u8 = 0x5a;

/// Local TUN address.
pub const BENCH_LOCAL: Ipv4Addr = Ipv4Addr::new(10, 88, 12, 1);

/// Peer address. The kernel routes this address to the TUN device.
pub const BENCH_PEER: Ipv4Addr = Ipv4Addr::new(10, 88, 12, 2);

/// IPv4 netmask.
pub const BENCH_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// UDP port for the bench sockets.
pub const BENCH_UDP_PORT: u16 = 47821;

/// Requested TUN device name.
pub const BENCH_IFACE: &str = "orblxbn";

/// ADR-0002 session id for the bench frames.
pub const BENCH_SESSION_ID: u32 = 12;

/// Ticket hash field. The bench does not check a capability ticket.
pub const BENCH_TICKET_HASH: [u8; 16] = [0; 16];

/// Pass threshold in decimal megabits per second.
pub const BENCH_MIN_MBPS: f64 = 100.0;

/// Wall-clock limit for the transfer.
const BENCH_DEADLINE: Duration = Duration::from_secs(60);

/// Read wait when the TUN device has no packet.
const BENCH_READ_WAIT: Duration = Duration::from_millis(50);

/// Bytes that cross the TUN device for `round_trips` round trips.
///
/// Each round trip reads one IPv4 packet and writes one IPv4 packet.
#[must_use]
pub const fn bench_transfer_bytes(round_trips: u64) -> u64 {
    round_trips * (BENCH_PACKET_LEN as u64) * 2
}

/// Decimal megabits per second.
///
/// `bits = bytes * 8`
/// `mbps = bits / elapsed_s / 1e6`
///
/// `elapsed_s` must be greater than zero.
/// `bytes` must be at most 2^53 so the value is an exact integer in `f64`.
#[must_use]
pub fn decimal_mbps(bytes: u64, elapsed_s: f64) -> f64 {
    let bits = (bytes as f64) * 8.0;
    bits / elapsed_s / 1_000_000.0
}

/// Return true when the effective capability set contains `CAP_NET_ADMIN`.
///
/// `hex` is the `CapEff` field. `CAP_NET_ADMIN` is bit 12.
#[must_use]
pub fn cap_eff_has_net_admin(hex: &str) -> bool {
    let Ok(value) = u128::from_str_radix(hex.trim(), 16) else {
        return false;
    };
    value & (1_u128 << 12) != 0
}

/// One measured local TUN round trip.
#[derive(Debug, Clone, PartialEq)]
pub struct TunBenchReport {
    /// Decimal megabits per second from [`decimal_mbps`].
    pub mbps: f64,
    /// IPv4 bytes read from the TUN device plus IPv4 bytes written to it.
    pub bytes: u64,
    /// Wall-clock seconds from the first UDP send to the last UDP receive.
    pub elapsed_s: f64,
    /// Completed round trips.
    pub round_trips: u64,
    /// UDP payload length in bytes.
    pub payload_len: usize,
    /// IPv4 packet length in bytes.
    pub packet_len: usize,
    /// TUN device name.
    pub iface: String,
}

impl TunBenchReport {
    /// Return true when the rate is at least [`BENCH_MIN_MBPS`].
    #[must_use]
    pub fn pass(&self) -> bool {
        self.mbps >= BENCH_MIN_MBPS
    }

    /// Machine-readable result lines.
    #[must_use]
    pub fn report_lines(&self) -> String {
        let result = if self.pass() { "pass" } else { "fail" };
        format!(
            "\
K3 tun_ready true
tun_bench_iface={iface}
tun_bench_mbps={mbps:.6}
tun_bench_result={result}
tun_bench_bytes={bytes}
tun_bench_elapsed_s={elapsed:.9}
tun_bench_round_trips={round_trips}
tun_bench_payload_len={payload_len}
tun_bench_packet_len={packet_len}
tun_bench_window={window}
tun_bench_min_mbps=100
tun_bench_formula=bits = bytes * 8; mbps = bits / elapsed_s / 1e6
",
            iface = self.iface,
            mbps = self.mbps,
            bytes = self.bytes,
            elapsed = self.elapsed_s,
            round_trips = self.round_trips,
            payload_len = self.payload_len,
            packet_len = self.packet_len,
            window = BENCH_WINDOW,
        )
    }
}

/// The bench ran, or the host cannot open a TUN device.
#[derive(Debug, Clone, PartialEq)]
pub enum TunBenchOutcome {
    /// The bench measured one round trip.
    Measured(TunBenchReport),
    /// The host cannot run the live TUN bench.
    Skipped(String),
}

/// Run one local TUN round trip.
///
/// On a host that cannot open a TUN device, the function returns [`TunBenchOutcome::Skipped`].
/// The caller prints that reason and exits 0.
pub fn run_local_tun_bench() -> Result<TunBenchOutcome, String> {
    #[cfg(target_os = "linux")]
    {
        live::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(TunBenchOutcome::Skipped(
            "K3: This host is not Linux. The local TUN bench measures a Linux TUN device."
                .to_string(),
        ))
    }
}

fn reflect_bench_packet(packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if !is_bench_request(packet) {
        return Ok(None);
    }
    let framed = data_frame_bytes(packet)?;
    let decoded = Frame::decode(&framed).map_err(|err| err.to_string())?;
    if decoded.frame_type != FrameType::Data {
        return Err("The frame type is not DATA.".to_string());
    }
    if decoded.session_id != BENCH_SESSION_ID || decoded.ticket_hash != BENCH_TICKET_HASH {
        return Err("The DATA frame header is not the bench header.".to_string());
    }
    if decoded.payload.as_slice() != packet {
        return Err("The DATA frame payload differs from the IPv4 packet.".to_string());
    }
    let mut reply = decoded.payload;
    swap_headers(&mut reply)?;
    write_checksums(&mut reply)?;
    Ok(Some(reply))
}

fn is_bench_request(packet: &[u8]) -> bool {
    if packet.len() != BENCH_PACKET_LEN || packet[0] != 0x45 {
        return false;
    }
    if !crate::is_ipv4_packet(packet) {
        return false;
    }
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    if frag & 0x3fff != 0 {
        return false;
    }
    if packet[9] != 17 {
        return false;
    }
    if packet[12..16] != BENCH_LOCAL.octets() || packet[16..20] != BENCH_PEER.octets() {
        return false;
    }
    let src_port = u16::from_be_bytes([packet[20], packet[21]]);
    let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
    if src_port != BENCH_UDP_PORT || dst_port != BENCH_UDP_PORT {
        return false;
    }
    let udp_len = u16::from_be_bytes([packet[24], packet[25]]);
    udp_len == u16::try_from(BENCH_UDP_HEADER_LEN + BENCH_PAYLOAD_LEN).unwrap_or(0)
}

fn data_frame_bytes(packet: &[u8]) -> Result<Vec<u8>, String> {
    let seq = payload_seq(packet)?;
    let frame = Frame {
        frame_type: FrameType::Data,
        flags: 0,
        session_id: BENCH_SESSION_ID,
        seq,
        ticket_hash: BENCH_TICKET_HASH,
        payload: packet.to_vec(),
    };
    Ok(frame.encode())
}

fn payload_seq(packet: &[u8]) -> Result<u64, String> {
    let start = BENCH_IPV4_HEADER_LEN + BENCH_UDP_HEADER_LEN;
    let end = start + 8;
    let slice = packet
        .get(start..end)
        .ok_or_else(|| "The UDP payload is short.".to_string())?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(slice);
    Ok(u64::from_be_bytes(bytes))
}

fn swap_headers(packet: &mut [u8]) -> Result<(), String> {
    if packet.len() < BENCH_IPV4_HEADER_LEN + BENCH_UDP_HEADER_LEN {
        return Err("The packet is shorter than the IPv4 and UDP headers.".to_string());
    }
    let src = [packet[12], packet[13], packet[14], packet[15]];
    let dst = [packet[16], packet[17], packet[18], packet[19]];
    packet[12..16].copy_from_slice(&dst);
    packet[16..20].copy_from_slice(&src);
    let src_port = [packet[20], packet[21]];
    let dst_port = [packet[22], packet[23]];
    packet[20..22].copy_from_slice(&dst_port);
    packet[22..24].copy_from_slice(&src_port);
    Ok(())
}

fn write_checksums(packet: &mut [u8]) -> Result<(), String> {
    if packet.len() != BENCH_PACKET_LEN || packet[0] != 0x45 {
        return Err("The packet is not one bench IPv4 packet.".to_string());
    }
    packet[10] = 0;
    packet[11] = 0;
    let ip_sum = internet_checksum(&packet[..BENCH_IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[26] = 0;
    packet[27] = 0;
    let mut udp_sum = udp_checksum(packet)?;
    if udp_sum == 0 {
        udp_sum = 0xffff;
    }
    packet[26..28].copy_from_slice(&udp_sum.to_be_bytes());
    Ok(())
}

fn udp_checksum(packet: &[u8]) -> Result<u16, String> {
    let udp = packet
        .get(BENCH_IPV4_HEADER_LEN..)
        .ok_or_else(|| "The packet has no UDP segment.".to_string())?;
    let mut buf = [0u8; 12 + BENCH_PACKET_LEN];
    let end = 12 + udp.len();
    if end > buf.len() {
        return Err("The UDP segment is too long.".to_string());
    }
    buf[0..4].copy_from_slice(&packet[12..16]);
    buf[4..8].copy_from_slice(&packet[16..20]);
    buf[9] = 17;
    let udp_len =
        u16::try_from(udp.len()).map_err(|_| "The UDP length does not fit.".to_string())?;
    buf[10..12].copy_from_slice(&udp_len.to_be_bytes());
    buf[12..end].copy_from_slice(udp);
    Ok(internet_checksum(&buf[..end]))
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[index], data[index + 1]]));
        index += 2;
    }
    if index < data.len() {
        sum += u32::from(data[index]) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

#[cfg(test)]
fn sample_udp(seq: u64) -> Vec<u8> {
    let mut packet = vec![0u8; BENCH_PACKET_LEN];
    packet[0] = 0x45;
    let total = u16::try_from(BENCH_PACKET_LEN).unwrap_or(0);
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&BENCH_LOCAL.octets());
    packet[16..20].copy_from_slice(&BENCH_PEER.octets());
    packet[20..22].copy_from_slice(&BENCH_UDP_PORT.to_be_bytes());
    packet[22..24].copy_from_slice(&BENCH_UDP_PORT.to_be_bytes());
    let udp_len = u16::try_from(BENCH_UDP_HEADER_LEN + BENCH_PAYLOAD_LEN).unwrap_or(0);
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
    let payload = &mut packet[BENCH_IPV4_HEADER_LEN + BENCH_UDP_HEADER_LEN..];
    payload.fill(BENCH_PAYLOAD_FILL);
    payload[..8].copy_from_slice(&seq.to_be_bytes());
    write_checksums(&mut packet).expect("the sample packet is one bench packet");
    packet
}

#[cfg(target_os = "linux")]
mod live {
    use super::{
        bench_transfer_bytes, cap_eff_has_net_admin, decimal_mbps, reflect_bench_packet,
        TunBenchOutcome, TunBenchReport, BENCH_DEADLINE, BENCH_IFACE, BENCH_LOCAL, BENCH_NETMASK,
        BENCH_PACKET_LEN, BENCH_PAYLOAD_FILL, BENCH_PAYLOAD_LEN, BENCH_PEER, BENCH_READ_WAIT,
        BENCH_ROUND_TRIPS, BENCH_UDP_PORT, BENCH_WINDOW,
    };
    use crate::tun_dev::open_linux_device;
    use crate::TunConfig;
    use std::io::ErrorKind;
    use std::net::{IpAddr, SocketAddr, UdpSocket};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;
    use tun::AbstractDevice;

    struct Shared {
        stop: AtomicBool,
        bytes: AtomicU64,
        reflected: AtomicU64,
        error: Mutex<Option<String>>,
    }

    struct RpFilterRestore {
        previous: String,
    }

    impl RpFilterRestore {
        fn relax(iface: &str) -> Result<Self, String> {
            if iface.is_empty() || !iface.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                return Err("The TUN name is not valid.".to_string());
            }
            let all_path = "/proc/sys/net/ipv4/conf/all/rp_filter";
            let previous = std::fs::read_to_string(all_path)
                .map_err(|err| format!("The rp_filter read failed. {err}"))?;
            std::fs::write(all_path, "0\n")
                .map_err(|err| format!("The rp_filter write failed. {err}"))?;
            let guard = Self { previous };
            let dev_path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
            std::fs::write(&dev_path, "0\n")
                .map_err(|err| format!("The interface rp_filter write failed. {err}"))?;
            let ipv6_path = format!("/proc/sys/net/ipv6/conf/{iface}/disable_ipv6");
            let _ = std::fs::write(ipv6_path, "1\n");
            Ok(guard)
        }
    }

    impl Drop for RpFilterRestore {
        fn drop(&mut self) {
            let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", &self.previous);
        }
    }

    pub(super) fn run() -> Result<TunBenchOutcome, String> {
        if let Some(reason) = skip_reason() {
            return Ok(TunBenchOutcome::Skipped(reason));
        }
        measure()
    }

    fn skip_reason() -> Option<String> {
        if !std::path::Path::new("/dev/net/tun").exists() {
            return Some("K3: /dev/net/tun is absent.".to_string());
        }
        if !process_has_net_admin() {
            return Some("K3: CAP_NET_ADMIN is absent.".to_string());
        }
        if !ip_available() {
            return Some("K3: The ip command is absent. The TUN bench needs iproute2.".to_string());
        }
        None
    }

    fn process_has_net_admin() -> bool {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        for line in status.lines() {
            let Some(hex) = line.strip_prefix("CapEff:") else {
                continue;
            };
            return cap_eff_has_net_admin(hex);
        }
        false
    }

    fn ip_available() -> bool {
        const CANDIDATES: [&str; 4] = ["ip", "/usr/sbin/ip", "/sbin/ip", "/bin/ip"];
        CANDIDATES.iter().any(|cmd| {
            std::process::Command::new(cmd)
                .arg("-V")
                .output()
                .is_ok_and(|output| output.status.success())
        })
    }

    fn measure() -> Result<TunBenchOutcome, String> {
        let config = TunConfig {
            name: Some(BENCH_IFACE.to_string()),
            address: BENCH_LOCAL,
            netmask: BENCH_NETMASK,
        };
        let device = open_linux_device(&config).map_err(|err| err.to_string())?;
        let iface = device.tun_name().map_err(|err| err.to_string())?;
        let address = device.address().map_err(|err| err.to_string())?;
        if address != IpAddr::V4(BENCH_LOCAL) {
            return Err("The TUN address is not the bench address.".to_string());
        }
        let netmask = device.netmask().map_err(|err| err.to_string())?;
        if netmask != IpAddr::V4(BENCH_NETMASK) {
            return Err("The TUN netmask is not the bench netmask.".to_string());
        }
        let _rp_filter = RpFilterRestore::relax(&iface)?;
        let socket = UdpSocket::bind(SocketAddr::from((BENCH_LOCAL, BENCH_UDP_PORT)))
            .map_err(|err| format!("The UDP bind failed. {err}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|err| format!("The UDP socket mode failed. {err}"))?;
        let (elapsed_s, bytes) = transfer(device, socket)?;
        if !(elapsed_s.is_finite() && elapsed_s > 0.0) {
            return Err("The elapsed time is not a positive number.".to_string());
        }
        if bytes > (1_u64 << 53) {
            return Err("The byte count is too large for the Mbps formula.".to_string());
        }
        let expected = bench_transfer_bytes(BENCH_ROUND_TRIPS);
        if bytes != expected {
            return Err(format!(
                "The TUN byte count is {bytes}. The round-trip byte count is {expected}."
            ));
        }
        let mbps = decimal_mbps(bytes, elapsed_s);
        if !mbps.is_finite() {
            return Err("The Mbps value is not a finite number.".to_string());
        }
        Ok(TunBenchOutcome::Measured(TunBenchReport {
            mbps,
            bytes,
            elapsed_s,
            round_trips: BENCH_ROUND_TRIPS,
            payload_len: BENCH_PAYLOAD_LEN,
            packet_len: BENCH_PACKET_LEN,
            iface,
        }))
    }

    fn transfer(device: tun::Device, socket: UdpSocket) -> Result<(f64, u64), String> {
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            bytes: AtomicU64::new(0),
            reflected: AtomicU64::new(0),
            error: Mutex::new(None),
        });
        let shared_reader = Arc::clone(&shared);
        let reader = thread::Builder::new()
            .name("gyeol-tun-bench".to_string())
            .spawn(move || reflect_loop(device, shared_reader))
            .map_err(|err| format!("The TUN reader thread did not start. {err}"))?;
        let pumped = pump_socket(&socket, &shared);
        shared.stop.store(true, Ordering::Release);
        let joined = reader
            .join()
            .map_err(|_| "The TUN reader thread stopped.".to_string())?;
        joined?;
        let elapsed_s = pumped?;
        let reflected = shared.reflected.load(Ordering::Acquire);
        if reflected != BENCH_ROUND_TRIPS {
            return Err(format!(
                "The TUN device reflected {reflected} packets. The bench sent {BENCH_ROUND_TRIPS} packets."
            ));
        }
        Ok((elapsed_s, shared.bytes.load(Ordering::Acquire)))
    }

    fn reflect_loop(device: tun::Device, shared: Arc<Shared>) -> Result<(), String> {
        let mut buf = vec![0u8; 65_535];
        while !shared.stop.load(Ordering::Acquire) {
            match device.recv_timeout(&mut buf, BENCH_READ_WAIT) {
                Ok(size) => {
                    let reply = match reflect_bench_packet(&buf[..size]) {
                        Ok(Some(reply)) => reply,
                        Ok(None) => continue,
                        Err(err) => return fail(&shared, err),
                    };
                    if size != BENCH_PACKET_LEN || reply.len() != BENCH_PACKET_LEN {
                        return fail(
                            &shared,
                            "The TUN packet length is not the bench packet length.".to_string(),
                        );
                    }
                    let addend = u64::try_from(size + reply.len())
                        .map_err(|_| "The packet length does not fit.".to_string())?;
                    shared.bytes.fetch_add(addend, Ordering::Release);
                    shared.reflected.fetch_add(1, Ordering::Release);
                    match device.send(&reply) {
                        Ok(wrote) if wrote == reply.len() => {}
                        Ok(_) => {
                            return fail(
                                &shared,
                                "The TUN device wrote a short packet.".to_string(),
                            );
                        }
                        Err(err) => return fail(&shared, format!("The TUN write failed. {err}")),
                    }
                }
                Err(err) if is_idle(err.kind()) => {}
                Err(err) => return fail(&shared, format!("The TUN read failed. {err}")),
            }
        }
        Ok(())
    }

    fn fail(shared: &Shared, err: String) -> Result<(), String> {
        if let Ok(mut slot) = shared.error.lock() {
            *slot = Some(err.clone());
        }
        Err(err)
    }

    fn is_idle(kind: ErrorKind) -> bool {
        matches!(
            kind,
            ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
        )
    }

    fn pump_socket(socket: &UdpSocket, shared: &Shared) -> Result<f64, String> {
        let peer = SocketAddr::from((BENCH_PEER, BENCH_UDP_PORT));
        let mut payload = [BENCH_PAYLOAD_FILL; BENCH_PAYLOAD_LEN];
        let mut recv_buf = [0u8; 2048];
        let trips = usize::try_from(BENCH_ROUND_TRIPS)
            .map_err(|_| "The round-trip count is too large.".to_string())?;
        let mut seen = vec![false; trips];
        let mut sent = 0u64;
        let mut got = 0u64;
        let mut inflight = 0usize;
        let mut start: Option<Instant> = None;
        let deadline = Instant::now() + BENCH_DEADLINE;
        loop {
            if let Some(err) = shared_error(shared) {
                return Err(err);
            }
            if Instant::now() >= deadline {
                return Err("The bench did not receive every UDP reply.".to_string());
            }
            let mut progress = false;
            while inflight < BENCH_WINDOW && sent < BENCH_ROUND_TRIPS {
                payload[..8].copy_from_slice(&sent.to_be_bytes());
                let now = Instant::now();
                match socket.send_to(&payload, peer) {
                    Ok(size) if size == payload.len() => {
                        if start.is_none() {
                            start = Some(now);
                        }
                        sent += 1;
                        inflight += 1;
                        progress = true;
                    }
                    Ok(_) => return Err("The UDP send wrote a short payload.".to_string()),
                    Err(err) if is_idle(err.kind()) => break,
                    Err(err) => return Err(format!("The UDP send failed. {err}")),
                }
            }
            loop {
                match socket.recv_from(&mut recv_buf) {
                    Ok((size, _)) => {
                        accept_reply(&recv_buf[..size], &mut seen)?;
                        got += 1;
                        inflight = inflight.saturating_sub(1);
                        progress = true;
                        if got == BENCH_ROUND_TRIPS {
                            let started =
                                start.ok_or_else(|| "The bench has no start time.".to_string())?;
                            return Ok(started.elapsed().as_secs_f64());
                        }
                    }
                    Err(err) if is_idle(err.kind()) => break,
                    Err(err) => return Err(format!("The UDP receive failed. {err}")),
                }
            }
            if !progress {
                thread::yield_now();
            }
        }
    }

    fn accept_reply(buf: &[u8], seen: &mut [bool]) -> Result<(), String> {
        if buf.len() != BENCH_PAYLOAD_LEN {
            return Err(format!("The UDP reply length is {} bytes.", buf.len()));
        }
        if buf[8..].iter().any(|byte| *byte != BENCH_PAYLOAD_FILL) {
            return Err("The UDP reply payload is not the bench payload.".to_string());
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[..8]);
        let seq = u64::from_be_bytes(seq_bytes);
        let Some(index) = usize::try_from(seq)
            .ok()
            .filter(|index| *index < seen.len())
        else {
            return Err("The UDP reply sequence is outside the bench range.".to_string());
        };
        if seen[index] {
            return Err("The UDP reply sequence is a duplicate.".to_string());
        }
        seen[index] = true;
        Ok(())
    }

    fn shared_error(shared: &Shared) -> Option<String> {
        shared.error.lock().ok().and_then(|slot| slot.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bench_transfer_bytes, cap_eff_has_net_admin, data_frame_bytes, decimal_mbps,
        internet_checksum, reflect_bench_packet, sample_udp, udp_checksum, TunBenchReport,
        BENCH_LOCAL, BENCH_MIN_MBPS, BENCH_PACKET_LEN, BENCH_PAYLOAD_LEN, BENCH_PEER,
        BENCH_ROUND_TRIPS, BENCH_SESSION_ID, BENCH_TICKET_HASH, BENCH_WINDOW,
    };
    use crate::{Frame, FrameType};

    #[test]
    fn decimal_mbps_uses_the_documented_formula() {
        let mbps = decimal_mbps(12_500_000, 1.0);
        assert!((mbps - 100.0).abs() < 1e-9);
        let half = decimal_mbps(1_000_000, 0.5);
        assert!((half - 16.0).abs() < 1e-9);
        let one = decimal_mbps(125_000, 1.0);
        assert!((one - 1.0).abs() < 1e-12);
        assert!((BENCH_MIN_MBPS - 100.0).abs() < 1e-9);
    }

    #[test]
    fn transfer_bytes_count_both_directions() {
        assert_eq!(BENCH_PACKET_LEN, 1428);
        assert_eq!(bench_transfer_bytes(1), 2_856);
        assert_eq!(
            bench_transfer_bytes(BENCH_ROUND_TRIPS),
            BENCH_ROUND_TRIPS * 1_428 * 2
        );
    }

    #[test]
    fn cap_eff_bit_12_is_net_admin() {
        assert!(cap_eff_has_net_admin("0000000000001000"));
        assert!(cap_eff_has_net_admin("000001ffffffffff"));
        assert!(!cap_eff_has_net_admin("0000000000000000"));
        assert!(!cap_eff_has_net_admin("not-hex"));
    }

    #[test]
    fn data_frame_round_trip_keeps_the_ipv4_packet() {
        let packet = sample_udp(3);
        let bytes = data_frame_bytes(&packet).unwrap();
        let frame = Frame::decode(&bytes).unwrap();
        assert_eq!(frame.frame_type, FrameType::Data);
        assert_eq!(frame.session_id, BENCH_SESSION_ID);
        assert_eq!(frame.seq, 3);
        assert_eq!(frame.ticket_hash, BENCH_TICKET_HASH);
        assert_eq!(frame.payload, packet);
        assert_eq!(frame.flags, 0);
    }

    #[test]
    fn reflect_swaps_the_peers_and_keeps_valid_checksums() {
        let packet = sample_udp(7);
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert_eq!(udp_checksum(&packet).unwrap(), 0);
        let reply = reflect_bench_packet(&packet).unwrap().unwrap();
        assert_eq!(&reply[12..16], &BENCH_PEER.octets());
        assert_eq!(&reply[16..20], &BENCH_LOCAL.octets());
        assert_eq!(reply[28..], packet[28..]);
        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(udp_checksum(&reply).unwrap(), 0);
        assert!(reflect_bench_packet(&reply).unwrap().is_none());
    }

    #[test]
    fn reflect_ignores_a_packet_that_is_not_the_bench_request() {
        let mut packet = sample_udp(1);
        packet[9] = 1;
        assert!(reflect_bench_packet(&packet).unwrap().is_none());
        packet[9] = 17;
        packet[0] = 0x60;
        assert!(reflect_bench_packet(&packet).unwrap().is_none());
    }

    #[test]
    fn report_lines_print_the_measured_fields() {
        let report = TunBenchReport {
            mbps: 100.0,
            bytes: bench_transfer_bytes(BENCH_ROUND_TRIPS),
            elapsed_s: 1.5,
            round_trips: BENCH_ROUND_TRIPS,
            payload_len: BENCH_PAYLOAD_LEN,
            packet_len: BENCH_PACKET_LEN,
            iface: "orblxbn".to_string(),
        };
        let text = report.report_lines();
        assert!(report.pass());
        assert!(text.contains("K3 tun_ready true\n"));
        assert!(text.contains("tun_bench_iface=orblxbn\n"));
        assert!(text.contains("tun_bench_mbps=100.000000\n"));
        assert!(text.contains("tun_bench_result=pass\n"));
        assert!(text.contains("tun_bench_elapsed_s=1.500000000\n"));
        assert!(text.contains(&format!("tun_bench_window={BENCH_WINDOW}\n")));
        assert!(
            text.contains("tun_bench_formula=bits = bytes * 8; mbps = bits / elapsed_s / 1e6\n")
        );
        let slow = TunBenchReport {
            mbps: 99.0,
            ..report
        };
        assert!(!slow.pass());
        assert!(slow.report_lines().contains("tun_bench_result=fail\n"));
    }
}
