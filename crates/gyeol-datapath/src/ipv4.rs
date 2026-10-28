use std::net::Ipv4Addr;

use crate::HelloError;

/// Return true when `packet` is one complete IPv4 packet.
#[must_use]
pub fn is_ipv4_packet(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet.len() > 65_535 {
        return false;
    }
    if packet[0] >> 4 != 4 {
        return false;
    }
    let header_words = usize::from(packet[0] & 0x0f);
    if header_words < 5 {
        return false;
    }
    let header_len = header_words * 4;
    if packet.len() < header_len {
        return false;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    total == packet.len() && total >= header_len
}

/// Build one IPv4 packet with a 20-byte header.
///
/// The checksum field is zero.
/// The caller uses this helper in tests and in the in-memory path.
pub fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Result<Vec<u8>, HelloError> {
    let total = 20usize
        .checked_add(payload.len())
        .ok_or(HelloError::NotIpv4)?;
    if total > 65_535 {
        return Err(HelloError::NotIpv4);
    }
    let total_u16 = u16::try_from(total).map_err(|_| HelloError::NotIpv4)?;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..].copy_from_slice(payload);
    Ok(packet)
}

/// One TCP or UDP destination from an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpUdpDestination {
    /// Destination address.
    pub addr: Ipv4Addr,
    /// IP protocol number. The value is 6 or 17.
    pub proto: u8,
    /// Destination port.
    pub port: u16,
}

/// Read the TCP or UDP destination.
///
/// The function returns `None` for a packet that is not TCP or UDP.
/// The function returns `None` when the destination port is 0.
pub(crate) fn tcp_udp_destination(packet: &[u8]) -> Option<TcpUdpDestination> {
    if !is_ipv4_packet(packet) {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let proto = packet[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    let port_end = header_len.checked_add(4)?;
    if packet.len() < port_end {
        return None;
    }
    let port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    if port == 0 {
        return None;
    }
    let addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some(TcpUdpDestination { addr, proto, port })
}

/// Build one IPv4 packet with a 20-byte header and a 20-byte TCP header.
///
/// The checksum fields are zero.
#[cfg(test)]
pub(crate) fn tcp_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, HelloError> {
    let total = 40usize
        .checked_add(payload.len())
        .ok_or(HelloError::NotIpv4)?;
    if total > 65_535 {
        return Err(HelloError::NotIpv4);
    }
    let total_u16 = u16::try_from(total).map_err(|_| HelloError::NotIpv4)?;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[32] = 5 << 4;
    packet[40..].copy_from_slice(payload);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::{ipv4_packet, is_ipv4_packet, tcp_ipv4_packet, tcp_udp_destination};
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_packet_round_trip_check() {
        let src = Ipv4Addr::new(10, 8, 0, 1);
        let dst = Ipv4Addr::new(10, 8, 0, 2);
        let packet = ipv4_packet(src, dst, b"ping").unwrap();
        assert!(is_ipv4_packet(&packet));
        assert_eq!(&packet[12..16], &src.octets());
        assert_eq!(&packet[16..20], &dst.octets());
        assert_eq!(&packet[20..], b"ping");
    }

    #[test]
    fn tcp_destination_reads_the_host_and_the_port() {
        let src = Ipv4Addr::new(10, 8, 0, 1);
        let dst = Ipv4Addr::new(10, 8, 0, 10);
        let packet = tcp_ipv4_packet(src, dst, 443, b"https").unwrap();
        assert!(is_ipv4_packet(&packet));
        let dest = tcp_udp_destination(&packet).unwrap();
        assert_eq!(dest.addr, dst);
        assert_eq!(dest.proto, 6);
        assert_eq!(dest.port, 443);
        let ping = ipv4_packet(src, dst, b"ping").unwrap();
        assert!(tcp_udp_destination(&ping).is_none());
    }

    #[test]
    fn ipv6_packet_is_rejected() {
        let mut packet = ipv4_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, b"").unwrap();
        packet[0] = 0x60;
        assert!(!is_ipv4_packet(&packet));
    }
}
