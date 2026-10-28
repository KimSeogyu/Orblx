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

#[cfg(test)]
mod tests {
    use super::{ipv4_packet, is_ipv4_packet};
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
    fn ipv6_packet_is_rejected() {
        let mut packet = ipv4_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, b"").unwrap();
        packet[0] = 0x60;
        assert!(!is_ipv4_packet(&packet));
    }
}
