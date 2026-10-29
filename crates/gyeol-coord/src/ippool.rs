use std::net::Ipv4Addr;

use crate::error::CoordError;

const POOL_FIRST: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const POOL_LAST: Ipv4Addr = Ipv4Addr::new(100, 127, 255, 254);

/// Return the overlay address for a zero-based index in `100.64.0.0/10`.
///
/// Index 0 is `100.64.0.1`.
/// The network address and the broadcast address are not used.
pub fn overlay_ip(index: u32) -> Result<Ipv4Addr, CoordError> {
    let start = u32::from(POOL_FIRST);
    let end = u32::from(POOL_LAST);
    let addr = start.checked_add(index).ok_or(CoordError::Pool)?;
    if addr > end {
        return Err(CoordError::Pool);
    }
    Ok(Ipv4Addr::from(addr))
}

/// Return true when `ip` is an address this coordinator assigns.
pub fn is_overlay_ip(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    (u32::from(POOL_FIRST)..=u32::from(POOL_LAST)).contains(&value)
}

/// Parse `host:port`.
///
/// IPv6 text is rejected.
pub fn parse_endpoint(text: &str) -> Result<(), CoordError> {
    let (host, port) = text.rsplit_once(':').ok_or(CoordError::Endpoint)?;
    if host.is_empty() || host.len() > 253 || host.starts_with('[') {
        return Err(CoordError::Endpoint);
    }
    let port: u16 = port.parse().map_err(|_| CoordError::Endpoint)?;
    if port == 0 {
        return Err(CoordError::Endpoint);
    }
    let labels_ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if !labels_ok {
        return Err(CoordError::Endpoint);
    }
    Ok(())
}

/// Parse an IPv4 network prefix and return the canonical text.
pub fn canonical_route(text: &str) -> Result<String, CoordError> {
    let (addr, prefix_text) = text.split_once('/').ok_or(CoordError::Route)?;
    let ip: Ipv4Addr = addr.parse().map_err(|_| CoordError::Route)?;
    let prefix: u8 = prefix_text.parse().map_err(|_| CoordError::Route)?;
    if prefix > 32 {
        return Err(CoordError::Route);
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    if u32::from(ip) & mask != u32::from(ip) {
        return Err(CoordError::Route);
    }
    Ok(format!("{ip}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_route, is_overlay_ip, overlay_ip, parse_endpoint, POOL_FIRST, POOL_LAST,
    };
    use std::net::Ipv4Addr;

    #[test]
    fn pool_starts_at_the_first_host_and_stops_before_broadcast() {
        assert_eq!(overlay_ip(0).unwrap(), POOL_FIRST);
        assert!(is_overlay_ip(POOL_FIRST));
        assert!(is_overlay_ip(POOL_LAST));
        assert!(!is_overlay_ip(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(!is_overlay_ip(Ipv4Addr::new(100, 127, 255, 255)));
        let last = u32::from(POOL_LAST) - u32::from(POOL_FIRST);
        assert_eq!(overlay_ip(last).unwrap(), POOL_LAST);
        assert!(overlay_ip(last + 1).is_err());
    }

    #[test]
    fn endpoint_and_route_parsers_reject_bad_text() {
        assert!(parse_endpoint("server-a:443").is_ok());
        assert!(parse_endpoint("10.1.0.2:1").is_ok());
        assert!(parse_endpoint("server-a:0").is_err());
        assert!(parse_endpoint("[2001:db8::1]:443").is_err());
        assert_eq!(canonical_route("192.168.1.0/24").unwrap(), "192.168.1.0/24");
        assert_eq!(canonical_route("0.0.0.0/0").unwrap(), "0.0.0.0/0");
        assert!(canonical_route("192.168.1.5/24").is_err());
    }
}
