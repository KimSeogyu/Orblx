//! The ingress interface of one accepted overlay connection.
//!
//! A peer overlay address is valid only when the connection comes in on the overlay TUN interface.
//! The datapath writes a packet to TUN only after the QUIC session authenticates the peer SVID.
//! A packet that comes in on an underlay interface has no such check, so its source address can be forged.
//!
//! On Linux, the listener sets `IP_PKTINFO`. Each accepted socket keeps the interface index
//! of its first SYN, and `IP_PKTOPTIONS` returns that index.
//! On other systems the index is not available. The serve listener then prints one
//! `serve_ingress_check unavailable` line and keeps the W21-4 source address check.

use std::net::Ipv4Addr;

/// Where one overlay connection came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ingress {
    /// The connection came in on the overlay TUN interface.
    Tunnel,
    /// The connection came in on a different interface.
    Other,
    /// The system cannot tell the interface.
    Unknown,
}

/// Compare the ingress interface index with the TUN interface index.
pub(crate) fn classify(ingress_index: Option<u32>, tunnel_index: Option<u32>) -> Ingress {
    match (ingress_index, tunnel_index) {
        (Some(ingress), Some(tunnel)) if ingress == tunnel => Ingress::Tunnel,
        (Some(_), Some(_)) => Ingress::Other,
        _ => Ingress::Unknown,
    }
}

/// True when this system can read the ingress interface of an accepted TCP socket.
pub(crate) const CHECK_AVAILABLE: bool = cfg!(target_os = "linux");

/// The index of the interface that has the IPv4 address `addr`.
pub(crate) fn index_for_addr(addr: Ipv4Addr) -> Option<u32> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head to `list`. freeifaddrs releases it below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node of the list from getifaddrs. The list is valid until freeifaddrs.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is not null. The family field is at the same offset in each sockaddr type.
        let family = i32::from(unsafe { (*entry.ifa_addr).sa_family });
        if family != libc::AF_INET {
            continue;
        }
        // SAFETY: the family is AF_INET, so the address is a sockaddr_in.
        let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
        if Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) != addr {
            continue;
        }
        // SAFETY: `ifa_name` is a C string that the list owns.
        let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
        if index != 0 {
            found = Some(index);
            break;
        }
    }
    // SAFETY: `list` came from getifaddrs and is released one time.
    unsafe { libc::freeifaddrs(list) };
    found
}

/// Ask the kernel to keep the ingress interface for each accepted socket.
#[cfg(target_os = "linux")]
pub(crate) fn enable(listener: &impl std::os::fd::AsRawFd) -> bool {
    let on: libc::c_int = 1;
    // SAFETY: the fd is an open IPv4 TCP socket. The option value is one c_int.
    let rc = unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Ask the kernel to keep the ingress interface for each accepted socket.
#[cfg(not(target_os = "linux"))]
pub(crate) fn enable<T>(_listener: &T) -> bool {
    false
}

/// The ingress interface index of one accepted TCP socket.
#[cfg(target_os = "linux")]
pub(crate) fn ingress_index(stream: &impl std::os::fd::AsRawFd) -> Option<u32> {
    // u64 items keep the control message headers aligned.
    let mut buf = [0u64; 32];
    let mut len = std::mem::size_of_val(&buf) as libc::socklen_t;
    // SAFETY: `buf` has `len` bytes. The kernel writes control messages and sets `len`.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_PKTOPTIONS,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 || len == 0 {
        return None;
    }
    // SAFETY: an all-zero msghdr is valid. Only the control fields are set.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_control = buf.as_mut_ptr().cast();
    msg.msg_controllen = len as _;
    // SAFETY: `msg` points at `len` bytes of control messages from the kernel.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is a header inside `buf`. CMSG_NXTHDR checks the bounds.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_PKTINFO {
            // SAFETY: an IP_PKTINFO message holds one in_pktinfo. read_unaligned does not need alignment.
            let info: libc::in_pktinfo =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast()) };
            return u32::try_from(info.ipi_ifindex)
                .ok()
                .filter(|index| *index != 0);
        }
        // SAFETY: as above.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    None
}

/// The ingress interface index of one accepted TCP socket.
#[cfg(not(target_os = "linux"))]
pub(crate) fn ingress_index<T>(_stream: &T) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_tunnel_index_is_tunnel() {
        assert_eq!(classify(Some(7), Some(7)), Ingress::Tunnel);
        assert_eq!(classify(Some(2), Some(7)), Ingress::Other);
        assert_eq!(classify(None, Some(7)), Ingress::Unknown);
        assert_eq!(classify(Some(7), None), Ingress::Unknown);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_reports_the_loopback_ingress_for_a_loopback_connection() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("runtime"));
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap_or_else(|_| panic!("bind"));
            assert!(enable(&listener));
            let addr = listener.local_addr().unwrap_or_else(|_| panic!("addr"));
            let client = tokio::net::TcpStream::connect(addr);
            let (accepted, _client) = tokio::join!(listener.accept(), client);
            let (stream, _) = accepted.unwrap_or_else(|_| panic!("accept"));
            let loopback = index_for_addr(Ipv4Addr::LOCALHOST);
            assert!(loopback.is_some());
            assert_eq!(ingress_index(&stream), loopback);
            // The loopback is not the TUN interface, so the connection is not Tunnel.
            let fake_tunnel = loopback.map(|index| index + 1000);
            assert_eq!(
                classify(ingress_index(&stream), fake_tunnel),
                Ingress::Other
            );
        });
    }
}
