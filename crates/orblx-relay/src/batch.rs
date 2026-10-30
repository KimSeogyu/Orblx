//! Batch UDP send and receive.
//!
//! On Linux the functions use sendmmsg(2) and recvmmsg(2). One system call moves many datagrams.
//! On other systems the functions use one call for each datagram.
//! The functions do not read the payload bytes.

use std::io;
use std::net::{SocketAddr, UdpSocket};

/// The largest number of datagrams in one system call.
pub const UDP_BATCH: usize = 32;

/// The destination of each datagram in a batch.
#[derive(Debug, Clone, Copy)]
pub enum BatchPeer<'a> {
    /// The socket is connected. The datagrams go to the connected address.
    Connected,
    /// All datagrams go to one address.
    One(SocketAddr),
    /// Datagram `i` goes to address `i`. The slice has one address for each datagram.
    Each(&'a [SocketAddr]),
}

impl BatchPeer<'_> {
    fn at(&self, index: usize) -> Option<SocketAddr> {
        match self {
            Self::Connected => None,
            Self::One(addr) => Some(*addr),
            Self::Each(list) => list.get(index).copied(),
        }
    }
}

/// Send datagrams. Each datagram is `prefix` followed by one item of `frames`.
///
/// The function returns the number of datagrams that the kernel accepted.
/// A number less than `frames.len()` means that the next send failed.
/// The function returns the error only when it sent no datagram.
pub fn send_batch(
    socket: &UdpSocket,
    prefix: &[u8],
    frames: &[&[u8]],
    peer: BatchPeer<'_>,
) -> io::Result<usize> {
    if let BatchPeer::Each(list) = peer {
        if list.len() < frames.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The batch has fewer addresses than datagrams.",
            ));
        }
    }
    let mut sent = 0;
    while sent < frames.len() {
        let end = (sent + UDP_BATCH).min(frames.len());
        match send_chunk(socket, prefix, &frames[sent..end], peer, sent) {
            Ok(0) => break,
            Ok(count) => sent += count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                if sent == 0 {
                    return Err(err);
                }
                break;
            }
        }
    }
    Ok(sent)
}

#[cfg(target_os = "linux")]
fn send_chunk(
    socket: &UdpSocket,
    prefix: &[u8],
    frames: &[&[u8]],
    peer: BatchPeer<'_>,
    offset: usize,
) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let mut names: Vec<(libc::sockaddr_storage, libc::socklen_t)> =
        Vec::with_capacity(frames.len());
    let mut iovs: Vec<[libc::iovec; 2]> = Vec::with_capacity(frames.len());
    for (index, frame) in frames.iter().enumerate() {
        if let Some(addr) = peer.at(offset + index) {
            names.push(sockaddr_of(addr));
        }
        iovs.push([
            libc::iovec {
                iov_base: prefix.as_ptr() as *mut libc::c_void,
                iov_len: prefix.len(),
            },
            libc::iovec {
                iov_base: frame.as_ptr() as *mut libc::c_void,
                iov_len: frame.len(),
            },
        ]);
    }
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(frames.len());
    for (index, iov) in iovs.iter_mut().enumerate() {
        // SAFETY: msghdr is a plain C struct. All zero bytes is a valid empty value.
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = iov.as_mut_ptr();
        hdr.msg_iovlen = 2 as _;
        if let Some((storage, len)) = names.get_mut(index) {
            hdr.msg_name = (storage as *mut libc::sockaddr_storage).cast::<libc::c_void>();
            hdr.msg_namelen = *len;
        }
        msgs.push(libc::mmsghdr {
            msg_hdr: hdr,
            msg_len: 0,
        });
    }
    let count = libc::c_uint::try_from(msgs.len()).unwrap_or(0);
    // SAFETY: `msgs`, `iovs`, `names`, `prefix`, and `frames` stay alive and unchanged for the call.
    // Each msghdr points to valid iovec and sockaddr values.
    let rc = unsafe { libc::sendmmsg(socket.as_raw_fd(), msgs.as_mut_ptr(), count, 0 as _) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(rc).unwrap_or(0))
}

#[cfg(not(target_os = "linux"))]
fn send_chunk(
    socket: &UdpSocket,
    prefix: &[u8],
    frames: &[&[u8]],
    peer: BatchPeer<'_>,
    offset: usize,
) -> io::Result<usize> {
    let mut buf = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        buf.clear();
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(frame);
        let result = match peer.at(offset + index) {
            Some(addr) => socket.send_to(&buf, addr),
            None => socket.send(&buf),
        };
        if let Err(err) = result {
            if index == 0 {
                return Err(err);
            }
            return Ok(index);
        }
    }
    Ok(frames.len())
}

/// Receive buffers for [`recv_batch`].
pub struct RecvBatch {
    data: Vec<u8>,
    slot_len: usize,
    lens: Vec<usize>,
    from: Vec<Option<SocketAddr>>,
    count: usize,
}

impl RecvBatch {
    /// Make buffers for `slots` datagrams of up to `slot_len` bytes each.
    #[must_use]
    pub fn new(slots: usize, slot_len: usize) -> Self {
        let slots = slots.max(1);
        Self {
            data: vec![0u8; slots * slot_len],
            slot_len,
            lens: vec![0; slots],
            from: vec![None; slots],
            count: 0,
        }
    }

    /// The number of datagrams from the last receive.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// True when the last receive got no datagram.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Datagram `index` and its source address.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<(&[u8], Option<SocketAddr>)> {
        if index >= self.count {
            return None;
        }
        let start = index * self.slot_len;
        Some((
            &self.data[start..start + self.lens[index]],
            self.from[index],
        ))
    }
}

/// Receive one or more datagrams.
///
/// The call waits like `recv_from` for the first datagram. It then takes the datagrams that already wait, up to the batch size.
pub fn recv_batch(socket: &UdpSocket, batch: &mut RecvBatch) -> io::Result<usize> {
    batch.count = 0;
    let count = recv_chunk(socket, batch)?;
    batch.count = count;
    Ok(count)
}

#[cfg(target_os = "linux")]
fn recv_chunk(socket: &UdpSocket, batch: &mut RecvBatch) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let slots = batch.lens.len();
    // SAFETY: sockaddr_storage is a plain C struct. All zero bytes is a valid value.
    let mut names: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; slots];
    let mut iovs: Vec<libc::iovec> = batch
        .data
        .chunks_mut(batch.slot_len)
        .take(slots)
        .map(|chunk| libc::iovec {
            iov_base: chunk.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: chunk.len(),
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(slots);
    for (iov, name) in iovs.iter_mut().zip(names.iter_mut()) {
        // SAFETY: msghdr is a plain C struct. All zero bytes is a valid empty value.
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = iov;
        hdr.msg_iovlen = 1 as _;
        hdr.msg_name = (name as *mut libc::sockaddr_storage).cast::<libc::c_void>();
        hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msgs.push(libc::mmsghdr {
            msg_hdr: hdr,
            msg_len: 0,
        });
    }
    let count = libc::c_uint::try_from(msgs.len()).unwrap_or(0);
    // SAFETY: `msgs`, `iovs`, `names`, and `batch.data` stay alive for the call.
    // Each iovec points into `batch.data` with its own length.
    let rc = unsafe {
        libc::recvmmsg(
            socket.as_raw_fd(),
            msgs.as_mut_ptr(),
            count,
            libc::MSG_WAITFORONE as _,
            std::ptr::null_mut(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let got = usize::try_from(rc).unwrap_or(0);
    for index in 0..got {
        let len = msgs[index].msg_len as usize;
        batch.lens[index] = len.min(batch.slot_len);
        batch.from[index] = addr_of(&names[index], msgs[index].msg_hdr.msg_namelen);
    }
    Ok(got)
}

#[cfg(not(target_os = "linux"))]
fn recv_chunk(socket: &UdpSocket, batch: &mut RecvBatch) -> io::Result<usize> {
    let slot_len = batch.slot_len;
    let (size, from) = socket.recv_from(&mut batch.data[..slot_len])?;
    batch.lens[0] = size;
    batch.from[0] = Some(from);
    Ok(1)
}

#[cfg(target_os = "linux")]
fn sockaddr_of(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is a plain C struct. All zero bytes is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than sockaddr_in and has a stricter alignment.
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                    sin,
                );
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: sockaddr_storage is larger than sockaddr_in6 and has a stricter alignment.
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                    sin6,
                );
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}

#[cfg(target_os = "linux")]
fn addr_of(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let len = len as usize;
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET if len >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family is AF_INET, so the storage holds a sockaddr_in.
            let sin =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::from((ip, u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 if len >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the family is AF_INET6, so the storage holds a sockaddr_in6.
            let sin6 = unsafe {
                &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn batch_send_and_receive_keep_bytes_order_and_source() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        let frames: Vec<Vec<u8>> = (0..70u8).map(|i| vec![i; 100 + usize::from(i)]).collect();
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        assert_eq!(
            send_batch(&tx, b"pre", &refs, BatchPeer::One(to)).unwrap(),
            70
        );
        let mut batch = RecvBatch::new(UDP_BATCH, 2048);
        let mut seen = Vec::new();
        while seen.len() < 70 {
            recv_batch(&rx, &mut batch).unwrap();
            assert!(!batch.is_empty());
            for index in 0..batch.len() {
                let (bytes, from) = batch.get(index).unwrap();
                assert_eq!(from, Some(tx.local_addr().unwrap()));
                seen.push(bytes.to_vec());
            }
        }
        for (index, bytes) in seen.iter().enumerate() {
            let mut want = b"pre".to_vec();
            want.extend_from_slice(&frames[index]);
            assert_eq!(bytes, &want);
        }
    }

    #[test]
    fn each_peer_needs_one_address_for_each_datagram() {
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let frames: [&[u8]; 2] = [b"a", b"b"];
        let one = [tx.local_addr().unwrap()];
        assert!(send_batch(&tx, &[], &frames, BatchPeer::Each(&one)).is_err());
    }
}
