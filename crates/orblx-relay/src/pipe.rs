use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use crate::error::io_error;
use crate::{
    decode_datagram, encode_datagram, encode_tcp_record, take_tcp_record, RelayError, RelayKind,
    RelaySessionId, RelayTransport,
};

/// A peer attachment to the Relay.
///
/// The pipe sends and receives opaque payloads.
/// The pipe does not encrypt and does not decrypt.
#[derive(Debug)]
pub struct RelayPipe {
    inner: Inner,
    transport: RelayTransport,
    session_id: RelaySessionId,
}

#[derive(Debug)]
enum Inner {
    Udp(UdpSocket),
    Tcp { stream: TcpStream, buf: Vec<u8> },
}

impl RelayPipe {
    /// Attach over UDP and wait for the empty ATTACH reply.
    pub fn connect_udp(
        relay: SocketAddr,
        session_id: RelaySessionId,
        timeout: Duration,
    ) -> Result<Self, RelayError> {
        let socket = UdpSocket::bind(bind_addr(relay)).map_err(io_error)?;
        socket.connect(relay).map_err(io_error)?;
        let attach = encode_datagram(RelayKind::Attach, session_id, &[])?;
        let started = Instant::now();
        let mut buf = [0u8; 2048];
        while started.elapsed() < timeout {
            socket.send(&attach).map_err(io_error)?;
            let remaining = timeout.saturating_sub(started.elapsed());
            let slice = remaining.min(Duration::from_millis(100));
            if slice.is_zero() {
                break;
            }
            socket.set_read_timeout(Some(slice)).map_err(io_error)?;
            match socket.recv(&mut buf) {
                Ok(size) => {
                    expect_attach(&buf[..size], session_id)?;
                    socket.set_nonblocking(true).map_err(io_error)?;
                    return Ok(Self {
                        inner: Inner::Udp(socket),
                        transport: RelayTransport::Udp,
                        session_id,
                    });
                }
                Err(err) if is_udp_blocked(&err) => return Err(RelayError::UdpBlocked),
                Err(err) if is_timeout(&err) => continue,
                Err(err) => return Err(io_error(err)),
            }
        }
        Err(RelayError::UdpBlocked)
    }

    /// Attach over TCP and wait for the empty ATTACH reply.
    ///
    /// The TCP stream uses the QUIC-style length prefix.
    pub fn connect_tcp(
        relay: SocketAddr,
        session_id: RelaySessionId,
        timeout: Duration,
    ) -> Result<Self, RelayError> {
        let mut stream = TcpStream::connect_timeout(&relay, timeout).map_err(io_error)?;
        stream.set_nodelay(true).map_err(io_error)?;
        stream.set_read_timeout(Some(timeout)).map_err(io_error)?;
        stream.set_write_timeout(Some(timeout)).map_err(io_error)?;
        let attach = encode_datagram(RelayKind::Attach, session_id, &[])?;
        let record = encode_tcp_record(&attach)?;
        stream.write_all(&record).map_err(io_error)?;
        let mut buf = Vec::new();
        let datagram = read_record_blocking(&mut stream, &mut buf, timeout)?;
        expect_attach_datagram(&datagram, session_id)?;
        stream.set_nonblocking(true).map_err(io_error)?;
        Ok(Self {
            inner: Inner::Tcp { stream, buf },
            transport: RelayTransport::Tcp,
            session_id,
        })
    }

    /// Return the transport that reached the Relay.
    #[must_use]
    pub fn transport(&self) -> RelayTransport {
        self.transport
    }

    /// Return the session id.
    #[must_use]
    pub fn session_id(&self) -> RelaySessionId {
        self.session_id
    }

    /// Send one opaque payload.
    ///
    /// The bytes are copied into a DATA datagram.
    /// The function does not read the bytes.
    pub fn send_opaque(&mut self, payload: &[u8]) -> Result<(), RelayError> {
        match &mut self.inner {
            Inner::Udp(socket) => send_data_udp(socket, self.session_id, payload),
            Inner::Tcp { stream, .. } => send_data_tcp(stream, self.session_id, payload),
        }
    }

    /// Return a second handle that sends on the same attachment.
    ///
    /// A different thread can send with the handle while this pipe waits for data.
    /// Only one thread at a time must send on a TCP attachment.
    pub fn sender(&self) -> Result<RelaySender, RelayError> {
        let inner = match &self.inner {
            Inner::Udp(socket) => SenderInner::Udp(socket.try_clone().map_err(io_error)?),
            Inner::Tcp { stream, .. } => SenderInner::Tcp(stream.try_clone().map_err(io_error)?),
        };
        Ok(RelaySender {
            inner,
            session_id: self.session_id,
        })
    }

    /// Block until the socket has bytes to read, or until the timeout ends.
    ///
    /// Return true when the socket has bytes to read.
    /// The function does not read the bytes.
    pub fn wait_readable(&self, timeout: Duration) -> Result<bool, RelayError> {
        let fd = match &self.inner {
            Inner::Udp(socket) => socket.as_raw_fd(),
            Inner::Tcp { stream, .. } => stream.as_raw_fd(),
        };
        wait_fds_readable(&[fd], timeout)
    }

    /// Block until the socket or `other` has bytes to read, or until the timeout ends.
    ///
    /// Return true when one of the two has bytes to read.
    /// A bridge uses this to wait on its local face and on the Relay at the same time.
    pub fn wait_readable_or<T: AsRawFd>(
        &self,
        other: &T,
        timeout: Duration,
    ) -> Result<bool, RelayError> {
        let fd = match &self.inner {
            Inner::Udp(socket) => socket.as_raw_fd(),
            Inner::Tcp { stream, .. } => stream.as_raw_fd(),
        };
        wait_fds_readable(&[fd, other.as_raw_fd()], timeout)
    }

    /// Receive one opaque DATA payload.
    ///
    /// `Ok(None)` means the socket has no full payload yet.
    pub fn recv_opaque(&mut self) -> Result<Option<Vec<u8>>, RelayError> {
        match &mut self.inner {
            Inner::Udp(socket) => recv_udp(socket, self.session_id),
            Inner::Tcp { stream, buf } => recv_tcp(stream, buf, self.session_id),
        }
    }

    /// Best-effort DETACH.
    pub fn detach(&mut self) {
        let Ok(datagram) = encode_datagram(RelayKind::Detach, self.session_id, &[]) else {
            return;
        };
        match &mut self.inner {
            Inner::Udp(socket) => {
                let _ = send_udp(socket, &datagram);
            }
            Inner::Tcp { stream, .. } => {
                if let Ok(record) = encode_tcp_record(&datagram) {
                    let _ = write_all_retry(stream, &record);
                }
            }
        }
    }
}

/// A send handle for one Relay attachment.
///
/// [`RelayPipe::sender`] makes the handle.
#[derive(Debug)]
pub struct RelaySender {
    inner: SenderInner,
    session_id: RelaySessionId,
}

#[derive(Debug)]
enum SenderInner {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl RelaySender {
    /// Send one opaque payload.
    ///
    /// The function does not read the bytes.
    pub fn send_opaque(&mut self, payload: &[u8]) -> Result<(), RelayError> {
        match &mut self.inner {
            SenderInner::Udp(socket) => send_data_udp(socket, self.session_id, payload),
            SenderInner::Tcp(stream) => send_data_tcp(stream, self.session_id, payload),
        }
    }
}

fn send_data_udp(
    socket: &UdpSocket,
    session_id: RelaySessionId,
    payload: &[u8],
) -> Result<(), RelayError> {
    let datagram = encode_datagram(RelayKind::Data, session_id, payload)?;
    send_udp(socket, &datagram)
}

fn send_data_tcp(
    stream: &mut TcpStream,
    session_id: RelaySessionId,
    payload: &[u8],
) -> Result<(), RelayError> {
    let datagram = encode_datagram(RelayKind::Data, session_id, payload)?;
    let record = encode_tcp_record(&datagram)?;
    write_all_retry(stream, &record)
}

/// Wait with poll(2) until one of the descriptors is readable.
fn wait_fds_readable(fds: &[libc::c_int], timeout: Duration) -> Result<bool, RelayError> {
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    let mut entries: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let count = libc::nfds_t::try_from(entries.len()).unwrap_or(0);
    // SAFETY: `entries` holds `count` valid pollfd values for the whole call.
    let rc = unsafe { libc::poll(entries.as_mut_ptr(), count, millis) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(io_error(err));
    }
    // An error or a hang-up also wakes the caller. The next read reports it.
    Ok(rc > 0 && entries.iter().any(|entry| entry.revents != 0))
}

fn bind_addr(relay: SocketAddr) -> SocketAddr {
    match relay {
        SocketAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
    }
}

fn expect_attach(buf: &[u8], session_id: RelaySessionId) -> Result<(), RelayError> {
    let datagram = decode_datagram(buf)?;
    expect_attach_datagram(&datagram, session_id)
}

fn expect_attach_datagram(
    datagram: &crate::RelayDatagram,
    session_id: RelaySessionId,
) -> Result<(), RelayError> {
    if datagram.kind != RelayKind::Attach
        || datagram.session_id != session_id
        || !datagram.payload.is_empty()
    {
        return Err(RelayError::BadDatagram);
    }
    Ok(())
}

fn send_udp(socket: &UdpSocket, bytes: &[u8]) -> Result<(), RelayError> {
    let started = Instant::now();
    loop {
        match socket.send(bytes) {
            Ok(size) if size == bytes.len() => return Ok(()),
            Ok(_) => return Err(RelayError::Io("The UDP send was short.".to_string())),
            Err(err) if is_timeout(&err) => {
                if started.elapsed() > Duration::from_millis(200) {
                    return Err(RelayError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) => return Err(io_error(err)),
        }
    }
}

fn recv_udp(socket: &UdpSocket, session_id: RelaySessionId) -> Result<Option<Vec<u8>>, RelayError> {
    let mut buf = [0u8; 65_535];
    loop {
        match socket.recv(&mut buf) {
            Ok(size) => {
                let datagram = decode_datagram(&buf[..size])?;
                if datagram.session_id != session_id {
                    return Err(RelayError::BadSession);
                }
                match datagram.kind {
                    RelayKind::Data => return Ok(Some(datagram.payload)),
                    RelayKind::Attach | RelayKind::Detach => continue,
                }
            }
            Err(err) if is_timeout(&err) => return Ok(None),
            Err(err) => return Err(io_error(err)),
        }
    }
}

fn recv_tcp(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    session_id: RelaySessionId,
) -> Result<Option<Vec<u8>>, RelayError> {
    pull_tcp(stream, buf)?;
    loop {
        match take_tcp_record(buf)? {
            None => return Ok(None),
            Some((datagram, used)) => {
                buf.drain(..used);
                if datagram.session_id != session_id {
                    return Err(RelayError::BadSession);
                }
                match datagram.kind {
                    RelayKind::Data => return Ok(Some(datagram.payload)),
                    RelayKind::Attach | RelayKind::Detach => continue,
                }
            }
        }
    }
}

fn pull_tcp(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Result<(), RelayError> {
    let mut tmp = [0u8; 2048];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => return Err(RelayError::Closed),
            Ok(size) => {
                buf.extend_from_slice(&tmp[..size]);
            }
            Err(err) if is_timeout(&err) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(io_error(err)),
        }
    }
}

fn read_record_blocking(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    timeout: Duration,
) -> Result<crate::RelayDatagram, RelayError> {
    let started = Instant::now();
    loop {
        if let Some((datagram, used)) = take_tcp_record(buf)? {
            buf.drain(..used);
            return Ok(datagram);
        }
        if started.elapsed() >= timeout {
            return Err(RelayError::Timeout);
        }
        let mut tmp = [0u8; 2048];
        match stream.read(&mut tmp) {
            Ok(0) => return Err(RelayError::Closed),
            Ok(size) => buf.extend_from_slice(&tmp[..size]),
            Err(err) if is_timeout(&err) => return Err(RelayError::Timeout),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(io_error(err)),
        }
    }
}

fn write_all_retry(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), RelayError> {
    let mut offset = 0;
    let started = Instant::now();
    while offset < bytes.len() {
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(RelayError::Closed),
            Ok(size) => offset += size,
            Err(err) if is_timeout(&err) => {
                if started.elapsed() > Duration::from_millis(500) {
                    return Err(RelayError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(io_error(err)),
        }
    }
    Ok(())
}

fn is_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
    )
}

fn is_udp_blocked(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown
    )
}
