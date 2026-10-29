use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::io_error;
use crate::session::encode_hex;
use crate::{
    contains_needle, encode_datagram, encode_tcp_record, take_tcp_record, RelayError, RelayKind,
    RelaySessionId, MAX_DATAGRAM_LEN,
};

const READ_SLICE: Duration = Duration::from_millis(50);

/// Bind addresses and the lab audit needle.
pub struct ServerConfig {
    /// UDP listen socket.
    ///
    /// `None` means the server does not open UDP.
    pub udp_bind: Option<SocketAddr>,
    /// TCP listen socket.
    ///
    /// `None` means the server does not open TCP.
    pub tcp_bind: Option<SocketAddr>,
    /// When set, each forwarded payload is scanned for this byte string.
    ///
    /// The scan does not decrypt.
    /// The Relay still forwards the original bytes.
    pub audit_absent: Option<Vec<u8>>,
    /// Optional audit log.
    ///
    /// Each line is `forward`, the session id, the payload length, and the hit flag.
    /// The line does not contain the payload.
    pub audit_path: Option<std::path::PathBuf>,
    /// When true, the UDP socket stays bound and the server does not answer.
    ///
    /// This matches a firewall DROP on UDP.
    /// TCP still answers when `tcp_bind` is set.
    pub udp_discard: bool,
}

/// Counters from the Relay process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// ATTACH registrations.
    pub attaches: u64,
    /// DATA payloads delivered to the other peer.
    pub forwards: u64,
    /// Sum of delivered payload lengths.
    pub forward_bytes: u64,
    /// Delivered payloads that contain the audit needle.
    pub plaintext_hits: u64,
    /// DATA datagrams that were not delivered.
    pub drops: u64,
}

/// A running Relay process.
///
/// Drop stops the listen threads.
pub struct RelayServer {
    shared: Arc<Shared>,
    udp_addr: Option<SocketAddr>,
    tcp_addr: Option<SocketAddr>,
    udp_thread: Option<JoinHandle<()>>,
    accept_thread: Option<JoinHandle<()>>,
}

struct Shared {
    stop: AtomicBool,
    sessions: Mutex<HashMap<RelaySessionId, Session>>,
    next_id: AtomicU64,
    stats: Mutex<RelayStats>,
    udp: Mutex<Option<Arc<UdpSocket>>>,
    audit_absent: Option<Vec<u8>>,
    audit: Mutex<Option<File>>,
    conns: Mutex<Vec<JoinHandle<()>>>,
    udp_discard: bool,
}

struct Session {
    slots: Vec<Slot>,
}

struct Slot {
    id: u64,
    dest: Dest,
}

#[derive(Clone)]
enum Dest {
    Udp(SocketAddr),
    Tcp(SyncSender<Vec<u8>>),
}

impl RelayServer {
    /// Bind the requested sockets and start the listen loops.
    pub fn spawn(config: ServerConfig) -> Result<Self, RelayError> {
        if config.udp_bind.is_none() && config.tcp_bind.is_none() {
            return Err(RelayError::Io(
                "The Relay needs a UDP socket or a TCP socket.".to_string(),
            ));
        }
        let audit = match config.audit_path {
            Some(path) => Some(File::create(path).map_err(io_error)?),
            None => None,
        };
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            stats: Mutex::new(RelayStats::default()),
            udp: Mutex::new(None),
            audit_absent: config.audit_absent,
            audit: Mutex::new(audit),
            conns: Mutex::new(Vec::new()),
            udp_discard: config.udp_discard,
        });

        let (udp_addr, udp_thread) = match config.udp_bind {
            Some(addr) => {
                let socket = UdpSocket::bind(addr).map_err(io_error)?;
                socket
                    .set_read_timeout(Some(READ_SLICE))
                    .map_err(io_error)?;
                let bound = socket.local_addr().map_err(io_error)?;
                let shared_socket = Arc::new(socket);
                *lock_mutex(&shared.udp) = Some(Arc::clone(&shared_socket));
                let shared_loop = Arc::clone(&shared);
                let handle = thread::spawn(move || udp_loop(shared_socket, shared_loop));
                (Some(bound), Some(handle))
            }
            None => (None, None),
        };

        let (tcp_addr, accept_thread) = match config.tcp_bind {
            Some(addr) => {
                let listener = TcpListener::bind(addr).map_err(io_error)?;
                listener.set_nonblocking(true).map_err(io_error)?;
                let bound = listener.local_addr().map_err(io_error)?;
                let shared_loop = Arc::clone(&shared);
                let handle = thread::spawn(move || accept_loop(listener, shared_loop));
                (Some(bound), Some(handle))
            }
            None => (None, None),
        };

        Ok(Self {
            shared,
            udp_addr,
            tcp_addr,
            udp_thread,
            accept_thread,
        })
    }

    /// Return the bound UDP socket.
    #[must_use]
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addr
    }

    /// Return the bound TCP socket.
    #[must_use]
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    /// Copy the counters.
    #[must_use]
    pub fn stats(&self) -> RelayStats {
        *lock_mutex(&self.shared.stats)
    }

    /// Stop the listen loops and wait for them.
    pub fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.udp_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        let handles = std::mem::take(&mut *lock_mutex(&self.shared.conns));
        for handle in handles {
            let _ = handle.join();
        }
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn udp_loop(socket: Arc<UdpSocket>, shared: Arc<Shared>) {
    let mut buf = [0u8; MAX_DATAGRAM_LEN];
    while !shared.stop.load(Ordering::Relaxed) {
        let (size, from) = match socket.recv_from(&mut buf) {
            Ok(packet) => packet,
            Err(err) if is_timeout(&err) => continue,
            Err(_) => break,
        };
        if shared.udp_discard {
            continue;
        }
        if let Err(error) = handle_udp(&shared, &socket, from, &buf[..size]) {
            let _ = error;
            bump_drop(&shared);
        }
    }
}

fn handle_udp(
    shared: &Shared,
    socket: &UdpSocket,
    from: SocketAddr,
    bytes: &[u8],
) -> Result<(), RelayError> {
    let datagram = crate::decode_datagram(bytes)?;
    match datagram.kind {
        RelayKind::Attach => {
            if !datagram.payload.is_empty() {
                return Err(RelayError::BadDatagram);
            }
            register_udp(shared, datagram.session_id, from)?;
            let ack = encode_datagram(RelayKind::Attach, datagram.session_id, &[])?;
            socket.send_to(&ack, from).map_err(io_error)?;
            Ok(())
        }
        RelayKind::Data => {
            let id = udp_peer_id(shared, datagram.session_id, from)?;
            forward(shared, datagram.session_id, id, &datagram.payload);
            Ok(())
        }
        RelayKind::Detach => {
            if let Ok(id) = udp_peer_id(shared, datagram.session_id, from) {
                remove_peer(shared, datagram.session_id, id);
            }
            Ok(())
        }
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    while !shared.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let shared_conn = Arc::clone(&shared);
                let handle = thread::spawn(move || tcp_conn(stream, shared_conn));
                lock_mutex(&shared.conns).push(handle);
            }
            Err(err) if is_timeout(&err) => thread::sleep(Duration::from_millis(10)),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn tcp_conn(mut stream: TcpStream, shared: Arc<Shared>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(READ_SLICE));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(32);
    let mut buf = Vec::new();
    let mut peer: Option<(RelaySessionId, u64)> = None;
    while !shared.stop.load(Ordering::Relaxed) {
        match read_some(&mut stream, &mut buf) {
            Ok(()) => {}
            Err(RelayError::Timeout) => {}
            Err(_) => break,
        }
        let handled = match drain_records(&mut buf) {
            Ok(records) => records,
            Err(_) => break,
        };
        for datagram in handled {
            match datagram.kind {
                RelayKind::Attach => {
                    if !datagram.payload.is_empty() {
                        return;
                    }
                    match register_tcp(&shared, datagram.session_id, tx.clone()) {
                        Ok(id) => {
                            peer = Some((datagram.session_id, id));
                            let Ok(ack) =
                                encode_datagram(RelayKind::Attach, datagram.session_id, &[])
                            else {
                                return;
                            };
                            let Ok(record) = encode_tcp_record(&ack) else {
                                return;
                            };
                            if stream.write_all(&record).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                RelayKind::Data => {
                    let Some((session_id, id)) = peer else {
                        continue;
                    };
                    if datagram.session_id != session_id {
                        bump_drop(&shared);
                        continue;
                    }
                    forward(&shared, session_id, id, &datagram.payload);
                }
                RelayKind::Detach => {
                    if let Some((session_id, id)) = peer.take() {
                        if datagram.session_id == session_id {
                            remove_peer(&shared, session_id, id);
                        }
                    }
                    return;
                }
            }
        }
        while let Ok(record) = rx.try_recv() {
            if stream.write_all(&record).is_err() {
                if let Some((session_id, id)) = peer.take() {
                    remove_peer(&shared, session_id, id);
                }
                return;
            }
        }
    }
    if let Some((session_id, id)) = peer {
        remove_peer(&shared, session_id, id);
    }
}

fn read_some(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Result<(), RelayError> {
    let mut tmp = [0u8; 2048];
    match stream.read(&mut tmp) {
        Ok(0) => Err(RelayError::Closed),
        Ok(size) => {
            buf.extend_from_slice(&tmp[..size]);
            Ok(())
        }
        Err(err) if is_timeout(&err) => Err(RelayError::Timeout),
        Err(err) if err.kind() == ErrorKind::Interrupted => Ok(()),
        Err(err) => Err(io_error(err)),
    }
}

fn drain_records(buf: &mut Vec<u8>) -> Result<Vec<crate::RelayDatagram>, RelayError> {
    let mut out = Vec::new();
    while let Some((datagram, used)) = take_tcp_record(buf)? {
        buf.drain(..used);
        out.push(datagram);
    }
    Ok(out)
}

fn register_udp(
    shared: &Shared,
    session_id: RelaySessionId,
    addr: SocketAddr,
) -> Result<u64, RelayError> {
    let mut sessions = lock_mutex(&shared.sessions);
    let session = sessions
        .entry(session_id)
        .or_insert_with(|| Session { slots: Vec::new() });
    if let Some(slot) = session.slots.iter().find(|slot| match slot.dest {
        Dest::Udp(existing) => existing == addr,
        Dest::Tcp(_) => false,
    }) {
        return Ok(slot.id);
    }
    if session.slots.len() >= 2 {
        return Err(RelayError::SessionFull);
    }
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    session.slots.push(Slot {
        id,
        dest: Dest::Udp(addr),
    });
    lock_mutex(&shared.stats).attaches += 1;
    Ok(id)
}

fn register_tcp(
    shared: &Shared,
    session_id: RelaySessionId,
    tx: SyncSender<Vec<u8>>,
) -> Result<u64, RelayError> {
    let mut sessions = lock_mutex(&shared.sessions);
    let session = sessions
        .entry(session_id)
        .or_insert_with(|| Session { slots: Vec::new() });
    if session.slots.len() >= 2 {
        return Err(RelayError::SessionFull);
    }
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    session.slots.push(Slot {
        id,
        dest: Dest::Tcp(tx),
    });
    lock_mutex(&shared.stats).attaches += 1;
    Ok(id)
}

fn udp_peer_id(
    shared: &Shared,
    session_id: RelaySessionId,
    addr: SocketAddr,
) -> Result<u64, RelayError> {
    let sessions = lock_mutex(&shared.sessions);
    let session = sessions.get(&session_id).ok_or(RelayError::NotAttached)?;
    session
        .slots
        .iter()
        .find_map(|slot| match slot.dest {
            Dest::Udp(existing) if existing == addr => Some(slot.id),
            Dest::Udp(_) | Dest::Tcp(_) => None,
        })
        .ok_or(RelayError::NotAttached)
}

fn remove_peer(shared: &Shared, session_id: RelaySessionId, id: u64) {
    let mut sessions = lock_mutex(&shared.sessions);
    let Some(session) = sessions.get_mut(&session_id) else {
        return;
    };
    session.slots.retain(|slot| slot.id != id);
    if session.slots.is_empty() {
        sessions.remove(&session_id);
    }
}

fn forward(shared: &Shared, session_id: RelaySessionId, from_id: u64, payload: &[u8]) {
    let dest = {
        let sessions = lock_mutex(&shared.sessions);
        let Some(session) = sessions.get(&session_id) else {
            bump_drop(shared);
            return;
        };
        session
            .slots
            .iter()
            .find(|slot| slot.id != from_id)
            .map(|slot| slot.dest.clone())
    };
    let Some(dest) = dest else {
        bump_drop(shared);
        return;
    };
    let hit = shared
        .audit_absent
        .as_ref()
        .is_some_and(|needle| contains_needle(payload, needle));
    let sent = match dest {
        Dest::Udp(addr) => send_udp(shared, session_id, payload, addr),
        Dest::Tcp(tx) => send_tcp(session_id, payload, &tx),
    };
    if !sent {
        bump_drop(shared);
        return;
    }
    {
        let mut stats = lock_mutex(&shared.stats);
        stats.forwards += 1;
        stats.forward_bytes += payload.len() as u64;
        if hit {
            stats.plaintext_hits += 1;
        }
    }
    write_audit(shared, session_id, payload.len(), hit);
}

fn send_udp(shared: &Shared, session_id: RelaySessionId, payload: &[u8], addr: SocketAddr) -> bool {
    let socket = {
        let guard = lock_mutex(&shared.udp);
        guard.clone()
    };
    let Some(socket) = socket else {
        return false;
    };
    let Ok(datagram) = encode_datagram(RelayKind::Data, session_id, payload) else {
        return false;
    };
    socket.send_to(&datagram, addr).is_ok()
}

fn send_tcp(session_id: RelaySessionId, payload: &[u8], tx: &SyncSender<Vec<u8>>) -> bool {
    let Ok(datagram) = encode_datagram(RelayKind::Data, session_id, payload) else {
        return false;
    };
    let Ok(record) = encode_tcp_record(&datagram) else {
        return false;
    };
    match tx.try_send(record) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
    }
}

fn write_audit(shared: &Shared, session_id: RelaySessionId, len: usize, hit: bool) {
    let mut guard = lock_mutex(&shared.audit);
    let Some(file) = guard.as_mut() else {
        return;
    };
    let hit_flag = u8::from(hit);
    let line = format!(
        "forward {} {len} {hit_flag}\n",
        encode_hex(session_id.as_bytes())
    );
    let _ = file.write_all(line.as_bytes());
    let _ = file.flush();
}

fn bump_drop(shared: &Shared) {
    lock_mutex(&shared.stats).drops += 1;
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

fn is_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{RelayServer, ServerConfig};
    use crate::{RelayPipe, RelaySessionId};

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn server_both() -> RelayServer {
        RelayServer::spawn(ServerConfig {
            udp_bind: Some(localhost(0)),
            tcp_bind: Some(localhost(0)),
            audit_absent: Some(b"orblx-w6-relay-probe".to_vec()),
            audit_path: None,
            udp_discard: false,
        })
        .unwrap()
    }

    #[test]
    fn udp_forwards_opaque_bytes_and_counts_a_needle() {
        let server = server_both();
        let udp = server.udp_addr().unwrap();
        let session = RelaySessionId::generate().unwrap();
        let mut left = RelayPipe::connect_udp(udp, session, Duration::from_secs(2)).unwrap();
        let mut right = RelayPipe::connect_udp(udp, session, Duration::from_secs(2)).unwrap();
        let payload = b"opaque-ciphertext-not-a-key";
        left.send_opaque(payload).unwrap();
        let got = recv_some(&mut right);
        assert_eq!(got, payload);
        assert!(!crate::contains_needle(payload, b"orblx-w6-relay-probe"));
        left.send_opaque(b"xxorblx-w6-relay-probeyy").unwrap();
        let leaked = recv_some(&mut right);
        assert_eq!(leaked, b"xxorblx-w6-relay-probeyy");
        let stats = server.stats();
        assert_eq!(stats.attaches, 2);
        assert_eq!(stats.forwards, 2);
        assert_eq!(stats.plaintext_hits, 1);
        assert_eq!(
            stats.forward_bytes,
            payload.len() as u64 + leaked.len() as u64
        );
    }

    #[test]
    fn sessions_do_not_cross() {
        let server = server_both();
        let udp = server.udp_addr().unwrap();
        let session_a = RelaySessionId::from_bytes([0x0a; 16]);
        let session_b = RelaySessionId::from_bytes([0x0b; 16]);
        let mut a1 = RelayPipe::connect_udp(udp, session_a, Duration::from_secs(2)).unwrap();
        let mut a2 = RelayPipe::connect_udp(udp, session_a, Duration::from_secs(2)).unwrap();
        let mut b1 = RelayPipe::connect_udp(udp, session_b, Duration::from_secs(2)).unwrap();
        let mut b2 = RelayPipe::connect_udp(udp, session_b, Duration::from_secs(2)).unwrap();
        a1.send_opaque(b"only-session-a").unwrap();
        b1.send_opaque(b"only-session-b").unwrap();
        assert_eq!(recv_some(&mut a2), b"only-session-a");
        assert_eq!(recv_some(&mut b2), b"only-session-b");
        assert!(a2.recv_opaque().unwrap().is_none());
        assert!(b2.recv_opaque().unwrap().is_none());
    }

    #[test]
    fn tcp_forwards_the_same_bytes() {
        let server = server_both();
        let tcp = server.tcp_addr().unwrap();
        let session = RelaySessionId::generate().unwrap();
        let mut left = RelayPipe::connect_tcp(tcp, session, Duration::from_secs(2)).unwrap();
        let mut right = RelayPipe::connect_tcp(tcp, session, Duration::from_secs(2)).unwrap();
        let payload = [0u8, 1, 2, 255, 9];
        left.send_opaque(&payload).unwrap();
        assert_eq!(recv_some(&mut right), payload);
        assert_eq!(server.stats().plaintext_hits, 0);
        assert!(server.stats().forwards >= 1);
    }

    #[test]
    fn udp_timeout_is_udp_blocked() {
        let blackhole = std::net::UdpSocket::bind(localhost(0)).unwrap();
        let addr = blackhole.local_addr().unwrap();
        let err = RelayPipe::connect_udp(
            addr,
            RelaySessionId::from_bytes([1; 16]),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(err, crate::RelayError::UdpBlocked);
        drop(blackhole);
    }

    fn recv_some(pipe: &mut RelayPipe) -> Vec<u8> {
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            if let Some(bytes) = pipe.recv_opaque().unwrap() {
                return bytes;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the Relay did not deliver a payload");
    }
}
