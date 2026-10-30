use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::batch::{recv_batch, send_batch, BatchPeer, RecvBatch, UDP_BATCH};
use crate::error::io_error;
use crate::session::encode_hex;
use crate::{
    contains_needle, encode_datagram, encode_tcp_record, take_tcp_record, RelayError, RelayKind,
    RelaySessionId, MAX_DATAGRAM_LEN, RELAY_HEADER_LEN,
};

const READ_SLICE: Duration = Duration::from_millis(50);

/// A peer that sends nothing for this long loses the session slot.
///
/// A restarted node can attach again.
/// A live peer sends a probe before this time.
const PEER_IDLE: Duration = Duration::from_secs(1);

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
    last_seen: Instant,
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

    /// Return a reader for the counters.
    ///
    /// The metrics listener calls the reader.
    #[must_use]
    pub fn stats_reader(&self) -> Arc<dyn Fn() -> RelayStats + Send + Sync> {
        let shared = Arc::clone(&self.shared);
        Arc::new(move || *lock_mutex(&shared.stats))
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

/// Receive buffers that move between the receive thread and the send thread.
const UDP_POOL: usize = 4;
/// A batch that comes after this gap with no other batch is on a quiet flow.
///
/// When the send thread has no batch, the receive thread sends a quiet batch at once.
/// This removes the wake-up time of the send thread from the RTT.
/// A busy flow still uses the send thread, so two cores share the work.
const QUIET_GAP: Duration = Duration::from_millis(1);

fn udp_loop(socket: Arc<UdpSocket>, shared: Arc<Shared>) {
    // The receive thread reads and routes. The send thread writes.
    // The kernel work of the two calls runs on two cores.
    // One recvmmsg call takes all datagrams that wait, up to the batch size.
    // One sendmmsg call sends all UDP forwards of the batch.
    let (full_tx, full_rx) = mpsc::sync_channel::<(RecvBatch, Vec<UdpForward>)>(UDP_POOL);
    let (free_tx, free_rx) = mpsc::sync_channel::<(RecvBatch, Vec<UdpForward>)>(UDP_POOL);
    for _ in 0..UDP_POOL {
        let _ = free_tx.send((
            RecvBatch::new(UDP_BATCH, MAX_DATAGRAM_LEN),
            Vec::with_capacity(UDP_BATCH),
        ));
    }
    // The batches that the send thread has and did not send yet.
    let in_flight = Arc::new(AtomicUsize::new(0));
    let send_socket = Arc::clone(&socket);
    let send_shared = Arc::clone(&shared);
    let send_in_flight = Arc::clone(&in_flight);
    let sender = thread::Builder::new()
        .name("orblx-relay-send".to_string())
        .spawn(move || {
            while let Ok((batch, out)) = full_rx.recv() {
                send_forwards(&send_shared, &send_socket, &batch, &out);
                send_in_flight.fetch_sub(1, Ordering::AcqRel);
                if free_tx.send((batch, out)).is_err() {
                    break;
                }
            }
        });
    let Ok(sender) = sender else {
        return;
    };
    // The buffers of a batch that this thread sent itself.
    let mut held: Option<(RecvBatch, Vec<UdpForward>)> = None;
    let mut last_batch: Option<Instant> = None;
    'run: while !shared.stop.load(Ordering::Relaxed) {
        let (mut batch, mut out) = match held.take() {
            Some(buffers) => buffers,
            None => match free_rx.recv() {
                Ok(buffers) => buffers,
                Err(_) => break,
            },
        };
        loop {
            if shared.stop.load(Ordering::Relaxed) {
                break 'run;
            }
            match recv_batch(&socket, &mut batch) {
                Ok(_) => break,
                Err(err) if is_timeout(&err) => continue,
                Err(_) => break 'run,
            }
        }
        let at = Instant::now();
        let quiet = last_batch.is_none_or(|last| at.duration_since(last) >= QUIET_GAP);
        last_batch = Some(at);
        out.clear();
        if !shared.udp_discard {
            for index in 0..batch.len() {
                let Some((bytes, Some(from))) = batch.get(index) else {
                    bump_drop(&shared);
                    continue;
                };
                match handle_udp(&shared, &socket, from, bytes) {
                    Ok(Some((session_id, addr, hit))) => out.push(UdpForward {
                        index,
                        session_id,
                        addr,
                        len: bytes.len() - RELAY_HEADER_LEN,
                        hit,
                    }),
                    Ok(None) => {}
                    Err(_) => bump_drop(&shared),
                }
            }
        }
        // No batch waits for the send thread, so a send on this thread keeps the order.
        if quiet && in_flight.load(Ordering::Acquire) == 0 {
            send_forwards(&shared, &socket, &batch, &out);
            held = Some((batch, out));
            continue;
        }
        in_flight.fetch_add(1, Ordering::AcqRel);
        if full_tx.send((batch, out)).is_err() {
            break;
        }
    }
    drop(full_tx);
    let _ = sender.join();
}

/// One UDP forward that waits for the batch send.
struct UdpForward {
    index: usize,
    session_id: RelaySessionId,
    addr: SocketAddr,
    len: usize,
    hit: bool,
}

/// Send the UDP forwards of one batch. The bytes are the received datagrams without a change.
fn send_forwards(shared: &Shared, socket: &UdpSocket, batch: &RecvBatch, out: &[UdpForward]) {
    if out.is_empty() {
        return;
    }
    let frames: Vec<&[u8]> = out
        .iter()
        .filter_map(|item| batch.get(item.index).map(|(bytes, _)| bytes))
        .collect();
    let addrs: Vec<SocketAddr> = out.iter().map(|item| item.addr).collect();
    if frames.len() != out.len() {
        lock_mutex(&shared.stats).drops += out.len() as u64;
        return;
    }
    // A failed datagram is a drop. The send goes on with the next datagram.
    let mut ok = vec![false; out.len()];
    let mut next = 0;
    while next < out.len() {
        let sent = send_batch(
            socket,
            &[],
            &frames[next..],
            BatchPeer::Each(&addrs[next..]),
        )
        .unwrap_or(0);
        for flag in &mut ok[next..next + sent] {
            *flag = true;
        }
        next += sent + 1;
    }
    {
        let mut stats = lock_mutex(&shared.stats);
        for (item, sent) in out.iter().zip(&ok) {
            if !sent {
                stats.drops += 1;
                continue;
            }
            stats.forwards += 1;
            stats.forward_bytes += item.len as u64;
            if item.hit {
                stats.plaintext_hits += 1;
            }
        }
    }
    for (item, _) in out.iter().zip(&ok).filter(|(_, sent)| **sent) {
        write_audit(shared, item.session_id, item.len, item.hit);
    }
}

/// Handle one UDP datagram.
///
/// A DATA datagram for a UDP peer returns the session, the address, and the needle flag.
/// The caller sends the original bytes. A DATA datagram has the same bytes on both sides of the Relay.
fn handle_udp(
    shared: &Shared,
    socket: &UdpSocket,
    from: SocketAddr,
    bytes: &[u8],
) -> Result<Option<(RelaySessionId, SocketAddr, bool)>, RelayError> {
    let (kind, session_id, payload) = crate::wire::split_datagram(bytes)?;
    match kind {
        RelayKind::Attach => {
            if !payload.is_empty() {
                return Err(RelayError::BadDatagram);
            }
            register_udp(shared, session_id, from)?;
            let ack = encode_datagram(RelayKind::Attach, session_id, &[])?;
            socket.send_to(&ack, from).map_err(io_error)?;
            Ok(None)
        }
        RelayKind::Data => {
            let dest = udp_route(shared, session_id, from)?;
            let hit = shared
                .audit_absent
                .as_ref()
                .is_some_and(|needle| contains_needle(payload, needle));
            match dest {
                Dest::Udp(addr) => Ok(Some((session_id, addr, hit))),
                Dest::Tcp(tx) => {
                    if !send_tcp(session_id, payload, &tx) {
                        return Err(RelayError::NotAttached);
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
                    Ok(None)
                }
            }
        }
        RelayKind::Detach => {
            if let Ok(id) = udp_peer_id(shared, session_id, from) {
                remove_peer(shared, session_id, id);
            }
            Ok(None)
        }
    }
}

/// Find the sender slot, mark it as seen, and return the other peer. One lock.
fn udp_route(
    shared: &Shared,
    session_id: RelaySessionId,
    from: SocketAddr,
) -> Result<Dest, RelayError> {
    let mut sessions = lock_mutex(&shared.sessions);
    let session = sessions
        .get_mut(&session_id)
        .ok_or(RelayError::NotAttached)?;
    let slot = session
        .slots
        .iter_mut()
        .find(|slot| matches!(slot.dest, Dest::Udp(existing) if existing == from))
        .ok_or(RelayError::NotAttached)?;
    slot.last_seen = Instant::now();
    let id = slot.id;
    session
        .slots
        .iter()
        .find(|slot| slot.id != id)
        .map(|slot| slot.dest.clone())
        .ok_or(RelayError::NotAttached)
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
    // A writer thread sends each record when it arrives.
    // The reader loop does not wait for a read timeout before it can send.
    let Ok(writer) = stream.try_clone() else {
        return;
    };
    let writer_thread = thread::spawn(move || tcp_writer(writer, rx));
    let mut buf = Vec::new();
    let mut peer: Option<(RelaySessionId, u64)> = None;
    'conn: while !shared.stop.load(Ordering::Relaxed) {
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
                        break 'conn;
                    }
                    match register_tcp(&shared, datagram.session_id, tx.clone()) {
                        Ok(id) => {
                            peer = Some((datagram.session_id, id));
                            let Ok(ack) =
                                encode_datagram(RelayKind::Attach, datagram.session_id, &[])
                            else {
                                break 'conn;
                            };
                            let Ok(record) = encode_tcp_record(&ack) else {
                                break 'conn;
                            };
                            if tx.send(record).is_err() {
                                break 'conn;
                            }
                        }
                        Err(_) => break 'conn,
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
                    touch_slot(&shared, session_id, id);
                    forward(&shared, session_id, id, &datagram.payload);
                }
                RelayKind::Detach => {
                    if let Some((session_id, id)) = peer.take() {
                        if datagram.session_id == session_id {
                            remove_peer(&shared, session_id, id);
                        }
                    }
                    break 'conn;
                }
            }
        }
    }
    if let Some((session_id, id)) = peer {
        remove_peer(&shared, session_id, id);
    }
    drop(tx);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = writer_thread.join();
}

/// Write each queued record to the TCP stream until all senders close.
fn tcp_writer(mut stream: TcpStream, rx: mpsc::Receiver<Vec<u8>>) {
    for record in rx {
        if stream.write_all(&record).is_err() {
            // The reader loop sees the closed stream and removes the peer.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
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
    if let Some(slot) = session.slots.iter_mut().find(|slot| match slot.dest {
        Dest::Udp(existing) => existing == addr,
        Dest::Tcp(_) => false,
    }) {
        slot.last_seen = Instant::now();
        return Ok(slot.id);
    }
    reap_idle(session);
    if session.slots.len() >= 2 {
        return Err(RelayError::SessionFull);
    }
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    session.slots.push(Slot {
        id,
        dest: Dest::Udp(addr),
        last_seen: Instant::now(),
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
    reap_idle(session);
    if session.slots.len() >= 2 {
        return Err(RelayError::SessionFull);
    }
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    session.slots.push(Slot {
        id,
        dest: Dest::Tcp(tx),
        last_seen: Instant::now(),
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

fn reap_idle(session: &mut Session) {
    let now = Instant::now();
    session
        .slots
        .retain(|slot| now.saturating_duration_since(slot.last_seen) < PEER_IDLE);
}

fn touch_slot(shared: &Shared, session_id: RelaySessionId, id: u64) {
    let mut sessions = lock_mutex(&shared.sessions);
    let Some(session) = sessions.get_mut(&session_id) else {
        return;
    };
    if let Some(slot) = session.slots.iter_mut().find(|slot| slot.id == id) {
        slot.last_seen = Instant::now();
    }
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
    fn tcp_sender_keeps_order_and_wait_readable_wakes() {
        let server = server_both();
        let tcp = server.tcp_addr().unwrap();
        let session = RelaySessionId::generate().unwrap();
        let left = RelayPipe::connect_tcp(tcp, session, Duration::from_secs(2)).unwrap();
        let mut right = RelayPipe::connect_tcp(tcp, session, Duration::from_secs(2)).unwrap();
        assert!(!right.wait_readable(Duration::from_millis(50)).unwrap());
        let mut sender = left.sender().unwrap();
        for index in 0u8..20 {
            sender.send_opaque(&[index, 7, 7]).unwrap();
        }
        let mut got = Vec::new();
        let started = std::time::Instant::now();
        while got.len() < 20 && started.elapsed() < Duration::from_secs(5) {
            if !right.wait_readable(Duration::from_secs(1)).unwrap() {
                continue;
            }
            while let Some(bytes) = right.recv_opaque().unwrap() {
                got.push(bytes);
            }
        }
        let want: Vec<Vec<u8>> = (0u8..20).map(|index| vec![index, 7, 7]).collect();
        assert_eq!(got, want);
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
