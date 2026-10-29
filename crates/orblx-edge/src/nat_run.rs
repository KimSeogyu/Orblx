//! NAT node runtime.
//!
//! The node publishes a STUN reflexive address.
//! The coordinator signs that address.
//! The peer verifies the signature and then punches.
//! The overlay session stays up when the path moves between direct and relay.

use std::collections::VecDeque;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use orblx_datapath::{
    format_node_status, is_ipv4_packet, open_tun, NodeStatus, StatusPeer, TunConfig,
    LINUX_TUN_NAME, NODE_PID_FILE, NODE_STATUS_FILE,
};
use orblx_relay::{RelayPipe, RelaySessionId};

use crate::nat_path::{
    encode_hello, relay_allowed, select_path, session_id, session_punch_token, KeyGate, Opened,
    OverlayPath, PathSelect, KIND_DATA, KIND_PROBE, STALE_MS,
};
use crate::punch::{decode_punch, encode_punch, exchange_same_ip, PunchKind, PunchToken};
use crate::signed::{encode_hex, verify_signed_candidate, SignedCandidate};
use crate::{EdgeError, StunClient, DIRECT_ATTEMPT_BUDGET, DIRECT_QUIC_PORT};

const HOLD_LIMIT: usize = 64;
const PROBE_GAP: Duration = Duration::from_millis(150);
const HELLO_GAP: Duration = Duration::from_millis(50);
const PUNCH_GAP: Duration = Duration::from_millis(200);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_signal: i32) {
    STOP.store(true, Ordering::Relaxed);
}

fn stopped() -> bool {
    STOP.load(Ordering::Relaxed)
}

fn install_signals() {
    // SAFETY: the handler stores one atomic flag and returns.
    unsafe {
        libc::signal(libc::SIGINT, on_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_stop as *const () as libc::sighandler_t);
    }
}

/// Inputs for one NAT node.
pub struct NatConfig {
    /// The node state directory.
    ///
    /// The directory receives `status.txt` and the pid file.
    pub state_dir: PathBuf,
    /// This node name.
    pub name: String,
    /// This overlay address.
    pub overlay: Ipv4Addr,
    /// This SPIFFE ID.
    pub svid: String,
    /// This leaf `not_after` time as Unix seconds.
    pub svid_expiry: u64,
    /// The peer name.
    pub peer_name: String,
    /// The peer overlay address.
    pub peer_overlay: Ipv4Addr,
    /// The peer SPIFFE ID.
    pub peer_svid: String,
    /// The STUN server.
    pub stun: SocketAddr,
    /// The Relay UDP socket.
    pub relay_udp: SocketAddr,
    /// The Relay TCP socket.
    pub relay_tcp: SocketAddr,
    /// Replace the default route with this gateway before the TUN device opens.
    pub gateway: Option<Ipv4Addr>,
    /// The coordinator netmap public key.
    pub netmap_public: [u8; 32],
    /// Publish this reflexive endpoint and return the signed candidate list.
    ///
    /// The closure talks to the coordinator.
    /// The closure must not log a private key.
    pub publish: Box<dyn FnMut(String) -> Result<Vec<SignedCandidate>, String> + Send>,
}

/// Run one NAT node until SIGINT or SIGTERM.
pub fn run_nat_node(config: NatConfig) -> Result<(), EdgeError> {
    install_signals();
    if let Some(gateway) = config.gateway {
        set_default_route(gateway)?;
    }
    let (socket, reflexive) = gather_reflexive(config.stun)?;
    println!("The reflexive endpoint is {reflexive}.");
    let session = session_id(&config.name, &config.peer_name)?;
    println!("session {}", encode_hex(&session));
    let gate = KeyGate::generate(session, &config.name, &config.peer_name)?;
    write_record(&config.state_dir, &config.name, config.overlay)?;
    let _pid = PidGuard::create(&config.state_dir)?;
    let bridge = open_tun(&TunConfig {
        name: Some(LINUX_TUN_NAME.to_string()),
        address: config.overlay,
        netmask: Ipv4Addr::new(255, 192, 0, 0),
    })
    .map_err(|err| EdgeError::Io(err.to_string()))?;
    let tun_name = bridge.name.clone();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", &tun_name, "arp", "off"])
        .status();
    let _ = Command::new("ip")
        .args(["route", "replace", "100.64.0.0/10", "dev", &tun_name])
        .status();
    let (from_tx, from_rx) = std::sync::mpsc::channel();
    let (to_tx, to_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut from_tun = bridge.from_tun;
    thread::Builder::new()
        .name("orblx-nat-tun-read".to_string())
        .spawn(move || {
            while let Some(packet) = from_tun.blocking_recv() {
                if from_tx.send(packet).is_err() {
                    break;
                }
            }
        })
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let to_tun = bridge.to_tun;
    thread::Builder::new()
        .name("orblx-nat-tun-write".to_string())
        .spawn(move || {
            while let Ok(packet) = to_rx.recv() {
                if to_tun.blocking_send(packet).is_err() {
                    break;
                }
            }
        })
        .map_err(|err| EdgeError::Io(err.to_string()))?;

    let hub = Arc::new(Hub {
        state_dir: config.state_dir,
        name: config.name,
        overlay: config.overlay,
        svid: config.svid,
        svid_expiry: config.svid_expiry,
        peer_name: config.peer_name,
        peer_overlay: config.peer_overlay,
        peer_svid: config.peer_svid,
        relay_udp: config.relay_udp,
        relay_tcp: config.relay_tcp,
        netmap_public: config.netmap_public,
        session,
        token: session_punch_token(&session),
        relay_id: RelaySessionId::from_bytes(session),
        started: Instant::now(),
        keys: Mutex::new(gate),
        select: Mutex::new(PathSelect::default()),
        queues: Mutex::new(Queues::default()),
        peer_reflexive: Mutex::new(None),
        candidate_at: Mutex::new(None),
        active: AtomicU64::new(0),
        direct_rx: AtomicU64::new(0),
        relay_rx: AtomicU64::new(0),
        saw_direct: AtomicBool::new(false),
        peer_confirmed: AtomicBool::new(false),
        to_tun: Mutex::new(to_tx),
    });
    hub.write_status(None);

    let publish_hub = Arc::clone(&hub);
    let reflexive_text = reflexive.to_string();
    let mut publish = config.publish;
    thread::Builder::new()
        .name("orblx-nat-publish".to_string())
        .spawn(move || publish_loop(publish_hub, reflexive_text, &mut publish))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let relay_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-relay".to_string())
        .spawn(move || relay_loop(relay_hub))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let router_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-router".to_string())
        .spawn(move || router_loop(router_hub, from_rx))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let direct_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-direct".to_string())
        .spawn(move || direct_loop(direct_hub, socket))
        .map_err(|err| EdgeError::Io(err.to_string()))?;

    while !stopped() {
        thread::sleep(Duration::from_millis(200));
    }
    println!("The NAT node is stopping.");
    Ok(())
}

struct PidGuard {
    path: PathBuf,
}

impl PidGuard {
    fn create(dir: &Path) -> Result<Self, EdgeError> {
        let path = dir.join(NODE_PID_FILE);
        fs::write(&path, std::process::id().to_string())
            .map_err(|err| EdgeError::Io(err.to_string()))?;
        Ok(Self { path })
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_record(dir: &Path, name: &str, overlay: Ipv4Addr) -> Result<(), EdgeError> {
    fs::create_dir_all(dir).map_err(|err| EdgeError::Io(err.to_string()))?;
    let text = format!("{{\n  \"name\": \"{name}\",\n  \"overlay_ip\": \"{overlay}\"\n}}\n");
    fs::write(dir.join("node.json"), text).map_err(|err| EdgeError::Io(err.to_string()))
}

/// Point the default route at the lab NAT router.
///
/// Call this before the first coordinator request.
/// The Docker bridge gateway is not the lab router.
pub fn prepare_nat_gateway(gateway: Ipv4Addr) -> Result<(), EdgeError> {
    set_default_route(gateway)
}

fn set_default_route(gateway: Ipv4Addr) -> Result<(), EdgeError> {
    let text = gateway.to_string();
    let status = Command::new("ip")
        .args(["route", "replace", "default", "via", &text])
        .status()
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    if !status.success() {
        return Err(EdgeError::Io(
            "The default route did not change.".to_string(),
        ));
    }
    println!("The default route uses {text}.");
    Ok(())
}

fn gather_reflexive(stun: SocketAddr) -> Result<(UdpSocket, SocketAddr), EdgeError> {
    let mut last = EdgeError::Timeout;
    for _ in 0..5 {
        if stopped() {
            return Err(EdgeError::Timeout);
        }
        let client = StunClient::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, DIRECT_QUIC_PORT)))?;
        match client.gather(stun, Duration::from_secs(2)) {
            Ok(addr) => return Ok((client.into_socket(), addr)),
            Err(EdgeError::Timeout) => {
                last = EdgeError::Timeout;
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last)
}

struct Hub {
    state_dir: PathBuf,
    name: String,
    overlay: Ipv4Addr,
    svid: String,
    svid_expiry: u64,
    peer_name: String,
    peer_overlay: Ipv4Addr,
    peer_svid: String,
    relay_udp: SocketAddr,
    relay_tcp: SocketAddr,
    netmap_public: [u8; 32],
    session: [u8; 16],
    token: PunchToken,
    relay_id: RelaySessionId,
    started: Instant,
    keys: Mutex<KeyGate>,
    select: Mutex<PathSelect>,
    queues: Mutex<Queues>,
    peer_reflexive: Mutex<Option<SocketAddr>>,
    candidate_at: Mutex<Option<Instant>>,
    active: AtomicU64,
    direct_rx: AtomicU64,
    relay_rx: AtomicU64,
    saw_direct: AtomicBool,
    peer_confirmed: AtomicBool,
    to_tun: Mutex<std::sync::mpsc::Sender<Vec<u8>>>,
}

#[derive(Default)]
struct Queues {
    direct: VecDeque<Vec<u8>>,
    relay: VecDeque<Vec<u8>>,
    hold: VecDeque<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Direct,
    Relay,
}

impl Hub {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        *lock(&self.peer_reflexive)
    }

    fn mark_rx(&self, slot: Slot) {
        let now = self.now_ms();
        match slot {
            Slot::Direct => self.direct_rx.store(now, Ordering::Relaxed),
            Slot::Relay => self.relay_rx.store(now, Ordering::Relaxed),
        }
    }

    fn fresh(&self, slot: Slot, now: u64) -> bool {
        let rx = match slot {
            Slot::Direct => self.direct_rx.load(Ordering::Relaxed),
            Slot::Relay => self.relay_rx.load(Ordering::Relaxed),
        };
        rx != 0 && now.saturating_sub(rx) <= STALE_MS
    }

    fn accept(&self, frame: &[u8], slot: Slot) -> Option<Vec<u8>> {
        let opened = {
            let mut gate = lock(&self.keys);
            match gate.open_frame(frame) {
                Ok(opened) => opened,
                Err(_) => return None,
            }
        };
        match opened {
            Some(Opened::Hello) | None => None,
            Some(Opened::Probe) => {
                self.peer_confirmed.store(true, Ordering::Relaxed);
                self.mark_rx(slot);
                None
            }
            Some(Opened::Data(packet)) => {
                self.peer_confirmed.store(true, Ordering::Relaxed);
                self.mark_rx(slot);
                if is_ipv4_packet(&packet) {
                    Some(packet)
                } else {
                    None
                }
            }
        }
    }

    fn send_control(&self, last_hello: &mut Instant, last_probe: &mut Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let ready = lock(&self.keys).ready();
        let confirmed = self.peer_confirmed.load(Ordering::Relaxed);
        let now = Instant::now();
        // A node that already stored the peer key still sends its own key.
        // The punch loop drops frames that are not punch datagrams.
        // The peer may miss the first hello.
        if !confirmed && now.duration_since(*last_hello) >= HELLO_GAP {
            let public = lock(&self.keys).public_key();
            out.push(encode_hello(&self.session, &public));
            *last_hello = now;
        }
        if ready && now.duration_since(*last_probe) >= PROBE_GAP {
            if let Some(frame) = self.seal(KIND_PROBE, &[1]) {
                out.push(frame);
                *last_probe = now;
            }
        }
        out
    }

    fn seal(&self, kind: u8, plain: &[u8]) -> Option<Vec<u8>> {
        let mut gate = lock(&self.keys);
        if !gate.ready() {
            return None;
        }
        gate.seal(kind, plain).ok()
    }

    fn enqueue(&self, packet: Vec<u8>) {
        if !is_ipv4_packet(&packet) {
            return;
        }
        let mut queues = lock(&self.queues);
        let queue = match active_path(self.active.load(Ordering::Relaxed)) {
            Some(OverlayPath::Direct) => &mut queues.direct,
            Some(OverlayPath::Relay) => &mut queues.relay,
            None => &mut queues.hold,
        };
        push_bound(queue, packet);
    }

    fn pop(&self, path: OverlayPath) -> Option<Vec<u8>> {
        let mut queues = lock(&self.queues);
        match path {
            OverlayPath::Direct => queues.direct.pop_front(),
            OverlayPath::Relay => queues.relay.pop_front(),
        }
    }

    fn push_front(&self, path: OverlayPath, packet: Vec<u8>) {
        let mut queues = lock(&self.queues);
        let queue = match path {
            OverlayPath::Direct => &mut queues.direct,
            OverlayPath::Relay => &mut queues.relay,
        };
        queue.push_front(packet);
    }

    fn flush_hold(&self, path: OverlayPath) {
        let mut queues = lock(&self.queues);
        if queues.hold.is_empty() {
            return;
        }
        let pending: Vec<Vec<u8>> = queues.hold.drain(..).collect();
        let queue = match path {
            OverlayPath::Direct => &mut queues.direct,
            OverlayPath::Relay => &mut queues.relay,
        };
        for packet in pending {
            push_bound(queue, packet);
        }
    }

    fn deliver(&self, packet: Vec<u8>) {
        let sender = lock(&self.to_tun);
        let _ = sender.send(packet);
    }

    fn write_status(&self, path: Option<OverlayPath>) {
        let path_text = match path {
            Some(path) => path.as_str(),
            None => "down",
        };
        let status = NodeStatus {
            state: "up".to_string(),
            name: self.name.clone(),
            overlay_ip: self.overlay.to_string(),
            svid: self.svid.clone(),
            svid_expiry: self.svid_expiry,
            peers: vec![StatusPeer {
                name: self.peer_name.clone(),
                overlay_ip: self.peer_overlay.to_string(),
                path: path_text.to_string(),
                svid: self.peer_svid.clone(),
                svid_expiry: None,
            }],
        };
        let text = format_node_status(&status);
        let path = self.state_dir.join(NODE_STATUS_FILE);
        let tmp = self.state_dir.join("status.txt.tmp");
        if fs::write(&tmp, text.as_bytes()).is_ok() {
            let _ = fs::rename(&tmp, &path);
        }
    }
}

fn active_path(value: u64) -> Option<OverlayPath> {
    match value {
        1 => Some(OverlayPath::Direct),
        2 => Some(OverlayPath::Relay),
        _ => None,
    }
}

fn path_code(path: Option<OverlayPath>) -> u64 {
    match path {
        Some(OverlayPath::Direct) => 1,
        Some(OverlayPath::Relay) => 2,
        None => 0,
    }
}

fn push_bound(queue: &mut VecDeque<Vec<u8>>, packet: Vec<u8>) {
    if queue.len() >= HOLD_LIMIT {
        queue.pop_front();
    }
    queue.push_back(packet);
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

fn publish_loop(
    hub: Arc<Hub>,
    reflexive: String,
    publish: &mut dyn FnMut(String) -> Result<Vec<SignedCandidate>, String>,
) {
    while !stopped() {
        match publish(reflexive.clone()) {
            Ok(list) => store_peer(&hub, &list),
            Err(err) => {
                eprintln!("The candidate update failed. The node will retry. {err}");
            }
        }
        for _ in 0..10 {
            if stopped() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn store_peer(hub: &Hub, list: &[SignedCandidate]) {
    for item in list {
        if item.name != hub.peer_name {
            continue;
        }
        if verify_signed_candidate(item, &hub.netmap_public).is_err() {
            continue;
        }
        let Some(addr) = usable_endpoint(&item.endpoint) else {
            continue;
        };
        let mut slot = lock(&hub.peer_reflexive);
        if *slot != Some(addr) {
            println!("The candidate for {} is {}.", item.name, item.endpoint);
            *slot = Some(addr);
        }
        drop(slot);
        let mut started = lock(&hub.candidate_at);
        if started.is_none() {
            *started = Some(Instant::now());
        }
    }
}

fn usable_endpoint(text: &str) -> Option<SocketAddr> {
    if text == "127.0.0.1:9" {
        return None;
    }
    let addr: SocketAddr = text.parse().ok()?;
    if addr.port() == 0 || addr.ip().is_unspecified() {
        None
    } else {
        Some(addr)
    }
}

fn direct_loop(hub: Arc<Hub>, socket: UdpSocket) {
    let mut direct_peer = coordinated_punch(&hub, &socket);
    let _ = socket.set_read_timeout(Some(Duration::from_millis(20)));
    let mut last_hello = Instant::now() - HELLO_GAP;
    let mut last_probe = Instant::now() - PROBE_GAP;
    let mut last_punch = Instant::now() - PUNCH_GAP;
    let mut buf = [0u8; 65_535];
    while !stopped() {
        let fresh = hub.fresh(Slot::Direct, hub.now_ms());
        if (direct_peer.is_none() || !fresh) && last_punch.elapsed() >= PUNCH_GAP {
            if let Some(peer) = hub.peer_addr() {
                let packet = encode_punch(PunchKind::Check, hub.token);
                let _ = socket.send_to(&packet, peer);
            }
            last_punch = Instant::now();
        }
        match socket.recv_from(&mut buf) {
            Ok((size, from)) => {
                if let Some(kind) = decode_punch(&buf[..size], hub.token) {
                    if let Some(signed) = hub.peer_addr() {
                        if from.ip() == signed.ip() {
                            direct_peer = Some(from);
                            if kind == PunchKind::Check {
                                let ack = encode_punch(PunchKind::Ack, hub.token);
                                let _ = socket.send_to(&ack, from);
                            }
                        }
                    }
                } else if let Some(packet) = hub.accept(&buf[..size], Slot::Direct) {
                    hub.deliver(packet);
                }
            }
            Err(err) if is_idle(&err) => {}
            Err(err) => {
                eprintln!("The direct socket read failed. {err}");
                thread::sleep(Duration::from_millis(20));
            }
        }
        if let Some(peer) = direct_peer {
            for frame in hub.send_control(&mut last_hello, &mut last_probe) {
                let _ = socket.send_to(&frame, peer);
            }
            drain_direct(&hub, &socket, peer);
        }
    }
}

fn coordinated_punch(hub: &Hub, socket: &UdpSocket) -> Option<SocketAddr> {
    let mut started: Option<Instant> = None;
    while !stopped() {
        let Some(peer) = hub.peer_addr() else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        let start = *started.get_or_insert_with(Instant::now);
        if start.elapsed() >= DIRECT_ATTEMPT_BUDGET {
            println!("The direct attempt ended. The node can use the relay.");
            return None;
        }
        let round = Instant::now() + Duration::from_millis(500);
        let deadline = round.min(start + DIRECT_ATTEMPT_BUDGET);
        match exchange_same_ip(socket, &[peer], peer, hub.token, deadline) {
            Ok(outcome) => {
                println!("The hole punch reached {}.", outcome.peer);
                return Some(outcome.peer);
            }
            Err(failure) => {
                if !matches!(failure.error, EdgeError::DirectBudget) {
                    eprintln!("The hole punch stopped. {}", failure.error);
                }
            }
        }
    }
    None
}

fn drain_direct(hub: &Hub, socket: &UdpSocket, peer: SocketAddr) {
    while !stopped() {
        let Some(packet) = hub.pop(OverlayPath::Direct) else {
            return;
        };
        let Some(frame) = hub.seal(KIND_DATA, &packet) else {
            hub.push_front(OverlayPath::Direct, packet);
            return;
        };
        if socket.send_to(&frame, peer).is_err() {
            hub.push_front(OverlayPath::Direct, packet);
            return;
        }
    }
}

fn relay_loop(hub: Arc<Hub>) {
    let mut pipe: Option<RelayPipe> = None;
    let mut last_hello = Instant::now() - HELLO_GAP;
    let mut last_probe = Instant::now() - PROBE_GAP;
    while !stopped() {
        if pipe.is_none() {
            match connect_relay(&hub) {
                Ok(next) => {
                    println!("The relay transport is {}.", next.transport());
                    pipe = Some(next);
                }
                Err(err) => {
                    eprintln!("The relay attach failed. The node will retry. {err}");
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
            }
        }
        let Some(current) = pipe.as_mut() else {
            continue;
        };
        match current.recv_opaque() {
            Ok(Some(frame)) => {
                if let Some(packet) = hub.accept(&frame, Slot::Relay) {
                    hub.deliver(packet);
                }
            }
            Ok(None) => {}
            Err(_) => {
                eprintln!("The relay path stopped. The node will attach again.");
                pipe = None;
                thread::sleep(Duration::from_millis(200));
                continue;
            }
        }
        let frames = hub.send_control(&mut last_hello, &mut last_probe);
        let mut failed = false;
        if let Some(current) = pipe.as_mut() {
            for frame in frames {
                if current.send_opaque(&frame).is_err() {
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            pipe = None;
            continue;
        }
        if !drain_relay(&hub, pipe.as_mut()) {
            pipe = None;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn connect_relay(hub: &Hub) -> Result<RelayPipe, orblx_relay::RelayError> {
    match RelayPipe::connect_udp(hub.relay_udp, hub.relay_id, Duration::from_millis(800)) {
        Ok(pipe) => Ok(pipe),
        Err(_) => RelayPipe::connect_tcp(hub.relay_tcp, hub.relay_id, Duration::from_secs(2)),
    }
}

fn drain_relay(hub: &Hub, pipe: Option<&mut RelayPipe>) -> bool {
    let Some(pipe) = pipe else {
        return true;
    };
    while !stopped() {
        let Some(packet) = hub.pop(OverlayPath::Relay) else {
            return true;
        };
        let Some(frame) = hub.seal(KIND_DATA, &packet) else {
            hub.push_front(OverlayPath::Relay, packet);
            return true;
        };
        if pipe.send_opaque(&frame).is_err() {
            hub.push_front(OverlayPath::Relay, packet);
            return false;
        }
    }
    true
}

fn router_loop(hub: Arc<Hub>, packets: std::sync::mpsc::Receiver<Vec<u8>>) {
    let mut reported: Option<OverlayPath> = None;
    let mut known = false;
    let mut last_status = Instant::now() - Duration::from_secs(1);
    while !stopped() {
        match packets.recv_timeout(Duration::from_millis(50)) {
            Ok(packet) => hub.enqueue(packet),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
        let now = hub.now_ms();
        let direct_ok = hub.fresh(Slot::Direct, now);
        let relay_ok = hub.fresh(Slot::Relay, now);
        let budget_done = lock(&hub.candidate_at)
            .map(|start| start.elapsed() >= DIRECT_ATTEMPT_BUDGET)
            .unwrap_or(false);
        let allowed = relay_allowed(
            hub.saw_direct.load(Ordering::Relaxed),
            direct_ok,
            budget_done,
        );
        let next = {
            let mut select = lock(&hub.select);
            select_path(&mut select, direct_ok, relay_ok, allowed, now)
        };
        if next == Some(OverlayPath::Direct) {
            hub.saw_direct.store(true, Ordering::Relaxed);
        }
        hub.active.store(path_code(next), Ordering::Relaxed);
        if let Some(path) = next {
            hub.flush_hold(path);
        }
        if !known || next != reported {
            if let Some(path) = next {
                println!("The path to {} is {}.", hub.peer_name, path.as_str());
                println!(
                    "session {} path {}",
                    encode_hex(&hub.session),
                    path.as_str()
                );
            }
            reported = next;
            known = true;
            hub.write_status(next);
            last_status = Instant::now();
        } else if last_status.elapsed() >= Duration::from_millis(500) {
            hub.write_status(next);
            last_status = Instant::now();
        }
    }
}

fn is_idle(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
    )
}
