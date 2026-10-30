//! NAT node runtime.
//!
//! The node publishes a STUN reflexive address.
//! The coordinator signs that address.
//! The peer verifies the signature and then punches.
//! The overlay session stays up when the path moves between direct and relay.
//! A path move is make-before-break.
//! The node keeps the old path until the new path carries probes both ways.

use std::collections::VecDeque;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use orblx_datapath::{
    format_node_status, is_ipv4_packet, open_tun, NodeStatus, StatusPeer, TunConfig,
    LINUX_TUN_NAME, NODE_PID_FILE, NODE_STATUS_FILE,
};
use orblx_relay::{send_batch, BatchPeer, RelayPipe, RelaySender, RelaySessionId};

use crate::birthday::{
    local_kind, peer_kind, strategy, MappingKind, RateGate, Spray, Strategy, BIRTHDAY_SOCKETS,
    BIRTHDAY_WINDOW, PROBE_BURST, PROBE_RATE, SOCKET_REFRESH,
};
use crate::nat_path::{
    relay_allowed, select_path, session_id, session_punch_token, HelloAuth, KeyGate, Opened,
    OverlayPath, PathSelect, SendPlan, KIND_DATA, KIND_PROBE, PROBE_GAP_MS, PROBE_HEARS, RESEND_MS,
    STALE_MS,
};
use crate::punch::{decode_punch, encode_punch, exchange_same_ip, PunchKind, PunchToken};
use crate::signed::{encode_hex, verify_signed_candidate, SignedCandidate};
use crate::{EdgeError, StunClient, DIRECT_ATTEMPT_BUDGET, DIRECT_QUIC_PORT};

const HOLD_LIMIT: usize = 64;
/// The router takes up to this many TUN packets for one seal and send round.
/// The value is less than HOLD_LIMIT, so one round does not push a queued frame out.
const ROUTER_BATCH: usize = orblx_relay::UDP_BATCH;
const RECENT_LIMIT: usize = 128;
const PROBE_GAP: Duration = Duration::from_millis(PROBE_GAP_MS);
const HELLO_GAP: Duration = Duration::from_millis(50);
const PUNCH_GAP: Duration = Duration::from_millis(200);
const RELAY_ONLY_PUNCH_GAP: Duration = Duration::from_secs(2);
const DIRECT_READ: Duration = Duration::from_millis(5);
/// The longest time that the relay loop blocks on its socket.
///
/// Data frames wake the loop at once. The limit only sets the timing of the control frames and the stop check.
const RELAY_WAIT: Duration = Duration::from_millis(20);
/// The send thread also flushes the queues after this time without a wake.
const SEND_WAIT: Duration = Duration::from_millis(50);
/// After a renewal the node sends the new hello on each path for this time.
const RENEW_HELLO_MS: u64 = 5_000;
/// The gap between two hello frames after a renewal.
const RENEW_HELLO_GAP: Duration = Duration::from_millis(500);
const RENEW_RETRY_MIN: Duration = Duration::from_secs(1);
const RENEW_RETRY_MAX: Duration = Duration::from_secs(30);

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

/// Publish reflexive endpoints and return the signed candidate list.
pub type PublishFn = Box<dyn FnMut(Vec<String>) -> Result<Vec<SignedCandidate>, String> + Send>;

/// A renewed leaf SVID for the signed hello.
///
/// The value does not print the seed.
pub struct RenewedLeaf {
    /// The renewed leaf DER.
    pub cert_der: Vec<u8>,
    /// The Ed25519 seed of the renewed leaf key.
    pub seed: [u8; 32],
}

impl std::fmt::Debug for RenewedLeaf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RenewedLeaf")
            .field("cert_der_len", &self.cert_der.len())
            .finish_non_exhaustive()
    }
}

/// Renew the leaf SVID at the coordinator and return the new leaf.
///
/// The closure stores the new state files.
/// The closure must not log a private key.
pub type RenewFn = Box<dyn FnMut() -> Result<RenewedLeaf, String> + Send>;

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
    /// A second STUN server on another address or port.
    ///
    /// Two answers show the NAT mapping kind.
    pub stun_alt: Option<SocketAddr>,
    /// The Relay UDP socket.
    pub relay_udp: SocketAddr,
    /// The Relay TCP socket.
    pub relay_tcp: SocketAddr,
    /// Replace the default route with this gateway before the TUN device opens.
    pub gateway: Option<Ipv4Addr>,
    /// The coordinator netmap public key.
    pub netmap_public: [u8; 32],
    /// The SVID material for the signed hello.
    pub hello: HelloAuth,
    /// Publish these reflexive endpoints and return the signed candidate list.
    ///
    /// The closure talks to the coordinator.
    /// The closure must not log a private key.
    pub publish: PublishFn,
    /// Renew the leaf SVID before it expires.
    ///
    /// After a renewal the node sends a new signed hello on the direct path and on the relay path.
    /// The peer then shows the new expiry.
    /// `None` keeps the first leaf.
    pub renew: Option<RenewFn>,
}

/// Run one NAT node until SIGINT or SIGTERM.
pub fn run_nat_node(config: NatConfig) -> Result<(), EdgeError> {
    install_signals();
    if let Some(gateway) = config.gateway {
        set_default_route(gateway)?;
    }
    let (socket, reflexive, alt) = gather_reflexive(config.stun, config.stun_alt)?;
    println!("The reflexive endpoint is {reflexive}.");
    if let Some(alt) = alt {
        println!("The second reflexive endpoint is {alt}.");
    }
    let nat_kind = local_kind(reflexive, alt);
    println!("The local NAT mapping is {}.", nat_kind.as_str());
    let leaf_der = config.hello.cert_der.clone();
    let session = session_id(&config.name, &config.peer_name)?;
    println!("session {}", encode_hex(&session));
    let gate = KeyGate::generate(session, &config.name, &config.peer_name, config.hello)?;
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
        svid_expiry: AtomicU64::new(config.svid_expiry),
        hello_until: AtomicU64::new(0),
        direct_out: Mutex::new(None),
        relay_out: Mutex::new(None),
        relay_broken: AtomicBool::new(false),
        peer_name: config.peer_name,
        peer_overlay: config.peer_overlay,
        peer_svid: config.peer_svid,
        relay_udp: config.relay_udp,
        relay_tcp: config.relay_tcp,
        netmap_public: config.netmap_public,
        nat_kind,
        session,
        token: session_punch_token(&session),
        relay_id: RelaySessionId::from_bytes(session),
        started: Instant::now(),
        keys: Mutex::new(gate),
        select: Mutex::new(PathSelect::default()),
        queues: Mutex::new(Queues::default()),
        queued: Condvar::new(),
        peer_endpoints: Mutex::new(Vec::new()),
        candidate_at: Mutex::new(None),
        plan: AtomicU64::new(0),
        direct_rx: AtomicU64::new(0),
        relay_rx: AtomicU64::new(0),
        direct_heard: AtomicU64::new(0),
        relay_heard: AtomicU64::new(0),
        saw_direct: AtomicBool::new(false),
        peer_confirmed: AtomicBool::new(false),
        to_tun: Mutex::new(to_tx),
    });
    hub.write_status(None);

    let publish_hub = Arc::clone(&hub);
    let mut reflexive_text = vec![reflexive.to_string()];
    if let Some(alt) = alt {
        reflexive_text.push(alt.to_string());
    }
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
    let send_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-send".to_string())
        .spawn(move || send_loop(send_hub))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let router_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-router".to_string())
        .spawn(move || router_loop(router_hub, from_rx))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    if let Some(renew) = config.renew {
        let renew_hub = Arc::clone(&hub);
        thread::Builder::new()
            .name("orblx-nat-renew".to_string())
            .spawn(move || renew_loop(renew_hub, leaf_der, renew))
            .map_err(|err| EdgeError::Io(err.to_string()))?;
    }
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

type Reflexive = (UdpSocket, SocketAddr, Option<SocketAddr>);

fn gather_reflexive(stun: SocketAddr, alt: Option<SocketAddr>) -> Result<Reflexive, EdgeError> {
    let mut last = EdgeError::Timeout;
    for _ in 0..5 {
        if stopped() {
            return Err(EdgeError::Timeout);
        }
        let client = StunClient::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, DIRECT_QUIC_PORT)))?;
        match client.gather(stun, Duration::from_secs(2)) {
            Ok(addr) => {
                // The second answer uses the same local socket.
                // A different port means an endpoint-dependent mapping.
                let second = match alt {
                    Some(server) => gather_alt(&client, server),
                    None => None,
                };
                return Ok((client.into_socket(), addr, second));
            }
            Err(EdgeError::Timeout) => {
                last = EdgeError::Timeout;
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last)
}

fn gather_alt(client: &StunClient, server: SocketAddr) -> Option<SocketAddr> {
    for _ in 0..3 {
        match client.gather(server, Duration::from_secs(1)) {
            Ok(addr) => return Some(addr),
            Err(EdgeError::Timeout) => continue,
            Err(_) => return None,
        }
    }
    eprintln!("The second STUN server did not answer. The NAT mapping kind is unknown.");
    None
}

struct Hub {
    state_dir: PathBuf,
    name: String,
    overlay: Ipv4Addr,
    svid: String,
    svid_expiry: AtomicU64,
    /// Until this time in ms, the node sends its hello again on each path.
    hello_until: AtomicU64,
    /// The direct socket and the peer address after a punch.
    ///
    /// The router sends a data frame at once with this socket.
    direct_out: Mutex<Option<(UdpSocket, SocketAddr)>>,
    /// The send handle of the relay attachment.
    ///
    /// The router and the relay loop send with this handle at once.
    /// The lock keeps the frames on a TCP attachment in order.
    relay_out: Mutex<Option<RelaySender>>,
    /// A send on the relay handle failed. The relay loop attaches again.
    relay_broken: AtomicBool,
    peer_name: String,
    peer_overlay: Ipv4Addr,
    peer_svid: String,
    relay_udp: SocketAddr,
    relay_tcp: SocketAddr,
    netmap_public: [u8; 32],
    nat_kind: MappingKind,
    session: [u8; 16],
    token: PunchToken,
    relay_id: RelaySessionId,
    started: Instant,
    keys: Mutex<KeyGate>,
    select: Mutex<PathSelect>,
    queues: Mutex<Queues>,
    /// Wakes the send thread. It goes with `queues`.
    queued: Condvar,
    peer_endpoints: Mutex<Vec<SocketAddr>>,
    candidate_at: Mutex<Option<Instant>>,
    plan: AtomicU64,
    direct_rx: AtomicU64,
    relay_rx: AtomicU64,
    direct_heard: AtomicU64,
    relay_heard: AtomicU64,
    saw_direct: AtomicBool,
    peer_confirmed: AtomicBool,
    to_tun: Mutex<std::sync::mpsc::Sender<Vec<u8>>>,
}

/// Sealed frames for each path, and plain packets that wait for a path.
#[derive(Default)]
struct Queues {
    direct: VecDeque<Vec<u8>>,
    relay: VecDeque<Vec<u8>>,
    hold: VecDeque<Vec<u8>>,
    /// Frames sent on direct, with the send time in ms.
    ///
    /// A move to relay sends these frames again.
    recent: VecDeque<(u64, Vec<u8>)>,
    /// True when new frames wait for the send thread.
    wake: bool,
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

    /// The first signed endpoint of the peer.
    fn peer_addr(&self) -> Option<SocketAddr> {
        lock(&self.peer_endpoints).first().copied()
    }

    /// The ports in the signed endpoints of the peer.
    fn peer_ports(&self) -> Vec<u16> {
        lock(&self.peer_endpoints)
            .iter()
            .map(SocketAddr::port)
            .collect()
    }

    fn peer_kind(&self) -> MappingKind {
        peer_kind(&lock(&self.peer_endpoints))
    }

    fn mark_rx(&self, slot: Slot) {
        let now = self.now_ms().max(1);
        match slot {
            Slot::Direct => self.direct_rx.store(now, Ordering::Relaxed),
            Slot::Relay => self.relay_rx.store(now, Ordering::Relaxed),
        }
    }

    fn mark_heard(&self, slot: Slot, hears: bool) {
        let value = if hears { self.now_ms().max(1) } else { 0 };
        match slot {
            Slot::Direct => self.direct_heard.store(value, Ordering::Relaxed),
            Slot::Relay => self.relay_heard.store(value, Ordering::Relaxed),
        }
    }

    /// Return true when a frame arrived on this path in the stale time.
    fn fresh(&self, slot: Slot, now: u64) -> bool {
        let rx = match slot {
            Slot::Direct => self.direct_rx.load(Ordering::Relaxed),
            Slot::Relay => self.relay_rx.load(Ordering::Relaxed),
        };
        recent_ms(rx, now)
    }

    /// Return true when probes went both ways on this path in the stale time.
    fn both_ways(&self, slot: Slot, now: u64) -> bool {
        let heard = match slot {
            Slot::Direct => self.direct_heard.load(Ordering::Relaxed),
            Slot::Relay => self.relay_heard.load(Ordering::Relaxed),
        };
        self.fresh(slot, now) && recent_ms(heard, now)
    }

    /// Open one frame.
    ///
    /// The second value is true when the frame was a fresh probe or data frame.
    fn accept(&self, frame: &[u8], slot: Slot) -> (Option<Vec<u8>>, bool) {
        let opened = {
            let mut gate = lock(&self.keys);
            match gate.open_frame(frame) {
                Ok(opened) => opened,
                Err(EdgeError::Identity(text)) => {
                    eprintln!("{text}");
                    return (None, false);
                }
                Err(_) => return (None, false),
            }
        };
        match opened {
            Some(Opened::Hello) | None => (None, false),
            Some(Opened::Probe(flags)) => {
                self.peer_confirmed.store(true, Ordering::Relaxed);
                self.mark_rx(slot);
                self.mark_heard(slot, flags & PROBE_HEARS != 0);
                (None, true)
            }
            Some(Opened::Data(packet)) => {
                self.peer_confirmed.store(true, Ordering::Relaxed);
                self.mark_rx(slot);
                if is_ipv4_packet(&packet) {
                    (Some(packet), true)
                } else {
                    (None, true)
                }
            }
        }
    }

    fn send_control(
        &self,
        slot: Slot,
        last_hello: &mut Instant,
        last_probe: &mut Instant,
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let ready = lock(&self.keys).ready();
        let confirmed = self.peer_confirmed.load(Ordering::Relaxed);
        let now = Instant::now();
        // A node that already stored the peer key still sends its own key.
        // The punch loop drops frames that are not punch datagrams.
        // The peer may miss the first hello.
        // After a renewal the node sends the new hello again, also to a confirmed peer.
        let renewed = self.now_ms() < self.hello_until.load(Ordering::Relaxed);
        let gap = if confirmed {
            RENEW_HELLO_GAP
        } else {
            HELLO_GAP
        };
        if (!confirmed || renewed) && now.duration_since(*last_hello) >= gap {
            out.push(lock(&self.keys).hello_frame());
            *last_hello = now;
        }
        if ready && now.duration_since(*last_probe) >= PROBE_GAP {
            // The flag tells the peer that this node receives on this path.
            let hears = if self.fresh(slot, self.now_ms()) {
                PROBE_HEARS
            } else {
                0
            };
            if let Some(frame) = self.seal(KIND_PROBE, &[hears]) {
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

    fn current_plan(&self) -> SendPlan {
        plan_of(self.plan.load(Ordering::Relaxed))
    }

    /// Seal and queue a batch of TUN packets.
    ///
    /// The function takes the key lock one time and the queue lock one time for the batch.
    fn enqueue_batch(&self, packets: Vec<Vec<u8>>) {
        let plan = self.current_plan();
        let packets = packets.into_iter().filter(|packet| is_ipv4_packet(packet));
        if plan == SendPlan::Hold {
            let mut queues = lock(&self.queues);
            for packet in packets {
                push_bound(&mut queues.hold, packet);
            }
            return;
        }
        // One seal for each packet. The key gate gives each frame its own counter.
        // The same frame can go on two paths. The receiver drops the second copy.
        let mut frames = Vec::with_capacity(ROUTER_BATCH);
        let mut held = Vec::new();
        {
            let mut gate = lock(&self.keys);
            for packet in packets {
                let sealed = if gate.ready() {
                    gate.seal(KIND_DATA, &packet).ok()
                } else {
                    None
                };
                match sealed {
                    Some(frame) => frames.push(frame),
                    None => held.push(packet),
                }
            }
        }
        let mut queues = lock(&self.queues);
        for packet in held {
            push_bound(&mut queues.hold, packet);
        }
        let now = self.now_ms();
        for frame in frames {
            Self::route_locked(&mut queues, frame, plan, now);
        }
        queues.wake = true;
        drop(queues);
        self.queued.notify_one();
    }

    /// Wake the send thread.
    fn wake_sender(&self) {
        lock(&self.queues).wake = true;
        self.queued.notify_one();
    }

    fn route(&self, frame: Vec<u8>, plan: SendPlan) {
        let now = self.now_ms();
        let mut queues = lock(&self.queues);
        Self::route_locked(&mut queues, frame, plan, now);
    }

    fn route_locked(queues: &mut Queues, frame: Vec<u8>, plan: SendPlan, now: u64) {
        if plan.uses_direct() {
            push_bound(&mut queues.direct, frame.clone());
            queues.recent.push_back((now, frame.clone()));
            while queues.recent.len() > RECENT_LIMIT
                || queues
                    .recent
                    .front()
                    .is_some_and(|(at, _)| now.saturating_sub(*at) > 2 * RESEND_MS)
            {
                queues.recent.pop_front();
            }
        }
        if plan.uses_relay() {
            push_bound(&mut queues.relay, frame);
        }
    }

    /// Send again on the relay the direct frames sent at or after `since_ms`.
    fn resend_on_relay(&self, since_ms: u64) -> usize {
        let mut queues = lock(&self.queues);
        let frames: Vec<Vec<u8>> = queues
            .recent
            .drain(..)
            .filter(|(at, _)| *at >= since_ms)
            .map(|(_, frame)| frame)
            .collect();
        let count = frames.len();
        for frame in frames {
            push_bound(&mut queues.relay, frame);
        }
        count
    }

    /// Take up to `max` frames from the front of one queue.
    fn pop_many(&self, path: OverlayPath, max: usize) -> Vec<Vec<u8>> {
        let mut queues = lock(&self.queues);
        let queue = match path {
            OverlayPath::Direct => &mut queues.direct,
            OverlayPath::Relay => &mut queues.relay,
        };
        let count = queue.len().min(max);
        queue.drain(..count).collect()
    }

    /// Put frames back at the front of one queue. The frames keep their order.
    fn push_front_many(&self, path: OverlayPath, frames: Vec<Vec<u8>>) {
        let mut queues = lock(&self.queues);
        let queue = match path {
            OverlayPath::Direct => &mut queues.direct,
            OverlayPath::Relay => &mut queues.relay,
        };
        for frame in frames.into_iter().rev() {
            queue.push_front(frame);
        }
    }

    fn flush_hold(&self, plan: SendPlan) {
        if plan == SendPlan::Hold {
            return;
        }
        let pending: Vec<Vec<u8>> = {
            let mut queues = lock(&self.queues);
            if queues.hold.is_empty() {
                return;
            }
            queues.hold.drain(..).collect()
        };
        for packet in pending {
            match self.seal(KIND_DATA, &packet) {
                Some(frame) => self.route(frame, plan),
                None => push_bound(&mut lock(&self.queues).hold, packet),
            }
        }
    }

    /// Send the queued direct frames now, when the direct socket is known.
    fn flush_direct(&self) {
        let out = lock(&self.direct_out);
        if let Some((socket, peer)) = out.as_ref() {
            drain_direct(self, socket, *peer);
        }
    }

    /// Store the direct socket and the peer address for [`Hub::flush_direct`].
    /// Send all queued relay frames now. Return false when a send fails.
    fn flush_relay(&self) -> bool {
        let mut out = lock(&self.relay_out);
        let Some(sender) = out.as_mut() else {
            return true;
        };
        loop {
            let mut frames = self.pop_many(OverlayPath::Relay, ROUTER_BATCH);
            if frames.is_empty() {
                return true;
            }
            let (sent, result) = sender.send_many(&frames);
            if result.is_err() {
                self.push_front_many(OverlayPath::Relay, frames.split_off(sent));
                *out = None;
                self.relay_broken.store(true, Ordering::Relaxed);
                return false;
            }
        }
    }

    /// Send control frames on the relay. Return false when a send fails.
    fn send_relay(&self, frames: Vec<Vec<u8>>) -> bool {
        let mut out = lock(&self.relay_out);
        let Some(sender) = out.as_mut() else {
            return frames.is_empty();
        };
        for frame in frames {
            if sender.send_opaque(&frame).is_err() {
                *out = None;
                self.relay_broken.store(true, Ordering::Relaxed);
                return false;
            }
        }
        true
    }

    fn set_relay_out(&self, sender: Option<RelaySender>) {
        *lock(&self.relay_out) = sender;
        self.relay_broken.store(false, Ordering::Relaxed);
    }

    fn set_direct_out(&self, socket: &UdpSocket, peer: SocketAddr) {
        match socket.try_clone() {
            Ok(clone) => *lock(&self.direct_out) = Some((clone, peer)),
            Err(err) => {
                eprintln!("The direct socket did not clone. {err}");
                *lock(&self.direct_out) = None;
            }
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
        let peer_expiry = lock(&self.keys).peer_not_after();
        let status = NodeStatus {
            state: "up".to_string(),
            name: self.name.clone(),
            overlay_ip: self.overlay.to_string(),
            svid: self.svid.clone(),
            svid_expiry: self.svid_expiry.load(Ordering::Relaxed),
            exit_node: None,
            peers: vec![StatusPeer {
                name: self.peer_name.clone(),
                overlay_ip: self.peer_overlay.to_string(),
                path: path_text.to_string(),
                svid: self.peer_svid.clone(),
                // The value comes from the peer SVID in the signed hello.
                svid_expiry: peer_expiry,
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

fn recent_ms(at: u64, now: u64) -> bool {
    at != 0 && now.saturating_sub(at) <= STALE_MS
}

fn plan_of(value: u64) -> SendPlan {
    match value {
        1 => SendPlan::Direct,
        2 => SendPlan::Relay,
        3 => SendPlan::Both,
        _ => SendPlan::Hold,
    }
}

fn plan_code(plan: SendPlan) -> u64 {
    match plan {
        SendPlan::Hold => 0,
        SendPlan::Direct => 1,
        SendPlan::Relay => 2,
        SendPlan::Both => 3,
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
    reflexive: Vec<String>,
    publish: &mut dyn FnMut(Vec<String>) -> Result<Vec<SignedCandidate>, String>,
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
    let mut verified = Vec::new();
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
        verified.push(addr);
    }
    if verified.is_empty() {
        return;
    }
    let mut slot = lock(&hub.peer_endpoints);
    if *slot != verified {
        for addr in &verified {
            println!("The candidate for {} is {}.", hub.peer_name, addr);
        }
        *slot = verified;
    }
    drop(slot);
    let mut started = lock(&hub.candidate_at);
    if started.is_none() {
        *started = Some(Instant::now());
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

/// The extra sockets of the hard side for one birthday attempt.
struct Fleet {
    sockets: Vec<UdpSocket>,
    sent_at: Vec<Option<Instant>>,
    next: usize,
    started: Instant,
    gate: RateGate,
    sent: u64,
}

impl Fleet {
    fn open(count: usize, now: Instant) -> Result<Self, EdgeError> {
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                .map_err(|err| EdgeError::Io(err.to_string()))?;
            socket
                .set_nonblocking(true)
                .map_err(|err| EdgeError::Io(err.to_string()))?;
            sockets.push(socket);
        }
        Ok(Self {
            sent_at: vec![None; sockets.len()],
            sockets,
            next: 0,
            started: now,
            gate: RateGate::new(PROBE_RATE, PROBE_BURST, now),
            sent: 0,
        })
    }

    fn done(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= BIRTHDAY_WINDOW
    }

    /// Send the punch on the sockets that are due, in the rate limit.
    fn send_due(&mut self, peer: SocketAddr, packet: &[u8], now: Instant) {
        let count = self.sockets.len();
        for _ in 0..count {
            let index = self.next;
            let due = self.sent_at[index]
                .map(|at| now.saturating_duration_since(at) >= SOCKET_REFRESH)
                .unwrap_or(true);
            if !due {
                self.next = (index + 1) % count;
                continue;
            }
            if self.gate.take(now, 1) == 0 {
                return;
            }
            let _ = self.sockets[index].send_to(packet, peer);
            self.sent_at[index] = Some(now);
            self.sent += 1;
            self.next = (index + 1) % count;
        }
    }

    /// Return the socket index and source of the first punch from `ip`.
    fn poll(&self, token: PunchToken, ip: IpAddr) -> Option<(usize, SocketAddr, PunchKind)> {
        let mut fds: Vec<libc::pollfd> = self
            .sockets
            .iter()
            .map(|socket| libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is a valid array of pollfd values with the given length.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
        if ready <= 0 {
            return None;
        }
        let mut buf = [0u8; 2048];
        for (index, fd) in fds.iter().enumerate() {
            if fd.revents & libc::POLLIN == 0 {
                continue;
            }
            while let Ok((size, from)) = self.sockets[index].recv_from(&mut buf) {
                if from.ip() != ip {
                    continue;
                }
                if let Some(kind) = decode_punch(&buf[..size], token) {
                    return Some((index, from, kind));
                }
            }
        }
        None
    }

    fn take(mut self, index: usize) -> UdpSocket {
        self.sockets.swap_remove(index)
    }
}

fn direct_loop(hub: Arc<Hub>, socket: UdpSocket) {
    let mut socket = socket;
    let (mut direct_peer, plan) = coordinated_punch(&hub, &socket);
    let _ = socket.set_read_timeout(Some(DIRECT_READ));
    let mut spray: Option<Spray> = None;
    let mut fleet: Option<Fleet> = None;
    if direct_peer.is_none() {
        let now = Instant::now();
        match plan {
            Strategy::Spray => {
                if let Some(peer) = hub.peer_addr() {
                    spray = Some(Spray::new(peer.ip(), &hub.peer_ports(), now));
                }
            }
            Strategy::Sockets => match Fleet::open(BIRTHDAY_SOCKETS, now) {
                Ok(opened) => fleet = Some(opened),
                Err(err) => eprintln!("The birthday sockets did not open. {err}"),
            },
            Strategy::Plain | Strategy::RelayOnly => {}
        }
    }
    let check = encode_punch(PunchKind::Check, hub.token);
    let ack = encode_punch(PunchKind::Ack, hub.token);
    let punch_gap = if plan == Strategy::RelayOnly {
        RELAY_ONLY_PUNCH_GAP
    } else {
        PUNCH_GAP
    };
    let mut last_hello = Instant::now() - HELLO_GAP;
    let mut last_probe = Instant::now() - PROBE_GAP;
    let mut last_punch = Instant::now() - punch_gap;
    let mut buf = [0u8; 65_535];
    // The direct peer and socket that the router uses. A change stores them again.
    let mut shared: Option<(SocketAddr, Option<SocketAddr>)> = None;
    while !stopped() {
        if let Some(peer) = direct_peer {
            let key = (peer, socket.local_addr().ok());
            if shared != Some(key) {
                hub.set_direct_out(&socket, peer);
                shared = Some(key);
            }
        }
        let now = Instant::now();
        let fresh = hub.fresh(Slot::Direct, hub.now_ms());
        if (direct_peer.is_none() || !fresh) && last_punch.elapsed() >= punch_gap {
            let signed = hub.peer_addr();
            if let Some(peer) = signed {
                let _ = socket.send_to(&check, peer);
            }
            // The last working address can differ from the signed address.
            // A symmetric NAT maps a new port for this flow.
            if let Some(known) = direct_peer.filter(|known| Some(*known) != signed) {
                let _ = socket.send_to(&check, known);
            }
            last_punch = now;
        }
        if direct_peer.is_none() {
            if let Some(active) = spray.as_mut() {
                match active.due(now) {
                    Ok(targets) => {
                        for target in targets {
                            let _ = socket.send_to(&check, target);
                        }
                    }
                    Err(err) => eprintln!("The port spray stopped. {err}"),
                }
                if active.done(now) {
                    println!(
                        "The port spray ended after {} probes. The node uses the relay.",
                        active.sent()
                    );
                    spray = None;
                }
            }
            if let (Some(active), Some(peer)) = (fleet.as_mut(), hub.peer_addr()) {
                active.send_due(peer, &check, now);
                if let Some((index, from, kind)) = active.poll(hub.token, peer.ip()) {
                    let sent = active.sent;
                    if let Some(winner) = fleet.take() {
                        socket = winner.take(index);
                        let _ = socket.set_nonblocking(false);
                        let _ = socket.set_read_timeout(Some(DIRECT_READ));
                        if kind == PunchKind::Check {
                            let _ = socket.send_to(&ack, from);
                        }
                        println!(
                            "The birthday punch reached {from} with socket {index} after {sent} probes."
                        );
                        println!("The hole punch reached {from}.");
                        direct_peer = Some(from);
                    }
                } else if active.done(now) {
                    println!(
                        "The birthday attempt ended after {} probes. The node uses the relay.",
                        active.sent
                    );
                    fleet = None;
                }
            }
        }
        match socket.recv_from(&mut buf) {
            Ok((size, from)) => {
                if let Some(kind) = decode_punch(&buf[..size], hub.token) {
                    if let Some(signed) = hub.peer_addr() {
                        if from.ip() == signed.ip() {
                            if direct_peer.is_none() {
                                if let Some(active) = spray.take() {
                                    println!(
                                        "The port spray reached {from} after {} probes.",
                                        active.sent()
                                    );
                                }
                                println!("The hole punch reached {from}.");
                            }
                            direct_peer = Some(from);
                            if kind == PunchKind::Check {
                                let _ = socket.send_to(&ack, from);
                            }
                        }
                    }
                } else {
                    let (packet, fresh_frame) = hub.accept(&buf[..size], Slot::Direct);
                    // A fresh sealed frame shows the current address of the peer.
                    if fresh_frame
                        && direct_peer.is_some_and(|known| known != from)
                        && hub
                            .peer_addr()
                            .is_some_and(|signed| signed.ip() == from.ip())
                    {
                        direct_peer = Some(from);
                    }
                    if let Some(packet) = packet {
                        hub.deliver(packet);
                    }
                }
            }
            Err(err) if is_idle(&err) => {}
            Err(err) => {
                eprintln!("The direct socket read failed. {err}");
                thread::sleep(Duration::from_millis(20));
            }
        }
        if let Some(peer) = direct_peer {
            for frame in hub.send_control(Slot::Direct, &mut last_hello, &mut last_probe) {
                let _ = socket.send_to(&frame, peer);
            }
            drain_direct(&hub, &socket, peer);
        }
    }
}

fn coordinated_punch(hub: &Hub, socket: &UdpSocket) -> (Option<SocketAddr>, Strategy) {
    let mut started: Option<Instant> = None;
    let mut plan: Option<Strategy> = None;
    while !stopped() {
        let Some(peer) = hub.peer_addr() else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        let chosen = *plan.get_or_insert_with(|| {
            let peer_nat = hub.peer_kind();
            let chosen = strategy(hub.nat_kind, peer_nat);
            println!(
                "The punch plan is {}. The local mapping is {}. The peer mapping is {}.",
                chosen.as_str(),
                hub.nat_kind.as_str(),
                peer_nat.as_str()
            );
            chosen
        });
        if chosen != Strategy::Plain {
            return (None, chosen);
        }
        let start = *started.get_or_insert_with(Instant::now);
        if start.elapsed() >= DIRECT_ATTEMPT_BUDGET {
            println!("The direct attempt ended. The node can use the relay.");
            return (None, chosen);
        }
        let round = Instant::now() + Duration::from_millis(500);
        let deadline = round.min(start + DIRECT_ATTEMPT_BUDGET);
        match exchange_same_ip(socket, &[peer], peer, hub.token, deadline) {
            Ok(outcome) => {
                println!("The hole punch reached {}.", outcome.peer);
                return (Some(outcome.peer), chosen);
            }
            Err(failure) => {
                if !matches!(failure.error, EdgeError::DirectBudget) {
                    eprintln!("The hole punch stopped. {}", failure.error);
                }
            }
        }
    }
    (None, plan.unwrap_or(Strategy::Plain))
}

fn drain_direct(hub: &Hub, socket: &UdpSocket, peer: SocketAddr) {
    while !stopped() {
        let mut frames = hub.pop_many(OverlayPath::Direct, ROUTER_BATCH);
        if frames.is_empty() {
            return;
        }
        // One sendmmsg call on Linux for the batch.
        let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let sent = send_batch(socket, &[], &refs, BatchPeer::One(peer)).unwrap_or(0);
        if sent < frames.len() {
            hub.push_front_many(OverlayPath::Direct, frames.split_off(sent));
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
            let attached = connect_relay(&hub).and_then(|next| {
                let sender = next.sender()?;
                Ok((next, sender))
            });
            match attached {
                Ok((next, sender)) => {
                    println!("The relay transport is {}.", next.transport());
                    hub.set_relay_out(Some(sender));
                    pipe = Some(next);
                }
                Err(err) => {
                    eprintln!("The relay attach failed. The node will retry. {err}");
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
            }
        }
        if hub.relay_broken.load(Ordering::Relaxed) {
            hub.set_relay_out(None);
            pipe = None;
            continue;
        }
        let Some(current) = pipe.as_mut() else {
            continue;
        };
        let mut broken = false;
        // Read all frames that wait on the relay socket.
        loop {
            match current.recv_opaque() {
                Ok(Some(frame)) => {
                    if let (Some(packet), _) = hub.accept(&frame, Slot::Relay) {
                        hub.deliver(packet);
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        if broken {
            eprintln!("The relay path stopped. The node will attach again.");
            hub.set_relay_out(None);
            pipe = None;
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        let frames = hub.send_control(Slot::Relay, &mut last_hello, &mut last_probe);
        if !hub.send_relay(frames) || !hub.flush_relay() {
            hub.set_relay_out(None);
            pipe = None;
            continue;
        }
        // Block until the relay socket has data, or until the next control frame is due.
        // The router sends data frames itself. This loop does not poll for them.
        if current.wait_readable(RELAY_WAIT).is_err() {
            hub.set_relay_out(None);
            pipe = None;
        }
    }
    hub.set_relay_out(None);
}

fn renew_loop(hub: Arc<Hub>, first_der: Vec<u8>, mut renew: RenewFn) {
    let mut der = first_der;
    let mut retry = RENEW_RETRY_MIN;
    while !stopped() {
        let due = match orblx_identity::leaf_validity(&der) {
            Ok((not_before, not_after)) => renew_unix(not_before, not_after),
            Err(err) => {
                eprintln!("The leaf SVID validity did not decode. The node does not renew. {err}");
                return;
            }
        };
        if !sleep_until_unix(due) {
            return;
        }
        match renew() {
            Ok(leaf) => {
                let expiry = match orblx_identity::leaf_not_after(&leaf.cert_der) {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!("The renewed SVID did not decode. The node will retry. {err}");
                        if !sleep_for(retry) {
                            return;
                        }
                        retry = (retry * 2).min(RENEW_RETRY_MAX);
                        continue;
                    }
                };
                lock(&hub.keys).set_leaf(leaf.cert_der.clone(), &leaf.seed);
                hub.svid_expiry.store(expiry, Ordering::Relaxed);
                hub.hello_until.store(
                    hub.now_ms().saturating_add(RENEW_HELLO_MS),
                    Ordering::Relaxed,
                );
                println!("The node renewed the SVID. The new expiry is {expiry}.");
                der = leaf.cert_der;
                retry = RENEW_RETRY_MIN;
            }
            Err(err) => {
                eprintln!("The SVID renewal failed. The node will retry. {err}");
                if !sleep_for(retry) {
                    return;
                }
                retry = (retry * 2).min(RENEW_RETRY_MAX);
            }
        }
    }
}

/// The Unix time to renew a leaf: two thirds of its life.
fn renew_unix(not_before: u64, not_after: u64) -> u64 {
    let life = not_after.saturating_sub(not_before);
    not_before.saturating_add(life.saturating_mul(2) / 3)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// Sleep until the Unix time. Return false when the node stops.
fn sleep_until_unix(due: u64) -> bool {
    while unix_now() < due {
        if stopped() {
            return false;
        }
        thread::sleep(Duration::from_millis(200));
    }
    !stopped()
}

/// Sleep for the time. Return false when the node stops.
fn sleep_for(time: Duration) -> bool {
    let end = Instant::now() + time;
    while Instant::now() < end {
        if stopped() {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    !stopped()
}

fn connect_relay(hub: &Hub) -> Result<RelayPipe, orblx_relay::RelayError> {
    match RelayPipe::connect_udp(hub.relay_udp, hub.relay_id, Duration::from_millis(800)) {
        Ok(pipe) => Ok(pipe),
        Err(_) => RelayPipe::connect_tcp(hub.relay_tcp, hub.relay_id, Duration::from_secs(2)),
    }
}

/// Send the queued frames on the direct socket and on the relay.
///
/// The router seals. This thread does the kernel send, so the two parts run on two cores.
/// One thread sends each path, so the frames keep their order.
fn send_loop(hub: Arc<Hub>) {
    while !stopped() {
        {
            let mut queues = lock(&hub.queues);
            if !queues.wake {
                queues = match hub.queued.wait_timeout(queues, SEND_WAIT) {
                    Ok((guard, _)) => guard,
                    Err(err) => err.into_inner().0,
                };
            }
            queues.wake = false;
        }
        hub.flush_direct();
        hub.flush_relay();
    }
}

fn router_loop(hub: Arc<Hub>, packets: std::sync::mpsc::Receiver<Vec<u8>>) {
    let mut reported: Option<OverlayPath> = None;
    let mut known = false;
    let mut last_status = Instant::now() - Duration::from_secs(1);
    // The time of the last move off direct, for the resend window.
    let mut left_direct: Option<u64> = None;
    while !stopped() {
        match packets.recv_timeout(Duration::from_millis(10)) {
            Ok(packet) => {
                // Take the packets that already wait, up to one batch.
                let mut batch = Vec::with_capacity(ROUTER_BATCH);
                batch.push(packet);
                while batch.len() < ROUTER_BATCH {
                    match packets.try_recv() {
                        Ok(next) => batch.push(next),
                        Err(_) => break,
                    }
                }
                // The send thread sends the frames. The router does not wait for the kernel send.
                hub.enqueue_batch(batch);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
        let now = hub.now_ms();
        let direct_ok = hub.both_ways(Slot::Direct, now);
        let relay_ok = hub.both_ways(Slot::Relay, now);
        let budget_done = lock(&hub.candidate_at)
            .map(|start| start.elapsed() >= DIRECT_ATTEMPT_BUDGET)
            .unwrap_or(false);
        let allowed = relay_allowed(
            hub.saw_direct.load(Ordering::Relaxed),
            direct_ok,
            budget_done,
        );
        let (before, next, plan) = {
            let mut select = lock(&hub.select);
            let before = select.current;
            let next = select_path(&mut select, direct_ok, relay_ok, allowed, now);
            (before, next, select.plan(now))
        };
        if next == Some(OverlayPath::Direct) {
            hub.saw_direct.store(true, Ordering::Relaxed);
            left_direct = None;
        }
        if before == Some(OverlayPath::Direct) && next != Some(OverlayPath::Direct) {
            left_direct = Some(now);
        }
        hub.plan.store(plan_code(plan), Ordering::Relaxed);
        if next == Some(OverlayPath::Relay) {
            if let Some(left) = left_direct.take() {
                // Make before break failed for this move: direct went silent first.
                // Frames from the last stale window may be lost. Send them again on the relay.
                let count = hub.resend_on_relay(left.saturating_sub(RESEND_MS));
                println!("The node sent {count} recent frames again on the relay.");
            }
        }
        hub.flush_hold(plan);
        // The hold queue and the resend can put frames on the queues.
        hub.wake_sender();
        if !known || next != reported {
            if let Some(path) = next {
                println!("The path to {} is {}.", hub.peer_name, path.as_str());
                println!(
                    "session {} path {}",
                    encode_hex(&hub.session),
                    path.as_str()
                );
            }
            if before == Some(OverlayPath::Relay) && next == Some(OverlayPath::Direct) {
                println!("The relay also carries frames during the overlap.");
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
