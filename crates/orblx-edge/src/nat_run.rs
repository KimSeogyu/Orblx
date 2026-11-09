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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_datapath::{
    format_node_status, is_ipv4_packet, open_tun_port, NodeStatus, PacketFilter, StatusPeer,
    TunConfig, TunPort, LINUX_TUN_NAME, NODE_PID_FILE, NODE_STATUS_FILE,
};
use orblx_relay::{
    recv_batch, send_batch, BatchPeer, RecvBatch, RelayPipe, RelaySender, RelaySessionId, UDP_BATCH,
};

use crate::birthday::{
    classify_ports, local_kind, peer_kind, predict_continues, predict_targets, retry_delay,
    strategy_for, MappingKind, PortAlloc, PredictSpray, RateGate, Spray, Strategy, ALLOC_SAMPLES,
    BIRTHDAY_SOCKETS, BIRTHDAY_WINDOW, PREDICT_ATTEMPTS, PREDICT_PACKET_BUDGET, PREDICT_PORT_MAX,
    PROBE_BURST, PROBE_RATE, SOCKET_REFRESH, SPRAY_MAX,
};
use crate::nat_path::{
    relay_allowed, select_path, session_id, session_punch_token, HelloAuth, KeyGate, Opened,
    OverlayPath, PathSelect, SendPlan, KIND_DATA, KIND_PROBE, PROBE_GAP_MS, PROBE_HEARS, RESEND_MS,
    STALE_MS,
};
use crate::portmap::{
    candidate_texts, load_port_map_nonce, probe_port_map, ActiveMap, PortMapChoice, ProbeReport,
    ProbeRequest, PORT_MAP_BUDGET,
};
use crate::punch::{
    admit_punch, decode_punch, encode_punch, exchange_same_ip, PunchDecision, PunchKind, PunchToken,
};
use crate::signed::{encode_hex, verify_signed_candidate, SignedCandidate};
use crate::{
    EdgeError, PathMachine, PathOffer, PathPick, StunClient, DIRECT_ATTEMPT_BUDGET,
    DIRECT_QUIC_PORT, RELAY_FAR_MS,
};

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
/// The longest time that the router blocks on the TUN device.
const ROUTER_WAIT: Duration = Duration::from_millis(10);
/// A packet that comes after this gap with no other packet is on a quiet flow.
///
/// A quiet packet does not go to a second thread. The thread that has it does the kernel call at once.
/// This removes the wake-up time of a sleeping thread from the RTT.
/// A busy flow still uses the second thread, so two cores share the work.
const QUIET_GAP: Duration = Duration::from_millis(1);
/// The most packets that wait for the TUN write thread. More packets are dropped.
const TUN_QUEUE_LIMIT: usize = 4096;
/// The size of one receive slot on the direct socket.
const DIRECT_SLOT: usize = 65_535;
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
    /// A peer relay that already has a working path.
    ///
    /// `None` means the node does not use a peer relay.
    /// The node does not wait for this address before the first coordinator Relay packet.
    pub peer_relay: Option<SocketAddr>,
    /// Replace the default route with this gateway before the TUN device opens.
    pub gateway: Option<Ipv4Addr>,
    /// Ask the gateway for a mapped UDP port. `Off` skips the probe.
    pub port_map: PortMapChoice,
    /// The lifetime to request, in seconds. Zero selects 7200 seconds.
    pub port_map_lifetime: u32,
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
    /// The receiver packet filter (W24).
    ///
    /// `None` keeps the old datapath. The node does not check the packet port.
    pub filter: Option<Arc<PacketFilter>>,
}

/// Run one NAT node until SIGINT or SIGTERM.
pub fn run_nat_node(config: NatConfig) -> Result<(), EdgeError> {
    let started = Instant::now();
    let origin_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    println!("clock_origin unix_ms {origin_ms}");
    install_signals();
    // The status file is from the previous process until this process writes it.
    // Write `down` before the probe so a reader does not treat the old path as live.
    write_status_file(&config.state_dir, &starting_status(&config));
    if let Some(gateway) = config.gateway {
        set_default_route(gateway)?;
    }
    // The probe runs beside STUN and the relay. A silent gateway must not delay the first relay packet.
    let probe_handle = spawn_port_map_probe(&config, started)?;
    let (socket, reflexive, alt) = gather_reflexive(config.stun, config.stun_alt)?;
    println!("The reflexive endpoint is {reflexive}.");
    if let Some(alt) = alt {
        println!("The second reflexive endpoint is {alt}.");
    }
    let stun_kind = local_kind(reflexive, alt);
    println!("The STUN mapping is {}.", stun_kind.as_str());
    // The probe may later replace this with an endpoint-independent map.
    println!("The local NAT mapping is {}.", stun_kind.as_str());
    let mut stun_texts = vec![reflexive.to_string()];
    if let Some(alt) = alt {
        stun_texts.push(alt.to_string());
    }
    let leaf_der = config.hello.cert_der.clone();
    let session = session_id(&config.name, &config.peer_name)?;
    println!("session {}", encode_hex(&session));
    let gate = KeyGate::generate(session, &config.name, &config.peer_name, config.hello)?;
    write_record(&config.state_dir, &config.name, config.overlay)?;
    let _pid = PidGuard::create(&config.state_dir)?;
    let tun = open_tun_port(&TunConfig {
        name: Some(LINUX_TUN_NAME.to_string()),
        address: config.overlay,
        netmask: Ipv4Addr::new(255, 192, 0, 0),
    })
    .map_err(|err| EdgeError::Io(err.to_string()))?;
    let tun_name = tun.name.clone();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", &tun_name, "arp", "off"])
        .status();
    let _ = Command::new("ip")
        .args(["route", "replace", "100.64.0.0/10", "dev", &tun_name])
        .status();

    let hub = Arc::new(Hub {
        filter: config.filter,
        state_dir: config.state_dir,
        name: config.name,
        overlay: config.overlay,
        svid: config.svid,
        svid_expiry: AtomicU64::new(config.svid_expiry),
        hello_until: AtomicU64::new(0),
        direct_out: Mutex::new(None),
        relay_out: Mutex::new(None),
        relay_broken: AtomicBool::new(false),
        relay_data_noted: AtomicBool::new(false),
        peer_out: Mutex::new(None),
        peer_broken: AtomicBool::new(false),
        peer_data_noted: AtomicBool::new(false),
        peer_relay: config.peer_relay,
        coord_rtt_ms: AtomicU64::new(0),
        peer_name: config.peer_name,
        peer_overlay: config.peer_overlay,
        peer_svid: config.peer_svid,
        relay_udp: config.relay_udp,
        relay_tcp: config.relay_tcp,
        netmap_public: config.netmap_public,
        nat_kind: Mutex::new(stun_kind),
        stun: config.stun,
        reflexive: Mutex::new(stun_texts.clone()),
        local_alloc: Mutex::new(PortAlloc::Unknown),
        stun_texts,
        mapped: Mutex::new(None),
        port_map: Mutex::new(None),
        probe_done: AtomicBool::new(probe_handle.is_none()),
        publish_gen: AtomicU64::new(0),
        session,
        token: session_punch_token(&session),
        relay_id: RelaySessionId::from_bytes(session),
        started,
        keys: Mutex::new(gate),
        select: Mutex::new(PathSelect::default()),
        queues: Mutex::new(Queues::default()),
        queued: Condvar::new(),
        peer_endpoints: Mutex::new(Vec::new()),
        candidate_at: Mutex::new(None),
        plan: AtomicU64::new(0),
        direct_rx: AtomicU64::new(0),
        relay_rx: AtomicU64::new(0),
        peer_rx: AtomicU64::new(0),
        direct_heard: AtomicU64::new(0),
        relay_heard: AtomicU64::new(0),
        peer_heard: AtomicU64::new(0),
        saw_direct: AtomicBool::new(false),
        peer_confirmed: AtomicBool::new(false),
        flushing: AtomicBool::new(false),
        tun,
        tun_lane: Mutex::new(TunLane::default()),
        tun_ready: Condvar::new(),
    });
    hub.write_status(None);

    let publish_hub = Arc::clone(&hub);
    let mut publish = config.publish;
    thread::Builder::new()
        .name("orblx-nat-publish".to_string())
        .spawn(move || publish_loop(publish_hub, &mut publish))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    if let Some(handle) = probe_handle {
        let apply_hub = Arc::clone(&hub);
        thread::Builder::new()
            .name("orblx-nat-portmap".to_string())
            .spawn(move || apply_port_map(apply_hub, handle))
            .map_err(|err| EdgeError::Io(err.to_string()))?;
        let renew_hub = Arc::clone(&hub);
        thread::Builder::new()
            .name("orblx-nat-portmap-renew".to_string())
            .spawn(move || renew_port_map(renew_hub))
            .map_err(|err| EdgeError::Io(err.to_string()))?;
    }
    let relay_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-relay".to_string())
        .spawn(move || relay_loop(relay_hub))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    if hub.peer_relay.is_some() {
        println!("The peer relay discovery does not delay the first packet.");
        let peer_hub = Arc::clone(&hub);
        thread::Builder::new()
            .name("orblx-nat-peer-relay".to_string())
            .spawn(move || peer_relay_loop(peer_hub))
            .map_err(|err| EdgeError::Io(err.to_string()))?;
    }
    let send_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-send".to_string())
        .spawn(move || send_loop(send_hub))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let router_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-router".to_string())
        .spawn(move || router_loop(router_hub))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let tun_hub = Arc::clone(&hub);
    thread::Builder::new()
        .name("orblx-nat-tun-write".to_string())
        .spawn(move || tun_write_loop(tun_hub))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    if let Some(renew) = config.renew {
        let renew_hub = Arc::clone(&hub);
        thread::Builder::new()
            .name("orblx-nat-renew".to_string())
            .spawn(move || renew_loop(renew_hub, leaf_der, renew))
            .map_err(|err| EdgeError::Io(err.to_string()))?;
    }
    if stun_kind == MappingKind::Hard {
        // The relay threads are already up. These samples must not hold the first packet.
        let sample_hub = Arc::clone(&hub);
        let stun = config.stun;
        thread::Builder::new()
            .name("orblx-nat-sample".to_string())
            .spawn(move || sample_allocation(&sample_hub, stun))
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
    // Drop deletes the map. The router removes the port.
    drop(lock(&hub.port_map).take());
    Ok(())
}

fn since_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

/// Start the gateway probe on a side thread.
///
/// `None` means the probe is off. The relay path does not wait for this thread.
fn spawn_port_map_probe(
    config: &NatConfig,
    started: Instant,
) -> Result<Option<thread::JoinHandle<ProbeReport>>, EdgeError> {
    if matches!(config.port_map, PortMapChoice::Off) {
        println!("The port map is off.");
        println!("The port map probe took 0 ms.");
        println!("The port map probe did not start.");
        return Ok(None);
    }
    let nonce = load_port_map_nonce(&config.state_dir)?;
    let request = ProbeRequest {
        choice: config.port_map,
        gateway: config.gateway,
        internal_port: DIRECT_QUIC_PORT,
        lifetime_secs: config.port_map_lifetime,
        budget: PORT_MAP_BUDGET,
        nonce: Some(nonce),
    };
    thread::Builder::new()
        .name("orblx-nat-portmap-probe".to_string())
        .spawn(move || {
            println!("The port map probe started at {} ms.", since_ms(started));
            println!(
                "The port map probe budget is {} ms.",
                PORT_MAP_BUDGET.as_millis()
            );
            let report = probe_port_map(request);
            println!("The port map probe took {} ms.", report.elapsed.as_millis());
            if report.mapping.is_none() {
                println!("The port map probe ended. No router answered.");
            }
            report
        })
        .map_err(|err| EdgeError::Io(err.to_string()))
        .map(Some)
}

fn apply_port_map(hub: Arc<Hub>, handle: thread::JoinHandle<ProbeReport>) {
    let Ok(report) = handle.join() else {
        hub.probe_done.store(true, Ordering::Relaxed);
        return;
    };
    let Some(mapping) = report.mapping else {
        hub.probe_done.store(true, Ordering::Relaxed);
        return;
    };
    let external = mapping.external();
    let protocol = mapping.protocol().as_str();
    let lifetime = mapping.lifetime_secs();
    *lock(&hub.mapped) = Some(external);
    *lock(&hub.nat_kind) = MappingKind::Easy;
    *lock(&hub.port_map) = Some(mapping);
    hub.publish_gen.fetch_add(1, Ordering::Relaxed);
    hub.probe_done.store(true, Ordering::Relaxed);
    println!("The port map was granted at {} ms.", hub.now_ms());
    println!("The port map is {protocol} {external} lifetime {lifetime}.");
    println!("The local NAT mapping is endpoint-independent.");
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
    /// The receiver packet filter. `None` keeps the old datapath.
    filter: Option<Arc<PacketFilter>>,
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
    /// True after the first data frame on the relay.
    relay_data_noted: AtomicBool,
    /// The send handle of the peer relay attachment.
    peer_out: Mutex<Option<RelaySender>>,
    /// A send on the peer relay handle failed. The peer relay loop attaches again.
    peer_broken: AtomicBool,
    /// True after the first data frame on the peer relay.
    peer_data_noted: AtomicBool,
    /// The peer relay address. `None` means this node does not use a peer relay.
    peer_relay: Option<SocketAddr>,
    /// The coordinator Relay attach round-trip, in ms. Zero means no sample.
    coord_rtt_ms: AtomicU64,
    peer_name: String,
    peer_overlay: Ipv4Addr,
    peer_svid: String,
    relay_udp: SocketAddr,
    relay_tcp: SocketAddr,
    netmap_public: [u8; 32],
    /// The punch kind. A granted map replaces the STUN kind.
    nat_kind: Mutex<MappingKind>,
    /// The STUN server used for allocation samples.
    stun: SocketAddr,
    /// Reflexive endpoints, in sample order. A mapped port replaces this list.
    reflexive: Mutex<Vec<String>>,
    /// The local port allocation class.
    local_alloc: Mutex<PortAlloc>,
    /// The STUN endpoints. A mapped port replaces them in the published list.
    stun_texts: Vec<String>,
    /// The mapped external socket, when the router granted one.
    mapped: Mutex<Option<SocketAddr>>,
    /// The live map. Drop removes it from the router.
    port_map: Mutex<Option<ActiveMap>>,
    /// True when the probe thread has finished. `Off` starts true.
    probe_done: AtomicBool,
    /// Bumps when the published endpoints should be sent at once.
    publish_gen: AtomicU64,
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
    peer_rx: AtomicU64,
    direct_heard: AtomicU64,
    relay_heard: AtomicU64,
    peer_heard: AtomicU64,
    saw_direct: AtomicBool,
    peer_confirmed: AtomicBool,
    /// True while one thread sends the queued frames.
    ///
    /// The router and the send thread both send. The flag lets one of them send at a time,
    /// so the frames of one path keep their order.
    flushing: AtomicBool,
    /// The TUN device. The router reads it. The receive threads and the TUN write thread write it.
    tun: TunPort,
    /// Packets for the TUN write thread.
    tun_lane: Mutex<TunLane>,
    /// Wakes the TUN write thread. It goes with `tun_lane`.
    tun_ready: Condvar,
}

/// Opened packets that wait for the TUN write.
#[derive(Default)]
struct TunLane {
    queue: VecDeque<Vec<u8>>,
    /// True while one thread writes to the TUN device.
    busy: bool,
    /// True while the TUN write thread waits on `tun_ready`.
    waiting: bool,
    /// The time of the last delivered packet.
    last: Option<Instant>,
}

/// Sealed frames for each path, and plain packets that wait for a path.
#[derive(Default)]
struct Queues {
    direct: VecDeque<Vec<u8>>,
    relay: VecDeque<Vec<u8>>,
    peer: VecDeque<Vec<u8>>,
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
    Peer,
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

    fn local_alloc(&self) -> PortAlloc {
        *lock(&self.local_alloc)
    }

    fn kind(&self) -> MappingKind {
        *lock(&self.nat_kind)
    }

    fn peer_alloc(&self) -> PortAlloc {
        classify_ports(&self.peer_ports())
    }

    fn mark_rx(&self, slot: Slot) {
        let now = self.now_ms().max(1);
        let first = match slot {
            Slot::Direct => self.direct_rx.swap(now, Ordering::Relaxed) == 0,
            Slot::Relay => self.relay_rx.swap(now, Ordering::Relaxed) == 0,
            Slot::Peer => self.peer_rx.swap(now, Ordering::Relaxed) == 0,
        };
        if first {
            let name = match slot {
                Slot::Direct => "direct",
                Slot::Relay => "relay",
                Slot::Peer => "peer-relay",
            };
            println!("The first {name} packet arrived at {now} ms.");
        }
    }

    fn mark_heard(&self, slot: Slot, hears: bool) {
        let value = if hears { self.now_ms().max(1) } else { 0 };
        match slot {
            Slot::Direct => self.direct_heard.store(value, Ordering::Relaxed),
            Slot::Relay => self.relay_heard.store(value, Ordering::Relaxed),
            Slot::Peer => self.peer_heard.store(value, Ordering::Relaxed),
        }
    }

    /// Return true when a frame arrived on this path in the stale time.
    fn fresh(&self, slot: Slot, now: u64) -> bool {
        let rx = match slot {
            Slot::Direct => self.direct_rx.load(Ordering::Relaxed),
            Slot::Relay => self.relay_rx.load(Ordering::Relaxed),
            Slot::Peer => self.peer_rx.load(Ordering::Relaxed),
        };
        recent_ms(rx, now)
    }

    /// Return true when probes went both ways on this path in the stale time.
    fn both_ways(&self, slot: Slot, now: u64) -> bool {
        let heard = match slot {
            Slot::Direct => self.direct_heard.load(Ordering::Relaxed),
            Slot::Relay => self.relay_heard.load(Ordering::Relaxed),
            Slot::Peer => self.peer_heard.load(Ordering::Relaxed),
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
                let allowed = self
                    .filter
                    .as_ref()
                    .is_none_or(|filter| filter.allow_inbound(&self.peer_svid, &packet));
                if is_ipv4_packet(&packet) && allowed {
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
    /// When `wake` is true, the send thread sends the frames.
    /// When `wake` is false, the caller sends them with [`Hub::send_now`].
    fn enqueue_batch(&self, packets: Vec<Vec<u8>>, wake: bool) {
        let plan = self.current_plan();
        let packets = packets.into_iter().filter(|packet| {
            if !is_ipv4_packet(packet) {
                return false;
            }
            if let Some(filter) = &self.filter {
                filter.note_outbound(packet);
            }
            true
        });
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
        if !wake {
            return;
        }
        queues.wake = true;
        drop(queues);
        self.queued.notify_one();
    }

    /// Send the queued frames on this thread.
    ///
    /// When the send thread sends at this time, the function wakes it again instead.
    fn send_now(&self) {
        if self
            .flushing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.flush_direct();
            self.flush_relay();
            self.flush_peer();
            self.flushing.store(false, Ordering::Release);
        } else {
            self.wake_sender();
        }
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
            push_bound(&mut queues.relay, frame.clone());
        }
        if plan.uses_peer() {
            push_bound(&mut queues.peer, frame);
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
            OverlayPath::PeerRelay => &mut queues.peer,
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
            OverlayPath::PeerRelay => &mut queues.peer,
        };
        for frame in frames.into_iter().rev() {
            queue.push_front(frame);
        }
    }

    /// Seal and queue the held packets. Return true when a frame was queued.
    fn flush_hold(&self, plan: SendPlan) -> bool {
        if plan == SendPlan::Hold {
            return false;
        }
        let pending: Vec<Vec<u8>> = {
            let mut queues = lock(&self.queues);
            if queues.hold.is_empty() {
                return false;
            }
            queues.hold.drain(..).collect()
        };
        let mut queued = false;
        for packet in pending {
            match self.seal(KIND_DATA, &packet) {
                Some(frame) => {
                    self.route(frame, plan);
                    queued = true;
                }
                None => push_bound(&mut lock(&self.queues).hold, packet),
            }
        }
        queued
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
            if sent > 0 && !self.relay_data_noted.swap(true, Ordering::Relaxed) {
                println!("first_packet relay ms {}", self.now_ms());
            }
            if result.is_err() {
                self.push_front_many(OverlayPath::Relay, frames.split_off(sent));
                *out = None;
                self.relay_broken.store(true, Ordering::Relaxed);
                return false;
            }
        }
    }

    /// Send all queued peer-relay frames now. Return false when a send fails.
    fn flush_peer(&self) -> bool {
        let mut out = lock(&self.peer_out);
        let Some(sender) = out.as_mut() else {
            return true;
        };
        loop {
            let mut frames = self.pop_many(OverlayPath::PeerRelay, ROUTER_BATCH);
            if frames.is_empty() {
                return true;
            }
            let (sent, result) = sender.send_many(&frames);
            if sent > 0 && !self.peer_data_noted.swap(true, Ordering::Relaxed) {
                println!("first_packet peer-relay ms {}", self.now_ms());
            }
            if result.is_err() {
                self.push_front_many(OverlayPath::PeerRelay, frames.split_off(sent));
                *out = None;
                self.peer_broken.store(true, Ordering::Relaxed);
                return false;
            }
        }
    }

    /// Send control frames on the peer relay. Return false when a send fails.
    fn send_peer(&self, frames: Vec<Vec<u8>>) -> bool {
        let mut out = lock(&self.peer_out);
        let Some(sender) = out.as_mut() else {
            return frames.is_empty();
        };
        for frame in frames {
            if sender.send_opaque(&frame).is_err() {
                *out = None;
                self.peer_broken.store(true, Ordering::Relaxed);
                return false;
            }
        }
        true
    }

    fn set_peer_out(&self, sender: Option<RelaySender>) {
        *lock(&self.peer_out) = sender;
        self.peer_broken.store(false, Ordering::Relaxed);
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

    /// Write opened packets to the TUN device.
    ///
    /// A quiet flow writes at once on this thread. A busy flow gives the packets to the TUN write thread.
    /// One thread writes at a time and the queue goes first, so the packets keep their order.
    fn deliver(&self, packets: Vec<Vec<u8>>) {
        if packets.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut lane = lock(&self.tun_lane);
        let quiet = lane
            .last
            .is_none_or(|last| now.duration_since(last) >= QUIET_GAP);
        lane.last = Some(now);
        if quiet && !lane.busy && lane.queue.is_empty() {
            lane.busy = true;
            drop(lane);
            for packet in &packets {
                let _ = self.tun.send(packet);
            }
            let mut lane = lock(&self.tun_lane);
            lane.busy = false;
            let wake = lane.waiting && !lane.queue.is_empty();
            drop(lane);
            if wake {
                self.tun_ready.notify_one();
            }
            return;
        }
        for packet in packets {
            if lane.queue.len() < TUN_QUEUE_LIMIT {
                lane.queue.push_back(packet);
            }
        }
        let wake = lane.waiting;
        drop(lane);
        if wake {
            self.tun_ready.notify_one();
        }
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
            reauth: None,
            peers: vec![StatusPeer {
                name: self.peer_name.clone(),
                overlay_ip: self.peer_overlay.to_string(),
                path: path_text.to_string(),
                svid: self.peer_svid.clone(),
                // The value comes from the peer SVID in the signed hello.
                svid_expiry: peer_expiry,
            }],
        };
        write_status_file(&self.state_dir, &status);
    }
}

fn starting_status(config: &NatConfig) -> NodeStatus {
    NodeStatus {
        state: "starting".to_string(),
        name: config.name.clone(),
        overlay_ip: config.overlay.to_string(),
        svid: config.svid.clone(),
        svid_expiry: config.svid_expiry,
        exit_node: None,
        reauth: None,
        peers: vec![StatusPeer {
            name: config.peer_name.clone(),
            overlay_ip: config.peer_overlay.to_string(),
            path: "down".to_string(),
            svid: config.peer_svid.clone(),
            svid_expiry: None,
        }],
    }
}

fn write_status_file(dir: &Path, status: &NodeStatus) {
    let text = format_node_status(status);
    let path = dir.join(NODE_STATUS_FILE);
    let tmp = dir.join("status.txt.tmp");
    if fs::write(&tmp, text.as_bytes()).is_ok() {
        let _ = fs::rename(&tmp, &path);
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
        4 => SendPlan::Peer,
        _ => SendPlan::Hold,
    }
}

fn plan_code(plan: SendPlan) -> u64 {
    match plan {
        SendPlan::Hold => 0,
        SendPlan::Direct => 1,
        SendPlan::Relay => 2,
        SendPlan::Both => 3,
        SendPlan::Peer => 4,
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
    publish: &mut dyn FnMut(Vec<String>) -> Result<Vec<SignedCandidate>, String>,
) {
    let mut last = Vec::new();
    while !stopped() {
        let gen = hub.publish_gen.load(Ordering::Relaxed);
        let mapped = *lock(&hub.mapped);
        // A granted map replaces the STUN list. Otherwise publish the sample list.
        let texts = if mapped.is_some() {
            candidate_texts(&hub.stun_texts, mapped)
        } else {
            lock(&hub.reflexive).clone()
        };
        match publish(texts.clone()) {
            Ok(list) => {
                store_peer(&hub, &list);
                if texts != last {
                    println!("The endpoints were published at {} ms.", hub.now_ms());
                    last = texts;
                }
            }
            Err(err) => {
                eprintln!("The candidate update failed. The node will retry. {err}");
            }
        }
        for _ in 0..10 {
            if stopped() {
                return;
            }
            if hub.publish_gen.load(Ordering::Relaxed) != gen {
                break;
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
    let (mut direct_peer, mut plan) = coordinated_punch(&hub, &socket);
    let _ = socket.set_read_timeout(Some(DIRECT_READ));
    let mut spray: Option<Spray> = None;
    let mut fleet: Option<Fleet> = None;
    let mut predict: Option<PredictCycle> = None;
    arm_punch(&hub, plan, &mut spray, &mut fleet);
    if plan == Strategy::Predict {
        predict = Some(PredictCycle::start(&hub, Instant::now()));
    }
    let check = encode_punch(PunchKind::Check, hub.token);
    let ack = encode_punch(PunchKind::Ack, hub.token);
    let mut punch_gap = punch_gap_for(plan);
    let mut last_hello = Instant::now() - HELLO_GAP;
    let mut last_probe = Instant::now() - PROBE_GAP;
    let mut last_punch = Instant::now() - PUNCH_GAP;
    // One recvmmsg call takes the datagrams that wait, up to one batch.
    let mut batch = RecvBatch::new(UDP_BATCH, DIRECT_SLOT);
    let mut opened: Vec<Vec<u8>> = Vec::with_capacity(UDP_BATCH);
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
        if direct_peer.is_none() && current_strategy(&hub) != plan {
            plan = log_plan(&hub);
            punch_gap = punch_gap_for(plan);
            spray = None;
            fleet = None;
            arm_punch(&hub, plan, &mut spray, &mut fleet);
            predict = if plan == Strategy::Predict {
                Some(PredictCycle::start(&hub, now))
            } else {
                None
            };
        }
        let fresh = hub.fresh(Slot::Direct, hub.now_ms());
        if (direct_peer.is_none() || !fresh) && last_punch.elapsed() >= punch_gap {
            let signed = hub.peer_addr();
            // A random hard pair does not send punch probes.
            if plan != Strategy::RelayOnly {
                if let Some(peer) = signed {
                    let _ = socket.send_to(&check, peer);
                }
            }
            // The last working address can differ from the signed address.
            // A symmetric NAT maps a new port for this flow.
            if let Some(known) = direct_peer.filter(|known| Some(*known) != signed) {
                let _ = socket.send_to(&check, known);
            }
            last_punch = now;
        }
        if direct_peer.is_none() {
            if let Some(cycle) = predict.as_mut() {
                cycle.drive(&hub, &socket, &check, now);
            }
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
        match recv_batch(&socket, &mut batch) {
            Ok(_) => {
                for index in 0..batch.len() {
                    let Some((bytes, Some(from))) = batch.get(index) else {
                        continue;
                    };
                    match admit_punch(
                        bytes,
                        hub.token,
                        from.ip(),
                        hub.peer_addr().map(|addr| addr.ip()),
                    ) {
                        Some(PunchDecision::DropToken) => {
                            println!("punch_drop {from} token");
                        }
                        Some(PunchDecision::DropNetmap) => {
                            println!("punch_drop {from} netmap");
                        }
                        Some(PunchDecision::Accept(kind)) => {
                            if direct_peer.is_none() {
                                if let Some(active) = spray.take() {
                                    println!(
                                        "The port spray reached {from} after {} probes.",
                                        active.sent()
                                    );
                                }
                                if let Some(active) = predict.take() {
                                    let sent = active.spray.sent();
                                    println!(
                                        "The predict spray reached {from} after {sent} probes."
                                    );
                                    println!("predict_probes {sent}");
                                }
                                println!("The hole punch reached {from}.");
                            }
                            direct_peer = Some(from);
                            if kind == PunchKind::Check {
                                let _ = socket.send_to(&ack, from);
                            }
                        }
                        None => {
                            let (packet, fresh_frame) = hub.accept(bytes, Slot::Direct);
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
                                opened.push(packet);
                            }
                        }
                    }
                }
                hub.deliver(std::mem::take(&mut opened));
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

fn endpoint_ports(texts: &[String]) -> Vec<u16> {
    texts
        .iter()
        .filter_map(|text| text.parse::<SocketAddr>().ok())
        .map(|addr| addr.port())
        .collect()
}

fn sample_allocation(hub: &Hub, stun: SocketAddr) {
    let samples = alloc_samples(stun, ALLOC_SAMPLES);
    if samples.is_empty() {
        return;
    }
    let mut list = lock(&hub.reflexive);
    for addr in &samples {
        println!("The allocation sample is {addr}.");
        if list.len() < 8 {
            list.push(addr.to_string());
        }
    }
    let ports = endpoint_ports(&list);
    drop(list);
    let alloc = classify_ports(&ports);
    *lock(&hub.local_alloc) = alloc;
    println!("The local port allocation is {alloc}.");
    hub.publish_gen.fetch_add(1, Ordering::Relaxed);
}

fn alloc_samples(server: SocketAddr, count: usize) -> Vec<SocketAddr> {
    let mut found = Vec::new();
    for _ in 0..count {
        if stopped() {
            break;
        }
        let Ok(client) = StunClient::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))) else {
            break;
        };
        if let Ok(addr) = client.gather(server, Duration::from_millis(800)) {
            found.push(addr);
        }
    }
    found
}

fn current_strategy(hub: &Hub) -> Strategy {
    strategy_for(
        hub.kind(),
        hub.peer_kind(),
        hub.local_alloc(),
        hub.peer_alloc(),
    )
}

fn log_plan(hub: &Hub) -> Strategy {
    let peer_nat = hub.peer_kind();
    let local_nat = hub.kind();
    let local_alloc = hub.local_alloc();
    let peer_alloc = hub.peer_alloc();
    let chosen = strategy_for(local_nat, peer_nat, local_alloc, peer_alloc);
    println!(
        "The punch plan is {}. The local mapping is {}. The peer mapping is {}.",
        chosen.as_str(),
        local_nat.as_str(),
        peer_nat.as_str()
    );
    println!("The punch plan time is {} ms.", hub.now_ms());
    if local_nat == MappingKind::Hard || peer_nat == MappingKind::Hard {
        println!("The local port allocation is {local_alloc}.");
        println!("The peer port allocation is {peer_alloc}.");
    }
    chosen
}

/// One predict attempt, then a bounded wait, then another attempt.
///
/// The cycle stops after [`PREDICT_ATTEMPTS`]. It does not start another spray.
struct PredictCycle {
    spray: PredictSpray,
    attempt: u32,
    resume_at: Option<Instant>,
    stopped: bool,
}

impl PredictCycle {
    fn start(hub: &Hub, now: Instant) -> Self {
        println!(
            "predict_budget attempts {PREDICT_ATTEMPTS} packets_per_attempt {SPRAY_MAX} port_cap {PREDICT_PORT_MAX} rate {PROBE_RATE} packet_budget {PREDICT_PACKET_BUDGET}"
        );
        println!("The predict attempt 1 starts.");
        Self {
            spray: spray_for(hub, now),
            attempt: 1,
            resume_at: None,
            stopped: false,
        }
    }

    fn drive(&mut self, hub: &Hub, socket: &UdpSocket, check: &[u8], now: Instant) {
        if self.stopped {
            return;
        }
        if let Some(until) = self.resume_at {
            if now < until {
                return;
            }
            if !predict_continues(self.attempt) {
                self.stopped = true;
                println!(
                    "The predict budget is spent after {} attempts.",
                    self.attempt
                );
                return;
            }
            self.spray = spray_for(hub, now);
            self.resume_at = None;
            self.attempt = self.attempt.saturating_add(1);
            println!("The predict attempt {} starts.", self.attempt);
        }
        if let Some(peer) = hub.peer_addr() {
            self.spray
                .set_targets(peer.ip(), predict_targets(hub.peer_alloc()));
        }
        for target in self.spray.due(now) {
            let _ = socket.send_to(check, target);
        }
        if self.spray.done(now) {
            let sent = self.spray.sent();
            println!("The predict attempt ended after {sent} probes. The node uses the relay.");
            println!("predict_probes {sent}");
            if !predict_continues(self.attempt) {
                self.stopped = true;
                println!(
                    "The predict budget is spent after {} attempts.",
                    self.attempt
                );
                return;
            }
            let delay = retry_delay(self.attempt);
            println!(
                "The predict attempt will retry after {} seconds.",
                delay.as_secs()
            );
            self.resume_at = Some(now + delay);
            refresh_alloc_samples(hub);
        }
    }
}

fn spray_for(hub: &Hub, now: Instant) -> PredictSpray {
    match hub.peer_addr() {
        Some(peer) => PredictSpray::new(peer.ip(), predict_targets(hub.peer_alloc()), now),
        None => PredictSpray::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Vec::new(), now),
    }
}

fn refresh_alloc_samples(hub: &Hub) {
    let samples = alloc_samples(hub.stun, ALLOC_SAMPLES);
    if samples.len() < 4 {
        return;
    }
    let ports: Vec<u16> = samples.iter().map(|addr| addr.port()).collect();
    let alloc = classify_ports(&ports);
    *lock(&hub.local_alloc) = alloc;
    println!("The local port allocation is {alloc}.");
    let mut list = lock(&hub.reflexive);
    let keep = 2.min(list.len());
    list.truncate(keep);
    for addr in samples {
        if list.len() >= 8 {
            break;
        }
        list.push(addr.to_string());
    }
    hub.publish_gen.fetch_add(1, Ordering::Relaxed);
}

fn punch_gap_for(plan: Strategy) -> Duration {
    if plan == Strategy::RelayOnly {
        RELAY_ONLY_PUNCH_GAP
    } else {
        PUNCH_GAP
    }
}

fn arm_punch(hub: &Hub, plan: Strategy, spray: &mut Option<Spray>, fleet: &mut Option<Fleet>) {
    if spray.is_some() || fleet.is_some() {
        return;
    }
    let now = Instant::now();
    match plan {
        Strategy::Spray => {
            if let Some(peer) = hub.peer_addr() {
                *spray = Some(Spray::new(peer.ip(), &hub.peer_ports(), now));
            }
        }
        Strategy::Sockets => match Fleet::open(BIRTHDAY_SOCKETS, now) {
            Ok(opened) => *fleet = Some(opened),
            Err(err) => eprintln!("The birthday sockets did not open. {err}"),
        },
        Strategy::Plain | Strategy::RelayOnly | Strategy::Predict => {}
    }
}

fn coordinated_punch(hub: &Hub, socket: &UdpSocket) -> (Option<SocketAddr>, Strategy) {
    let mut started: Option<Instant> = None;
    let mut plan: Option<Strategy> = None;
    let mut hard_wait: Option<Instant> = None;
    while !stopped() {
        let Some(peer) = hub.peer_addr() else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        // One signed endpoint is not enough to class a hard peer.
        // Wait briefly so the allocation samples can arrive before the plan is fixed.
        if hub.kind() == MappingKind::Hard && hub.peer_kind() == MappingKind::Unknown {
            let waited = hard_wait.get_or_insert_with(Instant::now);
            if waited.elapsed() < Duration::from_secs(2) {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        }
        let chosen = *plan.get_or_insert_with(|| log_plan(hub));
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
        let mut opened = Vec::new();
        // Read all frames that wait on the relay socket.
        loop {
            match current.recv_opaque() {
                Ok(Some(frame)) => {
                    if let (Some(packet), _) = hub.accept(&frame, Slot::Relay) {
                        opened.push(packet);
                    }
                    if opened.len() >= UDP_BATCH {
                        hub.deliver(std::mem::take(&mut opened));
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        hub.deliver(opened);
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

fn peer_relay_loop(hub: Arc<Hub>) {
    let Some(addr) = hub.peer_relay else {
        return;
    };
    println!("The peer relay address is {addr}.");
    let mut pipe: Option<RelayPipe> = None;
    let mut last_hello = Instant::now() - HELLO_GAP;
    let mut last_probe = Instant::now() - PROBE_GAP;
    while !stopped() {
        if pipe.is_none() {
            let attached = connect_peer(&hub, addr).and_then(|next| {
                let sender = next.sender()?;
                Ok((next, sender))
            });
            match attached {
                Ok((next, sender)) => {
                    println!("The peer relay transport is {}.", next.transport());
                    hub.set_peer_out(Some(sender));
                    pipe = Some(next);
                }
                Err(err) => {
                    eprintln!("The peer relay attach failed. The node will retry. {err}");
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
            }
        }
        if hub.peer_broken.load(Ordering::Relaxed) {
            hub.set_peer_out(None);
            pipe = None;
            continue;
        }
        let Some(current) = pipe.as_mut() else {
            continue;
        };
        let mut broken = false;
        let mut opened = Vec::new();
        loop {
            match current.recv_opaque() {
                Ok(Some(frame)) => {
                    if let (Some(packet), _) = hub.accept(&frame, Slot::Peer) {
                        opened.push(packet);
                    }
                    if opened.len() >= UDP_BATCH {
                        hub.deliver(std::mem::take(&mut opened));
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        hub.deliver(opened);
        if broken {
            eprintln!("The peer relay path stopped. The node will attach again.");
            hub.set_peer_out(None);
            pipe = None;
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        let frames = hub.send_control(Slot::Peer, &mut last_hello, &mut last_probe);
        if !hub.send_peer(frames) || !hub.flush_peer() {
            hub.set_peer_out(None);
            pipe = None;
            continue;
        }
        if current.wait_readable(RELAY_WAIT).is_err() {
            hub.set_peer_out(None);
            pipe = None;
        }
    }
    hub.set_peer_out(None);
}

fn renew_port_map(hub: Arc<Hub>) {
    loop {
        let wait = {
            let guard = lock(&hub.port_map);
            match guard.as_ref() {
                Some(mapping) => Some(Duration::from_secs(u64::from(
                    mapping.lifetime_secs().max(2) / 2,
                ))),
                None if hub.probe_done.load(Ordering::Relaxed) => return,
                None => None,
            }
        };
        let Some(wait) = wait else {
            if !sleep_for(Duration::from_millis(50)) {
                return;
            }
            continue;
        };
        if !sleep_for(wait) {
            return;
        }
        let renewed = {
            let mut guard = lock(&hub.port_map);
            let Some(mapping) = guard.as_mut() else {
                return;
            };
            let before = mapping.external();
            match mapping.renew() {
                Ok(()) => {
                    let external = mapping.external();
                    let lifetime = mapping.lifetime_secs();
                    Some((before, external, lifetime))
                }
                Err(err) => {
                    eprintln!("The port map renew failed. The node will try again. {err}");
                    None
                }
            }
        };
        let Some((before, external, lifetime)) = renewed else {
            if !sleep_for(Duration::from_secs(1)) {
                return;
            }
            continue;
        };
        println!(
            "The port map was renewed. The endpoint is {external}. The lifetime is {lifetime} s."
        );
        if external != before {
            *lock(&hub.mapped) = Some(external);
        }
    }
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
    let started = Instant::now();
    let pipe = match RelayPipe::connect_udp(hub.relay_udp, hub.relay_id, Duration::from_millis(800))
    {
        Ok(pipe) => pipe,
        Err(_) => RelayPipe::connect_tcp(hub.relay_tcp, hub.relay_id, Duration::from_secs(2))?,
    };
    let rtt = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let rtt = rtt.max(1);
    hub.coord_rtt_ms.store(rtt, Ordering::Relaxed);
    println!("The coordinator relay rtt is {rtt} ms.");
    if rtt >= RELAY_FAR_MS {
        println!("The coordinator relay is far.");
    } else {
        println!("The coordinator relay is near.");
    }
    Ok(pipe)
}

fn connect_peer(hub: &Hub, addr: SocketAddr) -> Result<RelayPipe, orblx_relay::RelayError> {
    match RelayPipe::connect_udp(addr, hub.relay_id, Duration::from_millis(800)) {
        Ok(pipe) => Ok(pipe),
        Err(_) => RelayPipe::connect_tcp(addr, hub.relay_id, Duration::from_secs(2)),
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
        // When the router sends at this time, it sends all queued frames.
        if hub
            .flushing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            hub.flush_direct();
            hub.flush_relay();
            hub.flush_peer();
            hub.flushing.store(false, Ordering::Release);
        }
    }
}

/// Write the queued packets of a busy flow to the TUN device.
fn tun_write_loop(hub: Arc<Hub>) {
    while !stopped() {
        let packets: Vec<Vec<u8>> = {
            let mut lane = lock(&hub.tun_lane);
            while (lane.queue.is_empty() || lane.busy) && !stopped() {
                lane.waiting = true;
                lane = match hub.tun_ready.wait_timeout(lane, SEND_WAIT) {
                    Ok((guard, _)) => guard,
                    Err(err) => err.into_inner().0,
                };
                lane.waiting = false;
            }
            if lane.queue.is_empty() || lane.busy {
                continue;
            }
            lane.busy = true;
            lane.queue.drain(..).collect()
        };
        for packet in &packets {
            let _ = hub.tun.send(packet);
        }
        lock(&hub.tun_lane).busy = false;
    }
}

fn router_loop(hub: Arc<Hub>) {
    let mut buf = vec![0u8; 65_535];
    let mut last_packet: Option<Instant> = None;
    let mut reported: Option<OverlayPath> = None;
    let mut known = false;
    let mut last_status = Instant::now() - Duration::from_secs(1);
    // The time of the last move off direct, for the resend window.
    let mut left_direct: Option<u64> = None;
    while !stopped() {
        match hub.tun.recv_timeout(&mut buf, ROUTER_WAIT) {
            Ok(Some(size)) => {
                let at = Instant::now();
                let quiet = last_packet.is_none_or(|last| at.duration_since(last) >= QUIET_GAP);
                last_packet = Some(at);
                // Take the packets that already wait, up to one batch.
                let mut batch = Vec::with_capacity(ROUTER_BATCH);
                batch.push(buf[..size].to_vec());
                while batch.len() < ROUTER_BATCH {
                    match hub.tun.recv_timeout(&mut buf, Duration::ZERO) {
                        Ok(Some(size)) => batch.push(buf[..size].to_vec()),
                        _ => break,
                    }
                }
                // A busy flow: the send thread sends the frames, and the router seals the next batch.
                // A quiet flow: the router sends at once, with no thread wake-up.
                hub.enqueue_batch(batch, !quiet);
                if quiet {
                    hub.send_now();
                }
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("The TUN device stopped. {err}");
                return;
            }
        }
        let now = hub.now_ms();
        let direct_ok = hub.both_ways(Slot::Direct, now);
        let relay_ok = hub.both_ways(Slot::Relay, now);
        // A hard pair starts on the relay at once. The predict spray must not hold the first packet.
        let hard_pair = hub.kind() == MappingKind::Hard && hub.peer_kind() == MappingKind::Hard;
        let budget_done = hard_pair
            || lock(&hub.candidate_at)
                .map(|start| start.elapsed() >= DIRECT_ATTEMPT_BUDGET)
                .unwrap_or(false);
        let allowed = relay_allowed(
            hub.saw_direct.load(Ordering::Relaxed),
            direct_ok,
            budget_done,
        );
        let peer_ok = hub.both_ways(Slot::Peer, now);
        let rtt_ms = hub.coord_rtt_ms.load(Ordering::Relaxed);
        let offer = PathOffer {
            direct_up: direct_ok,
            direct_failed: !direct_ok && allowed,
            coordinator_up: relay_ok,
            coordinator_rtt_ms: if rtt_ms == 0 { None } else { Some(rtt_ms) },
            peer_relay_up: peer_ok,
        };
        let pick = PathMachine::pick_path(offer);
        let (before, next, plan) = {
            let mut select = lock(&hub.select);
            let before = select.current;
            let base = select_path(&mut select, direct_ok, relay_ok, allowed, now);
            let base_plan = select.plan(now);
            let (next, plan) = apply_pick(base, base_plan, pick);
            select.current = next;
            (before, next, plan)
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
                if count > 0 {
                    hub.wake_sender();
                }
            }
        }
        // The hold queue can put frames on the queues.
        if hub.flush_hold(plan) {
            hub.wake_sender();
        }
        if !known || next != reported {
            if next == Some(OverlayPath::PeerRelay) {
                println!("The path pick is peer-relay.");
                if offer.coordinator_up {
                    println!("The coordinator relay is far.");
                } else {
                    println!("The coordinator relay is down.");
                }
                println!("The direct path failed.");
            }
            if let Some(path) = next {
                println!("The path to {} is {}.", hub.peer_name, path.as_str());
                println!("path_up {} ms {now}", path.as_str());
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

/// Keep a live direct path.
/// Replace a relay path with the peer relay when [`PathMachine::pick_path`] says so.
/// A pick of [`PathPick::None`] does not wait.
fn apply_pick(
    base: Option<OverlayPath>,
    plan: SendPlan,
    pick: PathPick,
) -> (Option<OverlayPath>, SendPlan) {
    if matches!(base, Some(OverlayPath::Direct)) {
        return (base, plan);
    }
    match pick {
        PathPick::Direct => (Some(OverlayPath::Direct), SendPlan::Direct),
        PathPick::Relay => (Some(OverlayPath::Relay), SendPlan::Relay),
        PathPick::PeerRelay => (Some(OverlayPath::PeerRelay), SendPlan::Peer),
        PathPick::None => {
            if matches!(base, Some(OverlayPath::Relay)) {
                (base, plan)
            } else {
                (None, SendPlan::Hold)
            }
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
