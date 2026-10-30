//! The long-running node.
//!
//! The process keeps one QUIC session for each peer.
//! The router sends each outbound TUN packet to the peer that owns the destination.
//! The state directory keeps the overlay IP across a restart.
//! Linux uses the `orblx0` TUN device.
//! macOS uses a kernel-chosen utun device.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_identity::{decode_certificate_pem, extract_spiffe_id, leaf_validity, DenySet, SpiffeId};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::dns::{
    refresh_resolver, serve_dns, DnsTable, ExitNodeForwarder, LinkResolverGuard, PeerVisibility,
    QueryForwarder, ResolvConfForwarder, DNS_PORT,
};
use crate::ipv4::{inbound_action, InboundAction};
#[cfg(target_os = "macos")]
use crate::netmap::{ipv4_mask, parse_cidr};
use crate::netmap::{parse_ipv4, Netmap, NetmapPeer};
use crate::quic::{HelloEndpoint, SessionEvent};
use crate::router::{route_packet, RouterTable};
use crate::tun_dev::{open_tun, TunConfig};
use crate::{HelloConfig, HelloError, HelloSender, HelloSession, FLAG_REKEY_REQ};

macro_rules! tr {
    ($($a:tt)*) => {
        if std::env::var_os("ORBLX_TRACE_RENEW").is_some() {
            let ms = SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
            eprintln!("trace {ms} {}", format!($($a)*));
        }
    };
}

/// The node record file in the state directory.
pub const NODE_RECORD_FILE: &str = "node.json";

/// The pid file in the state directory.
pub const NODE_PID_FILE: &str = "orblxd.pid";

/// The status file in the state directory.
pub const NODE_STATUS_FILE: &str = "status.txt";

const PATH_DIRECT: &str = "direct";
const PATH_STALE: &str = "stale";
const PATH_DOWN: &str = "down";
/// A session with no received frame for this long is `stale`.
const STALE_AFTER: Duration = Duration::from_secs(2);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);

static LINK_GENERATION: AtomicU64 = AtomicU64::new(1);

/// A new leaf from the coordinator.
///
/// Debug output elides the private key.
pub struct RenewedLeaf {
    /// PEM certificate for this node.
    pub certificate_pem: String,
    /// PEM private key for this node.
    pub private_key_pem: String,
}

impl std::fmt::Debug for RenewedLeaf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RenewedLeaf")
            .field("private_key_pem", &"[elided]")
            .finish()
    }
}

/// Calls the coordinator renew API.
///
/// The function must not log keys or tokens.
#[derive(Clone)]
pub struct SvidRenewer {
    renew: Arc<dyn Fn() -> Result<RenewedLeaf, String> + Send + Sync>,
}

impl std::fmt::Debug for SvidRenewer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SvidRenewer")
    }
}

impl SvidRenewer {
    /// Store the renew function.
    pub fn new<F>(renew: F) -> Self
    where
        F: Fn() -> Result<RenewedLeaf, String> + Send + Sync + 'static,
    {
        Self {
            renew: Arc::new(renew),
        }
    }

    fn renew(&self) -> Result<RenewedLeaf, String> {
        (self.renew)()
    }
}

/// In-memory packets for tests.
///
/// `from_tun` carries packets that the node sends to peers.
/// `to_tun` carries packets that peers send to the node.
pub struct MemoryDevice {
    /// Packets from the local host.
    pub from_tun: mpsc::Receiver<Vec<u8>>,
    /// Packets for the local host.
    pub to_tun: mpsc::Sender<Vec<u8>>,
}

/// Inputs for one node process.
pub struct NodeRequest {
    /// The leaf, the trust bundle, and the capability ticket.
    pub config: HelloConfig,
    /// The peer netmap.
    pub netmap: Netmap,
    /// The UDP socket for QUIC.
    pub listen: SocketAddr,
    /// The state directory. The default is `/var/lib/orblx`.
    pub state_dir: PathBuf,
    /// Renews the node SVID. `None` keeps the file certificate.
    pub renew: Option<SvidRenewer>,
    /// Stops the node when the watch value is true.
    ///
    /// `None` waits for SIGINT or SIGTERM.
    pub stop: Option<watch::Receiver<bool>>,
    /// Install approved subnet routes from the netmap into the TUN device.
    pub accept_routes: bool,
    /// Local CIDRs this node forwards onto a connected LAN.
    pub forward_routes: Vec<String>,
    /// Masquerade overlay traffic that leaves this node.
    pub forward_exit: bool,
    /// The selected exit node. `None` means this node does not use one.
    pub exit_node: Option<String>,
    /// Keep connected LAN prefixes outside the tunnel.
    pub allow_lan: bool,
    /// Coordinator, Relay, and peer underlay addresses.
    pub underlay: Vec<Ipv4Addr>,
    /// The orblx Relay socket. `None` means direct UDP only.
    pub relay: Option<SocketAddr>,
    /// The netmap file. The node reads it again when the file changes.
    pub netmap_path: PathBuf,
    /// [`crate::GrantPeers`] hides peers the signed grants do not let this node reach.
    /// [`crate::AllowPeers`] allows every peer when the node has no grant file.
    pub visibility: Arc<dyn PeerVisibility>,
    /// Runs after the overlay address is ready.
    ///
    /// The node daemon starts SSH from this hook.
    /// `None` starts no extra listener.
    pub on_ready: Option<Box<dyn FnOnce(Ipv4Addr) + Send>>,
    /// Loopback Prometheus address.
    ///
    /// `None` does not open the metrics port.
    /// The default command uses `127.0.0.1:9464`.
    pub metrics: Option<SocketAddr>,
    /// The receiver packet filter (W24).
    ///
    /// `None` keeps the old datapath. The node does not check the packet port.
    pub filter: Option<Arc<crate::PacketFilter>>,
}

/// One peer line in `orblx status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPeer {
    /// The peer name.
    pub name: String,
    /// The peer overlay address.
    pub overlay_ip: String,
    /// `direct`, `stale`, or `down`.
    pub path: String,
    /// The peer SPIFFE ID.
    pub svid: String,
    /// The peer leaf `not_after` time. `None` means the session is down.
    pub svid_expiry: Option<u64>,
}

/// The status text for one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    /// `up`, `down`, or `starting`.
    pub state: String,
    /// The local node name.
    pub name: String,
    /// The overlay address from the state directory.
    pub overlay_ip: String,
    /// The local SPIFFE ID.
    pub svid: String,
    /// The local leaf `not_after` time as Unix seconds.
    pub svid_expiry: u64,
    /// The selected exit node. `None` means this node does not use one.
    pub exit_node: Option<String>,
    /// One entry for each peer.
    pub peers: Vec<StatusPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRecord {
    name: String,
    overlay_ip: String,
}

struct NodeView {
    name: String,
    overlay_ip: String,
    svid: String,
    exit_node: Option<String>,
    not_before: AtomicU64,
    not_after: AtomicU64,
}

#[derive(Clone)]
struct PeerView {
    name: String,
    overlay_ip: String,
    svid: String,
    session: bool,
    last_rx: Option<Instant>,
    svid_expiry: Option<u64>,
    reported: String,
}

struct LiveLink {
    tx: mpsc::Sender<Vec<u8>>,
    cancel: watch::Sender<bool>,
    generation: u64,
    ask_rekey: watch::Sender<u64>,
}

/// A link that a newer session for the same peer replaced (W25-11).
///
/// The link gets no new packets. It sends the packets in its queue, ends its send
/// stream, and reads until the peer ends its send stream. `cancel` stops it at once.
struct RetiredLink {
    peer: String,
    cancel: watch::Sender<bool>,
}

struct NodeCounters {
    tx: AtomicU64,
    rx: AtomicU64,
}

#[derive(Clone)]
struct Mesh {
    endpoint: Arc<HelloEndpoint>,
    identity: Arc<Mutex<HelloConfig>>,
    netmap: Arc<Netmap>,
    netmap_path: PathBuf,
    node: Arc<NodeView>,
    links: Arc<Mutex<HashMap<String, LiveLink>>>,
    /// Replaced links that still drain, by generation (W25-11).
    retired: Arc<Mutex<HashMap<u64, RetiredLink>>>,
    peers: Arc<Mutex<Vec<PeerView>>>,
    counters: Arc<NodeCounters>,
    to_tun: mpsc::Sender<Vec<u8>>,
    overlay: Ipv4Addr,
    state_dir: Arc<PathBuf>,
    relay: Option<SocketAddr>,
    shutdown: watch::Receiver<bool>,
    rekey_tx: watch::Sender<u64>,
    rekey_rx: watch::Receiver<u64>,
    filter: Option<Arc<crate::PacketFilter>>,
}

/// Format `orblx status` text.
///
/// Peer lines are sorted by name.
#[must_use]
pub fn format_node_status(status: &NodeStatus) -> String {
    let mut peers = status.peers.clone();
    peers.sort_by(|left, right| left.name.cmp(&right.name));
    let mut text = format!(
        "state {}\nname {}\noverlay_ip {}\nsvid {}\nsvid_expiry {}\n",
        status.state, status.name, status.overlay_ip, status.svid, status.svid_expiry
    );
    if let Some(name) = &status.exit_node {
        text.push_str(&format!("exit_node {name}\n"));
    }
    for peer in peers {
        let expiry = match peer.svid_expiry {
            Some(value) => value.to_string(),
            None => "unknown".to_string(),
        };
        text.push_str(&format!(
            "peer {} overlay_ip {} path {} svid {} svid_expiry {}\n",
            peer.name, peer.overlay_ip, peer.path, peer.svid, expiry
        ));
    }
    text
}

/// Read the status text for a state directory.
///
/// A live pid returns the status file.
/// A stopped node returns the overlay IP from the state directory.
pub fn read_status_text(state_dir: &Path) -> Result<String, HelloError> {
    let record = read_record(state_dir)?;
    if running_pid(state_dir).is_some() {
        let path = state_dir.join(NODE_STATUS_FILE);
        match fs::read_to_string(&path) {
            Ok(text) if !text.is_empty() => Ok(text),
            Ok(_) | Err(_) => Ok(format!(
                "state starting\nname {}\noverlay_ip {}\n",
                record.name, record.overlay_ip
            )),
        }
    } else {
        Ok(format!(
            "state down\nname {}\noverlay_ip {}\n",
            record.name, record.overlay_ip
        ))
    }
}

/// Return the pid when the node process is running.
#[must_use]
pub fn running_pid(state_dir: &Path) -> Option<u32> {
    let pid = read_pid(state_dir)?;
    if process_is_running(pid) {
        Some(pid)
    } else {
        None
    }
}

/// Run the node until the process receives SIGINT or SIGTERM.
pub fn run_node(request: NodeRequest) -> Result<(), HelloError> {
    let mut prepared = prepare_node(request)?;
    let install = prepared
        .router
        .install_cidrs(prepared.request.accept_routes);
    for cidr in &install {
        println!("The node installs route {cidr}.");
    }
    if let Some(name) = prepared.request.exit_node.clone() {
        if prepared.router.is_exit(&name) {
            println!("The node installs route 0.0.0.0/0 through the exit node {name}.");
        } else {
            println!("The exit node {name} is not approved. The node does not use it.");
            prepared.request.exit_node = None;
        }
    }
    prepared.view.exit_node = prepared.request.exit_node.clone();
    let bridge = open_tun(&TunConfig {
        name: tun_device_name(),
        address: parse_ipv4(&prepared.record.overlay_ip)
            .map_err(|err| HelloError::Node(err.to_string()))?,
        netmask: Ipv4Addr::new(255, 255, 255, 255),
    })?;
    prepare_link(&bridge.name, &install)?;
    if !prepared.request.forward_routes.is_empty() {
        crate::subnet::enable_kernel_forward(&prepared.request.forward_routes)?;
    }
    if prepared.request.forward_exit {
        crate::subnet::enable_exit_masquerade()?;
    }
    let exit_routes = if prepared.request.exit_node.is_some() {
        Some(crate::exit_route::install_exit_routes(
            &bridge.name,
            prepared.request.allow_lan,
            &prepared.request.underlay,
        )?)
    } else {
        None
    };
    println!("The overlay IP is {}.", prepared.record.overlay_ip);
    println!(
        "The state directory is {}.",
        prepared.request.state_dir.display()
    );
    println!("The TUN device is {}.", bridge.name);
    announce_renew(&prepared.request);
    let overlay =
        parse_ipv4(&prepared.record.overlay_ip).map_err(|err| HelloError::Node(err.to_string()))?;
    if let Some(on_ready) = prepared.request.on_ready.take() {
        on_ready(overlay);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    let result = runtime.block_on(run_mesh(
        prepared,
        bridge.from_tun,
        bridge.to_tun,
        Some(bridge.name),
    ));
    drop(exit_routes);
    result
}

/// Run the node with in-memory packets.
///
/// Call this function inside a Tokio runtime.
/// The function does not open a TUN device.
pub async fn run_memory_node(request: NodeRequest, device: MemoryDevice) -> Result<(), HelloError> {
    let mut prepared = prepare_node(request)?;
    println!("The overlay IP is {}.", prepared.record.overlay_ip);
    println!(
        "The state directory is {}.",
        prepared.request.state_dir.display()
    );
    println!("The TUN device is memory.");
    announce_renew(&prepared.request);
    let overlay =
        parse_ipv4(&prepared.record.overlay_ip).map_err(|err| HelloError::Node(err.to_string()))?;
    if let Some(on_ready) = prepared.request.on_ready.take() {
        on_ready(overlay);
    }
    run_mesh(prepared, device.from_tun, device.to_tun, None).await
}

struct PreparedNode {
    request: NodeRequest,
    view: NodeView,
    record: NodeRecord,
    router: RouterTable,
    _pid_guard: PidGuard,
}

fn prepare_node(request: NodeRequest) -> Result<PreparedNode, HelloError> {
    request
        .netmap
        .check()
        .map_err(|err| HelloError::Node(err.to_string()))?;
    let view = local_view(&request)?;
    let record = load_or_create_state(&request.state_dir, &request.netmap)?;
    if record.overlay_ip != view.overlay_ip || record.name != view.name {
        return Err(HelloError::Node(format!(
            "The state directory keeps overlay IP {} for node {}. The netmap has overlay IP {}.",
            record.overlay_ip, record.name, view.overlay_ip
        )));
    }
    if let Some(pid) = running_pid(&request.state_dir) {
        return Err(HelloError::Node(format!(
            "The node is already running. The pid is {pid}."
        )));
    }
    let pid_guard = PidGuard::create(&request.state_dir)?;
    let router = RouterTable::from_netmap(&request.netmap)
        .map_err(|err| HelloError::Node(err.to_string()))?;
    Ok(PreparedNode {
        request,
        view,
        record,
        router,
        _pid_guard: pid_guard,
    })
}

fn announce_renew(request: &NodeRequest) {
    if request.renew.is_some() {
        println!("The node renews the SVID at two thirds of the certificate life.");
    } else {
        println!(
            "The node does not renew the SVID. The state directory has no coordinator address."
        );
    }
}

async fn run_mesh_inner(
    request: NodeRequest,
    view: NodeView,
    router: RouterTable,
    from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    interface: Option<String>,
    _pid_guard: PidGuard,
) -> Result<(), HelloError> {
    let identity = Arc::new(Mutex::new(request.config.clone()));
    let netmap_path = request.netmap_path.clone();
    let visibility = Arc::clone(&request.visibility);
    let endpoint = Arc::new(HelloEndpoint::bind_node(request.config, request.listen)?);
    let bound = endpoint.local_addr()?;
    println!("The node {} listens on UDP {bound}.", view.name);
    let state_dir = Arc::new(request.state_dir);
    let node = Arc::new(view);
    let peers = Arc::new(Mutex::new(initial_peers(&request.netmap)));
    let links = Arc::new(Mutex::new(HashMap::<String, LiveLink>::new()));
    let router = Arc::new(router);
    publish(&state_dir, &node, &peers, "up");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (rekey_tx, rekey_rx) = watch::channel(0u64);
    let mut tasks = Vec::<JoinHandle<()>>::new();
    let counters = Arc::new(NodeCounters {
        tx: AtomicU64::new(0),
        rx: AtomicU64::new(0),
    });

    let tun_shutdown = shutdown_rx.clone();
    let tun_router = Arc::clone(&router);
    let tun_links = Arc::clone(&links);
    let tun_counters = Arc::clone(&counters);
    let accept_routes = request.accept_routes;
    let exit_node = request.exit_node.clone();
    let relay = request.relay;
    tasks.push(tokio::spawn(async move {
        read_tun(
            from_tun,
            tun_router,
            tun_links,
            tun_shutdown,
            accept_routes,
            exit_node,
            tun_counters,
        )
        .await;
    }));

    let netmap = Arc::new(request.netmap);
    let overlay = parse_ipv4(&node.overlay_ip).map_err(|err| HelloError::Node(err.to_string()))?;
    let dns_shutdown = shutdown_rx.clone();
    let mesh = Mesh {
        endpoint: Arc::clone(&endpoint),
        identity,
        netmap: Arc::clone(&netmap),
        netmap_path: netmap_path.clone(),
        node: Arc::clone(&node),
        links: Arc::clone(&links),
        retired: Arc::new(Mutex::new(HashMap::new())),
        peers: Arc::clone(&peers),
        counters: Arc::clone(&counters),
        to_tun: to_tun.clone(),
        overlay,
        state_dir: Arc::clone(&state_dir),
        relay,
        shutdown: shutdown_rx,
        rekey_tx,
        rekey_rx,
        filter: request.filter.clone(),
    };
    if let Some(addr) = request.metrics {
        let metrics_peers = Arc::clone(&peers);
        let metrics_counters = Arc::clone(&counters);
        match orblx_audit::spawn_metrics_server(addr, move || {
            let sessions = lock(&metrics_peers)
                .iter()
                .filter(|peer| peer.session)
                .count();
            let sessions = u64::try_from(sessions).unwrap_or(u64::MAX);
            format!(
                "{}{}{}",
                orblx_audit::sample_line(
                    "orblx_node_packets_tx",
                    "counter",
                    metrics_counters.tx.load(Ordering::Relaxed)
                ),
                orblx_audit::sample_line(
                    "orblx_node_packets_rx",
                    "counter",
                    metrics_counters.rx.load(Ordering::Relaxed)
                ),
                orblx_audit::sample_line("orblx_node_sessions", "gauge", sessions),
            )
        }) {
            Ok(bound) => println!("metrics {bound}"),
            Err(err) => eprintln!("{err}"),
        }
    }
    apply_lock_allow(&mesh);
    let lock_mesh = mesh.clone();
    let deny_endpoint = Arc::clone(&endpoint);
    let deny_dir = Arc::clone(&state_dir);
    let mut deny_shutdown = mesh.shutdown.clone();
    tasks.push(tokio::spawn(async move {
        // The deny list reloads each 100 ms, so an unshare or a revoke stops a peer
        // at most 100 ms after the node writes the new list (W25-1).
        // The node lock check stays at each 10 s (each 100 ticks).
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        // The node applies the list only when the file text changes. Thus the
        // tick does not touch the endpoint or the links when nothing changed.
        let mut ticks: u64 = 0;
        let mut last_text: Option<Vec<u8>> = None;
        loop {
            tokio::select! {
                changed = deny_shutdown.changed() => {
                    if changed.is_err() || *deny_shutdown.borrow() {
                        return;
                    }
                }
                _ = tick.tick() => {
                    if let Ok(bytes) = fs::read(deny_dir.join("deny.json")) {
                        if last_text.as_deref() != Some(bytes.as_slice()) {
                            if let Some(deny) = parse_deny(&bytes) {
                                // Replace first, so a session that starts now uses the new list.
                                // Then close the open sessions of the denied peers.
                                deny_endpoint.replace_deny(deny.clone());
                                close_denied_links(&lock_mesh, &deny);
                                last_text = Some(bytes);
                            }
                        }
                    }
                    if ticks.is_multiple_of(100) {
                        apply_lock_allow(&lock_mesh);
                    }
                    ticks = ticks.wrapping_add(1);
                }
            }
        }
    }));
    let accept_mesh = mesh.clone();
    tasks.push(tokio::spawn(async move {
        accept_loop(accept_mesh).await;
    }));

    for peer in netmap.peers.iter() {
        if we_dial(&node.name, &peer.name) {
            let dial_mesh = mesh.clone();
            let peer = peer.clone();
            tasks.push(tokio::spawn(async move {
                dial_peer(dial_mesh, peer).await;
            }));
        } else if mesh.relay.is_some() {
            let accept_mesh = mesh.clone();
            let peer = peer.clone();
            tasks.push(tokio::spawn(async move {
                accept_relay(accept_mesh, peer).await;
            }));
        }
    }

    if let Some(renewer) = request.renew {
        let renew_mesh = mesh.clone();
        tasks.push(tokio::spawn(async move {
            renew_loop(renew_mesh, renewer).await;
        }));
    }

    let mut status_mesh = mesh.clone();
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                changed = status_mesh.shutdown.changed() => {
                    if changed.is_err() || *status_mesh.shutdown.borrow() {
                        return;
                    }
                }
                _ = tick.tick() => {
                    publish(&status_mesh.state_dir, &status_mesh.node, &status_mesh.peers, "up");
                }
            }
        }
    }));

    let resolver = if let Some(interface) = interface {
        let overlay =
            parse_ipv4(&node.overlay_ip).map_err(|err| HelloError::Node(err.to_string()))?;
        let exit_dns = exit_dns_target(&netmap, request.exit_node.as_deref());
        let (guard, dns_tasks) = spawn_overlay_dns(
            DnsSpawn {
                interface,
                overlay,
                netmap_path,
                node_name: node.name.clone(),
                node_overlay: node.overlay_ip.clone(),
                visibility,
                shutdown: dns_shutdown,
                exit_dns,
            },
            &netmap,
        )
        .await;
        tasks.extend(dns_tasks);
        Some(guard)
    } else {
        None
    };

    wait_for_stop(request.stop).await;
    let _ = shutdown_tx.send(true);
    drop(resolver);
    endpoint.close();
    tokio::time::sleep(Duration::from_millis(200)).await;
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    publish(&state_dir, &node, &peers, "down");
    println!("The node is down.");
    drop(to_tun);
    Ok(())
}

async fn run_mesh(
    prepared: PreparedNode,
    from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    interface: Option<String>,
) -> Result<(), HelloError> {
    let PreparedNode {
        request,
        view,
        router,
        _pid_guard,
        ..
    } = prepared;
    run_mesh_inner(
        request, view, router, from_tun, to_tun, interface, _pid_guard,
    )
    .await
}

fn local_view(request: &NodeRequest) -> Result<NodeView, HelloError> {
    let der =
        decode_certificate_pem(&request.config.certificate_pem).map_err(HelloError::Identity)?;
    let svid = extract_spiffe_id(&der).map_err(HelloError::Identity)?;
    let expected = SpiffeId::node(&request.netmap.self_node.name).map_err(|_| {
        HelloError::Node(format!(
            "The node name {} is not valid.",
            request.netmap.self_node.name
        ))
    })?;
    if svid != expected {
        return Err(HelloError::Node(format!(
            "The node certificate SPIFFE ID is {}. The netmap name is {}.",
            svid.as_uri(),
            request.netmap.self_node.name
        )));
    }
    let overlay = parse_ipv4(&request.netmap.self_node.overlay_ip)
        .map_err(|err| HelloError::Node(err.to_string()))?;
    let (not_before, not_after) = leaf_validity(&der).map_err(HelloError::Identity)?;
    Ok(NodeView {
        name: request.netmap.self_node.name.clone(),
        overlay_ip: overlay.to_string(),
        svid: svid.as_uri().to_string(),
        exit_node: None,
        not_before: AtomicU64::new(not_before),
        not_after: AtomicU64::new(not_after),
    })
}

fn initial_peers(map: &Netmap) -> Vec<PeerView> {
    map.peers
        .iter()
        .map(|peer| PeerView {
            name: peer.name.clone(),
            overlay_ip: peer.overlay_ip.clone(),
            svid: peer.svid.clone(),
            session: false,
            last_rx: None,
            svid_expiry: None,
            reported: PATH_DOWN.to_string(),
        })
        .collect()
}

fn we_dial(self_name: &str, peer_name: &str) -> bool {
    self_name < peer_name
}

async fn wait_for_stop(external: Option<watch::Receiver<bool>>) {
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    match terminate {
        Ok(mut terminate) => {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if let Err(err) = result {
                        eprintln!("The node did not wait for SIGINT. {err}");
                    }
                }
                _ = terminate.recv() => {}
                _ = external_stop(external) => {}
            }
        }
        Err(err) => {
            eprintln!("The node did not install the stop handler. {err}");
            external_stop(external).await;
        }
    }
}

async fn external_stop(external: Option<watch::Receiver<bool>>) {
    let Some(mut external) = external else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if *external.borrow() {
            return;
        }
        if external.changed().await.is_err() {
            return;
        }
    }
}

async fn read_tun(
    mut from_tun: mpsc::Receiver<Vec<u8>>,
    router: Arc<RouterTable>,
    links: Arc<Mutex<HashMap<String, LiveLink>>>,
    mut shutdown: watch::Receiver<bool>,
    accept_routes: bool,
    exit_node: Option<String>,
    counters: Arc<NodeCounters>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            packet = from_tun.recv() => {
                let Some(packet) = packet else {
                    return;
                };
                let Some(peer) = route_packet(&router, &packet, accept_routes, exit_node.as_deref()) else {
                    continue;
                };
                let peer = peer.to_string();
                let tx = {
                    let map = lock(&links);
                    map.get(&peer).map(|link| link.tx.clone())
                };
                if let Some(tx) = tx {
                    if tx.send(packet).await.is_ok() {
                        counters.tx.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

fn fresh_netmap(mesh: &Mesh) -> Netmap {
    match Netmap::from_path(&mesh.netmap_path) {
        Ok(netmap) => netmap,
        Err(_) => (*mesh.netmap).clone(),
    }
}

/// Limit new sessions to the netmap peers when node lock is on (W23-1).
///
/// The node lock pass already removed each peer without a trusted owner signature
/// from the netmap file. Without a node lock file, the endpoint allows every trusted leaf.
fn apply_lock_allow(mesh: &Mesh) {
    if !mesh.state_dir.join(crate::NODE_LOCK_FILE).exists() {
        mesh.endpoint.replace_allow(None);
        return;
    }
    let netmap = fresh_netmap(mesh);
    let allow: HashSet<String> = netmap.peers.iter().map(|peer| peer.svid.clone()).collect();
    mesh.endpoint.replace_allow(Some(allow));
}

/// Close each open session whose peer SPIFFE ID is in the deny list (W25-1).
///
/// The per-frame check denies only ticket nonces. A peer that the coordinator
/// hides or revokes after the session started must lose the session here.
/// The dial task then tries again, and the session check refuses the denied peer.
/// When the deny list drops the peer again, the next dial brings the session back.
fn close_denied_links(mesh: &Mesh, deny: &DenySet) {
    let netmap = fresh_netmap(mesh);
    let svids: HashMap<&str, &str> = mesh
        .netmap
        .peers
        .iter()
        .chain(netmap.peers.iter())
        .map(|peer| (peer.name.as_str(), peer.svid.as_str()))
        .collect();
    let links = lock(&mesh.links);
    for (name, link) in links.iter() {
        let Some(svid) = svids.get(name.as_str()) else {
            continue;
        };
        let Ok(id) = SpiffeId::parse(svid) else {
            continue;
        };
        if deny.reject_uri(&id).is_err() && !*link.cancel.borrow() {
            println!("The peer {name} is in the deny list. The node closes the session.");
            let _ = link.cancel.send(true);
        }
    }
    drop(links);
    for retired in lock(&mesh.retired).values() {
        let Some(svid) = svids.get(retired.peer.as_str()) else {
            continue;
        };
        let Ok(id) = SpiffeId::parse(svid) else {
            continue;
        };
        if deny.reject_uri(&id).is_err() {
            let _ = retired.cancel.send(true);
        }
    }
}

fn parse_deny(bytes: &[u8]) -> Option<DenySet> {
    let mut deny = DenySet::empty();
    match deny.apply_json(bytes) {
        Ok(_) => Some(deny),
        Err(_) => None,
    }
}

async fn accept_loop(mut mesh: Mesh) {
    loop {
        tokio::select! {
            changed = mesh.shutdown.changed() => {
                if changed.is_err() || *mesh.shutdown.borrow() {
                    return;
                }
            }
            accepted = mesh.endpoint.accept_one() => {
                match accepted {
                    Ok(session) => {
                        tr!("{} accepted {}", mesh.node.name, session.peer_id().as_uri());
                        let netmap = fresh_netmap(&mesh);
                        let peer_name = netmap.peers.iter().find(|peer| peer.svid == session.peer_id().as_uri()).map(|peer| peer.name.clone());
                        let Some(peer_name) = peer_name else {
                            eprintln!(
                                "The node drops a session from {}.",
                                session.peer_id().as_uri()
                            );
                            continue;
                        };
                        if we_dial(&mesh.node.name, &peer_name) {
                            eprintln!(
                                "The node drops a session from {peer_name}. This node dials that peer."
                            );
                            continue;
                        }
                        let link = mesh.clone();
                        let (remote_tx, _remote_rx) = watch::channel(0u64);
                        tokio::spawn(async move {
                            run_link(link, session, peer_name, remote_tx, None).await;
                        });
                    }
                    Err(HelloError::EndpointClosed) => return,
                    Err(err) => {
                        eprintln!("The node did not accept a peer. {err}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }
}

async fn dial_peer(mut mesh: Mesh, peer: NetmapPeer) {
    let (remote_tx, mut remote_rx) = watch::channel(0u64);
    loop {
        if stopped(&mesh) {
            return;
        }
        let Some((session, relay_face)) = dial_ready(&mut mesh, &peer).await else {
            return;
        };
        let mut task = spawn_link(
            &mesh,
            session,
            peer.name.clone(),
            remote_tx.clone(),
            relay_face,
        );
        loop {
            tokio::select! {
                _ = &mut task => break,
                changed = mesh.rekey_rx.changed() => {
                    if changed.is_err() || stopped(&mesh) {
                        return;
                    }
                    tr!("{} reconnect cause=local_renew peer={}", mesh.node.name, peer.name);
                    reconnect(&mut mesh, &peer, &remote_tx, &mut remote_rx, &mut task).await;
                }
                changed = remote_rx.changed() => {
                    if changed.is_err() || stopped(&mesh) {
                        return;
                    }
                    tr!("{} reconnect cause=peer_rekey_req peer={}", mesh.node.name, peer.name);
                    reconnect(&mut mesh, &peer, &remote_tx, &mut remote_rx, &mut task).await;
                }
            }
        }
    }
}

fn spawn_link(
    mesh: &Mesh,
    session: HelloSession,
    name: String,
    remote_tx: watch::Sender<u64>,
    relay_face: Option<crate::relay_path::RelayFace>,
) -> JoinHandle<()> {
    let mesh = mesh.clone();
    tokio::spawn(async move {
        run_link(mesh, session, name, remote_tx, relay_face).await;
    })
}

async fn reconnect(
    mesh: &mut Mesh,
    peer: &NetmapPeer,
    remote_tx: &watch::Sender<u64>,
    remote_rx: &mut watch::Receiver<u64>,
    task: &mut JoinHandle<()>,
) {
    // The new handshake uses the identity of both nodes as of now. Earlier renew signals
    // of either node need no second session (W25-11).
    mesh.rekey_rx.borrow_and_update();
    remote_rx.borrow_and_update();
    let t0 = Instant::now();
    let Some((session, relay_face)) = dial_once(mesh, peer).await else {
        tr!(
            "{} dial_failed peer={} ms={}",
            mesh.node.name,
            peer.name,
            t0.elapsed().as_millis()
        );
        return;
    };
    tr!(
        "{} dial_done peer={} ms={}",
        mesh.node.name,
        peer.name,
        t0.elapsed().as_millis()
    );
    let next = spawn_link(
        mesh,
        session,
        peer.name.clone(),
        remote_tx.clone(),
        relay_face,
    );
    // The old link drains and then stops (see `drive_session`). Do not wait for it here.
    drop(std::mem::replace(task, next));
}

async fn dial_ready(
    mesh: &mut Mesh,
    peer: &NetmapPeer,
) -> Option<(HelloSession, Option<crate::relay_path::RelayFace>)> {
    loop {
        if stopped(mesh) {
            return None;
        }
        if let Some(session) = dial_once(mesh, peer).await {
            return Some(session);
        }
        tokio::select! {
            changed = mesh.shutdown.changed() => {
                if changed.is_err() || *mesh.shutdown.borrow() {
                    return None;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn dial_once(
    mesh: &mut Mesh,
    peer: &NetmapPeer,
) -> Option<(HelloSession, Option<crate::relay_path::RelayFace>)> {
    for endpoint_text in &peer.endpoints {
        if stopped(mesh) {
            return None;
        }
        let addr = match resolve_endpoint(endpoint_text).await {
            Ok(addr) => addr,
            Err(()) => {
                eprintln!(
                    "The endpoint {endpoint_text} for {} is not valid.",
                    peer.name
                );
                continue;
            }
        };
        let connect = mesh.endpoint.connect_one(addr);
        let result = tokio::select! {
            changed = mesh.shutdown.changed() => {
                if changed.is_err() || *mesh.shutdown.borrow() {
                    return None;
                }
                continue;
            }
            result = tokio::time::timeout(Duration::from_secs(3), connect) => result,
        };
        match result {
            Ok(Ok(session)) => {
                if session.peer_id().as_uri() != peer.svid {
                    eprintln!(
                        "The peer {} presented {}.",
                        peer.name,
                        session.peer_id().as_uri()
                    );
                    continue;
                }
                return Some((session, None));
            }
            Ok(Err(err)) => {
                eprintln!("The dial to {} at {addr} failed. {err}", peer.name);
            }
            Err(_) => {
                eprintln!(
                    "The dial to {} at {addr} failed. The attempt timed out.",
                    peer.name
                );
            }
        }
    }
    if let Some(relay) = mesh.relay {
        return dial_relay(mesh, peer, relay)
            .await
            .map(|(session, face)| (session, Some(face)));
    }
    None
}

async fn dial_relay(
    mesh: &Mesh,
    peer: &NetmapPeer,
    relay: SocketAddr,
) -> Option<(HelloSession, crate::relay_path::RelayFace)> {
    let config = lock(&mesh.identity).clone();
    let session_id = crate::relay_path::relay_session_id(&mesh.node.name, &peer.name);
    let opened = tokio::task::spawn_blocking(move || {
        crate::relay_path::open_relay(config, relay, session_id, false)
    })
    .await
    .ok()?;
    let face = match opened {
        Ok(face) => face,
        Err(err) => {
            eprintln!("The Relay path to {} failed. {err}", peer.name);
            return None;
        }
    };
    match face.endpoint.connect_one(face.face_addr).await {
        Ok(session) => {
            if session.peer_id().as_uri() != peer.svid {
                eprintln!(
                    "The peer {} presented {}.",
                    peer.name,
                    session.peer_id().as_uri()
                );
                return None;
            }
            Some((session, face))
        }
        Err(err) => {
            eprintln!("The Relay path to {} failed. {err}", peer.name);
            None
        }
    }
}

async fn accept_relay(mut mesh: Mesh, peer: NetmapPeer) {
    let Some(relay) = mesh.relay else {
        return;
    };
    let (remote_tx, _remote_rx) = watch::channel(0u64);
    loop {
        if stopped(&mesh) {
            return;
        }
        let config = lock(&mesh.identity).clone();
        let session_id = crate::relay_path::relay_session_id(&mesh.node.name, &peer.name);
        let opened = tokio::task::spawn_blocking(move || {
            crate::relay_path::open_relay(config, relay, session_id, true)
        })
        .await;
        let face = match opened {
            Ok(Ok(face)) => face,
            Ok(Err(err)) => {
                eprintln!("The Relay path to {} failed. {err}", peer.name);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => return,
        };
        let accepted = face.endpoint.accept_one();
        tokio::select! {
            changed = mesh.shutdown.changed() => {
                if changed.is_err() || *mesh.shutdown.borrow() {
                    return;
                }
            }
            result = accepted => {
                match result {
                    Ok(session) if session.peer_id().as_uri() == peer.svid => {
                        run_link(mesh.clone(), session, peer.name.clone(), remote_tx.clone(), Some(face)).await;
                    }
                    Ok(session) => {
                        eprintln!(
                            "The peer {} presented {}.",
                            peer.name,
                            session.peer_id().as_uri()
                        );
                    }
                    Err(err) => {
                        eprintln!("The Relay path to {} failed. {err}", peer.name);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }
}

fn stopped(mesh: &Mesh) -> bool {
    *mesh.shutdown.borrow()
}

async fn resolve_endpoint(text: &str) -> Result<SocketAddr, ()> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = tokio::net::lookup_host(text).await.map_err(|_| ())?;
    addrs.next().ok_or(())
}

async fn run_link(
    mesh: Mesh,
    session: HelloSession,
    name: String,
    remote_rekey: watch::Sender<u64>,
    relay_face: Option<crate::relay_path::RelayFace>,
) {
    if let Some(face) = &relay_face {
        let kind = match face.transport {
            orblx_relay::RelayTransport::Tcp => "TCP",
            orblx_relay::RelayTransport::Udp => "UDP",
        };
        println!("The path to {name} uses the {kind} Relay.");
    }
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (ask_tx, ask_rx) = watch::channel(0u64);
    let (tx, rx) = mpsc::channel(32);
    let generation = LINK_GENERATION.fetch_add(1, Ordering::Relaxed);
    let expiry = session.peer_not_after();
    {
        let mut map = lock(&mesh.links);
        if mesh.endpoint.denies(session.peer_id()) {
            println!("The node ended the session with {name}. The deny list revokes the peer.");
            return;
        }
        tr!(
            "{} link_up peer={} gen={}",
            mesh.node.name,
            name,
            generation
        );
        if let Some(old) = map.insert(
            name.clone(),
            LiveLink {
                tx,
                cancel: cancel_tx,
                generation,
                ask_rekey: ask_tx,
            },
        ) {
            // Make before break (W25-11): the new session carries new packets now.
            // The old link drains. Its queue closes when `old.tx` drops here.
            tr!(
                "{} link_retire_old peer={} old_gen={}",
                mesh.node.name,
                name,
                old.generation
            );
            lock(&mesh.retired).insert(
                old.generation,
                RetiredLink {
                    peer: name.clone(),
                    cancel: old.cancel,
                },
            );
        }
    }
    set_session(&mesh.peers, &name, true, Some(expiry));
    publish(&mesh.state_dir, &mesh.node, &mesh.peers, "up");
    let peer_svid = session.peer_id().as_uri().to_string();
    let (sender, receiver) = session.split();
    let peers = Arc::clone(&mesh.peers);
    let state_dir = Arc::clone(&mesh.state_dir);
    let node = Arc::clone(&mesh.node);
    let peer_name = name.clone();
    drive_session(
        SessionIo {
            sender,
            receiver,
            packets: rx,
            cancel: cancel_rx,
            to_tun: mesh.to_tun.clone(),
            overlay: mesh.overlay,
            ask_rekey: ask_rx,
            remote_rekey,
            counters: Arc::clone(&mesh.counters),
            filter: mesh.filter.clone(),
            peer_svid,
            links: Arc::clone(&mesh.links),
            peer: name.clone(),
            label: format!("{} peer={} gen={}", mesh.node.name, name, generation),
        },
        move || note_rx(&peers, &state_dir, &node, &peer_name),
    )
    .await;
    lock(&mesh.retired).remove(&generation);
    let removed = {
        let mut map = lock(&mesh.links);
        if map.get(&name).map(|link| link.generation) == Some(generation) {
            map.remove(&name);
            true
        } else {
            false
        }
    };
    if removed {
        set_session(&mesh.peers, &name, false, None);
        publish(&mesh.state_dir, &mesh.node, &mesh.peers, "up");
    }
}

struct SessionIo {
    sender: HelloSender,
    receiver: crate::HelloReceiver,
    packets: mpsc::Receiver<Vec<u8>>,
    cancel: watch::Receiver<bool>,
    to_tun: mpsc::Sender<Vec<u8>>,
    overlay: Ipv4Addr,
    ask_rekey: watch::Receiver<u64>,
    remote_rekey: watch::Sender<u64>,
    counters: Arc<NodeCounters>,
    filter: Option<Arc<crate::PacketFilter>>,
    peer_svid: String,
    /// The live links. A draining link sends its replies on the current link.
    links: Arc<Mutex<HashMap<String, LiveLink>>>,
    peer: String,
    label: String,
}

type NextEvent = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (crate::HelloReceiver, Result<SessionEvent, HelloError>)>
            + Send,
    >,
>;

/// Read one frame to the end.
///
/// The future owns the receiver, so `select!` can poll it again after another branch
/// wins. A dropped read would lose the bytes it already took from the stream (W25-11).
fn next_event(mut receiver: crate::HelloReceiver) -> NextEvent {
    Box::pin(async move {
        let event = receiver.recv_event().await;
        (receiver, event)
    })
}

async fn poll_slot<T>(
    slot: &mut Option<std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>>,
) -> T {
    match slot {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

async fn drive_session(io: SessionIo, on_rx: impl Fn() + Send) {
    let SessionIo {
        mut sender,
        receiver,
        mut packets,
        mut cancel,
        to_tun,
        overlay,
        mut ask_rekey,
        remote_rekey,
        counters,
        filter,
        peer_svid,
        links,
        peer,
        label,
    } = io;
    let mut first_rx = true;
    let mut first_tx = true;
    // The queue is open while this link is the live link for the peer.
    let mut tx_open = true;
    let mut tx_end: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> = None;
    let mut tx_done = false;
    let mut ask_open = true;
    let mut rx_next: Option<NextEvent> = Some(next_event(receiver));
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    loop {
        if tx_done && rx_next.is_none() {
            tr!("{label} session_end reason=drained");
            return;
        }
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    tr!("{label} session_end reason=cancel");
                    return;
                }
            }
            changed = ask_rekey.changed(), if tx_open && ask_open => {
                if changed.is_err() {
                    // The link was replaced. The new link sends the rekey requests.
                    ask_open = false;
                    continue;
                }
                tr!("{label} send_rekey_req");
                if sender.send_ctrl(FLAG_REKEY_REQ).await.is_err() {
                    tr!("{label} session_end reason=send_rekey_err");
                    return;
                }
            }
            _ = keepalive.tick(), if tx_open => {
                if sender.send_ctrl(0).await.is_err() {
                    return;
                }
            }
            packet = packets.recv(), if tx_open => {
                let Some(packet) = packet else {
                    // A newer link replaced this one, and the queue is empty.
                    tx_open = false;
                    tr!("{label} tx_end");
                    tx_end = Some(Box::pin(sender.finish()));
                    continue;
                };
                if let Some(filter) = &filter {
                    filter.note_outbound(&packet);
                }
                if first_tx {
                    tr!("{label} first_tx");
                    first_tx = false;
                }
                if sender.send_ipv4(&packet).await.is_err() {
                    tr!("{label} session_end reason=send_err");
                    return;
                }
                counters.tx.fetch_add(1, Ordering::Relaxed);
            }
            () = poll_slot(&mut tx_end), if tx_end.is_some() => {
                tx_end = None;
                tx_done = true;
            }
            (receiver, incoming) = poll_slot(&mut rx_next), if rx_next.is_some() => {
                rx_next = None;
                match incoming {
                    Ok(event) => {
                        rx_next = Some(next_event(receiver));
                        match event {
                            SessionEvent::Packet(packet) => {
                                if first_rx {
                                    tr!("{label} first_rx");
                                    first_rx = false;
                                }
                                on_rx();
                                counters.rx.fetch_add(1, Ordering::Relaxed);
                                if let Some(filter) = &filter {
                                    if !filter.allow_inbound(&peer_svid, &packet) {
                                        continue;
                                    }
                                }
                                match inbound_action(&packet, overlay) {
                                    InboundAction::Reply(reply) if tx_open => {
                                        if sender.send_ipv4(&reply).await.is_err() {
                                            return;
                                        }
                                        counters.tx.fetch_add(1, Ordering::Relaxed);
                                    }
                                    InboundAction::Reply(reply) => {
                                        // This send stream ended. The live link carries the reply.
                                        let live = lock(&links).get(&peer).map(|link| link.tx.clone());
                                        if let Some(live) = live {
                                            if live.try_send(reply).is_ok() {
                                                counters.tx.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    InboundAction::Forward => {
                                        if to_tun.send(packet).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                            SessionEvent::Keepalive => on_rx(),
                            SessionEvent::Rekey => {
                                tr!("{label} got_rekey_req");
                                on_rx();
                                let next = remote_rekey.borrow().saturating_add(1);
                                let _ = remote_rekey.send(next);
                            }
                        }
                    }
                    Err(HelloError::StreamClosed) => {
                        // The peer replaced this session and sent all its frames on it.
                        tr!("{label} rx_end");
                    }
                    Err(err) => {
                        tr!("{label} session_end reason=recv_err {err}");
                        return;
                    }
                }
            }
        }
    }
}

fn set_session(peers: &Mutex<Vec<PeerView>>, name: &str, session: bool, expiry: Option<u64>) {
    let mut peers = lock(peers);
    if let Some(peer) = peers.iter_mut().find(|peer| peer.name == name) {
        peer.session = session;
        if session {
            peer.svid_expiry = expiry;
        } else {
            peer.last_rx = None;
            peer.svid_expiry = None;
        }
    }
}

fn note_rx(peers: &Mutex<Vec<PeerView>>, dir: &Path, node: &NodeView, name: &str) {
    let changed = {
        let mut peers = lock(peers);
        let Some(peer) = peers.iter_mut().find(|peer| peer.name == name) else {
            return;
        };
        let before = current_path(peer, Instant::now());
        peer.last_rx = Some(Instant::now());
        let after = current_path(peer, Instant::now());
        before != after
    };
    if changed {
        publish(dir, node, peers, "up");
    }
}

fn current_path(peer: &PeerView, now: Instant) -> &'static str {
    path_kind(
        peer.session,
        peer.last_rx.map(|then| now.saturating_duration_since(then)),
    )
}

fn path_kind(session: bool, age: Option<Duration>) -> &'static str {
    if !session {
        return PATH_DOWN;
    }
    match age {
        Some(age) if age <= STALE_AFTER => PATH_DIRECT,
        Some(_) | None => PATH_STALE,
    }
}

fn publish(dir: &Path, node: &NodeView, peers: &Mutex<Vec<PeerView>>, state: &str) {
    let now = Instant::now();
    let peers = {
        let mut peers = lock(peers);
        for peer in peers.iter_mut() {
            let path = current_path(peer, now);
            if peer.reported != path {
                println!("The path to {} is {path}.", peer.name);
                peer.reported = path.to_string();
            }
        }
        peers.clone()
    };
    let status = NodeStatus {
        state: state.to_string(),
        name: node.name.clone(),
        overlay_ip: node.overlay_ip.clone(),
        svid: node.svid.clone(),
        svid_expiry: node.not_after.load(Ordering::Relaxed),
        exit_node: node.exit_node.clone(),
        peers: peers
            .iter()
            .map(|peer| StatusPeer {
                name: peer.name.clone(),
                overlay_ip: peer.overlay_ip.clone(),
                path: current_path(peer, now).to_string(),
                svid: peer.svid.clone(),
                svid_expiry: peer.svid_expiry,
            })
            .collect(),
    };
    let text = format_node_status(&status);
    if let Err(err) = write_atomic(&dir.join(NODE_STATUS_FILE), text.as_bytes()) {
        eprintln!("The node did not write the status file. {err}");
    }
}

async fn renew_loop(mut mesh: Mesh, renewer: SvidRenewer) {
    loop {
        if stopped(&mesh) {
            return;
        }
        let not_before = mesh.node.not_before.load(Ordering::Relaxed);
        let not_after = mesh.node.not_after.load(Ordering::Relaxed);
        let due = renew_unix(not_before, not_after);
        let wait = due.saturating_sub(unix_now());
        tokio::select! {
            changed = mesh.shutdown.changed() => {
                if changed.is_err() || *mesh.shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
        }
        if stopped(&mesh) {
            return;
        }
        let mut attempt = 0u32;
        loop {
            if stopped(&mesh) {
                return;
            }
            tr!("{} renew_start", mesh.node.name);
            let renewer = renewer.clone();
            let fetched = tokio::task::spawn_blocking(move || renewer.renew()).await;
            let leaf = match fetched {
                Ok(Ok(leaf)) => leaf,
                Ok(Err(err)) => {
                    eprintln!(
                        "The SVID renewal failed. The node will retry. {}",
                        safe_text(&err)
                    );
                    if !sleep_retry(&mut mesh, retry_delay(attempt)).await {
                        return;
                    }
                    attempt = attempt.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    eprintln!("The SVID renewal failed. The node will retry.");
                    if !sleep_retry(&mut mesh, retry_delay(attempt)).await {
                        return;
                    }
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            };
            match apply_leaf(&mesh, &leaf) {
                Ok(expiry) => {
                    tr!("{} renew_applied signal_rekey", mesh.node.name);
                    signal_rekey(&mesh);
                    publish(&mesh.state_dir, &mesh.node, &mesh.peers, "up");
                    println!("The node renewed the SVID. The new expiry is {expiry}.");
                    break;
                }
                Err(err) => {
                    eprintln!(
                        "The SVID renewal failed. The node will retry. {}",
                        safe_text(&err.to_string())
                    );
                    if !sleep_retry(&mut mesh, retry_delay(attempt)).await {
                        return;
                    }
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

fn apply_leaf(mesh: &Mesh, leaf: &RenewedLeaf) -> Result<u64, HelloError> {
    let der = decode_certificate_pem(&leaf.certificate_pem).map_err(HelloError::Identity)?;
    let id = extract_spiffe_id(&der).map_err(HelloError::Identity)?;
    if id.as_uri() != mesh.node.svid {
        return Err(HelloError::Node(
            "The renewed SVID name does not match this node.".to_string(),
        ));
    }
    let (not_before, not_after) = leaf_validity(&der).map_err(HelloError::Identity)?;
    let previous = lock(&mesh.identity).clone();
    let next = {
        let mut config = lock(&mesh.identity);
        config.certificate_pem = leaf.certificate_pem.clone();
        config.private_key_pem = leaf.private_key_pem.clone();
        config.clone()
    };
    if let Err(err) = mesh.endpoint.install_identity(&next) {
        *lock(&mesh.identity) = previous;
        return Err(err);
    }
    mesh.node.not_before.store(not_before, Ordering::Relaxed);
    mesh.node.not_after.store(not_after, Ordering::Relaxed);
    Ok(not_after)
}

fn signal_rekey(mesh: &Mesh) {
    {
        let links = lock(&mesh.links);
        for link in links.values() {
            let next = link.ask_rekey.borrow().saturating_add(1);
            let _ = link.ask_rekey.send(next);
        }
    }
    let next = mesh.rekey_rx.borrow().saturating_add(1);
    let _ = mesh.rekey_tx.send(next);
}

async fn sleep_retry(mesh: &mut Mesh, delay: Duration) -> bool {
    tokio::select! {
        changed = mesh.shutdown.changed() => {
            changed.is_ok() && !*mesh.shutdown.borrow()
        }
        _ = tokio::time::sleep(delay) => true,
    }
}

fn retry_delay(attempt: u32) -> Duration {
    let secs = 1u64.checked_shl(attempt).unwrap_or(30).min(30);
    Duration::from_secs(secs)
}

fn renew_unix(not_before: u64, not_after: u64) -> u64 {
    let life = not_after.saturating_sub(not_before);
    not_before.saturating_add(life.saturating_mul(2) / 3)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn safe_text(text: &str) -> String {
    if text.contains("PRIVATE")
        || text.contains("BEGIN ")
        || text.contains("ge1.")
        || text.contains('\n')
    {
        return "The coordinator request failed.".to_string();
    }
    text.to_string()
}

fn load_or_create_state(dir: &Path, netmap: &Netmap) -> Result<NodeRecord, HelloError> {
    fs::create_dir_all(dir).map_err(|err| HelloError::Node(err.to_string()))?;
    let overlay = parse_ipv4(&netmap.self_node.overlay_ip)
        .map_err(|err| HelloError::Node(err.to_string()))?
        .to_string();
    let path = dir.join(NODE_RECORD_FILE);
    if path.exists() {
        let stored = read_record(dir)?;
        let stored_ip = parse_ipv4(&stored.overlay_ip)
            .map_err(|err| HelloError::Node(err.to_string()))?
            .to_string();
        if stored.name != netmap.self_node.name || stored_ip != overlay {
            return Err(HelloError::Node(format!(
                "The state directory keeps overlay IP {stored_ip} for node {}. The netmap has overlay IP {overlay}.",
                stored.name
            )));
        }
        return Ok(NodeRecord {
            name: stored.name,
            overlay_ip: stored_ip,
        });
    }
    let record = NodeRecord {
        name: netmap.self_node.name.clone(),
        overlay_ip: overlay,
    };
    let text =
        serde_json::to_string_pretty(&record).map_err(|err| HelloError::Node(err.to_string()))?;
    write_atomic(&path, text.as_bytes())?;
    Ok(record)
}

fn read_record(dir: &Path) -> Result<NodeRecord, HelloError> {
    let path = dir.join(NODE_RECORD_FILE);
    let bytes = fs::read(&path).map_err(|_| {
        HelloError::Node(format!(
            "The state directory {} has no node record.",
            dir.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        HelloError::Node(format!(
            "The node record {} is not valid. {err}",
            path.display()
        ))
    })
}

fn read_pid(dir: &Path) -> Option<u32> {
    let text = fs::read_to_string(dir.join(NODE_PID_FILE)).ok()?;
    text.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn process_is_running(pid: u32) -> bool {
    pid != 0 && Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(target_os = "macos")]
fn process_is_running(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: the pid is positive. Signal 0 does not deliver a signal. It checks that the process exists.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_is_running(pid: u32) -> bool {
    let _ = pid;
    false
}

#[cfg(target_os = "linux")]
fn tun_device_name() -> Option<String> {
    Some(crate::tun_dev::LINUX_TUN_NAME.to_string())
}

#[cfg(target_os = "macos")]
fn tun_device_name() -> Option<String> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn tun_device_name() -> Option<String> {
    None
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), HelloError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|err| HelloError::Node(err.to_string()))?;
    fs::rename(&tmp, path).map_err(|err| HelloError::Node(err.to_string()))
}

#[cfg(target_os = "linux")]
fn prepare_link(name: &str, cidrs: &[String]) -> Result<(), HelloError> {
    run_ip(&["link", "set", "dev", name, "arp", "off"])?;
    run_ip(&["link", "set", "dev", name, "up"])?;
    for cidr in cidrs {
        run_ip(&["route", "replace", cidr, "dev", name])?;
    }
    let rp_filter = format!("/proc/sys/net/ipv4/conf/{name}/rp_filter");
    if let Err(err) = fs::write(&rp_filter, "0\n") {
        eprintln!("The node did not set rp_filter for {name}. {err}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn prepare_link(name: &str, cidrs: &[String]) -> Result<(), HelloError> {
    for cidr in cidrs {
        let (network, prefix_len) =
            parse_cidr(cidr).map_err(|err| HelloError::Node(err.to_string()))?;
        crate::tun_macos::install_destination_route(
            name,
            Ipv4Addr::from(ipv4_mask(prefix_len) & u32::from(network)),
            Ipv4Addr::from(ipv4_mask(prefix_len)),
        )?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn prepare_link(name: &str, cidrs: &[String]) -> Result<(), HelloError> {
    let _ = (name, cidrs);
    Err(HelloError::Node(
        "The node opens a TUN device on Linux or macOS.".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> Result<(), HelloError> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|err| HelloError::Node(format!("The ip command did not start. {err}")))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    Err(HelloError::Node(format!(
        "The ip command failed. ip {} {detail}",
        args.join(" ")
    )))
}

#[derive(Clone)]
struct ExitDns {
    address: Ipv4Addr,
    name: String,
}

struct DnsSpawn {
    interface: String,
    overlay: Ipv4Addr,
    netmap_path: PathBuf,
    node_name: String,
    node_overlay: String,
    visibility: Arc<dyn PeerVisibility>,
    shutdown: watch::Receiver<bool>,
    exit_dns: Option<ExitDns>,
}

fn exit_dns_target(netmap: &Netmap, exit_node: Option<&str>) -> Option<ExitDns> {
    let name = exit_node?;
    let peer = netmap
        .peers
        .iter()
        .find(|peer| peer.name == name && peer.exit_node)?;
    let address = parse_ipv4(&peer.overlay_ip).ok()?;
    Some(ExitDns {
        address,
        name: name.to_string(),
    })
}

async fn spawn_overlay_dns(
    dns: DnsSpawn,
    netmap: &Netmap,
) -> (LinkResolverGuard, Vec<JoinHandle<()>>) {
    let guard = LinkResolverGuard::new(&dns.interface);
    let table = DnsTable::from_netmap(netmap);
    let bind_at = SocketAddr::from((dns.overlay, DNS_PORT));
    let socket = match tokio::net::UdpSocket::bind(bind_at).await {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("The DNS responder did not bind {bind_at}. {err} The node continues.");
            return (guard, Vec::new());
        }
    };
    println!("The DNS responder listens on {bind_at}.");
    let capture_all = dns.exit_dns.is_some();
    refresh_resolver(
        &dns.interface,
        dns.overlay,
        &table,
        dns.visibility.as_ref(),
        &guard.armed_flag(),
        capture_all,
    );
    let (table_tx, table_rx) = watch::channel(table);
    let mut tasks = Vec::new();
    let serve_visibility = Arc::clone(&dns.visibility);
    let serve_shutdown = dns.shutdown.clone();
    let overlay = dns.overlay;
    let forwarder: Arc<dyn QueryForwarder> = if let Some(exit) = dns.exit_dns.clone() {
        Arc::new(ExitNodeForwarder::new(exit.address, exit.name, overlay))
    } else {
        Arc::new(ResolvConfForwarder::new(overlay))
    };
    tasks.push(tokio::spawn(async move {
        serve_dns(
            socket,
            table_rx,
            serve_visibility,
            forwarder,
            overlay,
            serve_shutdown,
        )
        .await;
    }));
    let armed = guard.armed_flag();
    tasks.push(tokio::spawn(async move {
        watch_netmap_dns(DnsWatch {
            path: dns.netmap_path,
            node_name: dns.node_name,
            node_overlay: dns.node_overlay,
            interface: dns.interface,
            overlay,
            visibility: dns.visibility,
            armed,
            tables: table_tx,
            shutdown: dns.shutdown,
            capture_all,
        })
        .await;
    }));
    (guard, tasks)
}

struct DnsWatch {
    path: PathBuf,
    node_name: String,
    node_overlay: String,
    interface: String,
    overlay: Ipv4Addr,
    visibility: Arc<dyn PeerVisibility>,
    armed: Arc<AtomicBool>,
    tables: watch::Sender<DnsTable>,
    shutdown: watch::Receiver<bool>,
    capture_all: bool,
}

async fn watch_netmap_dns(mut watch_state: DnsWatch) {
    let mut last = fs::read(&watch_state.path).unwrap_or_default();
    let mut last_error = String::new();
    let mut grant_revision = watch_state.visibility.revision();
    loop {
        tokio::select! {
            changed = watch_state.shutdown.changed() => {
                if changed.is_err() || *watch_state.shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                let next = watch_state.visibility.revision();
                if next != grant_revision {
                    grant_revision = next;
                    let table = watch_state.tables.borrow().clone();
                    refresh_resolver(
                        &watch_state.interface,
                        watch_state.overlay,
                        &table,
                        watch_state.visibility.as_ref(),
                        &watch_state.armed,
                        watch_state.capture_all,
                    );
                    println!("The DNS answers follow the new grants.");
                }
                reload_dns_file(&watch_state, &mut last, &mut last_error);
            }
        }
    }
}

fn reload_dns_file(watch_state: &DnsWatch, last: &mut Vec<u8>, last_error: &mut String) {
    match fs::read(&watch_state.path) {
        Ok(bytes) if bytes == *last => {}
        Ok(bytes) => match Netmap::from_slice(&bytes) {
            Ok(map) if self_matches(&map, &watch_state.node_name, &watch_state.node_overlay) => {
                last.clone_from(&bytes);
                last_error.clear();
                let table = DnsTable::from_netmap(&map);
                refresh_resolver(
                    &watch_state.interface,
                    watch_state.overlay,
                    &table,
                    watch_state.visibility.as_ref(),
                    &watch_state.armed,
                    watch_state.capture_all,
                );
                let _ = watch_state.tables.send(table);
                println!("The DNS answers follow the new netmap.");
            }
            Ok(_) => {
                *last = bytes;
                let text = "The netmap self node does not match the running node.".to_string();
                if text != *last_error {
                    eprintln!("The node keeps the current DNS answers. {text}");
                    *last_error = text;
                }
            }
            Err(err) => {
                *last = bytes;
                let text = err.to_string();
                if text != *last_error {
                    eprintln!("The node did not load the netmap for DNS. {text}");
                    *last_error = text;
                }
            }
        },
        Err(err) => {
            let text = err.to_string();
            if text != *last_error {
                eprintln!("The node did not read the netmap for DNS. {text}");
                *last_error = text;
            }
        }
    }
}

fn self_matches(map: &Netmap, name: &str, overlay: &str) -> bool {
    if map.self_node.name != name {
        return false;
    }
    match parse_ipv4(&map.self_node.overlay_ip) {
        Ok(ip) => ip.to_string() == overlay,
        Err(_) => false,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

struct PidGuard {
    path: PathBuf,
}

impl PidGuard {
    fn create(dir: &Path) -> Result<Self, HelloError> {
        let path = dir.join(NODE_PID_FILE);
        fs::write(&path, std::process::id().to_string())
            .map_err(|err| HelloError::Node(err.to_string()))?;
        Ok(Self { path })
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{format_node_status, load_or_create_state, NodeStatus, StatusPeer};
    use crate::netmap::Netmap;

    fn sample_map(ip: &str) -> Netmap {
        let text = format!(
            r#"{{
                "version": 1,
                "self": {{"name": "a", "overlay_ip": "{ip}"}},
                "peers": []
            }}"#
        );
        Netmap::from_slice(text.as_bytes()).unwrap()
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orblx-w18-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_state_directory_keeps_the_overlay_ip() {
        let dir = test_dir("state");
        let first = load_or_create_state(&dir, &sample_map("100.64.0.1")).unwrap();
        assert_eq!(first.overlay_ip, "100.64.0.1");
        let second = load_or_create_state(&dir, &sample_map("100.64.0.1")).unwrap();
        assert_eq!(second.overlay_ip, "100.64.0.1");
        let err = load_or_create_state(&dir, &sample_map("100.64.0.9")).unwrap_err();
        assert!(err.to_string().contains("100.64.0.1"));
        assert!(err.to_string().contains("100.64.0.9"));
        let stored = fs::read_to_string(dir.join(super::NODE_RECORD_FILE)).unwrap();
        assert!(stored.contains("100.64.0.1"));
        assert!(!stored.contains("100.64.0.9"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_text_lists_each_peer_path_and_expiry() {
        let text = format_node_status(&NodeStatus {
            state: "up".to_string(),
            name: "a".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            svid: "spiffe://orblx.local/node/a".to_string(),
            svid_expiry: 100,
            exit_node: None,
            peers: vec![
                StatusPeer {
                    name: "c".to_string(),
                    overlay_ip: "100.64.0.3".to_string(),
                    path: "down".to_string(),
                    svid: "spiffe://orblx.local/node/c".to_string(),
                    svid_expiry: None,
                },
                StatusPeer {
                    name: "b".to_string(),
                    overlay_ip: "100.64.0.2".to_string(),
                    path: "direct".to_string(),
                    svid: "spiffe://orblx.local/node/b".to_string(),
                    svid_expiry: Some(200),
                },
            ],
        });
        assert!(text.contains("state up\n"));
        assert!(text.contains("overlay_ip 100.64.0.1\n"));
        assert!(text.contains(
            "peer b overlay_ip 100.64.0.2 path direct svid spiffe://orblx.local/node/b svid_expiry 200\n"
        ));
        assert!(text.contains(
            "peer c overlay_ip 100.64.0.3 path down svid spiffe://orblx.local/node/c svid_expiry unknown\n"
        ));
        assert!(text.find("peer b").unwrap() < text.find("peer c").unwrap());
    }

    #[test]
    fn renewal_starts_at_two_thirds_of_the_life() {
        assert_eq!(super::renew_unix(1_000, 1_060), 1_040);
        assert_eq!(super::renew_unix(0, 3), 2);
        assert_eq!(super::renew_unix(50, 50), 50);
    }

    #[test]
    fn status_path_is_not_direct_without_a_recent_packet() {
        assert_eq!(super::path_kind(false, None), "down");
        assert_eq!(super::path_kind(true, None), "stale");
        assert_eq!(
            super::path_kind(true, Some(Duration::from_secs(1))),
            "direct"
        );
        assert_eq!(
            super::path_kind(true, Some(Duration::from_secs(2))),
            "direct"
        );
        assert_eq!(
            super::path_kind(true, Some(Duration::from_millis(2_001))),
            "stale"
        );
        let text = format_node_status(&NodeStatus {
            state: "up".to_string(),
            name: "a".to_string(),
            overlay_ip: "100.64.0.1".to_string(),
            svid: "spiffe://orblx.local/node/a".to_string(),
            svid_expiry: 100,
            exit_node: None,
            peers: vec![StatusPeer {
                name: "b".to_string(),
                overlay_ip: "100.64.0.2".to_string(),
                path: "stale".to_string(),
                svid: "spiffe://orblx.local/node/b".to_string(),
                svid_expiry: Some(200),
            }],
        });
        assert!(text.contains("path stale "));
        assert!(!text.contains("path direct "));
    }

    #[test]
    fn renewal_errors_do_not_keep_key_text() {
        let text = super::safe_text("-----BEGIN PRIVATE KEY-----\nabc");
        assert_eq!(text, "The coordinator request failed.");
        assert!(!text.contains("PRIVATE"));
    }
}
