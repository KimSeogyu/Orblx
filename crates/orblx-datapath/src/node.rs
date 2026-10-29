//! The long-running node.
//!
//! The process keeps one QUIC session for each peer.
//! The router sends each outbound TUN packet to the peer that owns the destination.
//! The state directory keeps the overlay IP across a restart.
//! Linux uses the `orblx0` TUN device.
//! macOS uses a kernel-chosen utun device.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_identity::{decode_certificate_pem, extract_spiffe_id, leaf_validity, SpiffeId};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::dns::{
    refresh_resolver, serve_dns, DnsTable, LinkResolverGuard, PeerVisibility, ResolvConfForwarder,
    DNS_PORT,
};
#[cfg(target_os = "macos")]
use crate::netmap::{ipv4_mask, parse_cidr};
use crate::netmap::{parse_ipv4, Netmap, NetmapPeer};
use crate::quic::{HelloEndpoint, SessionEvent};
use crate::router::{route_packet, RouterTable};
use crate::tun_dev::{open_tun, TunConfig};
use crate::{HelloConfig, HelloError, HelloSender, HelloSession, FLAG_REKEY_REQ};

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
    /// The netmap file. The node reads it again when the file changes.
    pub netmap_path: PathBuf,
    /// [`crate::GrantPeers`] hides peers the signed grants do not let this node reach.
    /// [`crate::AllowPeers`] allows every peer when the node has no grant file.
    pub visibility: Arc<dyn PeerVisibility>,
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

#[derive(Clone)]
struct Mesh {
    endpoint: Arc<HelloEndpoint>,
    identity: Arc<Mutex<HelloConfig>>,
    netmap: Arc<Netmap>,
    node: Arc<NodeView>,
    links: Arc<Mutex<HashMap<String, LiveLink>>>,
    peers: Arc<Mutex<Vec<PeerView>>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    state_dir: Arc<PathBuf>,
    shutdown: watch::Receiver<bool>,
    rekey_tx: watch::Sender<u64>,
    rekey_rx: watch::Receiver<u64>,
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
    let prepared = prepare_node(request)?;
    let install = prepared
        .router
        .install_cidrs(prepared.request.accept_routes);
    for cidr in &install {
        println!("The node installs route {cidr}.");
    }
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
    println!("The overlay IP is {}.", prepared.record.overlay_ip);
    println!(
        "The state directory is {}.",
        prepared.request.state_dir.display()
    );
    println!("The TUN device is {}.", bridge.name);
    announce_renew(&prepared.request);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    runtime.block_on(run_mesh(
        prepared,
        bridge.from_tun,
        bridge.to_tun,
        Some(bridge.name),
    ))
}

/// Run the node with in-memory packets.
///
/// Call this function inside a Tokio runtime.
/// The function does not open a TUN device.
pub async fn run_memory_node(request: NodeRequest, device: MemoryDevice) -> Result<(), HelloError> {
    let prepared = prepare_node(request)?;
    println!("The overlay IP is {}.", prepared.record.overlay_ip);
    println!(
        "The state directory is {}.",
        prepared.request.state_dir.display()
    );
    println!("The TUN device is memory.");
    announce_renew(&prepared.request);
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

    let tun_shutdown = shutdown_rx.clone();
    let tun_router = Arc::clone(&router);
    let tun_links = Arc::clone(&links);
    let accept_routes = request.accept_routes;
    tasks.push(tokio::spawn(async move {
        read_tun(from_tun, tun_router, tun_links, tun_shutdown, accept_routes).await;
    }));

    let netmap = Arc::new(request.netmap);
    let dns_shutdown = shutdown_rx.clone();
    let mesh = Mesh {
        endpoint: Arc::clone(&endpoint),
        identity,
        netmap: Arc::clone(&netmap),
        node: Arc::clone(&node),
        links: Arc::clone(&links),
        peers: Arc::clone(&peers),
        to_tun: to_tun.clone(),
        state_dir: Arc::clone(&state_dir),
        shutdown: shutdown_rx,
        rekey_tx,
        rekey_rx,
    };
    let accept_mesh = mesh.clone();
    tasks.push(tokio::spawn(async move {
        accept_loop(accept_mesh).await;
    }));

    for peer in netmap
        .peers
        .iter()
        .filter(|peer| we_dial(&node.name, &peer.name))
    {
        let dial_mesh = mesh.clone();
        let peer = peer.clone();
        tasks.push(tokio::spawn(async move {
            dial_peer(dial_mesh, peer).await;
        }));
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
        let (guard, dns_tasks) = spawn_overlay_dns(
            DnsSpawn {
                interface,
                overlay,
                netmap_path,
                node_name: node.name.clone(),
                node_overlay: node.overlay_ip.clone(),
                visibility,
                shutdown: dns_shutdown,
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
                let Some(peer) = route_packet(&router, &packet, accept_routes) else {
                    continue;
                };
                let peer = peer.to_string();
                let tx = {
                    let map = lock(&links);
                    map.get(&peer).map(|link| link.tx.clone())
                };
                if let Some(tx) = tx {
                    let _ = tx.send(packet).await;
                }
            }
        }
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
                        let peer_name = mesh.netmap.peers.iter().find(|peer| peer.svid == session.peer_id().as_uri()).map(|peer| peer.name.clone());
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
                            run_link(link, session, peer_name, remote_tx).await;
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
        let Some(session) = dial_ready(&mut mesh, &peer).await else {
            return;
        };
        let mut task = spawn_link(&mesh, session, peer.name.clone(), remote_tx.clone());
        loop {
            tokio::select! {
                _ = &mut task => break,
                changed = mesh.rekey_rx.changed() => {
                    if changed.is_err() || stopped(&mesh) {
                        return;
                    }
                    reconnect(&mut mesh, &peer, &remote_tx, &mut task).await;
                }
                changed = remote_rx.changed() => {
                    if changed.is_err() || stopped(&mesh) {
                        return;
                    }
                    reconnect(&mut mesh, &peer, &remote_tx, &mut task).await;
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
) -> JoinHandle<()> {
    let mesh = mesh.clone();
    tokio::spawn(async move {
        run_link(mesh, session, name, remote_tx).await;
    })
}

async fn reconnect(
    mesh: &mut Mesh,
    peer: &NetmapPeer,
    remote_tx: &watch::Sender<u64>,
    task: &mut JoinHandle<()>,
) {
    let Some(session) = dial_once(mesh, peer).await else {
        return;
    };
    let next = spawn_link(mesh, session, peer.name.clone(), remote_tx.clone());
    let mut old = std::mem::replace(task, next);
    if tokio::time::timeout(Duration::from_secs(2), &mut old)
        .await
        .is_err()
    {
        old.abort();
    }
}

async fn dial_ready(mesh: &mut Mesh, peer: &NetmapPeer) -> Option<HelloSession> {
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

async fn dial_once(mesh: &mut Mesh, peer: &NetmapPeer) -> Option<HelloSession> {
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
        tokio::select! {
            changed = mesh.shutdown.changed() => {
                if changed.is_err() || *mesh.shutdown.borrow() {
                    return None;
                }
            }
            result = connect => {
                match result {
                    Ok(session) => {
                        if session.peer_id().as_uri() != peer.svid {
                            eprintln!(
                                "The peer {} presented {}.",
                                peer.name,
                                session.peer_id().as_uri()
                            );
                            continue;
                        }
                        return Some(session);
                    }
                    Err(err) => {
                        eprintln!("The dial to {} at {addr} failed. {err}", peer.name);
                    }
                }
            }
        }
    }
    None
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
) {
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (ask_tx, ask_rx) = watch::channel(0u64);
    let (tx, rx) = mpsc::channel(32);
    let generation = LINK_GENERATION.fetch_add(1, Ordering::Relaxed);
    let expiry = session.peer_not_after();
    {
        let mut map = lock(&mesh.links);
        if let Some(old) = map.insert(
            name.clone(),
            LiveLink {
                tx,
                cancel: cancel_tx,
                generation,
                ask_rekey: ask_tx,
            },
        ) {
            let _ = old.cancel.send(true);
        }
    }
    set_session(&mesh.peers, &name, true, Some(expiry));
    publish(&mesh.state_dir, &mesh.node, &mesh.peers, "up");
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
            ask_rekey: ask_rx,
            remote_rekey,
        },
        move || note_rx(&peers, &state_dir, &node, &peer_name),
    )
    .await;
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
    ask_rekey: watch::Receiver<u64>,
    remote_rekey: watch::Sender<u64>,
}

async fn drive_session(io: SessionIo, on_rx: impl Fn() + Send) {
    let SessionIo {
        mut sender,
        mut receiver,
        mut packets,
        mut cancel,
        to_tun,
        mut ask_rekey,
        remote_rekey,
    } = io;
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    return;
                }
            }
            changed = ask_rekey.changed() => {
                if changed.is_err() {
                    return;
                }
                if sender.send_ctrl(FLAG_REKEY_REQ).await.is_err() {
                    return;
                }
            }
            _ = keepalive.tick() => {
                if sender.send_ctrl(0).await.is_err() {
                    return;
                }
            }
            packet = packets.recv() => {
                let Some(packet) = packet else {
                    return;
                };
                if sender.send_ipv4(&packet).await.is_err() {
                    return;
                }
            }
            incoming = receiver.recv_event() => {
                match incoming {
                    Ok(SessionEvent::Packet(packet)) => {
                        on_rx();
                        if to_tun.send(packet).await.is_err() {
                            return;
                        }
                    }
                    Ok(SessionEvent::Keepalive) => on_rx(),
                    Ok(SessionEvent::Rekey) => {
                        on_rx();
                        let next = remote_rekey.borrow().saturating_add(1);
                        let _ = remote_rekey.send(next);
                    }
                    Err(_) => return,
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

struct DnsSpawn {
    interface: String,
    overlay: Ipv4Addr,
    netmap_path: PathBuf,
    node_name: String,
    node_overlay: String,
    visibility: Arc<dyn PeerVisibility>,
    shutdown: watch::Receiver<bool>,
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
    refresh_resolver(
        &dns.interface,
        dns.overlay,
        &table,
        dns.visibility.as_ref(),
        &guard.armed_flag(),
    );
    let (table_tx, table_rx) = watch::channel(table);
    let mut tasks = Vec::new();
    let serve_visibility = Arc::clone(&dns.visibility);
    let serve_shutdown = dns.shutdown.clone();
    let overlay = dns.overlay;
    tasks.push(tokio::spawn(async move {
        serve_dns(
            socket,
            table_rx,
            serve_visibility,
            Arc::new(ResolvConfForwarder::new(overlay)),
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
