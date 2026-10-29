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
use std::time::Duration;

use orblx_identity::{decode_certificate_pem, extract_spiffe_id, leaf_not_after, SpiffeId};
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
use crate::quic::HelloEndpoint;
use crate::router::{route_packet, RouterTable};
use crate::tun_dev::{open_tun, TunConfig};
use crate::{HelloConfig, HelloError, HelloSession};

/// The node record file in the state directory.
pub const NODE_RECORD_FILE: &str = "node.json";

/// The pid file in the state directory.
pub const NODE_PID_FILE: &str = "orblxd.pid";

/// The status file in the state directory.
pub const NODE_STATUS_FILE: &str = "status.txt";

const PATH_DIRECT: &str = "direct";
const PATH_DOWN: &str = "down";

static LINK_GENERATION: AtomicU64 = AtomicU64::new(1);

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
    /// Install approved subnet routes from the netmap into the TUN device.
    pub accept_routes: bool,
    /// Local CIDRs this node forwards onto a connected LAN.
    pub forward_routes: Vec<String>,
    /// The netmap file. The node reads it again when the file changes.
    pub netmap_path: PathBuf,
    /// W18-5 replaces this hook. [`crate::AllowPeers`] allows every peer.
    pub visibility: Arc<dyn PeerVisibility>,
}

/// One peer line in `orblx status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPeer {
    /// The peer name.
    pub name: String,
    /// The peer overlay address.
    pub overlay_ip: String,
    /// `direct` or `down`.
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
    svid_expiry: u64,
}

struct PeerView {
    name: String,
    overlay_ip: String,
    svid: String,
    path: String,
    svid_expiry: Option<u64>,
}

struct LiveLink {
    tx: mpsc::Sender<Vec<u8>>,
    cancel: watch::Sender<bool>,
    generation: u64,
}

#[derive(Clone)]
struct Mesh {
    endpoint: Arc<HelloEndpoint>,
    netmap: Arc<Netmap>,
    node: Arc<NodeView>,
    links: Arc<Mutex<HashMap<String, LiveLink>>>,
    peers: Arc<Mutex<Vec<PeerView>>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    state_dir: Arc<PathBuf>,
    shutdown: watch::Receiver<bool>,
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
    let _pid_guard = PidGuard::create(&request.state_dir)?;
    let router = RouterTable::from_netmap(&request.netmap)
        .map_err(|err| HelloError::Node(err.to_string()))?;
    let install = router.install_cidrs(request.accept_routes);
    for cidr in &install {
        println!("The node installs route {cidr}.");
    }
    let bridge = open_tun(&TunConfig {
        name: tun_device_name(),
        address: parse_ipv4(&record.overlay_ip).map_err(|err| HelloError::Node(err.to_string()))?,
        netmask: Ipv4Addr::new(255, 255, 255, 255),
    })?;
    prepare_link(&bridge.name, &install)?;
    if !request.forward_routes.is_empty() {
        crate::subnet::enable_kernel_forward(&request.forward_routes)?;
    }
    println!("The overlay IP is {}.", record.overlay_ip);
    println!("The state directory is {}.", request.state_dir.display());
    println!("The TUN device is {}.", bridge.name);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    runtime.block_on(run_mesh(request, view, router, bridge))
}

async fn run_mesh(
    request: NodeRequest,
    view: NodeView,
    router: RouterTable,
    bridge: crate::TunBridge,
) -> Result<(), HelloError> {
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
    publish(&state_dir, &node, &lock(&peers), "up");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = Vec::<JoinHandle<()>>::new();

    let tun_shutdown = shutdown_rx.clone();
    let tun_router = Arc::clone(&router);
    let tun_links = Arc::clone(&links);
    let from_tun = bridge.from_tun;
    let accept_routes = request.accept_routes;
    tasks.push(tokio::spawn(async move {
        read_tun(from_tun, tun_router, tun_links, tun_shutdown, accept_routes).await;
    }));

    let netmap = Arc::new(request.netmap);
    let dns_shutdown = shutdown_rx.clone();
    let mesh = Mesh {
        endpoint: Arc::clone(&endpoint),
        netmap: Arc::clone(&netmap),
        node: Arc::clone(&node),
        links: Arc::clone(&links),
        peers: Arc::clone(&peers),
        to_tun: bridge.to_tun.clone(),
        state_dir: Arc::clone(&state_dir),
        shutdown: shutdown_rx,
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

    let overlay = parse_ipv4(&node.overlay_ip).map_err(|err| HelloError::Node(err.to_string()))?;
    let (resolver, dns_tasks) = spawn_overlay_dns(
        DnsSpawn {
            interface: bridge.name.clone(),
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

    wait_for_stop().await;
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
    publish(&state_dir, &node, &lock(&peers), "down");
    println!("The node is down.");
    drop(bridge.to_tun);
    Ok(())
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
    Ok(NodeView {
        name: request.netmap.self_node.name.clone(),
        overlay_ip: overlay.to_string(),
        svid: svid.as_uri().to_string(),
        svid_expiry: leaf_not_after(&der).map_err(HelloError::Identity)?,
    })
}

fn initial_peers(map: &Netmap) -> Vec<PeerView> {
    map.peers
        .iter()
        .map(|peer| PeerView {
            name: peer.name.clone(),
            overlay_ip: peer.overlay_ip.clone(),
            svid: peer.svid.clone(),
            path: PATH_DOWN.to_string(),
            svid_expiry: None,
        })
        .collect()
}

fn we_dial(self_name: &str, peer_name: &str) -> bool {
    self_name < peer_name
}

async fn wait_for_stop() {
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(err) => {
                eprintln!("The node did not install the stop handler. {err}");
                std::future::pending::<()>().await;
                return;
            }
        };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(err) = result {
                eprintln!("The node did not wait for SIGINT. {err}");
            }
        }
        _ = terminate.recv() => {}
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
                        tokio::spawn(async move {
                            run_link(
                                session,
                                peer_name,
                                link.links,
                                link.peers,
                                link.to_tun,
                                link.state_dir,
                                link.node,
                            )
                            .await;
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
    loop {
        if *mesh.shutdown.borrow() {
            return;
        }
        for endpoint_text in &peer.endpoints {
            if *mesh.shutdown.borrow() {
                return;
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
                        return;
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
                            run_link(
                                session,
                                peer.name.clone(),
                                Arc::clone(&mesh.links),
                                Arc::clone(&mesh.peers),
                                mesh.to_tun.clone(),
                                Arc::clone(&mesh.state_dir),
                                Arc::clone(&mesh.node),
                            )
                            .await;
                        }
                        Err(err) => {
                            eprintln!("The dial to {} at {addr} failed. {err}", peer.name);
                        }
                    }
                }
            }
        }
        tokio::select! {
            changed = mesh.shutdown.changed() => {
                if changed.is_err() || *mesh.shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn resolve_endpoint(text: &str) -> Result<SocketAddr, ()> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = tokio::net::lookup_host(text).await.map_err(|_| ())?;
    addrs.next().ok_or(())
}

async fn run_link(
    session: HelloSession,
    name: String,
    links: Arc<Mutex<HashMap<String, LiveLink>>>,
    peers: Arc<Mutex<Vec<PeerView>>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    state_dir: Arc<PathBuf>,
    node: Arc<NodeView>,
) {
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (tx, rx) = mpsc::channel(32);
    let generation = LINK_GENERATION.fetch_add(1, Ordering::Relaxed);
    let expiry = session.peer_not_after();
    {
        let mut map = lock(&links);
        if let Some(old) = map.insert(
            name.clone(),
            LiveLink {
                tx,
                cancel: cancel_tx,
                generation,
            },
        ) {
            let _ = old.cancel.send(true);
        }
    }
    set_peer(&peers, &name, PATH_DIRECT, Some(expiry));
    publish(&state_dir, &node, &lock(&peers), "up");
    println!("The path to {name} is direct.");
    let (sender, receiver) = session.split();
    drive_session(sender, receiver, rx, cancel_rx, to_tun).await;
    let removed = {
        let mut map = lock(&links);
        if map.get(&name).map(|link| link.generation) == Some(generation) {
            map.remove(&name);
            true
        } else {
            false
        }
    };
    if removed {
        set_peer(&peers, &name, PATH_DOWN, None);
        publish(&state_dir, &node, &lock(&peers), "up");
        println!("The path to {name} is down.");
    }
}

async fn drive_session(
    mut sender: crate::HelloSender,
    mut receiver: crate::HelloReceiver,
    mut packets: mpsc::Receiver<Vec<u8>>,
    mut cancel: watch::Receiver<bool>,
    to_tun: mpsc::Sender<Vec<u8>>,
) {
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
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
            incoming = receiver.recv_ipv4() => {
                match incoming {
                    Ok(packet) => {
                        if to_tun.send(packet).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        }
    }
}

fn set_peer(peers: &Mutex<Vec<PeerView>>, name: &str, path: &str, expiry: Option<u64>) {
    let mut peers = lock(peers);
    if let Some(peer) = peers.iter_mut().find(|peer| peer.name == name) {
        peer.path = path.to_string();
        peer.svid_expiry = expiry;
    }
}

fn publish(dir: &Path, node: &NodeView, peers: &[PeerView], state: &str) {
    let status = NodeStatus {
        state: state.to_string(),
        name: node.name.clone(),
        overlay_ip: node.overlay_ip.clone(),
        svid: node.svid.clone(),
        svid_expiry: node.svid_expiry,
        peers: peers
            .iter()
            .map(|peer| StatusPeer {
                name: peer.name.clone(),
                overlay_ip: peer.overlay_ip.clone(),
                path: peer.path.clone(),
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
    loop {
        tokio::select! {
            changed = watch_state.shutdown.changed() => {
                if changed.is_err() || *watch_state.shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
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
}
