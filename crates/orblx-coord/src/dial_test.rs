//! W25-28: the dial schedule to a dead peer after the fast dial window.
//!
//! These tests use real nodes on 127.0.0.1. A dead peer is a UDP socket that records each
//! datagram and does not answer. A handshake is one QUIC Initial destination connection ID.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_crypto::{mac_input, ticket_mac, TicketKey, TicketRing};
use orblx_datapath::{
    ipv4_packet, run_memory_node, AllowPeers, MemoryDevice, Netmap, NodeRequest, RenewedLeaf,
    SvidRenewer, NODE_STATUS_FILE,
};
use orblx_identity::{sign_ticket, SpiffeId, TicketClaims, TicketFlags, TicketSigner, TrustBundle};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::client;
use crate::server;
use crate::{Coordinator, EnrollResult, OidcConfig};

/// The fast dial window of the node plus the time limit of the last fast dial attempt.
const WINDOW_END: Duration = Duration::from_secs(13);
/// The longest time from outbound traffic or a netmap change to the session (W25-28).
const WAKE_LIMIT: Duration = Duration::from_secs(1);

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let mut raw = [0u8; 6];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
        let tag: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("orblx-dial-{label}-{tag}"));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.local_addr().unwrap().port()
}

/// One coordinator and the ticket keys for the leaf configs of the test nodes.
struct Rig {
    scratch: Scratch,
    addr: SocketAddr,
    bundle: String,
    coord: Coordinator,
    server: JoinHandle<()>,
    trust: TrustBundle,
    signer: TicketSigner,
    ring: TicketRing,
    now: SystemTime,
}

const MAC_KEY: [u8; 32] = [0x58; 32];

impl Rig {
    async fn new(label: &str) -> Self {
        let scratch = Scratch::new(label);
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let (addr, server) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
        let trust = TrustBundle::from_pem(&bundle).unwrap();
        let signer = TicketSigner::generate();
        let now = SystemTime::now();
        let key = TicketKey::new(
            signer.verifier(),
            MAC_KEY,
            now - Duration::from_secs(60),
            now + Duration::from_secs(3_600),
        )
        .unwrap();
        let ring = TicketRing::single(key, &[11; 32]).unwrap();
        Self {
            scratch,
            addr,
            bundle,
            coord,
            server,
            trust,
            signer,
            ring,
            now,
        }
    }

    async fn enroll(&self, name: &str, port: u16) -> EnrollResult {
        let token = self.coord.create_token(Duration::from_secs(600)).unwrap();
        client::enroll_with_token(
            self.addr,
            "coord",
            &self.bundle,
            name,
            &token.secret,
            &[format!("127.0.0.1:{port}")],
            &[],
        )
        .await
        .unwrap()
    }

    fn config(&self, enrolled: &EnrollResult) -> orblx_datapath::HelloConfig {
        let id = SpiffeId::node(&enrolled.name).unwrap();
        let start = self.now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let signed = sign_ticket(
            &self.signer,
            &TicketClaims {
                issuer: SpiffeId::coord("coord").unwrap(),
                subject: id,
                not_before: start,
                expires: start + 3_600,
                dst_cidr: "0.0.0.0/0".to_string(),
                proto: 0,
                dst_port: 0,
                flags: TicketFlags::none(),
            },
        )
        .unwrap();
        let mac = ticket_mac(&MAC_KEY, mac_input(&signed.bytes)).unwrap();
        orblx_datapath::HelloConfig::from_issued(
            &enrolled.certificate_pem,
            &enrolled.private_key_pem,
            self.trust.clone(),
            signed.bytes,
            mac,
            self.ring.clone(),
        )
    }

    fn renewer(&self, state: PathBuf) -> SvidRenewer {
        let addr = self.addr;
        let bundle = self.bundle.clone();
        SvidRenewer::new(move || {
            let result = client::renew_svid_blocking(addr, "coord", &bundle, &state)
                .map_err(|err| err.to_string())?;
            Ok(RenewedLeaf {
                certificate_pem: result.certificate_pem,
                private_key_pem: result.private_key_pem,
            })
        })
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.server.abort();
        let _ = &self.scratch;
    }
}

/// The netmap text of `name`. Each peer is (name, overlay address, UDP port).
fn netmap_text(name: &str, ip: &str, peers: &[(String, String, u16)]) -> String {
    let peers: Vec<String> = peers
        .iter()
        .map(|(peer, peer_ip, port)| {
            format!(
                r#"{{"name": "{peer}", "overlay_ip": "{peer_ip}", "svid": "spiffe://orblx.local/node/{peer}", "endpoints": ["127.0.0.1:{port}"], "routes": []}}"#
            )
        })
        .collect();
    format!(
        r#"{{"version": 1, "self": {{"name": "{name}", "overlay_ip": "{ip}"}}, "peers": [{}]}}"#,
        peers.join(", ")
    )
}

/// A running memory node.
struct TestNode {
    state: Scratch,
    to_node: mpsc::Sender<Vec<u8>>,
    from_node: mpsc::Receiver<Vec<u8>>,
    stop: watch::Sender<bool>,
    task: JoinHandle<Result<(), orblx_datapath::HelloError>>,
}

/// Trace points with Unix ms for the set-up window of a test (W25-28).
///
/// Each line shows the Unix ms and the ms after the clock of the test started.
#[derive(Clone, Copy)]
struct SetupTrace {
    test: &'static str,
    started: Instant,
}

impl SetupTrace {
    fn mark(self, point: &str) {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or(0);
        eprintln!(
            "setup_trace {} unix_ms {unix_ms} since_start_ms {} {point}",
            self.test,
            self.started.elapsed().as_millis()
        );
    }
}

fn mark(trace: Option<SetupTrace>, point: &str) {
    if let Some(trace) = trace {
        trace.mark(point);
    }
}

impl TestNode {
    fn start(rig: &Rig, state: Scratch, enrolled: &EnrollResult, port: u16, netmap: &str) -> Self {
        Self::start_traced(rig, state, enrolled, port, netmap, None)
    }

    /// Start a node. With `trace`, mark each set-up step. The steps before
    /// `run_memory_node` are test-only harness code.
    fn start_traced(
        rig: &Rig,
        state: Scratch,
        enrolled: &EnrollResult,
        port: u16,
        netmap: &str,
        trace: Option<SetupTrace>,
    ) -> Self {
        mark(trace, "harness write_state begin");
        enrolled.write_state(&state.0).unwrap();
        mark(trace, "harness write_state end");
        let netmap_path = state.0.join("netmap.json");
        mark(trace, "harness netmap_write begin");
        fs::write(&netmap_path, netmap).unwrap();
        mark(trace, "harness netmap_write end");
        mark(trace, "harness request_build begin");
        let (stop, stop_rx) = watch::channel(false);
        let (to_node, from_tun) = mpsc::channel(256);
        let (to_tun, from_node) = mpsc::channel(256);
        let request = NodeRequest {
            config: rig.config(enrolled),
            netmap: Netmap::from_slice(netmap.as_bytes()).unwrap(),
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            netmap_path,
            state_dir: state.0.clone(),
            renew: Some(rig.renewer(state.0.clone())),
            stop: Some(stop_rx),
            accept_routes: false,
            forward_routes: Vec::new(),
            forward_exit: false,
            exit_node: None,
            allow_lan: false,
            underlay: Vec::new(),
            relay: None,
            visibility: Arc::new(AllowPeers),
            on_ready: None,
            on_listen: None,
            metrics: None,
            filter: None,
        };
        mark(trace, "harness request_build end");
        mark(trace, "harness spawn begin");
        let task = tokio::spawn(async move {
            mark(trace, "product run_memory_node enter");
            run_memory_node(request, MemoryDevice { from_tun, to_tun }).await
        });
        mark(trace, "harness spawn end");
        Self {
            state,
            to_node,
            from_node,
            stop,
            task,
        }
    }

    fn direct_to(&self, peer: &str) -> bool {
        fs::read_to_string(self.state.0.join(NODE_STATUS_FILE)).is_ok_and(|text| {
            text.lines().any(|line| {
                line.starts_with(&format!("peer {peer} ")) && line.contains(" path direct ")
            })
        })
    }

    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

/// One datagram at a dead peer.
struct Seen {
    at: Duration,
    port: u16,
    /// The destination connection ID of a QUIC Initial packet.
    initial: Option<Vec<u8>>,
}

/// UDP sockets that record each datagram and do not answer.
struct DeadPeers {
    ports: Vec<u16>,
    seen: Arc<Mutex<Vec<Seen>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl DeadPeers {
    async fn bind(count: usize, zero: Instant) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut ports = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..count {
            let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let port = socket.local_addr().unwrap().port();
            ports.push(port);
            let seen = Arc::clone(&seen);
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                while let Ok((len, _)) = socket.recv_from(&mut buf).await {
                    let data = &buf[..len];
                    seen.lock().unwrap().push(Seen {
                        at: zero.elapsed(),
                        port,
                        initial: quic_initial_dcid(data),
                    });
                }
            }));
        }
        Self { ports, seen, tasks }
    }

    /// The first time of each handshake, sorted.
    fn handshake_starts(&self) -> Vec<Duration> {
        let mut first: HashMap<(u16, Vec<u8>), Duration> = HashMap::new();
        for seen in self.seen.lock().unwrap().iter() {
            if let Some(dcid) = &seen.initial {
                first.entry((seen.port, dcid.clone())).or_insert(seen.at);
            }
        }
        let mut starts: Vec<Duration> = first.into_values().collect();
        starts.sort();
        starts
    }
}

impl Drop for DeadPeers {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The destination connection ID of a QUIC v1 Initial packet, or `None`.
fn quic_initial_dcid(data: &[u8]) -> Option<Vec<u8>> {
    let first = *data.first()?;
    if first & 0x80 == 0 || (first & 0x30) >> 4 != 0 {
        return None;
    }
    let len = usize::from(*data.get(5)?);
    data.get(6..6 + len).map(<[u8]>::to_vec)
}

fn packet_to(dst_last: u8) -> Vec<u8> {
    ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, dst_last),
        b"w25-28",
    )
    .unwrap()
}

/// W25-28 gate 1: for 5 minutes, a dead peer gets no handshake after the fast window,
/// or one handshake each 60 s or more. The node logs each dial (see the test output).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_peer_gets_at_most_one_dial_per_minute_after_the_fast_window() {
    let run = Duration::from_secs(
        std::env::var("ORBLX_DEAD_PEER_SECS")
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(300),
    );
    let rig = Rig::new("dead").await;
    let port_a = free_port();
    let enrolled = rig.enroll("a", port_a).await;
    let zero = Instant::now();
    let dead = DeadPeers::bind(1, zero).await;
    let peers = vec![("b".to_string(), "100.64.0.2".to_string(), dead.ports[0])];
    let node = TestNode::start(
        &rig,
        Scratch::new("dead-a"),
        &enrolled,
        port_a,
        &netmap_text("a", "100.64.0.1", &peers),
    );
    tokio::time::sleep(run).await;
    node.stop().await;
    let starts = dead.handshake_starts();
    let in_window = starts.iter().filter(|at| **at <= WINDOW_END).count();
    let after: Vec<Duration> = starts.into_iter().filter(|at| *at > WINDOW_END).collect();
    let mut gaps = Vec::new();
    let mut last = WINDOW_END;
    for at in &after {
        gaps.push(at.saturating_sub(last));
        last = *at;
    }
    let packets = dead.seen.lock().unwrap().len();
    println!(
        "dead_peer run_s {} packets {packets} handshakes_in_window {in_window} handshakes_after_window {} after_window_at_s {:?} min_gap_s {:?}",
        run.as_secs(),
        after.len(),
        after.iter().map(|at| at.as_secs_f64()).collect::<Vec<_>>(),
        gaps.iter().min().map(Duration::as_secs_f64)
    );
    assert!(in_window > 0, "the node did not dial in the fast window");
    for gap in gaps {
        assert!(
            gap >= Duration::from_secs(60),
            "two dials after the fast window were {} s apart",
            gap.as_secs_f64()
        );
    }
}

/// Start node `a` with peer `b` at `port_b`, where nothing listens.
/// Wait to the end of the fast window. Then start `b` at `listen_b`.
/// The function returns node a, node b, and the rig.
async fn idle_pair(label: &str, port_b: u16, listen_b: u16) -> (Rig, TestNode, TestNode) {
    let rig = Rig::new(label).await;
    let port_a = free_port();
    let enrolled_a = rig.enroll("a", port_a).await;
    let enrolled_b = rig.enroll("b", listen_b).await;
    let peers_a = vec![("b".to_string(), "100.64.0.2".to_string(), port_b)];
    let peers_b = vec![("a".to_string(), "100.64.0.1".to_string(), port_a)];
    let node_a = TestNode::start(
        &rig,
        Scratch::new(&format!("{label}-a")),
        &enrolled_a,
        port_a,
        &netmap_text("a", "100.64.0.1", &peers_a),
    );
    tokio::time::sleep(WINDOW_END + Duration::from_secs(1)).await;
    let node_b = TestNode::start(
        &rig,
        Scratch::new(&format!("{label}-b")),
        &enrolled_b,
        listen_b,
        &netmap_text("b", "100.64.0.2", &peers_b),
    );
    // Node b listens. Node a waits after its fast window, so it does not dial b now.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !node_a.direct_to("b"),
        "node a dialed b after the fast window with no traffic and no netmap change"
    );
    (rig, node_a, node_b)
}

/// W25-28 gate 2: outbound traffic to a peer after the fast window starts a dial, and the
/// first packet reaches the peer in 1 s or less.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_traffic_dials_an_idle_peer_and_the_first_packet_arrives() {
    let port_b = free_port();
    let (_rig, node_a, mut node_b) = idle_pair("traffic", port_b, port_b).await;
    let sent = Instant::now();
    let mut reached = None;
    while sent.elapsed() < Duration::from_secs(5) {
        let _ = node_a.to_node.send(packet_to(2)).await;
        if let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(50), node_b.from_node.recv()).await
        {
            reached = Some(sent.elapsed());
            break;
        }
    }
    node_a.stop().await;
    node_b.stop().await;
    let reached = reached.expect("no packet reached b in 5 s after the traffic started");
    println!("traffic_redial first_packet_ms {}", reached.as_millis());
    assert!(
        reached <= WAKE_LIMIT,
        "the first packet came {} ms after the traffic started",
        reached.as_millis()
    );
}

/// W25-28 gate 2: a netmap change after the fast window starts a dial in 1 s or less.
/// The new netmap has the new endpoint of the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_netmap_change_dials_an_idle_peer_in_one_second() {
    let dead_port = free_port();
    let port_b = free_port();
    let (_rig, node_a, node_b) = idle_pair("netmap", dead_port, port_b).await;
    let peers_a = vec![("b".to_string(), "100.64.0.2".to_string(), port_b)];
    let written = Instant::now();
    fs::write(
        node_a.state.0.join("netmap.json"),
        netmap_text("a", "100.64.0.1", &peers_a),
    )
    .unwrap();
    let mut direct = None;
    while written.elapsed() < Duration::from_secs(5) {
        if node_a.direct_to("b") {
            direct = Some(written.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    node_a.stop().await;
    node_b.stop().await;
    let direct = direct.expect("node a had no session to b 5 s after the netmap change");
    println!("netmap_redial session_ms {}", direct.as_millis());
    assert!(
        direct <= WAKE_LIMIT,
        "the session came {} ms after the netmap change",
        direct.as_millis()
    );
}

/// W25-28 gate 3: with 50 offline peers, the node sends 100 packets per second or less
/// to them in the 0-10 s window (the mean of the window). The test also prints the packets
/// of each second. The first attempt of each peer is free of the probe budget, so the QUIC
/// resends of these 50 attempts at about 1 s and 3 s make the busiest seconds. A live peer in the same netmap gets its first packet
/// without a wait for the probe budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_offline_peers_stay_at_or_below_100_packets_per_second() {
    let rig = Rig::new("fifty").await;
    let port_a = free_port();
    let port_b = free_port();
    let enrolled_a = rig.enroll("a", port_a).await;
    let enrolled_b = rig.enroll("b", port_b).await;
    let zero = Instant::now();
    let dead = DeadPeers::bind(50, zero).await;
    let mut peers_a = vec![("b".to_string(), "100.64.0.2".to_string(), port_b)];
    for (index, port) in dead.ports.iter().enumerate() {
        peers_a.push((
            format!("p{index:02}"),
            format!("100.64.1.{}", index + 1),
            *port,
        ));
    }
    let peers_b = vec![("a".to_string(), "100.64.0.1".to_string(), port_a)];
    let mut node_b = TestNode::start(
        &rig,
        Scratch::new("fifty-b"),
        &enrolled_b,
        port_b,
        &netmap_text("b", "100.64.0.2", &peers_b),
    );
    let slept = Instant::now();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = Instant::now();
    let trace = SetupTrace {
        test: "fifty",
        started,
    };
    trace.mark(&format!(
        "harness sleep_500_end slept_ms {}",
        slept.elapsed().as_millis()
    ));
    mark(Some(trace), "harness scratch begin");
    let scratch_a = Scratch::new("fifty-a");
    let netmap_a = netmap_text("a", "100.64.0.1", &peers_a);
    mark(Some(trace), "harness scratch end");
    let node_a =
        TestNode::start_traced(&rig, scratch_a, &enrolled_a, port_a, &netmap_a, Some(trace));
    let mut live = None;
    let mut first_send = true;
    while started.elapsed() < Duration::from_secs(5) {
        let _ = node_a.to_node.send(packet_to(2)).await;
        if first_send {
            trace.mark("harness first_packet_sent");
            first_send = false;
        }
        if let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(20), node_b.from_node.recv()).await
        {
            live = Some(started.elapsed());
            trace.mark("harness live_packet_received");
            break;
        }
    }
    let offset = started.saturating_duration_since(zero);
    tokio::time::sleep(Duration::from_secs(11).saturating_sub(started.elapsed())).await;
    node_a.stop().await;
    node_b.stop().await;
    let seen: Vec<Duration> = dead
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|seen| seen.at.saturating_sub(offset))
        .collect();
    let mut per_second = vec![0usize; 10];
    for at in seen {
        if let Some(slot) = per_second.get_mut(usize::try_from(at.as_secs()).unwrap()) {
            *slot += 1;
        }
    }
    let total: usize = per_second.iter().sum();
    let handshakes = dead.handshake_starts().len();
    let live = live.expect("the live peer b got no packet in 5 s");
    println!(
        "fifty_offline packets_0_10s {total} pps_avg {:.1} pps_max_1s {} per_second {per_second:?} handshakes {handshakes} live_first_packet_ms {}",
        total as f64 / 10.0,
        per_second.iter().max().unwrap(),
        live.as_millis()
    );
    assert!(
        live <= Duration::from_millis(500),
        "the first packet to the live peer came after {} ms",
        live.as_millis()
    );
    assert!(
        total <= 1_000,
        "{total} packets to the offline peers in 0-10 s, more than 100 per second"
    );
}
