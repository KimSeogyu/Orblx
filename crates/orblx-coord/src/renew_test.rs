use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_crypto::{mac_input, ticket_mac, TicketKey, TicketRing};
use orblx_datapath::{
    ipv4_packet, run_memory_node, AllowPeers, HelloEndpoint, ListenEvent, MemoryDevice, Netmap,
    NodeRequest, RenewedLeaf, SvidRenewer, NODE_STATUS_FILE,
};
use orblx_identity::{
    decode_certificate_pem, leaf_validity, sign_ticket, SpiffeId, TicketClaims, TicketFlags,
    TicketSigner, TrustBundle,
};
use tokio::sync::{mpsc, watch};

use crate::client;
use crate::server;
use crate::{Coordinator, OidcConfig};

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let mut raw = [0u8; 6];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
        let path = std::env::temp_dir().join(format!("orblx-renew-{label}-{}", hex(&raw)));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::new();
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.local_addr().unwrap().port()
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::test]
async fn renew_replaces_the_leaf_and_keeps_the_address() {
    let scratch = Scratch::new("api");
    let node = Scratch::new("api-node");
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.set_node_svid_ttl(Duration::from_secs(60)).unwrap();
    let token = coord.create_token(Duration::from_secs(600)).unwrap();
    let (addr, handle) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let first = client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "server-a",
        &token.secret,
        &["127.0.0.1:443".to_string()],
        &[],
    )
    .await
    .unwrap();
    first.write_state(&node.0).unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let renewed = client::renew_svid(addr, "coord", &bundle, &node.0)
        .await
        .unwrap();
    assert_eq!(renewed.overlay_ip, "100.64.0.1");
    assert_eq!(renewed.name, "server-a");
    assert_ne!(renewed.certificate_pem, first.certificate_pem);
    assert!(!format!("{renewed:?}").contains("PRIVATE"));
    let der = decode_certificate_pem(&renewed.certificate_pem).unwrap();
    let (not_before, not_after) = leaf_validity(&der).unwrap();
    assert_eq!(not_after.saturating_sub(not_before), 60);
    let stored = fs::read_to_string(node.0.join("node.key.pem")).unwrap();
    assert_eq!(stored, renewed.private_key_pem);
    let failed = client::renew_svid(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        "coord",
        &bundle,
        &node.0,
    )
    .await
    .unwrap_err();
    let text = failed.to_string();
    assert!(!text.contains("PRIVATE"));
    assert!(!text.contains("BEGIN"));
    assert!(!text.contains(&token.secret));
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_stays_up_for_three_svid_lifetimes() {
    const LIFE_SECS: u64 = 60;
    const PROBE_MS: u64 = 20;
    const RENEW_GAP_LIMIT: Duration = Duration::from_millis(200);
    let scratch = Scratch::new("life");
    let node_a = Scratch::new("life-a");
    let node_b = Scratch::new("life-b");
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord
        .set_node_svid_ttl(Duration::from_secs(LIFE_SECS))
        .unwrap();
    let token_a = coord.create_token(Duration::from_secs(600)).unwrap();
    let token_b = coord.create_token(Duration::from_secs(600)).unwrap();
    let (addr, handle) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let issued_at = Instant::now();
    let port_a = free_port();
    let port_b = free_port();
    let enrolled_a = client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "a",
        &token_a.secret,
        &[format!("127.0.0.1:{port_a}")],
        &[],
    )
    .await
    .unwrap();
    let enrolled_b = client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "b",
        &token_b.secret,
        &[format!("127.0.0.1:{port_b}")],
        &[],
    )
    .await
    .unwrap();
    enrolled_a.write_state(&node_a.0).unwrap();
    enrolled_b.write_state(&node_b.0).unwrap();

    let trust = TrustBundle::from_pem(&bundle).unwrap();
    let signer = TicketSigner::generate();
    let mac_key = [0x44; 32];
    let now = SystemTime::now();
    let ticket_key = TicketKey::new(
        signer.verifier(),
        mac_key,
        now - Duration::from_secs(60),
        now + Duration::from_secs(3_600),
    )
    .unwrap();
    let ring = TicketRing::single(ticket_key, &[7; 32]).unwrap();
    let config_a = leaf_config(&enrolled_a, &trust, &signer, &mac_key, &ring, now);
    let config_b = leaf_config(&enrolled_b, &trust, &signer, &mac_key, &ring, now);
    let map_a = netmap("a", "100.64.0.1", "b", "100.64.0.2", port_b);
    let map_b = netmap("b", "100.64.0.2", "a", "100.64.0.1", port_a);

    let renewals = Arc::new(Mutex::new(Vec::new()));
    let (stop_tx, stop_a) = watch::channel(false);
    let stop_b = stop_a.clone();
    let (a_in_tx, a_in_rx) = mpsc::channel(64);
    let (a_out_tx, mut a_out_rx) = mpsc::channel(64);
    let (b_in_tx, b_in_rx) = mpsc::channel(64);
    let (b_out_tx, mut b_out_rx) = mpsc::channel(64);

    let task_a = tokio::spawn(run_memory_node(
        node_request(
            config_a,
            map_a,
            port_a,
            node_a.0.clone(),
            renewer(
                addr,
                bundle.clone(),
                node_a.0.clone(),
                Arc::clone(&renewals),
            ),
            stop_a,
        ),
        MemoryDevice {
            from_tun: a_in_rx,
            to_tun: a_out_tx,
        },
    ));
    let task_b = tokio::spawn(run_memory_node(
        node_request(
            config_b,
            map_b,
            port_b,
            node_b.0.clone(),
            renewer(
                addr,
                bundle.clone(),
                node_b.0.clone(),
                Arc::clone(&renewals),
            ),
            stop_b,
        ),
        MemoryDevice {
            from_tun: b_in_rx,
            to_tun: b_out_tx,
        },
    ));

    // The stall probe shares the runtime with the nodes and the coordinator. A late tick
    // shows that the runtime thread did not run, so the gap is not in the datapath.
    let max_stall = Arc::new(Mutex::new(Duration::ZERO));
    let stall_probe = tokio::spawn(stall_probe(Arc::clone(&max_stall)));
    // The OS stall probe runs on its own thread, outside the runtime. A stall that both probes
    // see at the same time is a host stall (the thread did not get a CPU), not blocking code.
    let os_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let max_os_stall = Arc::new(Mutex::new(Duration::ZERO));
    let os_probe = {
        let (stop, max) = (Arc::clone(&os_stop), Arc::clone(&max_os_stall));
        std::thread::spawn(move || os_stall_probe(&stop, &max))
    };

    let mut last_ab: Option<Instant> = None;
    let mut last_ba: Option<Instant> = None;
    let mut max_gap = Duration::ZERO;
    let mut gaps = Vec::new();
    let mut got_ab = 0u64;
    let mut got_ba = 0u64;
    let mut saw_direct = false;
    let mut expiries = HashSet::new();
    let limit = Duration::from_secs(LIFE_SECS * 3 + 8);
    let mut round = 0u64;
    let mut status_read: Option<tokio::task::JoinHandle<(std::io::Result<String>, u128)>> = None;
    while issued_at.elapsed() < limit {
        // One probe each way every 20 ms, so a 200 ms gap shows as about 10 lost probes.
        let _ = a_in_tx
            .send(
                ipv4_packet(
                    Ipv4Addr::new(100, 64, 0, 1),
                    Ipv4Addr::new(100, 64, 0, 2),
                    b"ab",
                )
                .unwrap(),
            )
            .await;
        let _ = b_in_tx
            .send(
                ipv4_packet(
                    Ipv4Addr::new(100, 64, 0, 2),
                    Ipv4Addr::new(100, 64, 0, 1),
                    b"ba",
                )
                .unwrap(),
            )
            .await;
        let tick = tokio::time::Instant::now() + Duration::from_millis(PROBE_MS);
        loop {
            tokio::select! {
                got = b_out_rx.recv() => {
                    if got.is_some() {
                        note_gap("ab", &mut last_ab, &mut max_gap, &mut gaps);
                        got_ab += 1;
                    }
                }
                got = a_out_rx.recv() => {
                    if got.is_some() {
                        note_gap("ba", &mut last_ba, &mut max_gap, &mut gaps);
                        got_ba += 1;
                    }
                }
                () = tokio::time::sleep_until(tick) => break,
            }
        }
        round += 1;
        // W25-11: the status file read runs on a blocking thread. A slow disk read must not
        // stop this loop, because then the loop sends no probes and sees a false gap.
        if status_read.as_ref().is_some_and(|read| read.is_finished()) {
            let (read, read_ms) = status_read.take().unwrap().await.unwrap();
            if read_ms >= 20 {
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();
                eprintln!("trace {ms} test slow_io op=status_read ms={read_ms}");
            }
            if let Ok(text) = read {
                if text.contains("path direct ") {
                    saw_direct = true;
                }
                if let Some(value) = text
                    .lines()
                    .find_map(|line| line.strip_prefix("svid_expiry "))
                {
                    expiries.insert(value.to_string());
                }
            }
        }
        if status_read.is_none() && round.is_multiple_of(10) {
            let path = node_a.0.join(NODE_STATUS_FILE);
            status_read = Some(tokio::task::spawn_blocking(move || {
                let read_started = Instant::now();
                let read = fs::read_to_string(path);
                (read, read_started.elapsed().as_millis())
            }));
        }
        if last_ab.is_some() && last_ba.is_some() && max_gap > Duration::from_secs(2) {
            break;
        }
    }
    stall_probe.abort();
    os_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = os_probe.join();
    let max_stall = *max_stall.lock().unwrap();
    let max_os_stall = *max_os_stall.lock().unwrap();
    let renewals = renewals.lock().unwrap().clone();
    let renew_gap = renewal_max_gap(&gaps, &renewals);
    println!(
        "renew_gap_summary probe_ms {PROBE_MS} ab {got_ab} ba {got_ba} max_gap_ms {} renewals {} renewal_max_gap_ms {} runtime_max_stall_ms {} os_max_stall_ms {} expiries {}",
        max_gap.as_millis(),
        renewals.len(),
        renew_gap.as_millis(),
        max_stall.as_millis(),
        max_os_stall.as_millis(),
        expiries.len()
    );

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), task_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), task_b).await;
    handle.abort();

    assert!(
        got_ab > 100 && got_ba > 100,
        "packets a-to-b {got_ab} b-to-a {got_ba}"
    );
    assert!(
        max_gap <= Duration::from_secs(2),
        "packet gap {} ms",
        max_gap.as_millis()
    );
    assert!(
        renewals.len() >= 4,
        "renew calls {} over three lifetimes",
        renewals.len()
    );
    assert!(
        renew_gap <= RENEW_GAP_LIMIT,
        "packet gap {} ms at an SVID renewal",
        renew_gap.as_millis()
    );
    assert!(saw_direct, "status did not report path direct");
    assert!(
        expiries.len() >= 3,
        "svid expiries {expiries:?} over three lifetimes"
    );
}

/// The times of one late peer case (W25-6c).
///
/// `listener` is the listener start event that node `b` logs itself.
struct LatePeerTimes {
    enroll_to_listener: Option<Duration>,
    listener_to_first_packet: Option<Duration>,
    enroll_to_first_packet: Option<Duration>,
}

/// The late peer gate: the first packet from `a` comes to `b` 2 s or less after `b` starts
/// its UDP listener. The start is the listener start event of node `b`.
fn late_peer_gate(times: &LatePeerTimes) -> Result<(), String> {
    let limit = Duration::from_secs(2);
    match times.listener_to_first_packet {
        None => Err("no packet came from node a after the listener of b started".to_string()),
        Some(took) if took > limit => Err(format!(
            "the first packet came {} ms after the listener of b started (limit {} ms)",
            took.as_millis(),
            limit.as_millis()
        )),
        Some(_) => Ok(()),
    }
}

/// Node `a` runs first. Node `b` enrolls later, so `a` gets `b` from a new netmap.
///
/// `before_listen` delays the start of node `b` after its enrollment, before its listener starts.
/// `after_listen` stops node `b` in its listener start hook, before it accepts or dials.
/// Both are test-only. The node daemon has no delay.
async fn late_peer_case(
    tag: &str,
    before_listen: Duration,
    after_listen: Duration,
) -> LatePeerTimes {
    let scratch = Scratch::new("late");
    let node_a = Scratch::new("late-a");
    let node_b = Scratch::new("late-b");
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let (addr, handle) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let port_a = free_port();
    let port_b = free_port();
    let token_a = coord.create_token(Duration::from_secs(600)).unwrap();
    let enrolled_a = client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "a",
        &token_a.secret,
        &[format!("127.0.0.1:{port_a}")],
        &[],
    )
    .await
    .unwrap();
    enrolled_a.write_state(&node_a.0).unwrap();
    let map_a = Netmap::from_path(&node_a.0.join("netmap.json")).unwrap();
    assert!(map_a.peers.is_empty());

    let trust = TrustBundle::from_pem(&bundle).unwrap();
    let signer = TicketSigner::generate();
    let mac_key = [0x45; 32];
    let now = SystemTime::now();
    let ticket_key = TicketKey::new(
        signer.verifier(),
        mac_key,
        now - Duration::from_secs(60),
        now + Duration::from_secs(3_600),
    )
    .unwrap();
    let ring = TicketRing::single(ticket_key, &[8; 32]).unwrap();
    let config_a = leaf_config(&enrolled_a, &trust, &signer, &mac_key, &ring, now);
    let (stop_tx, stop_a) = watch::channel(false);
    let stop_b = stop_a.clone();
    let (a_in_tx, a_in_rx) = mpsc::channel(64);
    let (a_out_tx, _a_out_rx) = mpsc::channel(64);
    let (_b_in_tx, b_in_rx) = mpsc::channel(64);
    let (b_out_tx, mut b_out_rx) = mpsc::channel(64);
    let task_a = tokio::spawn(run_memory_node(
        node_request(
            config_a,
            map_a,
            port_a,
            node_a.0.clone(),
            renewer(
                addr,
                bundle.clone(),
                node_a.0.clone(),
                Arc::new(Mutex::new(Vec::new())),
            ),
            stop_a,
        ),
        MemoryDevice {
            from_tun: a_in_rx,
            to_tun: a_out_tx,
        },
    ));
    let sync_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sync = {
        let (stop, bundle, dir) = (Arc::clone(&sync_stop), bundle.clone(), node_a.0.clone());
        tokio::task::spawn_blocking(move || {
            let mut etag: Option<String> = None;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                match client::fetch_policy_wait_blocking(
                    addr,
                    "coord",
                    &bundle,
                    &dir,
                    etag.as_deref(),
                ) {
                    Ok(next) => {
                        if etag.as_deref() != Some(next.etag.as_str()) {
                            next.view.write_state(&dir).unwrap();
                        }
                        etag = Some(next.etag);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(100)),
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;

    let enrolled_at = Instant::now();
    let token_b = coord.create_token(Duration::from_secs(600)).unwrap();
    let token_done = Instant::now();
    let (enrolled_b, close_waits) = with_close_waits(client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "b",
        &token_b.secret,
        &[format!("127.0.0.1:{port_b}")],
        &[],
    ))
    .await;
    let enrolled_b = enrolled_b.unwrap();
    let enroll_done = Instant::now();
    enrolled_b.write_state(&node_b.0).unwrap();
    let state_done = Instant::now();
    let map_b = Netmap::from_path(&node_b.0.join("netmap.json")).unwrap();
    let netmap_done = Instant::now();
    let config_b = leaf_config(&enrolled_b, &trust, &signer, &mac_key, &ring, now);
    let config_done = Instant::now();
    if !before_listen.is_zero() {
        tokio::time::sleep(before_listen).await;
    }
    let listened = Arc::new(Mutex::new(None::<ListenEvent>));
    let mut request_b = node_request(
        config_b,
        map_b,
        port_b,
        node_b.0.clone(),
        renewer(
            addr,
            bundle.clone(),
            node_b.0.clone(),
            Arc::new(Mutex::new(Vec::new())),
        ),
        stop_b,
    );
    let hook = Arc::clone(&listened);
    request_b.on_listen = Some(Box::new(move |event| {
        *hook.lock().unwrap() = Some(event);
        if !after_listen.is_zero() {
            std::thread::sleep(after_listen);
        }
    }));
    let spawn_at = Instant::now();
    let task_b = tokio::spawn(run_memory_node(
        request_b,
        MemoryDevice {
            from_tun: b_in_rx,
            to_tun: b_out_tx,
        },
    ));
    let marks = StartMarks {
        enroll_start: enrolled_at,
        token_done,
        enroll_done,
        close_waits,
        state_done,
        netmap_done,
        config_done,
        spawn_at,
    };
    let mut first_packet = None;
    let wait = before_listen + after_listen + Duration::from_secs(8);
    while enrolled_at.elapsed() < wait {
        let _ = a_in_tx
            .send(
                ipv4_packet(
                    Ipv4Addr::new(100, 64, 0, 1),
                    Ipv4Addr::new(100, 64, 0, 2),
                    b"late",
                )
                .unwrap(),
            )
            .await;
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(50), b_out_rx.recv()).await
        {
            first_packet = Some(Instant::now());
            break;
        }
    }
    sync_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), task_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), task_b).await;
    handle.abort();
    let _ = tokio::time::timeout(Duration::from_secs(25), sync).await;
    let listener = *listened.lock().unwrap();
    if let Some(event) = listener {
        // Report only (W25-21).
        println!("late_peer {tag} {}", startup_phases(&marks, &event).line());
    }
    let times = LatePeerTimes {
        enroll_to_listener: listener.map(|event| event.at.saturating_duration_since(enrolled_at)),
        listener_to_first_packet: match (listener, first_packet) {
            (Some(event), Some(at)) => Some(at.saturating_duration_since(event.at)),
            _ => None,
        },
        enroll_to_first_packet: first_packet.map(|at| at.saturating_duration_since(enrolled_at)),
    };
    let ms = |value: Option<Duration>| {
        value.map_or_else(|| "none".to_string(), |took| took.as_millis().to_string())
    };
    // Report only. The gate uses listener_to_first_packet.
    println!(
        "late_peer {tag} enroll_to_listener_ms {}",
        ms(times.enroll_to_listener)
    );
    println!(
        "late_peer {tag} enroll_to_first_packet_ms {}",
        ms(times.enroll_to_first_packet)
    );
    // The gate line.
    println!(
        "late_peer {tag} listener_to_first_packet_ms {} limit_ms 2000",
        ms(times.listener_to_first_packet)
    );
    times
}

/// The harness times of one node start, from the enroll call to the spawn of the node (W25-21).
struct StartMarks {
    enroll_start: Instant,
    token_done: Instant,
    enroll_done: Instant,
    /// The close-wait times of the enroll call (client::CLOSE_WAITS).
    close_waits: Vec<Duration>,
    state_done: Instant,
    netmap_done: Instant,
    config_done: Instant,
    spawn_at: Instant,
}

/// The start-up phases from the enroll call to the listener start (W25-21).
///
/// The harness gives the times up to the spawn. The node gives the other times in its
/// listener start event.
#[derive(Clone, Copy, Debug)]
struct StartupPhases {
    /// The coordinator makes the enroll token (the harness, not the node).
    token: Duration,
    /// The enroll call up to the reply: connect, handshake, request and reply.
    enroll_call: Duration,
    /// The enroll call after the reply: the close and the endpoint wait (up to 2 s).
    close_wait: Duration,
    write_state: Duration,
    netmap_read: Duration,
    leaf_config: Duration,
    /// A test delay before the spawn. It is zero without an injected delay.
    harness_wait: Duration,
    spawn_to_node: Duration,
    prepare: Duration,
    to_bind: Duration,
    bind: Duration,
    total: Duration,
}

/// The phases of [`StartupPhases`] in time order, with their names.
const PHASES: [(&str, PhaseField); 12] = [
    ("token", |p| p.token),
    ("enroll_call", |p| p.enroll_call),
    ("close_wait", |p| p.close_wait),
    ("write_state", |p| p.write_state),
    ("netmap_read", |p| p.netmap_read),
    ("leaf_config", |p| p.leaf_config),
    ("harness_wait", |p| p.harness_wait),
    ("spawn_to_node", |p| p.spawn_to_node),
    ("prepare", |p| p.prepare),
    ("to_bind", |p| p.to_bind),
    ("bind", |p| p.bind),
    ("total", |p| p.total),
];

impl StartupPhases {
    fn line(&self) -> String {
        let mut text = "startup_ms".to_string();
        for (name, field) in PHASES {
            text.push_str(&format!(
                " {name} {:.1}",
                field(self).as_secs_f64() * 1000.0
            ));
        }
        text
    }
}

/// One phase of [`StartupPhases`].
type PhaseField = fn(&StartupPhases) -> Duration;

fn startup_phases(marks: &StartMarks, event: &ListenEvent) -> StartupPhases {
    let span = |from: Instant, to: Instant| to.saturating_duration_since(from);
    let call = span(marks.token_done, marks.enroll_done);
    let close_wait = marks.close_waits.iter().sum::<Duration>().min(call);
    StartupPhases {
        token: span(marks.enroll_start, marks.token_done),
        enroll_call: call - close_wait,
        close_wait,
        write_state: span(marks.enroll_done, marks.state_done),
        netmap_read: span(marks.state_done, marks.netmap_done),
        leaf_config: span(marks.netmap_done, marks.config_done),
        harness_wait: span(marks.config_done, marks.spawn_at),
        spawn_to_node: span(marks.spawn_at, event.phases.entered_at),
        prepare: span(event.phases.entered_at, event.phases.prepared_at),
        to_bind: span(event.phases.prepared_at, event.bind_at),
        bind: span(event.bind_at, event.at),
        total: span(marks.enroll_start, event.at),
    }
}

/// Runs a coordinator call and returns its result and the close-wait times of its calls.
async fn with_close_waits<T>(call: impl std::future::Future<Output = T>) -> (T, Vec<Duration>) {
    client::CLOSE_WAITS
        .scope(std::cell::RefCell::new(Vec::new()), async {
            let out = call.await;
            let waits = client::CLOSE_WAITS.with(|waits| waits.borrow().clone());
            (out, waits)
        })
        .await
}

/// W25-21 measurement: `ORBLX_STARTUP_RUNS` node starts (default 10), each from the enroll
/// call to the listener start, with a new coordinator for each run.
///
/// Run it with `cargo test -p orblx-coord --lib -- --ignored --nocapture startup_cost_runs`.
/// The gate: the median of the enroll-to-listener time is 1 s or less.
/// A median above 2 s prints an alert line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement: run it on demand under the proof lock"]
async fn startup_cost_runs() {
    let runs: usize = std::env::var("ORBLX_STARTUP_RUNS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(10);
    assert!(runs > 0, "ORBLX_STARTUP_RUNS must be 1 or more");
    let mut all = Vec::new();
    for run in 1..=runs {
        let phases = startup_cost_once().await;
        println!("startup_cost run {run} {}", phases.line());
        all.push(phases);
    }
    let pick = |field: PhaseField, q: f64| {
        let mut values: Vec<Duration> = all.iter().map(field).collect();
        values.sort();
        // Nearest rank.
        let rank = ((q * values.len() as f64).ceil() as usize).clamp(1, values.len());
        values[rank - 1]
    };
    let median = |field: PhaseField| {
        let mut values: Vec<Duration> = all.iter().map(field).collect();
        values.sort();
        let n = values.len();
        if n % 2 == 1 {
            values[n / 2]
        } else {
            (values[n / 2 - 1] + values[n / 2]) / 2
        }
    };
    for (name, field) in PHASES {
        println!(
            "startup_cost phase {name} median_ms {:.1} p95_ms {:.1} max_ms {:.1}",
            median(field).as_secs_f64() * 1000.0,
            pick(field, 0.95).as_secs_f64() * 1000.0,
            pick(field, 1.0).as_secs_f64() * 1000.0
        );
    }
    let total = median(|p| p.total);
    println!(
        "startup_cost summary runs {runs} enroll_to_listener median_ms {} p95_ms {} max_ms {} limit_ms 1000",
        total.as_millis(),
        pick(|p| p.total, 0.95).as_millis(),
        pick(|p| p.total, 1.0).as_millis()
    );
    if total > Duration::from_secs(2) {
        println!(
            "startup_cost alert median_ms {} is more than 2000 ms",
            total.as_millis()
        );
    }
    // ORBLX_STARTUP_REPORT_ONLY=1 is for the busy CI runner: it prints the numbers and does
    // not apply the idle-box gate.
    if std::env::var("ORBLX_STARTUP_REPORT_ONLY").as_deref() == Ok("1") {
        println!("startup_cost report_only: the idle-box gate is not applied");
        return;
    }
    assert!(
        total <= Duration::from_secs(1),
        "the enroll-to-listener median is {} ms, more than 1000 ms",
        total.as_millis()
    );
}

/// One node start from the enroll call to the listener start. The node then stops.
async fn startup_cost_once() -> StartupPhases {
    let scratch = Scratch::new("start");
    let node_dir = Scratch::new("start-n");
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let (addr, handle) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let trust = TrustBundle::from_pem(&bundle).unwrap();
    let signer = TicketSigner::generate();
    let mac_key = [0x47; 32];
    let now = SystemTime::now();
    let ticket_key = TicketKey::new(
        signer.verifier(),
        mac_key,
        now - Duration::from_secs(60),
        now + Duration::from_secs(3_600),
    )
    .unwrap();
    let ring = TicketRing::single(ticket_key, &[7; 32]).unwrap();
    let port = free_port();
    let enroll_start = Instant::now();
    let token = coord.create_token(Duration::from_secs(600)).unwrap();
    let token_done = Instant::now();
    let (enrolled, close_waits) = with_close_waits(client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "b",
        &token.secret,
        &[format!("127.0.0.1:{port}")],
        &[],
    ))
    .await;
    let enrolled = enrolled.unwrap();
    let enroll_done = Instant::now();
    enrolled.write_state(&node_dir.0).unwrap();
    let state_done = Instant::now();
    let map = Netmap::from_path(&node_dir.0.join("netmap.json")).unwrap();
    let netmap_done = Instant::now();
    let config = leaf_config(&enrolled, &trust, &signer, &mac_key, &ring, now);
    let config_done = Instant::now();
    let (stop_tx, stop) = watch::channel(false);
    let (listen_tx, listen_rx) = tokio::sync::oneshot::channel::<ListenEvent>();
    let mut request = node_request(
        config,
        map,
        port,
        node_dir.0.clone(),
        renewer(addr, bundle.clone(), node_dir.0.clone()),
        stop,
    );
    request.on_listen = Some(Box::new(move |event| {
        let _ = listen_tx.send(event);
    }));
    let (_in_tx, in_rx) = mpsc::channel(64);
    let (out_tx, _out_rx) = mpsc::channel(64);
    let spawn_at = Instant::now();
    let task = tokio::spawn(run_memory_node(
        request,
        MemoryDevice {
            from_tun: in_rx,
            to_tun: out_tx,
        },
    ));
    let event = tokio::time::timeout(Duration::from_secs(30), listen_rx)
        .await
        .expect("node b did not start its listener in 30 s")
        .expect("node b ended before its listener started");
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    handle.abort();
    let marks = StartMarks {
        enroll_start,
        token_done,
        enroll_done,
        close_waits,
        state_done,
        netmap_done,
        config_done,
        spawn_at,
    };
    startup_phases(&marks, &event)
}

/// W25-6 and W25-6c: a peer that enrolls after a node started is reachable 2 s or less
/// after its UDP listener starts.
///
/// Node a runs with a netmap that has no peer. A sync loop does what `orblx up --coord`
/// does: it waits with `policy-wait` and writes the new files. Then b enrolls and starts.
/// Node a must add b from the new netmap file and dial b. No node restarts.
/// The start of the gate is the listener start event that node b logs itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_enrolls_later_is_reachable_in_two_seconds() {
    let times = late_peer_case("gate", Duration::ZERO, Duration::ZERO).await;
    if let Err(why) = late_peer_gate(&times) {
        panic!("the late peer gate failed: {why}");
    }
}

/// W25-6c negative test: a stop of 2.5 s after the listener of b starts, before b accepts,
/// makes the gate fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_late_peer_gate_fails_when_the_peer_stops_after_its_listener_starts() {
    let stop = Duration::from_millis(2_500);
    let times = late_peer_case("stop_after_listen", Duration::ZERO, stop).await;
    let took = times
        .listener_to_first_packet
        .expect("no packet came after the stop");
    assert!(
        took >= stop,
        "the first packet came {} ms after the listener",
        took.as_millis()
    );
    assert!(
        late_peer_gate(&times).is_err(),
        "the gate passed with a 2.5 s stop after the listener start"
    );
}

/// W25-6c negative test: a delay of 2.5 s before the listener of b starts does not make
/// the gate fail. The enroll-to-listener line shows the delay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_late_peer_gate_passes_when_the_listener_of_the_peer_starts_late() {
    let delay = Duration::from_millis(2_500);
    let times = late_peer_case("delay_before_listen", delay, Duration::ZERO).await;
    let to_listener = times
        .enroll_to_listener
        .expect("node b did not start its listener");
    assert!(
        to_listener >= delay,
        "enroll to listener was {} ms, less than the delay",
        to_listener.as_millis()
    );
    if let Err(why) = late_peer_gate(&times) {
        panic!("the late peer gate failed: {why}");
    }
}

/// W25-6b: a dial to a peer that starts to listen late ends soon after the peer listens.
///
/// A peer can enroll, and so be in the netmap of a node, before its UDP listener is up.
/// QUIC sends the Initial packet of one attempt again only after about 1 s and then 2 s more.
/// The probed connect starts one more attempt each 250 ms, so the dial does not wait for that backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_to_a_peer_that_listens_late_ends_soon_after_it_listens() {
    let scratch = Scratch::new("probe");
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let (addr, handle) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let trust = TrustBundle::from_pem(&bundle).unwrap();
    let signer = TicketSigner::generate();
    let mac_key = [0x46; 32];
    let now = SystemTime::now();
    let ticket_key = TicketKey::new(
        signer.verifier(),
        mac_key,
        now - Duration::from_secs(60),
        now + Duration::from_secs(3_600),
    )
    .unwrap();
    let ring = TicketRing::single(ticket_key, &[9; 32]).unwrap();
    let mut configs = Vec::new();
    for name in ["a", "b"] {
        let token = coord.create_token(Duration::from_secs(600)).unwrap();
        let port = free_port();
        let enrolled = client::enroll_with_token(
            addr,
            "coord",
            &bundle,
            name,
            &token.secret,
            &[format!("127.0.0.1:{port}")],
            &[],
        )
        .await
        .unwrap();
        configs.push(leaf_config(
            &enrolled, &trust, &signer, &mac_key, &ring, now,
        ));
    }
    let config_b = configs.pop().unwrap();
    let config_a = configs.pop().unwrap();
    let dialer = Arc::new(
        HelloEndpoint::bind_node(config_a, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap(),
    );
    let late = Duration::from_millis(1_200);
    let port_b = free_port();
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port_b));
    let listener = tokio::spawn(async move {
        tokio::time::sleep(late).await;
        let endpoint = HelloEndpoint::bind_node(config_b, target).unwrap();
        let listening = Instant::now();
        let session = endpoint.accept_one().await.unwrap();
        (listening, session, endpoint)
    });
    let started = Instant::now();
    let session = tokio::time::timeout(
        Duration::from_secs(3),
        dialer.connect_probed(target, Duration::from_millis(250)),
    )
    .await
    .expect("the probed dial did not end in 3 s")
    .unwrap();
    let dialed = Instant::now();
    let (listening, _accepted, _endpoint) = listener.await.unwrap();
    handle.abort();
    let after_listen = dialed.saturating_duration_since(listening);
    println!(
        "probed_dial_ms {} after_listen_ms {}",
        dialed.duration_since(started).as_millis(),
        after_listen.as_millis()
    );
    assert_eq!(session.peer_id().as_uri(), "spiffe://orblx.local/node/b");
    assert!(
        after_listen <= Duration::from_millis(800),
        "the dial ended {} ms after the peer listened",
        after_listen.as_millis()
    );
}

/// W25-6b: node `a` dials peer `b`, and `b` starts `late` after the dial task of `a` starts.
///
/// The delay is the test condition: it puts the listener of `b` after the first dial of `a`.
/// The function returns the time from the start of node `b` (before its UDP bind)
/// to the first packet from `a` at `b`, or `None` when no packet came in `late` + 8 s.
async fn late_listener_case(tag: &str, late: Duration) -> Option<Duration> {
    let scratch = Scratch::new(&format!("lateL-{tag}"));
    let node_a = Scratch::new(&format!("lateL-{tag}-a"));
    let node_b = Scratch::new(&format!("lateL-{tag}-b"));
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let (addr, handle) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let port_a = free_port();
    let port_b = free_port();
    let mut enrolled = Vec::new();
    for (name, port) in [("a", port_a), ("b", port_b)] {
        let token = coord.create_token(Duration::from_secs(600)).unwrap();
        let result = client::enroll_with_token(
            addr,
            "coord",
            &bundle,
            name,
            &token.secret,
            &[format!("127.0.0.1:{port}")],
            &[],
        )
        .await
        .unwrap();
        enrolled.push(result);
    }
    enrolled[0].write_state(&node_a.0).unwrap();
    enrolled[1].write_state(&node_b.0).unwrap();
    let trust = TrustBundle::from_pem(&bundle).unwrap();
    let signer = TicketSigner::generate();
    let mac_key = [0x47; 32];
    let now = SystemTime::now();
    let ticket_key = TicketKey::new(
        signer.verifier(),
        mac_key,
        now - Duration::from_secs(60),
        now + Duration::from_secs(3_600),
    )
    .unwrap();
    let ring = TicketRing::single(ticket_key, &[10; 32]).unwrap();
    let config_a = leaf_config(&enrolled[0], &trust, &signer, &mac_key, &ring, now);
    let config_b = leaf_config(&enrolled[1], &trust, &signer, &mac_key, &ring, now);
    let map_a = netmap("a", "100.64.0.1", "b", "100.64.0.2", port_b);
    let map_b = netmap("b", "100.64.0.2", "a", "100.64.0.1", port_a);

    let (stop_tx, stop_a) = watch::channel(false);
    let stop_b = stop_a.clone();
    let (a_in_tx, a_in_rx) = mpsc::channel(64);
    let (a_out_tx, _a_out_rx) = mpsc::channel(64);
    let (_b_in_tx, b_in_rx) = mpsc::channel(64);
    let (b_out_tx, mut b_out_rx) = mpsc::channel(64);
    let task_a = tokio::spawn(run_memory_node(
        node_request(
            config_a,
            map_a,
            port_a,
            node_a.0.clone(),
            renewer(
                addr,
                bundle.clone(),
                node_a.0.clone(),
                Arc::new(Mutex::new(Vec::new())),
            ),
            stop_a,
        ),
        MemoryDevice {
            from_tun: a_in_rx,
            to_tun: a_out_tx,
        },
    ));
    tokio::time::sleep(late).await;
    let started_b = Instant::now();
    let task_b = tokio::spawn(run_memory_node(
        node_request(
            config_b,
            map_b,
            port_b,
            node_b.0.clone(),
            renewer(
                addr,
                bundle.clone(),
                node_b.0.clone(),
                Arc::new(Mutex::new(Vec::new())),
            ),
            stop_b,
        ),
        MemoryDevice {
            from_tun: b_in_rx,
            to_tun: b_out_tx,
        },
    ));
    let mut reached = None;
    while started_b.elapsed() < Duration::from_secs(8) {
        let _ = a_in_tx
            .send(
                ipv4_packet(
                    Ipv4Addr::new(100, 64, 0, 1),
                    Ipv4Addr::new(100, 64, 0, 2),
                    b"late",
                )
                .unwrap(),
            )
            .await;
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(50), b_out_rx.recv()).await
        {
            reached = Some(started_b.elapsed());
            break;
        }
    }
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), task_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), task_b).await;
    handle.abort();
    reached
}

/// W25-6b: a peer that starts to listen 0 s, 1.5 s, or 4.5 s after the first dial is reachable
/// in 2 s or less after it starts.
///
/// With one QUIC attempt for each dial (the path before W25-6b), the 1.5 s and 4.5 s cases
/// wait for the next dial after the 3 s attempt limit and a 1 s pause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_listener_is_reachable_in_two_seconds_after_it_starts() {
    let mut results = Vec::new();
    for late_ms in [0u64, 1_500, 4_500] {
        let reached =
            late_listener_case(&late_ms.to_string(), Duration::from_millis(late_ms)).await;
        println!(
            "late_listener late_ms {late_ms} reach_after_start_ms {}",
            reached.map_or("none".to_string(), |time| time.as_millis().to_string())
        );
        results.push((late_ms, reached));
    }
    for (late_ms, reached) in results {
        let reached = reached.unwrap_or_else(|| panic!("late {late_ms} ms: no packet in 8 s"));
        assert!(
            reached <= Duration::from_secs(2),
            "late {late_ms} ms: the peer was reachable {} ms after it started",
            reached.as_millis()
        );
    }
}

/// W25-6b soak: `ORBLX_LATE_SOAK_RUNS` runs (default 50) with delays from 0 s to 5 s, spread evenly.
///
/// Run it with `cargo test -p orblx-coord --lib -- --ignored --nocapture late_listener_soak`.
/// Each run must reach the peer 2 s or less after it starts. The test runs all cases first and then
/// fails if one or more cases failed, so the output has the full table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "soak: about 50 node pairs, run it on demand"]
async fn late_listener_soak() {
    let runs: u64 = std::env::var("ORBLX_LATE_SOAK_RUNS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(50)
        .max(2);
    let mut failures = 0;
    for run in 0..runs {
        let late_ms = run * 5_000 / (runs - 1);
        let reached =
            late_listener_case(&format!("soak{run}"), Duration::from_millis(late_ms)).await;
        let ok = reached.is_some_and(|time| time <= Duration::from_secs(2));
        if !ok {
            failures += 1;
        }
        println!(
            "late_soak run {} late_ms {late_ms} reach_after_start_ms {} result {}",
            run + 1,
            reached.map_or("none".to_string(), |time| time.as_millis().to_string()),
            if ok { "ok" } else { "FAIL" }
        );
    }
    println!("late_soak runs {runs} failures {failures}");
    assert_eq!(
        failures, 0,
        "{failures} of {runs} late listener runs failed"
    );
}

/// The renewal window: from 1 s before a renew call to 3 s after it (W25-11).
const RENEW_WINDOW_BEFORE: Duration = Duration::from_secs(1);
const RENEW_WINDOW_AFTER: Duration = Duration::from_secs(3);

/// Return the largest gap that overlaps one renewal window.
fn renewal_max_gap(gaps: &[(Instant, Instant)], renewals: &[Instant]) -> Duration {
    gaps.iter()
        .filter(|(prev, now)| {
            renewals.iter().any(|start| {
                let from = start.checked_sub(RENEW_WINDOW_BEFORE).unwrap_or(*start);
                let to = *start + RENEW_WINDOW_AFTER;
                *prev < to && *now > from
            })
        })
        .map(|(prev, now)| now.saturating_duration_since(*prev))
        .max()
        .unwrap_or(Duration::ZERO)
}

/// Tick every 5 ms and keep the largest delay of a tick. Trace a delay over 100 ms.
async fn stall_probe(max_stall: Arc<Mutex<Duration>>) {
    let step = Duration::from_millis(5);
    let mut last = Instant::now();
    loop {
        tokio::time::sleep(step).await;
        let now = Instant::now();
        let late = now.saturating_duration_since(last).saturating_sub(step);
        if late > Duration::from_millis(100) {
            let ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            eprintln!("trace {ms} test stall ms={}", late.as_millis());
        }
        {
            let mut max = max_stall.lock().unwrap();
            if late > *max {
                *max = late;
            }
        }
        last = now;
    }
}

/// The same probe on an OS thread. Trace a delay over 100 ms.
fn os_stall_probe(stop: &std::sync::atomic::AtomicBool, max_stall: &Mutex<Duration>) {
    let step = Duration::from_millis(5);
    let mut last = Instant::now();
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(step);
        let now = Instant::now();
        let late = now.saturating_duration_since(last).saturating_sub(step);
        if late > Duration::from_millis(100) {
            let ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            eprintln!("trace {ms} test os_stall ms={}", late.as_millis());
        }
        {
            let mut max = max_stall.lock().unwrap();
            if late > *max {
                *max = late;
            }
        }
        last = now;
    }
}

fn note_gap(
    dir: &str,
    last: &mut Option<Instant>,
    max_gap: &mut Duration,
    gaps: &mut Vec<(Instant, Instant)>,
) {
    let now = Instant::now();
    if let Some(prev) = *last {
        let gap = now.saturating_duration_since(prev);
        if gap > Duration::from_millis(40) {
            gaps.push((prev, now));
        }
        if gap > Duration::from_millis(100) {
            let ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            eprintln!("trace {ms} test gap dir={dir} ms={}", gap.as_millis());
        }
        if gap > *max_gap {
            *max_gap = gap;
        }
    }
    *last = Some(now);
}

/// A renewer that also notes the time of each renew call.
fn renewer(
    addr: SocketAddr,
    bundle: String,
    state: PathBuf,
    calls: Arc<Mutex<Vec<Instant>>>,
) -> SvidRenewer {
    SvidRenewer::new(move || {
        calls.lock().unwrap().push(Instant::now());
        let result = client::renew_svid_blocking(addr, "coord", &bundle, &state)
            .map_err(|err| err.to_string())?;
        Ok(RenewedLeaf {
            certificate_pem: result.certificate_pem,
            private_key_pem: result.private_key_pem,
        })
    })
}

fn node_request(
    config: orblx_datapath::HelloConfig,
    netmap: Netmap,
    port: u16,
    state_dir: PathBuf,
    renew: SvidRenewer,
    stop: watch::Receiver<bool>,
) -> NodeRequest {
    NodeRequest {
        config,
        netmap,
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        netmap_path: state_dir.join("netmap.json"),
        state_dir,
        renew: Some(renew),
        stop: Some(stop),
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
    }
}

fn leaf_config(
    enrolled: &crate::EnrollResult,
    trust: &TrustBundle,
    signer: &TicketSigner,
    mac_key: &[u8; 32],
    ring: &TicketRing,
    now: SystemTime,
) -> orblx_datapath::HelloConfig {
    let id = SpiffeId::node(&enrolled.name).unwrap();
    let start = unix(now);
    let signed = sign_ticket(
        signer,
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
    let mac = ticket_mac(mac_key, mac_input(&signed.bytes)).unwrap();
    orblx_datapath::HelloConfig::from_issued(
        &enrolled.certificate_pem,
        &enrolled.private_key_pem,
        trust.clone(),
        signed.bytes,
        mac,
        ring.clone(),
    )
}

fn netmap(name: &str, ip: &str, peer: &str, peer_ip: &str, peer_port: u16) -> Netmap {
    let text = format!(
        r#"{{
            "version": 1,
            "self": {{"name": "{name}", "overlay_ip": "{ip}"}},
            "peers": [{{
                "name": "{peer}",
                "overlay_ip": "{peer_ip}",
                "svid": "spiffe://orblx.local/node/{peer}",
                "endpoints": ["127.0.0.1:{peer_port}"],
                "routes": []
            }}]
        }}"#
    );
    Netmap::from_slice(text.as_bytes()).unwrap()
}
