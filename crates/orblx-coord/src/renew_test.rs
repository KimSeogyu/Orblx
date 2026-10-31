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
    TicketSigner, TrustBundle, MAX_SKEW,
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
            renewer(addr, bundle.clone(), node_a.0.clone()),
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
            renewer(addr, bundle.clone(), node_b.0.clone()),
            stop_b,
        ),
        MemoryDevice {
            from_tun: b_in_rx,
            to_tun: b_out_tx,
        },
    ));

    let mut last_ab: Option<Instant> = None;
    let mut last_ba: Option<Instant> = None;
    let mut max_gap = Duration::ZERO;
    let mut got_ab = 0u64;
    let mut got_ba = 0u64;
    let mut saw_direct = false;
    let mut expiries = HashSet::new();
    let limit = Duration::from_secs(LIFE_SECS * 3 + 8);
    while issued_at.elapsed() < limit {
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
        let slice_end = Instant::now() + Duration::from_millis(200);
        while Instant::now() < slice_end {
            if let Ok(Some(_)) =
                tokio::time::timeout(Duration::from_millis(20), b_out_rx.recv()).await
            {
                note_gap(&mut last_ab, &mut max_gap);
                got_ab += 1;
            }
            if let Ok(Some(_)) =
                tokio::time::timeout(Duration::from_millis(20), a_out_rx.recv()).await
            {
                note_gap(&mut last_ba, &mut max_gap);
                got_ba += 1;
            }
        }
        if let Ok(text) = fs::read_to_string(node_a.0.join(NODE_STATUS_FILE)) {
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
        if last_ab.is_some() && last_ba.is_some() && max_gap > Duration::from_secs(2) {
            break;
        }
    }

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
            renewer(addr, bundle.clone(), node_a.0.clone()),
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
        renewer(addr, bundle.clone(), node_b.0.clone()),
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
    // Node b binds port 0 itself and reports the real port in the listen event. A port from
    // free_port() is free only until its socket drops, and a parallel test can take it then
    // (CI startup-cost run 41138247996: "node b ended before its listener started").
    // Node b has no peer here, so no node dials the endpoint that it enrolls with.
    let unused_endpoint = "127.0.0.1:9";
    let enroll_start = Instant::now();
    let token = coord.create_token(Duration::from_secs(600)).unwrap();
    let token_done = Instant::now();
    let (enrolled, close_waits) = with_close_waits(client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "b",
        &token.secret,
        &[unused_endpoint.to_string()],
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
        0,
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
    let event = match tokio::time::timeout(Duration::from_secs(30), listen_rx)
        .await
        .expect("node b did not start its listener in 30 s")
    {
        Ok(event) => event,
        // The node dropped the listen callback, so it ended. Show its own error.
        Err(_) => {
            let ended = tokio::time::timeout(Duration::from_secs(3), task).await;
            panic!("node b ended before its listener started: {ended:?}");
        }
    };
    assert_ne!(event.addr.port(), 0, "node b reported no bound port");
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
            renewer(addr, bundle.clone(), node_a.0.clone()),
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
            renewer(addr, bundle.clone(), node_b.0.clone()),
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

fn note_gap(last: &mut Option<Instant>, max_gap: &mut Duration) {
    let now = Instant::now();
    if let Some(prev) = *last {
        let gap = now.saturating_duration_since(prev);
        if gap > *max_gap {
            *max_gap = gap;
        }
    }
    *last = Some(now);
}

fn renewer(addr: SocketAddr, bundle: String, state: PathBuf) -> SvidRenewer {
    SvidRenewer::new(move || {
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

/// W25-33: the coordinator issues a new leaf at two thirds of the life, from the same CA.
#[test]
fn coordinator_leaf_renews_at_two_thirds_from_the_same_ca() {
    let scratch = Scratch::new("coordleaf");
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord.set_coord_svid_ttl(Duration::from_secs(9)).unwrap();
    let first = coord.tls_material().unwrap();
    let first_der = decode_certificate_pem(&first.certificate_pem).unwrap();
    let (not_before, not_after) = leaf_validity(&first_der).unwrap();
    assert_eq!(not_after - not_before, 9);
    let start = UNIX_EPOCH + Duration::from_secs(not_before);
    assert_eq!(
        coord
            .renew_coord_svid_if_due(start + Duration::from_secs(5))
            .unwrap(),
        None
    );
    let renewed = coord
        .renew_coord_svid_if_due(start + Duration::from_secs(6))
        .unwrap()
        .unwrap();
    assert_eq!(renewed, not_before + 6 + 9);
    let second = coord.tls_material().unwrap();
    assert_eq!(second.trust_pem, first.trust_pem);
    assert_ne!(second.certificate_pem, first.certificate_pem);
    let second_der = decode_certificate_pem(&second.certificate_pem).unwrap();
    let trust = TrustBundle::from_pem(&first.trust_pem).unwrap();
    let id = trust
        .authenticate_leaf(
            &second_der,
            start + Duration::from_secs(14),
            &orblx_identity::DenySet::empty(),
        )
        .unwrap();
    assert_eq!(id, SpiffeId::coord("coord").unwrap());
    assert!(coord
        .set_coord_svid_ttl(Duration::from_secs(15 * 60 + 1))
        .is_err());
}

/// W25-33: the coordinator renews its own leaf, and the nodes keep their sessions.
///
/// The coordinator leaf lives 10 s. The node leaf lives 60 s. The test runs for 95 s, so it
/// crosses more than 3 coordinator leaf ends and the first end plus [`MAX_SKEW`]. A probe node
/// calls the coordinator once a second. Node `c` stays offline across coordinator rotations,
/// then comes back, renews, and reaches `a`. Before the fix, the coordinator showed one leaf
/// for its whole life. After the end plus the skew, each coordinator call failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_renew_across_coordinator_cert_ends() {
    const COORD_LIFE: u64 = 10;
    const NODE_LIFE: u64 = 60;
    const C_START: Duration = Duration::from_secs(50);
    const RUN: Duration = Duration::from_secs(95);
    const LATE: Duration = Duration::from_secs(85);
    let scratch = Scratch::new("coordcert");
    let dirs: Vec<Scratch> = ["a", "b", "c", "p"]
        .iter()
        .map(|name| Scratch::new(&format!("coordcert-{name}")))
        .collect();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    coord
        .set_coord_svid_ttl(Duration::from_secs(COORD_LIFE))
        .unwrap();
    coord
        .set_node_svid_ttl(Duration::from_secs(NODE_LIFE))
        .unwrap();
    let (addr, handle) = server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let issued_at = Instant::now();
    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let mut enrolled = Vec::new();
    for (at, name) in ["a", "b", "c", "p"].iter().enumerate() {
        let token = coord.create_token(Duration::from_secs(600)).unwrap();
        let endpoint = format!("127.0.0.1:{}", ports.get(at).copied().unwrap_or(1));
        let result = client::enroll_with_token(
            addr,
            "coord",
            &bundle,
            name,
            &token.secret,
            &[endpoint],
            &[],
        )
        .await
        .unwrap();
        result.write_state(&dirs[at].0).unwrap();
        enrolled.push(result);
    }
    let first_coord_end = coord.coord_svid_not_after().unwrap();

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
    let ips = ["100.64.0.1", "100.64.0.2", "100.64.0.3"];
    let names = ["a", "b", "c"];
    let renew_fail = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut requests = Vec::new();
    for at in 0..3 {
        let config = leaf_config(&enrolled[at], &trust, &signer, &mac_key, &ring, now);
        let peers: Vec<(&str, &str, u16)> = (0..3)
            .filter(|other| *other != at)
            .map(|other| (names[other], ips[other], ports[other]))
            .collect();
        let map = mesh_netmap(names[at], ips[at], &peers);
        let request = node_request(
            config,
            map,
            ports[at],
            dirs[at].0.clone(),
            counted_renewer(
                addr,
                bundle.clone(),
                dirs[at].0.clone(),
                Arc::clone(&renew_fail),
            ),
            stop_rx.clone(),
        );
        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, out_rx) = mpsc::channel(64);
        inputs.push(in_tx);
        outputs.push(out_rx);
        requests.push((
            request,
            MemoryDevice {
                from_tun: in_rx,
                to_tun: out_tx,
            },
        ));
    }
    let mut requests = requests.into_iter();
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let (request, device) = requests.next().unwrap();
        tasks.push(tokio::spawn(run_memory_node(request, device)));
    }
    let mut late_c = requests.next();
    let mut c_started: Option<Instant> = None;

    let mut coord_ends = HashSet::new();
    let mut expiries: Vec<HashSet<String>> = vec![HashSet::new(); 3];
    let mut last_ab: Option<Instant> = None;
    let mut last_ba: Option<Instant> = None;
    let mut max_gap = Duration::ZERO;
    let (mut got_ab, mut got_ba, mut got_ca, mut got_ac) = (0u64, 0u64, 0u64, 0u64);
    let (mut late_ab, mut late_ba) = (0u64, 0u64);
    let (mut probes, mut probe_fail) = (0u64, 0u64);
    let mut probe_renewals = 0u64;
    let mut next_probe = Instant::now();
    let probe_dir = dirs[3].0.clone();
    let mut probe_leaf =
        leaf_validity(&decode_certificate_pem(&enrolled[3].certificate_pem).unwrap()).unwrap();
    let send = |from: usize, to: usize, body: &'static [u8]| {
        ipv4_packet(
            ips[from].parse::<Ipv4Addr>().unwrap(),
            ips[to].parse::<Ipv4Addr>().unwrap(),
            body,
        )
        .unwrap()
    };
    while issued_at.elapsed() < RUN {
        if c_started.is_none() && issued_at.elapsed() >= C_START {
            if let Some((request, device)) = late_c.take() {
                tasks.push(tokio::spawn(run_memory_node(request, device)));
                c_started = Some(Instant::now());
            }
        }
        let _ = inputs[0].send(send(0, 1, b"ab")).await;
        let _ = inputs[1].send(send(1, 0, b"ba")).await;
        if c_started.is_some() {
            let _ = inputs[2].send(send(2, 0, b"ca")).await;
            let _ = inputs[0].send(send(0, 2, b"ac")).await;
        }
        let late = issued_at.elapsed() >= LATE;
        let slice_end = Instant::now() + Duration::from_millis(200);
        while Instant::now() < slice_end {
            if let Ok(Some(packet)) =
                tokio::time::timeout(Duration::from_millis(20), outputs[1].recv()).await
            {
                if packet.ends_with(b"ab") {
                    note_gap(&mut last_ab, &mut max_gap);
                    got_ab += 1;
                    late_ab += u64::from(late);
                }
            }
            if let Ok(Some(packet)) =
                tokio::time::timeout(Duration::from_millis(20), outputs[0].recv()).await
            {
                if packet.ends_with(b"ba") {
                    note_gap(&mut last_ba, &mut max_gap);
                    got_ba += 1;
                    late_ba += u64::from(late);
                } else if packet.ends_with(b"ca") {
                    got_ca += 1;
                }
            }
            if let Ok(Some(packet)) =
                tokio::time::timeout(Duration::from_millis(5), outputs[2].recv()).await
            {
                if packet.ends_with(b"ac") {
                    got_ac += 1;
                }
            }
        }
        coord_ends.insert(coord.coord_svid_not_after().unwrap());
        for at in 0..3 {
            if let Ok(text) = fs::read_to_string(dirs[at].0.join(NODE_STATUS_FILE)) {
                if let Some(value) = text
                    .lines()
                    .find_map(|line| line.strip_prefix("svid_expiry "))
                {
                    expiries[at].insert(value.to_string());
                }
            }
        }
        if Instant::now() >= next_probe {
            next_probe = Instant::now() + Duration::from_secs(1);
            probes += 1;
            let now_unix = unix(SystemTime::now());
            let (not_before, not_after) = probe_leaf;
            if now_unix >= not_before + (not_after - not_before) * 2 / 3 {
                match client::renew_svid(addr, "coord", &bundle, &probe_dir).await {
                    Ok(renewed) => {
                        probe_renewals += 1;
                        probe_leaf = leaf_validity(
                            &decode_certificate_pem(&renewed.certificate_pem).unwrap(),
                        )
                        .unwrap();
                    }
                    Err(err) => {
                        probe_fail += 1;
                        println!("coord probe renew failed: {err}");
                    }
                }
            } else if let Err(err) = client::fetch_netmap(addr, "coord", &bundle, &probe_dir).await
            {
                probe_fail += 1;
                println!("coord probe netmap failed: {err}");
            }
        }
    }
    let _ = stop_tx.send(true);
    for task in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }
    handle.abort();

    let end_unix = unix(SystemTime::now());
    let crossed = coord_ends.iter().filter(|end| **end < end_unix).count();
    let renew_fail = renew_fail.load(std::sync::atomic::Ordering::Relaxed);
    println!(
        "coord_cert_ends_crossed {crossed} first_end_plus_skew_crossed {} probes {probes} \
         probe_fail {probe_fail} probe_renewals {probe_renewals} node_renew_fail {renew_fail} \
         expiries a {} b {} c {} ab {got_ab} ba {got_ba} late_ab {late_ab} late_ba {late_ba} \
         ca {got_ca} ac {got_ac} max_gap_ms {}",
        end_unix > first_coord_end + MAX_SKEW.as_secs(),
        expiries[0].len(),
        expiries[1].len(),
        expiries[2].len(),
        max_gap.as_millis()
    );
    assert!(
        end_unix > first_coord_end + MAX_SKEW.as_secs(),
        "the run did not cross the first coordinator leaf end plus the skew"
    );
    assert_eq!(probe_fail, 0, "coordinator probe failures");
    assert_eq!(renew_fail, 0, "node renewal failures");
    assert!(crossed >= 3, "coordinator leaf ends crossed {crossed}");
    assert!(probes >= 60, "coordinator probes {probes}");
    assert!(probe_renewals >= 1, "the probe node did not renew");
    assert!(
        expiries[0].len() >= 3 && expiries[1].len() >= 3,
        "node a and b leaf expiries {:?} {:?}",
        expiries[0],
        expiries[1]
    );
    assert!(
        expiries[2].len() >= 2,
        "node c did not renew after it came back: {:?}",
        expiries[2]
    );
    assert!(
        got_ab > 100 && got_ba > 100,
        "packets a-to-b {got_ab} b-to-a {got_ba}"
    );
    assert!(
        late_ab > 0 && late_ba > 0,
        "late packets a-to-b {late_ab} b-to-a {late_ba}"
    );
    assert!(
        got_ca > 20 && got_ac > 20,
        "packets c-to-a {got_ca} a-to-c {got_ac}"
    );
    assert!(
        max_gap <= Duration::from_secs(2),
        "packet gap {} ms",
        max_gap.as_millis()
    );
}

fn counted_renewer(
    addr: SocketAddr,
    bundle: String,
    state: PathBuf,
    failures: Arc<std::sync::atomic::AtomicU64>,
) -> SvidRenewer {
    SvidRenewer::new(move || {
        let result =
            client::renew_svid_blocking(addr, "coord", &bundle, &state).map_err(|err| {
                failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                err.to_string()
            })?;
        Ok(RenewedLeaf {
            certificate_pem: result.certificate_pem,
            private_key_pem: result.private_key_pem,
        })
    })
}

fn mesh_netmap(name: &str, ip: &str, peers: &[(&str, &str, u16)]) -> Netmap {
    let peers = peers
        .iter()
        .map(|(peer, peer_ip, port)| {
            format!(
                r#"{{"name": "{peer}", "overlay_ip": "{peer_ip}",
                    "svid": "spiffe://orblx.local/node/{peer}",
                    "endpoints": ["127.0.0.1:{port}"], "routes": []}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let text = format!(
        r#"{{"version": 1, "self": {{"name": "{name}", "overlay_ip": "{ip}"}}, "peers": [{peers}]}}"#
    );
    Netmap::from_slice(text.as_bytes()).unwrap()
}
