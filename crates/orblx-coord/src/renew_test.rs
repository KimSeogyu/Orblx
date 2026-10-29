use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_crypto::{mac_input, ticket_mac, TicketKey, TicketRing};
use orblx_datapath::{
    ipv4_packet, run_memory_node, AllowPeers, MemoryDevice, Netmap, NodeRequest, RenewedLeaf,
    SvidRenewer, NODE_STATUS_FILE,
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
        metrics: None,
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
