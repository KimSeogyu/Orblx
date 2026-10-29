use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use super::sni::{read_tls_record, tls_server_name};
use super::{fail, SPOKE_OVERLAY};
use crate::ipv4::{
    decode_tcp_segment, encode_tcp_segment, TcpSegment, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH,
};
use crate::{HelloError, HelloSession};

const CHUNK: usize = 8192;
const DATA_FLAGS: u8 = TCP_FLAG_PSH | TCP_FLAG_ACK;
const FIN_FLAGS: u8 = TCP_FLAG_FIN | TCP_FLAG_ACK;

/// One app listener behind the hub.
#[derive(Clone, Copy)]
pub(crate) struct HubApp {
    pub overlay_port: u16,
    pub backend: SocketAddr,
}

/// One HTTPS name on the spoke.
pub(crate) struct SpokeRoute {
    pub host: String,
    pub overlay: Ipv4Addr,
    pub overlay_port: u16,
}

/// Counts of payload-bearing DATA frames for each overlay address.
#[derive(Default)]
pub(crate) struct MeshCounts {
    to_overlay: Mutex<HashMap<Ipv4Addr, u64>>,
    from_overlay: Mutex<HashMap<Ipv4Addr, u64>>,
}

impl MeshCounts {
    pub(crate) fn record_to(&self, addr: Ipv4Addr) {
        let mut map = lock_map(&self.to_overlay);
        *map.entry(addr).or_insert(0) += 1;
    }

    pub(crate) fn record_from(&self, addr: Ipv4Addr) {
        let mut map = lock_map(&self.from_overlay);
        *map.entry(addr).or_insert(0) += 1;
    }

    pub(crate) fn count_to(&self, addr: Ipv4Addr) -> u64 {
        lock_map(&self.to_overlay).get(&addr).copied().unwrap_or(0)
    }

    pub(crate) fn count_from(&self, addr: Ipv4Addr) -> u64 {
        lock_map(&self.from_overlay)
            .get(&addr)
            .copied()
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    spoke_port: u16,
    app: Ipv4Addr,
    app_port: u16,
}

enum DownMsg {
    Data(Vec<u8>),
    Fin,
}

#[derive(Clone, Copy)]
struct SegmentEnds {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

/// Forward overlay TCP segments to the app listeners.
///
/// The session is the one bidirectional QUIC stream.
pub(crate) async fn relay_hub(
    session: HelloSession,
    apps: HashMap<Ipv4Addr, HubApp>,
) -> Result<(), HelloError> {
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(128);
    let mut flows: HashMap<FlowKey, mpsc::Sender<DownMsg>> = HashMap::new();
    let (mut sender, mut receiver) = session.split();
    loop {
        tokio::select! {
            packet = out_rx.recv() => {
                let Some(packet) = packet else {
                    break;
                };
                sender.send_ipv4(&packet).await?;
            }
            incoming = receiver.recv_ipv4() => {
                let packet = match incoming {
                    Ok(packet) => packet,
                    Err(HelloError::StreamClosed) => break,
                    Err(err) => return Err(err),
                };
                accept_from_spoke(&apps, &mut flows, &out_tx, &packet).await;
            }
        }
    }
    Ok(())
}

/// Accept browser TCP connections and carry them on the mesh.
///
/// The session is the one bidirectional QUIC stream.
pub(crate) async fn relay_spoke(
    session: HelloSession,
    ingress: TcpListener,
    routes: Arc<[SpokeRoute]>,
    stats: Arc<MeshCounts>,
) -> Result<(), HelloError> {
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(128);
    let flows = Arc::new(Mutex::new(HashMap::<FlowKey, mpsc::Sender<DownMsg>>::new()));
    let ports = Arc::new(AtomicU16::new(40_000));
    let (mut sender, mut receiver) = session.split();
    loop {
        tokio::select! {
            packet = out_rx.recv() => {
                let Some(packet) = packet else {
                    break;
                };
                sender.send_ipv4(&packet).await?;
                note_to(&stats, &packet);
            }
            incoming = receiver.recv_ipv4() => {
                let packet = match incoming {
                    Ok(packet) => packet,
                    Err(HelloError::StreamClosed) => break,
                    Err(err) => return Err(err),
                };
                note_from(&stats, &packet);
                dispatch_down(&flows, &packet).await;
            }
            accepted = ingress.accept() => {
                let (stream, _) = accepted.map_err(|err| {
                    fail(format!("The spoke ingress did not accept a connection. {err}"))
                })?;
                let routes = Arc::clone(&routes);
                let flows = Arc::clone(&flows);
                let out_tx = out_tx.clone();
                let ports = Arc::clone(&ports);
                tokio::spawn(async move {
                    handle_ingress(stream, routes, flows, out_tx, ports).await;
                });
            }
        }
    }
    Ok(())
}

async fn accept_from_spoke(
    apps: &HashMap<Ipv4Addr, HubApp>,
    flows: &mut HashMap<FlowKey, mpsc::Sender<DownMsg>>,
    out_tx: &mpsc::Sender<Vec<u8>>,
    packet: &[u8],
) {
    let Some(segment) = decode_tcp_segment(packet) else {
        return;
    };
    let Some(app) = apps.get(&segment.dst).copied() else {
        return;
    };
    if segment.dst_port != app.overlay_port || segment.dst_port == 0 || segment.src_port == 0 {
        return;
    }
    let key = FlowKey {
        spoke_port: segment.src_port,
        app: segment.dst,
        app_port: segment.dst_port,
    };
    if let std::collections::hash_map::Entry::Vacant(entry) = flows.entry(key) {
        let return_ends = SegmentEnds {
            src: segment.dst,
            dst: segment.src,
            src_port: segment.dst_port,
            dst_port: segment.src_port,
        };
        match open_backend(app.backend, return_ends, out_tx.clone()).await {
            Ok(tx) => {
                entry.insert(tx);
            }
            Err(err) => {
                eprintln!("The connector hub did not reach the app. {err}");
                return;
            }
        }
    }
    let Some(tx) = flows.get(&key).cloned() else {
        return;
    };
    if !forward_segment(&tx, segment).await {
        flows.remove(&key);
    }
}

async fn open_backend(
    backend: SocketAddr,
    ends: SegmentEnds,
    out_tx: mpsc::Sender<Vec<u8>>,
) -> Result<mpsc::Sender<DownMsg>, HelloError> {
    let stream = TcpStream::connect(backend)
        .await
        .map_err(|err| fail(format!("The hub did not connect to {backend}. {err}")))?;
    stream
        .set_nodelay(true)
        .map_err(|err| fail(format!("The hub socket option failed. {err}")))?;
    let (read, write) = stream.into_split();
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        read_backend(read, out_tx, ends).await;
    });
    tokio::spawn(async move {
        write_backend(write, rx).await;
    });
    Ok(tx)
}

async fn read_backend(mut read: OwnedReadHalf, outbound: mpsc::Sender<Vec<u8>>, ends: SegmentEnds) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        match read.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = send_segment(&outbound, ends, FIN_FLAGS, &[]).await;
                break;
            }
            Ok(size) => {
                if send_segment(&outbound, ends, DATA_FLAGS, &buf[..size])
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn write_backend(mut write: OwnedWriteHalf, mut inbound: mpsc::Receiver<DownMsg>) {
    while let Some(msg) = inbound.recv().await {
        let stop = match msg {
            DownMsg::Data(bytes) => write.write_all(&bytes).await.is_err(),
            DownMsg::Fin => {
                let _ = write.shutdown().await;
                true
            }
        };
        if stop {
            break;
        }
    }
}

async fn dispatch_down(flows: &Mutex<HashMap<FlowKey, mpsc::Sender<DownMsg>>>, packet: &[u8]) {
    let Some(segment) = decode_tcp_segment(packet) else {
        return;
    };
    let key = FlowKey {
        spoke_port: segment.dst_port,
        app: segment.src,
        app_port: segment.src_port,
    };
    let tx = {
        let map = lock_map(flows);
        map.get(&key).cloned()
    };
    let Some(tx) = tx else {
        return;
    };
    let _ = forward_segment(&tx, segment).await;
}

async fn handle_ingress(
    mut stream: TcpStream,
    routes: Arc<[SpokeRoute]>,
    flows: Arc<Mutex<HashMap<FlowKey, mpsc::Sender<DownMsg>>>>,
    outbound: mpsc::Sender<Vec<u8>>,
    ports: Arc<AtomicU16>,
) {
    let _ = stream.set_nodelay(true);
    let record = match read_tls_record(&mut stream).await {
        Ok(record) => record,
        Err(err) => {
            eprintln!("The connector spoke did not read the TLS record. {err}");
            return;
        }
    };
    let Some(host) = tls_server_name(&record) else {
        eprintln!("The connector spoke did not read a server name.");
        return;
    };
    let Some(route) = routes
        .iter()
        .find(|route| route.host.eq_ignore_ascii_case(&host))
    else {
        eprintln!("The connector spoke rejected the name {host}.");
        return;
    };
    let src_port = alloc_port(&ports);
    let key = FlowKey {
        spoke_port: src_port,
        app: route.overlay,
        app_port: route.overlay_port,
    };
    let ends = SegmentEnds {
        src: SPOKE_OVERLAY,
        dst: route.overlay,
        src_port,
        dst_port: route.overlay_port,
    };
    let (down_tx, mut down_rx) = mpsc::channel(64);
    {
        let mut map = lock_map(&flows);
        map.insert(key, down_tx);
    }
    if send_segment(&outbound, ends, DATA_FLAGS, &record)
        .await
        .is_err()
    {
        remove_flow(&flows, key);
        return;
    }
    let (mut read, mut write) = stream.into_split();
    let mut buf = vec![0u8; CHUNK];
    loop {
        tokio::select! {
            biased;
            msg = down_rx.recv() => {
                match msg {
                    Some(DownMsg::Data(bytes)) => {
                        if write.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    Some(DownMsg::Fin) | None => {
                        let _ = write.shutdown().await;
                        break;
                    }
                }
            }
            result = read.read(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        let _ = send_segment(&outbound, ends, FIN_FLAGS, &[]).await;
                        break;
                    }
                    Ok(size) => {
                        if send_segment(&outbound, ends, DATA_FLAGS, &buf[..size]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    remove_flow(&flows, key);
}

async fn forward_segment(tx: &mpsc::Sender<DownMsg>, segment: TcpSegment) -> bool {
    if !segment.payload.is_empty() && tx.send(DownMsg::Data(segment.payload)).await.is_err() {
        return false;
    }
    if segment.flags & TCP_FLAG_FIN != 0 && tx.send(DownMsg::Fin).await.is_err() {
        return false;
    }
    true
}

async fn send_segment(
    outbound: &mpsc::Sender<Vec<u8>>,
    ends: SegmentEnds,
    flags: u8,
    payload: &[u8],
) -> Result<(), HelloError> {
    let packet = encode_tcp_segment(
        ends.src,
        ends.dst,
        ends.src_port,
        ends.dst_port,
        flags,
        payload,
    )?;
    outbound
        .send(packet)
        .await
        .map_err(|_| fail("The mesh sender stopped."))?;
    Ok(())
}

fn note_to(stats: &MeshCounts, packet: &[u8]) {
    let Some(segment) = decode_tcp_segment(packet) else {
        return;
    };
    if !segment.payload.is_empty() {
        stats.record_to(segment.dst);
    }
}

fn note_from(stats: &MeshCounts, packet: &[u8]) {
    let Some(segment) = decode_tcp_segment(packet) else {
        return;
    };
    if !segment.payload.is_empty() {
        stats.record_from(segment.src);
    }
}

fn alloc_port(ports: &AtomicU16) -> u16 {
    loop {
        let port = ports.fetch_add(1, Ordering::Relaxed);
        if port >= 40_000 {
            return port;
        }
    }
}

fn remove_flow(flows: &Mutex<HashMap<FlowKey, mpsc::Sender<DownMsg>>>, key: FlowKey) {
    let mut map = lock_map(flows);
    map.remove(&key);
}

fn lock_map<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}
