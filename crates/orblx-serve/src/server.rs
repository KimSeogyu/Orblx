//! The serve and funnel listeners in the node daemon.
//!
//! The watcher reads `serve.json` every 300 ms.
//! The overlay listener binds only the overlay address.
//! The funnel listener binds only when the file has `funnel: true`.
//! Each overlay connection maps the source address to a peer SPIFFE ID with the netmap.
//! The policy must allow that ID to reach this node on TCP at the HTTPS port.
//! A denied or unknown source gets no TLS handshake.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use orblx_datapath::Netmap;
use orblx_identity::{DenySet, Policy, SpiffeId, TrustBundle};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::ServeConfig;

const WATCH_GAP: Duration = Duration::from_millis(300);
const PROTO_TCP: u8 = 6;
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);

struct Shared {
    state_dir: PathBuf,
    netmap_path: PathBuf,
    overlay: Ipv4Addr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Face {
    Overlay,
    Funnel,
}

struct Running {
    addr: SocketAddr,
    target_port: u16,
    task: JoinHandle<()>,
}

/// Start the serve watcher in the node daemon.
///
/// The function returns after the watcher thread starts.
/// The watcher opens and closes the listeners when `serve.json` changes.
pub fn spawn_serve(state_dir: &Path, netmap_path: &Path, overlay: Ipv4Addr) {
    let shared = Arc::new(Shared {
        state_dir: state_dir.to_path_buf(),
        netmap_path: netmap_path.to_path_buf(),
        overlay,
    });
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                eprintln!("The serve watcher did not start.");
                return;
            }
        };
        runtime.block_on(watch(shared));
    });
}

async fn watch(shared: Arc<Shared>) {
    let mut overlay: Option<Running> = None;
    let mut funnel: Option<Running> = None;
    let mut last_error = String::new();
    loop {
        let config = match ServeConfig::load(&shared.state_dir) {
            Ok(config) => {
                last_error.clear();
                config
            }
            Err(err) => {
                if err != last_error {
                    eprintln!("{err} Serve and funnel stay closed.");
                    last_error = err;
                }
                None
            }
        };
        let want_overlay = config.as_ref().map(|config| {
            (
                SocketAddr::new(IpAddr::V4(shared.overlay), config.https_port),
                config.target_port,
            )
        });
        let want_funnel = config.as_ref().and_then(|config| {
            if config.funnel {
                config.funnel_listen.map(|addr| (addr, config.target_port))
            } else {
                None
            }
        });
        apply(&shared, Face::Overlay, &mut overlay, want_overlay).await;
        apply(&shared, Face::Funnel, &mut funnel, want_funnel).await;
        tokio::time::sleep(WATCH_GAP).await;
    }
}

async fn apply(
    shared: &Arc<Shared>,
    face: Face,
    slot: &mut Option<Running>,
    want: Option<(SocketAddr, u16)>,
) {
    let same = match (slot.as_ref(), want) {
        (Some(running), Some((addr, target))) => {
            running.addr == addr && running.target_port == target && !running.task.is_finished()
        }
        (None, None) => true,
        _ => false,
    };
    if same {
        return;
    }
    if let Some(running) = slot.take() {
        running.task.abort();
        let _ = running.task.await;
        println!("{}_closed {}", face_name(face), running.addr);
    }
    let Some((addr, target_port)) = want else {
        return;
    };
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!(
                "The {} listener did not bind {addr}. {err}",
                face_name(face)
            );
            return;
        }
    };
    println!(
        "{}_listen {addr} target 127.0.0.1:{target_port}",
        face_name(face)
    );
    let shared = Arc::clone(shared);
    let https_port = addr.port();
    let task = tokio::spawn(async move {
        // The listener task owns each connection task.
        // When the listener task stops, the JoinSet drop stops the open connections too.
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    let shared = Arc::clone(&shared);
                    conns.spawn(async move {
                        handle(shared, face, stream, peer, https_port, target_port).await;
                    });
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    });
    *slot = Some(Running {
        addr,
        target_port,
        task,
    });
}

fn face_name(face: Face) -> &'static str {
    match face {
        Face::Overlay => "serve",
        Face::Funnel => "funnel",
    }
}

async fn handle(
    shared: Arc<Shared>,
    face: Face,
    stream: TcpStream,
    peer: SocketAddr,
    https_port: u16,
    target_port: u16,
) {
    match face {
        Face::Overlay => match admit(&shared, peer.ip(), https_port) {
            Ok(src) => println!("serve_allow {src} from {}", peer.ip()),
            Err(reason) => {
                // Close before TLS. The denied source gets no data.
                println!("serve_deny {reason} from {}", peer.ip());
                drop(stream);
                return;
            }
        },
        Face::Funnel => println!("funnel_accept from {}", peer.ip()),
    }
    let acceptor = match acceptor(&shared.state_dir) {
        Ok(acceptor) => acceptor,
        Err(err) => {
            eprintln!("{err}");
            return;
        }
    };
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_LIMIT, acceptor.accept(stream)).await
    else {
        println!("{}_tls_failed from {}", face_name(face), peer.ip());
        return;
    };
    let Ok(mut local) = TcpStream::connect((Ipv4Addr::LOCALHOST, target_port)).await else {
        eprintln!("The local port 127.0.0.1:{target_port} did not accept the connection.");
        return;
    };
    let _ = copy_bidirectional(&mut tls, &mut local).await;
}

/// Map the source address to a peer SPIFFE ID and check the policy.
///
/// The error is a short reason. It does not hold secrets.
fn admit(shared: &Shared, src: IpAddr, https_port: u16) -> Result<String, String> {
    let netmap =
        Netmap::from_path(&shared.netmap_path).map_err(|_| "netmap-not-valid".to_string())?;
    let src_text = src.to_string();
    let Some(peer) = netmap.peers.iter().find(|peer| peer.overlay_ip == src_text) else {
        return Err("unknown-source".to_string());
    };
    let src_id = SpiffeId::parse(&peer.svid).map_err(|_| "unknown-source".to_string())?;
    let self_id = node_id(&shared.state_dir)?;
    let policy_path = shared.state_dir.join("policy.hujson");
    let policy = Policy::from_path(&policy_path).map_err(|_| "no-policy".to_string())?;
    if policy.allows(&src_id, &self_id, PROTO_TCP, https_port) {
        Ok(src_id.as_uri().to_string())
    } else {
        Err(src_id.as_uri().to_string())
    }
}

fn node_id(state_dir: &Path) -> Result<SpiffeId, String> {
    let cert_pem =
        fs::read_to_string(state_dir.join("cert.pem")).map_err(|_| "no-node-svid".to_string())?;
    let bundle_pem = fs::read_to_string(state_dir.join("bundle.pem"))
        .map_err(|_| "no-trust-bundle".to_string())?;
    let bundle = TrustBundle::from_pem(&bundle_pem).map_err(|_| "no-trust-bundle".to_string())?;
    let der = orblx_identity::decode_certificate_pem(&cert_pem)
        .map_err(|_| "no-node-svid".to_string())?;
    bundle
        .authenticate_leaf(&der, SystemTime::now(), &DenySet::empty())
        .map_err(|_| "no-node-svid".to_string())
}

/// Build the TLS acceptor from the node SVID files.
///
/// The function reads the files for each connection. A renewed SVID applies at once.
fn acceptor(state_dir: &Path) -> Result<TlsAcceptor, String> {
    let cert_pem = fs::read(state_dir.join("cert.pem"))
        .map_err(|_| "The node SVID did not open.".to_string())?;
    let key_pem = fs::read(state_dir.join("key.pem"))
        .map_err(|_| "The node SVID key did not open.".to_string())?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|_| "The node SVID is not valid.".to_string())?;
    if certs.is_empty() {
        return Err("The node SVID is not valid.".to_string());
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|_| "The node SVID key is not valid.".to_string())?
        .ok_or_else(|| "The node SVID key is not valid.".to_string())?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "The TLS config did not build.".to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| "The node SVID key does not match the SVID.".to_string())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}
