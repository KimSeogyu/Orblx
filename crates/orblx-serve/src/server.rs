//! The serve and funnel listeners in the node daemon.
//!
//! The watcher reads `serve.json` every 300 ms.
//! The overlay listener binds only the overlay address.
//! The funnel listener binds only when the file has `funnel: true`.
//! Each overlay connection maps the source address to a peer SPIFFE ID with the netmap.
//! The policy must allow that ID to reach this node on TCP at the HTTPS port.
//! A denied or unknown source gets no TLS handshake.
//! A peer source address counts only when the connection comes in on the overlay TUN
//! interface. A connection with a peer source address from a different interface is
//! a forged peer address. It gets `serve_deny forged-source` and no TLS handshake.
//! After the TLS handshake, the HTTP/1.1 proxy in `http.rs` reads each request.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use orblx_datapath::Netmap;
use orblx_identity::{DenySet, Policy, SpiffeId, TrustBundle};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::ServeConfig;
use crate::http::{self, Target};
use crate::ingress::{self, Ingress};

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

/// One listener that the serve state wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Want {
    addr: SocketAddr,
    target_port: u16,
    body_limit: u64,
}

struct Running {
    want: Want,
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
        let (want_overlay, want_funnel) = plan(config.as_ref(), shared.overlay);
        apply(&shared, Face::Overlay, &mut overlay, want_overlay).await;
        apply(&shared, Face::Funnel, &mut funnel, want_funnel).await;
        tokio::time::sleep(WATCH_GAP).await;
    }
}

/// The listeners that one serve state wants: the overlay listener and the funnel listener.
///
/// The funnel listener is `None` unless the state has `funnel: true` and a listen address.
/// No serve state means no listener.
fn plan(config: Option<&ServeConfig>, overlay: Ipv4Addr) -> (Option<Want>, Option<Want>) {
    let Some(config) = config else {
        return (None, None);
    };
    let overlay = Want {
        addr: SocketAddr::new(IpAddr::V4(overlay), config.https_port),
        target_port: config.target_port,
        body_limit: config.body_limit(),
    };
    let funnel = match (config.funnel, config.funnel_listen) {
        (true, Some(addr)) => Some(Want { addr, ..overlay }),
        _ => None,
    };
    (Some(overlay), funnel)
}

async fn apply(shared: &Arc<Shared>, face: Face, slot: &mut Option<Running>, want: Option<Want>) {
    let same = match (slot.as_ref(), want) {
        (Some(running), Some(want)) => running.want == want && !running.task.is_finished(),
        (None, None) => true,
        _ => false,
    };
    if same {
        return;
    }
    if let Some(running) = slot.take() {
        running.task.abort();
        let _ = running.task.await;
        println!("{}_closed {}", face_name(face), running.want.addr);
    }
    let Some(want) = want else {
        return;
    };
    let addr = want.addr;
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
    if face == Face::Overlay && !ingress::enable(&listener) {
        // The W21-4 source address check still applies.
        println!("serve_ingress_check unavailable");
    }
    println!(
        "{}_listen {addr} target 127.0.0.1:{} max_body {}",
        face_name(face),
        want.target_port,
        want.body_limit
    );
    let shared = Arc::clone(shared);
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
                        handle(shared, face, stream, peer, want).await;
                    });
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    });
    *slot = Some(Running { want, task });
}

fn face_name(face: Face) -> &'static str {
    match face {
        Face::Overlay => "serve",
        Face::Funnel => "funnel",
    }
}

async fn handle(shared: Arc<Shared>, face: Face, stream: TcpStream, peer: SocketAddr, want: Want) {
    match face {
        Face::Overlay => match admit(
            &shared,
            peer.ip(),
            overlay_ingress(&shared, &stream),
            want.addr.port(),
        ) {
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
    let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_LIMIT, acceptor.accept(stream)).await else {
        println!("{}_tls_failed from {}", face_name(face), peer.ip());
        return;
    };
    let target = Target {
        face: face_name(face),
        port: want.target_port,
        body_limit: want.body_limit,
        client: peer.ip(),
    };
    http::serve_connection(tls, target).await;
}

/// Where one overlay connection came in.
///
/// Without the Linux ingress check, the function returns `Tunnel`.
/// The W21-4 source address check then still applies.
fn overlay_ingress(shared: &Shared, stream: &TcpStream) -> Ingress {
    if !ingress::CHECK_AVAILABLE {
        return Ingress::Tunnel;
    }
    ingress::classify(
        ingress::ingress_index(stream),
        ingress::index_for_addr(shared.overlay),
    )
}

/// Map the source address to a peer SPIFFE ID and check the policy.
///
/// A peer address counts only when the connection came in on the overlay TUN interface.
/// The error is a short reason. It does not hold secrets.
fn admit(
    shared: &Shared,
    src: IpAddr,
    ingress: Ingress,
    https_port: u16,
) -> Result<String, String> {
    let netmap =
        Netmap::from_path(&shared.netmap_path).map_err(|_| "netmap-not-valid".to_string())?;
    let src_text = src.to_string();
    let Some(peer) = netmap.peers.iter().find(|peer| peer.overlay_ip == src_text) else {
        return Err("unknown-source".to_string());
    };
    match ingress {
        Ingress::Tunnel => {}
        // A peer address from an underlay interface did not pass the QUIC SVID check.
        Ingress::Other => return Err("forged-source".to_string()),
        Ingress::Unknown => return Err("ingress-unknown".to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("orblx-serve-server-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("temp dir"));
        dir
    }

    fn shared_with_netmap(name: &str) -> Shared {
        let dir = temp_dir(name);
        let netmap = dir.join("netmap.json");
        fs::write(
            &netmap,
            r#"{
  "version": 1,
  "self": {"name": "b", "overlay_ip": "100.64.0.2"},
  "peers": [
    {"name": "a", "overlay_ip": "100.64.0.1", "svid": "spiffe://orblx.local/node/a",
     "endpoints": ["192.0.2.11:443"], "routes": ["100.64.0.1/32"]}
  ]
}"#,
        )
        .unwrap_or_else(|_| panic!("netmap"));
        Shared {
            state_dir: dir,
            netmap_path: netmap,
            overlay: Ipv4Addr::new(100, 64, 0, 2),
        }
    }

    #[test]
    fn a_forged_peer_address_is_rejected() {
        let shared = shared_with_netmap("forged");
        let peer_a = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        // The source is the netmap address of peer a, but the connection came in on an
        // underlay interface, not on TUN.
        assert_eq!(
            admit(&shared, peer_a, Ingress::Other, 443),
            Err("forged-source".to_string())
        );
        // Fail closed when the interface is not known.
        assert_eq!(
            admit(&shared, peer_a, Ingress::Unknown, 443),
            Err("ingress-unknown".to_string())
        );
        // A source that is not a netmap peer stays unknown-source on each interface.
        let outside = IpAddr::V4(Ipv4Addr::new(172, 30, 42, 20));
        for ingress in [Ingress::Tunnel, Ingress::Other, Ingress::Unknown] {
            assert_eq!(
                admit(&shared, outside, ingress, 443),
                Err("unknown-source".to_string())
            );
        }
        // On TUN the peer address goes on to the SVID and policy checks.
        // This state directory has no node SVID, so the check stops there.
        assert_eq!(
            admit(&shared, peer_a, Ingress::Tunnel, 443),
            Err("no-node-svid".to_string())
        );
        let _ = fs::remove_dir_all(&shared.state_dir);
    }

    #[test]
    fn funnel_stays_off_by_default() {
        let overlay = Ipv4Addr::new(100, 64, 0, 2);
        assert_eq!(plan(None, overlay), (None, None));

        // The W21-4 file has no funnel field.
        let config: ServeConfig =
            serde_json::from_str(r#"{"version":1,"target_port":8080,"https_port":443}"#)
                .unwrap_or_else(|_| panic!("serve config"));
        let (serve, funnel) = plan(Some(&config), overlay);
        let serve = serve.unwrap_or_else(|| panic!("serve listener"));
        assert_eq!(
            serve.addr,
            "100.64.0.2:443".parse().unwrap_or_else(|_| panic!("addr"))
        );
        assert_eq!(funnel, None);

        // A listen address alone does not open funnel. Only funnel: true does.
        let mut config = config;
        config.funnel_listen = Some("192.0.2.10:8443".parse().unwrap_or_else(|_| panic!("addr")));
        assert_eq!(plan(Some(&config), overlay).1, None);
        config.funnel = true;
        let funnel = plan(Some(&config), overlay)
            .1
            .unwrap_or_else(|| panic!("funnel listener"));
        assert_eq!(
            funnel.addr,
            "192.0.2.10:8443".parse().unwrap_or_else(|_| panic!("addr"))
        );

        // funnel: true without a listen address does not load.
        let bad = r#"{"version":1,"target_port":8080,"https_port":443,"funnel":true}"#;
        let bad: ServeConfig = serde_json::from_str(bad).unwrap_or_else(|_| panic!("parse"));
        assert!(bad.check().is_err());
    }
}
