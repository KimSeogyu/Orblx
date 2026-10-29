use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_crypto::{mac_input, ticket_mac, TicketKey, TicketRing};
use orblx_identity::{
    sign_ticket, DenySet, MiniCa, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
    TicketVerifier, TrustBundle, MAX_USER_TTL,
};
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::https::{
    fetch_https, issue_app_material, serve_https, AppIdentity, AppListener, AppMaterial,
};
use super::relay::{relay_hub, relay_spoke, HubApp, MeshCounts, SpokeRoute};
use super::{
    fail, TwoAppProof, APP_A_BODY, APP_A_HOST, APP_A_OVERLAY, APP_B_BODY, APP_B_HOST,
    APP_B_OVERLAY, APP_OVERLAY_PORT,
};
use crate::{HelloConfig, HelloEndpoint, HelloError};

const FILE_TRUST: &str = "trust-bundle.pem";
const FILE_HUB_CERT: &str = "hub-cert.pem";
const FILE_HUB_KEY: &str = "hub-key.pem";
const FILE_HUB_TICKET: &str = "hub-ticket.bin";
const FILE_SPOKE_CERT: &str = "spoke-cert.pem";
const FILE_SPOKE_KEY: &str = "spoke-key.pem";
const FILE_SPOKE_TICKET: &str = "spoke-ticket.bin";
const FILE_TICKET_VERIFIER: &str = "ticket-verifier.pem";
const FILE_TICKET_MAC_KEY: &str = "ticket-mac.key";
const FILE_NOT_BEFORE: &str = "ticket-not-before";
const FILE_NOT_AFTER: &str = "ticket-not-after";
const FILE_SVID_CA_PUB: &str = "svid-ca.pub";
const FILE_APP_CA: &str = "app-ca.pem";
const FILE_APP_A_CERT: &str = "app-a.pem";
const FILE_APP_A_KEY: &str = "app-a.key";
const FILE_APP_B_CERT: &str = "app-b.pem";
const FILE_APP_B_KEY: &str = "app-b.key";

const PROVE_TIMEOUT: Duration = Duration::from_secs(30);

struct LabBundle {
    hub: HelloConfig,
    spoke: HelloConfig,
    apps: AppMaterial,
    trust_pem: String,
    ticket_verifier_pem: String,
    ticket_mac_key: [u8; 32],
    ticket_not_before: SystemTime,
    ticket_not_after: SystemTime,
    svid_ca_public: [u8; 32],
}

struct StopTasks(Vec<JoinHandle<()>>);

impl Drop for StopTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

struct MeshStart {
    ingress: SocketAddr,
    quic_hub: SocketAddr,
    backend_a: SocketAddr,
    backend_b: SocketAddr,
    ca_pem: String,
    stats: Arc<MeshCounts>,
    _listeners: (AppListener, AppListener),
    _tasks: StopTasks,
}

/// Write one connector lab directory.
///
/// The ticket sidecar files use the same names as `hello-quic`.
/// The SVID PEM files stay on disk.
pub fn issue_connector_lab(dir: &Path) -> Result<(), HelloError> {
    let bundle = build_lab()?;
    std::fs::create_dir_all(dir).map_err(|err| {
        fail(format!(
            "The directory {} was not created. {err}",
            dir.display()
        ))
    })?;
    write_bundle(dir, &bundle)
}

/// Run the two-app HTTPS proof in memory.
///
/// The client dials the spoke ingress.
/// The app listeners use other local ports.
/// The HTTPS bytes cross one QUIC stream as IPv4 DATA frames.
pub fn prove_two_https_apps() -> Result<TwoAppProof, HelloError> {
    let bundle = build_lab()?;
    block_on_proof(prove_with(bundle))
}

/// Run the two-app HTTPS proof from a lab directory.
///
/// The function loads the SVID PEM files and the ticket files from `dir`.
pub fn prove_lab_directory(dir: &Path) -> Result<TwoAppProof, HelloError> {
    let bundle = load_bundle(dir)?;
    block_on_proof(prove_with(bundle))
}

/// Run the hub until the spoke closes the session.
///
/// The hub starts the two HTTPS apps on loopback ports.
/// The spoke reaches those apps by the overlay addresses.
pub fn run_hub_dir(dir: &Path, listen: SocketAddr) -> Result<(), HelloError> {
    let bundle = load_bundle(dir)?;
    block_on(async move {
        let listener_a = serve_https(
            loopback(0),
            &bundle.apps.app_a.cert_pem,
            &bundle.apps.app_a.key_pem,
            APP_A_BODY.to_string(),
        )
        .await?;
        let listener_b = serve_https(
            loopback(0),
            &bundle.apps.app_b.cert_pem,
            &bundle.apps.app_b.key_pem,
            APP_B_BODY.to_string(),
        )
        .await?;
        println!(
            "The Orblx connector hub serves {APP_A_HOST} on overlay {APP_A_OVERLAY}:{APP_OVERLAY_PORT}."
        );
        println!(
            "The Orblx connector hub serves {APP_B_HOST} on overlay {APP_B_OVERLAY}:{APP_OVERLAY_PORT}."
        );
        let endpoint = HelloEndpoint::bind_server(bundle.hub, listen)?;
        let local = endpoint.local_addr()?;
        println!("The connector hub listens on UDP {local}.");
        let session = endpoint.accept_one().await?;
        println!("The peer SPIFFE ID is {}.", session.peer_id().as_uri());
        relay_hub(session, hub_apps(listener_a.local, listener_b.local)).await?;
        Ok(())
    })
}

/// Run the spoke until the hub closes the session.
///
/// `ingress` is the socket for the browser or for curl.
pub fn run_spoke_dir(dir: &Path, peer: SocketAddr, ingress: SocketAddr) -> Result<(), HelloError> {
    let bundle = load_bundle(dir)?;
    block_on(async move {
        let listener = TcpListener::bind(ingress).await.map_err(|err| {
            fail(format!(
                "The spoke ingress did not bind on {ingress}. {err}"
            ))
        })?;
        let local = listener
            .local_addr()
            .map_err(|err| fail(format!("The spoke ingress has no address. {err}")))?;
        println!("The Orblx connector spoke listens on {local}.");
        println!("The spoke connects to UDP {peer}.");
        let endpoint = HelloEndpoint::bind_client(bundle.spoke, loopback(0))?;
        println!("The local UDP socket is {}.", endpoint.local_addr()?);
        let session = endpoint.connect_one(peer).await?;
        println!("The peer SPIFFE ID is {}.", session.peer_id().as_uri());
        let stats = Arc::new(MeshCounts::default());
        relay_spoke(session, listener, default_routes(), stats).await?;
        Ok(())
    })
}

/// Serve both apps in one process and wait.
///
/// The function writes the app CA to `ca_out`.
/// curl dials `ingress`.
/// The HTTPS bytes still cross the QUIC mesh.
pub fn serve_userspace(ingress: SocketAddr, ca_out: &Path) -> Result<(), HelloError> {
    let bundle = build_lab()?;
    block_on(async move {
        write_ca(ca_out, &bundle.apps.ca_pem)?;
        let started = start_mesh(bundle, ingress).await?;
        print_curl(started.ingress, ca_out);
        println!("The connector waits. Stop the process to exit.");
        std::future::pending::<()>().await;
        Ok(())
    })
}

/// Serve the two apps on the given sockets and wait.
///
/// This command does not open a TUN device.
/// Assign the overlay addresses before you bind them.
pub fn serve_apps_dir(
    dir: &Path,
    bind_a: SocketAddr,
    bind_b: SocketAddr,
) -> Result<(), HelloError> {
    let bundle = load_bundle(dir)?;
    block_on(async move {
        let listener_a = serve_https(
            bind_a,
            &bundle.apps.app_a.cert_pem,
            &bundle.apps.app_a.key_pem,
            APP_A_BODY.to_string(),
        )
        .await?;
        let listener_b = serve_https(
            bind_b,
            &bundle.apps.app_b.cert_pem,
            &bundle.apps.app_b.key_pem,
            APP_B_BODY.to_string(),
        )
        .await?;
        println!(
            "The Orblx app {APP_A_HOST} listens on {}. The body is {APP_A_BODY}.",
            listener_a.local
        );
        println!(
            "The Orblx app {APP_B_HOST} listens on {}. The body is {APP_B_BODY}.",
            listener_b.local
        );
        println!("The CA file is {}.", dir.join(FILE_APP_CA).display());
        println!("This command does not open a TUN device.");
        println!("The TUN device needs CAP_NET_ADMIN on Linux.");
        println!("The connector waits. Stop the process to exit.");
        std::future::pending::<()>().await;
        Ok(())
    })
}

fn block_on(
    future: impl std::future::Future<Output = Result<(), HelloError>>,
) -> Result<(), HelloError> {
    let runtime = runtime()?;
    runtime.block_on(future)
}

fn block_on_proof(
    future: impl std::future::Future<Output = Result<TwoAppProof, HelloError>>,
) -> Result<TwoAppProof, HelloError> {
    let runtime = runtime()?;
    runtime.block_on(async {
        tokio::time::timeout(PROVE_TIMEOUT, future)
            .await
            .map_err(|_| fail("The connector proof timed out."))?
    })
}

fn runtime() -> Result<tokio::runtime::Runtime, HelloError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| HelloError::Io(err.to_string()))
}

async fn prove_with(bundle: LabBundle) -> Result<TwoAppProof, HelloError> {
    let started = start_mesh(bundle, loopback(0)).await?;
    let mut app_a =
        fetch_https(started.ingress, APP_A_HOST, APP_A_OVERLAY, &started.ca_pem).await?;
    let mut app_b =
        fetch_https(started.ingress, APP_B_HOST, APP_B_OVERLAY, &started.ca_pem).await?;
    app_a.mesh_to = started.stats.count_to(APP_A_OVERLAY);
    app_a.mesh_from = started.stats.count_from(APP_A_OVERLAY);
    app_b.mesh_to = started.stats.count_to(APP_B_OVERLAY);
    app_b.mesh_from = started.stats.count_from(APP_B_OVERLAY);
    Ok(TwoAppProof {
        ingress: started.ingress,
        quic_hub: started.quic_hub,
        backend_a: started.backend_a,
        backend_b: started.backend_b,
        app_a,
        app_b,
    })
}

async fn start_mesh(bundle: LabBundle, ingress_bind: SocketAddr) -> Result<MeshStart, HelloError> {
    let listener_a = serve_https(
        loopback(0),
        &bundle.apps.app_a.cert_pem,
        &bundle.apps.app_a.key_pem,
        APP_A_BODY.to_string(),
    )
    .await?;
    let listener_b = serve_https(
        loopback(0),
        &bundle.apps.app_b.cert_pem,
        &bundle.apps.app_b.key_pem,
        APP_B_BODY.to_string(),
    )
    .await?;
    let backend_a = listener_a.local;
    let backend_b = listener_b.local;
    let endpoint = HelloEndpoint::bind_server(bundle.hub, loopback(0))?;
    let quic_hub = endpoint.local_addr()?;
    let apps = hub_apps(backend_a, backend_b);
    let hub_task = tokio::spawn(async move {
        let session = match endpoint.accept_one().await {
            Ok(session) => session,
            Err(err) => {
                eprintln!("The connector hub did not accept the spoke. {err}");
                return;
            }
        };
        if let Err(err) = relay_hub(session, apps).await {
            eprintln!("The connector hub stopped. {err}");
        }
    });
    let ingress = TcpListener::bind(ingress_bind).await.map_err(|err| {
        fail(format!(
            "The spoke ingress did not bind on {ingress_bind}. {err}"
        ))
    })?;
    let ingress_addr = ingress
        .local_addr()
        .map_err(|err| fail(format!("The spoke ingress has no address. {err}")))?;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let stats = Arc::new(MeshCounts::default());
    let stats_task = Arc::clone(&stats);
    let spoke_config = bundle.spoke;
    let spoke_task = tokio::spawn(async move {
        let endpoint = match HelloEndpoint::bind_client(spoke_config, loopback(0)) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                let _ = ready_tx.send(Err(err));
                return;
            }
        };
        let session = match endpoint.connect_one(quic_hub).await {
            Ok(session) => session,
            Err(err) => {
                let _ = ready_tx.send(Err(err));
                return;
            }
        };
        if ready_tx.send(Ok(())).is_err() {
            return;
        }
        if let Err(err) = relay_spoke(session, ingress, default_routes(), stats_task).await {
            eprintln!("The connector spoke stopped. {err}");
        }
    });
    ready_rx
        .await
        .map_err(|_| fail("The spoke stopped before the session was ready."))??;
    Ok(MeshStart {
        ingress: ingress_addr,
        quic_hub,
        backend_a,
        backend_b,
        ca_pem: bundle.apps.ca_pem,
        stats,
        _listeners: (listener_a, listener_b),
        _tasks: StopTasks(vec![hub_task, spoke_task]),
    })
}

fn print_curl(ingress: SocketAddr, ca_out: &Path) {
    let port = ingress.port();
    let ip = ingress.ip();
    println!("The product name is Orblx.");
    println!("The connector spoke listens on {ingress}.");
    println!("The app {APP_A_HOST} uses overlay {APP_A_OVERLAY}:{APP_OVERLAY_PORT}.");
    println!("The app {APP_B_HOST} uses overlay {APP_B_OVERLAY}:{APP_OVERLAY_PORT}.");
    println!("The CA file is {}.", ca_out.display());
    println!("Fetch app A:");
    println!(
        "curl --resolve {APP_A_HOST}:{port}:{ip} --cacert {} https://{APP_A_HOST}:{port}/",
        ca_out.display()
    );
    println!("Fetch app B:");
    println!(
        "curl --resolve {APP_B_HOST}:{port}:{ip} --cacert {} https://{APP_B_HOST}:{port}/",
        ca_out.display()
    );
    println!("The path is the QUIC mesh. curl does not dial the app listeners.");
}

fn hub_apps(backend_a: SocketAddr, backend_b: SocketAddr) -> HashMap<Ipv4Addr, HubApp> {
    let mut apps = HashMap::new();
    apps.insert(
        APP_A_OVERLAY,
        HubApp {
            overlay_port: APP_OVERLAY_PORT,
            backend: backend_a,
        },
    );
    apps.insert(
        APP_B_OVERLAY,
        HubApp {
            overlay_port: APP_OVERLAY_PORT,
            backend: backend_b,
        },
    );
    apps
}

fn default_routes() -> Arc<[SpokeRoute]> {
    Arc::from([
        SpokeRoute {
            host: APP_A_HOST.to_string(),
            overlay: APP_A_OVERLAY,
            overlay_port: APP_OVERLAY_PORT,
        },
        SpokeRoute {
            host: APP_B_HOST.to_string(),
            overlay: APP_B_OVERLAY,
            overlay_port: APP_OVERLAY_PORT,
        },
    ])
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn build_lab() -> Result<LabBundle, HelloError> {
    let now = SystemTime::now();
    let ca = MiniCa::generate(now).map_err(HelloError::Identity)?;
    let deny = DenySet::empty();
    let hub_id = SpiffeId::user("connector-hub").map_err(HelloError::Identity)?;
    let spoke_id = SpiffeId::user("connector-spoke").map_err(HelloError::Identity)?;
    let hub_svid = ca
        .issue(&hub_id, now, MAX_USER_TTL, &deny)
        .map_err(HelloError::Identity)?;
    let spoke_svid = ca
        .issue(&spoke_id, now, MAX_USER_TTL, &deny)
        .map_err(HelloError::Identity)?;
    let signer = TicketSigner::generate();
    let mut mac_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut mac_key);
    let not_before = now
        .checked_sub(Duration::from_secs(60))
        .ok_or_else(|| fail("The ticket start time is not valid."))?;
    let not_after = now
        .checked_add(Duration::from_secs(86_400))
        .ok_or_else(|| fail("The ticket end time is not valid."))?;
    let ring = TicketRing::single(
        TicketKey::new(signer.verifier(), mac_key, not_before, not_after)
            .map_err(HelloError::Ticket)?,
        ca.public_key(),
    )
    .map_err(HelloError::Ticket)?;
    let trust = ca.trust_bundle().clone();
    let hub_ticket = present(&signer, &mac_key, now, &hub_id)?;
    let spoke_ticket = present(&signer, &mac_key, now, &spoke_id)?;
    let apps = issue_app_material(APP_A_HOST, APP_B_HOST)?;
    let trust_pem = ca.trust_bundle_pem().to_string();
    let ticket_verifier_pem = signer.public_key_pem();
    let svid_ca_public = *ca.public_key();
    Ok(LabBundle {
        hub: config_from(
            &hub_svid.certificate_pem,
            &hub_svid.private_key_pem,
            trust.clone(),
            hub_ticket,
            ring.clone(),
        ),
        spoke: config_from(
            &spoke_svid.certificate_pem,
            &spoke_svid.private_key_pem,
            trust,
            spoke_ticket,
            ring,
        ),
        apps,
        trust_pem,
        ticket_verifier_pem,
        ticket_mac_key: mac_key,
        ticket_not_before: not_before,
        ticket_not_after: not_after,
        svid_ca_public,
    })
}

struct PresentedTicket {
    bytes: Vec<u8>,
    mac: [u8; 32],
}

fn present(
    signer: &TicketSigner,
    mac_key: &[u8; 32],
    now: SystemTime,
    subject: &SpiffeId,
) -> Result<PresentedTicket, HelloError> {
    let start = unix_secs(now)?;
    let signed = sign_ticket(
        signer,
        &TicketClaims {
            issuer: SpiffeId::coord("1").map_err(HelloError::Identity)?,
            subject: subject.clone(),
            not_before: start,
            expires: start + 600,
            dst_cidr: "10.8.0.0/24".to_string(),
            proto: 6,
            dst_port: APP_OVERLAY_PORT,
            flags: TicketFlags::none(),
        },
    )
    .map_err(HelloError::Identity)?;
    let mac = ticket_mac(mac_key, mac_input(&signed.bytes)).map_err(HelloError::Ticket)?;
    Ok(PresentedTicket {
        bytes: signed.bytes,
        mac,
    })
}

fn config_from(
    certificate_pem: &str,
    private_key_pem: &str,
    trust: TrustBundle,
    ticket: PresentedTicket,
    ring: TicketRing,
) -> HelloConfig {
    HelloConfig::from_issued(
        certificate_pem,
        private_key_pem,
        trust,
        ticket.bytes,
        ticket.mac,
        ring,
    )
}

fn write_bundle(dir: &Path, bundle: &LabBundle) -> Result<(), HelloError> {
    write_text(&dir.join(FILE_TRUST), &bundle.trust_pem)?;
    write_text(&dir.join(FILE_HUB_CERT), &bundle.hub.certificate_pem)?;
    write_text(&dir.join(FILE_HUB_KEY), &bundle.hub.private_key_pem)?;
    write_bytes(&dir.join(FILE_HUB_TICKET), &bundle.hub.ticket_bytes)?;
    write_bytes(
        &mac_path(&dir.join(FILE_HUB_TICKET)),
        &bundle.hub.ticket_mac,
    )?;
    write_text(&dir.join(FILE_SPOKE_CERT), &bundle.spoke.certificate_pem)?;
    write_text(&dir.join(FILE_SPOKE_KEY), &bundle.spoke.private_key_pem)?;
    write_bytes(&dir.join(FILE_SPOKE_TICKET), &bundle.spoke.ticket_bytes)?;
    write_bytes(
        &mac_path(&dir.join(FILE_SPOKE_TICKET)),
        &bundle.spoke.ticket_mac,
    )?;
    write_text(&dir.join(FILE_TICKET_VERIFIER), &bundle.ticket_verifier_pem)?;
    write_bytes(&dir.join(FILE_TICKET_MAC_KEY), &bundle.ticket_mac_key)?;
    write_unix(&dir.join(FILE_NOT_BEFORE), bundle.ticket_not_before)?;
    write_unix(&dir.join(FILE_NOT_AFTER), bundle.ticket_not_after)?;
    write_bytes(&dir.join(FILE_SVID_CA_PUB), &bundle.svid_ca_public)?;
    write_text(&dir.join(FILE_APP_CA), &bundle.apps.ca_pem)?;
    write_text(&dir.join(FILE_APP_A_CERT), &bundle.apps.app_a.cert_pem)?;
    write_text(&dir.join(FILE_APP_A_KEY), &bundle.apps.app_a.key_pem)?;
    write_text(&dir.join(FILE_APP_B_CERT), &bundle.apps.app_b.cert_pem)?;
    write_text(&dir.join(FILE_APP_B_KEY), &bundle.apps.app_b.key_pem)?;
    Ok(())
}

fn write_ca(path: &Path, pem: &str) -> Result<(), HelloError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| {
                fail(format!(
                    "The directory {} was not created. {err}",
                    parent.display()
                ))
            })?;
        }
    }
    std::fs::write(path, pem).map_err(|err| {
        fail(format!(
            "The file {} was not written. {err}",
            path.display()
        ))
    })
}

fn load_bundle(dir: &Path) -> Result<LabBundle, HelloError> {
    let trust_pem = read_text(&dir.join(FILE_TRUST))?;
    let trust = TrustBundle::from_pem(&trust_pem).map_err(HelloError::Identity)?;
    let ticket_verifier_pem = read_text(&dir.join(FILE_TICKET_VERIFIER))?;
    let ticket_mac_key = read_array(&dir.join(FILE_TICKET_MAC_KEY))?;
    let ticket_not_before = read_unix(&dir.join(FILE_NOT_BEFORE))?;
    let ticket_not_after = read_unix(&dir.join(FILE_NOT_AFTER))?;
    let svid_ca_public = read_array(&dir.join(FILE_SVID_CA_PUB))?;
    let verifier =
        TicketVerifier::from_public_pem(&ticket_verifier_pem).map_err(HelloError::Identity)?;
    let ring = TicketRing::single(
        TicketKey::new(
            verifier,
            ticket_mac_key,
            ticket_not_before,
            ticket_not_after,
        )
        .map_err(HelloError::Ticket)?,
        &svid_ca_public,
    )
    .map_err(HelloError::Ticket)?;
    let hub = load_hello(
        dir,
        FILE_HUB_CERT,
        FILE_HUB_KEY,
        FILE_HUB_TICKET,
        trust.clone(),
        &ring,
    )?;
    let spoke = load_hello(
        dir,
        FILE_SPOKE_CERT,
        FILE_SPOKE_KEY,
        FILE_SPOKE_TICKET,
        trust,
        &ring,
    )?;
    let apps = AppMaterial {
        ca_pem: read_text(&dir.join(FILE_APP_CA))?,
        app_a: AppIdentity {
            cert_pem: read_text(&dir.join(FILE_APP_A_CERT))?,
            key_pem: read_text(&dir.join(FILE_APP_A_KEY))?,
        },
        app_b: AppIdentity {
            cert_pem: read_text(&dir.join(FILE_APP_B_CERT))?,
            key_pem: read_text(&dir.join(FILE_APP_B_KEY))?,
        },
    };
    Ok(LabBundle {
        hub,
        spoke,
        apps,
        trust_pem,
        ticket_verifier_pem,
        ticket_mac_key,
        ticket_not_before,
        ticket_not_after,
        svid_ca_public,
    })
}

fn load_hello(
    dir: &Path,
    cert_name: &str,
    key_name: &str,
    ticket_name: &str,
    trust: TrustBundle,
    ring: &TicketRing,
) -> Result<HelloConfig, HelloError> {
    let ticket_path = dir.join(ticket_name);
    Ok(HelloConfig {
        certificate_pem: read_text(&dir.join(cert_name))?,
        private_key_pem: read_text(&dir.join(key_name))?,
        trust,
        ticket_bytes: read_bytes(&ticket_path)?,
        ticket_mac: read_array(&mac_path(&ticket_path))?,
        ticket_ring: ring.clone(),
        deny: DenySet::empty(),
    })
}

fn unix_secs(time: SystemTime) -> Result<u64, HelloError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| fail(err.to_string()))
}

fn write_text(path: &Path, text: &str) -> Result<(), HelloError> {
    write_bytes(path, text.as_bytes())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), HelloError> {
    std::fs::write(path, bytes).map_err(|err| {
        fail(format!(
            "The file {} was not written. {err}",
            path.display()
        ))
    })
}

fn write_unix(path: &Path, time: SystemTime) -> Result<(), HelloError> {
    let secs = unix_secs(time)?;
    write_text(path, &secs.to_string())
}

fn read_text(path: &Path) -> Result<String, HelloError> {
    std::fs::read_to_string(path)
        .map_err(|err| fail(format!("The file {} did not open. {err}", path.display())))
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, HelloError> {
    std::fs::read(path)
        .map_err(|err| fail(format!("The file {} did not open. {err}", path.display())))
}

fn read_array(path: &Path) -> Result<[u8; 32], HelloError> {
    let bytes = read_bytes(path)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        fail(format!(
            "The file {} has {} bytes and the reader needs 32 bytes.",
            path.display(),
            bytes.len()
        ))
    })
}

fn read_unix(path: &Path) -> Result<SystemTime, HelloError> {
    let text = read_text(path)?;
    let secs: u64 = text
        .trim()
        .parse()
        .map_err(|_| fail(format!("The time in {} is not valid.", path.display())))?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

fn mac_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".mac");
    PathBuf::from(name)
}
