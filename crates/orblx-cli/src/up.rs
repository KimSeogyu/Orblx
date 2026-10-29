//! `orblx up`, `orblx down`, `orblx status`, and `orblx node-issue`.
//!
//! The node process stays in the foreground.
//! The state directory keeps the overlay IP.
//! The command does not print the private key or the ticket MAC key.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_coord::{
    advertise_routes_blocking, decode_hex_32, encode_hex, verify_signed_grants, NetmapKey,
    SignedGrants,
};
use orblx_crypto::{mac_input, ticket_mac};
use orblx_datapath::{
    read_status_text, remove_link_resolver, run_node, running_pid, AllowPeers, GrantPeers,
    HelloConfig, Netmap, NodeRequest, PeerVisibility, DEFAULT_UDP_PORT, LINUX_TUN_NAME,
};
use orblx_identity::{
    sign_ticket, DenySet, MiniCa, Policy, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
    MAX_USER_TTL,
};

use super::{parse_socket, take_value};

const DEFAULT_STATE_DIR: &str = "/var/lib/orblx";
const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";
const BUNDLE_FILE: &str = "bundle.pem";
const TICKET_FILE: &str = "ticket.bin";
const FILE_SECRET: u32 = 0o600;
const FILE_PUBLIC: u32 = 0o644;
const DIR_PRIVATE: u32 = 0o700;

pub(crate) enum Command {
    Help(String),
    Up(UpOptions),
    Down(StateOptions),
    Status(StateOptions),
    Issue(IssueOptions),
}

pub(crate) struct UpOptions {
    pub(crate) netmap: PathBuf,
    pub(crate) netmap_set: bool,
    pub(crate) state_dir: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) accept_routes: bool,
    pub(crate) advertise_routes: Vec<String>,
    pub(crate) coord: Option<SocketAddr>,
    pub(crate) coord_name: String,
    pub(crate) bundle: Option<PathBuf>,
}

pub(crate) struct StateOptions {
    pub(crate) state_dir: PathBuf,
}

pub(crate) struct IssueOptions {
    out: PathBuf,
    nodes: Vec<(String, Ipv4Addr)>,
    policy: Option<PathBuf>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Help(_) => formatter.write_str("Help"),
            Self::Up(options) => formatter
                .debug_struct("Up")
                .field("netmap", &options.netmap)
                .field("state_dir", &options.state_dir)
                .field("listen", &options.listen)
                .field("accept_routes", &options.accept_routes)
                .field("advertise_routes", &options.advertise_routes.len())
                .finish(),
            Self::Down(options) | Self::Status(options) => formatter
                .debug_struct("State")
                .field("state_dir", &options.state_dir)
                .finish(),
            Self::Issue(options) => formatter
                .debug_struct("Issue")
                .field("out", &options.out)
                .field("nodes", &options.nodes.len())
                .field("policy", &options.policy)
                .finish(),
        }
    }
}

pub(crate) fn parse_up(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(help_text()));
    }
    let mut netmap = None;
    let mut state_dir = None;
    let mut listen = None;
    let mut accept_routes = false;
    let mut advertise_routes = Vec::new();
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--accept-routes" {
            accept_routes = true;
            continue;
        }
        let value = take_value(args, &mut index)?;
        match flag {
            "--netmap" => netmap = Some(PathBuf::from(value)),
            "--state-dir" => state_dir = Some(PathBuf::from(value)),
            "--listen" => listen = Some(parse_socket(&value, DEFAULT_UDP_PORT)?),
            "--advertise-routes" => advertise_routes.push(value),
            "--coord" => coord = Some(parse_socket(&value, 443)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help_text())),
        }
    }
    let state_dir = state_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let netmap_set = netmap.is_some();
    let netmap = netmap.unwrap_or_else(|| state_dir.join("netmap.json"));
    if !advertise_routes.is_empty() && coord.is_some() && bundle.is_none() {
        return Err(format!("The command needs --bundle.\n{}", help_text()));
    }
    if accept_routes && coord.is_some() && bundle.is_none() && advertise_routes.is_empty() {
        return Err(format!("The command needs --bundle.\n{}", help_text()));
    }
    Ok(Command::Up(UpOptions {
        netmap,
        netmap_set,
        state_dir,
        listen: listen
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_UDP_PORT))),
        accept_routes,
        advertise_routes,
        coord,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle,
    }))
}

pub(crate) fn parse_down(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(help_text()));
    }
    Ok(Command::Down(parse_state(args)?))
}

pub(crate) fn parse_status(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(help_text()));
    }
    Ok(Command::Status(parse_state(args)?))
}

pub(crate) fn parse_issue(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(help_text()));
    }
    let mut out = None;
    let mut nodes = Vec::new();
    let mut policy = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--out" => out = Some(PathBuf::from(value)),
            "--node" => nodes.push(parse_node(&value)?),
            "--policy" => policy = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help_text())),
        }
    }
    let out = out.ok_or_else(|| format!("The command needs --out.\n{}", help_text()))?;
    if nodes.is_empty() {
        return Err(format!("The command needs --node.\n{}", help_text()));
    }
    Ok(Command::Issue(IssueOptions { out, nodes, policy }))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Up(options) => run_up(options),
        Command::Down(options) => run_down(options),
        Command::Status(options) => run_status(options),
        Command::Issue(options) => run_issue(options),
    }
}

fn run_up(options: UpOptions) -> Result<(), String> {
    let (netmap_path, forward_routes) = publish_routes(&options)?;
    let netmap = Netmap::from_path(&netmap_path).map_err(|err| err.to_string())?;
    let config = load_config(&options.state_dir)?;
    let visibility = load_visibility(&options.state_dir, &netmap.self_node.name)?;
    run_node(NodeRequest {
        config,
        netmap,
        listen: options.listen,
        state_dir: options.state_dir,
        accept_routes: options.accept_routes,
        forward_routes,
        netmap_path,
        visibility,
    })
    .map_err(|err| err.to_string())
}

fn publish_routes(options: &UpOptions) -> Result<(PathBuf, Vec<String>), String> {
    if options.advertise_routes.is_empty() && !(options.accept_routes && options.coord.is_some()) {
        return Ok((options.netmap.clone(), options.advertise_routes.clone()));
    }
    let Some(coord) = options.coord else {
        return Ok((options.netmap.clone(), options.advertise_routes.clone()));
    };
    let bundle = options
        .bundle
        .as_ref()
        .ok_or_else(|| format!("The command needs --bundle.\n{}", help_text()))?;
    let bundle_pem = fs::read_to_string(bundle)
        .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
    if options.advertise_routes.is_empty() {
        orblx_coord::fetch_netmap_blocking(
            coord,
            &options.coord_name,
            &bundle_pem,
            &options.state_dir,
        )
        .map_err(|err| err.to_string())?;
        println!("The node uses the coordinator netmap.");
        return Ok((options.state_dir.join("netmap.json"), Vec::new()));
    }
    let view = advertise_routes_blocking(
        coord,
        &options.coord_name,
        &bundle_pem,
        &options.state_dir,
        &options.advertise_routes,
    )
    .map_err(|err| err.to_string())?;
    for route in &view.approved_routes {
        println!("approved route {route}");
    }
    for route in &view.advertised_routes {
        if !view.approved_routes.iter().any(|item| item == route) {
            println!("held route {route}");
        }
    }
    let path = if options.netmap_set {
        fs::copy(options.state_dir.join("netmap.json"), &options.netmap)
            .map_err(|err| format!("The netmap file was not written. {err}"))?;
        options.netmap.clone()
    } else {
        options.state_dir.join("netmap.json")
    };
    println!("The node uses the coordinator netmap.");
    Ok((path, view.approved_routes))
}

fn run_down(options: StateOptions) -> Result<(), String> {
    let Some(pid) = running_pid(&options.state_dir) else {
        println!("The node is down.");
        let _ = remove_link_resolver(LINUX_TUN_NAME);
        return Ok(());
    };
    let status = std::process::Command::new("kill")
        .args(["-s", "TERM", &pid.to_string()])
        .status()
        .map_err(|err| format!("The stop signal was not sent. {err}"))?;
    if !status.success() {
        return Err(format!("The stop signal to pid {pid} failed."));
    }
    for _ in 0..50 {
        if running_pid(&options.state_dir).is_none() {
            println!("The node is down.");
            let _ = remove_link_resolver(LINUX_TUN_NAME);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("The node pid {pid} did not stop."))
}

fn run_status(options: StateOptions) -> Result<(), String> {
    let text = read_status_text(&options.state_dir).map_err(|err| err.to_string())?;
    print!("{text}");
    Ok(())
}

fn run_issue(options: IssueOptions) -> Result<(), String> {
    let mut seen = HashSet::new();
    for (name, _) in &options.nodes {
        SpiffeId::node(name).map_err(|_| format!("The node name {name} is not valid."))?;
        if !seen.insert(name.clone()) {
            return Err(format!("The node name {name} is repeated."));
        }
    }
    let now = SystemTime::now();
    let ca = MiniCa::generate(now).map_err(|err| err.to_string())?;
    let signer = TicketSigner::generate();
    if signer.public_key() == *ca.public_key() {
        return Err("The ticket key matches the SVID CA key.".to_string());
    }
    let mac_key = random_key()?;
    let now_unix = unix_secs(now)?;
    let key_not_before = now_unix.saturating_sub(120);
    let key_not_after = now_unix.saturating_add(24 * 60 * 60);
    fs::create_dir_all(&options.out).map_err(|err| {
        format!(
            "The directory {} was not created. {err}",
            options.out.display()
        )
    })?;
    for (name, overlay) in &options.nodes {
        let dir = options.out.join(name);
        fs::create_dir_all(&dir)
            .map_err(|err| format!("The directory {} was not created. {err}", dir.display()))?;
        set_dir_mode(&dir)?;
        let id = SpiffeId::node(name).map_err(|err| err.to_string())?;
        let issued = ca
            .issue(&id, now, MAX_USER_TTL, &DenySet::empty())
            .map_err(|err| err.to_string())?;
        let claims = TicketClaims {
            issuer: SpiffeId::coord("w18").map_err(|err| err.to_string())?,
            subject: id,
            not_before: now_unix,
            expires: now_unix.saturating_add(MAX_USER_TTL.as_secs()),
            dst_cidr: "0.0.0.0/0".to_string(),
            proto: 0,
            dst_port: 0,
            flags: TicketFlags::none(),
        };
        let signed = sign_ticket(&signer, &claims).map_err(|err| err.to_string())?;
        let mac = ticket_mac(&mac_key, mac_input(&signed.bytes)).map_err(|err| err.to_string())?;
        write_mode(
            &dir.join(CERT_FILE),
            issued.certificate_pem.as_bytes(),
            FILE_PUBLIC,
        )?;
        write_mode(
            &dir.join(KEY_FILE),
            issued.private_key_pem.as_bytes(),
            FILE_SECRET,
        )?;
        write_mode(
            &dir.join(BUNDLE_FILE),
            ca.certificate_pem().as_bytes(),
            FILE_PUBLIC,
        )?;
        write_mode(&dir.join(TICKET_FILE), &signed.bytes, FILE_SECRET)?;
        write_mode(&dir.join(format!("{TICKET_FILE}.mac")), &mac, FILE_SECRET)?;
        write_mode(
            &dir.join("ticket-verifier.pem"),
            signer.public_key_pem().as_bytes(),
            FILE_PUBLIC,
        )?;
        write_mode(&dir.join("ticket-mac.key"), &mac_key, FILE_SECRET)?;
        write_mode(&dir.join("svid-ca.pub"), ca.public_key(), FILE_PUBLIC)?;
        write_mode(
            &dir.join("ticket-not-before"),
            key_not_before.to_string().as_bytes(),
            FILE_PUBLIC,
        )?;
        write_mode(
            &dir.join("ticket-not-after"),
            key_not_after.to_string().as_bytes(),
            FILE_PUBLIC,
        )?;
        println!(
            "The command wrote the node {name} material for overlay {overlay} in {}.",
            dir.display()
        );
    }
    if let Some(policy) = &options.policy {
        write_signed_grants(&options.out, &options.nodes, policy)?;
    }
    Ok(())
}

fn load_visibility(dir: &Path, self_name: &str) -> Result<Arc<dyn PeerVisibility>, String> {
    let path = dir.join("grants.signed.json");
    if !path.exists() {
        return Ok(Arc::new(AllowPeers));
    }
    let signed: SignedGrants = serde_json::from_str(&read_text(&path)?)
        .map_err(|_| "The grants are not valid.".to_string())?;
    let public = decode_hex_32(read_text(&dir.join("netmap.pub"))?.trim())
        .map_err(|_| "The netmap public key is not valid.".to_string())?;
    verify_signed_grants(&signed, &public)
        .map_err(|_| "The grant signature is not valid.".to_string())?;
    let receiver = SpiffeId::node(self_name).map_err(|err| err.to_string())?;
    if signed.grants.receiver != receiver.as_uri() {
        return Err("The grant receiver does not match the node.".to_string());
    }
    println!(
        "The DNS responder uses the signed grants. This node can reach {} peers.",
        signed.grants.reach.len()
    );
    Ok(Arc::new(GrantPeers::from_grants(&signed.grants)))
}

fn write_signed_grants(
    out: &Path,
    nodes: &[(String, Ipv4Addr)],
    policy_path: &Path,
) -> Result<(), String> {
    let policy = Policy::from_path(policy_path).map_err(|err| err.to_string())?;
    let key = NetmapKey::generate();
    let public = format!("{}\n", encode_hex(&key.public()));
    for (name, _) in nodes {
        let id = SpiffeId::node(name).map_err(|err| err.to_string())?;
        let grants = policy.receiver_grants(&id);
        let signed = key.sign_grants(&grants).map_err(|err| err.to_string())?;
        let dir = out.join(name);
        let signed_text =
            serde_json::to_string(&signed).map_err(|_| "The grants are not valid.".to_string())?;
        let grant_text = serde_json::to_string(&signed.grants)
            .map_err(|_| "The grants are not valid.".to_string())?;
        write_mode(
            &dir.join("grants.signed.json"),
            signed_text.as_bytes(),
            FILE_PUBLIC,
        )?;
        write_mode(&dir.join("grants.json"), grant_text.as_bytes(), FILE_PUBLIC)?;
        write_mode(&dir.join("netmap.pub"), public.as_bytes(), FILE_PUBLIC)?;
        println!(
            "The command wrote signed grants for {name}. reach {}",
            grants.reach.len()
        );
    }
    Ok(())
}

fn load_config(dir: &Path) -> Result<HelloConfig, String> {
    let certificate_pem = read_text(&dir.join(CERT_FILE))?;
    let private_key_pem = read_text(&dir.join(KEY_FILE))?;
    let bundle_pem = read_text(&dir.join(BUNDLE_FILE))?;
    let trust =
        orblx_identity::TrustBundle::from_pem(&bundle_pem).map_err(|err| err.to_string())?;
    super::ticket_load::load_hello_config(
        certificate_pem,
        private_key_pem,
        trust,
        &dir.join(TICKET_FILE),
    )
}

fn parse_state(args: &[String]) -> Result<StateOptions, String> {
    let mut state_dir = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--state-dir" => state_dir = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help_text())),
        }
    }
    Ok(StateOptions {
        state_dir: state_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
    })
}

fn parse_node(value: &str) -> Result<(String, Ipv4Addr), String> {
    let Some((name, ip_text)) = value.split_once('=') else {
        return Err(format!(
            "The node value {value} is not NAME=OVERLAY_IP.\n{}",
            help_text()
        ));
    };
    let ip = ip_text
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("The overlay address {ip_text} is not valid."))?;
    if name.is_empty() {
        return Err("The node name is empty.".to_string());
    }
    Ok((name.to_string(), ip))
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn help_text() -> String {
    format!(
        "\
orblx up [--netmap FILE] [--state-dir DIR] [--listen ADDR] [--accept-routes] [--advertise-routes CIDR] [--coord ADDR] [--bundle FILE] [--coord-name NAME]
orblx down [--state-dir DIR]
orblx status [--state-dir DIR]
orblx node-issue --out DIR --node NAME=OVERLAY_IP [--node NAME=OVERLAY_IP ...] [--policy FILE]

The node keeps one QUIC session for each peer.
The router sends each outbound TUN packet to the peer that owns the destination.
The node answers DNS on the overlay address at port 53.
A netmap name is <node>.<owner>.orblx and the short name <node>.
The node forwards every other name.
The node reads grants.signed.json from the state directory.
That file is the signed grant document from the netmap.
A peer absent from the reach list is NXDOMAIN.
A missing grant file allows every peer.
The --policy file writes those signed grants during node-issue.
The node does not read the policy file.
On Linux the node sets the per-link domain ~orblx on the TUN device.
On macOS the node writes /etc/resolver/orblx.
orblx down removes that resolver configuration.
The default state directory is {DEFAULT_STATE_DIR}.
The default netmap file is {DEFAULT_STATE_DIR}/netmap.json.
The node stores the overlay IP in that directory.
A restart reads the stored overlay IP.
The --listen address is the UDP socket.
The default port is {DEFAULT_UDP_PORT}.
The state directory holds the node certificate, the private key, the trust bundle, and the capability ticket.
The command does not print the private key or the ticket MAC key.
orblx status prints each peer, the path kind, and the SVID expiry.
The path kind is direct when the QUIC session is up.
--advertise-routes sends the CIDR to the coordinator when --coord and --bundle are set.
The coordinator publishes a route after the policy approves it.
A route that the policy does not approve stays off the signed netmap.
--accept-routes installs approved subnet routes on the TUN device.
The node does not install 0.0.0.0/0.
The router forwards an approved local subnet with kernel masquerade.
"
    )
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(path)
        .map_err(|err| format!("The file {} was not written. {err}", path.display()))?;
    file.write_all(bytes)
        .map_err(|err| format!("The file {} was not written. {err}", path.display()))?;
    Ok(())
}

fn set_dir_mode(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(DIR_PRIVATE))
        .map_err(|err| format!("The directory {} was not updated. {err}", path.display()))
}

fn random_key() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    let mut file = fs::File::open("/dev/urandom")
        .map_err(|err| format!("The random source did not open. {err}"))?;
    file.read_exact(&mut bytes)
        .map_err(|err| format!("The random source did not fill the key. {err}"))?;
    Ok(bytes)
}

fn unix_secs(now: SystemTime) -> Result<u64, String> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "The clock is not valid.".to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    use super::{parse_issue, parse_up, run, Command, DEFAULT_STATE_DIR};

    #[test]
    fn up_defaults_the_state_directory_and_the_port() {
        let command = parse_up(&["--netmap".to_string(), "netmap.json".to_string()]).unwrap();
        match command {
            Command::Up(options) => {
                assert_eq!(options.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
                assert_eq!(
                    options.listen,
                    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443))
                );
                assert_eq!(options.netmap, PathBuf::from("netmap.json"));
                assert!(!options.accept_routes);
                assert!(options.advertise_routes.is_empty());
            }
            Command::Help(_) | Command::Down(_) | Command::Status(_) | Command::Issue(_) => {
                panic!("the parser did not select up");
            }
        }
    }

    #[test]
    fn up_defaults_the_netmap_file() {
        let command = parse_up(&[]).unwrap();
        match command {
            Command::Up(options) => {
                assert_eq!(
                    options.netmap,
                    PathBuf::from(DEFAULT_STATE_DIR).join("netmap.json")
                );
                assert!(!options.netmap_set);
            }
            Command::Help(_) | Command::Down(_) | Command::Status(_) | Command::Issue(_) => {
                panic!("the parser did not select up");
            }
        }
    }

    #[test]
    fn up_accepts_route_flags() {
        let command = parse_up(&[
            "--accept-routes".to_string(),
            "--advertise-routes".to_string(),
            "10.88.0.0/24".to_string(),
            "--advertise-routes".to_string(),
            "10.99.0.0/24".to_string(),
        ])
        .unwrap();
        match command {
            Command::Up(options) => {
                assert!(options.accept_routes);
                assert_eq!(options.advertise_routes.len(), 2);
                assert!(options.coord.is_none());
            }
            Command::Help(_) | Command::Down(_) | Command::Status(_) | Command::Issue(_) => {
                panic!("the parser did not select up");
            }
        }
    }

    #[test]
    fn node_issue_writes_material_the_node_can_load() {
        let dir = std::env::temp_dir().join(format!("orblx-w18-issue-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        run(parse_issue(&[
            "--out".to_string(),
            dir.to_string_lossy().to_string(),
            "--node".to_string(),
            "a=100.64.0.1".to_string(),
        ])
        .unwrap())
        .unwrap();
        let config = super::load_config(&dir.join("a")).unwrap();
        assert!(config.certificate_pem.contains("CERTIFICATE"));
        assert!(!config.private_key_pem.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_issue_signs_grants_that_hide_a_denied_peer() {
        let dir = std::env::temp_dir().join(format!("orblx-w18-grants-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("policy.hujson");
        fs::write(
            &policy,
            r#"{
                "acls": [
                    {"action": "accept", "src": ["spiffe://orblx.local/node/a"], "proto": "tcp", "dst": ["spiffe://orblx.local/node/b:8080"]},
                    {"action": "accept", "src": ["spiffe://orblx.local/node/b"], "proto": "tcp", "dst": ["spiffe://orblx.local/node/a:8080"]}
                ],
                "tests": [{
                    "src": "spiffe://orblx.local/node/a",
                    "proto": "tcp",
                    "accept": ["spiffe://orblx.local/node/b:8080"],
                    "deny": ["spiffe://orblx.local/node/c:8080"]
                }]
            }"#,
        )
        .unwrap();
        run(parse_issue(&[
            "--out".to_string(),
            dir.to_string_lossy().to_string(),
            "--policy".to_string(),
            policy.to_string_lossy().to_string(),
            "--node".to_string(),
            "a=100.64.0.1".to_string(),
            "--node".to_string(),
            "b=100.64.0.2".to_string(),
            "--node".to_string(),
            "c=100.64.0.3".to_string(),
        ])
        .unwrap())
        .unwrap();
        let visibility = super::load_visibility(&dir.join("a"), "a").unwrap();
        let peer_b = orblx_datapath::NetmapPeer {
            name: "b".to_string(),
            overlay_ip: "100.64.0.2".to_string(),
            svid: "spiffe://orblx.local/node/b".to_string(),
            endpoints: vec!["172.28.18.12:443".to_string()],
            routes: Vec::new(),
            owner: "lab".to_string(),
        };
        let mut peer_c = peer_b.clone();
        peer_c.name = "c".to_string();
        peer_c.overlay_ip = "100.64.0.3".to_string();
        peer_c.svid = "spiffe://orblx.local/node/c".to_string();
        assert!(visibility.is_visible(&peer_b));
        assert!(!visibility.is_visible(&peer_c));
        let mut signed = fs::read_to_string(dir.join("a").join("grants.signed.json")).unwrap();
        signed.push('x');
        fs::write(dir.join("a").join("grants.signed.json"), signed).unwrap();
        assert!(super::load_visibility(&dir.join("a"), "a").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
