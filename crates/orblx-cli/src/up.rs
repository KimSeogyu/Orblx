//! `orblx up`, `orblx down`, `orblx status`, and `orblx node-issue`.
//!
//! The node process stays in the foreground.
//! The state directory keeps the overlay IP.
//! The command does not print the private key or the ticket MAC key.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_coord::{
    advertise_routes_blocking, decode_hex_32, encode_hex, renew_svid_blocking,
    verify_signed_grants, NetmapKey, SignedGrants,
};
use orblx_crypto::{mac_input, ticket_mac};
use orblx_datapath::{
    read_status_text, remove_link_resolver, run_node, running_pid, AllowPeers, HelloConfig, Netmap,
    NetmapPeer, NodeRequest, PeerVisibility, RenewedLeaf, SvidRenewer, DEFAULT_UDP_PORT,
    LINUX_TUN_NAME,
};
use orblx_identity::{
    sign_ticket, DenySet, MiniCa, Policy, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
    MAX_AGENT_TTL, MAX_USER_TTL,
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
    Up(Box<UpOptions>),
    Down(StateOptions),
    Status(StateOptions),
    Issue(IssueOptions),
    Set(SetOptions),
}

pub(crate) struct SetOptions {
    pub(crate) state_dir: PathBuf,
    pub(crate) exit_node: String,
    pub(crate) allow_lan: bool,
}

pub(crate) struct UpOptions {
    pub(crate) netmap: PathBuf,
    pub(crate) netmap_set: bool,
    pub(crate) state_dir: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) accept_routes: bool,
    pub(crate) advertise_routes: Vec<String>,
    pub(crate) advertise_exit: bool,
    pub(crate) exit_node: Option<String>,
    pub(crate) allow_lan: bool,
    pub(crate) relay: Option<SocketAddr>,
    pub(crate) coord: Option<SocketAddr>,
    pub(crate) coord_name: Option<String>,
    pub(crate) bundle: Option<PathBuf>,
    pub(crate) metrics: Option<SocketAddr>,
}

pub(crate) struct StateOptions {
    pub(crate) state_dir: PathBuf,
}

pub(crate) struct IssueOptions {
    out: PathBuf,
    nodes: Vec<(String, Ipv4Addr)>,
    policy: Option<PathBuf>,
    users: Vec<String>,
    agents: Vec<IssuedAgent>,
}

struct IssuedAgent {
    name: String,
    parent: String,
    host: Ipv4Addr,
    user: String,
}

struct PendingAgent {
    name: String,
    parent: Option<String>,
    host: Option<Ipv4Addr>,
    user: Option<String>,
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
                .field("advertise_exit", &options.advertise_exit)
                .field("exit_node", &options.exit_node)
                .field("allow_lan", &options.allow_lan)
                .field("relay", &options.relay)
                .field("coord", &options.coord)
                .field("metrics", &options.metrics)
                .finish(),
            Self::Set(options) => formatter
                .debug_struct("Set")
                .field("state_dir", &options.state_dir)
                .field("exit_node", &options.exit_node)
                .field("allow_lan", &options.allow_lan)
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
                .field("users", &options.users.len())
                .field("agents", &options.agents.len())
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
    let mut advertise_exit = false;
    let mut exit_node = None;
    let mut allow_lan = false;
    let mut relay = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut metrics = Some(orblx_audit::default_metrics_addr());
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--accept-routes" {
            accept_routes = true;
            continue;
        }
        if flag == "--advertise-exit-node" {
            advertise_exit = true;
            continue;
        }
        if flag == "--exit-node-allow-lan-access" {
            allow_lan = true;
            continue;
        }
        let value = take_value(args, &mut index)?;
        match flag {
            "--netmap" => netmap = Some(PathBuf::from(value)),
            "--state-dir" => state_dir = Some(PathBuf::from(value)),
            "--listen" => listen = Some(parse_socket(&value, DEFAULT_UDP_PORT)?),
            "--advertise-routes" => advertise_routes.push(value),
            "--exit-node" => exit_node = Some(value),
            "--relay" => relay = Some(parse_socket(&value, 443)?),
            "--coord" => coord = Some(parse_socket(&value, 443)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--metrics" => {
                metrics = if value == "off" {
                    None
                } else {
                    Some(parse_socket(&value, orblx_audit::DEFAULT_METRICS_PORT)?)
                };
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help_text())),
        }
    }
    let state_dir = state_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    let netmap_set = netmap.is_some();
    let netmap = netmap.unwrap_or_else(|| state_dir.join("netmap.json"));
    let needs_bundle = coord.is_some()
        && bundle.is_none()
        && (advertise_exit || !advertise_routes.is_empty() || accept_routes || exit_node.is_some());
    if needs_bundle {
        return Err(format!("The command needs --bundle.\n{}", help_text()));
    }
    if let Some(name) = exit_node.as_deref() {
        if name.is_empty() {
            return Err(format!("The exit node name is empty.\n{}", help_text()));
        }
    }
    Ok(Command::Up(Box::new(UpOptions {
        netmap,
        netmap_set,
        state_dir,
        listen: listen
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_UDP_PORT))),
        accept_routes,
        advertise_routes,
        advertise_exit,
        exit_node,
        allow_lan,
        relay,
        coord,
        coord_name,
        bundle,
        metrics,
    })))
}

pub(crate) fn parse_set(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(help_text()));
    }
    let mut state_dir = None;
    let mut exit_node = None;
    let mut allow_lan = false;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--exit-node-allow-lan-access" {
            allow_lan = true;
            continue;
        }
        let value = take_value(args, &mut index)?;
        match flag {
            "--state-dir" => state_dir = Some(PathBuf::from(value)),
            "--exit-node" => exit_node = Some(value),
            other => return Err(format!("The flag {other} is not valid.\n{}", help_text())),
        }
    }
    let exit_node =
        exit_node.ok_or_else(|| format!("The command needs --exit-node.\n{}", help_text()))?;
    if exit_node.is_empty() {
        return Err(format!("The exit node name is empty.\n{}", help_text()));
    }
    Ok(Command::Set(SetOptions {
        state_dir: state_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
        exit_node,
        allow_lan,
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
    let mut users = Vec::new();
    let mut agents = Vec::new();
    let mut pending: Option<PendingAgent> = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--out" => out = Some(PathBuf::from(value)),
            "--node" => nodes.push(parse_node(&value)?),
            "--policy" => policy = Some(PathBuf::from(value)),
            "--user" => users.push(value),
            "--agent" => {
                if let Some(agent) = pending.take() {
                    agents.push(finish_agent(agent)?);
                }
                pending = Some(PendingAgent {
                    name: value,
                    parent: None,
                    host: None,
                    user: None,
                });
            }
            "--agent-parent" => {
                let agent = pending.as_mut().ok_or_else(|| {
                    format!("The flag --agent-parent needs --agent.\n{}", help_text())
                })?;
                agent.parent = Some(value);
            }
            "--agent-host" => {
                let agent = pending.as_mut().ok_or_else(|| {
                    format!("The flag --agent-host needs --agent.\n{}", help_text())
                })?;
                agent.host = Some(parse_ipv4(&value)?);
            }
            "--agent-user" => {
                let agent = pending.as_mut().ok_or_else(|| {
                    format!("The flag --agent-user needs --agent.\n{}", help_text())
                })?;
                agent.user = Some(value);
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help_text())),
        }
    }
    if let Some(agent) = pending {
        agents.push(finish_agent(agent)?);
    }
    let out = out.ok_or_else(|| format!("The command needs --out.\n{}", help_text()))?;
    if nodes.is_empty() {
        return Err(format!("The command needs --node.\n{}", help_text()));
    }
    Ok(Command::Issue(IssueOptions {
        out,
        nodes,
        policy,
        users,
        agents,
    }))
}

fn finish_agent(agent: PendingAgent) -> Result<IssuedAgent, String> {
    let parent = agent.parent.ok_or_else(|| {
        format!(
            "The agent {} needs --agent-parent.\n{}",
            agent.name,
            help_text()
        )
    })?;
    let host = agent.host.ok_or_else(|| {
        format!(
            "The agent {} needs --agent-host.\n{}",
            agent.name,
            help_text()
        )
    })?;
    let user = agent.user.ok_or_else(|| {
        format!(
            "The agent {} needs --agent-user.\n{}",
            agent.name,
            help_text()
        )
    })?;
    Ok(IssuedAgent {
        name: agent.name,
        parent,
        host,
        user,
    })
}

fn parse_ipv4(text: &str) -> Result<Ipv4Addr, String> {
    text.parse()
        .map_err(|_| format!("The overlay address {text} is not valid."))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Up(options) => run_up(*options),
        Command::Down(options) => run_down(options),
        Command::Status(options) => run_status(options),
        Command::Issue(options) => run_issue(options),
        Command::Set(options) => run_set(options),
    }
}

fn run_up(mut options: UpOptions) -> Result<(), String> {
    apply_saved_exit(&mut options)?;
    let (netmap_path, forward_routes, forward_exit) = publish_routes(&options)?;
    let netmap = Netmap::from_path(&netmap_path).map_err(|err| err.to_string())?;
    let config = load_config(&options.state_dir)?;
    let visibility = load_visibility(&options.state_dir, &netmap.self_node.name)?;
    let ssh_state = options.state_dir.clone();
    spawn_deny_refresh(&options);
    let underlay = underlay_for(&netmap, options.coord, options.relay);
    let renew = load_renewer(&options.state_dir, options.coord, options.coord_name)?;
    run_node(NodeRequest {
        config,
        netmap,
        listen: options.listen,
        state_dir: options.state_dir,
        renew,
        stop: None,
        accept_routes: options.accept_routes,
        forward_routes,
        forward_exit,
        exit_node: options.exit_node,
        allow_lan: options.allow_lan,
        underlay,
        relay: options.relay,
        netmap_path,
        visibility,
        on_ready: Some(Box::new(move |overlay| {
            if let Err(err) = orblx_ssh::spawn_overlay_server(&ssh_state, overlay) {
                eprintln!("The SSH server did not start. {err}");
            }
        })),
        metrics: options.metrics,
    })
    .map_err(|err| err.to_string())
}

fn push_ipv4(extra: &mut Vec<Ipv4Addr>, addr: Option<SocketAddr>) {
    if let Some(SocketAddr::V4(addr)) = addr {
        extra.push(*addr.ip());
    }
}

fn underlay_for(
    netmap: &Netmap,
    coord: Option<SocketAddr>,
    relay: Option<SocketAddr>,
) -> Vec<Ipv4Addr> {
    let mut extra = Vec::new();
    push_ipv4(&mut extra, coord);
    push_ipv4(&mut extra, relay);
    let mut endpoints = Vec::new();
    for peer in &netmap.peers {
        endpoints.extend(peer.endpoints.iter().cloned());
    }
    orblx_datapath::underlay_addresses(&endpoints, &extra)
}

fn load_renewer(
    state: &Path,
    coord: Option<SocketAddr>,
    coord_name: Option<String>,
) -> Result<Option<SvidRenewer>, String> {
    let address = match coord {
        Some(value) => value,
        None => {
            let path = state.join("coord-addr");
            if !path.exists() {
                return Ok(None);
            }
            let text = read_text(&path)?;
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            resolve_coord(trimmed)?
        }
    };
    let name = match coord_name {
        Some(value) => value,
        None => {
            let path = state.join("coord-name");
            if path.exists() {
                let text = read_text(&path)?;
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    "coord".to_string()
                } else {
                    trimmed.to_string()
                }
            } else {
                "coord".to_string()
            }
        }
    };
    let state = state.to_path_buf();
    Ok(Some(SvidRenewer::new(move || {
        renew_from_coord(&state, address, &name)
    })))
}

fn renew_from_coord(state: &Path, coord: SocketAddr, name: &str) -> Result<RenewedLeaf, String> {
    let bundle = read_text(&state.join(BUNDLE_FILE))?;
    let result = renew_svid_blocking(coord, name, &bundle, state).map_err(|err| err.to_string())?;
    Ok(RenewedLeaf {
        certificate_pem: result.certificate_pem,
        private_key_pem: result.private_key_pem,
    })
}

fn resolve_coord(text: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = text
        .to_socket_addrs()
        .map_err(|_| format!("The coordinator address {text} is not valid."))?;
    addrs
        .next()
        .ok_or_else(|| format!("The coordinator address {text} is not valid."))
}

fn publish_routes(options: &UpOptions) -> Result<(PathBuf, Vec<String>, bool), String> {
    let wants_fetch = options.coord.is_some()
        && (options.accept_routes || options.exit_node.is_some() || options.advertise_exit);
    if options.advertise_routes.is_empty() && !options.advertise_exit && !wants_fetch {
        return Ok((options.netmap.clone(), Vec::new(), false));
    }
    let Some(coord) = options.coord else {
        return Ok((
            options.netmap.clone(),
            options.advertise_routes.clone(),
            options.advertise_exit,
        ));
    };
    let bundle = options
        .bundle
        .as_ref()
        .ok_or_else(|| format!("The command needs --bundle.\n{}", help_text()))?;
    let bundle_pem = fs::read_to_string(bundle)
        .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
    let coord_name = options.coord_name.as_deref().unwrap_or("coord");
    if options.advertise_routes.is_empty() && !options.advertise_exit {
        orblx_coord::fetch_netmap_blocking(coord, coord_name, &bundle_pem, &options.state_dir)
            .map_err(|err| err.to_string())?;
        println!("The node uses the coordinator netmap.");
        return Ok((options.state_dir.join("netmap.json"), Vec::new(), false));
    }
    let mut forward_routes = Vec::new();
    let mut forward_exit = false;
    if !options.advertise_routes.is_empty() {
        let view = advertise_routes_blocking(
            coord,
            coord_name,
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
        if options.netmap_set {
            fs::copy(options.state_dir.join("netmap.json"), &options.netmap)
                .map_err(|err| format!("The netmap file was not written. {err}"))?;
        }
        forward_routes = view.approved_routes;
    }
    if options.advertise_exit {
        let view = orblx_coord::advertise_exit_blocking(
            coord,
            coord_name,
            &bundle_pem,
            &options.state_dir,
            true,
        )
        .map_err(|err| err.to_string())?;
        if view.exit_approved {
            println!("approved exit node");
            forward_exit = true;
        } else {
            println!("held exit node");
        }
        if options.netmap_set {
            fs::copy(options.state_dir.join("netmap.json"), &options.netmap)
                .map_err(|err| format!("The netmap file was not written. {err}"))?;
        }
    }
    println!("The node uses the coordinator netmap.");
    let path = if options.netmap_set {
        options.netmap.clone()
    } else {
        options.state_dir.join("netmap.json")
    };
    Ok((path, forward_routes, forward_exit))
}

fn apply_saved_exit(options: &mut UpOptions) -> Result<(), String> {
    if options.exit_node.is_some() {
        return Ok(());
    }
    let path = options.state_dir.join("exit-node.json");
    if !path.exists() {
        return Ok(());
    }
    let text = read_text(&path)?;
    let prefs: ExitPrefs =
        serde_json::from_str(&text).map_err(|_| "The exit node file is not valid.".to_string())?;
    if prefs.exit_node.is_empty() {
        return Ok(());
    }
    options.exit_node = Some(prefs.exit_node);
    options.allow_lan = options.allow_lan || prefs.allow_lan;
    println!(
        "The node uses exit node {}.",
        options.exit_node.as_deref().unwrap_or("")
    );
    Ok(())
}

fn run_set(options: SetOptions) -> Result<(), String> {
    fs::create_dir_all(&options.state_dir).map_err(|err| {
        format!(
            "The directory {} was not created. {err}",
            options.state_dir.display()
        )
    })?;
    let prefs = ExitPrefs {
        exit_node: options.exit_node.clone(),
        allow_lan: options.allow_lan,
    };
    let text = serde_json::to_string(&prefs)
        .map_err(|_| "The exit node file was not written.".to_string())?;
    write_mode(
        &options.state_dir.join("exit-node.json"),
        text.as_bytes(),
        FILE_PUBLIC,
    )?;
    if options.allow_lan {
        println!(
            "The next start uses exit node {} and keeps LAN access.",
            options.exit_node
        );
    } else {
        println!("The next start uses exit node {}.", options.exit_node);
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExitPrefs {
    exit_node: String,
    #[serde(default)]
    allow_lan: bool,
}

fn spawn_deny_refresh(options: &UpOptions) {
    let coord = match options.coord {
        Some(addr) => addr,
        None => {
            let path = options.state_dir.join("coord-addr");
            let Ok(text) = fs::read_to_string(&path) else {
                return;
            };
            let Ok(addr) = text.trim().parse::<SocketAddr>() else {
                return;
            };
            addr
        }
    };
    let name = match &options.coord_name {
        Some(name) => name.clone(),
        None => fs::read_to_string(options.state_dir.join("coord-name"))
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "coord".to_string()),
    };
    let state = options.state_dir.clone();
    thread::spawn(move || loop {
        if let Ok(bundle) = fs::read_to_string(state.join(BUNDLE_FILE)) {
            if let Ok(text) = orblx_coord::fetch_deny_blocking(coord, &name, &bundle, &state) {
                let _ = fs::write(state.join("deny.json"), text.as_bytes());
            }
        }
        thread::sleep(Duration::from_secs(10));
    });
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
    issue_users(&options, &ca)?;
    issue_agents(&options, &ca, &signer, now, now_unix)?;
    Ok(())
}

fn issue_users(options: &IssueOptions, ca: &MiniCa) -> Result<(), String> {
    let mut seen = HashSet::new();
    let now = SystemTime::now();
    for name in &options.users {
        SpiffeId::user(name).map_err(|_| format!("The user name {name} is not valid."))?;
        if !seen.insert(name.clone()) {
            return Err(format!("The user name {name} is repeated."));
        }
        let dir = options.out.join("users").join(name);
        fs::create_dir_all(&dir)
            .map_err(|err| format!("The directory {} was not created. {err}", dir.display()))?;
        set_dir_mode(&dir)?;
        let id = SpiffeId::user(name).map_err(|err| err.to_string())?;
        let issued = ca
            .issue(&id, now, MAX_USER_TTL, &DenySet::empty())
            .map_err(|err| err.to_string())?;
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
        println!(
            "The command wrote the user {name} material in {}.",
            dir.display()
        );
    }
    Ok(())
}

fn issue_agents(
    options: &IssueOptions,
    ca: &MiniCa,
    signer: &TicketSigner,
    now: SystemTime,
    now_unix: u64,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for agent in &options.agents {
        SpiffeId::agent(&agent.name)
            .map_err(|_| format!("The agent name {} is not valid.", agent.name))?;
        if !seen.insert(agent.name.clone()) {
            return Err(format!("The agent name {} is repeated.", agent.name));
        }
        if !options.users.iter().any(|user| user == &agent.parent) {
            return Err(format!(
                "The agent {} parent {} is not a user in this issue.",
                agent.name, agent.parent
            ));
        }
        if !login_name_ok(&agent.user) {
            return Err(format!("The login name {} is not valid.", agent.user));
        }
        let dir = options.out.join("agents").join(&agent.name);
        fs::create_dir_all(&dir)
            .map_err(|err| format!("The directory {} was not created. {err}", dir.display()))?;
        set_dir_mode(&dir)?;
        let id = SpiffeId::agent(&agent.name).map_err(|err| err.to_string())?;
        let issued = ca
            .issue(&id, now, MAX_AGENT_TTL, &DenySet::empty())
            .map_err(|err| err.to_string())?;
        let claims = TicketClaims {
            issuer: SpiffeId::coord("ssh").map_err(|err| err.to_string())?,
            subject: id,
            not_before: now_unix,
            expires: now_unix.saturating_add(MAX_AGENT_TTL.as_secs()),
            dst_cidr: format!("{}/32", agent.host),
            proto: 6,
            dst_port: 22,
            flags: TicketFlags::new(true, true),
        };
        let signed = sign_ticket(signer, &claims).map_err(|err| err.to_string())?;
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
        println!(
            "The command wrote the agent {} ticket for host {} user {} in {}.",
            agent.name,
            agent.host,
            agent.user,
            dir.display()
        );
    }
    Ok(())
}

fn login_name_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
}

fn load_visibility(dir: &Path, self_name: &str) -> Result<Arc<dyn PeerVisibility>, String> {
    let path = dir.join("grants.signed.json");
    if !path.exists() {
        return Ok(Arc::new(AllowPeers));
    }
    let live = LiveGrants::open(&path, dir, self_name)?;
    println!(
        "The DNS responder uses the signed grants. This node can reach {} peers.",
        live.reach_len()
    );
    Ok(Arc::new(live))
}

/// Signed grants that the node reads again after a renewal.
struct LiveGrants {
    path: PathBuf,
    public: [u8; 32],
    receiver: String,
    reach: Mutex<HashSet<String>>,
    seen: Mutex<Vec<u8>>,
    revision: AtomicU64,
    error: Mutex<String>,
}

impl LiveGrants {
    fn open(path: &Path, dir: &Path, self_name: &str) -> Result<Self, String> {
        let bytes = fs::read(path)
            .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
        let signed = parse_grants(&bytes)?;
        let public = decode_hex_32(read_text(&dir.join("netmap.pub"))?.trim())
            .map_err(|_| "The netmap public key is not valid.".to_string())?;
        verify_signed_grants(&signed, &public)
            .map_err(|_| "The grant signature is not valid.".to_string())?;
        let receiver = SpiffeId::node(self_name).map_err(|err| err.to_string())?;
        if signed.grants.receiver != receiver.as_uri() {
            return Err("The grant receiver does not match the node.".to_string());
        }
        Ok(Self {
            path: path.to_path_buf(),
            public,
            receiver: receiver.as_uri().to_string(),
            reach: Mutex::new(signed.grants.reach.into_iter().collect()),
            seen: Mutex::new(bytes),
            revision: AtomicU64::new(1),
            error: Mutex::new(String::new()),
        })
    }

    fn reach_len(&self) -> usize {
        self.reach
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .len()
    }

    fn refresh(&self) {
        let Ok(bytes) = fs::read(&self.path) else {
            return;
        };
        {
            let seen = self.seen.lock().unwrap_or_else(|err| err.into_inner());
            if *seen == bytes {
                return;
            }
        }
        let signed = match parse_grants(&bytes) {
            Ok(signed) => signed,
            Err(text) => {
                self.keep_previous(bytes, &text);
                return;
            }
        };
        if verify_signed_grants(&signed, &self.public).is_err() {
            self.keep_previous(bytes, "The grant signature is not valid.");
            return;
        }
        if signed.grants.receiver != self.receiver {
            self.keep_previous(bytes, "The grant receiver does not match the node.");
            return;
        }
        let count = signed.grants.reach.len();
        *self.reach.lock().unwrap_or_else(|err| err.into_inner()) =
            signed.grants.reach.into_iter().collect();
        *self.seen.lock().unwrap_or_else(|err| err.into_inner()) = bytes;
        self.revision.fetch_add(1, Ordering::Relaxed);
        println!("The DNS responder loaded new signed grants. This node can reach {count} peers.");
    }

    fn keep_previous(&self, bytes: Vec<u8>, text: &str) {
        *self.seen.lock().unwrap_or_else(|err| err.into_inner()) = bytes;
        let mut error = self.error.lock().unwrap_or_else(|err| err.into_inner());
        if *error != text {
            eprintln!("The node keeps the current DNS grants. {text}");
            *error = text.to_string();
        }
    }
}

impl PeerVisibility for LiveGrants {
    fn is_visible(&self, peer: &NetmapPeer) -> bool {
        self.refresh();
        self.reach
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .contains(&peer.svid)
    }

    fn revision(&self) -> u64 {
        self.refresh();
        self.revision.load(Ordering::Relaxed)
    }
}

fn parse_grants(bytes: &[u8]) -> Result<SignedGrants, String> {
    serde_json::from_slice(bytes).map_err(|_| "The grants are not valid.".to_string())
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
orblx up [--netmap FILE] [--state-dir DIR] [--listen ADDR] [--accept-routes] [--advertise-routes CIDR] [--advertise-exit-node] [--exit-node NAME] [--exit-node-allow-lan-access] [--relay ADDR] [--coord ADDR] [--bundle FILE] [--coord-name NAME]
orblx set --exit-node NAME [--exit-node-allow-lan-access] [--state-dir DIR]
orblx down [--state-dir DIR]
orblx status [--state-dir DIR]
orblx node-issue --out DIR --node NAME=OVERLAY_IP [--node NAME=OVERLAY_IP ...] [--policy FILE] [--user NAME] [--agent NAME --agent-parent USER --agent-host ADDR --agent-user USER]

The node keeps one QUIC session for each peer.
The router sends each outbound TUN packet to the peer that owns the destination.
The node answers DNS on the overlay address at port 53.
A netmap name is <node>.<owner>.orblx and the short name <node>.
The node forwards every other name.
The node reads grants.signed.json from the state directory.
That file is the signed grant document from the netmap.
A peer absent from the reach list is NXDOMAIN.
A new grants.signed.json file replaces the DNS reach list.
A missing grant file allows every peer.
The --policy file writes those signed grants during node-issue.
The node does not read the policy file.
--user writes a user SVID under users/NAME.
--agent writes an agent SVID and one ticket under agents/NAME.
The ticket sets FLAG_AGENT_JIT and FLAG_ONE_SHOT.
The ticket names one host, TCP, and port 22.
The login name comes from --agent-user.
The command does not print the private key or the ticket.
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
The path kind is direct when the session received a frame in the last 2 seconds.
The path kind is stale when the session is up and that frame is older.
The path kind is down when the session is down.
The node renews the SVID from the coordinator at two thirds of the certificate life.
The coordinator address is --coord or the file coord-addr in the state directory.
The command does not print the private key or a token.
--advertise-routes sends the CIDR to the coordinator when --coord and --bundle are set.
The coordinator publishes a route after the policy approves it.
A route that the policy does not approve stays off the signed netmap.
--accept-routes installs approved subnet routes on the TUN device.
--exit-node NAME routes 0.0.0.0/0 through that approved exit node.
An exit node that the policy does not approve is not used.
--exit-node-allow-lan-access keeps connected LAN prefixes on the local interface.
--advertise-exit-node offers this node as an exit node.
The policy autoApprovers exitNode class approves that offer.
The node masquerades overlay traffic that leaves the node.
The node keeps coordinator, Relay, and peer underlay addresses outside the tunnel.
While an exit node is in use, non-overlay DNS queries go through that exit node.
--relay ADDR is the orblx Relay. UDP is the first path. TCP port 443 is the fallback.
orblx set stores the exit node for the next orblx up.
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
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use orblx_identity::{verify_ticket, DenySet, TicketVerifier};

    use super::{parse_issue, parse_set, parse_up, run, Command, DEFAULT_STATE_DIR};

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
            Command::Help(_)
            | Command::Down(_)
            | Command::Status(_)
            | Command::Issue(_)
            | Command::Set(_) => {
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
            Command::Help(_)
            | Command::Down(_)
            | Command::Status(_)
            | Command::Issue(_)
            | Command::Set(_) => {
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
            Command::Help(_)
            | Command::Down(_)
            | Command::Status(_)
            | Command::Issue(_)
            | Command::Set(_) => {
                panic!("the parser did not select up");
            }
        }
    }

    #[test]
    fn up_and_set_accept_the_exit_node_flags() {
        let command = parse_up(&[
            "--advertise-exit-node".to_string(),
            "--exit-node".to_string(),
            "exit".to_string(),
            "--exit-node-allow-lan-access".to_string(),
            "--relay".to_string(),
            "172.30.19.5:443".to_string(),
        ])
        .unwrap();
        match command {
            Command::Up(options) => {
                assert!(options.advertise_exit);
                assert_eq!(options.exit_node.as_deref(), Some("exit"));
                assert!(options.allow_lan);
                assert_eq!(options.relay.unwrap().port(), 443);
            }
            Command::Help(_)
            | Command::Down(_)
            | Command::Status(_)
            | Command::Issue(_)
            | Command::Set(_) => {
                panic!("the parser did not select up");
            }
        }
        let set = parse_set(&[
            "--exit-node".to_string(),
            "exit".to_string(),
            "--state-dir".to_string(),
            "/tmp/orblx-exit".to_string(),
        ])
        .unwrap();
        match set {
            Command::Set(options) => {
                assert_eq!(options.exit_node, "exit");
                assert!(!options.allow_lan);
            }
            Command::Help(_)
            | Command::Up(_)
            | Command::Down(_)
            | Command::Status(_)
            | Command::Issue(_) => {
                panic!("the parser did not select set");
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
    fn node_issue_writes_a_user_svid_and_one_agent_ticket() {
        let dir = std::env::temp_dir().join(format!("orblx-w19-issue-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        run(parse_issue(&[
            "--out".to_string(),
            dir.to_string_lossy().to_string(),
            "--node".to_string(),
            "b=100.64.0.2".to_string(),
            "--user".to_string(),
            "alice".to_string(),
            "--agent".to_string(),
            "helper".to_string(),
            "--agent-parent".to_string(),
            "alice".to_string(),
            "--agent-host".to_string(),
            "100.64.0.2".to_string(),
            "--agent-user".to_string(),
            "alice".to_string(),
        ])
        .unwrap())
        .unwrap();
        assert!(dir.join("users").join("alice").join("cert.pem").exists());
        assert!(!dir.join("users").join("alice").join("ticket.bin").exists());
        let ticket_path = dir.join("agents").join("helper").join("ticket.bin");
        let mode = fs::metadata(&ticket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let verifier = TicketVerifier::from_public_pem(
            &fs::read_to_string(dir.join("b").join("ticket-verifier.pem")).unwrap(),
        )
        .unwrap();
        let ticket = fs::read(&ticket_path).unwrap();
        let verified = verify_ticket(
            &verifier,
            &ticket,
            std::time::SystemTime::now(),
            &DenySet::empty(),
        )
        .unwrap();
        assert!(verified.flags.agent_jit());
        assert!(verified.flags.one_shot());
        assert_eq!(verified.dst_cidr, "100.64.0.2/32");
        assert_eq!(verified.proto, 6);
        assert_eq!(verified.dst_port, 22);
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
            exit_node: false,
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

    #[test]
    fn a_new_grant_file_replaces_the_dns_reach_list() {
        let dir =
            std::env::temp_dir().join(format!("orblx-w18-live-grants-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key = orblx_coord::NetmapKey::generate();
        fs::write(
            dir.join("netmap.pub"),
            format!("{}\n", orblx_coord::encode_hex(&key.public())),
        )
        .unwrap();
        let peer = grant_peer("b");
        write_reach(&dir, &key, vec![peer.svid.clone()]);
        let visibility = super::load_visibility(&dir, "a").unwrap();
        assert!(visibility.is_visible(&peer));
        let first = visibility.revision();
        write_reach(&dir, &key, Vec::new());
        assert!(!visibility.is_visible(&peer));
        assert!(visibility.revision() > first);
        fs::write(dir.join("grants.signed.json"), b"not-json").unwrap();
        assert!(!visibility.is_visible(&peer));
        let _ = fs::remove_dir_all(&dir);
    }

    fn grant_peer(name: &str) -> orblx_datapath::NetmapPeer {
        orblx_datapath::NetmapPeer {
            name: name.to_string(),
            overlay_ip: "100.64.0.2".to_string(),
            svid: format!("spiffe://orblx.local/node/{name}"),
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            owner: "lab".to_string(),
        }
    }

    fn write_reach(dir: &std::path::Path, key: &orblx_coord::NetmapKey, reach: Vec<String>) {
        let grants = orblx_identity::ReceiverGrants {
            version: 1,
            receiver: "spiffe://orblx.local/node/a".to_string(),
            grants: Vec::new(),
            reach,
        };
        let signed = key.sign_grants(&grants).unwrap();
        let text = serde_json::to_string(&signed).unwrap();
        fs::write(dir.join("grants.signed.json"), text).unwrap();
    }
}
