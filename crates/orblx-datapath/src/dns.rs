//! Overlay DNS for the node.
//!
//! The responder listens on the node overlay address.
//! It answers `<node>.<owner>.orblx` and the short name `<node>`.
//! Names outside that set go to the system resolver.
//! A hidden peer gets NXDOMAIN. The responder does not forward that name.
//!
//! [`GrantPeers`] reads the `reach` list on the signed grants.
//! A peer absent from that list is NXDOMAIN.
//! [`AllowPeers`] allows every peer when the node has no grant file.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread;
use std::time::Duration;

use orblx_identity::ReceiverGrants;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::watch;

use crate::netmap::{valid_owner_name, Netmap, NetmapPeer};

/// UDP port for the overlay DNS responder.
pub const DNS_PORT: u16 = 53;

/// macOS resolver file for the `orblx` domain.
pub const MACOS_RESOLVER_PATH: &str = "/etc/resolver/orblx";

const DNS_TTL: u32 = 5;
const QTYPE_A: u16 = 1;
const QTYPE_ANY: u16 = 255;
const QCLASS_IN: u16 = 1;
const QCLASS_ANY: u16 = 255;
const RCODE_NOERROR: u8 = 0;
const RCODE_FORMERR: u8 = 1;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;
#[cfg(target_os = "linux")]
const COMMAND_WAIT: Duration = Duration::from_secs(5);

/// The node calls this hook for each peer before it answers a DNS name.
pub trait PeerVisibility: Send + Sync {
    /// Return true when the node may answer names for this peer.
    fn is_visible(&self, peer: &NetmapPeer) -> bool;
}

/// The visibility hook for a node that has no signed grants.
///
/// It allows every peer.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowPeers;

impl PeerVisibility for AllowPeers {
    fn is_visible(&self, peer: &NetmapPeer) -> bool {
        is_visible(peer)
    }
}

/// The default check. It allows every peer.
#[must_use]
pub fn is_visible(peer: &NetmapPeer) -> bool {
    let _ = peer;
    true
}

/// Peers the signed grants let this node reach.
///
/// The list is the `reach` field of [`ReceiverGrants`].
/// The node does not read a second policy file.
#[derive(Debug, Clone)]
pub struct GrantPeers {
    reach: HashSet<String>,
}

impl GrantPeers {
    /// Build the hook from the signed grant document.
    #[must_use]
    pub fn from_grants(grants: &ReceiverGrants) -> Self {
        Self {
            reach: grants.reach.iter().cloned().collect(),
        }
    }
}

impl PeerVisibility for GrantPeers {
    fn is_visible(&self, peer: &NetmapPeer) -> bool {
        self.reach.contains(&peer.svid)
    }
}

/// One DNS answer set built from a netmap.
#[derive(Debug, Clone)]
pub struct DnsTable {
    names: HashMap<String, usize>,
    nodes: Vec<DnsNode>,
}

#[derive(Debug, Clone)]
struct DnsNode {
    address: Ipv4Addr,
    owner: String,
    peer: Option<NetmapPeer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameClass {
    Address(Ipv4Addr),
    Hidden,
    Unknown,
}

struct ParsedQuery {
    id: u16,
    rd: bool,
    name: String,
    qtype: u16,
    qclass: u16,
    question: Vec<u8>,
}

/// A DNS forward failure.
#[derive(Debug)]
pub(crate) struct ForwardError;

impl std::fmt::Display for ForwardError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("The DNS forward failed.")
    }
}

pub(crate) trait QueryForwarder: Send + Sync {
    fn forward(&self, query: &[u8]) -> Result<Vec<u8>, ForwardError>;
}

/// Forwards a query to a nameserver from the system resolver files.
///
/// The forwarder skips the overlay address.
pub(crate) struct ResolvConfForwarder {
    avoid: Ipv4Addr,
}

impl ResolvConfForwarder {
    pub(crate) fn new(avoid: Ipv4Addr) -> Self {
        Self { avoid }
    }
}

impl QueryForwarder for ResolvConfForwarder {
    fn forward(&self, query: &[u8]) -> Result<Vec<u8>, ForwardError> {
        let servers = upstream_nameservers(self.avoid);
        if servers.is_empty() || query.len() < 2 {
            return Err(ForwardError);
        }
        let id = u16::from_be_bytes([query[0], query[1]]);
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .map_err(|_| ForwardError)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| ForwardError)?;
        let mut buf = [0u8; 1500];
        for server in servers {
            if socket.send_to(query, server).is_err() {
                continue;
            }
            match socket.recv_from(&mut buf) {
                Ok((size, from)) if size >= 12 && from == server => {
                    let response_id = u16::from_be_bytes([buf[0], buf[1]]);
                    if response_id == id {
                        return Ok(buf[..size].to_vec());
                    }
                }
                Ok(_) | Err(_) => {}
            }
        }
        Err(ForwardError)
    }
}

/// Removes the resolver configuration when the node stops.
pub(crate) struct LinkResolverGuard {
    interface: String,
    armed: Arc<AtomicBool>,
}

impl LinkResolverGuard {
    pub(crate) fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            armed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn armed_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.armed)
    }
}

impl Drop for LinkResolverGuard {
    fn drop(&mut self) {
        if self.armed.load(Ordering::Relaxed) {
            if let Err(err) = remove_link_resolver(&self.interface) {
                eprintln!("{err}");
            }
        }
    }
}

impl DnsTable {
    /// Build the answer set for one netmap.
    ///
    /// The local node is always present.
    /// A peer stays in the table. [`PeerVisibility`] decides the answer.
    #[must_use]
    pub fn from_netmap(map: &Netmap) -> Self {
        let mut table = Self {
            names: HashMap::new(),
            nodes: Vec::new(),
        };
        table.insert_node(
            &map.self_node.name,
            &map.self_node.owner,
            &map.self_node.overlay_ip,
            None,
        );
        for peer in &map.peers {
            table.insert_node(
                &peer.name,
                &peer.owner,
                &peer.overlay_ip,
                Some(peer.clone()),
            );
        }
        table
    }

    fn insert_node(&mut self, name: &str, owner: &str, address: &str, peer: Option<NetmapPeer>) {
        if !valid_dns_name(name) {
            return;
        }
        let Ok(ip) = address.parse::<Ipv4Addr>() else {
            return;
        };
        let index = self.nodes.len();
        self.nodes.push(DnsNode {
            address: ip,
            owner: owner.to_string(),
            peer,
        });
        self.insert_name(&name.to_ascii_lowercase(), index);
        if let Some(fqdn) = node_fqdn(name, owner) {
            self.insert_name(&fqdn, index);
        }
    }

    fn insert_name(&mut self, name: &str, index: usize) {
        if !self.names.contains_key(name) {
            self.names.insert(name.to_string(), index);
        }
    }

    fn classify(&self, name: &str, visibility: &dyn PeerVisibility) -> NameClass {
        let Some(index) = self.names.get(name) else {
            return NameClass::Unknown;
        };
        let Some(node) = self.nodes.get(*index) else {
            return NameClass::Unknown;
        };
        if let Some(peer) = &node.peer {
            if !visibility.is_visible(peer) {
                return NameClass::Hidden;
            }
        }
        NameClass::Address(node.address)
    }
}

/// Search domains for the visible nodes.
///
/// Each value is `<owner>.orblx`.
#[must_use]
pub(crate) fn search_domains(table: &DnsTable, visibility: &dyn PeerVisibility) -> Vec<String> {
    let mut domains = Vec::new();
    for node in &table.nodes {
        if let Some(peer) = &node.peer {
            if !visibility.is_visible(peer) {
                continue;
            }
        }
        push_owner(&mut domains, &node.owner);
    }
    domains
}

fn push_owner(domains: &mut Vec<String>, owner: &str) {
    let Some(domain) = owner_domain(owner) else {
        return;
    };
    if !domains.iter().any(|item| item == &domain) {
        domains.push(domain);
    }
}

fn owner_domain(owner: &str) -> Option<String> {
    if !valid_owner_name(owner) {
        return None;
    }
    Some(format!("{}.orblx", owner.to_ascii_lowercase()))
}

fn node_fqdn(name: &str, owner: &str) -> Option<String> {
    if !valid_dns_name(name) || !valid_owner_name(owner) {
        return None;
    }
    let fqdn = format!(
        "{}.{}.orblx",
        name.to_ascii_lowercase(),
        owner.to_ascii_lowercase()
    );
    if valid_dns_name(&fqdn) {
        Some(fqdn)
    } else {
        None
    }
}

/// `resolvectl domain` arguments.
///
/// The routing domain `~orblx` is always present.
#[must_use]
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn domain_args(interface: &str, search: &[String]) -> Vec<String> {
    let mut args = vec![
        "domain".to_string(),
        interface.to_string(),
        "~orblx".to_string(),
    ];
    for domain in search {
        if domain.starts_with('-') || domain.contains([' ', '\t', '\n']) {
            continue;
        }
        if !args.iter().any(|item| item == domain) {
            args.push(domain.clone());
        }
    }
    args
}

/// Text for `/etc/resolver/orblx`.
#[must_use]
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn macos_resolver_text(nameserver: Ipv4Addr, search: &[String]) -> String {
    let mut text = format!("nameserver {nameserver}\n");
    if !search.is_empty() {
        text.push_str("search");
        for domain in search {
            text.push(' ');
            text.push_str(domain);
        }
        text.push('\n');
    }
    text
}

/// Point the host resolver at the overlay DNS responder.
///
/// Linux uses `resolvectl` on the TUN device.
/// macOS writes [`MACOS_RESOLVER_PATH`].
/// A missing `resolvectl` returns an error. The caller keeps the node up.
pub fn install_link_resolver(
    interface: &str,
    nameserver: Ipv4Addr,
    search: &[String],
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux_install(interface, nameserver, search)
    }
    #[cfg(target_os = "macos")]
    {
        macos_install(interface, nameserver, search)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (interface, nameserver, search);
        Err("The node sets the DNS resolver on Linux or macOS. The node continues.".to_string())
    }
}

/// Remove the resolver configuration.
///
/// Linux reverts the TUN link.
/// macOS deletes [`MACOS_RESOLVER_PATH`].
pub fn remove_link_resolver(interface: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux_remove(interface)
    }
    #[cfg(target_os = "macos")]
    {
        macos_remove(interface)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface;
        Ok(())
    }
}

pub(crate) fn refresh_resolver(
    interface: &str,
    nameserver: Ipv4Addr,
    table: &DnsTable,
    visibility: &dyn PeerVisibility,
    armed: &AtomicBool,
) {
    let search = search_domains(table, visibility);
    match install_link_resolver(interface, nameserver, &search) {
        Ok(()) => {
            armed.store(true, Ordering::Relaxed);
            println!("The DNS resolver for {interface} uses {nameserver} and the domain ~orblx.");
        }
        Err(err) => eprintln!("{err}"),
    }
}

/// Answer DNS queries until `shutdown` is true.
pub(crate) async fn serve_dns(
    socket: TokioUdpSocket,
    tables: watch::Receiver<DnsTable>,
    visibility: Arc<dyn PeerVisibility>,
    forwarder: Arc<dyn QueryForwarder>,
    mut shutdown: watch::Receiver<bool>,
) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            packet = socket.recv_from(&mut buf) => {
                let (size, peer) = match packet {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let query = buf[..size].to_vec();
                let table = tables.borrow().clone();
                let visibility = Arc::clone(&visibility);
                let forwarder = Arc::clone(&forwarder);
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    let response = tokio::task::spawn_blocking(move || {
                        respond(&table, visibility.as_ref(), &query, forwarder.as_ref())
                    })
                    .await;
                    if let Ok(bytes) = response {
                        if !bytes.is_empty() {
                            let _ = socket.send_to(&bytes, peer).await;
                        }
                    }
                });
            }
        }
    }
}

fn respond(
    table: &DnsTable,
    visibility: &dyn PeerVisibility,
    query: &[u8],
    forwarder: &dyn QueryForwarder,
) -> Vec<u8> {
    if query.len() < 12 {
        return formerr(query);
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return Vec::new();
    }
    let opcode = (flags >> 11) & 0x0f;
    if opcode != 0 {
        return error_header(query, RCODE_FORMERR);
    }
    let Some(parsed) = parse_query(query) else {
        return formerr(query);
    };
    if parsed.qclass != QCLASS_IN && parsed.qclass != QCLASS_ANY {
        return local_error(&parsed, RCODE_REFUSED);
    }
    match table.classify(&parsed.name, visibility) {
        NameClass::Address(ip) => local_address(&parsed, ip),
        NameClass::Hidden => local_error(&parsed, RCODE_NXDOMAIN),
        NameClass::Unknown if in_overlay_zone(&parsed.name) => local_error(&parsed, RCODE_NXDOMAIN),
        NameClass::Unknown => match forwarder.forward(query) {
            Ok(bytes) => bytes,
            Err(ForwardError) => local_error(&parsed, RCODE_SERVFAIL),
        },
    }
}

fn local_address(parsed: &ParsedQuery, ip: Ipv4Addr) -> Vec<u8> {
    if parsed.qtype == QTYPE_A || parsed.qtype == QTYPE_ANY {
        let mut out = header(parsed, RCODE_NOERROR, true, false, 1);
        out.extend_from_slice(&parsed.question);
        push_a(&mut out, ip);
        out
    } else {
        local_error(parsed, RCODE_NOERROR)
    }
}

fn local_error(parsed: &ParsedQuery, rcode: u8) -> Vec<u8> {
    let mut out = header(parsed, rcode, true, false, 0);
    out.extend_from_slice(&parsed.question);
    out
}

fn formerr(query: &[u8]) -> Vec<u8> {
    error_header(query, RCODE_FORMERR)
}

fn error_header(query: &[u8], rcode: u8) -> Vec<u8> {
    let id = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    };
    let rd = query.len() >= 4 && query[2] & 0x01 != 0;
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flag_bits(rd, false, false, rcode).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn header(parsed: &ParsedQuery, rcode: u8, aa: bool, ra: bool, answers: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + parsed.question.len());
    out.extend_from_slice(&parsed.id.to_be_bytes());
    out.extend_from_slice(&flag_bits(parsed.rd, aa, ra, rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn flag_bits(rd: bool, aa: bool, ra: bool, rcode: u8) -> u16 {
    let mut flags = 0x8000u16;
    if aa {
        flags |= 0x0400;
    }
    if rd {
        flags |= 0x0100;
    }
    if ra {
        flags |= 0x0080;
    }
    flags |= u16::from(rcode & 0x0f);
    flags
}

fn push_a(out: &mut Vec<u8>, ip: Ipv4Addr) {
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&QTYPE_A.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    out.extend_from_slice(&DNS_TTL.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
}

fn parse_query(query: &[u8]) -> Option<ParsedQuery> {
    let id = u16::from_be_bytes([query[0], query[1]]);
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let questions = u16::from_be_bytes([query[4], query[5]]);
    if questions != 1 {
        return None;
    }
    let (name, end) = read_name(query, 12).ok()?;
    if end + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[end], query[end + 1]]);
    let qclass = u16::from_be_bytes([query[end + 2], query[end + 3]]);
    Some(ParsedQuery {
        id,
        rd: flags & 0x0100 != 0,
        name,
        qtype,
        qclass,
        question: query[12..end + 4].to_vec(),
    })
}

fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), ()> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut end = start;
    let mut jumped = false;
    let mut hops = 0usize;
    loop {
        if offset >= msg.len() || hops > 32 {
            return Err(());
        }
        let len = msg[offset];
        if len == 0 {
            if !jumped {
                end = offset + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= msg.len() {
                return Err(());
            }
            let pointer = (usize::from(len & 0x3f) << 8) | usize::from(msg[offset + 1]);
            if pointer >= msg.len() {
                return Err(());
            }
            if !jumped {
                end = offset + 2;
            }
            offset = pointer;
            jumped = true;
            hops += 1;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(());
        }
        let label_len = usize::from(len);
        let label_at = offset + 1;
        let label_end = label_at + label_len;
        if label_end > msg.len() {
            return Err(());
        }
        let label = std::str::from_utf8(&msg[label_at..label_end]).map_err(|_| ())?;
        if !valid_dns_label(label) {
            return Err(());
        }
        labels.push(label.to_ascii_lowercase());
        offset = label_end;
        if !jumped {
            end = offset;
        }
        hops += 1;
    }
    let name = labels.join(".");
    if name.len() > 253 {
        return Err(());
    }
    Ok((name, end))
}

fn in_overlay_zone(name: &str) -> bool {
    name == "orblx" || name.ends_with(".orblx")
}

fn valid_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(valid_dns_label)
}

fn valid_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

fn upstream_nameservers(avoid: Ipv4Addr) -> Vec<SocketAddr> {
    for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if let Ok(text) = fs::read_to_string(path) {
            let servers = nameservers_from_resolv(&text, avoid);
            if !servers.is_empty() {
                return servers;
            }
        }
    }
    Vec::new()
}

pub(crate) fn nameservers_from_resolv(text: &str, avoid: Ipv4Addr) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        if !rest.starts_with(|ch: char| ch.is_whitespace()) {
            continue;
        }
        let Some(token) = rest.split_whitespace().next() else {
            continue;
        };
        let Ok(ip) = token.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip == avoid
            || ip.is_unspecified()
            || ip.is_broadcast()
            || ip == Ipv4Addr::new(127, 0, 0, 53)
        {
            continue;
        }
        let server = SocketAddr::from((ip, DNS_PORT));
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    servers
}

#[cfg(target_os = "linux")]
fn linux_install(interface: &str, nameserver: Ipv4Addr, search: &[String]) -> Result<(), String> {
    let dns = vec![
        "dns".to_string(),
        interface.to_string(),
        nameserver.to_string(),
    ];
    let domain = domain_args(interface, search);
    let default_route = vec![
        "default-route".to_string(),
        interface.to_string(),
        "false".to_string(),
    ];
    for args in [dns, domain, default_route] {
        run_resolvectl(&args).map_err(|err| resolvectl_message(interface, err))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_remove(interface: &str) -> Result<(), String> {
    match run_resolvectl(&["revert".to_string(), interface.to_string()]) {
        Ok(()) | Err(CommandError::Missing) => Ok(()),
        Err(CommandError::Failed(detail)) => Err(format!(
            "The command resolvectl did not revert {interface}. {detail}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn resolvectl_message(interface: &str, err: CommandError) -> String {
    match err {
        CommandError::Missing => format!(
            "The command resolvectl is not available. The node does not set the DNS domain ~orblx on {interface}. The node continues."
        ),
        CommandError::Failed(detail) => format!(
            "The command resolvectl did not set the DNS domain ~orblx on {interface}. {detail} The node continues."
        ),
    }
}

#[cfg(target_os = "linux")]
enum CommandError {
    Missing,
    Failed(String),
}

#[cfg(target_os = "linux")]
fn run_resolvectl(args: &[String]) -> Result<(), CommandError> {
    let mut child = Command::new("resolvectl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            if err.kind() == ErrorKind::NotFound {
                CommandError::Missing
            } else {
                CommandError::Failed(err.to_string())
            }
        })?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let mut detail = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_string(&mut detail);
                }
                let detail = detail.trim();
                if detail.is_empty() {
                    return Err(CommandError::Failed(format!(
                        "The exit status is {status}."
                    )));
                }
                return Err(CommandError::Failed(detail.to_string()));
            }
            Ok(None) if started.elapsed() > COMMAND_WAIT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandError::Failed(
                    "The command did not finish.".to_string(),
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(err) => return Err(CommandError::Failed(err.to_string())),
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_install(interface: &str, nameserver: Ipv4Addr, search: &[String]) -> Result<(), String> {
    let _ = interface;
    let text = macos_resolver_text(nameserver, search);
    if let Some(parent) = std::path::Path::new(MACOS_RESOLVER_PATH).parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!("The file {MACOS_RESOLVER_PATH} was not written. {err} The node continues.")
        })?;
    }
    fs::write(MACOS_RESOLVER_PATH, text).map_err(|err| {
        format!("The file {MACOS_RESOLVER_PATH} was not written. {err} The node continues.")
    })?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_remove(interface: &str) -> Result<(), String> {
    let _ = interface;
    match fs::remove_file(MACOS_RESOLVER_PATH) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "The file {MACOS_RESOLVER_PATH} was not removed. {err}"
        )),
    }
}

#[cfg(test)]
fn encode_query(name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x1234u16.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        msg.push(u8::try_from(label.len()).unwrap_or(0));
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&QTYPE_A.to_be_bytes());
    msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
    msg
}

#[cfg(test)]
fn rcode(msg: &[u8]) -> u8 {
    msg[3] & 0x0f
}

#[cfg(test)]
fn first_a(msg: &[u8]) -> Option<Ipv4Addr> {
    if msg.len() < 12 {
        return None;
    }
    let answers = u16::from_be_bytes([msg[6], msg[7]]);
    if answers == 0 {
        return None;
    }
    let (_, mut offset) = read_name(msg, 12).ok()?;
    offset = offset.checked_add(4)?;
    let (_, next) = read_name(msg, offset).ok()?;
    if next + 14 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
    let rdlength = u16::from_be_bytes([msg[next + 8], msg[next + 9]]);
    if qtype != QTYPE_A || rdlength != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        msg[next + 10],
        msg[next + 11],
        msg[next + 12],
        msg[next + 13],
    ))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::net::UdpSocket;
    use tokio::sync::watch;

    use orblx_identity::{Policy, SpiffeId};

    use super::{
        domain_args, encode_query, first_a, macos_resolver_text, nameservers_from_resolv, rcode,
        respond, serve_dns, AllowPeers, DnsTable, ForwardError, GrantPeers, PeerVisibility,
        QueryForwarder,
    };
    use crate::netmap::{Netmap, NetmapPeer};

    struct CountingForward {
        calls: AtomicUsize,
    }

    impl CountingForward {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl QueryForwarder for CountingForward {
        fn forward(&self, query: &[u8]) -> Result<Vec<u8>, ForwardError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut out = query.to_vec();
            out.extend_from_slice(&[203, 0, 113, 10]);
            Ok(out)
        }
    }

    struct DenyPeer;

    impl PeerVisibility for DenyPeer {
        fn is_visible(&self, peer: &NetmapPeer) -> bool {
            peer.name != "b"
        }
    }

    fn lab_map(ip_b: &str) -> Netmap {
        let text = format!(
            r#"{{
                "version": 1,
                "self": {{"name": "a", "overlay_ip": "100.64.0.1", "owner": "lab"}},
                "peers": [{{
                    "name": "b",
                    "overlay_ip": "{ip_b}",
                    "owner": "lab",
                    "svid": "spiffe://orblx.local/node/b",
                    "endpoints": ["172.28.18.12:443"],
                    "routes": []
                }}]
            }}"#
        );
        Netmap::from_slice(text.as_bytes()).unwrap()
    }

    #[test]
    fn netmap_names_answer_the_fqdn_and_the_short_name() {
        let table = DnsTable::from_netmap(&lab_map("100.64.0.2"));
        let forwarder = CountingForward::new();
        for name in ["b.lab.orblx", "b.lab.orblx.", "B.Lab.ORBLX", "b"] {
            let response = respond(&table, &AllowPeers, &encode_query(name), &forwarder);
            assert_eq!(rcode(&response), 0, "{name}");
            assert_eq!(
                first_a(&response),
                Some(Ipv4Addr::new(100, 64, 0, 2)),
                "{name}"
            );
        }
        let self_name = respond(
            &table,
            &AllowPeers,
            &encode_query("a.lab.orblx"),
            &forwarder,
        );
        assert_eq!(first_a(&self_name), Some(Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!(forwarder.calls(), 0);
        assert!(super::is_visible(&table.nodes[1].peer.clone().unwrap()));
    }

    #[test]
    fn a_name_outside_the_netmap_is_forwarded() {
        let table = DnsTable::from_netmap(&lab_map("100.64.0.2"));
        let forwarder = CountingForward::new();
        let response = respond(
            &table,
            &AllowPeers,
            &encode_query("example.test"),
            &forwarder,
        );
        assert_eq!(forwarder.calls(), 1);
        assert!(response.windows(4).any(|bytes| bytes == [203, 0, 113, 10]));
        let outside = respond(
            &table,
            &AllowPeers,
            &encode_query("missing.lab.orblx"),
            &forwarder,
        );
        assert_eq!(rcode(&outside), 3);
        assert_eq!(forwarder.calls(), 1);
    }

    #[test]
    fn a_hidden_node_is_nxdomain() {
        let table = DnsTable::from_netmap(&lab_map("100.64.0.2"));
        let forwarder = CountingForward::new();
        for name in ["b", "b.lab.orblx"] {
            let response = respond(&table, &DenyPeer, &encode_query(name), &forwarder);
            assert_eq!(rcode(&response), 3, "{name}");
            assert!(response.windows(4).all(|bytes| bytes != [100, 64, 0, 2]));
        }
        assert_eq!(forwarder.calls(), 0);
        let visible = respond(&table, &DenyPeer, &encode_query("a"), &forwarder);
        assert_eq!(first_a(&visible), Some(Ipv4Addr::new(100, 64, 0, 1)));
    }

    #[test]
    fn signed_grants_hide_a_peer_this_node_cannot_reach() {
        let policy = Policy::from_hujson(
            r#"{
                "acls": [{
                    "action": "accept",
                    "src": ["spiffe://orblx.local/node/a"],
                    "proto": "tcp",
                    "dst": ["spiffe://orblx.local/node/b:8080"]
                }],
                "tests": [{
                    "src": "spiffe://orblx.local/node/a",
                    "proto": "tcp",
                    "accept": ["spiffe://orblx.local/node/b:8080"],
                    "deny": ["spiffe://orblx.local/node/c:8080"]
                }]
            }"#
            .as_bytes(),
        )
        .unwrap();
        let grants = policy.receiver_grants(&SpiffeId::node("a").unwrap());
        let hook = GrantPeers::from_grants(&grants);
        let text = r#"{
            "version": 1,
            "self": {"name": "a", "overlay_ip": "100.64.0.1", "owner": "lab"},
            "peers": [
                {
                    "name": "b",
                    "overlay_ip": "100.64.0.2",
                    "owner": "lab",
                    "svid": "spiffe://orblx.local/node/b",
                    "endpoints": ["172.28.18.12:443"],
                    "routes": []
                },
                {
                    "name": "c",
                    "overlay_ip": "100.64.0.3",
                    "owner": "lab",
                    "svid": "spiffe://orblx.local/node/c",
                    "endpoints": ["172.28.18.13:443"],
                    "routes": []
                }
            ]
        }"#;
        let table = DnsTable::from_netmap(&Netmap::from_slice(text.as_bytes()).unwrap());
        let forwarder = CountingForward::new();
        for name in ["b", "b.lab.orblx"] {
            let response = respond(&table, &hook, &encode_query(name), &forwarder);
            assert_eq!(rcode(&response), 0, "{name}");
            assert_eq!(
                first_a(&response),
                Some(Ipv4Addr::new(100, 64, 0, 2)),
                "{name}"
            );
        }
        for name in ["c", "c.lab.orblx"] {
            let response = respond(&table, &hook, &encode_query(name), &forwarder);
            assert_eq!(rcode(&response), 3, "{name}");
            assert!(response.windows(4).all(|bytes| bytes != [100, 64, 0, 3]));
        }
        assert_eq!(forwarder.calls(), 0);
    }

    #[test]
    fn a_new_netmap_replaces_the_answers() {
        let forwarder = CountingForward::new();
        let first = DnsTable::from_netmap(&lab_map("100.64.0.2"));
        let second = DnsTable::from_netmap(&lab_map("100.64.0.9"));
        let before = respond(
            &first,
            &AllowPeers,
            &encode_query("b.lab.orblx"),
            &forwarder,
        );
        let after = respond(&second, &AllowPeers, &encode_query("b"), &forwarder);
        assert_eq!(first_a(&before), Some(Ipv4Addr::new(100, 64, 0, 2)));
        assert_eq!(first_a(&after), Some(Ipv4Addr::new(100, 64, 0, 9)));
    }

    #[test]
    fn the_linux_domain_list_starts_with_the_orblx_route() {
        let args = domain_args("orblx0", &["lab.orblx".to_string()]);
        assert_eq!(
            args,
            vec![
                "domain".to_string(),
                "orblx0".to_string(),
                "~orblx".to_string(),
                "lab.orblx".to_string()
            ]
        );
    }

    #[test]
    fn the_macos_resolver_file_names_the_overlay_address() {
        let text = macos_resolver_text(Ipv4Addr::new(100, 64, 0, 1), &["lab.orblx".to_string()]);
        assert!(text.contains("nameserver 100.64.0.1\n"));
        assert!(text.contains("search lab.orblx\n"));
    }

    #[test]
    fn resolv_conf_skips_the_overlay_address_and_the_stub() {
        let text = "nameserver 100.64.0.1\nnameserver 127.0.0.53\nnameserver 127.0.0.11\n";
        let servers = nameservers_from_resolv(text, Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].ip().to_string(), "127.0.0.11");
    }

    #[test]
    fn search_domains_skip_a_hidden_owner() {
        let text = r#"{
            "version": 1,
            "self": {"name": "a", "overlay_ip": "100.64.0.1", "owner": "lab"},
            "peers": [{
                "name": "b",
                "overlay_ip": "100.64.0.2",
                "owner": "secret",
                "svid": "spiffe://orblx.local/node/b",
                "endpoints": ["172.28.18.12:443"],
                "routes": []
            }]
        }"#;
        let table = DnsTable::from_netmap(&Netmap::from_slice(text.as_bytes()).unwrap());
        assert_eq!(
            super::search_domains(&table, &DenyPeer),
            vec!["lab.orblx".to_string()]
        );
        assert_eq!(
            super::search_domains(&table, &AllowPeers),
            vec!["lab.orblx".to_string(), "secret.orblx".to_string()]
        );
    }

    #[tokio::test]
    async fn the_server_uses_the_new_netmap() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (table_tx, table_rx) = watch::channel(DnsTable::from_netmap(&lab_map("100.64.0.2")));
        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(serve_dns(
            socket,
            table_rx,
            Arc::new(AllowPeers),
            Arc::new(CountingForward::new()),
            stop_rx,
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first = exchange(&client, server_addr, &encode_query("b.lab.orblx")).await;
        assert_eq!(first_a(&first), Some(Ipv4Addr::new(100, 64, 0, 2)));
        table_tx
            .send(DnsTable::from_netmap(&lab_map("100.64.0.9")))
            .unwrap();
        let second = exchange(&client, server_addr, &encode_query("b")).await;
        assert_eq!(first_a(&second), Some(Ipv4Addr::new(100, 64, 0, 9)));
        stop_tx.send(true).unwrap();
        task.await.unwrap();
    }

    async fn exchange(client: &UdpSocket, server: std::net::SocketAddr, query: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 1500];
        for _ in 0..20 {
            client.send_to(query, server).await.unwrap();
            let recv = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                client.recv_from(&mut buf),
            )
            .await;
            if let Ok(Ok((size, _))) = recv {
                return buf[..size].to_vec();
            }
        }
        panic!("the DNS responder sent no reply");
    }
}
