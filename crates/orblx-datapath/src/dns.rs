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
//!
//! Split DNS (W24-F): the netmap field `split_dns` maps a domain to nameservers.
//! A name in that domain goes to a zone nameserver over the overlay route.
//! The node sends the query only when a netmap peer route covers the nameserver
//! and the kernel route for the nameserver uses the overlay device.
//! Otherwise the node answers REFUSED. The query never goes to the system resolver.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread;
use std::time::Duration;

use orblx_identity::ReceiverGrants;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::watch;

use crate::netmap::{ipv4_mask, parse_cidr, valid_owner_name, Netmap, NetmapPeer};

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

    /// A value that changes when the reach list changes.
    ///
    /// The node reads this value and refreshes the resolver search list.
    fn revision(&self) -> u64 {
        0
    }
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
    split: Vec<SplitZone>,
    source: Option<Ipv4Addr>,
}

/// One split DNS zone with the nameservers that a netmap peer route covers (W24-F).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SplitZone {
    domain: String,
    routed: Vec<Ipv4Addr>,
}

/// Split DNS queries that the node sent over the overlay (W24-F).
static SPLIT_SENT: AtomicU64 = AtomicU64::new(0);

/// Split DNS queries that the node refused without a send (W24-F).
static SPLIT_REFUSED: AtomicU64 = AtomicU64::new(0);

/// The split DNS counters: sent over the overlay, and refused without a send (W24-F).
#[cfg(test)]
fn split_dns_counters() -> (u64, u64) {
    (
        SPLIT_SENT.load(Ordering::Relaxed),
        SPLIT_REFUSED.load(Ordering::Relaxed),
    )
}

/// The path for a split DNS query (W24-F).
pub(crate) trait SplitPath: Send + Sync {
    /// Return true when the kernel route for `server` uses the overlay device.
    fn overlay_route(&self, server: Ipv4Addr) -> bool;
    /// Send one query to `server` port 53 from `source` and return the response.
    fn exchange(
        &self,
        source: Option<Ipv4Addr>,
        server: Ipv4Addr,
        query: &[u8],
    ) -> Result<Vec<u8>, ForwardError>;
}

/// The host route table and a UDP socket (W24-F).
pub(crate) struct SystemSplitPath;

impl SplitPath for SystemSplitPath {
    fn overlay_route(&self, server: Ipv4Addr) -> bool {
        kernel_route_uses_overlay(server)
    }

    fn exchange(
        &self,
        source: Option<Ipv4Addr>,
        server: Ipv4Addr,
        query: &[u8],
    ) -> Result<Vec<u8>, ForwardError> {
        udp_exchange(
            source.unwrap_or(Ipv4Addr::UNSPECIFIED),
            SocketAddr::from((server, DNS_PORT)),
            query,
        )
    }
}

/// Return true when the best kernel route for `server` uses the overlay device.
///
/// Linux reads `/proc/net/route`. macOS runs `route -n get`.
/// Other systems return false, so the node answers REFUSED.
fn kernel_route_uses_overlay(server: Ipv4Addr) -> bool {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/proc/net/route").is_ok_and(|text| {
            best_route_device(&text, server).as_deref() == Some(crate::LINUX_TUN_NAME)
        })
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("route")
            .args(["-n", "get", &server.to_string()])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .is_some_and(|text| {
                text.lines().any(|line| {
                    line.trim()
                        .strip_prefix("interface:")
                        .is_some_and(|name| name.trim().starts_with("utun"))
                })
            })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = server;
        false
    }
}

/// Return the device of the longest matching route in `/proc/net/route` text.
///
/// A tie on the prefix length uses the lower metric.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn best_route_device(text: &str, server: Ipv4Addr) -> Option<String> {
    let target = u32::from(server);
    let mut best: Option<(u32, u32, String)> = None;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let (Ok(dest), Ok(flags), Ok(metric), Ok(mask)) = (
            u32::from_str_radix(fields[1], 16),
            u16::from_str_radix(fields[3], 16),
            fields[6].parse::<u32>(),
            u32::from_str_radix(fields[7], 16),
        ) else {
            continue;
        };
        if flags & 1 == 0 {
            continue;
        }
        // The kernel prints the network-order bytes as one host-order word.
        let dest = u32::from_be_bytes(dest.to_ne_bytes());
        let mask = u32::from_be_bytes(mask.to_ne_bytes());
        if target & mask != dest & mask {
            continue;
        }
        let len = mask.count_ones();
        let better = match &best {
            None => true,
            Some((best_len, best_metric, _)) => {
                len > *best_len || (len == *best_len && metric < *best_metric)
            }
        };
        if better {
            best = Some((len, metric, fields[0].to_string()));
        }
    }
    best.map(|(_, _, device)| device)
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

/// Forwards a non-overlay query to the exit node.
///
/// The packet uses the node overlay address as the source.
/// The exit node then uses its own resolver.
pub(crate) struct ExitNodeForwarder {
    exit: Ipv4Addr,
    name: String,
    source: Ipv4Addr,
}

impl ExitNodeForwarder {
    pub(crate) fn new(exit: Ipv4Addr, name: String, source: Ipv4Addr) -> Self {
        Self { exit, name, source }
    }

    #[cfg(test)]
    pub(crate) fn target(&self) -> SocketAddr {
        SocketAddr::from((self.exit, DNS_PORT))
    }
}

impl QueryForwarder for ExitNodeForwarder {
    fn forward(&self, query: &[u8]) -> Result<Vec<u8>, ForwardError> {
        let name = dns_query_name(query).unwrap_or_else(|| "a name".to_string());
        println!(
            "The node sends a DNS query for {name} through the exit node {}.",
            self.name
        );
        udp_exchange(self.source, SocketAddr::from((self.exit, DNS_PORT)), query)
    }
}

/// Send one DNS query from `source` to `server` and wait 2 s for the response.
fn udp_exchange(
    source: Ipv4Addr,
    server: SocketAddr,
    query: &[u8],
) -> Result<Vec<u8>, ForwardError> {
    if query.len() < 2 {
        return Err(ForwardError);
    }
    let socket = UdpSocket::bind(SocketAddr::from((source, 0))).map_err(|_| ForwardError)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ForwardError)?;
    let id = u16::from_be_bytes([query[0], query[1]]);
    socket.send_to(query, server).map_err(|_| ForwardError)?;
    let mut buf = [0u8; 1500];
    match socket.recv_from(&mut buf) {
        Ok((size, from)) if size >= 12 && from == server => {
            let response_id = u16::from_be_bytes([buf[0], buf[1]]);
            if response_id == id {
                return Ok(buf[..size].to_vec());
            }
            Err(ForwardError)
        }
        Ok(_) | Err(_) => Err(ForwardError),
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
            split: split_zones(map),
            source: map.self_node.overlay_ip.parse().ok(),
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

    /// Return the split zone with the longest domain that holds `name` (W24-F).
    fn split_zone(&self, name: &str) -> Option<&SplitZone> {
        self.split
            .iter()
            .filter(|zone| {
                name == zone.domain
                    || name
                        .strip_suffix(zone.domain.as_str())
                        .is_some_and(|head| head.ends_with('.'))
            })
            .max_by_key(|zone| zone.domain.len())
    }

    /// The `resolvectl` routing domains for the split zones, for example `~corp.lan`.
    fn split_routing_domains(&self) -> Vec<String> {
        self.split
            .iter()
            .map(|zone| format!("~{}", zone.domain))
            .collect()
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

/// Build the split zones from the netmap (W24-F).
///
/// A nameserver stays in a zone only when a peer route in the netmap covers it.
fn split_zones(map: &Netmap) -> Vec<SplitZone> {
    let routes: Vec<(u32, u32)> = map
        .peers
        .iter()
        .flat_map(|peer| peer.routes.iter())
        .filter_map(|route| parse_cidr(route).ok())
        .filter(|(_, len)| *len > 0)
        .map(|(ip, len)| (u32::from(ip), ipv4_mask(len)))
        .collect();
    map.split_dns
        .iter()
        .map(|zone| SplitZone {
            domain: zone.domain.to_ascii_lowercase(),
            routed: zone
                .nameservers
                .iter()
                .filter_map(|text| text.parse::<Ipv4Addr>().ok())
                .filter(|ip| {
                    let value = u32::from(*ip);
                    routes.iter().any(|(net, mask)| value & mask == *net)
                })
                .collect(),
        })
        .collect()
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
pub(crate) fn domain_args(interface: &str, search: &[String], capture_all: bool) -> Vec<String> {
    let mut args = vec![
        "domain".to_string(),
        interface.to_string(),
        "~orblx".to_string(),
    ];
    if capture_all {
        args.push("~.".to_string());
    }
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
    let search: Vec<&String> = search
        .iter()
        .filter(|item| !item.starts_with('~'))
        .collect();
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
    capture_all: bool,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux_install(interface, nameserver, search, capture_all)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = capture_all;
        macos_install(interface, nameserver, search)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (interface, nameserver, search, capture_all);
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
    capture_all: bool,
) {
    let mut search = search_domains(table, visibility);
    let split = table.split_routing_domains();
    search.extend(split.iter().cloned());
    match install_link_resolver(interface, nameserver, &search, capture_all) {
        Ok(()) => {
            armed.store(true, Ordering::Relaxed);
            println!("The DNS resolver for {interface} uses {nameserver} and the domain ~orblx.");
            if !split.is_empty() {
                println!(
                    "The DNS resolver for {interface} also routes {}.",
                    split.join(" ")
                );
            }
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
    local: Ipv4Addr,
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
                if let Some(name) = dns_query_name(&query) {
                    if is_cgnat(peer.ip()) && peer.ip() != IpAddr::V4(local) {
                        println!(
                            "The node received a DNS query for {name} from {}.",
                            peer.ip()
                        );
                    }
                }
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
    respond_with(table, visibility, query, forwarder, &SystemSplitPath)
}

fn respond_with(
    table: &DnsTable,
    visibility: &dyn PeerVisibility,
    query: &[u8],
    forwarder: &dyn QueryForwarder,
    split: &dyn SplitPath,
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
        NameClass::Unknown => match table.split_zone(&parsed.name) {
            Some(zone) => split_answer(table, zone, &parsed, query, split),
            None => forward_answer(&parsed, query, forwarder),
        },
    }
}

fn forward_answer(parsed: &ParsedQuery, query: &[u8], forwarder: &dyn QueryForwarder) -> Vec<u8> {
    match forwarder.forward(query) {
        Ok(bytes) => bytes,
        Err(ForwardError) => local_error(parsed, RCODE_SERVFAIL),
    }
}

/// Answer a name in a split zone (W24-F).
///
/// The node sends the query to a zone nameserver over the overlay route.
/// Without an overlay route, the node answers REFUSED.
/// The node never sends a split zone query to the system resolver.
fn split_answer(
    table: &DnsTable,
    zone: &SplitZone,
    parsed: &ParsedQuery,
    query: &[u8],
    split: &dyn SplitPath,
) -> Vec<u8> {
    let servers: Vec<Ipv4Addr> = zone
        .routed
        .iter()
        .copied()
        .filter(|server| split.overlay_route(*server))
        .collect();
    if servers.is_empty() {
        let count = SPLIT_REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
        println!(
            "The node refused a DNS query for {}. No overlay route reaches a nameserver for {}. split_refused={count}",
            parsed.name, zone.domain
        );
        return local_error(parsed, RCODE_REFUSED);
    }
    for server in servers {
        let count = SPLIT_SENT.fetch_add(1, Ordering::Relaxed) + 1;
        println!(
            "The node sends a DNS query for {} to {server} for {} through the overlay. split_sent={count}",
            parsed.name, zone.domain
        );
        if let Ok(bytes) = split.exchange(table.source, server, query) {
            return bytes;
        }
    }
    local_error(parsed, RCODE_SERVFAIL)
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

fn dns_query_name(query: &[u8]) -> Option<String> {
    let parsed = parse_query(query)?;
    if parsed.name.is_empty() {
        None
    } else {
        Some(parsed.name)
    }
}

fn is_cgnat(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let octets = ip.octets();
    octets[0] == 100 && (64..128).contains(&octets[1])
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
fn linux_install(
    interface: &str,
    nameserver: Ipv4Addr,
    search: &[String],
    capture_all: bool,
) -> Result<(), String> {
    let dns = vec![
        "dns".to_string(),
        interface.to_string(),
        nameserver.to_string(),
    ];
    let domain = domain_args(interface, search, capture_all);
    let route_flag = if capture_all { "true" } else { "false" };
    let default_route = vec![
        "default-route".to_string(),
        interface.to_string(),
        route_flag.to_string(),
    ];
    for args in [dns, domain, default_route] {
        run_resolvectl_retry(&args).map_err(|err| resolvectl_message(interface, err))?;
    }
    if capture_all {
        silence_other_links(interface);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn silence_other_links(keep: &str) {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == keep || name == "lo" {
            continue;
        }
        let _ = run_resolvectl(&["default-route".to_string(), name, "false".to_string()]);
    }
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
fn run_resolvectl_retry(args: &[String]) -> Result<(), CommandError> {
    let mut attempt = 0;
    loop {
        match run_resolvectl(args) {
            Ok(()) => return Ok(()),
            Err(CommandError::Missing) => return Err(CommandError::Missing),
            Err(CommandError::Failed(detail)) => {
                let transient = detail.contains("Connection refused") || detail.contains("sd_bus");
                if !transient || attempt == 19 {
                    return Err(CommandError::Failed(detail));
                }
                attempt += 1;
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
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
        respond, serve_dns, AllowPeers, DnsTable, ExitNodeForwarder, ForwardError, GrantPeers,
        PeerVisibility, QueryForwarder,
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
    fn the_exit_node_forwarder_targets_the_exit_overlay() {
        let forwarder = ExitNodeForwarder::new(
            Ipv4Addr::new(100, 64, 0, 2),
            "exit".to_string(),
            Ipv4Addr::new(100, 64, 0, 4),
        );
        assert_eq!(
            forwarder.target(),
            std::net::SocketAddr::from((Ipv4Addr::new(100, 64, 0, 2), 53))
        );
    }

    #[test]
    fn the_linux_domain_list_starts_with_the_orblx_route() {
        let args = domain_args("orblx0", &["lab.orblx".to_string()], false);
        assert_eq!(
            args,
            vec![
                "domain".to_string(),
                "orblx0".to_string(),
                "~orblx".to_string(),
                "lab.orblx".to_string()
            ]
        );
        let captured = domain_args("orblx0", &[], true);
        assert!(captured.iter().any(|item| item == "~."));
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
            Ipv4Addr::new(100, 64, 0, 1),
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

    struct FakeSplit {
        overlay: bool,
        answer: bool,
        sent: std::sync::Mutex<Vec<(Option<Ipv4Addr>, Ipv4Addr)>>,
    }

    impl FakeSplit {
        fn new(overlay: bool, answer: bool) -> Self {
            Self {
                overlay,
                answer,
                sent: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(Option<Ipv4Addr>, Ipv4Addr)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl super::SplitPath for FakeSplit {
        fn overlay_route(&self, _server: Ipv4Addr) -> bool {
            self.overlay
        }

        fn exchange(
            &self,
            source: Option<Ipv4Addr>,
            server: Ipv4Addr,
            query: &[u8],
        ) -> Result<Vec<u8>, ForwardError> {
            self.sent.lock().unwrap().push((source, server));
            if !self.answer {
                return Err(ForwardError);
            }
            let mut out = query.to_vec();
            out[2] |= 0x80;
            out.extend_from_slice(&[10, 88, 0, 20]);
            Ok(out)
        }
    }

    fn split_map(zones: &str) -> Netmap {
        let text = format!(
            r#"{{
                "version": 1,
                "self": {{"name": "a", "overlay_ip": "100.64.0.1", "owner": "lab"}},
                "peers": [{{
                    "name": "router",
                    "overlay_ip": "100.64.0.2",
                    "owner": "lab",
                    "svid": "spiffe://orblx.local/node/router",
                    "endpoints": ["172.30.18.12:443"],
                    "routes": ["10.88.0.0/24"]
                }}],
                "split_dns": [{zones}]
            }}"#
        );
        Netmap::from_slice(text.as_bytes()).unwrap()
    }

    const CORP: &str = r#"{"domain": "corp.lan", "nameservers": ["10.99.0.53", "10.88.0.53"]}"#;

    fn ask(
        table: &DnsTable,
        name: &str,
        split: &FakeSplit,
        forwarder: &CountingForward,
    ) -> Vec<u8> {
        super::respond_with(table, &AllowPeers, &encode_query(name), forwarder, split)
    }

    #[test]
    fn a_split_name_goes_to_the_routed_nameserver_over_the_overlay() {
        let table = DnsTable::from_netmap(&split_map(CORP));
        let split = FakeSplit::new(true, true);
        let forwarder = CountingForward::new();
        let (sent_before, _) = super::split_dns_counters();
        for name in ["db.corp.lan", "DB.Corp.Lan.", "corp.lan", "a.b.corp.lan"] {
            let response = ask(&table, name, &split, &forwarder);
            assert!(response.ends_with(&[10, 88, 0, 20]), "{name}");
        }
        // 10.99.0.53 has no netmap route. Only 10.88.0.53 gets the queries.
        let sent = split.sent();
        assert_eq!(sent.len(), 4);
        assert!(sent.iter().all(|item| *item
            == (
                Some(Ipv4Addr::new(100, 64, 0, 1)),
                Ipv4Addr::new(10, 88, 0, 53)
            )));
        assert_eq!(forwarder.calls(), 0);
        assert!(super::split_dns_counters().0 >= sent_before + 4);
    }

    #[test]
    fn a_split_name_without_an_overlay_route_is_refused_and_not_forwarded() {
        let table = DnsTable::from_netmap(&split_map(CORP));
        let split = FakeSplit::new(false, true);
        let forwarder = CountingForward::new();
        let (_, refused_before) = super::split_dns_counters();
        let response = ask(&table, "db.corp.lan", &split, &forwarder);
        assert_eq!(rcode(&response), 5);
        assert!(split.sent().is_empty());
        assert_eq!(forwarder.calls(), 0);
        assert!(super::split_dns_counters().1 > refused_before);
    }

    #[test]
    fn a_nameserver_outside_every_netmap_route_is_refused() {
        let zone = r#"{"domain": "other.lan", "nameservers": ["10.99.0.53"]}"#;
        let table = DnsTable::from_netmap(&split_map(zone));
        let split = FakeSplit::new(true, true);
        let forwarder = CountingForward::new();
        let response = ask(&table, "db.other.lan", &split, &forwarder);
        assert_eq!(rcode(&response), 5);
        assert!(split.sent().is_empty());
        assert_eq!(forwarder.calls(), 0);
    }

    #[test]
    fn a_silent_split_nameserver_is_servfail_and_not_forwarded() {
        let table = DnsTable::from_netmap(&split_map(CORP));
        let split = FakeSplit::new(true, false);
        let forwarder = CountingForward::new();
        let response = ask(&table, "db.corp.lan", &split, &forwarder);
        assert_eq!(rcode(&response), 2);
        assert_eq!(split.sent().len(), 1);
        assert_eq!(forwarder.calls(), 0);
    }

    #[test]
    fn names_outside_the_split_zones_keep_the_w18_behavior() {
        let table = DnsTable::from_netmap(&split_map(CORP));
        let split = FakeSplit::new(true, true);
        let forwarder = CountingForward::new();
        let router = ask(&table, "router.lab.orblx", &split, &forwarder);
        assert_eq!(first_a(&router), Some(Ipv4Addr::new(100, 64, 0, 2)));
        let missing = ask(&table, "db.corp.lan.orblx", &split, &forwarder);
        assert_eq!(rcode(&missing), 3);
        for name in ["notcorp.lan", "example.test", "lan"] {
            let response = ask(&table, name, &split, &forwarder);
            assert!(
                response.windows(4).any(|bytes| bytes == [203, 0, 113, 10]),
                "{name}"
            );
        }
        assert_eq!(forwarder.calls(), 3);
        assert!(split.sent().is_empty());
    }

    #[test]
    fn a_removed_split_zone_goes_back_to_the_forwarder() {
        let split = FakeSplit::new(true, true);
        let forwarder = CountingForward::new();
        let table = DnsTable::from_netmap(&lab_map("100.64.0.2"));
        let response = ask(&table, "db.corp.lan", &split, &forwarder);
        assert!(response.windows(4).any(|bytes| bytes == [203, 0, 113, 10]));
        assert_eq!(forwarder.calls(), 1);
        assert!(split.sent().is_empty());
    }

    #[test]
    fn the_longest_split_domain_wins() {
        let zones =
            format!(r#"{CORP}, {{"domain": "db.corp.lan", "nameservers": ["10.99.0.54"]}}"#);
        let table = DnsTable::from_netmap(&split_map(&zones));
        let split = FakeSplit::new(true, true);
        let forwarder = CountingForward::new();
        let response = ask(&table, "x.db.corp.lan", &split, &forwarder);
        assert_eq!(rcode(&response), 5);
        let response = ask(&table, "web.corp.lan", &split, &forwarder);
        assert_eq!(rcode(&response), 0);
    }

    #[test]
    fn split_zones_add_routing_domains() {
        let table = DnsTable::from_netmap(&split_map(CORP));
        let domains = table.split_routing_domains();
        assert_eq!(domains, vec!["~corp.lan".to_string()]);
        let args = domain_args("orblx0", &domains, false);
        assert_eq!(args, vec!["domain", "orblx0", "~orblx", "~corp.lan"]);
        let text = macos_resolver_text(Ipv4Addr::new(100, 64, 0, 1), &domains);
        assert_eq!(text, "nameserver 100.64.0.1\n");
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn the_longest_kernel_route_picks_the_device() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t011E1EAC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
            eth0\t00121EAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
            orblx0\t0000580A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
            orblx0\t0000400A\t00000000\t0000\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            super::best_route_device(text, Ipv4Addr::new(10, 88, 0, 53)).as_deref(),
            Some("orblx0")
        );
        assert_eq!(
            super::best_route_device(text, Ipv4Addr::new(10, 99, 0, 53)).as_deref(),
            Some("eth0")
        );
        // A route without the up flag does not count.
        assert_eq!(
            super::best_route_device(text, Ipv4Addr::new(10, 64, 0, 5)).as_deref(),
            Some("eth0")
        );
        assert_eq!(
            super::best_route_device("Iface\n", Ipv4Addr::new(10, 88, 0, 53)),
            None
        );
    }
}
