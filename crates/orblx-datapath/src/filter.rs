//! Receiver packet filter (W24).
//!
//! The signed grants list the sources, the protocols, and the ports that may reach this node.
//! When the grants set `filter`, the node drops each packet to its overlay address
//! that no grant allows. This is default deny.
//! A reply to a flow that this node started is allowed.
//! A packet to another address (a subnet route or an exit route) keeps the old behavior.
//!
//! The filter writes a sample of the drops to a config audit chain.
//! It writes at most one record for each source, protocol, and port in `AUDIT_KEY_GAP`,
//! and at most `AUDIT_PER_SECOND` records in one second.

use std::cell::Cell;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_audit::{ConfigAction, ConfigEvent, ConfigLog, EMPTY_DIGEST};
use orblx_identity::ReceiverGrants;

/// The packet deny audit chain in the node state directory.
pub const PACKET_AUDIT_FILE: &str = "packet-audit.jsonl";

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_UNREACHABLE: u8 = 3;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAMETER: u8 = 12;

/// A flow that this node started stays open for replies for this time after its last packet.
const FLOW_IDLE: Duration = Duration::from_secs(180);
/// The most flows that the filter keeps.
const MAX_FLOWS: usize = 65_536;
/// The filter removes old flows at most once in this time, or when the table is full.
const FLOW_SWEEP: Duration = Duration::from_secs(30);
/// One audit record for each source, protocol, and port in this time.
const AUDIT_KEY_GAP: Duration = Duration::from_secs(10);
/// The most audit records in one second.
const AUDIT_PER_SECOND: u32 = 5;
/// The most keys that the audit sampler keeps.
const MAX_AUDIT_KEYS: usize = 4_096;
/// The most records that wait for the audit thread.
const AUDIT_QUEUE: usize = 64;
/// A thread does not lock the flow table again for the same flow in this time.
/// The time is much shorter than `FLOW_IDLE`.
const FLOW_CACHE_FOR: Duration = Duration::from_secs(1);

/// The id of the next filter. The thread caches use it to keep the filters apart.
static NEXT_FILTER_ID: AtomicU64 = AtomicU64::new(1);

/// One flow that one thread checked: filter id, flow, time of the check.
type FlowCacheEntry = Option<(u64, FlowKey, Instant)>;

thread_local! {
    /// The last flow that this thread noted as outbound.
    static OUT_CACHE: Cell<FlowCacheEntry> = const { Cell::new(None) };
    /// The last flow that this thread found open for a reply.
    static REPLY_CACHE: Cell<FlowCacheEntry> = const { Cell::new(None) };
}

/// Return true when the cache holds `key` of filter `id` from less than `FLOW_CACHE_FOR` ago.
fn cache_hit(
    cache: &'static std::thread::LocalKey<Cell<FlowCacheEntry>>,
    id: u64,
    key: &FlowKey,
    now: Instant,
) -> bool {
    cache.with(|cell| {
        cell.get().is_some_and(|(seen_id, seen_key, at)| {
            seen_id == id && seen_key == *key && now.saturating_duration_since(at) < FLOW_CACHE_FOR
        })
    })
}

fn cache_set(
    cache: &'static std::thread::LocalKey<Cell<FlowCacheEntry>>,
    id: u64,
    key: FlowKey,
    now: Instant,
) {
    cache.with(|cell| cell.set(Some((id, key, now))));
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    local_port: u16,
    remote: Ipv4Addr,
    remote_port: u16,
}

#[derive(Default)]
struct Rules {
    /// Source SPIFFE ID to (protocol, first port, last port).
    by_src: HashMap<String, Vec<(u8, u16, u16)>>,
}

impl Rules {
    fn from_grants(grants: &ReceiverGrants) -> Self {
        let mut by_src: HashMap<String, Vec<(u8, u16, u16)>> = HashMap::new();
        for grant in &grants.grants {
            by_src.entry(grant.src.clone()).or_default().push((
                grant.proto,
                grant.port_start,
                grant.port_end,
            ));
        }
        Self { by_src }
    }

    fn permits(&self, src: &str, proto: u8, port: u16) -> bool {
        self.by_src.get(src).is_some_and(|rows| {
            rows.iter().any(|(row_proto, start, end)| {
                *row_proto == proto && (proto == PROTO_ICMP || (port >= *start && port <= *end))
            })
        })
    }
}

struct FlowTable {
    map: HashMap<FlowKey, Instant>,
    last_sweep: Instant,
}

impl FlowTable {
    fn note(&mut self, key: FlowKey, now: Instant) {
        if let Some(seen) = self.map.get_mut(&key) {
            *seen = now;
            return;
        }
        if self.map.len() >= MAX_FLOWS || now.duration_since(self.last_sweep) >= FLOW_SWEEP {
            self.map
                .retain(|_, seen| now.duration_since(*seen) < FLOW_IDLE);
            self.last_sweep = now;
        }
        if self.map.len() < MAX_FLOWS {
            self.map.insert(key, now);
        }
    }

    fn has(&self, key: &FlowKey, now: Instant) -> bool {
        self.map
            .get(key)
            .is_some_and(|seen| now.duration_since(*seen) < FLOW_IDLE)
    }
}

/// The parsed fields of one IPv4 packet.
struct Parsed {
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    /// True for a fragment after the first fragment. It has no port.
    tail: bool,
    /// TCP or UDP source port, or the ICMP echo identifier.
    src_port: u16,
    /// TCP or UDP destination port.
    dst_port: u16,
    icmp_type: u8,
    /// For an ICMP error: the flow of the packet in the error, as this node sent it.
    inner: Option<(Ipv4Addr, FlowKey)>,
}

fn parse(packet: &[u8]) -> Option<Parsed> {
    let (proto, src, dst, header, tail) = ip_header(packet)?;
    let mut parsed = Parsed {
        proto,
        src,
        dst,
        tail,
        src_port: 0,
        dst_port: 0,
        icmp_type: 0,
        inner: None,
    };
    if tail {
        return Some(parsed);
    }
    let body = &packet[header..];
    match proto {
        PROTO_TCP | PROTO_UDP => {
            let ports = body.get(..4)?;
            parsed.src_port = u16::from_be_bytes([ports[0], ports[1]]);
            parsed.dst_port = u16::from_be_bytes([ports[2], ports[3]]);
        }
        PROTO_ICMP => {
            let head = body.get(..8)?;
            parsed.icmp_type = head[0];
            match head[0] {
                ICMP_ECHO_REPLY | ICMP_ECHO_REQUEST => {
                    parsed.src_port = u16::from_be_bytes([head[4], head[5]]);
                }
                ICMP_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER => {
                    parsed.inner = inner_flow(&body[8..]);
                }
                _ => {}
            }
        }
        _ => {}
    }
    Some(parsed)
}

/// Return the protocol, the addresses, the header length, and the tail fragment flag.
fn ip_header(packet: &[u8]) -> Option<(u8, Ipv4Addr, Ipv4Addr, usize, bool)> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header = usize::from(first & 0x0f) * 4;
    if header < 20 || packet.len() < header {
        return None;
    }
    let offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((packet[9], src, dst, header, offset != 0))
}

/// The flow in an ICMP error body: the source address and the key as the sender saw it.
fn inner_flow(body: &[u8]) -> Option<(Ipv4Addr, FlowKey)> {
    let (proto, src, dst, header, tail) = ip_header(body)?;
    if tail {
        return None;
    }
    let rest = body.get(header..header + 8)?;
    let key = match proto {
        PROTO_TCP | PROTO_UDP => FlowKey {
            proto,
            local_port: u16::from_be_bytes([rest[0], rest[1]]),
            remote: dst,
            remote_port: u16::from_be_bytes([rest[2], rest[3]]),
        },
        PROTO_ICMP if rest[0] == ICMP_ECHO_REQUEST => FlowKey {
            proto,
            local_port: u16::from_be_bytes([rest[4], rest[5]]),
            remote: dst,
            remote_port: 0,
        },
        _ => return None,
    };
    Some((src, key))
}

/// Counters of one packet filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterStats {
    /// Packets that the filter dropped.
    pub denied: u64,
    /// Drops that have an audit record.
    pub audited: u64,
    /// Drops without an audit record (the sample and rate limit).
    pub suppressed: u64,
}

struct SampleGate {
    keys: HashMap<(String, u8, u16), Instant>,
    second: Instant,
    in_second: u32,
    /// Drops without a record since the last record.
    pending: u64,
}

/// The receiver packet filter of one node.
pub struct PacketFilter {
    id: u64,
    overlay: Ipv4Addr,
    active: AtomicBool,
    rules: RwLock<Rules>,
    flows: Mutex<FlowTable>,
    sample: Mutex<SampleGate>,
    audit: Option<SyncSender<ConfigEvent>>,
    denied: AtomicU64,
    audited: AtomicU64,
    suppressed: AtomicU64,
}

impl std::fmt::Debug for PacketFilter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PacketFilter")
            .field("overlay", &self.overlay)
            .field("active", &self.active())
            .finish_non_exhaustive()
    }
}

impl PacketFilter {
    /// Make a filter for the node with the overlay address `overlay`.
    ///
    /// The filter drops packets only when `grants.filter` is true.
    /// With `audit_path`, a thread writes the sampled drops to that config audit chain.
    #[must_use]
    pub fn new(
        overlay: Ipv4Addr,
        grants: &ReceiverGrants,
        audit_path: Option<PathBuf>,
    ) -> Arc<Self> {
        let audit = audit_path.and_then(spawn_audit);
        let now = Instant::now();
        Arc::new(Self {
            id: NEXT_FILTER_ID.fetch_add(1, Ordering::Relaxed),
            overlay,
            active: AtomicBool::new(grants.filter),
            rules: RwLock::new(Rules::from_grants(grants)),
            flows: Mutex::new(FlowTable {
                map: HashMap::new(),
                last_sweep: now,
            }),
            sample: Mutex::new(SampleGate {
                keys: HashMap::new(),
                second: now,
                in_second: 0,
                pending: 0,
            }),
            audit,
            denied: AtomicU64::new(0),
            audited: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        })
    }

    /// Use new signed grants.
    pub fn replace(&self, grants: &ReceiverGrants) {
        *self.rules.write().unwrap_or_else(|err| err.into_inner()) = Rules::from_grants(grants);
        self.active.store(grants.filter, Ordering::Relaxed);
    }

    /// Return true when the filter drops packets.
    #[must_use]
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Return the counters.
    #[must_use]
    pub fn stats(&self) -> FilterStats {
        FilterStats {
            denied: self.denied.load(Ordering::Relaxed),
            audited: self.audited.load(Ordering::Relaxed),
            suppressed: self.suppressed.load(Ordering::Relaxed),
        }
    }

    /// Record one packet that this node sends to a peer.
    ///
    /// A reply to this packet is then allowed.
    pub fn note_outbound(&self, packet: &[u8]) {
        if !self.active() {
            return;
        }
        let Some(parsed) = parse(packet) else {
            return;
        };
        if parsed.src != self.overlay || parsed.tail {
            return;
        }
        let key = match parsed.proto {
            PROTO_TCP | PROTO_UDP => FlowKey {
                proto: parsed.proto,
                local_port: parsed.src_port,
                remote: parsed.dst,
                remote_port: parsed.dst_port,
            },
            PROTO_ICMP if parsed.icmp_type == ICMP_ECHO_REQUEST => FlowKey {
                proto: PROTO_ICMP,
                local_port: parsed.src_port,
                remote: parsed.dst,
                remote_port: 0,
            },
            _ => return,
        };
        let now = Instant::now();
        // A steady flow does not lock the flow table for each packet.
        if cache_hit(&OUT_CACHE, self.id, &key, now) {
            return;
        }
        self.flows
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .note(key, now);
        cache_set(&OUT_CACHE, self.id, key, now);
    }

    /// Check one packet from the peer `src` (a SPIFFE ID).
    ///
    /// Return true when the node may deliver the packet.
    /// A drop counts and may write one audit record.
    pub fn allow_inbound(&self, src: &str, packet: &[u8]) -> bool {
        if !self.active() {
            return true;
        }
        let Some(parsed) = parse(packet) else {
            self.deny(src, None, 0, 0);
            return false;
        };
        if parsed.dst != self.overlay {
            return true;
        }
        if self.allowed(src, &parsed) {
            return true;
        }
        self.deny(src, Some(&parsed), parsed.proto, parsed.dst_port);
        false
    }

    fn allowed(&self, src: &str, parsed: &Parsed) -> bool {
        if parsed.tail {
            return false;
        }
        let now = Instant::now();
        match parsed.proto {
            PROTO_TCP | PROTO_UDP => {
                if self
                    .rules
                    .read()
                    .unwrap_or_else(|err| err.into_inner())
                    .permits(src, parsed.proto, parsed.dst_port)
                {
                    return true;
                }
                let reply = FlowKey {
                    proto: parsed.proto,
                    local_port: parsed.dst_port,
                    remote: parsed.src,
                    remote_port: parsed.src_port,
                };
                self.flow_open(&reply, now)
            }
            PROTO_ICMP => {
                if self
                    .rules
                    .read()
                    .unwrap_or_else(|err| err.into_inner())
                    .permits(src, PROTO_ICMP, 0)
                {
                    return true;
                }
                if parsed.icmp_type == ICMP_ECHO_REPLY {
                    let reply = FlowKey {
                        proto: PROTO_ICMP,
                        local_port: parsed.src_port,
                        remote: parsed.src,
                        remote_port: 0,
                    };
                    return self.flow_open(&reply, now);
                }
                match parsed.inner {
                    Some((inner_src, key)) if inner_src == self.overlay => {
                        self.flow_open(&key, now)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn flow_open(&self, key: &FlowKey, now: Instant) -> bool {
        // A steady reply flow does not lock the flow table for each packet.
        if cache_hit(&REPLY_CACHE, self.id, key, now) {
            return true;
        }
        let open = self
            .flows
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .has(key, now);
        if open {
            cache_set(&REPLY_CACHE, self.id, *key, now);
        }
        open
    }

    fn deny(&self, src: &str, parsed: Option<&Parsed>, proto: u8, port: u16) {
        self.denied.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let pending = {
            let mut gate = self.sample.lock().unwrap_or_else(|err| err.into_inner());
            if now.duration_since(gate.second) >= Duration::from_secs(1) {
                gate.second = now;
                gate.in_second = 0;
            }
            let key = (src.to_string(), proto, port);
            let recent = gate
                .keys
                .get(&key)
                .is_some_and(|seen| now.duration_since(*seen) < AUDIT_KEY_GAP);
            if recent || gate.in_second >= AUDIT_PER_SECOND {
                gate.pending = gate.pending.saturating_add(1);
                drop(gate);
                self.suppressed.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if gate.keys.len() >= MAX_AUDIT_KEYS {
                gate.keys
                    .retain(|_, seen| now.duration_since(*seen) < AUDIT_KEY_GAP);
            }
            gate.keys.insert(key, now);
            gate.in_second += 1;
            std::mem::take(&mut gate.pending)
        };
        self.audited.fetch_add(1, Ordering::Relaxed);
        let Some(audit) = &self.audit else {
            return;
        };
        let (src_ip, dst_ip) = match parsed {
            Some(parsed) => (parsed.src.to_string(), parsed.dst.to_string()),
            None => ("-".to_string(), "-".to_string()),
        };
        let event = ConfigEvent {
            actor: safe_text(src),
            at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0),
            action: ConfigAction::PacketDeny,
            target: format!("{}/{port}", proto_name(proto)),
            before: EMPTY_DIGEST,
            after: EMPTY_DIGEST,
            detail: format!(
                "src {src_ip} dst {dst_ip} proto {} port {port} unwritten_before {pending}",
                proto_name(proto)
            ),
        };
        if audit.try_send(event).is_err() {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn proto_name(proto: u8) -> String {
    match proto {
        PROTO_ICMP => "icmp".to_string(),
        PROTO_TCP => "tcp".to_string(),
        PROTO_UDP => "udp".to_string(),
        other => format!("ip{other}"),
    }
}

fn safe_text(text: &str) -> String {
    let clean: String = text
        .chars()
        .filter(|item| item.is_ascii_graphic())
        .take(256)
        .collect();
    if clean.is_empty() {
        "-".to_string()
    } else {
        clean
    }
}

fn spawn_audit(path: PathBuf) -> Option<SyncSender<ConfigEvent>> {
    let (tx, rx) = mpsc::sync_channel(AUDIT_QUEUE);
    let spawned = thread::Builder::new()
        .name("orblx-acl-audit".to_string())
        .spawn(move || audit_loop(&path, &rx));
    match spawned {
        Ok(_) => Some(tx),
        Err(err) => {
            eprintln!("The packet audit thread did not start. {err}");
            None
        }
    }
}

fn audit_loop(path: &std::path::Path, rx: &Receiver<ConfigEvent>) {
    let mut log = match ConfigLog::open(path) {
        Ok(log) => log,
        Err(err) => {
            eprintln!("The packet audit chain did not open. {err}");
            return;
        }
    };
    while let Ok(event) = rx.recv() {
        if let Err(err) = log.append(event) {
            eprintln!("The packet audit record was not written. {err}");
        }
    }
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod tests;
