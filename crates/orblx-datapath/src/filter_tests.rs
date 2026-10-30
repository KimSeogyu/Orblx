use std::net::Ipv4Addr;
use std::time::Duration;

use orblx_audit::verify_config_file;
use orblx_identity::{ReceiverGrant, ReceiverGrants, SubnetGrant};

use super::{PacketFilter, PACKET_AUDIT_FILE};

const ME: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const ALICE: &str = "spiffe://orblx.test/user/alice";
const BOB: &str = "spiffe://orblx.test/user/bob";

fn grants(filter: bool, rows: &[(&str, u8, u16, u16)]) -> ReceiverGrants {
    ReceiverGrants {
        version: 1,
        receiver: "spiffe://orblx.test/node/b".to_string(),
        grants: rows
            .iter()
            .map(|(src, proto, start, end)| ReceiverGrant {
                src: (*src).to_string(),
                proto: *proto,
                port_start: *start,
                port_end: *end,
            })
            .collect(),
        reach: Vec::new(),
        filter,
        subnets: Vec::new(),
    }
}

fn ip(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    let total = u16::try_from(20 + body.len()).unwrap_or(u16::MAX);
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[8] = 64;
    packet[9] = proto;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet.extend_from_slice(body);
    packet
}

fn l4(proto: u8, src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16) -> Vec<u8> {
    let mut body = vec![0u8; 20];
    body[0..2].copy_from_slice(&sport.to_be_bytes());
    body[2..4].copy_from_slice(&dport.to_be_bytes());
    ip(proto, src, dst, &body)
}

fn echo(kind: u8, src: Ipv4Addr, dst: Ipv4Addr, ident: u16) -> Vec<u8> {
    let mut body = vec![0u8; 16];
    body[0] = kind;
    body[4..6].copy_from_slice(&ident.to_be_bytes());
    ip(1, src, dst, &body)
}

#[test]
fn allowed_port_passes_and_other_port_drops() {
    let filter = PacketFilter::new(ME, &grants(true, &[(ALICE, 6, 22, 22)]), None);
    assert!(filter.allow_inbound(ALICE, &l4(6, PEER, 40000, ME, 22)));
    assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 40000, ME, 23)));
    assert!(!filter.allow_inbound(BOB, &l4(6, PEER, 40000, ME, 22)));
    assert!(!filter.allow_inbound(ALICE, &l4(17, PEER, 40000, ME, 22)));
    assert_eq!(filter.stats().denied, 3);
}

#[test]
fn empty_grants_with_filter_deny_all() {
    let filter = PacketFilter::new(ME, &grants(true, &[]), None);
    assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 1, ME, 22)));
    assert!(!filter.allow_inbound(ALICE, &echo(8, PEER, ME, 7)));
    assert!(!filter.allow_inbound(ALICE, &ip(47, PEER, ME, &[0; 8])));
    assert!(!filter.allow_inbound(ALICE, &[0x60, 0, 0, 0]));
}

#[test]
fn no_acl_keeps_old_behavior() {
    let filter = PacketFilter::new(ME, &grants(false, &[]), None);
    assert!(filter.allow_inbound(ALICE, &l4(6, PEER, 1, ME, 23)));
    assert!(filter.allow_inbound(ALICE, &echo(8, PEER, ME, 7)));
    assert_eq!(filter.stats().denied, 0);
}

#[test]
fn reply_to_own_flow_passes() {
    let filter = PacketFilter::new(ME, &grants(true, &[]), None);
    assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 5201, ME, 40001)));
    filter.note_outbound(&l4(6, ME, 40001, PEER, 5201));
    assert!(filter.allow_inbound(ALICE, &l4(6, PEER, 5201, ME, 40001)));
    // Another remote port is not the same flow.
    assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 5202, ME, 40001)));
    filter.note_outbound(&l4(17, ME, 40002, PEER, 53));
    assert!(filter.allow_inbound(ALICE, &l4(17, PEER, 53, ME, 40002)));
}

#[test]
fn flow_cache_stays_in_one_filter() {
    // The thread caches skip the flow table lock for a steady flow.
    // A second filter on the same thread must not use the flows of the first filter.
    let first = PacketFilter::new(ME, &grants(true, &[]), None);
    first.note_outbound(&l4(6, ME, 40001, PEER, 5201));
    assert!(first.allow_inbound(ALICE, &l4(6, PEER, 5201, ME, 40001)));
    assert!(first.allow_inbound(ALICE, &l4(6, PEER, 5201, ME, 40001)));
    let second = PacketFilter::new(ME, &grants(true, &[]), None);
    assert!(!second.allow_inbound(ALICE, &l4(6, PEER, 5201, ME, 40001)));
    second.note_outbound(&l4(6, ME, 40001, PEER, 5201));
    assert!(second.allow_inbound(ALICE, &l4(6, PEER, 5201, ME, 40001)));
    // The same ports with another protocol are not the same flow.
    assert!(!second.allow_inbound(ALICE, &l4(17, PEER, 5201, ME, 40001)));
}

#[test]
fn icmp_rule_works_as_written() {
    let receiver = PacketFilter::new(ME, &grants(true, &[(ALICE, 1, 1, 65535)]), None);
    assert!(receiver.allow_inbound(ALICE, &echo(8, PEER, ME, 9)));
    assert!(!receiver.allow_inbound(BOB, &echo(8, PEER, ME, 9)));
    // A TCP or UDP grant does not allow ICMP.
    let tcp_only = PacketFilter::new(ME, &grants(true, &[(ALICE, 6, 1, 65535)]), None);
    assert!(!tcp_only.allow_inbound(ALICE, &echo(8, PEER, ME, 9)));
    // The sender gets the echo reply for its own request without an ICMP grant.
    tcp_only.note_outbound(&echo(8, ME, PEER, 11));
    assert!(tcp_only.allow_inbound(ALICE, &echo(0, PEER, ME, 11)));
    assert!(!tcp_only.allow_inbound(ALICE, &echo(0, PEER, ME, 12)));
}

#[test]
fn icmp_error_for_own_flow_passes() {
    let filter = PacketFilter::new(ME, &grants(true, &[]), None);
    let sent = l4(17, ME, 40003, PEER, 9);
    let mut body = vec![3u8, 3, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&sent[..28]);
    let error = ip(1, PEER, ME, &body);
    assert!(!filter.allow_inbound(ALICE, &error));
    filter.note_outbound(&sent);
    assert!(filter.allow_inbound(ALICE, &error));
}

#[test]
fn transit_packet_and_tail_fragment() {
    let filter = PacketFilter::new(ME, &grants(true, &[(ALICE, 17, 1, 65535)]), None);
    // A packet for a subnet route is not for this node.
    assert!(filter.allow_inbound(ALICE, &l4(6, PEER, 1, Ipv4Addr::new(10, 9, 0, 5), 80)));
    let mut tail = l4(17, PEER, 1, ME, 53);
    tail[6] = 0x00;
    tail[7] = 0x10;
    assert!(!filter.allow_inbound(ALICE, &tail));
}

#[test]
fn replace_turns_filter_on_and_off() {
    let filter = PacketFilter::new(ME, &grants(false, &[]), None);
    assert!(filter.allow_inbound(ALICE, &l4(6, PEER, 1, ME, 23)));
    filter.replace(&grants(true, &[(ALICE, 6, 22, 22)]));
    assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 1, ME, 23)));
    assert!(filter.allow_inbound(ALICE, &l4(6, PEER, 1, ME, 22)));
    filter.replace(&grants(false, &[]));
    assert!(filter.allow_inbound(ALICE, &l4(6, PEER, 1, ME, 23)));
}

#[test]
fn deny_audit_is_sampled_and_rate_limited() {
    let dir = std::env::temp_dir().join(format!("orblx-w24acl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join(PACKET_AUDIT_FILE);
    let filter = PacketFilter::new(ME, &grants(true, &[]), Some(path.clone()));
    for _ in 0..200 {
        assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 40000, ME, 23)));
    }
    for port in 1000..1020 {
        assert!(!filter.allow_inbound(BOB, &l4(17, PEER, 40000, ME, port)));
    }
    let stats = filter.stats();
    assert_eq!(stats.denied, 220);
    assert!(stats.audited <= 10, "audited {}", stats.audited);
    assert!(stats.audited >= 1);
    assert_eq!(stats.audited + stats.suppressed, 220);
    drop(filter);
    let mut records = 0;
    for _ in 0..100 {
        if let Ok(checked) = verify_config_file(&path) {
            records = checked.records.len();
            if records as u64 == stats.audited {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(records as u64, stats.audited);
    let checked = verify_config_file(&path).expect("verify");
    let first = &checked.records[0].event;
    assert_eq!(first.action.as_str(), "packet-deny");
    assert_eq!(first.target, "tcp/23");
    assert_eq!(first.actor, ALICE);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn subnet_route_needs_a_subnet_grant() {
    let lan_dns = Ipv4Addr::new(10, 88, 24, 53);
    let lan_db = Ipv4Addr::new(10, 88, 24, 20);
    let other = Ipv4Addr::new(192, 168, 1, 1);
    let mut rules = grants(true, &[]);
    rules.subnets = vec![SubnetGrant {
        src: ALICE.to_string(),
        dst: "10.88.24.53/32".to_string(),
        proto: 17,
        port_start: 53,
        port_end: 53,
    }];
    let filter = PacketFilter::new(ME, &rules, None);
    // Before the node sets its routes, transit keeps the old behavior.
    assert!(filter.allow_inbound(BOB, &l4(17, PEER, 40000, lan_dns, 53)));
    filter.set_routes(&["10.88.24.0/24".to_string(), "0.0.0.0/0".to_string()]);
    assert!(filter.allow_inbound(ALICE, &l4(17, PEER, 40000, lan_dns, 53)));
    assert!(!filter.allow_inbound(BOB, &l4(17, PEER, 40000, lan_dns, 53)));
    assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 40000, lan_dns, 53)));
    assert!(!filter.allow_inbound(ALICE, &l4(17, PEER, 40000, lan_dns, 54)));
    assert!(!filter.allow_inbound(ALICE, &l4(6, PEER, 40000, lan_db, 80)));
    // An address outside the subnet routes (exit traffic) keeps the old behavior.
    assert!(filter.allow_inbound(BOB, &l4(6, PEER, 40000, other, 80)));
    assert_eq!(filter.stats().denied, 4);
    // Without an ACL the subnet route keeps the old behavior.
    let open = PacketFilter::new(ME, &grants(false, &[]), None);
    open.set_routes(&["10.88.24.0/24".to_string()]);
    assert!(open.allow_inbound(BOB, &l4(17, PEER, 40000, lan_dns, 53)));
}
