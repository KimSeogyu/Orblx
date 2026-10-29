//! PathMachine smash for Radioactive NAT.
//!
//! The runner records feed events from the path lab.
//! UDP block follows the Week 6 TCP Relay lab after Direct fails.
//! Symmetric NAT follows the Week 6 UDP Relay lab after Direct fails.
//! This runner does not upgrade a Relay path to Direct.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use orblx_relay::{RelayPreference, RelayServer, RelaySessionId, RelayTransport, ServerConfig};

use crate::nat_feed::{
    NatDifficulty, NatEventLog, NatInjectMode, NatLevel, PathKind, PhaseName, LAB_OVERLAY_IP,
};
use crate::{
    issue_direct_pair, AllocatePhase, DirectIdentity, DirectPhase, DirectRequest, DirectRole,
    EdgeError, EndpointCandidate, LabStunServer, MemoryCandidateSink, PathId, PathMachine,
    PathState, PunchToken, RelayLink, RelayPhase, RelayRequest, StunClient, RELAY_PROOF_PAYLOAD,
};

/// Direct failure budget from the Week 6 relay lab.
const DIRECT_FAIL_BUDGET: Duration = Duration::from_millis(200);

/// UDP attach wait when the Relay answers UDP.
const UDP_OPEN_TIMEOUT: Duration = Duration::from_secs(2);

/// UDP attach wait when the Relay discards UDP.
const UDP_BLOCK_TIMEOUT: Duration = Duration::from_millis(400);

/// TCP attach wait from the Week 6 relay lab.
const TCP_TIMEOUT: Duration = Duration::from_secs(2);

/// Attach plus QUIC budget from the Week 6 relay lab.
const QUIC_BUDGET: Duration = Duration::from_secs(8);

/// Head start so the Relay server proof listens first.
const SERVER_HEAD_START: Duration = Duration::from_millis(80);

/// STUN client wait.
const STUN_CLIENT_WAIT: Duration = Duration::from_secs(2);

/// STUN server wait.
const STUN_SERVER_WAIT: Duration = Duration::from_secs(3);

/// One smash request.
///
/// ShipPlatform maps the sim level and difficulty into these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatSmash {
    /// Easy, Medium, or Hard.
    pub difficulty: NatDifficulty,
    /// City Breeze, Agent JIT, or Radioactive NAT.
    pub level: NatLevel,
    /// UDP block or symmetric NAT.
    pub mode: NatInjectMode,
}

/// The result of one smash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatSmashReport {
    /// True when the path lab ran.
    pub ran: bool,
    /// True when Direct is up at the end.
    pub direct_up: bool,
    /// True when Relay is up at the end.
    pub relay_up: bool,
    /// Measured Direct attempt time.
    ///
    /// `None` when the lab did not run.
    pub direct_rtt_ms: Option<u64>,
    /// Measured Relay attach time.
    ///
    /// `None` when the lab did not run.
    pub relay_attach_rtt_ms: Option<u64>,
    /// UDP or TCP after Relay comes up.
    pub transport: Option<RelayTransport>,
    /// Reflexive socket text from Allocate.
    pub reflexive: Option<String>,
    /// Relay peer URI copied onto `path.up`.
    pub peer_uri: Option<String>,
    /// PathId hex used before Relay attaches.
    pub path_session_hex: String,
    /// Relay session hex used after Relay attaches.
    pub relay_session_hex: Option<String>,
    /// The JSON events.
    pub log: NatEventLog,
}

/// Run one NAT smash and record the feed events.
///
/// A quiet inject returns an empty log.
/// An armed inject drives `PathMachine` through Allocate, Direct, and Relay.
/// Under UDP block, Direct fails and the event `path.direct` has `ok` false.
/// The runner then switches to Relay.
/// UDP block discards Relay UDP and comes up on TCP.
/// Symmetric NAT comes up on Relay UDP after Direct fails.
/// The runner copies measured times into `rtt_ms`.
/// The runner does not retry Direct after Relay is up.
pub fn run_nat_smash(smash: NatSmash) -> Result<NatSmashReport, EdgeError> {
    let path_id = PathId::allocate()?;
    let path_session_hex = path_id.to_hex();
    let mut log = NatEventLog::start(smash.level, smash.difficulty, path_id);
    if !crate::nat_inject_armed(smash.level, smash.difficulty) {
        return Ok(quiet_report(log, path_session_hex));
    }
    log.push_inject(smash.mode);
    let driven = drive_path(smash.mode, &mut log)?;
    Ok(NatSmashReport {
        ran: true,
        direct_up: driven.direct_up,
        relay_up: driven.relay_up,
        direct_rtt_ms: Some(driven.direct_rtt_ms),
        relay_attach_rtt_ms: Some(driven.relay_attach_rtt_ms),
        transport: Some(driven.transport),
        reflexive: Some(driven.reflexive),
        peer_uri: Some(driven.peer_uri),
        path_session_hex,
        relay_session_hex: Some(driven.relay_session_hex),
        log,
    })
}

struct Driven {
    direct_rtt_ms: u64,
    relay_attach_rtt_ms: u64,
    transport: RelayTransport,
    reflexive: String,
    relay_session_hex: String,
    peer_uri: String,
    direct_up: bool,
    relay_up: bool,
}

fn quiet_report(log: NatEventLog, path_session_hex: String) -> NatSmashReport {
    NatSmashReport {
        ran: false,
        direct_up: false,
        relay_up: false,
        direct_rtt_ms: None,
        relay_attach_rtt_ms: None,
        transport: None,
        reflexive: None,
        peer_uri: None,
        path_session_hex,
        relay_session_hex: None,
        log,
    }
}

fn drive_path(mode: NatInjectMode, log: &mut NatEventLog) -> Result<Driven, EdgeError> {
    let client = gather_peer()?;
    let reflexive = client.reflexive.to_string();
    log.push_allocate(LAB_OVERLAY_IP, Some(&reflexive));
    let client = fail_direct(client)?;
    let direct_rtt_ms = client.rtt_ms;
    let direct_peer = direct_peer_uri();
    log.push_direct(false, Some(direct_rtt_ms));
    log.push_probe(false, direct_rtt_ms);
    log.push_down(PathKind::Direct, Some(&direct_peer));
    log.push_switch(PhaseName::Direct, PhaseName::Relay);

    let server = fail_direct(gather_peer()?)?;
    let relay = run_relay(mode, client.machine, server.machine)?;
    log.set_session_id(&relay.session_hex)?;
    log.push_hop(true, relay.attach_rtt_ms);
    log.push_relay(true, Some(relay.transport_slug));
    log.push_up(PathKind::Relay, Some(&relay.peer_uri));
    Ok(Driven {
        direct_rtt_ms,
        relay_attach_rtt_ms: relay.attach_rtt_ms,
        transport: relay.transport,
        reflexive,
        relay_session_hex: relay.session_hex,
        peer_uri: relay.peer_uri,
        direct_up: relay.direct_up,
        relay_up: relay.relay_up,
    })
}

struct RelayDone {
    attach_rtt_ms: u64,
    transport: RelayTransport,
    transport_slug: &'static str,
    session_hex: String,
    peer_uri: String,
    direct_up: bool,
    relay_up: bool,
}

struct RelayPlan {
    udp_discard: bool,
    preference: RelayPreference,
    udp_timeout: Duration,
    transport: RelayTransport,
}

fn plan_for(mode: NatInjectMode) -> RelayPlan {
    match mode {
        NatInjectMode::UdpBlock => RelayPlan {
            udp_discard: true,
            preference: RelayPreference::Auto,
            udp_timeout: UDP_BLOCK_TIMEOUT,
            transport: RelayTransport::Tcp,
        },
        NatInjectMode::Symmetric => RelayPlan {
            udp_discard: false,
            preference: RelayPreference::Udp,
            udp_timeout: UDP_OPEN_TIMEOUT,
            transport: RelayTransport::Udp,
        },
    }
}

fn run_relay(
    mode: NatInjectMode,
    client: PathMachine,
    server: PathMachine,
) -> Result<RelayDone, EdgeError> {
    let plan = plan_for(mode);
    let listen = loopback();
    let mut relay = RelayServer::spawn(ServerConfig {
        udp_bind: Some(listen),
        tcp_bind: Some(listen),
        audit_absent: Some(RELAY_PROOF_PAYLOAD.to_vec()),
        audit_path: None,
        udp_discard: plan.udp_discard,
    })
    .map_err(map_relay)?;
    let udp = relay
        .udp_addr()
        .ok_or_else(|| EdgeError::Relay("The Relay UDP socket did not bind.".to_string()))?;
    let tcp = relay
        .tcp_addr()
        .ok_or_else(|| EdgeError::Relay("The Relay TCP socket did not bind.".to_string()))?;
    let session = RelaySessionId::generate().map_err(map_relay)?;
    let request = RelayRequest {
        session_id: session,
        udp,
        tcp,
        preference: plan.preference,
        udp_timeout: plan.udp_timeout,
        tcp_timeout: TCP_TIMEOUT,
        budget: QUIC_BUDGET,
    };
    let material = issue_direct_pair(SystemTime::now())?;
    let attached = attach_both(server, client, request)?;
    if attached.client_transport != plan.transport || attached.server_transport != plan.transport {
        return Err(EdgeError::Relay(
            "The Relay transport does not match the inject.".to_string(),
        ));
    }
    let finished = finish_both(attached, material.server, material.client, session)?;
    let stats = relay.stats();
    relay.shutdown();
    if stats.forwards == 0 {
        return Err(EdgeError::Relay(
            "The Relay did not forward a payload.".to_string(),
        ));
    }
    if !finished.client_relay_up || !finished.server_relay_up {
        return Err(EdgeError::WrongState);
    }
    Ok(RelayDone {
        attach_rtt_ms: finished.attach_rtt_ms,
        transport: plan.transport,
        transport_slug: transport_slug(plan.transport),
        session_hex: session.to_hex(),
        peer_uri: relay_peer_uri(plan.transport, udp, tcp),
        direct_up: finished.client_direct_up,
        relay_up: finished.client_relay_up,
    })
}

struct AttachedPair {
    server: AttachedPeer,
    client: AttachedPeer,
    server_transport: RelayTransport,
    client_transport: RelayTransport,
    attach_rtt_ms: u64,
}

struct AttachedPeer {
    machine: PathMachine,
    link: RelayLink,
    transport: RelayTransport,
    session_id: RelaySessionId,
    attach_rtt_ms: u64,
}

struct FinishedPair {
    attach_rtt_ms: u64,
    client_direct_up: bool,
    client_relay_up: bool,
    server_relay_up: bool,
}

fn attach_both(
    server: PathMachine,
    client: PathMachine,
    request: RelayRequest,
) -> Result<AttachedPair, EdgeError> {
    let server_thread = thread::spawn(move || attach_one(server, request));
    let client_thread = thread::spawn(move || attach_one(client, request));
    let server_result = join_lab(server_thread);
    let client_result = join_lab(client_thread);
    let server = server_result?;
    let client = client_result?;
    Ok(AttachedPair {
        server_transport: server.transport,
        client_transport: client.transport,
        attach_rtt_ms: client.attach_rtt_ms,
        server,
        client,
    })
}

fn attach_one(mut machine: PathMachine, request: RelayRequest) -> Result<AttachedPeer, EdgeError> {
    let started = Instant::now();
    let link = machine.begin_relay(request)?;
    let attach_rtt_ms = duration_ms(started.elapsed());
    match machine.state() {
        PathState::Relay {
            phase:
                RelayPhase::Attach {
                    transport,
                    session_id,
                },
            ..
        } => Ok(AttachedPeer {
            machine,
            link,
            transport,
            session_id,
            attach_rtt_ms,
        }),
        PathState::Allocate { .. }
        | PathState::Direct { .. }
        | PathState::Relay {
            phase: RelayPhase::Up { .. } | RelayPhase::Failed { .. },
            ..
        } => Err(EdgeError::WrongState),
    }
}

fn finish_both(
    attached: AttachedPair,
    server_identity: DirectIdentity,
    client_identity: DirectIdentity,
    session: RelaySessionId,
) -> Result<FinishedPair, EdgeError> {
    let attach_rtt_ms = attached.attach_rtt_ms;
    let server_thread = thread::spawn(move || {
        finish_one(
            attached.server,
            DirectRole::Server,
            server_identity,
            session,
        )
    });
    thread::sleep(SERVER_HEAD_START);
    let client_thread = thread::spawn(move || {
        finish_one(
            attached.client,
            DirectRole::Client,
            client_identity,
            session,
        )
    });
    let server_result = join_lab(server_thread);
    let client_result = join_lab(client_thread);
    let server = server_result?;
    let client = client_result?;
    Ok(FinishedPair {
        attach_rtt_ms,
        client_direct_up: client.direct_is_up(),
        client_relay_up: client.relay_is_up(),
        server_relay_up: server.relay_is_up(),
    })
}

fn finish_one(
    peer: AttachedPeer,
    role: DirectRole,
    identity: DirectIdentity,
    session: RelaySessionId,
) -> Result<PathMachine, EdgeError> {
    if peer.session_id != session {
        return Err(EdgeError::WrongState);
    }
    let mut machine = peer.machine;
    let proof = machine.finish_relay(peer.link, role, &identity)?;
    if proof.transport != peer.transport || proof.session_id != session {
        return Err(EdgeError::WrongState);
    }
    if !machine.relay_is_up() {
        return Err(EdgeError::WrongState);
    }
    match machine.state() {
        PathState::Relay {
            phase: RelayPhase::Up { session_id, .. },
            ..
        } if session_id == session => Ok(machine),
        PathState::Allocate { .. } | PathState::Direct { .. } | PathState::Relay { .. } => {
            Err(EdgeError::WrongState)
        }
    }
}

struct Gathered {
    machine: PathMachine,
    socket: UdpSocket,
    reflexive: SocketAddr,
}

struct FailedDirect {
    machine: PathMachine,
    rtt_ms: u64,
}

fn gather_peer() -> Result<Gathered, EdgeError> {
    let stun = LabStunServer::bind(loopback())?;
    let stun_addr = stun.local_addr()?;
    let stun_thread = thread::spawn(move || stun.serve_one(STUN_SERVER_WAIT));
    let client = StunClient::bind(loopback())?;
    let mut machine = PathMachine::start_allocate();
    let mut sink = MemoryCandidateSink::default();
    let gathered = machine.gather_reflexive(&client, stun_addr, STUN_CLIENT_WAIT, &mut sink);
    let joined = join_lab(stun_thread);
    gathered?;
    joined?;
    let reflexive = ready_reflexive(&machine)?;
    Ok(Gathered {
        machine,
        socket: client.into_socket(),
        reflexive,
    })
}

fn fail_direct(gathered: Gathered) -> Result<FailedDirect, EdgeError> {
    let mut machine = gathered.machine;
    let started = Instant::now();
    let attempt = machine.establish_direct(DirectRequest {
        role: DirectRole::Server,
        remote: blackhole(),
        token: PunchToken::generate()?,
        socket: gathered.socket,
        identity: DirectIdentity::blank(),
        budget: DIRECT_FAIL_BUDGET,
    });
    let rtt_ms = duration_ms(started.elapsed());
    match attempt {
        Err(EdgeError::DirectBudget) => {}
        Ok(_) => {
            return Err(EdgeError::Relay(
                "Direct came up. The smash needs Direct to stop.".to_string(),
            ))
        }
        Err(error) => return Err(error),
    }
    require_direct_failed(&machine)?;
    Ok(FailedDirect { machine, rtt_ms })
}

fn ready_reflexive(machine: &PathMachine) -> Result<SocketAddr, EdgeError> {
    match machine.state() {
        PathState::Allocate {
            phase: AllocatePhase::Ready,
            candidate: Some(candidate),
        } => Ok(candidate.reflexive),
        PathState::Allocate { .. } | PathState::Direct { .. } | PathState::Relay { .. } => {
            Err(EdgeError::WrongState)
        }
    }
}

fn require_direct_failed(machine: &PathMachine) -> Result<(), EdgeError> {
    match machine.state() {
        PathState::Direct {
            phase: DirectPhase::Failed { packets_sent, .. },
            ..
        } => {
            if packets_sent == 0 {
                return Err(EdgeError::Relay(
                    "Direct stopped before a hole-punch datagram.".to_string(),
                ));
            }
            Ok(())
        }
        PathState::Allocate { .. } | PathState::Direct { .. } | PathState::Relay { .. } => {
            Err(EdgeError::WrongState)
        }
    }
}

fn transport_slug(transport: RelayTransport) -> &'static str {
    match transport {
        RelayTransport::Udp => "udp",
        RelayTransport::Tcp => "tcp",
    }
}

fn relay_peer_uri(transport: RelayTransport, udp: SocketAddr, tcp: SocketAddr) -> String {
    let address = match transport {
        RelayTransport::Udp => udp,
        RelayTransport::Tcp => tcp,
    };
    format!("{transport}://{address}")
}

fn direct_peer_uri() -> String {
    format!("udp://{}", blackhole().reflexive)
}

fn blackhole() -> EndpointCandidate {
    let socket = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    EndpointCandidate {
        local: socket,
        reflexive: socket,
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn map_relay(err: orblx_relay::RelayError) -> EdgeError {
    match err {
        orblx_relay::RelayError::UdpBlocked | orblx_relay::RelayError::Timeout => {
            EdgeError::RelayBudget
        }
        other @ (orblx_relay::RelayError::Io(_)
        | orblx_relay::RelayError::BadDatagram
        | orblx_relay::RelayError::BadSession
        | orblx_relay::RelayError::Closed
        | orblx_relay::RelayError::TooBig
        | orblx_relay::RelayError::SessionFull
        | orblx_relay::RelayError::NotAttached) => EdgeError::Relay(other.to_string()),
    }
}

fn join_lab<T>(handle: JoinHandle<Result<T, EdgeError>>) -> Result<T, EdgeError> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(EdgeError::LabThread),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use super::run_nat_smash;
    use crate::nat_feed::{
        NatDifficulty, NatInjectMode, NatLevel, KIND_NAT_INJECT, KIND_NAT_PROBE,
        KIND_PATH_ALLOCATE, KIND_PATH_DIRECT, KIND_PATH_DOWN, KIND_PATH_RELAY, KIND_PATH_SWITCH,
        KIND_PATH_UP, KIND_RELAY_HOP, LAB_OVERLAY_IP, NAT_FEED_SOURCE,
    };
    use crate::{NatSmash, STICK_AND_UPGRADE};
    use orblx_relay::RelayTransport;

    #[test]
    fn easy_city_breeze_stays_quiet() {
        let started = Instant::now();
        let mut report = run_nat_smash(NatSmash {
            difficulty: NatDifficulty::Easy,
            level: NatLevel::CityBreeze,
            mode: NatInjectMode::UdpBlock,
        })
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!report.ran);
        assert!(!report.direct_up);
        assert!(!report.relay_up);
        assert!(report.direct_rtt_ms.is_none());
        assert!(report.log.drain().is_empty());
        assert_eq!(report.path_session_hex.len(), 32);
    }

    #[test]
    fn udp_block_smash_emits_allocate_direct_fail_relay() {
        assert_smash(NatInjectMode::UdpBlock, RelayTransport::Tcp, "tcp");
    }

    #[test]
    fn symmetric_smash_emits_allocate_direct_fail_relay_udp() {
        assert_smash(NatInjectMode::Symmetric, RelayTransport::Udp, "udp");
    }

    fn assert_smash(mode: NatInjectMode, transport: RelayTransport, hop: &str) {
        let report = run_nat_smash(NatSmash {
            difficulty: NatDifficulty::Hard,
            level: NatLevel::RadioactiveNat,
            mode,
        })
        .expect("smash");
        assert!(report.ran);
        assert!(!report.direct_up);
        assert!(report.relay_up);
        assert_eq!(report.transport, Some(transport));
        assert_eq!(STICK_AND_UPGRADE, "reconnect");
        let direct_rtt = report.direct_rtt_ms.expect("direct rtt");
        let hop_rtt = report.relay_attach_rtt_ms.expect("hop rtt");
        assert!(direct_rtt >= 150, "direct rtt {direct_rtt}");
        assert!(hop_rtt < 5_000, "hop rtt {hop_rtt}");
        if mode == NatInjectMode::UdpBlock {
            assert!(hop_rtt >= 300, "udp block hop rtt {hop_rtt}");
        }
        let reflexive = report.reflexive.as_deref().expect("reflexive");
        assert!(reflexive.starts_with("127.0.0.1:"));
        let peer_uri = report.peer_uri.as_deref().expect("peer uri");
        assert!(peer_uri.starts_with(&format!("{hop}://")));
        let relay_hex = report.relay_session_hex.as_deref().expect("relay session");
        assert_eq!(relay_hex.len(), 32);
        assert_eq!(report.path_session_hex.len(), 32);

        let lines = report.log.lines();
        let kinds = [
            KIND_NAT_INJECT,
            KIND_PATH_ALLOCATE,
            KIND_PATH_DIRECT,
            KIND_NAT_PROBE,
            KIND_PATH_DOWN,
            KIND_PATH_SWITCH,
            KIND_RELAY_HOP,
            KIND_PATH_RELAY,
            KIND_PATH_UP,
        ];
        assert_eq!(lines.len(), kinds.len());
        for (index, line) in lines.iter().enumerate() {
            let value: Value = serde_json::from_str(line).unwrap();
            let object = value.as_object().unwrap();
            assert_eq!(object.get("v").unwrap().as_u64(), Some(1));
            assert_eq!(
                object.get("source").unwrap().as_str(),
                Some(NAT_FEED_SOURCE)
            );
            assert_eq!(
                object.get("level").unwrap().as_str(),
                Some("radioactive_nat")
            );
            assert_eq!(object.get("difficulty").unwrap().as_str(), Some("hard"));
            assert_eq!(object.get("kind").unwrap().as_str(), Some(kinds[index]));
            assert_eq!(
                object.get("seq").unwrap().as_u64(),
                Some(u64::try_from(index + 1).unwrap())
            );
            let session = object.get("session_id").unwrap().as_str().unwrap();
            assert_eq!(session.len(), 32);
            let expect = if index < 6 {
                report.path_session_hex.as_str()
            } else {
                relay_hex
            };
            assert_eq!(session, expect);
            let kind = object.get("kind").unwrap().as_str().unwrap();
            assert!(!kind.contains("stick"));
            assert!(!kind.contains("upgrade"));
        }

        let inject: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(inject.get("mode").unwrap().as_str(), Some(mode.slug()));
        assert_eq!(inject.get("armed").unwrap().as_bool(), Some(true));

        let allocate: Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(
            allocate.get("overlay_ip").unwrap().as_str(),
            Some(LAB_OVERLAY_IP)
        );
        assert_eq!(allocate.get("reflexive").unwrap().as_str(), Some(reflexive));

        let direct: Value = serde_json::from_str(&lines[2]).unwrap();
        assert_eq!(direct.get("ok").unwrap().as_bool(), Some(false));
        assert_eq!(direct.get("rtt_ms").unwrap().as_u64(), Some(direct_rtt));

        let probe: Value = serde_json::from_str(&lines[3]).unwrap();
        assert_eq!(probe.get("ok").unwrap().as_bool(), Some(false));
        assert_eq!(probe.get("rtt_ms").unwrap().as_u64(), Some(direct_rtt));

        let down: Value = serde_json::from_str(&lines[4]).unwrap();
        assert_eq!(down.get("path").unwrap().as_str(), Some("direct"));
        assert_eq!(
            down.get("peer_uri").unwrap().as_str(),
            Some("udp://127.0.0.1:9")
        );

        let switch: Value = serde_json::from_str(&lines[5]).unwrap();
        assert_eq!(switch.get("from").unwrap().as_str(), Some("direct"));
        assert_eq!(switch.get("to").unwrap().as_str(), Some("relay"));

        let hop_event: Value = serde_json::from_str(&lines[6]).unwrap();
        assert_eq!(hop_event.get("ok").unwrap().as_bool(), Some(true));
        assert_eq!(hop_event.get("rtt_ms").unwrap().as_u64(), Some(hop_rtt));

        let relay: Value = serde_json::from_str(&lines[7]).unwrap();
        assert_eq!(relay.get("ok").unwrap().as_bool(), Some(true));
        assert_eq!(relay.get("hop").unwrap().as_str(), Some(hop));

        let up: Value = serde_json::from_str(&lines[8]).unwrap();
        assert_eq!(up.get("path").unwrap().as_str(), Some("relay"));
        assert_eq!(up.get("peer_uri").unwrap().as_str(), Some(peer_uri));
    }
}
