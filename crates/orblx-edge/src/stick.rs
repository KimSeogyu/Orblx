//! Stick holds the Relay path and retries Direct.
//!
//! A failed retry leaves the machine on Relay.
//! A successful retry opens a new hello-quic session on the direct socket.
//! The process does not restart.
//! The Relay Quinn session is not migrated.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use orblx_relay::{
    RelayError, RelayPreference, RelayServer, RelaySessionId, RelayTransport, ServerConfig,
};

use crate::direct::issue_direct_pair;
use crate::lab::LabUdpNat;
use crate::{
    DirectIdentity, DirectPhase, DirectRequest, DirectRole, DirectUpgrade, EdgeError,
    EndpointCandidate, LabStunServer, MemoryCandidateSink, PathId, PathMachine, PathState,
    PunchToken, RelayLink, RelayProof, RelayRequest, StunClient, DIRECT_ATTEMPT_BUDGET,
    DIRECT_RETRY_INTERVAL, RELAY_PROOF_PAYLOAD, STICK_AND_UPGRADE,
};

const FAIL_BUDGET: Duration = Duration::from_millis(200);
const RELAY_BUDGET: Duration = Duration::from_secs(8);
const UDP_OPEN_TIMEOUT: Duration = Duration::from_secs(2);
const UDP_BLOCK_TIMEOUT: Duration = Duration::from_millis(400);
const TCP_TIMEOUT: Duration = Duration::from_secs(2);
const SERVER_HEAD_START: Duration = Duration::from_millis(80);
const STUN_WAIT: Duration = Duration::from_secs(3);
const SETUP_WAIT: Duration = Duration::from_secs(5);

/// The in-process NAT case for one stick lab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickNatKind {
    /// Two peers share one NAT address.
    ///
    /// Direct fails first.
    /// Relay uses UDP.
    /// A later retry uses the host candidates.
    SameNat,
    /// Direct has no answering peer.
    ///
    /// Relay uses UDP.
    /// The retry does not upgrade.
    Symmetric,
    /// The Relay UDP socket does not answer.
    ///
    /// Relay uses TCP.
    /// The Direct retry does not upgrade.
    UdpBlock,
}

impl StickNatKind {
    /// The lab name.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::SameNat => "same-nat",
            Self::Symmetric => "symmetric",
            Self::UdpBlock => "udp-block",
        }
    }

    const fn udp_discard(self) -> bool {
        match self {
            Self::SameNat | Self::Symmetric => false,
            Self::UdpBlock => true,
        }
    }

    const fn preference(self) -> RelayPreference {
        match self {
            Self::SameNat | Self::Symmetric => RelayPreference::Udp,
            Self::UdpBlock => RelayPreference::Auto,
        }
    }

    const fn udp_timeout(self) -> Duration {
        match self {
            Self::SameNat | Self::Symmetric => UDP_OPEN_TIMEOUT,
            Self::UdpBlock => UDP_BLOCK_TIMEOUT,
        }
    }

    const fn transport(self) -> RelayTransport {
        match self {
            Self::SameNat | Self::Symmetric => RelayTransport::Udp,
            Self::UdpBlock => RelayTransport::Tcp,
        }
    }
}

/// Evidence from one stick lab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickReport {
    /// `same-nat`, `symmetric`, or `udp-block`.
    pub nat: &'static str,
    /// The upgrade method. This build uses `reconnect`.
    pub method: &'static str,
    /// The Relay transport that came up first.
    pub transport: RelayTransport,
    /// True when both peers were on Relay before the retries.
    pub started_on_relay: bool,
    /// True when a retry before the interval left the Relay path in place.
    pub early_hold: bool,
    /// True when a failed Direct retry left the Relay path in place.
    pub failed_retry_held: bool,
    /// True when the Relay path id was unchanged by the failed retry.
    pub relay_path_stable: bool,
    /// True when both peers moved to Direct.
    pub upgraded: bool,
    /// The server Direct flag after the lab.
    pub server_direct_is_up: bool,
    /// The client Direct flag after the lab.
    pub client_direct_is_up: bool,
    /// The server Relay flag after the lab.
    pub server_relay_is_up: bool,
    /// The client Relay flag after the lab.
    pub client_relay_is_up: bool,
    /// The Relay QUIC probe echoed on both peers.
    pub relay_echo_ok: bool,
    /// The Direct QUIC probe echoed on both peers.
    ///
    /// False when the lab did not upgrade.
    pub direct_echo_ok: bool,
    /// True when the Direct peer address is the host socket.
    ///
    /// False when the lab did not upgrade.
    pub direct_on_host: bool,
    /// Relay forwards after the Relay proof and before the Direct retry.
    pub forwards_before: u64,
    /// Relay forwards after the Direct retry.
    pub forwards_after: u64,
    /// True when the lab process id changed.
    ///
    /// The lab does not start a new process.
    pub restarted: bool,
    /// The client Relay path id.
    pub from_path_id: PathId,
    /// The client Direct path id after an upgrade.
    pub to_path_id: Option<PathId>,
}

impl StickReport {
    /// Return true when this NAT case matches the lab rule.
    ///
    /// `same-nat` must end on Direct.
    /// `symmetric` and `udp-block` must stay on Relay.
    #[must_use]
    pub fn lab_ok(&self) -> bool {
        let common = self.method == STICK_AND_UPGRADE
            && self.started_on_relay
            && self.early_hold
            && self.failed_retry_held
            && self.relay_path_stable
            && self.relay_echo_ok
            && !self.restarted
            && self.forwards_before >= 1
            && self.forwards_after == self.forwards_before;
        match self.nat {
            "same-nat" => {
                common
                    && self.transport == RelayTransport::Udp
                    && self.upgraded
                    && self.server_direct_is_up
                    && self.client_direct_is_up
                    && !self.server_relay_is_up
                    && !self.client_relay_is_up
                    && self.direct_echo_ok
                    && self.direct_on_host
                    && self
                        .to_path_id
                        .is_some_and(|path_id| path_id != self.from_path_id)
            }
            "symmetric" => self.hold_ok(common, RelayTransport::Udp),
            "udp-block" => self.hold_ok(common, RelayTransport::Tcp),
            _ => false,
        }
    }

    fn hold_ok(&self, common: bool, transport: RelayTransport) -> bool {
        common
            && self.transport == transport
            && !self.upgraded
            && !self.server_direct_is_up
            && !self.client_direct_is_up
            && self.server_relay_is_up
            && self.client_relay_is_up
            && !self.direct_echo_ok
            && !self.direct_on_host
            && self.to_path_id.is_none()
    }

    /// Return the lab lines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let to_path = match self.to_path_id {
            Some(path_id) => path_id.to_hex(),
            None => "none".to_string(),
        };
        vec![
            format!("stick lab {}", self.nat),
            format!("method {}", self.method),
            format!("transport {}", self.transport),
            format!("started_on_relay {}", self.started_on_relay),
            format!("early_hold {}", self.early_hold),
            format!("failed_retry_held {}", self.failed_retry_held),
            format!("relay_path_stable {}", self.relay_path_stable),
            format!("upgraded {}", self.upgraded),
            format!("server direct_is_up {}", self.server_direct_is_up),
            format!("client direct_is_up {}", self.client_direct_is_up),
            format!("server relay_is_up {}", self.server_relay_is_up),
            format!("client relay_is_up {}", self.client_relay_is_up),
            format!("relay echo ok {}", self.relay_echo_ok),
            format!("direct echo ok {}", self.direct_echo_ok),
            format!("direct_on_host {}", self.direct_on_host),
            format!("forwards_before {}", self.forwards_before),
            format!("forwards_after {}", self.forwards_after),
            format!(
                "direct_used_relay {}",
                self.forwards_after != self.forwards_before
            ),
            format!("restarted {}", self.restarted),
            format!("from_path_id {}", self.from_path_id.to_hex()),
            format!("to_path_id {to_path}"),
        ]
    }
}

struct PeerStart {
    machine: PathMachine,
    socket: UdpSocket,
    reflexive: SocketAddr,
    local: SocketAddr,
}

struct LiveRelay {
    server: RelayServer,
    server_machine: PathMachine,
    client_machine: PathMachine,
    server_reflexive: SocketAddr,
    client_reflexive: SocketAddr,
    server_identity: DirectIdentity,
    client_identity: DirectIdentity,
    transport: RelayTransport,
    relay_echo_ok: bool,
    from_path_id: PathId,
    started_on_relay: bool,
}

struct Upgraded {
    server_machine: PathMachine,
    client_machine: PathMachine,
    client_upgrade: DirectUpgrade,
    forwards_before: u64,
    forwards_after: u64,
    direct_echo_ok: bool,
    direct_on_host: bool,
}

/// Run one stick lab.
///
/// The peers prove QUIC through the Relay first.
/// An early Direct retry does not leave Relay.
/// A Direct retry with no answering peer does not leave Relay.
/// `SameNat` then punches the host candidates and proves QUIC on that socket.
/// The function does not start a new process.
pub fn run_stick_upgrade(kind: StickNatKind) -> Result<StickReport, EdgeError> {
    let pid = process::id();
    let mut live = setup(kind)?;
    let early_hold = hold_early(&mut live.server_machine)? && hold_early(&mut live.client_machine)?;
    let failed_retry_held =
        hold_failed(&mut live.server_machine)? && hold_failed(&mut live.client_machine)?;
    let relay_path_stable = live.client_machine.path_id() == Some(live.from_path_id)
        && live.server_machine.relay_is_up()
        && live.client_machine.relay_is_up();
    let base = ReportBase {
        nat: kind.slug(),
        transport: live.transport,
        started_on_relay: live.started_on_relay,
        early_hold,
        failed_retry_held,
        relay_path_stable,
        relay_echo_ok: live.relay_echo_ok,
        from_path_id: live.from_path_id,
        restarted: process::id() != pid,
    };
    match kind {
        StickNatKind::SameNat => {
            let upgraded = upgrade_both(&mut live)?;
            Ok(report_upgraded(&base, &upgraded))
        }
        StickNatKind::Symmetric | StickNatKind::UdpBlock => {
            let forwards = live.server.stats().forwards;
            live.server.shutdown();
            Ok(report_held(
                &base,
                &live.server_machine,
                &live.client_machine,
                forwards,
            ))
        }
    }
}

struct ReportBase {
    nat: &'static str,
    transport: RelayTransport,
    started_on_relay: bool,
    early_hold: bool,
    failed_retry_held: bool,
    relay_path_stable: bool,
    relay_echo_ok: bool,
    from_path_id: PathId,
    restarted: bool,
}

fn report_held(
    base: &ReportBase,
    server: &PathMachine,
    client: &PathMachine,
    forwards: u64,
) -> StickReport {
    StickReport {
        nat: base.nat,
        method: STICK_AND_UPGRADE,
        transport: base.transport,
        started_on_relay: base.started_on_relay,
        early_hold: base.early_hold,
        failed_retry_held: base.failed_retry_held,
        relay_path_stable: base.relay_path_stable,
        upgraded: false,
        server_direct_is_up: server.direct_is_up(),
        client_direct_is_up: client.direct_is_up(),
        server_relay_is_up: server.relay_is_up(),
        client_relay_is_up: client.relay_is_up(),
        relay_echo_ok: base.relay_echo_ok,
        direct_echo_ok: false,
        direct_on_host: false,
        forwards_before: forwards,
        forwards_after: forwards,
        restarted: base.restarted,
        from_path_id: base.from_path_id,
        to_path_id: None,
    }
}

fn report_upgraded(base: &ReportBase, upgraded: &Upgraded) -> StickReport {
    StickReport {
        nat: base.nat,
        method: STICK_AND_UPGRADE,
        transport: base.transport,
        started_on_relay: base.started_on_relay,
        early_hold: base.early_hold,
        failed_retry_held: base.failed_retry_held,
        relay_path_stable: base.relay_path_stable,
        upgraded: upgraded.server_machine.direct_is_up() && upgraded.client_machine.direct_is_up(),
        server_direct_is_up: upgraded.server_machine.direct_is_up(),
        client_direct_is_up: upgraded.client_machine.direct_is_up(),
        server_relay_is_up: upgraded.server_machine.relay_is_up(),
        client_relay_is_up: upgraded.client_machine.relay_is_up(),
        relay_echo_ok: base.relay_echo_ok,
        direct_echo_ok: upgraded.direct_echo_ok,
        direct_on_host: upgraded.direct_on_host,
        forwards_before: upgraded.forwards_before,
        forwards_after: upgraded.forwards_after,
        restarted: base.restarted,
        from_path_id: base.from_path_id,
        to_path_id: Some(upgraded.client_upgrade.proof.path_id),
    }
}

fn setup(kind: StickNatKind) -> Result<LiveRelay, EdgeError> {
    let (server_peer, client_peer) = match kind {
        StickNatKind::SameNat => gather_same_nat()?,
        StickNatKind::Symmetric | StickNatKind::UdpBlock => gather_open_pair()?,
    };
    if kind == StickNatKind::SameNat {
        require_same_nat(&server_peer, &client_peer)?;
    }
    let server_reflexive = server_peer.reflexive;
    let client_reflexive = client_peer.reflexive;
    let server_machine = fail_direct(server_peer)?;
    let client_machine = fail_direct(client_peer)?;
    let material = issue_direct_pair(SystemTime::now())?;
    let listen = loopback();
    let mut relay = RelayServer::spawn(ServerConfig {
        udp_bind: Some(listen),
        tcp_bind: Some(listen),
        audit_absent: Some(RELAY_PROOF_PAYLOAD.to_vec()),
        audit_path: None,
        udp_discard: kind.udp_discard(),
    })
    .map_err(map_relay)?;
    let udp = relay
        .udp_addr()
        .ok_or_else(|| EdgeError::Relay("The Relay UDP socket did not bind.".to_string()))?;
    let tcp = relay
        .tcp_addr()
        .ok_or_else(|| EdgeError::Relay("The Relay TCP socket did not bind.".to_string()))?;
    let session_id = RelaySessionId::generate().map_err(map_relay)?;
    let request = RelayRequest {
        session_id,
        udp,
        tcp,
        preference: kind.preference(),
        udp_timeout: kind.udp_timeout(),
        tcp_timeout: TCP_TIMEOUT,
        budget: RELAY_BUDGET,
    };
    let (server_machine, server_proof, client_machine, client_proof) = finish_relay_pair(
        server_machine,
        client_machine,
        request,
        material.server.clone(),
        material.client.clone(),
    )?;
    if server_proof.transport != kind.transport() || client_proof.transport != kind.transport() {
        return Err(EdgeError::Relay(
            "The Relay transport does not match the lab.".to_string(),
        ));
    }
    let relay_echo_ok = echoed_has(&server_proof, &client_proof, RELAY_PROOF_PAYLOAD);
    let from_path_id = client_proof.path_id;
    let started_on_relay = server_machine.relay_is_up()
        && client_machine.relay_is_up()
        && server_machine.stick_holding()
        && client_machine.stick_holding()
        && !server_machine.direct_is_up()
        && !client_machine.direct_is_up();
    if !relay_echo_ok || !started_on_relay {
        relay.shutdown();
        return Err(EdgeError::Relay(
            "The Relay path did not come up.".to_string(),
        ));
    }
    Ok(LiveRelay {
        server: relay,
        server_machine,
        client_machine,
        server_reflexive,
        client_reflexive,
        server_identity: material.server,
        client_identity: material.client,
        transport: server_proof.transport,
        relay_echo_ok,
        from_path_id,
        started_on_relay,
    })
}

fn hold_early(machine: &mut PathMachine) -> Result<bool, EdgeError> {
    let due = machine.direct_retry_at().ok_or(EdgeError::WrongState)?;
    let now = due
        .checked_sub(Duration::from_millis(1))
        .ok_or(EdgeError::WrongState)?;
    let path_id = machine.path_id();
    let error = machine.retry_direct(now, closed_request()?);
    match error {
        Err(EdgeError::StickHold) => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(EdgeError::Relay(
                "An early Direct retry left the Relay path.".to_string(),
            ))
        }
    }
    let held = machine.relay_is_up()
        && machine.stick_holding()
        && !machine.direct_is_up()
        && machine.path_id() == path_id
        && machine.direct_retry_at() == Some(due);
    if !held {
        return Err(EdgeError::WrongState);
    }
    Ok(true)
}

fn hold_failed(machine: &mut PathMachine) -> Result<bool, EdgeError> {
    let now = machine.direct_retry_at().ok_or(EdgeError::WrongState)?;
    let path_id = machine.path_id();
    let error = machine.retry_direct(now, closed_request()?);
    match error {
        Ok(_) => {
            return Err(EdgeError::Relay(
                "Direct came up. The stick lab needs this retry to fail.".to_string(),
            ))
        }
        Err(EdgeError::StickHold) => return Err(EdgeError::StickHold),
        Err(EdgeError::WrongState) => return Err(EdgeError::WrongState),
        Err(EdgeError::Io(_))
        | Err(EdgeError::ShortStun { .. })
        | Err(EdgeError::NotStun)
        | Err(EdgeError::BadCookie)
        | Err(EdgeError::BadAttribute)
        | Err(EdgeError::BadFingerprint)
        | Err(EdgeError::BadFamily { .. })
        | Err(EdgeError::NotBindingRequest { .. })
        | Err(EdgeError::NotBindingSuccess { .. })
        | Err(EdgeError::TransactionMismatch)
        | Err(EdgeError::NoMappedAddress)
        | Err(EdgeError::UnknownRequired { .. })
        | Err(EdgeError::BindingError { .. })
        | Err(EdgeError::Timeout)
        | Err(EdgeError::CandidateRejected)
        | Err(EdgeError::LabThread)
        | Err(EdgeError::SocketMismatch)
        | Err(EdgeError::DirectBudget)
        | Err(EdgeError::EchoMismatch)
        | Err(EdgeError::BadCandidate)
        | Err(EdgeError::Signature)
        | Err(EdgeError::BadToken)
        | Err(EdgeError::Identity(_))
        | Err(EdgeError::Quic(_))
        | Err(EdgeError::RelayBudget)
        | Err(EdgeError::Relay(_))
        | Err(EdgeError::BadNatFeed(_)) => {}
    }
    let next = now
        .checked_add(DIRECT_RETRY_INTERVAL)
        .ok_or(EdgeError::WrongState)?;
    let held = machine.relay_is_up()
        && machine.stick_holding()
        && !machine.direct_is_up()
        && machine.path_id() == path_id
        && machine.direct_retry_at() == Some(next);
    if !held {
        return Err(EdgeError::WrongState);
    }
    Ok(true)
}

fn upgrade_both(live: &mut LiveRelay) -> Result<Upgraded, EdgeError> {
    let forwards_before = live.server.stats().forwards;
    if forwards_before == 0 {
        return Err(EdgeError::Relay(
            "The Relay did not forward a payload.".to_string(),
        ));
    }
    let token = PunchToken::generate()?;
    let server_socket = UdpSocket::bind(loopback()).map_err(crate::error::io_error)?;
    let client_socket = UdpSocket::bind(loopback()).map_err(crate::error::io_error)?;
    let server_addr = server_socket.local_addr().map_err(crate::error::io_error)?;
    let client_addr = client_socket.local_addr().map_err(crate::error::io_error)?;
    let server_now = live
        .server_machine
        .direct_retry_at()
        .ok_or(EdgeError::WrongState)?;
    let client_now = live
        .client_machine
        .direct_retry_at()
        .ok_or(EdgeError::WrongState)?;
    let server_remote = EndpointCandidate {
        local: client_addr,
        reflexive: live.client_reflexive,
    };
    let client_remote = EndpointCandidate {
        local: server_addr,
        reflexive: live.server_reflexive,
    };
    let server_machine = take_machine(&mut live.server_machine);
    let client_machine = take_machine(&mut live.client_machine);
    let server_identity = live.server_identity.clone();
    let client_identity = live.client_identity.clone();
    let server_thread = thread::spawn(move || {
        upgrade_one(
            server_machine,
            server_now,
            direct_request(
                DirectRole::Server,
                server_remote,
                server_socket,
                server_identity,
                DIRECT_ATTEMPT_BUDGET,
                token,
            ),
        )
    });
    thread::sleep(SERVER_HEAD_START);
    let client_thread = thread::spawn(move || {
        upgrade_one(
            client_machine,
            client_now,
            direct_request(
                DirectRole::Client,
                client_remote,
                client_socket,
                client_identity,
                DIRECT_ATTEMPT_BUDGET,
                token,
            ),
        )
    });
    let server_result = join_result(server_thread);
    let client_result = join_result(client_thread);
    let (server_machine, server_upgrade) = server_result?;
    let (client_machine, client_upgrade) = client_result?;
    let forwards_after = live.server.stats().forwards;
    live.server.shutdown();
    let direct_echo_ok = server_upgrade.proof.echoed == client_upgrade.proof.echoed
        && contains_bytes(&server_upgrade.proof.echoed, b"direct");
    let direct_on_host = server_upgrade.proof.peer == client_addr
        && client_upgrade.proof.peer == server_addr
        && server_upgrade.proof.peer != live.client_reflexive
        && client_upgrade.proof.peer != live.server_reflexive
        && server_upgrade.proof.quic_port == client_upgrade.proof.quic_port
        && client_upgrade.from_path_id == live.from_path_id
        && server_upgrade.proof.path_id != server_upgrade.from_path_id
        && client_upgrade.proof.path_id != client_upgrade.from_path_id;
    if !direct_echo_ok {
        return Err(EdgeError::EchoMismatch);
    }
    if !direct_on_host || !server_machine.direct_is_up() || !client_machine.direct_is_up() {
        return Err(EdgeError::WrongState);
    }
    Ok(Upgraded {
        server_machine,
        client_machine,
        client_upgrade,
        forwards_before,
        forwards_after,
        direct_echo_ok,
        direct_on_host,
    })
}

fn upgrade_one(
    mut machine: PathMachine,
    now: Instant,
    request: DirectRequest,
) -> Result<(PathMachine, DirectUpgrade), EdgeError> {
    let upgrade = machine.retry_direct(now, request)?;
    if machine.path_id() != Some(upgrade.proof.path_id)
        || machine.relay_is_up()
        || machine.stick_holding()
    {
        return Err(EdgeError::WrongState);
    }
    Ok((machine, upgrade))
}

fn take_machine(machine: &mut PathMachine) -> PathMachine {
    std::mem::replace(machine, PathMachine::start_allocate())
}

fn finish_relay_pair(
    server_machine: PathMachine,
    client_machine: PathMachine,
    request: RelayRequest,
    server_identity: DirectIdentity,
    client_identity: DirectIdentity,
) -> Result<(PathMachine, RelayProof, PathMachine, RelayProof), EdgeError> {
    let server_thread = thread::spawn(move || attach_one(server_machine, request));
    let client_thread = thread::spawn(move || attach_one(client_machine, request));
    let server_attached = join_result(server_thread);
    let client_attached = join_result(client_thread);
    let (server_machine, server_link) = server_attached?;
    let (client_machine, client_link) = client_attached?;
    let server_thread = thread::spawn(move || {
        prove_one(
            server_machine,
            server_link,
            DirectRole::Server,
            server_identity,
        )
    });
    thread::sleep(SERVER_HEAD_START);
    let client_thread = thread::spawn(move || {
        prove_one(
            client_machine,
            client_link,
            DirectRole::Client,
            client_identity,
        )
    });
    let server_proved = join_result(server_thread);
    let client_proved = join_result(client_thread);
    let (server_proof, server_machine) = server_proved?;
    let (client_proof, client_machine) = client_proved?;
    Ok((server_machine, server_proof, client_machine, client_proof))
}

fn attach_one(
    mut machine: PathMachine,
    request: RelayRequest,
) -> Result<(PathMachine, RelayLink), EdgeError> {
    let link = machine.begin_relay(request)?;
    Ok((machine, link))
}

fn prove_one(
    mut machine: PathMachine,
    link: RelayLink,
    role: DirectRole,
    identity: DirectIdentity,
) -> Result<(RelayProof, PathMachine), EdgeError> {
    let proof = machine.finish_relay(link, role, &identity)?;
    Ok((proof, machine))
}

fn gather_same_nat() -> Result<(PeerStart, PeerStart), EdgeError> {
    let server = StunClient::bind(loopback())?;
    let client = StunClient::bind(loopback())?;
    let stun = LabStunServer::bind(loopback())?;
    let stun_addr = stun.local_addr()?;
    let nat_server = LabUdpNat::bind(loopback(), stun_addr)?;
    let nat_client = LabUdpNat::bind(loopback(), stun_addr)?;
    let nat_server_addr = nat_server.local_addr()?;
    let nat_client_addr = nat_client.local_addr()?;
    let stun_thread = thread::spawn(move || stun.serve_many(2, SETUP_WAIT));
    let nat_server_thread = thread::spawn(move || nat_server.forward_one(SETUP_WAIT));
    let nat_client_thread = thread::spawn(move || nat_client.forward_one(SETUP_WAIT));
    let server_gathered = gather_machine(&server, nat_server_addr);
    let client_gathered = gather_machine(&client, nat_client_addr);
    let stun_outcome = join_thread(stun_thread)?;
    let nat_server_outcome = join_thread(nat_server_thread)?;
    let nat_client_outcome = join_thread(nat_client_thread)?;
    let server_peer = peer_from(server_gathered?, server)?;
    let client_peer = peer_from(client_gathered?, client)?;
    stun_outcome?;
    nat_server_outcome?;
    nat_client_outcome?;
    Ok((server_peer, client_peer))
}

fn gather_open_pair() -> Result<(PeerStart, PeerStart), EdgeError> {
    Ok((gather_open_one()?, gather_open_one()?))
}

fn gather_open_one() -> Result<PeerStart, EdgeError> {
    let stun = LabStunServer::bind(loopback())?;
    let stun_addr = stun.local_addr()?;
    let stun_thread = thread::spawn(move || stun.serve_one(STUN_WAIT));
    let client = StunClient::bind(loopback())?;
    let gathered = gather_machine(&client, stun_addr);
    let joined = join_thread(stun_thread)?;
    let peer = peer_from(gathered?, client)?;
    joined?;
    Ok(peer)
}

fn gather_machine(
    client: &StunClient,
    stun: SocketAddr,
) -> Result<(PathMachine, EndpointCandidate), EdgeError> {
    let mut machine = PathMachine::start_allocate();
    let mut sink = MemoryCandidateSink::default();
    let candidate = machine.gather_reflexive(client, stun, STUN_WAIT, &mut sink)?;
    Ok((machine, candidate))
}

fn peer_from(
    gathered: (PathMachine, EndpointCandidate),
    client: StunClient,
) -> Result<PeerStart, EdgeError> {
    let (machine, candidate) = gathered;
    Ok(PeerStart {
        machine,
        socket: client.into_socket(),
        reflexive: candidate.reflexive,
        local: candidate.local,
    })
}

fn require_same_nat(server: &PeerStart, client: &PeerStart) -> Result<(), EdgeError> {
    let same = server.reflexive.ip() == client.reflexive.ip()
        && server.reflexive != client.reflexive
        && server.local != server.reflexive
        && client.local != client.reflexive;
    if same {
        Ok(())
    } else {
        Err(EdgeError::Relay(
            "The same-NAT lab did not gather two reflexive addresses.".to_string(),
        ))
    }
}

fn fail_direct(peer: PeerStart) -> Result<PathMachine, EdgeError> {
    let mut machine = peer.machine;
    let error = machine.establish_direct(direct_request(
        DirectRole::Server,
        blackhole(),
        peer.socket,
        DirectIdentity::blank(),
        FAIL_BUDGET,
        PunchToken::generate()?,
    ));
    match error {
        Err(EdgeError::DirectBudget) => {}
        Ok(_) => {
            return Err(EdgeError::Relay(
                "Direct came up. The stick lab needs Direct to fail.".to_string(),
            ))
        }
        Err(error) => return Err(error),
    }
    require_direct_failed(&machine)?;
    Ok(machine)
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

fn closed_request() -> Result<DirectRequest, EdgeError> {
    let socket = UdpSocket::bind(loopback()).map_err(crate::error::io_error)?;
    Ok(direct_request(
        DirectRole::Server,
        blackhole(),
        socket,
        DirectIdentity::blank(),
        FAIL_BUDGET,
        PunchToken::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
    ))
}

fn direct_request(
    role: DirectRole,
    remote: EndpointCandidate,
    socket: UdpSocket,
    identity: DirectIdentity,
    budget: Duration,
    token: PunchToken,
) -> DirectRequest {
    DirectRequest {
        role,
        remote,
        token,
        socket,
        identity,
        budget,
    }
}

fn blackhole() -> EndpointCandidate {
    let socket = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    EndpointCandidate {
        local: socket,
        reflexive: socket,
    }
}

fn echoed_has(server: &RelayProof, client: &RelayProof, payload: &[u8]) -> bool {
    server.echoed == client.echoed && contains_bytes(&server.echoed, payload)
}

fn contains_bytes(packet: &[u8], payload: &[u8]) -> bool {
    packet
        .windows(payload.len())
        .any(|window| window == payload)
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn map_relay(err: RelayError) -> EdgeError {
    match err {
        RelayError::UdpBlocked | RelayError::Timeout => EdgeError::RelayBudget,
        other @ (RelayError::Io(_)
        | RelayError::BadDatagram
        | RelayError::BadSession
        | RelayError::Closed
        | RelayError::TooBig
        | RelayError::SessionFull
        | RelayError::NotAttached) => EdgeError::Relay(other.to_string()),
    }
}

fn join_thread<T>(handle: JoinHandle<T>) -> Result<T, EdgeError> {
    handle.join().map_err(|_| EdgeError::LabThread)
}

fn join_result<T>(handle: JoinHandle<Result<T, EdgeError>>) -> Result<T, EdgeError> {
    join_thread(handle)?
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::time::Instant;

    use super::{loopback, run_stick_upgrade, StickNatKind};
    use crate::{
        DirectIdentity, DirectRequest, DirectRole, EdgeError, EndpointCandidate, PathMachine,
        PunchToken, DIRECT_ATTEMPT_BUDGET,
    };

    #[test]
    fn retry_before_relay_is_rejected() {
        let mut machine = PathMachine::start_allocate();
        let socket = UdpSocket::bind(loopback()).unwrap();
        let remote = EndpointCandidate {
            local: socket.local_addr().unwrap(),
            reflexive: socket.local_addr().unwrap(),
        };
        let error = machine
            .retry_direct(
                Instant::now(),
                DirectRequest {
                    role: DirectRole::Server,
                    remote,
                    token: PunchToken::from_bytes([9; 8]),
                    socket,
                    identity: DirectIdentity::blank(),
                    budget: DIRECT_ATTEMPT_BUDGET,
                },
            )
            .unwrap_err();
        assert_eq!(error, EdgeError::WrongState);
        assert!(!machine.stick_holding());
        assert!(machine.direct_retry_at().is_none());
    }

    #[test]
    fn same_nat_upgrades_from_relay_to_direct_without_restart() {
        let report = run_stick_upgrade(StickNatKind::SameNat).expect("same-nat stick lab");
        assert!(report.lab_ok(), "{}", report.lines().join("\n"));
        assert!(report.upgraded);
        assert!(report.client_direct_is_up);
        assert!(!report.client_relay_is_up);
        assert!(!report.restarted);
        assert_eq!(report.method, "reconnect");
    }

    #[test]
    fn symmetric_sticks_on_relay_when_direct_stays_down() {
        let report = run_stick_upgrade(StickNatKind::Symmetric).expect("symmetric stick lab");
        assert!(report.lab_ok(), "{}", report.lines().join("\n"));
        assert!(!report.upgraded);
        assert!(report.client_relay_is_up);
        assert!(!report.client_direct_is_up);
    }

    #[test]
    fn udp_block_sticks_on_tcp_relay_when_direct_stays_down() {
        let report = run_stick_upgrade(StickNatKind::UdpBlock).expect("udp-block stick lab");
        assert!(report.lab_ok(), "{}", report.lines().join("\n"));
        assert!(!report.upgraded);
        assert_eq!(report.transport, orblx_relay::RelayTransport::Tcp);
        assert!(report.client_relay_is_up);
    }
}
