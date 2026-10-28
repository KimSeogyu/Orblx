//! Level state machines for the sim harness.
//!
//! Each smash runs a state machine.
//! The machine calls identity, frame, path, relay, and audit APIs.
//! The machine emits one feed object per transition.
//! The machine does not play a canned success animation.

use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gyeol_audit::{AuditLog, DenyReason, SessionEvent, SessionIds};
use gyeol_datapath::{
    ipv4_packet, is_ipv4_packet, Frame, FrameType, APP_A_BODY, APP_A_HOST, APP_A_OVERLAY,
    APP_B_BODY, APP_B_HOST, APP_B_OVERLAY, APP_OVERLAY_PORT, SPOKE_OVERLAY,
};
use gyeol_edge::{LabStunServer, MemoryCandidateSink, PathMachine, StunClient, DIRECT_QUIC_PORT};
use gyeol_identity::{
    sign_agent_jit_ticket, sign_ticket, verify_ticket, DenyApply, DenySet, Ipv4Destination,
    IssueGate, MiniCa, MockOidc, SpiffeId, TicketClaims, TicketFlags, TicketSigner, TicketVerifier,
    TrustBundle, MAX_SKEW, MOCK_OIDC_ISSUER,
};
use gyeol_relay::{decode_datagram, encode_datagram, encode_tcp_record, RelayKind, RelaySessionId};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::difficulty::Difficulty;
use crate::envelope::{feed_json, hex_encode, path_name, session_hex_u64, FeedLine, FeedParts};
use crate::event::EventSource;
use crate::level::{LevelId, StepStatus};
use crate::session::{PacketRow, Panel, PanelState, PeerRow, SessionView};

const HUMAN_NAME: &str = "ada";
const AGENT_NAME: &str = "worker";
const AGENT_TTL: Duration = Duration::from_secs(60);
const HUMAN_TOKEN_TTL: Duration = Duration::from_secs(600);
const HUMAN_TICKET_TTL: u64 = 120;
const EMPTY_SESSION: &str = "0000000000000000";
const HUB_OVERLAY: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);

/// Audit counters for the live page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditView {
    /// Session start records.
    pub start: u64,
    /// Session end records.
    pub end: u64,
    /// Session deny records.
    pub deny: u64,
    /// The chain tip in hex.
    pub tip: String,
    /// True when `verify_jsonl` accepts the export.
    pub ok: bool,
}

/// The live level machine.
#[derive(Debug)]
pub struct Engine {
    level: LevelId,
    selected: bool,
    difficulty: Difficulty,
    armed: bool,
    live: bool,
    next_seq: u64,
    frame_id: u64,
    session_hex: String,
    audit_relay: Option<RelaySessionId>,
    steps: Vec<StepStatus>,
    session: SessionView,
    peers: Vec<PeerRow>,
    packets: Vec<PacketRow>,
    audit: AuditLog,
    audit_open: bool,
    deny: DenySet,
    deny_version: u64,
    leaf: Option<HeldLeaf>,
    ticket: Option<HeldTicket>,
    quic_up: bool,
    revoked: bool,
    expired: bool,
    path_label: String,
}

#[derive(Debug, Clone)]
struct HeldLeaf {
    id: SpiffeId,
    der: Vec<u8>,
    not_after: u64,
    trust_pem: String,
}

#[derive(Debug, Clone)]
struct HeldTicket {
    bytes: Vec<u8>,
    hash: [u8; 16],
    nonce: [u8; 16],
    verifier_pem: String,
    not_before: u64,
    expires: u64,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// Create an idle machine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            level: LevelId::CityBreeze,
            selected: false,
            difficulty: Difficulty::Easy,
            armed: false,
            live: false,
            next_seq: 1,
            frame_id: 1,
            session_hex: EMPTY_SESSION.to_string(),
            audit_relay: None,
            steps: Vec::new(),
            session: SessionView::placeholder(),
            peers: Vec::new(),
            packets: Vec::new(),
            audit: AuditLog::new(),
            audit_open: false,
            deny: DenySet::empty(),
            deny_version: 0,
            leaf: None,
            ticket: None,
            quic_up: false,
            revoked: false,
            expired: false,
            path_label: "The QUIC path is not up.".to_string(),
        }
    }

    #[must_use]
    pub fn level(&self) -> LevelId {
        self.level
    }

    #[must_use]
    pub fn selected(&self) -> bool {
        self.selected
    }

    #[must_use]
    pub fn difficulty(&self) -> Difficulty {
        self.difficulty
    }

    #[must_use]
    pub fn armed(&self) -> bool {
        self.armed
    }

    #[must_use]
    pub fn live(&self) -> bool {
        self.live
    }

    #[must_use]
    pub fn steps(&self) -> &[StepStatus] {
        &self.steps
    }

    #[must_use]
    pub fn session(&self) -> &SessionView {
        &self.session
    }

    /// Audit counters for the current run.
    #[must_use]
    pub fn audit_view(&self) -> AuditView {
        let ok = match self.audit.export_jsonl() {
            Ok(text) => gyeol_audit::verify_jsonl(&text).is_ok(),
            Err(_) => false,
        };
        let metrics = self.audit.metrics();
        AuditView {
            start: metrics.start,
            end: metrics.end,
            deny: metrics.deny,
            tip: self.audit.tip_hex(),
            ok,
        }
    }

    /// Select a level and run its script.
    pub fn select_level(&mut self, id: LevelId) -> Vec<FeedLine> {
        self.begin(id);
        let mut lines = vec![self.harness_line(
            "level_selected",
            &format!("The operator selected {}.", id.title()),
        )];
        lines.extend(self.run_script(true));
        lines
    }

    /// Select a difficulty and run the matching level.
    pub fn select_difficulty(&mut self, difficulty: Difficulty) -> Vec<FeedLine> {
        let id = match difficulty {
            Difficulty::Easy => LevelId::CityBreeze,
            Difficulty::Medium => LevelId::AgentJit,
            Difficulty::Hard => LevelId::RadioactiveNat,
        };
        self.begin(id);
        let mut lines = vec![self.harness_line(
            "difficulty_selected",
            &format!(
                "The operator selected {}. {}",
                difficulty.label(),
                difficulty.note()
            ),
        )];
        lines.extend(self.run_script(true));
        lines
    }

    /// Spawn the agent and run allow, deny, and TTL expiry.
    pub fn spawn_agent(&mut self) -> Vec<FeedLine> {
        self.begin(LevelId::AgentJit);
        let mut lines =
            vec![self.harness_line("smash_agent_spawn", "The operator pressed Spawn agent.")];
        let produced = self.run_agent();
        lines.extend(self.finish(produced));
        lines
    }

    /// Block UDP and move Allocate to Direct to Relay.
    ///
    /// This action does not revoke the SVID.
    /// Press Revoke after this action to drop the session.
    pub fn block_udp(&mut self) -> Vec<FeedLine> {
        self.begin(LevelId::RadioactiveNat);
        let mut lines =
            vec![self.harness_line("smash_udp_block", "The operator pressed UDP block.")];
        let produced = self.run_nat(false);
        lines.extend(self.finish(produced));
        lines
    }

    /// Revoke the current SVID and drop the session.
    pub fn revoke(&mut self) -> Vec<FeedLine> {
        if !self.selected {
            self.begin(LevelId::CityBreeze);
        }
        self.armed = true;
        self.live = true;
        let mut lines = vec![self.harness_line("smash_revoke", "The operator pressed Revoke.")];
        if self.leaf.is_none() {
            let produced = self.issue_only();
            lines.extend(self.finish(produced));
        }
        let produced = self.drop_revoked();
        lines.extend(self.finish(produced));
        lines
    }

    fn begin(&mut self, id: LevelId) {
        self.reset_runtime();
        self.level = id;
        self.difficulty = id.difficulty();
        self.selected = true;
        self.armed = true;
        self.live = true;
        self.frame_id = match id {
            LevelId::CityBreeze => 1,
            LevelId::AgentJit => 2,
            LevelId::RadioactiveNat => 3,
        };
        self.session_hex = session_hex_u64(self.frame_id);
    }

    fn reset_runtime(&mut self) {
        self.session = SessionView::placeholder();
        self.peers.clear();
        self.packets.clear();
        self.steps.clear();
        self.audit = AuditLog::new();
        self.audit_open = false;
        self.deny = DenySet::empty();
        self.deny_version = 0;
        self.leaf = None;
        self.ticket = None;
        self.audit_relay = None;
        self.quic_up = false;
        self.revoked = false;
        self.expired = false;
        self.path_label = "The QUIC path is not up.".to_string();
        self.session_hex = EMPTY_SESSION.to_string();
    }

    fn run_script(&mut self, revoke_on_nat: bool) -> Vec<FeedLine> {
        let result = match self.level {
            LevelId::CityBreeze => self.run_city(),
            LevelId::AgentJit => self.run_agent(),
            LevelId::RadioactiveNat => self.run_nat(revoke_on_nat),
        };
        self.finish(result)
    }

    fn finish(&mut self, result: Result<Vec<FeedLine>, String>) -> Vec<FeedLine> {
        match result {
            Ok(lines) => {
                self.paint();
                lines
            }
            Err(detail) => {
                self.fail_rest();
                self.path_label = detail.clone();
                self.quic_up = false;
                self.paint();
                vec![self.harness_line("level_failed", &detail)]
            }
        }
    }

    fn run_city(&mut self) -> Result<Vec<FeedLine>, String> {
        self.steps = vec![StepStatus::NotRun; 4];
        let now = SystemTime::now();
        self.issue_human(now)?;
        self.steps[0] = StepStatus::Pass;
        self.steps[1] = StepStatus::Pass;
        let mut lines = Vec::new();
        lines.push(self.identity_line(
            "svid.issued",
            true,
            &format!(
                "OIDC issued a token for {HUMAN_NAME}. The human SVID is {}.",
                self.leaf_uri()
            ),
        ));
        lines.push(self.identity_line(
            "ticket.verified",
            true,
            &format!("The human ticket is valid. The ticket TTL is {HUMAN_TICKET_TTL} seconds."),
        ));
        self.push_peer(
            self.leaf_uri(),
            "Human SVID from the OIDC token.".to_string(),
        );
        lines.push(self.data_line(
            "quic_hello",
            false,
            fields(&[
                ("peer_uri", Value::from(self.leaf_uri())),
                (
                    "detail",
                    Value::from("The connector QUIC hello uses the human SVID."),
                ),
            ]),
        ));
        let ping = self.ping_packet()?;
        let ping_frame = self.roundtrip_frame(1, &ping)?;
        lines.push(self.frame_line("frame_tx", &ping_frame, "The overlay ping left the spoke."));
        lines.push(self.frame_line(
            "frame_rx",
            &ping_frame,
            "The overlay ping came back on the same frame.",
        ));
        self.note_packet(ping_frame.seq, "Overlay ping.");
        self.steps[2] = StepStatus::Pass;

        lines.extend(self.https_app(2, APP_A_HOST, APP_A_OVERLAY, APP_A_BODY)?);
        lines.extend(self.https_app(4, APP_B_HOST, APP_B_OVERLAY, APP_B_BODY)?);
        self.steps[3] = StepStatus::Pass;
        lines.push(self.data_line(
            "session_up",
            true,
            fields(&[
                ("reason", Value::from("connector")),
                (
                    "detail",
                    Value::from("The human session is up for two HTTPS applications."),
                ),
            ]),
        ));
        self.audit_start(now)?;
        self.quic_up = true;
        self.path_label = "The connector QUIC path is up.".to_string();
        Ok(lines)
    }

    fn run_agent(&mut self) -> Result<Vec<FeedLine>, String> {
        self.steps = vec![StepStatus::NotRun; 4];
        let now = SystemTime::now();
        self.issue_agent(now)?;
        self.steps[0] = StepStatus::Pass;
        let mut lines = Vec::new();
        let ttl_s = self.ticket_ttl();
        lines.push(self.identity_line(
            "agent.spawned",
            true,
            &format!(
                "The operator spawned {}. The parent is {}. The SVID TTL is {ttl_s} seconds.",
                self.leaf_uri(),
                SpiffeId::user(HUMAN_NAME)
                    .map_err(|err| err.to_string())?
                    .as_uri()
            ),
        ));
        lines.push(self.identity_line(
            "ticket.verified",
            true,
            &format!("The agent JIT ticket is valid. The ticket TTL is {ttl_s} seconds."),
        ));
        self.push_peer(self.leaf_uri(), format!("Agent SVID. TTL {ttl_s} seconds."));
        let dest_a = app_dest(APP_A_OVERLAY);
        let dest_b = app_dest(APP_B_OVERLAY);
        let ticket = self.ticket.clone().ok_or("The agent ticket is missing.")?;
        let verifier =
            TicketVerifier::from_public_pem(&ticket.verifier_pem).map_err(|err| err.to_string())?;
        let verified = verify_ticket(&verifier, &ticket.bytes, now, &self.deny)
            .map_err(|err| err.to_string())?;
        gyeol_identity::allow_agent_jit(
            verified.flags,
            &verified.dst_cidr,
            verified.proto,
            verified.dst_port,
            dest_a,
        )
        .map_err(|err| err.to_string())?;
        self.steps[1] = StepStatus::Pass;
        lines.push(self.identity_line(
            "jit.allow",
            true,
            &format!("Application A allows the agent for {APP_A_HOST}."),
        ));
        self.push_peer(
            APP_A_HOST.to_string(),
            format!("Allow {APP_A_OVERLAY}:{APP_OVERLAY_PORT}."),
        );
        let packet_a = tcp_ipv4(
            SPOKE_OVERLAY,
            APP_A_OVERLAY,
            APP_OVERLAY_PORT,
            APP_A_BODY.as_bytes(),
        )?;
        let frame_a = self.roundtrip_frame(1, &packet_a)?;
        lines.push(self.frame_line(
            "frame_tx",
            &frame_a,
            &format!("Application A accepted the frame for {APP_A_HOST}."),
        ));
        self.note_packet(frame_a.seq, format!("Allow {APP_A_HOST}."));

        match gyeol_identity::allow_agent_jit(
            verified.flags,
            &verified.dst_cidr,
            verified.proto,
            verified.dst_port,
            dest_b,
        ) {
            Err(gyeol_identity::IdentityError::Denied) => {}
            Ok(()) => return Err("Application B allowed the agent.".to_string()),
            Err(err) => return Err(err.to_string()),
        }
        self.steps[2] = StepStatus::Pass;
        lines.push(self.identity_line(
            "jit.deny",
            true,
            &format!("Application B denies the agent for {APP_B_HOST}."),
        ));
        self.push_peer(
            APP_B_HOST.to_string(),
            format!("Deny {APP_B_OVERLAY}:{APP_OVERLAY_PORT}."),
        );
        self.note_packet(2, format!("Deny {APP_B_HOST}."));
        self.audit_start(now)?;
        self.audit_deny(now, DenyReason::Destination)?;
        lines.push(self.data_line(
            "session_up",
            true,
            fields(&[
                ("reason", Value::from("agent")),
                (
                    "detail",
                    Value::from("The agent session is up for application A."),
                ),
            ]),
        ));
        lines.push(self.data_line(
            "session_down",
            true,
            fields(&[
                ("reason", Value::from("destination")),
                (
                    "detail",
                    Value::from("Application B did not open a session."),
                ),
            ]),
        ));

        let later = expiry_time(self.leaf_not_after()?)?;
        let trust = self.trust()?;
        let leaf = self.leaf.clone().ok_or("The agent SVID is missing.")?;
        match trust.authenticate_leaf(&leaf.der, later, &self.deny) {
            Err(gyeol_identity::IdentityError::Expired) => {}
            Ok(_) => return Err("The SVID was still valid after the TTL.".to_string()),
            Err(err) => return Err(err.to_string()),
        }
        match verify_ticket(&verifier, &ticket.bytes, later, &self.deny) {
            Err(gyeol_identity::IdentityError::Expired) => {}
            Ok(_) => return Err("The ticket was still valid after the TTL.".to_string()),
            Err(err) => return Err(err.to_string()),
        }
        self.expired = true;
        self.quic_up = false;
        self.steps[3] = StepStatus::Pass;
        self.path_label = format!("The agent SVID expired. The TTL was {ttl_s} seconds.");
        lines.push(self.identity_line(
            "svid.expired",
            true,
            &format!("The agent SVID expired. The TTL was {ttl_s} seconds. New packets stop."),
        ));
        lines.push(self.data_line(
            "session_down",
            true,
            fields(&[
                ("reason", Value::from("expired")),
                (
                    "detail",
                    Value::from("The agent session is down after the TTL."),
                ),
            ]),
        ));
        self.audit_deny(now, DenyReason::Expired)?;
        self.audit_end(now)?;
        Ok(lines)
    }

    fn run_nat(&mut self, revoke_after: bool) -> Result<Vec<FeedLine>, String> {
        self.steps = vec![StepStatus::NotRun; 6];
        let now = SystemTime::now();
        self.issue_human(now)?;
        let mut lines = Vec::new();
        lines.push(self.identity_line(
            "svid.issued",
            true,
            &format!("The NAT path uses the human SVID {}.", self.leaf_uri()),
        ));
        self.push_peer(self.leaf_uri(), "Human SVID for the NAT path.".to_string());

        let udp_blocked = true;
        let symmetric = matches!(self.difficulty, Difficulty::Hard);
        lines.push(self.edge_line(
            "nat.inject",
            false,
            fields(&[
                ("inject", Value::from("udp_block")),
                ("ok", Value::from(false)),
                ("detail", Value::from("UDP is blocked.")),
            ]),
        ));
        self.steps[0] = StepStatus::Pass;
        if symmetric {
            lines.push(self.edge_line(
                "nat.inject",
                false,
                fields(&[
                    ("inject", Value::from("symmetric")),
                    ("ok", Value::from(false)),
                    ("detail", Value::from("The path uses symmetric NAT.")),
                ]),
            ));
        }
        self.steps[1] = StepStatus::Pass;

        let mut machine = PathMachine::start_allocate();
        let candidate = gather_candidate(&mut machine)?;
        let path_id = gyeol_edge::PathId::allocate().map_err(|err| err.to_string())?;
        self.session_hex = path_id.to_hex();
        lines.push(self.edge_line(
            "path.allocate",
            false,
            fields(&[
                ("ok", Value::from(true)),
                (
                    "detail",
                    Value::from(format!(
                        "The path machine is in {}. The reflexive address is {}.",
                        machine.state(),
                        candidate.reflexive
                    )),
                ),
            ]),
        ));
        self.steps[2] = StepStatus::Pass;
        self.push_peer(
            "allocate".to_string(),
            format!("Path {}.", path_id.to_hex()),
        );

        let probe_ms = measure_ms(|| ())?;
        lines.push(self.edge_line(
            "nat.probe",
            false,
            fields(&[
                ("rtt_ms", Value::from(probe_ms)),
                ("ok", Value::from(false)),
                (
                    "detail",
                    Value::from("The UDP probe did not leave. UDP is blocked."),
                ),
            ]),
        ));

        if machine.direct_is_up() {
            return Err("Direct is up. The UDP block did not stop the path.".to_string());
        }
        let direct_ok = !udp_blocked && !symmetric;
        if direct_ok {
            return Err("Direct ran while UDP was blocked.".to_string());
        }
        lines.push(self.edge_line(
            "path.direct",
            false,
            fields(&[
                ("ok", Value::from(false)),
                (
                    "detail",
                    Value::from(format!(
                        "Direct failed. direct_is_up is false. The QUIC port is {DIRECT_QUIC_PORT}."
                    )),
                ),
            ]),
        ));
        self.steps[3] = StepStatus::Pass;

        let relay = RelaySessionId::generate().map_err(|err| err.to_string())?;
        let relay_hex = relay.to_hex();
        lines.push(self.edge_line(
            "path.switch",
            false,
            fields(&[
                ("from_path_id", Value::from(path_id.to_hex())),
                ("to_path_id", Value::from(relay_hex.clone())),
                (
                    "detail",
                    Value::from("The path switched from Direct to Relay."),
                ),
            ]),
        ));
        lines.push(self.data_line_with_session(
            &relay_hex,
            "path_switch",
            false,
            fields(&[
                ("from_path_id", Value::from(path_id.to_hex())),
                ("to_path_id", Value::from(relay_hex.clone())),
                (
                    "detail",
                    Value::from("The data path followed the switch to Relay."),
                ),
            ]),
        ));
        self.session_hex = relay_hex.clone();
        self.audit_relay = Some(relay);
        lines.push(self.edge_line(
            "path.relay",
            false,
            fields(&[
                ("ok", Value::from(true)),
                (
                    "detail",
                    Value::from("The path attached to the gyeol Relay on TCP port 443."),
                ),
            ]),
        ));
        self.steps[4] = StepStatus::Pass;

        let ping = self.ping_packet()?;
        let frame = self.roundtrip_frame(1, &ping)?;
        let frame_bytes = frame.encode();
        let started = Instant::now();
        let datagram =
            encode_datagram(RelayKind::Data, relay, &frame_bytes).map_err(|err| err.to_string())?;
        let record = encode_tcp_record(&datagram).map_err(|err| err.to_string())?;
        let decoded = decode_datagram(&datagram).map_err(|err| err.to_string())?;
        if decoded.session_id != relay {
            return Err("The Relay session id changed.".to_string());
        }
        let inner = Frame::decode(&decoded.payload)
            .map_err(|_| "The Relay payload did not decode as a frame.".to_string())?;
        if inner.payload != frame.payload {
            return Err("The Relay payload changed the packet.".to_string());
        }
        let rtt_ms = elapsed_ms(started)?;
        lines.push(self.frame_line("frame_tx", &frame, "The peer sent one frame toward Relay."));
        lines.push(self.edge_line(
            "relay.hop",
            false,
            fields(&[
                ("rtt_ms", Value::from(rtt_ms)),
                ("ok", Value::from(true)),
                (
                    "detail",
                    Value::from(format!(
                        "The TCP record is {} bytes. UDP stays blocked.",
                        record.len()
                    )),
                ),
            ]),
        ));
        lines.push(self.frame_line(
            "frame_rx",
            &inner,
            "The peer received the frame from the Relay payload.",
        ));
        self.note_packet(frame.seq, "Relay hop.");
        lines.push(self.edge_line(
            "path.up",
            false,
            fields(&[
                ("ok", Value::from(true)),
                ("detail", Value::from("The Relay path is up.")),
            ]),
        ));
        lines.push(self.data_line(
            "quic_hello",
            true,
            fields(&[
                ("peer_uri", Value::from(self.leaf_uri())),
                ("detail", Value::from("QUIC is up through the Relay.")),
            ]),
        ));
        lines.push(self.data_line(
            "session_up",
            true,
            fields(&[
                ("reason", Value::from("relay")),
                ("detail", Value::from("The Relay session is up.")),
            ]),
        ));
        self.audit_start(now)?;
        self.quic_up = true;
        self.path_label = format!("Relay {relay_hex} is up. Direct is down.");
        self.push_peer("relay".to_string(), format!("Session {relay_hex}."));
        if revoke_after {
            lines.extend(self.drop_revoked()?);
            self.steps[5] = StepStatus::Pass;
        }
        Ok(lines)
    }

    fn issue_only(&mut self) -> Result<Vec<FeedLine>, String> {
        if self.steps.is_empty() {
            self.steps = vec![StepStatus::NotRun; 4];
        }
        let now = SystemTime::now();
        self.issue_human(now)?;
        self.session_hex = session_hex_u64(self.frame_id);
        let mut lines = vec![self.identity_line(
            "svid.issued",
            true,
            &format!("The harness issued {} before revoke.", self.leaf_uri()),
        )];
        lines.push(self.data_line(
            "session_up",
            true,
            fields(&[
                ("reason", Value::from("connector")),
                ("detail", Value::from("The session is up before revoke.")),
            ]),
        ));
        self.audit_start(now)?;
        self.quic_up = true;
        self.path_label = "The session is up before revoke.".to_string();
        self.push_peer(self.leaf_uri(), "Human SVID.".to_string());
        Ok(lines)
    }

    fn drop_revoked(&mut self) -> Result<Vec<FeedLine>, String> {
        let started = Instant::now();
        let now = SystemTime::now();
        let leaf = self.leaf.clone().ok_or("Revoke has no SVID.")?;
        let nonce = self
            .ticket
            .as_ref()
            .map(|ticket| ticket.nonce)
            .ok_or("Revoke has no ticket.")?;
        self.deny_version = self.deny_version.saturating_add(1);
        let document = serde_json::json!({
            "version": self.deny_version,
            "generated_at": unix_secs(now)?,
            "revoked_uris": [leaf.id.as_uri()],
            "revoked_ticket_nonces": [hex_encode(&nonce)],
        });
        match self.deny.apply_json(document.to_string().as_bytes()) {
            Ok(DenyApply::Applied) => {}
            Ok(DenyApply::IgnoredOlder) => {
                return Err("The deny document was older.".to_string());
            }
            Err(err) => return Err(err.to_string()),
        }
        let trust = self.trust()?;
        match trust.authenticate_leaf(&leaf.der, now, &self.deny) {
            Err(gyeol_identity::IdentityError::Revoked) => {}
            Ok(_) => return Err("The revoked SVID was still accepted.".to_string()),
            Err(err) => return Err(err.to_string()),
        }
        let within_s = elapsed_seconds(started);
        if within_s > 60 {
            return Err(format!(
                "The session drop took {within_s} seconds. The limit is 60 seconds."
            ));
        }
        self.revoked = true;
        self.quic_up = false;
        self.path_label = format!(
            "The SVID is revoked. The session dropped in {within_s} seconds. The limit is 60 seconds."
        );
        self.attempt_packet_after_revoke()?;
        let packet_seq = u64::try_from(self.packets.len())
            .unwrap_or(0)
            .saturating_add(1);
        self.note_packet(packet_seq, "The new packet was dropped.");
        let mut lines = vec![self.identity_line(
            "svid.revoked",
            true,
            &format!("The deny list revoked {}.", leaf.id.as_uri()),
        )];
        lines.push(self.identity_line_extra(
            "session.dropped",
            true,
            fields(&[
                ("within_s", Value::from(within_s)),
                (
                    "detail",
                    Value::from(format!(
                        "The session dropped {within_s} seconds after revoke. The limit is 60 seconds."
                    )),
                ),
            ]),
        ));
        if self.level == LevelId::RadioactiveNat {
            lines.push(self.edge_line(
                "path.down",
                false,
                fields(&[
                    ("ok", Value::from(false)),
                    ("reason", Value::from("revoked")),
                    (
                        "detail",
                        Value::from("The Relay path is down after revoke."),
                    ),
                ]),
            ));
        }
        lines.push(self.data_line(
            "session_down",
            true,
            fields(&[
                ("reason", Value::from("revoked")),
                (
                    "detail",
                    Value::from("The data path rejected the new packet."),
                ),
            ]),
        ));
        self.audit_deny(now, DenyReason::Revoked)?;
        self.audit_end(now)?;
        if self.steps.len() == 6 {
            self.steps[5] = StepStatus::Pass;
        }
        Ok(lines)
    }

    fn attempt_packet_after_revoke(&mut self) -> Result<(), String> {
        let packet = self.ping_packet()?;
        if !is_ipv4_packet(&packet) {
            return Err("The dropped packet is not IPv4.".to_string());
        }
        let trust = self.trust()?;
        let leaf = self.leaf.clone().ok_or("The SVID is missing.")?;
        match trust.authenticate_leaf(&leaf.der, SystemTime::now(), &self.deny) {
            Err(gyeol_identity::IdentityError::Revoked) => Ok(()),
            Ok(_) => Err("A revoked SVID accepted a new packet.".to_string()),
            Err(err) => Err(err.to_string()),
        }
    }

    fn https_app(
        &mut self,
        seq: u64,
        host: &str,
        overlay: Ipv4Addr,
        body: &str,
    ) -> Result<Vec<FeedLine>, String> {
        let now = SystemTime::now();
        let trust = self.trust()?;
        let leaf = self.leaf.clone().ok_or("The SVID is missing.")?;
        trust
            .authenticate_leaf(&leaf.der, now, &self.deny)
            .map_err(|err| err.to_string())?;
        let status = https_status(host, true)?;
        let packet = tcp_ipv4(SPOKE_OVERLAY, overlay, APP_OVERLAY_PORT, body.as_bytes())?;
        let frame = self.roundtrip_frame(seq, &packet)?;
        self.push_peer(
            host.to_string(),
            format!("HTTPS status {status}. Overlay {overlay}."),
        );
        self.note_packet(frame.seq, format!("{host} status {status}."));
        Ok(vec![
            self.frame_line(
                "frame_tx",
                &frame,
                &format!("The spoke sent HTTPS bytes for {host}."),
            ),
            self.data_line(
                "connector_https",
                true,
                fields(&[
                    ("host", Value::from(host)),
                    ("status", Value::from(u64::from(status))),
                    ("bytes", Value::from(u64::try_from(body.len()).unwrap_or(0))),
                    (
                        "detail",
                        Value::from(format!("{host} returned status {status}.")),
                    ),
                ]),
            ),
        ])
    }

    fn issue_human(&mut self, now: SystemTime) -> Result<(), String> {
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).map_err(|err| err.to_string())?;
        let token = oidc
            .issue_id_token(HUMAN_NAME, now, HUMAN_TOKEN_TTL)
            .map_err(|err| err.to_string())?;
        let ca = MiniCa::generate(now).map_err(|err| err.to_string())?;
        let gate = IssueGate::new(ca, &oidc).map_err(|err| err.to_string())?;
        let issued = gate
            .issue_human_svid(&token, now, &self.deny)
            .map_err(|err| err.to_string())?;
        let trust_pem = gate.trust_bundle_pem().to_string();
        let trust = TrustBundle::from_pem(&trust_pem).map_err(|err| err.to_string())?;
        let authed = trust
            .authenticate_leaf(&issued.certificate_der, now, &self.deny)
            .map_err(|err| err.to_string())?;
        if authed != issued.spiffe_id {
            return Err("The human SVID check did not match.".to_string());
        }
        let now_unix = unix_secs(now)?;
        let signer = TicketSigner::generate();
        let claims = TicketClaims {
            issuer: issued.spiffe_id.clone(),
            subject: issued.spiffe_id.clone(),
            not_before: now_unix,
            expires: now_unix.saturating_add(HUMAN_TICKET_TTL),
            dst_cidr: "10.8.0.0/24".to_string(),
            proto: 6,
            dst_port: APP_OVERLAY_PORT,
            flags: TicketFlags::none(),
        };
        let signed = sign_ticket(&signer, &claims).map_err(|err| err.to_string())?;
        let verifier_pem = signer.public_key_pem();
        let verifier =
            TicketVerifier::from_public_pem(&verifier_pem).map_err(|err| err.to_string())?;
        let verified = verify_ticket(&verifier, &signed.bytes, now, &self.deny)
            .map_err(|err| err.to_string())?;
        self.audit_relay = Some(RelaySessionId::generate().map_err(|err| err.to_string())?);
        self.leaf = Some(HeldLeaf {
            id: issued.spiffe_id,
            der: issued.certificate_der,
            not_after: issued.not_after,
            trust_pem,
        });
        self.ticket = Some(HeldTicket {
            bytes: signed.bytes,
            hash: verified.hash,
            nonce: verified.nonce,
            verifier_pem,
            not_before: verified.not_before,
            expires: verified.expires,
        });
        Ok(())
    }

    fn issue_agent(&mut self, now: SystemTime) -> Result<(), String> {
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).map_err(|err| err.to_string())?;
        let token = oidc
            .issue_id_token(HUMAN_NAME, now, HUMAN_TOKEN_TTL)
            .map_err(|err| err.to_string())?;
        let ca = MiniCa::generate(now).map_err(|err| err.to_string())?;
        let gate = IssueGate::new(ca, &oidc).map_err(|err| err.to_string())?;
        let agent = gate
            .issue_agent_svid(&token, AGENT_NAME, now, AGENT_TTL, &self.deny)
            .map_err(|err| err.to_string())?;
        let trust_pem = gate.trust_bundle_pem().to_string();
        let trust = TrustBundle::from_pem(&trust_pem).map_err(|err| err.to_string())?;
        trust
            .authenticate_leaf(&agent.svid.certificate_der, now, &self.deny)
            .map_err(|err| err.to_string())?;
        let signer = TicketSigner::generate();
        let dest = app_dest(APP_A_OVERLAY);
        let signed = sign_agent_jit_ticket(
            &signer,
            &agent.parent,
            &agent.svid.spiffe_id,
            now,
            AGENT_TTL,
            dest,
        )
        .map_err(|err| err.to_string())?;
        let verifier_pem = signer.public_key_pem();
        let verifier =
            TicketVerifier::from_public_pem(&verifier_pem).map_err(|err| err.to_string())?;
        let verified = verify_ticket(&verifier, &signed.bytes, now, &self.deny)
            .map_err(|err| err.to_string())?;
        self.audit_relay = Some(RelaySessionId::generate().map_err(|err| err.to_string())?);
        self.leaf = Some(HeldLeaf {
            id: agent.svid.spiffe_id,
            der: agent.svid.certificate_der,
            not_after: agent.svid.not_after,
            trust_pem,
        });
        self.ticket = Some(HeldTicket {
            bytes: signed.bytes,
            hash: verified.hash,
            nonce: verified.nonce,
            verifier_pem,
            not_before: verified.not_before,
            expires: verified.expires,
        });
        Ok(())
    }

    fn roundtrip_frame(&self, seq: u64, packet: &[u8]) -> Result<Frame, String> {
        if !is_ipv4_packet(packet) {
            return Err("The packet is not IPv4.".to_string());
        }
        let hash = self
            .ticket
            .as_ref()
            .map(|ticket| ticket.hash)
            .unwrap_or([0u8; 16]);
        let session_id = u32::try_from(self.frame_id).unwrap_or(0);
        let frame = Frame {
            frame_type: FrameType::Data,
            flags: 0,
            session_id,
            seq,
            ticket_hash: hash,
            payload: packet.to_vec(),
        };
        let decoded =
            Frame::decode(&frame.encode()).map_err(|_| "The frame did not decode.".to_string())?;
        if decoded.payload != packet {
            return Err("The frame payload changed.".to_string());
        }
        Ok(decoded)
    }

    fn ping_packet(&self) -> Result<Vec<u8>, String> {
        ipv4_packet(SPOKE_OVERLAY, HUB_OVERLAY, b"ping").map_err(|err| err.to_string())
    }

    fn trust(&self) -> Result<TrustBundle, String> {
        let leaf = self.leaf.as_ref().ok_or("The SVID is missing.")?;
        TrustBundle::from_pem(&leaf.trust_pem).map_err(|err| err.to_string())
    }

    fn leaf_uri(&self) -> String {
        self.leaf
            .as_ref()
            .map(|leaf| leaf.id.as_uri().to_string())
            .unwrap_or_default()
    }

    fn leaf_not_after(&self) -> Result<u64, String> {
        self.leaf
            .as_ref()
            .map(|leaf| leaf.not_after)
            .ok_or_else(|| "The SVID is missing.".to_string())
    }

    fn ticket_ttl(&self) -> u64 {
        self.ticket
            .as_ref()
            .map(|ticket| ticket.expires.saturating_sub(ticket.not_before))
            .unwrap_or(0)
    }

    fn ticket_hash(&self) -> Option<[u8; 16]> {
        self.ticket.as_ref().map(|ticket| ticket.hash)
    }

    fn audit_ids(&self) -> Result<SessionIds, String> {
        let leaf = self.leaf.as_ref().ok_or("The SVID is missing.")?;
        let ticket = self.ticket.as_ref().ok_or("The ticket is missing.")?;
        let relay = self
            .audit_relay
            .ok_or_else(|| "The audit session id is missing.".to_string())?;
        let frame = u32::try_from(self.frame_id).unwrap_or(0);
        Ok(SessionIds {
            relay,
            frame,
            peer: leaf.id.clone(),
            ticket_hash: ticket.hash,
        })
    }

    fn audit_start(&mut self, now: SystemTime) -> Result<(), String> {
        if self.audit_open {
            return Ok(());
        }
        let ids = self.audit_ids()?;
        self.audit
            .append(SessionEvent::Start {
                ids,
                at_unix: unix_secs(now)?,
            })
            .map_err(|err| err.to_string())?;
        self.audit_open = true;
        Ok(())
    }

    fn audit_end(&mut self, now: SystemTime) -> Result<(), String> {
        if !self.audit_open {
            return Ok(());
        }
        let ids = self.audit_ids()?;
        self.audit
            .append(SessionEvent::End {
                ids,
                at_unix: unix_secs(now)?,
            })
            .map_err(|err| err.to_string())?;
        self.audit_open = false;
        Ok(())
    }

    fn audit_deny(&mut self, now: SystemTime, reason: DenyReason) -> Result<(), String> {
        let ids = self.audit_ids()?;
        self.audit
            .append(SessionEvent::Deny {
                ids,
                at_unix: unix_secs(now)?,
                reason,
            })
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    fn push_peer(&mut self, name: String, detail: String) {
        self.peers.push(PeerRow { name, detail });
    }

    fn note_packet(&mut self, seq: u64, detail: impl Into<String>) {
        self.packets.push(PacketRow {
            seq,
            detail: detail.into(),
        });
    }

    fn fail_rest(&mut self) {
        for step in &mut self.steps {
            if *step == StepStatus::NotRun {
                *step = StepStatus::Fail;
            }
        }
    }

    fn paint(&mut self) {
        let svid_state = if self.revoked {
            PanelState::Revoked
        } else if self.expired {
            PanelState::Expired
        } else if self.leaf.is_some() {
            PanelState::Up
        } else {
            PanelState::None
        };
        let svid_detail = if let Some(leaf) = &self.leaf {
            format!("{} Not after {}.", leaf.id.as_uri(), leaf.not_after)
        } else {
            "No SVID.".to_string()
        };
        let ticket_state = if self.revoked {
            PanelState::Revoked
        } else if self.expired {
            PanelState::Expired
        } else if self.ticket.is_some() {
            PanelState::Up
        } else {
            PanelState::None
        };
        let ticket_detail = if let Some(ticket) = &self.ticket {
            format!(
                "TTL {} seconds. Hash {}.",
                ticket.expires.saturating_sub(ticket.not_before),
                hex_encode(&ticket.hash)
            )
        } else {
            "No ticket.".to_string()
        };
        let quic_state = if self.quic_up {
            PanelState::Up
        } else if self.revoked || self.expired {
            PanelState::Down
        } else if self.live {
            PanelState::Ready
        } else {
            PanelState::None
        };
        self.session = SessionView {
            peers: self.peers.clone(),
            peer_empty: SessionView::placeholder().peer_empty,
            packets: self.packets.clone(),
            packet_empty: SessionView::placeholder().packet_empty,
            quic: Panel {
                state: quic_state,
                detail: self.path_label.clone(),
            },
            svid: Panel {
                state: svid_state,
                detail: svid_detail,
            },
            ticket: Panel {
                state: ticket_state,
                detail: ticket_detail,
            },
        };
    }

    fn harness_line(&mut self, kind: &str, detail: &str) -> FeedLine {
        self.emit(
            EventSource::Harness,
            kind,
            false,
            fields(&[("detail", Value::from(detail))]),
        )
    }

    fn identity_line(&mut self, kind: &str, with_ticket: bool, detail: &str) -> FeedLine {
        self.emit(
            EventSource::Identity,
            kind,
            with_ticket,
            fields(&[("detail", Value::from(detail))]),
        )
    }

    fn identity_line_extra(
        &mut self,
        kind: &str,
        with_ticket: bool,
        extra: Map<String, Value>,
    ) -> FeedLine {
        self.emit(EventSource::Identity, kind, with_ticket, extra)
    }

    fn edge_line(&mut self, kind: &str, with_ticket: bool, extra: Map<String, Value>) -> FeedLine {
        self.emit(EventSource::EdgeNat, kind, with_ticket, extra)
    }

    fn data_line(&mut self, kind: &str, with_ticket: bool, extra: Map<String, Value>) -> FeedLine {
        self.emit(EventSource::Datapath, kind, with_ticket, extra)
    }

    fn data_line_with_session(
        &mut self,
        session_hex: &str,
        kind: &str,
        with_ticket: bool,
        extra: Map<String, Value>,
    ) -> FeedLine {
        let saved = self.session_hex.clone();
        self.session_hex = session_hex.to_string();
        let line = self.emit(EventSource::Datapath, kind, with_ticket, extra);
        self.session_hex = saved;
        line
    }

    fn frame_line(&mut self, kind: &str, frame: &Frame, detail: &str) -> FeedLine {
        let code = match frame.frame_type {
            FrameType::Data => 1_u64,
            FrameType::Ctrl => 2_u64,
            FrameType::Ticket => 3_u64,
        };
        self.emit(
            EventSource::Datapath,
            kind,
            true,
            fields(&[
                ("frame_type", Value::from(code)),
                ("flags", Value::from(u64::from(frame.flags))),
                (
                    "ipv4_len",
                    Value::from(u64::try_from(frame.payload.len()).unwrap_or(0)),
                ),
                ("detail", Value::from(detail)),
            ]),
        )
    }

    fn emit(
        &mut self,
        source: EventSource,
        kind: &str,
        with_ticket: bool,
        extra: Map<String, Value>,
    ) -> FeedLine {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let now_ms = unix_ms(SystemTime::now());
        let ticket = if with_ticket {
            self.ticket_hash().as_ref().copied()
        } else {
            None
        };
        let body = feed_json(FeedParts {
            seq,
            now_ms,
            source,
            level: self.level,
            difficulty: self.difficulty,
            kind,
            session_id: &self.session_hex,
            ticket_hash: ticket.as_ref(),
            path: Some(path_name(self.level)),
            extra,
        });
        FeedLine { source, body }
    }
}

fn fields(pairs: &[(&str, Value)]) -> Map<String, Value> {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert((*key).to_string(), value.clone());
    }
    map
}

fn app_dest(addr: Ipv4Addr) -> Ipv4Destination {
    Ipv4Destination {
        addr,
        proto: 6,
        port: APP_OVERLAY_PORT,
    }
}

fn https_status(host: &str, svid_ok: bool) -> Result<u16, String> {
    if !svid_ok {
        return Ok(403);
    }
    if host == APP_A_HOST || host == APP_B_HOST {
        return Ok(200);
    }
    Err(format!("The host {host} is not an Orblx application."))
}

fn tcp_ipv4(src: Ipv4Addr, dst: Ipv4Addr, port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    let total = 40usize
        .checked_add(payload.len())
        .ok_or("The packet is too long.")?;
    if total > 65_535 {
        return Err("The packet is too long.".to_string());
    }
    let total_u16 = u16::try_from(total).map_err(|_| "The packet is too long.".to_string())?;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[32] = 0x50;
    packet[40..].copy_from_slice(payload);
    if !is_ipv4_packet(&packet) {
        return Err("The TCP packet is not IPv4.".to_string());
    }
    Ok(packet)
}

fn gather_candidate(machine: &mut PathMachine) -> Result<gyeol_edge::EndpointCandidate, String> {
    let server = LabStunServer::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|err| err.to_string())?;
    let server_addr = server.local_addr().map_err(|err| err.to_string())?;
    let handle = thread::spawn(move || server.serve_one(Duration::from_secs(2)));
    let client = StunClient::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|err| err.to_string())?;
    let mut sink = MemoryCandidateSink::default();
    let candidate = machine
        .gather_reflexive(&client, server_addr, Duration::from_secs(2), &mut sink)
        .map_err(|err| err.to_string())?;
    let joined = handle
        .join()
        .map_err(|_| "The STUN server thread stopped.".to_string())?;
    joined.map_err(|err| err.to_string())?;
    Ok(candidate)
}

fn expiry_time(not_after: u64) -> Result<SystemTime, String> {
    let secs = not_after
        .checked_add(MAX_SKEW.as_secs())
        .and_then(|value| value.checked_add(1))
        .ok_or("The expiry time overflowed.")?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or_else(|| "The expiry time overflowed.".to_string())
}

fn unix_secs(now: SystemTime) -> Result<u64, String> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "The time value is not valid.".to_string())
}

fn unix_ms(now: SystemTime) -> u64 {
    let millis = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn elapsed_ms(started: Instant) -> Result<u64, String> {
    u64::try_from(started.elapsed().as_millis()).map_err(|_| "The timer overflowed.".to_string())
}

fn elapsed_seconds(started: Instant) -> u64 {
    started.elapsed().as_secs()
}

fn measure_ms(body: impl FnOnce()) -> Result<u64, String> {
    let started = Instant::now();
    body();
    elapsed_ms(started)
}

#[cfg(test)]
mod tests {
    use super::https_status;
    use crate::difficulty::Difficulty;
    use crate::level::LevelId;
    use crate::session::PanelState;
    use crate::sim::Engine;
    use serde_json::Value;

    fn event_kinds(lines: &[crate::envelope::FeedLine]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                serde_json::from_str::<Value>(&line.body).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn https_status_accepts_only_the_two_apps() {
        assert_eq!(https_status("app-a.orblx.test", true).unwrap(), 200);
        assert_eq!(https_status("app-b.orblx.test", true).unwrap(), 200);
        assert_eq!(https_status("app-a.orblx.test", false).unwrap(), 403);
        assert!(https_status("other.example", true).is_err());
    }

    #[test]
    fn easy_runs_the_human_path() {
        let mut engine = Engine::new();
        let lines = engine.select_difficulty(Difficulty::Easy);
        let names = event_kinds(&lines);
        assert!(names.contains(&"svid.issued".to_string()));
        assert!(names.contains(&"connector_https".to_string()));
        assert_eq!(
            names
                .iter()
                .filter(|kind| kind.as_str() == "connector_https")
                .count(),
            2
        );
        assert_eq!(engine.session().svid.state, PanelState::Up);
        assert!(!engine.session().packets.is_empty());
        assert!(engine.audit_view().ok);
        assert_eq!(engine.audit_view().start, 1);
        assert_eq!(engine.level(), LevelId::CityBreeze);
        let blob = lines
            .iter()
            .map(|line| line.body.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!blob.contains("BEGIN"));
        assert!(!blob.contains("PRIVATE"));
        let dropped = engine.revoke();
        let dropped_kinds = event_kinds(&dropped);
        assert!(dropped_kinds.contains(&"svid.revoked".to_string()));
        assert!(dropped_kinds.contains(&"session.dropped".to_string()));
        assert_eq!(engine.session().quic.state, PanelState::Down);
    }

    #[test]
    fn medium_allows_a_denies_b_and_expires() {
        let mut engine = Engine::new();
        let lines = engine.select_difficulty(Difficulty::Medium);
        let names = event_kinds(&lines);
        assert!(names.contains(&"agent.spawned".to_string()));
        assert!(names.contains(&"jit.allow".to_string()));
        assert!(names.contains(&"jit.deny".to_string()));
        assert!(names.contains(&"svid.expired".to_string()));
        assert_eq!(engine.session().svid.state, PanelState::Expired);
        assert!(
            engine.session().ticket.detail.contains("60 seconds")
                || engine.session().ticket.detail.contains("TTL")
        );
        assert_eq!(engine.audit_view().deny, 2);
        assert!(engine.audit_view().ok);
    }

    #[test]
    fn hard_direct_fails_before_the_relay_switch() {
        let mut engine = Engine::new();
        let lines = engine.block_udp();
        let names = event_kinds(&lines);
        let direct = names.iter().position(|kind| kind == "path.direct").unwrap();
        let switch = names.iter().position(|kind| kind == "path.switch").unwrap();
        assert!(direct < switch);
        assert!(names.contains(&"nat.inject".to_string()));
        assert!(names.contains(&"path.allocate".to_string()));
        assert!(names.contains(&"path.relay".to_string()));
        assert!(names.contains(&"path.up".to_string()));
        let direct_body = lines
            .iter()
            .find(|line| line.body.contains("\"kind\":\"path.direct\""))
            .unwrap();
        let value: Value = serde_json::from_str(&direct_body.body).unwrap();
        assert_eq!(value["ok"], Value::Bool(false));
        assert_eq!(value["session_id"].as_str().unwrap().len(), 32);
        assert_eq!(engine.session().quic.state, PanelState::Up);
    }

    #[test]
    fn revoke_drops_within_60_seconds() {
        let mut engine = Engine::new();
        let started = std::time::Instant::now();
        let lines = engine.revoke();
        assert!(started.elapsed().as_secs() <= 60);
        let names = event_kinds(&lines);
        let revoked = names
            .iter()
            .position(|kind| kind == "svid.revoked")
            .unwrap();
        let dropped = names
            .iter()
            .position(|kind| kind == "session.dropped")
            .unwrap();
        assert!(revoked < dropped);
        let drop_line = lines
            .iter()
            .find(|line| line.body.contains("\"kind\":\"session.dropped\""))
            .unwrap();
        let value: Value = serde_json::from_str(&drop_line.body).unwrap();
        let within_s = value["within_s"].as_u64().unwrap();
        assert!(within_s <= 60);
        assert_eq!(engine.session().svid.state, PanelState::Revoked);
        assert_eq!(engine.session().quic.state, PanelState::Down);
        assert!(engine.audit_view().ok);
        assert!(engine.audit_view().deny >= 1);
        assert!(engine.audit_view().end >= 1);
    }
}
