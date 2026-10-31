//! The grant guard on the target node.
//!
//! The guard listens on `overlay:port` for one service.
//! Each new connection sends one proof line first.
//! The guard checks the line, then forwards the connection to the local service.
//! A poll thread fetches the deny document. The guard refuses every new
//! connection when the last good deny fetch is older than `stale_after`.
//! The guard writes grant, use, deny, expire, and revoke records to a hash chain.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use orblx_audit::{sha256_digest, ConfigAction, ConfigEvent, ConfigLog, EMPTY_DIGEST};
use orblx_identity::{DenySet, SpiffeId, TicketVerifier, TrustBundle};

use crate::grant::AgentGrant;
use crate::hex::encode_hex;
use crate::nonce_store::{NonceStore, SeenSet};
use crate::proof::{
    open_use, unix_millis, Admitted, Refused, UseTarget, UseTrust, PROOF_WINDOW_SECS,
};
use crate::AgentError;

const MAX_LINE: usize = 32 * 1024;
const LINE_TIMEOUT: Duration = Duration::from_secs(5);
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// A function that returns the current deny document text.
pub type DenyFetch = Box<dyn Fn() -> Result<String, String> + Send + 'static>;

/// Guard settings.
pub struct GuardConfig {
    /// Overlay listen address. The port is the service port.
    pub listen: SocketAddr,
    /// Service name.
    pub service: String,
    /// Local service address.
    pub target: SocketAddr,
    /// SPIFFE ID of this node.
    pub node: SpiffeId,
    /// SVID trust bundle.
    pub bundle: TrustBundle,
    /// Coordinator ticket key.
    pub verifier: TicketVerifier,
    /// Coordinator netmap key.
    pub netmap_public: [u8; 32],
    /// Grant audit chain file.
    pub audit_path: PathBuf,
    /// Request nonce file, apart from the audit chain file.
    ///
    /// The HTTP gateway uses it. `None` for the TCP guard, which has no
    /// request nonce. [`crate::run_gateway`] uses
    /// [`crate::default_nonce_path`] when it is `None`.
    pub nonce_path: Option<PathBuf>,
    /// Deny poll interval.
    pub poll: Duration,
    /// The guard refuses all uses when the last good deny fetch is older.
    pub stale_after: Duration,
}

impl std::fmt::Debug for GuardConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuardConfig")
            .field("listen", &self.listen)
            .field("service", &self.service)
            .field("node", &self.node)
            .finish()
    }
}

/// One guard decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    /// The use is admitted.
    Admit(Box<Admitted>),
    /// The use is refused. The text is the stable reason token.
    Refuse(&'static str),
}

struct Known {
    agent: SpiffeId,
    nonce: [u8; 16],
    expires_ms: u64,
    expired: bool,
    revoked: bool,
}

struct CoreState {
    deny: DenySet,
    deny_ok_at: Option<SystemTime>,
    audit: ConfigLog,
    known: BTreeMap<String, Known>,
    /// Seen request nonces: (ticket hash, nonce) to the proof stamp.
    seen: SeenSet,
    /// The nonce file. Each new entry goes to it before the request is admitted.
    nonces: Option<NonceStore>,
}

/// Extra checks for one request after the proof check.
///
/// The HTTP gateway uses this for the path scope and the replay check.
pub struct RequestCheck<'a> {
    /// The request nonce. The core refuses a second use with `replay`.
    pub nonce: Option<[u8; 16]>,
    /// The scope check. It returns the reason token on failure.
    pub scope: &'a dyn Fn(&AgentGrant) -> Result<(), &'static str>,
    /// Text for the audit detail and the log, for example the method and the path.
    /// It must not hold a token.
    pub note: &'a str,
}

/// Shared guard checks and the grant audit chain.
///
/// The TCP guard and an HTTP gateway use the same core.
pub struct GuardCore {
    node: SpiffeId,
    addr: Ipv4Addr,
    bundle: TrustBundle,
    verifier: TicketVerifier,
    netmap_public: [u8; 32],
    stale_after: Duration,
    state: Mutex<CoreState>,
}

impl GuardCore {
    /// Open the core and the audit chain.
    pub fn new(config: &GuardConfig) -> Result<Self, AgentError> {
        let IpAddr::V4(addr) = config.listen.ip() else {
            return Err(AgentError::Io(
                "The listen address is not IPv4.".to_string(),
            ));
        };
        // `open` checks the chain. A broken chain stops the start (fail closed).
        let audit = ConfigLog::open(&config.audit_path)
            .map_err(|err| AgentError::Audit(err.to_string()))?;
        let now = SystemTime::now();
        let mut seen = load_seen(&config.audit_path, now)?;
        let nonces = match &config.nonce_path {
            Some(path) => {
                let now_secs = now
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| AgentError::Time)?
                    .as_secs();
                let keep_after = now_secs.saturating_sub(2 * PROOF_WINDOW_SECS);
                let (store, stored) = NonceStore::open(path, keep_after)?;
                for (key, stamp) in stored {
                    seen.entry(key).or_insert(stamp);
                }
                Some(store)
            }
            None => None,
        };
        Ok(Self {
            node: config.node.clone(),
            addr,
            bundle: config.bundle.clone(),
            verifier: config.verifier.clone(),
            netmap_public: config.netmap_public,
            stale_after: config.stale_after,
            state: Mutex::new(CoreState {
                deny: DenySet::empty(),
                deny_ok_at: None,
                audit,
                known: BTreeMap::new(),
                seen,
                nonces,
            }),
        })
    }

    /// The number of request nonces that the core knows.
    pub fn seen_count(&self) -> usize {
        self.lock().map_or(0, |state| state.seen.len())
    }

    /// Apply one deny document and record revoked grants.
    pub fn apply_deny(&self, text: &str, now: SystemTime) -> Result<(), AgentError> {
        let mut state = self.lock()?;
        let _ = state
            .deny
            .apply_json(text.as_bytes())
            .map_err(|_| AgentError::Io("The deny document is not valid.".to_string()))?;
        state.deny_ok_at = Some(now);
        let version = state.deny.version().unwrap_or(0);
        let mut revoked = Vec::new();
        for (id, known) in &state.known {
            // An ended grant cannot be used, so a later deny entry does not revoke it.
            if known.revoked || known.expired {
                continue;
            }
            if state.deny.reject_uri(&known.agent).is_err()
                || state.deny.reject_nonce(&known.nonce).is_err()
            {
                revoked.push(id.clone());
            }
        }
        let at_ms = unix_millis(now)?;
        for id in revoked {
            if let Some(known) = state.known.get_mut(&id) {
                known.revoked = true;
            }
            let detail = format!("deny_version {version} seen_ms {at_ms}");
            let actor = self.node.as_uri().to_string();
            append(
                &mut state,
                &actor,
                ConfigAction::AgentRevoke,
                &id,
                EMPTY_DIGEST,
                &detail,
            )?;
            println!("agent grant {id} revoked deny_version {version} seen_ms {at_ms}");
        }
        Ok(())
    }

    /// Record grants that reached their end time.
    pub fn tick(&self, now: SystemTime) -> Result<(), AgentError> {
        let at_ms = unix_millis(now)?;
        let mut state = self.lock()?;
        let mut ended = Vec::new();
        for (id, known) in &state.known {
            if !known.expired && at_ms >= known.expires_ms {
                ended.push(id.clone());
            }
        }
        for id in ended {
            let expires_ms = match state.known.get_mut(&id) {
                Some(known) => {
                    known.expired = true;
                    known.expires_ms
                }
                None => continue,
            };
            let detail = format!("expires_ms {expires_ms} seen_ms {at_ms}");
            let actor = self.node.as_uri().to_string();
            append(
                &mut state,
                &actor,
                ConfigAction::AgentExpire,
                &id,
                EMPTY_DIGEST,
                &detail,
            )?;
            println!("agent grant {id} expired expires_ms {expires_ms} seen_ms {at_ms}");
        }
        Ok(())
    }

    /// Check one proof line and record the decision.
    ///
    /// `peer` is the remote socket address. It goes to the audit record.
    pub fn admit(
        &self,
        line: &str,
        service: &str,
        port: u16,
        extra: &[u8],
        peer: SocketAddr,
        now: SystemTime,
    ) -> Result<GuardDecision, AgentError> {
        let scope = |_: &AgentGrant| Ok(());
        let check = RequestCheck {
            nonce: None,
            scope: &scope,
            note: "",
        };
        self.admit_request(line, service, port, extra, &check, peer, now)
    }

    /// Check one proof line, then the request checks, and record the decision.
    ///
    /// The order is: deny freshness, proof, replay, scope.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_request(
        &self,
        line: &str,
        service: &str,
        port: u16,
        extra: &[u8],
        check: &RequestCheck<'_>,
        peer: SocketAddr,
        now: SystemTime,
    ) -> Result<GuardDecision, AgentError> {
        let note = if check.note.is_empty() {
            String::new()
        } else {
            format!(" {}", check.note)
        };
        let mut state = self.lock()?;
        let fresh = state
            .deny_ok_at
            .and_then(|at| now.duration_since(at).ok())
            .is_some_and(|age| age <= self.stale_after);
        let at_ms = unix_millis(now)?;
        if !fresh {
            let detail = format!(
                "reason stale service {service} port {port}{note} peer {peer} at_ms {at_ms}"
            );
            append(
                &mut state,
                "unknown",
                ConfigAction::AgentDeny,
                "none",
                EMPTY_DIGEST,
                &detail,
            )?;
            println!("agent deny reason stale service {service} port {port}{note} at_ms {at_ms}");
            return Ok(GuardDecision::Refuse("stale"));
        }
        let target = UseTarget {
            node: &self.node,
            addr: self.addr,
            service,
            port,
        };
        let trust = UseTrust {
            bundle: &self.bundle,
            verifier: &self.verifier,
            netmap_public: &self.netmap_public,
            deny: &state.deny,
        };
        let opened = open_use(line, target, trust, extra, now);
        let opened = match opened {
            Ok(admitted) => match self.request_checks(&mut state, &admitted, check, now) {
                Ok(()) => Ok(admitted),
                Err(reason) => {
                    // The grant is valid, so the core knows it for expiry and revoke.
                    self.note_grant(&mut state, &admitted.grant, admitted.nonce, &admitted.agent)?;
                    let actor = admitted.agent.as_uri().to_string();
                    let detail = format!(
                        "reason {reason} service {service} port {port}{note} peer {peer} at_ms {at_ms}"
                    );
                    append(
                        &mut state,
                        &actor,
                        ConfigAction::AgentDeny,
                        &admitted.grant.id,
                        EMPTY_DIGEST,
                        &detail,
                    )?;
                    println!(
                        "agent deny reason {reason} grant {} service {service} port {port}{note} at_ms {at_ms}",
                        admitted.grant.id
                    );
                    return Ok(GuardDecision::Refuse(reason));
                }
            },
            Err(refused) => Err(refused),
        };
        match opened {
            Ok(admitted) => {
                self.note_grant(&mut state, &admitted.grant, admitted.nonce, &admitted.agent)?;
                let detail = format!(
                    "service {service} port {port}{note} peer {peer} ticket_hash {}{} at_ms {at_ms}",
                    encode_hex(&admitted.ticket_hash),
                    check
                        .nonce
                        .map(|nonce| format!(
                            " nonce {} stamp {}",
                            encode_hex(&nonce),
                            admitted.stamp
                        ))
                        .unwrap_or_default()
                );
                let actor = admitted.agent.as_uri().to_string();
                let id = admitted.grant.id.clone();
                append(
                    &mut state,
                    &actor,
                    ConfigAction::AgentUse,
                    &id,
                    EMPTY_DIGEST,
                    &detail,
                )?;
                println!("agent use grant {id} service {service} port {port}{note} at_ms {at_ms}");
                Ok(GuardDecision::Admit(Box::new(admitted)))
            }
            Err(refused) => {
                let reason = refused.reason.as_str();
                record_refused(&mut state, &refused, service, port, &note, peer, at_ms)?;
                println!(
                    "agent deny reason {reason} service {service} port {port}{note} at_ms {at_ms}"
                );
                Ok(GuardDecision::Refuse(reason))
            }
        }
    }

    fn request_checks(
        &self,
        state: &mut CoreState,
        admitted: &Admitted,
        check: &RequestCheck<'_>,
        now: SystemTime,
    ) -> Result<(), &'static str> {
        let Some(nonce) = check.nonce else {
            return (check.scope)(&admitted.grant);
        };
        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        // A proof stamp outside the window fails the proof check, so older
        // entries cannot come back.
        let keep_after = now_secs.saturating_sub(2 * PROOF_WINDOW_SECS);
        state.seen.retain(|_, stamp| *stamp >= keep_after);
        let key = (admitted.ticket_hash, nonce);
        if state.seen.contains_key(&key) {
            return Err("replay");
        }
        state.seen.insert(key, admitted.stamp);
        // The entry goes to the nonce file before the request goes on.
        // A failed write refuses the request (fail closed).
        if let Some(store) = state.nonces.as_mut() {
            if let Err(err) = store.append(&key, admitted.stamp) {
                eprintln!("agent gateway nonce write failed. {err}");
                return Err("store");
            }
        }
        (check.scope)(&admitted.grant)
    }

    /// Record one request that the gateway refused before the proof check.
    ///
    /// `note` must not hold a token.
    pub fn record_early_deny(
        &self,
        reason: &str,
        service: &str,
        port: u16,
        note: &str,
        peer: SocketAddr,
        now: SystemTime,
    ) -> Result<(), AgentError> {
        let at_ms = unix_millis(now)?;
        let mut state = self.lock()?;
        let note = if note.is_empty() {
            String::new()
        } else {
            format!(" {note}")
        };
        let detail = format!(
            "reason {reason} service {service} port {port}{note} peer {peer} at_ms {at_ms}"
        );
        append(
            &mut state,
            "unknown",
            ConfigAction::AgentDeny,
            "none",
            EMPTY_DIGEST,
            &detail,
        )?;
        println!("agent deny reason {reason} service {service} port {port}{note} at_ms {at_ms}");
        Ok(())
    }

    fn note_grant(
        &self,
        state: &mut CoreState,
        grant: &AgentGrant,
        nonce: [u8; 16],
        agent: &SpiffeId,
    ) -> Result<(), AgentError> {
        if state.known.contains_key(&grant.id) {
            return Ok(());
        }
        state.known.insert(
            grant.id.clone(),
            Known {
                agent: agent.clone(),
                nonce,
                expires_ms: grant.expires.saturating_mul(1000),
                expired: false,
                revoked: false,
            },
        );
        let body = serde_json::to_vec(grant).map_err(|_| AgentError::Grant)?;
        let detail = format!(
            "agent {} requester {} node {} service {} port {} path {} not_before {} expires {}",
            grant.agent,
            grant.requester,
            grant.node,
            grant.service,
            grant.port,
            grant.path_prefix,
            grant.not_before,
            grant.expires
        );
        append(
            state,
            &grant.approver,
            ConfigAction::AgentGrant,
            &grant.id,
            sha256_digest(&body),
            &detail,
        )
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, CoreState>, AgentError> {
        self.state
            .lock()
            .map_err(|_| AgentError::Io("The guard state lock failed.".to_string()))
    }
}

/// Read the request nonces of recent `agent-use` records from the chain.
///
/// The gateway writes the use record before it forwards a request. Thus a
/// restart keeps each used nonce, and a proof that was used before the
/// restart is refused with `replay`. A record older than two proof windows
/// cannot match a valid proof, so the core skips it.
fn load_seen(path: &std::path::Path, now: SystemTime) -> Result<SeenSet, AgentError> {
    let mut seen = BTreeMap::new();
    if !path.exists() {
        return Ok(seen);
    }
    let checked =
        orblx_audit::verify_config_file(path).map_err(|err| AgentError::Audit(err.to_string()))?;
    let now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| AgentError::Time)?
        .as_secs();
    let keep_after = now_secs.saturating_sub(2 * PROOF_WINDOW_SECS);
    for record in checked.records {
        let event = record.event;
        // A record time is within one proof window of its proof stamp.
        if event.action != ConfigAction::AgentUse
            || event.at_unix.saturating_add(PROOF_WINDOW_SECS) < keep_after
        {
            continue;
        }
        let words: Vec<&str> = event.detail.split(' ').collect();
        let value = |key: &str| -> Option<[u8; 16]> {
            let index = words.iter().rposition(|word| *word == key)?;
            let bytes = crate::hex::decode_hex(words.get(index + 1)?).ok()?;
            <[u8; 16]>::try_from(bytes).ok()
        };
        let stamp = words
            .iter()
            .rposition(|word| *word == "stamp")
            .and_then(|index| words.get(index + 1))
            .and_then(|text| text.parse::<u64>().ok());
        if let (Some(hash), Some(nonce), Some(stamp)) =
            (value("ticket_hash"), value("nonce"), stamp)
        {
            seen.insert((hash, nonce), stamp);
        }
    }
    Ok(seen)
}

fn record_refused(
    state: &mut CoreState,
    refused: &Refused,
    service: &str,
    port: u16,
    note: &str,
    peer: SocketAddr,
    at_ms: u64,
) -> Result<(), AgentError> {
    let actor = refused
        .peer
        .as_ref()
        .map_or_else(|| "unknown".to_string(), |id| id.as_uri().to_string());
    let target = refused
        .grant_id
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let detail = format!(
        "reason {} service {service} port {port}{note} peer {peer} at_ms {at_ms}",
        refused.reason.as_str()
    );
    append(
        state,
        &actor,
        ConfigAction::AgentDeny,
        &target,
        EMPTY_DIGEST,
        &detail,
    )
}

fn append(
    state: &mut CoreState,
    actor: &str,
    action: ConfigAction,
    target: &str,
    after: [u8; 32],
    detail: &str,
) -> Result<(), AgentError> {
    let at_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| AgentError::Time)?
        .as_secs();
    state
        .audit
        .append(ConfigEvent {
            actor: actor.to_string(),
            at_unix,
            action,
            target: target.to_string(),
            before: EMPTY_DIGEST,
            after,
            detail: detail.to_string(),
        })
        .map(|_| ())
        .map_err(|err| AgentError::Audit(err.to_string()))
}

/// Run the TCP guard until the process stops.
pub fn run_guard(config: GuardConfig, fetch: DenyFetch) -> Result<(), AgentError> {
    let core = Arc::new(GuardCore::new(&config)?);
    let listener =
        TcpListener::bind(config.listen).map_err(|err| AgentError::Io(err.to_string()))?;
    spawn_poll(Arc::clone(&core), fetch, config.poll);
    println!(
        "agent guard service {} listen {} target {}",
        config.service, config.listen, config.target
    );
    let service = Arc::new(config.service.clone());
    let port = config.listen.port();
    let target = config.target;
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let core = Arc::clone(&core);
        let service = Arc::clone(&service);
        thread::spawn(move || {
            if let Err(err) = serve_one(&core, stream, &service, port, target) {
                eprintln!("agent guard connection failed. {err}");
            }
        });
    }
    Ok(())
}

/// Start the thread that reads the deny document and records expired grants.
pub(crate) fn spawn_poll(core: Arc<GuardCore>, fetch: DenyFetch, poll: Duration) {
    thread::spawn(move || loop {
        match fetch() {
            Ok(text) => {
                if let Err(err) = core.apply_deny(&text, SystemTime::now()) {
                    eprintln!("agent guard deny apply failed. {err}");
                }
            }
            Err(err) => eprintln!("agent guard deny fetch failed. {err}"),
        }
        if let Err(err) = core.tick(SystemTime::now()) {
            eprintln!("agent guard tick failed. {err}");
        }
        thread::sleep(poll);
    });
}

/// When `ORBLX_AGENT_TIMING` is `1`, the guard prints the time of each step of each
/// connection (W25-39). The line holds no proof byte.
fn timing_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("ORBLX_AGENT_TIMING").is_ok_and(|value| value == "1"))
}

/// The time of each guard step of one connection, in Unix microseconds. 0 means not reached.
#[derive(Default)]
struct ServeTiming {
    accept_us: u64,
    line_us: u64,
    admit_us: u64,
    upstream_us: u64,
    reply_us: u64,
}

impl ServeTiming {
    fn print(&self, peer: SocketAddr, result: &str) {
        if timing_on() {
            println!(
                "agent timing peer_port {} accept_us {} line_us {} admit_us {} upstream_us {} reply_us {} result {result}",
                peer.port(),
                self.accept_us,
                self.line_us,
                self.admit_us,
                self.upstream_us,
                self.reply_us
            );
        }
    }
}

fn serve_one(
    core: &GuardCore,
    stream: TcpStream,
    service: &str,
    port: u16,
    target: SocketAddr,
) -> Result<(), AgentError> {
    let mut timing = ServeTiming {
        accept_us: crate::client::unix_micros_now(),
        ..ServeTiming::default()
    };
    let io = |err: std::io::Error| AgentError::Io(err.to_string());
    let peer = stream.peer_addr().map_err(io)?;
    stream.set_read_timeout(Some(LINE_TIMEOUT)).map_err(io)?;
    let mut writer = stream.try_clone().map_err(io)?;
    let mut reader = BufReader::new(stream);
    let line = read_line(&mut reader)?;
    timing.line_us = crate::client::unix_micros_now();
    let decision = core.admit(&line, service, port, &[], peer, SystemTime::now())?;
    timing.admit_us = crate::client::unix_micros_now();
    match decision {
        GuardDecision::Refuse(reason) => {
            let _ = writer.write_all(format!("orblx-deny {reason}\n").as_bytes());
            timing.reply_us = crate::client::unix_micros_now();
            timing.print(peer, "deny");
            let _ = writer.shutdown(Shutdown::Both);
            Ok(())
        }
        GuardDecision::Admit(_) => {
            let mut upstream = TcpStream::connect_timeout(&target, DIAL_TIMEOUT).map_err(io)?;
            timing.upstream_us = crate::client::unix_micros_now();
            writer.write_all(b"orblx-ok\n").map_err(io)?;
            timing.reply_us = crate::client::unix_micros_now();
            timing.print(peer, "ok");
            let buffered = reader.buffer().to_vec();
            if !buffered.is_empty() {
                upstream.write_all(&buffered).map_err(io)?;
            }
            let client = reader.into_inner();
            client.set_read_timeout(None).map_err(io)?;
            splice(client, upstream).map_err(io)
        }
    }
}

fn read_line(reader: &mut BufReader<TcpStream>) -> Result<String, AgentError> {
    let mut raw = Vec::new();
    let mut limited = reader
        .by_ref()
        .take(u64::try_from(MAX_LINE).unwrap_or(u64::MAX));
    match limited.read_until(b'\n', &mut raw) {
        Ok(_) => Ok(String::from_utf8(raw).unwrap_or_default()),
        Err(_) => Ok(String::new()),
    }
}

fn splice(client: TcpStream, upstream: TcpStream) -> std::io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let forward = thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let mut upstream_read = upstream;
    let mut client_write = client;
    let _ = std::io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = forward.join();
    Ok(())
}
