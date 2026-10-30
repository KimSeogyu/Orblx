//! In-daemon SSH server.
//!
//! The listener uses the overlay address.
//! Each new session reads the deny file.
//! An open session reads the deny file again after the check period.
//! A rule can require a session recording. Then the server fails closed
//! when the recording does not open or does not write.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_audit::{AuditLog, SessionEvent, SessionIds};
use orblx_identity::{
    ed25519_public_key_from_certificate_pem, ed25519_seed_from_private_pem, DenyApply, DenySet,
    Policy, SpiffeId, TicketVerifier, TrustBundle,
};
use russh::keys::ssh_encoding::bytes::Bytes;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::net::TcpListener;

use crate::auth::{command_ok, open_login, overlay_listen_addr, RefusedLogin};
use crate::hostkey::host_key_from_seed;
use crate::record::Recorder;

struct Shared {
    overlay: Ipv4Addr,
    node_id: SpiffeId,
    host_key: [u8; 32],
    bundle: TrustBundle,
    verifier: Option<TicketVerifier>,
    state_dir: PathBuf,
    audit: Mutex<AuditLog>,
    spent: Mutex<BTreeSet<[u8; 16]>>,
    frames: AtomicU32,
}

#[derive(Clone)]
struct Admitted {
    src: SpiffeId,
    user: String,
    check_period: u64,
    ticket_hash: [u8; 16],
    frame: u32,
    recording: bool,
}

#[derive(Clone)]
struct SshHandler {
    shared: Arc<Shared>,
    admitted: Option<Admitted>,
}

/// Error text for one SSH session.
///
/// The text does not include keys or proofs.
#[derive(Debug)]
struct SessionFail;

impl std::fmt::Display for SessionFail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("The SSH session failed.")
    }
}

impl std::error::Error for SessionFail {}

impl From<russh::Error> for SessionFail {
    fn from(_err: russh::Error) -> Self {
        Self
    }
}

impl Handler for SshHandler {
    type Error = SessionFail;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(self.decide(user, password))
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        let outcome = self.exec_command(&command);
        if let Some((code, stdout)) = outcome {
            let _ = session.channel_success(channel);
            let _ = session.data(channel, Bytes::from(stdout));
            let _ = session.exit_status_request(channel, code);
            let _ = session.eof(channel);
            let _ = session.close(channel);
            let _ = session.disconnect(russh::Disconnect::ByApplication, "", "");
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }
}

impl SshHandler {
    fn decide(&mut self, user: &str, password: &str) -> Auth {
        let policy = load_policy(&self.shared.state_dir.join("policy.hujson"));
        let deny = load_deny(&self.shared.state_dir.join("deny.json"));
        if deny.reject_uri(&self.shared.node_id).is_err() {
            self.audit_refuse(&RefusedLogin {
                peer: self.shared.node_id.clone(),
                reason: orblx_audit::DenyReason::Revoked,
                ticket_hash: [0u8; 16],
            });
            return Auth::reject();
        }
        let spent = self
            .shared
            .spent
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        match open_login(
            user,
            password,
            &self.shared.node_id,
            self.shared.overlay,
            &self.shared.host_key,
            SystemTime::now(),
            &self.shared.bundle,
            &policy,
            &deny,
            self.shared.verifier.as_ref(),
            &spent,
        ) {
            Ok(admitted) => {
                if let Some(nonce) = admitted.spend_nonce {
                    if !spend_nonce(&self.shared, nonce) {
                        self.audit_refuse(&RefusedLogin {
                            peer: admitted.src,
                            reason: orblx_audit::DenyReason::Ticket,
                            ticket_hash: admitted.ticket_hash,
                        });
                        return Auth::reject();
                    }
                }
                let frame = self.shared.frames.fetch_add(1, Ordering::Relaxed);
                let recording =
                    policy.ssh_recording_required(&admitted.src, &self.shared.node_id, user);
                self.admitted = Some(Admitted {
                    src: admitted.src,
                    user: user.to_string(),
                    check_period: admitted.check_period,
                    ticket_hash: admitted.ticket_hash,
                    frame,
                    recording,
                });
                Auth::Accept
            }
            Err(refused) => {
                self.audit_refuse(&refused);
                Auth::reject()
            }
        }
    }

    fn exec_command(&mut self, command: &str) -> Option<(u32, Vec<u8>)> {
        let admitted = self.admitted.clone()?;
        if !command_ok(command) {
            self.audit_refuse(&RefusedLogin {
                peer: admitted.src,
                reason: orblx_audit::DenyReason::Destination,
                ticket_hash: admitted.ticket_hash,
            });
            return None;
        }
        if let Err(refused) = recheck(&self.shared, &admitted) {
            self.audit_refuse(&refused);
            return None;
        }
        let mut recorder = None;
        if admitted.recording {
            let opened = Recorder::create(&self.shared.state_dir, admitted.frame, &admitted.user)
                .and_then(|mut opened| {
                    opened.event(Duration::ZERO, "i", command.as_bytes())?;
                    Ok(opened)
                });
            match opened {
                Ok(opened) => recorder = Some(opened),
                Err(_) => {
                    eprintln!("The SSH session recording did not open. The session is refused.");
                    self.audit_refuse(&self.recording_refused(&admitted));
                    return None;
                }
            }
        }
        self.audit_event(SessionEvent::Start {
            ids: session_ids(&admitted),
            at_unix: unix_now(),
        });
        let output = run_command(command, &admitted, &self.shared, recorder.as_mut());
        match output {
            Ok((code, stdout)) => {
                if let Some(opened) = recorder {
                    let Ok((file, sha256)) = opened.finish() else {
                        eprintln!(
                            "The SSH session recording did not close. The session is refused."
                        );
                        self.audit_refuse(&self.recording_refused(&admitted));
                        return None;
                    };
                    let recorded = self.audit_event(SessionEvent::Record {
                        ids: session_ids(&admitted),
                        at_unix: unix_now(),
                        file,
                        sha256,
                    });
                    if !recorded {
                        return None;
                    }
                }
                self.audit_event(SessionEvent::End {
                    ids: session_ids(&admitted),
                    at_unix: unix_now(),
                });
                Some((code, stdout))
            }
            Err(reason) => {
                self.audit_refuse(&RefusedLogin {
                    peer: admitted.src,
                    reason,
                    ticket_hash: admitted.ticket_hash,
                });
                None
            }
        }
    }

    fn recording_refused(&self, admitted: &Admitted) -> RefusedLogin {
        RefusedLogin {
            peer: admitted.src.clone(),
            reason: orblx_audit::DenyReason::Recording,
            ticket_hash: admitted.ticket_hash,
        }
    }

    fn audit_refuse(&self, refused: &RefusedLogin) {
        self.audit_event(SessionEvent::Deny {
            ids: SessionIds::receiver_acl(refused.peer.clone(), 0, refused.ticket_hash),
            at_unix: unix_now(),
            reason: refused.reason,
        });
    }

    fn audit_event(&self, event: SessionEvent) -> bool {
        let mut log = self
            .shared
            .audit
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if log.append(event).is_err() {
            eprintln!("The audit chain did not record the SSH session.");
            return false;
        }
        let path = self.shared.state_dir.join("ssh-audit.jsonl");
        if log.write_jsonl(&path).is_err() {
            eprintln!("The audit chain did not record the SSH session.");
            return false;
        }
        true
    }
}

fn session_ids(admitted: &Admitted) -> SessionIds {
    SessionIds::receiver_acl(admitted.src.clone(), admitted.frame, admitted.ticket_hash)
}

fn recheck(shared: &Shared, admitted: &Admitted) -> Result<(), RefusedLogin> {
    let policy = load_policy(&shared.state_dir.join("policy.hujson"));
    let deny = load_deny(&shared.state_dir.join("deny.json"));
    if deny.reject_uri(&shared.node_id).is_err() {
        return Err(RefusedLogin {
            peer: shared.node_id.clone(),
            reason: orblx_audit::DenyReason::Revoked,
            ticket_hash: admitted.ticket_hash,
        });
    }
    if deny.reject_uri(&admitted.src).is_err() {
        return Err(RefusedLogin {
            peer: admitted.src.clone(),
            reason: orblx_audit::DenyReason::Revoked,
            ticket_hash: admitted.ticket_hash,
        });
    }
    if policy
        .ssh_check_period(&admitted.src, &shared.node_id, &admitted.user)
        .is_none()
    {
        return Err(RefusedLogin {
            peer: admitted.src.clone(),
            reason: orblx_audit::DenyReason::Destination,
            ticket_hash: admitted.ticket_hash,
        });
    }
    Ok(())
}

fn run_command(
    command: &str,
    admitted: &Admitted,
    shared: &Shared,
    mut recorder: Option<&mut Recorder>,
) -> Result<(u32, Vec<u8>), orblx_audit::DenyReason> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("ORBLX_SSH_USER", &admitted.user)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| orblx_audit::DenyReason::Destination)?;
    let started = Instant::now();
    let (chunks, output) = mpsc::channel::<(Duration, Vec<u8>)>();
    let reader = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(len) => {
                        if chunks
                            .send((started.elapsed(), buf[..len].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        })
    });
    let mut stdout = Vec::new();
    let mut checked = false;
    let fail = |child: &mut std::process::Child, reason| {
        let _ = child.kill();
        let _ = child.wait();
        Err(reason)
    };
    loop {
        if take_output(&output, &mut stdout, recorder.as_deref_mut()).is_err() {
            return fail(&mut child, orblx_audit::DenyReason::Recording);
        }
        if !checked && started.elapsed() >= Duration::from_secs(admitted.check_period.max(1)) {
            checked = true;
            if recheck(shared, admitted).is_err() {
                return fail(&mut child, orblx_audit::DenyReason::Revoked);
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(handle) = reader {
                    let _ = handle.join();
                }
                if take_output(&output, &mut stdout, recorder.as_deref_mut()).is_err() {
                    return Err(orblx_audit::DenyReason::Recording);
                }
                let code = status.code().unwrap_or(1);
                let code = u32::try_from(code).unwrap_or(1);
                return Ok((code, stdout));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => return fail(&mut child, orblx_audit::DenyReason::Destination),
        }
        if started.elapsed() > Duration::from_secs(30) {
            return fail(&mut child, orblx_audit::DenyReason::Expired);
        }
    }
}

/// Move the read output into the reply and into the recording.
///
/// The reply keeps the first 4096 bytes. The recording keeps all bytes.
fn take_output(
    output: &mpsc::Receiver<(Duration, Vec<u8>)>,
    stdout: &mut Vec<u8>,
    mut recorder: Option<&mut Recorder>,
) -> std::io::Result<()> {
    while let Ok((at, chunk)) = output.try_recv() {
        if let Some(recorder) = recorder.as_deref_mut() {
            recorder.event(at, "o", &chunk)?;
        }
        let room = 4096usize.saturating_sub(stdout.len());
        stdout.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }
    Ok(())
}

/// Start the SSH server on the overlay address.
///
/// The function returns after the listener thread starts.
/// The thread binds `overlay:22`.
pub fn spawn_overlay_server(state_dir: &Path, overlay: Ipv4Addr) -> Result<(), String> {
    let addr = overlay_listen_addr(overlay)?;
    let shared = Arc::new(Shared::load(state_dir, overlay)?);
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                eprintln!("The SSH server did not start.");
                return;
            }
        };
        if let Err(err) = runtime.block_on(listen(addr, shared)) {
            eprintln!("The SSH server stopped. {err}");
        }
    });
    Ok(())
}

async fn listen(addr: SocketAddr, shared: Arc<Shared>) -> Result<(), String> {
    let listener = bind_overlay(addr).await?;
    accept_loop(listener, shared).await
}

async fn bind_overlay(addr: SocketAddr) -> Result<TcpListener, String> {
    let mut last = String::from("The bind failed.");
    for _ in 0..50 {
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok(listener),
            Err(err) => {
                last = err.to_string();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(format!("The SSH server did not bind {addr}. {last}"))
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>) -> Result<(), String> {
    let local = listener
        .local_addr()
        .map_err(|_| "The SSH server did not bind.".to_string())?;
    if local.ip() != shared.overlay {
        return Err("The SSH server listens on the overlay address.".to_string());
    }
    println!("ssh_listen {local}");
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    let seed = svid_seed(&shared)?;
    let private = host_key_from_seed(&seed).map(|(key, _)| key)?;
    let config = russh::server::Config {
        methods,
        auth_rejection_time: Duration::from_millis(20),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        keys: vec![private],
        inactivity_timeout: Some(Duration::from_secs(120)),
        ..Default::default()
    };
    let config = Arc::new(config);
    loop {
        let (socket, _) = listener
            .accept()
            .await
            .map_err(|_| "The SSH server did not accept a session.".to_string())?;
        let config = Arc::clone(&config);
        let handler = SshHandler {
            shared: Arc::clone(&shared),
            admitted: None,
        };
        tokio::spawn(async move {
            let _ = russh::server::run_stream(config, socket, handler).await;
        });
    }
}

fn svid_seed(shared: &Shared) -> Result<[u8; 32], String> {
    let pem = fs::read_to_string(shared.state_dir.join("key.pem"))
        .map_err(|_| "The node SVID key did not open.".to_string())?;
    ed25519_seed_from_private_pem(&pem).map_err(|_| "The node SVID key is not valid.".to_string())
}

impl Shared {
    fn load(state_dir: &Path, overlay: Ipv4Addr) -> Result<Self, String> {
        let cert_pem = fs::read_to_string(state_dir.join("cert.pem"))
            .map_err(|_| "The node SVID did not open.".to_string())?;
        let bundle_pem = fs::read_to_string(state_dir.join("bundle.pem"))
            .map_err(|_| "The trust bundle did not open.".to_string())?;
        let bundle = TrustBundle::from_pem(&bundle_pem)
            .map_err(|_| "The trust bundle is not valid.".to_string())?;
        let node_id = bundle
            .authenticate_leaf(
                &orblx_identity::decode_certificate_pem(&cert_pem)
                    .map_err(|_| "The node SVID is not valid.".to_string())?,
                SystemTime::now(),
                &DenySet::empty(),
            )
            .map_err(|_| "The node SVID is not valid.".to_string())?;
        let host_key = ed25519_public_key_from_certificate_pem(&cert_pem)
            .map_err(|_| "The node SVID is not valid.".to_string())?;
        let verifier = match fs::read_to_string(state_dir.join("ticket-verifier.pem")) {
            Ok(pem) => Some(
                TicketVerifier::from_public_pem(&pem)
                    .map_err(|_| "The ticket verifier is not valid.".to_string())?,
            ),
            Err(_) => None,
        };
        Ok(Self {
            overlay,
            node_id,
            host_key,
            bundle,
            verifier,
            state_dir: state_dir.to_path_buf(),
            audit: Mutex::new(AuditLog::new()),
            spent: Mutex::new(load_spent(&state_dir.join("ssh-spent.txt"))),
            frames: AtomicU32::new(1),
        })
    }
}

fn load_policy(path: &Path) -> Policy {
    match Policy::from_path(path) {
        Ok(policy) => policy,
        Err(err) => {
            if path.exists() {
                eprintln!("The SSH policy did not load. {err}");
            }
            Policy::empty()
        }
    }
}

fn load_deny(path: &Path) -> DenySet {
    let Ok(bytes) = fs::read(path) else {
        return DenySet::empty();
    };
    let mut deny = DenySet::empty();
    match deny.apply_json(&bytes) {
        Ok(DenyApply::Applied | DenyApply::IgnoredOlder) => deny,
        Err(_) => {
            eprintln!("The deny file is not valid.");
            DenySet::empty()
        }
    }
}

fn load_spent(path: &Path) -> BTreeSet<[u8; 16]> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    let mut set = BTreeSet::new();
    for line in text.lines() {
        if let Some(nonce) = parse_hex_16(line.trim()) {
            set.insert(nonce);
        }
    }
    set
}

fn spend_nonce(shared: &Shared, nonce: [u8; 16]) -> bool {
    let mut spent = shared.spent.lock().unwrap_or_else(|err| err.into_inner());
    if !spent.insert(nonce) {
        return false;
    }
    let mut text = String::new();
    for item in spent.iter() {
        text.push_str(&encode_hex(item));
        text.push('\n');
    }
    let path = shared.state_dir.join("ssh-spent.txt");
    fs::write(path, text).is_ok()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_hex_16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_value(text.as_bytes()[index * 2])?;
        let low = hex_value(text.as_bytes()[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use orblx_audit::verify_file;
    use orblx_identity::{
        sign_ticket, DenySet, MiniCa, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
        MAX_AGENT_TTL, MAX_USER_TTL,
    };
    use tokio::net::TcpListener;

    use super::Shared;
    use crate::client::{run_session, SessionRequest};

    #[tokio::test]
    async fn a_session_on_the_overlay_address_audits_start_end_and_deny() {
        let dir = std::env::temp_dir().join(format!("orblx-ssh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = SystemTime::now();
        let ca = MiniCa::generate(now).unwrap();
        let signer = TicketSigner::generate();
        let node = SpiffeId::node("box").unwrap();
        let alice = SpiffeId::user("alice").unwrap();
        let mallory = SpiffeId::user("mallory").unwrap();
        let agent = SpiffeId::agent("helper").unwrap();
        let issued_node = ca
            .issue(&node, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_alice = ca
            .issue(&alice, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_mallory = ca
            .issue(&mallory, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_agent = ca
            .issue(&agent, now, MAX_AGENT_TTL, &DenySet::empty())
            .unwrap();
        std::fs::write(dir.join("cert.pem"), &issued_node.certificate_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &issued_node.private_key_pem).unwrap();
        std::fs::write(dir.join("bundle.pem"), ca.certificate_pem()).unwrap();
        std::fs::write(dir.join("ticket-verifier.pem"), signer.public_key_pem()).unwrap();
        std::fs::write(
            dir.join("policy.hujson"),
            r#"{
                "ssh": [
                    {
                        "src": ["spiffe://orblx.local/user/alice"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["alice"],
                        "checkPeriod": "30s"
                    },
                    {
                        "src": ["spiffe://orblx.local/agent/helper"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["alice"],
                        "checkPeriod": "30s"
                    }
                ]
            }"#,
        )
        .unwrap();
        let alice_dir = dir.join("alice");
        let mallory_dir = dir.join("mallory");
        let agent_dir = dir.join("agent");
        for path in [&alice_dir, &mallory_dir, &agent_dir] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("bundle.pem"), ca.certificate_pem()).unwrap();
        }
        std::fs::write(alice_dir.join("cert.pem"), &issued_alice.certificate_pem).unwrap();
        std::fs::write(alice_dir.join("key.pem"), &issued_alice.private_key_pem).unwrap();
        std::fs::write(
            mallory_dir.join("cert.pem"),
            &issued_mallory.certificate_pem,
        )
        .unwrap();
        std::fs::write(mallory_dir.join("key.pem"), &issued_mallory.private_key_pem).unwrap();
        std::fs::write(agent_dir.join("cert.pem"), &issued_agent.certificate_pem).unwrap();
        std::fs::write(agent_dir.join("key.pem"), &issued_agent.private_key_pem).unwrap();
        let stamp = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let ticket = sign_ticket(
            &signer,
            &TicketClaims {
                issuer: SpiffeId::coord("ssh").unwrap(),
                subject: agent.clone(),
                not_before: stamp,
                expires: stamp + 120,
                dst_cidr: "127.0.0.1/32".to_string(),
                proto: 6,
                dst_port: 22,
                flags: TicketFlags::new(true, true),
            },
        )
        .unwrap();
        std::fs::write(agent_dir.join("ticket.bin"), &ticket.bytes).unwrap();
        std::fs::write(dir.join("peer.pem"), &issued_node.certificate_pem).unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = std::sync::Arc::new(Shared::load(&dir, Ipv4Addr::LOCALHOST).unwrap());
        tokio::spawn(super::accept_loop(listener, shared));
        tokio::time::sleep(Duration::from_millis(200)).await;

        let ok = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: alice_dir.clone(),
            peer_cert: dir.join("peer.pem"),
            command: "printf '%s\\n' \"$ORBLX_SSH_USER\"".to_string(),
        })
        .await
        .unwrap();
        assert_eq!(ok.exit_status, 0);
        assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "alice");

        let node_deny = format!(
            r#"{{"version":1,"generated_at":1,"revoked_uris":["{}"],"revoked_ticket_nonces":[]}}"#,
            node.as_uri()
        );
        std::fs::write(dir.join("deny.json"), node_deny).unwrap();
        let node_started = std::time::Instant::now();
        let node_revoked = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: alice_dir.clone(),
            peer_cert: dir.join("peer.pem"),
            command: "printf %s\\n node".to_string(),
        })
        .await;
        assert!(node_revoked.is_err());
        assert!(node_started.elapsed() < Duration::from_secs(60));
        std::fs::write(
            dir.join("deny.json"),
            r#"{"version":2,"generated_at":2,"revoked_uris":[],"revoked_ticket_nonces":[]}"#,
        )
        .unwrap();
        let again = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: alice_dir.clone(),
            peer_cert: dir.join("peer.pem"),
            command: "printf '%s\\n' \"$ORBLX_SSH_USER\"".to_string(),
        })
        .await
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&again.stdout).trim(), "alice");

        let denied = session_within(SessionRequest {
            user: "mallory".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: mallory_dir,
            peer_cert: dir.join("peer.pem"),
            command: "printf %s\\n denied".to_string(),
        })
        .await;
        assert!(denied.is_err());

        let agent_ok = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: agent_dir.clone(),
            peer_cert: dir.join("peer.pem"),
            command: "printf '%s\\n' \"$ORBLX_SSH_USER\"".to_string(),
        })
        .await
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&agent_ok.stdout).trim(), "alice");
        let replay = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: agent_dir,
            peer_cert: dir.join("peer.pem"),
            command: "printf %s\\n replay".to_string(),
        })
        .await;
        assert!(replay.is_err());

        let document = format!(
            r#"{{"version":3,"generated_at":3,"revoked_uris":["{}"],"revoked_ticket_nonces":[]}}"#,
            alice.as_uri()
        );
        std::fs::write(dir.join("deny.json"), document).unwrap();
        let started = std::time::Instant::now();
        let revoked = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node,
            identity_dir: dir.join("alice"),
            peer_cert: dir.join("peer.pem"),
            command: "printf %s\\n revoked".to_string(),
        })
        .await;
        assert!(revoked.is_err());
        assert!(started.elapsed() < Duration::from_secs(60));

        let checked = verify_file(&dir.join("ssh-audit.jsonl")).unwrap();
        assert!(checked.metrics.start >= 1);
        assert!(checked.metrics.end >= 1);
        assert!(checked.metrics.deny >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_rule_with_recording_writes_the_file_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("orblx-ssh-rec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = SystemTime::now();
        let ca = MiniCa::generate(now).unwrap();
        let node = SpiffeId::node("box").unwrap();
        let alice = SpiffeId::user("alice").unwrap();
        let issued_node = ca
            .issue(&node, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_alice = ca
            .issue(&alice, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        std::fs::write(dir.join("cert.pem"), &issued_node.certificate_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &issued_node.private_key_pem).unwrap();
        std::fs::write(dir.join("bundle.pem"), ca.certificate_pem()).unwrap();
        std::fs::write(dir.join("peer.pem"), &issued_node.certificate_pem).unwrap();
        std::fs::write(
            dir.join("policy.hujson"),
            r#"{
                "ssh": [
                    {
                        "src": ["spiffe://orblx.local/user/alice"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["alice"],
                        "checkPeriod": "30s"
                    },
                    {
                        "src": ["spiffe://orblx.local/user/alice"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["rec"],
                        "checkPeriod": "30s",
                        "recording": "required"
                    }
                ]
            }"#,
        )
        .unwrap();
        let alice_dir = dir.join("alice");
        std::fs::create_dir_all(&alice_dir).unwrap();
        std::fs::write(alice_dir.join("bundle.pem"), ca.certificate_pem()).unwrap();
        std::fs::write(alice_dir.join("cert.pem"), &issued_alice.certificate_pem).unwrap();
        std::fs::write(alice_dir.join("key.pem"), &issued_alice.private_key_pem).unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = std::sync::Arc::new(Shared::load(&dir, Ipv4Addr::LOCALHOST).unwrap());
        tokio::spawn(super::accept_loop(listener, shared));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let request = |user: &str| SessionRequest {
            user: user.to_string(),
            addr,
            dst: node.clone(),
            identity_dir: alice_dir.clone(),
            peer_cert: dir.join("peer.pem"),
            command: "printf '%s\\n' \"recorded-$ORBLX_SSH_USER\"".to_string(),
        };

        let recorded = session_within(request("rec")).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&recorded.stdout).trim(),
            "recorded-rec"
        );
        let records: Vec<_> = std::fs::read_dir(dir.join(crate::record::RECORD_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(records.len(), 1);
        let cast = std::fs::read_to_string(&records[0]).unwrap();
        assert!(cast.contains("recorded-rec"));
        assert!(!cast.contains("PRIVATE KEY"));
        let checked = verify_file(&dir.join("ssh-audit.jsonl")).unwrap();
        assert_eq!(checked.metrics.record, 1);

        let plain = session_within(request("alice")).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&plain.stdout).trim(),
            "recorded-alice"
        );
        assert_eq!(
            std::fs::read_dir(dir.join(crate::record::RECORD_DIR))
                .unwrap()
                .count(),
            1
        );

        let original = std::fs::read(&records[0]).unwrap();
        let mut changed = original.clone();
        changed[0] ^= 0x01;
        std::fs::write(&records[0], &changed).unwrap();
        assert!(verify_file(&dir.join("ssh-audit.jsonl")).is_err());
        std::fs::write(&records[0], &original).unwrap();

        std::fs::rename(
            dir.join(crate::record::RECORD_DIR),
            dir.join("recordings-moved"),
        )
        .unwrap();
        std::fs::write(dir.join(crate::record::RECORD_DIR), b"not a directory").unwrap();
        assert!(session_within(request("rec")).await.is_err());
        let chain = std::fs::read_to_string(dir.join("ssh-audit.jsonl")).unwrap();
        assert!(chain.contains("\"reason\":\"recording\""));
        let plain = session_within(request("alice")).await.unwrap();
        assert_eq!(plain.exit_status, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn session_within(
        request: crate::client::SessionRequest,
    ) -> Result<crate::client::SessionOutput, String> {
        match tokio::time::timeout(Duration::from_secs(15), run_session(request)).await {
            Ok(result) => result,
            Err(_) => Err("The SSH session timed out.".to_string()),
        }
    }
}
