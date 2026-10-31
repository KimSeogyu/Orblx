//! In-daemon SSH server.
//!
//! The listener uses the overlay address.
//! Each new session reads the deny file.
//! An open session reads the deny file again after the check period.
//! A rule can require a session recording. Then the server fails closed
//! when the recording does not open or does not write.
//! A client can ask for a PTY and a shell. The server records the input and
//! the output of that shell in time order when the rule requires it.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orblx_audit::{AuditLog, SessionEvent, SessionIds};
use orblx_identity::{
    ed25519_seed_from_private_pem, DenyApply, DenySet, Policy, SpiffeId, TicketVerifier,
    TrustBundle,
};
use russh::keys::ssh_encoding::bytes::Bytes;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::net::TcpListener;

use crate::auth::{command_ok, open_login, overlay_listen_addr, RefusedLogin};
use crate::cert::{check_cert, fresh_netmap, CertInput, CertRefuse};
use crate::hostkey::host_key_from_seed;
use crate::pty::{kill_group, PtyShell, PtySpec};
use crate::record::{Recorder, Utf8Carry};

/// The open certificate sessions: serial to (key ID, stop flag) (W25-31).
type CertSessions = HashMap<u64, Vec<(String, Weak<AtomicBool>)>>;

struct Shared {
    overlay: Ipv4Addr,
    node_id: SpiffeId,
    bundle: TrustBundle,
    verifier: Option<TicketVerifier>,
    state_dir: PathBuf,
    audit: Mutex<AuditLog>,
    spent: Mutex<BTreeSet<[u8; 16]>>,
    frames: AtomicU32,
    /// The open certificate sessions by serial (W25-31). A revoked serial stops each session.
    cert_sessions: Mutex<CertSessions>,
}

/// The certificate facts of one open session (W25-31).
#[derive(Clone)]
struct CertSession {
    client_node: SpiffeId,
    /// The watcher sets the flag when the netmap revokes the serial or the key ID.
    stop: Arc<AtomicBool>,
    /// The certificate has `permit-pty`.
    pty: bool,
}

#[derive(Clone)]
struct Admitted {
    src: SpiffeId,
    user: String,
    check_period: u64,
    ticket_hash: [u8; 16],
    frame: u32,
    recording: bool,
    /// Set for a certificate login (W25-31).
    cert: Option<CertSession>,
}

#[derive(Clone)]
struct SshHandler {
    shared: Arc<Shared>,
    /// The public host key of this connection: the node SVID key when the connection opened.
    host_key: [u8; 32],
    /// The TCP peer address. The certificate `source-address` must contain it.
    peer: Option<SocketAddr>,
    admitted: Option<Admitted>,
    pty: Option<PtySpec>,
    shell: Option<Arc<LiveShell>>,
}

/// The recording state of one shell session.
struct ShellRecord {
    recorder: Recorder,
    input: Utf8Carry,
    output: Utf8Carry,
    hidden: bool,
}

/// One running PTY shell.
///
/// One lock keeps the recording. Each event takes its time under that lock,
/// so the events in the file are in time order.
struct LiveShell {
    writer: Mutex<File>,
    pid: u32,
    started: Instant,
    record: Mutex<Option<ShellRecord>>,
    failed: Mutex<Option<orblx_audit::DenyReason>>,
}

/// A message from the shell thread to the SSH session task.
enum ShellOut {
    Data(Vec<u8>),
    Exit(u32),
}

impl LiveShell {
    /// Record the input and then give it to the shell.
    ///
    /// When the terminal echo is off, the recording gets one `m` marker and
    /// not the input bytes. When the recording fails, the shell stops and the
    /// input does not go to the shell.
    fn input(&self, data: &[u8]) {
        let writer = self.writer.lock().unwrap_or_else(|err| err.into_inner());
        let hidden = crate::pty::echo_off(&writer);
        {
            let mut record = self.record.lock().unwrap_or_else(|err| err.into_inner());
            if let Some(state) = record.as_mut() {
                let at = self.started.elapsed();
                let written = if hidden {
                    state.input = Utf8Carry::default();
                    let first = !state.hidden;
                    state.hidden = true;
                    if first {
                        state.recorder.event_text(at, "m", "input hidden")
                    } else {
                        Ok(())
                    }
                } else {
                    state.hidden = false;
                    let text = state.input.take(data);
                    if text.is_empty() {
                        Ok(())
                    } else {
                        state.recorder.event_text(at, "i", &text)
                    }
                };
                if written.is_err() {
                    drop(record);
                    self.fail(orblx_audit::DenyReason::Recording);
                    return;
                }
            }
        }
        let mut writer = writer;
        if writer.write_all(data).is_err() {
            kill_group(self.pid, libc::SIGHUP);
        }
    }

    /// Record one output chunk. Return false when the recording failed.
    fn output(&self, data: &[u8]) -> bool {
        let mut record = self.record.lock().unwrap_or_else(|err| err.into_inner());
        let Some(state) = record.as_mut() else {
            return true;
        };
        let text = state.output.take(data);
        if text.is_empty() {
            return true;
        }
        let at = self.started.elapsed();
        if state.recorder.event_text(at, "o", &text).is_err() {
            drop(record);
            self.fail(orblx_audit::DenyReason::Recording);
            return false;
        }
        true
    }

    /// Set the terminal size and record it.
    fn resize(&self, cols: u16, rows: u16) {
        {
            let writer = self.writer.lock().unwrap_or_else(|err| err.into_inner());
            let _ = crate::pty::resize(&writer, cols, rows);
        }
        let mut record = self.record.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(state) = record.as_mut() {
            let at = self.started.elapsed();
            if state
                .recorder
                .event_text(at, "r", &format!("{cols}x{rows}"))
                .is_err()
            {
                drop(record);
                self.fail(orblx_audit::DenyReason::Recording);
            }
        }
    }

    /// Stop the shell and keep the first reason.
    fn fail(&self, reason: orblx_audit::DenyReason) {
        {
            let mut failed = self.failed.lock().unwrap_or_else(|err| err.into_inner());
            if failed.is_none() {
                *failed = Some(reason);
            }
        }
        kill_group(self.pid, libc::SIGKILL);
    }
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

    /// W25-31: russh calls this method after it checked the validity window, the CA
    /// signature, and the userauth signature with the certificate key.
    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &russh::keys::ssh_key::Certificate,
    ) -> Result<Auth, Self::Error> {
        Ok(self.decide_cert(user, certificate))
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

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.admitted.is_none() || self.shell.is_some() {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        // A certificate without `permit-pty` gets no PTY.
        if let Some(Admitted {
            cert: Some(cert), ..
        }) = &self.admitted
        {
            if !cert.pty {
                let _ = session.channel_failure(channel);
                return Ok(());
            }
        }
        self.pty = Some(PtySpec::from_request(term, col_width, row_height));
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.start_shell(channel, session.handle()) {
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(shell) = &self.shell {
            shell.input(data);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cols = crate::pty::clamp_size(col_width, 80);
        let rows = crate::pty::clamp_size(row_height, 24);
        if let Some(shell) = &self.shell {
            shell.resize(cols, rows);
        } else if let Some(spec) = self.pty.as_mut() {
            spec.cols = cols;
            spec.rows = rows;
        }
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(shell) = &self.shell {
            kill_group(shell.pid, libc::SIGHUP);
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        // The command blocks until it ends (up to its time limit).
        // Run it on a blocking thread, so that other sessions on this runtime continue.
        let worker = self.clone();
        let outcome = tokio::task::spawn_blocking(move || worker.exec_command(&command))
            .await
            .ok()
            .flatten();
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
    /// Check one user certificate (W25-31). The netmap gives the CA set and the revoked list.
    fn decide_cert(&mut self, user: &str, cert: &russh::keys::ssh_key::Certificate) -> Auth {
        let ticket_hash = cert_hash(cert.key_id());
        let refuse = |handler: &Self, peer: SpiffeId, refused: CertRefuse| {
            println!(
                "ssh certificate refused serial {} reason {}",
                cert.serial(),
                refused.as_str()
            );
            handler.audit_refuse(&RefusedLogin {
                peer,
                reason: refused.audit_reason(),
                ticket_hash,
            });
            Auth::reject()
        };
        let node_id = self.shared.node_id.clone();
        let Some(peer) = self.peer else {
            return refuse(self, node_id, CertRefuse::SourceAddress);
        };
        let now_unix = unix_now();
        let netmap = match fresh_netmap(&self.shared.state_dir, unix_now_ms()) {
            Ok(netmap) => netmap,
            Err(refused) => return refuse(self, node_id, refused),
        };
        let policy = load_policy(&self.shared.state_dir.join("policy.hujson"));
        let deny = load_deny(&self.shared.state_dir.join("deny.json"));
        if deny.reject_uri(&self.shared.node_id).is_err() {
            return refuse(self, node_id, CertRefuse::Revoked);
        }
        let checked = check_cert(&CertInput {
            cert,
            login: user,
            peer_ip: peer.ip(),
            now_unix,
            ca_set: &netmap.ssh_user_ca,
            revoked: &netmap.ssh_revoked,
            policy: &policy,
            node_id: &self.shared.node_id,
            deny: &deny,
        });
        let admit = match checked {
            Ok(admit) => admit,
            Err(refused) => return refuse(self, node_id, refused),
        };
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut sessions = self
                .shared
                .cert_sessions
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            sessions
                .entry(admit.serial)
                .or_default()
                .push((admit.key_id.clone(), Arc::downgrade(&stop)));
        }
        let frame = self.shared.frames.fetch_add(1, Ordering::Relaxed);
        let recording = policy.ssh_recording_required(&admit.src, &self.shared.node_id, user);
        println!(
            "ssh certificate accepted serial {} principal {}",
            admit.serial, admit.principal
        );
        self.admitted = Some(Admitted {
            src: admit.src,
            user: user.to_string(),
            check_period: admit.check_period,
            ticket_hash,
            frame,
            recording,
            cert: Some(CertSession {
                client_node: admit.client_node,
                stop,
                pty: admit.pty,
            }),
        });
        Auth::Accept
    }

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
            &self.host_key,
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
                    cert: None,
                });
                Auth::Accept
            }
            Err(refused) => {
                self.audit_refuse(&refused);
                Auth::reject()
            }
        }
    }

    fn exec_command(&self, command: &str) -> Option<(u32, Vec<u8>)> {
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

    /// Start a PTY shell. Return false when the server refuses it.
    ///
    /// The server refuses a shell without a PTY request.
    /// When the rule requires a recording and the file does not open,
    /// the server refuses the shell and audits the deny.
    fn start_shell(&mut self, channel: ChannelId, handle: russh::server::Handle) -> bool {
        let Some(admitted) = self.admitted.clone() else {
            return false;
        };
        if self.shell.is_some() {
            return false;
        }
        let Some(spec) = self.pty.clone() else {
            self.audit_refuse(&RefusedLogin {
                peer: admitted.src,
                reason: orblx_audit::DenyReason::Destination,
                ticket_hash: admitted.ticket_hash,
            });
            return false;
        };
        if let Err(refused) = recheck(&self.shared, &admitted) {
            self.audit_refuse(&refused);
            return false;
        }
        let mut recorder = None;
        if admitted.recording {
            match Recorder::create_sized(
                &self.shared.state_dir,
                admitted.frame,
                &admitted.user,
                spec.cols,
                spec.rows,
                Some(&spec.term),
            ) {
                Ok(opened) => recorder = Some(opened),
                Err(_) => {
                    eprintln!("The SSH session recording did not open. The session is refused.");
                    self.audit_refuse(&self.recording_refused(&admitted));
                    return false;
                }
            }
        }
        let started = Instant::now();
        let shell = match crate::pty::spawn_shell(&spec, &admitted.user) {
            Ok(shell) => shell,
            Err(_) => {
                eprintln!("The SSH shell did not start.");
                self.audit_refuse(&RefusedLogin {
                    peer: admitted.src,
                    reason: orblx_audit::DenyReason::Destination,
                    ticket_hash: admitted.ticket_hash,
                });
                return false;
            }
        };
        let Ok(writer) = shell.master.try_clone() else {
            let mut shell = shell;
            let _ = shell.child.kill();
            let _ = shell.child.wait();
            return false;
        };
        let live = Arc::new(LiveShell {
            writer: Mutex::new(writer),
            pid: shell.child.id(),
            started,
            record: Mutex::new(recorder.map(|recorder| ShellRecord {
                recorder,
                input: Utf8Carry::default(),
                output: Utf8Carry::default(),
                hidden: false,
            })),
            failed: Mutex::new(None),
        });
        self.audit_event(SessionEvent::Start {
            ids: session_ids(&admitted),
            at_unix: unix_now(),
        });
        self.shell = Some(Arc::clone(&live));
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<ShellOut>(64);
        let pump_shell = Arc::clone(&live);
        tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                match message {
                    ShellOut::Data(bytes) => {
                        if handle.data(channel, Bytes::from(bytes)).await.is_err() {
                            kill_group(pump_shell.pid, libc::SIGHUP);
                        }
                    }
                    ShellOut::Exit(code) => {
                        let _ = handle.exit_status_request(channel, code).await;
                        let _ = handle.eof(channel).await;
                        let _ = handle.close(channel).await;
                        break;
                    }
                }
            }
        });
        let owner = self.clone();
        let spawned = thread::Builder::new()
            .name("orblx-ssh-pty".to_string())
            .spawn(move || owner.run_shell(&live, shell, &admitted, &sender));
        spawned.is_ok()
    }

    /// Move the shell output to the client until the shell ends.
    /// Then write the recording hash and the end into the audit chain.
    fn run_shell(
        &self,
        live: &LiveShell,
        mut shell: PtyShell,
        admitted: &Admitted,
        sender: &tokio::sync::mpsc::Sender<ShellOut>,
    ) {
        let period = Duration::from_secs(admitted.check_period.max(1));
        let mut next_check = Instant::now() + period;
        let mut watch = DenyWatch::new(&self.shared);
        let mut buf = [0u8; 4096];
        let mut eof = false;
        let mut exit: Option<(std::process::ExitStatus, Instant)> = None;
        loop {
            if !eof && crate::pty::readable(&shell.master, 50) {
                match shell.master.read(&mut buf) {
                    Ok(0) => eof = true,
                    Ok(len) => {
                        let chunk = &buf[..len];
                        if live.output(chunk)
                            && sender
                                .blocking_send(ShellOut::Data(chunk.to_vec()))
                                .is_err()
                        {
                            kill_group(live.pid, libc::SIGHUP);
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => eof = true,
                }
            } else if eof {
                thread::sleep(Duration::from_millis(20));
            }
            if exit.is_none() {
                match shell.child.try_wait() {
                    Ok(Some(status)) => exit = Some((status, Instant::now())),
                    Ok(None) => {}
                    Err(_) => {
                        live.fail(orblx_audit::DenyReason::Destination);
                    }
                }
            }
            if let Some((_, at)) = exit {
                if eof || at.elapsed() > Duration::from_millis(500) {
                    break;
                }
            }
            if Instant::now() >= next_check {
                next_check += period;
                if recheck(&self.shared, admitted).is_err() {
                    live.fail(orblx_audit::DenyReason::Revoked);
                }
            }
            if watch.denied(&self.shared, admitted) {
                live.fail(orblx_audit::DenyReason::Revoked);
            }
        }
        // A process that the shell left behind can keep the terminal open.
        kill_group(live.pid, libc::SIGKILL);
        let code = exit
            .and_then(|(status, _)| status.code())
            .and_then(|code| u32::try_from(code).ok())
            .unwrap_or(1);
        let failed = live
            .failed
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take();
        let record = live
            .record
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take();
        let mut ok = true;
        if failed == Some(orblx_audit::DenyReason::Recording) {
            eprintln!("The SSH session recording did not write. The session is stopped.");
            self.audit_refuse(&self.recording_refused(admitted));
            ok = false;
        } else if let Some(state) = record {
            match state.recorder.finish() {
                Ok((file, sha256)) => {
                    ok = self.audit_event(SessionEvent::Record {
                        ids: session_ids(admitted),
                        at_unix: unix_now(),
                        file,
                        sha256,
                    });
                }
                Err(_) => {
                    eprintln!("The SSH session recording did not close. The session is refused.");
                    self.audit_refuse(&self.recording_refused(admitted));
                    ok = false;
                }
            }
        }
        match failed {
            Some(orblx_audit::DenyReason::Recording) => {}
            Some(reason) => {
                self.audit_refuse(&RefusedLogin {
                    peer: admitted.src.clone(),
                    reason,
                    ticket_hash: admitted.ticket_hash,
                });
            }
            None if ok => {
                self.audit_event(SessionEvent::End {
                    ids: session_ids(admitted),
                    at_unix: unix_now(),
                });
            }
            None => {}
        }
        let code = if ok && failed.is_none() { code } else { 1 };
        let _ = sender.blocking_send(ShellOut::Exit(code));
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

/// The time between two reads of `deny.json` for an open session (W25-2).
const DENY_WATCH: Duration = Duration::from_millis(100);

/// Watch `deny.json` for a revoke of an open session (W25-2).
///
/// The full recheck runs at each checkPeriod. The watch reads only the deny file,
/// each `DENY_WATCH`, and parses it only when the text changes. When the file
/// denies the source or this node, the session stops. Thus a revoke-all stops an
/// open session within one node deny fetch plus one watch period.
struct DenyWatch {
    path: PathBuf,
    next: Instant,
    last: Option<Vec<u8>>,
}

impl DenyWatch {
    fn new(shared: &Shared) -> Self {
        Self {
            path: shared.state_dir.join("deny.json"),
            next: Instant::now(),
            last: None,
        }
    }

    /// Return true when a new deny file text denies the session.
    fn denied(&mut self, shared: &Shared, admitted: &Admitted) -> bool {
        if let Some(cert) = &admitted.cert {
            if cert.stop.load(Ordering::Relaxed) {
                return true;
            }
        }
        let now = Instant::now();
        if now < self.next {
            return false;
        }
        self.next = now + DENY_WATCH;
        let Ok(bytes) = fs::read(&self.path) else {
            return false;
        };
        if self.last.as_deref() == Some(bytes.as_slice()) {
            return false;
        }
        let mut deny = DenySet::empty();
        let parsed = deny.apply_json(&bytes).is_ok();
        self.last = Some(bytes);
        parsed
            && (deny.reject_uri(&admitted.src).is_err()
                || deny.reject_uri(&shared.node_id).is_err()
                || admitted
                    .cert
                    .as_ref()
                    .is_some_and(|cert| deny.reject_uri(&cert.client_node).is_err()))
    }
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
    if let Some(cert) = &admitted.cert {
        if cert.stop.load(Ordering::Relaxed) || deny.reject_uri(&cert.client_node).is_err() {
            return Err(RefusedLogin {
                peer: admitted.src.clone(),
                reason: orblx_audit::DenyReason::Revoked,
                ticket_hash: admitted.ticket_hash,
            });
        }
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
    let mut watch = DenyWatch::new(shared);
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
        if watch.denied(shared, admitted) {
            return fail(&mut child, orblx_audit::DenyReason::Revoked);
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
    // W25-31: user certificates from the coordinator SSH user CA. A plain key gets deny.
    methods.push(MethodKind::PublicKey);
    spawn_revoke_watch(&shared);
    current_host_key(&shared)?;
    loop {
        let (socket, peer) = listener
            .accept()
            .await
            .map_err(|_| "The SSH server did not accept a session.".to_string())?;
        // The SVID renewal writes a new node key. Each connection reads the current key, so
        // the host key matches the current cert.pem that the client pins.
        let (private, host_key) = match current_host_key(&shared) {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("{err} The SSH session is refused.");
                continue;
            }
        };
        let config = Arc::new(russh::server::Config {
            methods: methods.clone(),
            auth_rejection_time: Duration::from_millis(20),
            auth_rejection_time_initial: Some(Duration::from_millis(1)),
            keys: vec![private],
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        });
        let handler = SshHandler {
            shared: Arc::clone(&shared),
            host_key,
            peer: Some(peer),
            admitted: None,
            pty: None,
            shell: None,
        };
        tokio::spawn(async move {
            let _ = russh::server::run_stream(config, socket, handler).await;
        });
    }
}

/// The time between two reads of `netmap.json` for revoked certificates (W25-31).
const REVOKE_WATCH: Duration = Duration::from_millis(100);

/// Stop each open session of a revoked certificate (W25-31).
///
/// The thread reads `netmap.json` each [`REVOKE_WATCH`], and parses it only when the text
/// changes. It sets the stop flag of each session whose serial or key ID is in `ssh_revoked`.
/// The session loops then stop the command or the shell at once.
fn spawn_revoke_watch(shared: &Arc<Shared>) {
    let weak = Arc::downgrade(shared);
    let _ = thread::Builder::new()
        .name("orblx-ssh-revoke".to_string())
        .spawn(move || {
            let mut last: Option<Vec<u8>> = None;
            loop {
                thread::sleep(REVOKE_WATCH);
                let Some(shared) = weak.upgrade() else {
                    return;
                };
                let Ok(bytes) = fs::read(shared.state_dir.join("netmap.json")) else {
                    continue;
                };
                if last.as_deref() == Some(bytes.as_slice()) {
                    continue;
                }
                if let Ok(netmap) = orblx_datapath::Netmap::from_slice(&bytes) {
                    stop_revoked(&shared, &netmap.ssh_revoked);
                }
                last = Some(bytes);
            }
        });
}

/// Set the stop flag of each open session with a revoked serial or key ID.
/// Return the number of stopped sessions.
fn stop_revoked(shared: &Shared, revoked: &[orblx_datapath::SshRevoked]) -> usize {
    let serials: BTreeSet<u64> = revoked.iter().map(|item| item.serial).collect();
    let key_ids: BTreeSet<&str> = revoked.iter().map(|item| item.key_id.as_str()).collect();
    let mut stopped = 0;
    let mut sessions = shared
        .cert_sessions
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    for (serial, list) in sessions.iter_mut() {
        list.retain(|(_, weak)| weak.strong_count() > 0);
        for (key_id, weak) in list.iter() {
            if !serials.contains(serial) && !key_ids.contains(key_id.as_str()) {
                continue;
            }
            if let Some(stop) = weak.upgrade() {
                if !stop.swap(true, Ordering::Relaxed) {
                    stopped += 1;
                    println!("ssh certificate revoked serial {serial}. The session stops.");
                }
            }
        }
    }
    sessions.retain(|_, list| !list.is_empty());
    stopped
}

/// The audit fingerprint of one certificate: the first 16 bytes of SHA-256 of the key ID.
fn cert_hash(key_id: &str) -> [u8; 16] {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(key_id.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// The SSH host key from the current node SVID key file.
fn current_host_key(shared: &Shared) -> Result<(russh::keys::PrivateKey, [u8; 32]), String> {
    host_key_from_seed(&svid_seed(shared)?)
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
            bundle,
            verifier,
            state_dir: state_dir.to_path_buf(),
            audit: Mutex::new(AuditLog::new()),
            spent: Mutex::new(load_spent(&state_dir.join("ssh-spent.txt"))),
            frames: AtomicU32::new(1),
            cert_sessions: Mutex::new(HashMap::new()),
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

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;
    use std::time::{Duration, Instant, SystemTime};

    use orblx_audit::verify_file;
    use orblx_identity::{
        sign_ticket, DenySet, MiniCa, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
        MAX_AGENT_TTL, MAX_USER_TTL,
    };
    use tokio::net::TcpListener;

    use super::{LiveShell, Shared, ShellRecord};
    use crate::client::{run_session, SessionRequest};
    use crate::record::{Recorder, Utf8Carry};

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
            cert_login: None,
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
            cert_login: None,
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
            cert_login: None,
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
            cert_login: None,
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
            cert_login: None,
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
            cert_login: None,
        })
        .await;
        assert!(replay.is_err());

        let document = format!(
            r#"{{"version":3,"generated_at":3,"revoked_uris":["{}"],"revoked_ticket_nonces":[]}}"#,
            alice.as_uri()
        );
        // W25-2: an open session stops soon after the deny file denies the source.
        // The server runs the command on a runtime thread, so a plain thread writes the file.
        let deny_path = dir.join("deny.json");
        let deny_text = document.clone();
        let opened = std::time::Instant::now();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            std::fs::write(deny_path, deny_text).unwrap();
            std::time::Instant::now()
        });
        let open = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: alice_dir.clone(),
            peer_cert: dir.join("peer.pem"),
            command: "sleep 5; printf %s\\n late".to_string(),
            cert_login: None,
        })
        .await;
        let ended = std::time::Instant::now();
        let denied_at = writer.join().unwrap();
        assert!(
            ended.duration_since(denied_at) < Duration::from_millis(1000),
            "the open session ran {:?} after the deny",
            ended.duration_since(denied_at)
        );
        assert!(ended.duration_since(opened) < Duration::from_millis(4000));
        if let Ok(output) = &open {
            assert!(!String::from_utf8_lossy(&output.stdout).contains("late"));
            assert_ne!(output.exit_status, 0);
        }
        std::fs::write(dir.join("deny.json"), document).unwrap();
        let started = std::time::Instant::now();
        let revoked = session_within(SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node,
            identity_dir: dir.join("alice"),
            peer_cert: dir.join("peer.pem"),
            command: "printf %s\\n revoked".to_string(),
            cert_login: None,
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
    async fn a_renewed_node_key_is_the_host_key_of_the_next_session() {
        // W25-31 proof run 8: the SVID renewal writes a new node key. The client pins the key
        // of the current cert.pem. The server must present that key on the next connection.
        let dir = std::env::temp_dir().join(format!("orblx-ssh-renew-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = SystemTime::now();
        let ca = MiniCa::generate(now).unwrap();
        let node = SpiffeId::node("box").unwrap();
        let alice = SpiffeId::user("alice").unwrap();
        let first = ca
            .issue(&node, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_alice = ca
            .issue(&alice, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        std::fs::write(dir.join("cert.pem"), &first.certificate_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &first.private_key_pem).unwrap();
        std::fs::write(dir.join("bundle.pem"), ca.certificate_pem()).unwrap();
        std::fs::write(
            dir.join("policy.hujson"),
            r#"{"ssh": [{"src": ["spiffe://orblx.local/user/alice"],
                "dst": ["spiffe://orblx.local/node/box"], "users": ["alice"],
                "checkPeriod": "30s"}]}"#,
        )
        .unwrap();
        let alice_dir = dir.join("alice");
        std::fs::create_dir_all(&alice_dir).unwrap();
        std::fs::write(alice_dir.join("bundle.pem"), ca.certificate_pem()).unwrap();
        std::fs::write(alice_dir.join("cert.pem"), &issued_alice.certificate_pem).unwrap();
        std::fs::write(alice_dir.join("key.pem"), &issued_alice.private_key_pem).unwrap();
        std::fs::write(dir.join("old-peer.pem"), &first.certificate_pem).unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = std::sync::Arc::new(Shared::load(&dir, Ipv4Addr::LOCALHOST).unwrap());
        tokio::spawn(super::accept_loop(listener, shared));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let login = |peer: &str| SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: node.clone(),
            identity_dir: alice_dir.clone(),
            peer_cert: dir.join(peer),
            command: "printf '%s\\n' \"$ORBLX_SSH_USER\"".to_string(),
            cert_login: None,
        };
        let before = session_within(login("old-peer.pem")).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&before.stdout).trim(), "alice");

        // The renewal: a new leaf with a new key, as in EnrollResult::write_state.
        let renewed = ca
            .issue(&node, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        assert_ne!(renewed.private_key_pem, first.private_key_pem);
        std::fs::write(dir.join("cert.pem"), &renewed.certificate_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &renewed.private_key_pem).unwrap();
        std::fs::write(dir.join("new-peer.pem"), &renewed.certificate_pem).unwrap();

        let after = session_within(login("new-peer.pem")).await.unwrap();
        assert_eq!(after.exit_status, 0);
        assert_eq!(String::from_utf8_lossy(&after.stdout).trim(), "alice");
        // The old key is no longer the host key.
        assert!(session_within(login("old-peer.pem")).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_rule_with_recording_writes_the_file_and_fails_closed() {
        let dir = recording_fixture("rec");
        let alice_dir = dir.join("alice");
        let node = SpiffeId::node("box").unwrap();

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
            cert_login: None,
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

    /// A node state directory with one plain rule (alice) and one rule that
    /// needs a recording (rec). The user directory is `alice`.
    fn recording_fixture(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("orblx-ssh-{tag}-{}", std::process::id()));
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
        dir
    }

    async fn start_server(dir: &std::path::Path) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shared = std::sync::Arc::new(Shared::load(dir, Ipv4Addr::LOCALHOST).unwrap());
        tokio::spawn(super::accept_loop(listener, shared));
        tokio::time::sleep(Duration::from_millis(200)).await;
        addr
    }

    async fn shell_within(
        request: crate::client::SessionRequest,
        steps: &[(&str, &[u8])],
    ) -> Result<(u32, String), String> {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&output);
        let task = tokio::spawn(crate::client::run_shell(
            request,
            crate::client::ShellTerminal {
                term: "xterm".to_string(),
                cols: 100,
                rows: 30,
            },
            receiver,
            move |bytes: &[u8]| sink.lock().unwrap().extend_from_slice(bytes),
        ));
        // Each step waits for its text in the output and then sends its input.
        for (wait_for, input) in steps {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !String::from_utf8_lossy(&output.lock().unwrap()).contains(wait_for)
                && Instant::now() < deadline
                && !task.is_finished()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if sender.send(input.to_vec()).await.is_err() {
                break;
            }
        }
        let code = match tokio::time::timeout(Duration::from_secs(20), task).await {
            Ok(Ok(result)) => result?,
            Ok(Err(_)) => return Err("The shell task failed.".to_string()),
            Err(_) => return Err("The SSH shell timed out.".to_string()),
        };
        let text = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
        Ok((code, text))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pty_shell_records_input_and_output_in_time_order() {
        let dir = recording_fixture("pty");
        let alice_dir = dir.join("alice");
        let addr = start_server(&dir).await;
        let request = |user: &str| SessionRequest {
            user: user.to_string(),
            addr,
            dst: SpiffeId::node("box").unwrap(),
            identity_dir: alice_dir.clone(),
            peer_cert: dir.join("peer.pem"),
            command: String::new(),
            cert_login: None,
        };
        // `$((...))` makes the output differ from the echo of the input.
        let steps: [(&str, &[u8]); 4] = [
            ("", b"echo pty-$((6*7))\n"),
            (
                "pty-42",
                b"stty -echo; echo hide-$((2+3)); read -r s; stty echo; echo got-${#s}\n",
            ),
            ("hide-5", b"hidden-w23\n"),
            ("got-10", b"exit\n"),
        ];

        let (code, text) = shell_within(request("rec"), &steps).await.unwrap();
        assert_eq!(code, 0);
        assert!(text.contains("pty-42"), "{text}");
        assert!(text.contains("got-10"), "{text}");
        let records: Vec<_> = std::fs::read_dir(dir.join(crate::record::RECORD_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(records.len(), 1);
        let cast = std::fs::read_to_string(&records[0]).unwrap();
        let mut lines = cast.lines();
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["width"], 100);
        assert_eq!(header["env"]["TERM"], "xterm");
        let events: Vec<serde_json::Value> = lines
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let times: Vec<f64> = events.iter().map(|row| row[0].as_f64().unwrap()).collect();
        assert!(times.windows(2).all(|pair| pair[0] <= pair[1]));
        let first_input = events
            .iter()
            .position(|row| row[1] == "i" && row[2].as_str().unwrap().contains("echo pty-"))
            .unwrap();
        let answer = events
            .iter()
            .position(|row| row[1] == "o" && row[2].as_str().unwrap().contains("pty-42"))
            .unwrap();
        assert!(first_input < answer);
        assert!(events
            .iter()
            .any(|row| row[1] == "m" && row[2] == "input hidden"));
        assert!(!cast.contains("hidden-w23"));
        assert!(!cast.contains("PRIVATE KEY"));
        let checked = verify_file(&dir.join("ssh-audit.jsonl")).unwrap();
        assert_eq!(checked.metrics.record, 1);

        let original = std::fs::read(&records[0]).unwrap();
        let mut changed = original.clone();
        let last = changed.len() - 2;
        changed[last] ^= 0x01;
        std::fs::write(&records[0], &changed).unwrap();
        assert!(verify_file(&dir.join("ssh-audit.jsonl")).is_err());
        std::fs::write(&records[0], &original).unwrap();
        assert!(verify_file(&dir.join("ssh-audit.jsonl")).is_ok());

        let (code, text) = shell_within(
            request("alice"),
            &[
                ("", b"echo plain-$ORBLX_SSH_USER\n"),
                ("plain-alice", b"exit\n"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(code, 0);
        assert!(text.contains("plain-alice"), "{text}");
        assert_eq!(
            std::fs::read_dir(dir.join(crate::record::RECORD_DIR))
                .unwrap()
                .count(),
            1
        );

        std::fs::rename(
            dir.join(crate::record::RECORD_DIR),
            dir.join("recordings-moved"),
        )
        .unwrap();
        std::fs::write(dir.join(crate::record::RECORD_DIR), b"not a directory").unwrap();
        assert!(shell_within(request("rec"), &[("", b"exit\n")])
            .await
            .is_err());
        let chain = std::fs::read_to_string(dir.join("ssh-audit.jsonl")).unwrap();
        assert!(chain.contains("\"reason\":\"recording\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shell_stops_when_a_recording_write_fails() {
        let spec = crate::pty::PtySpec::from_request("xterm", 80, 24);
        let mut shell = crate::pty::spawn_shell(&spec, "rec").unwrap();
        // A file that is open only for read fails each write.
        let path = std::env::temp_dir().join(format!("orblx-ssh-ro-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let full = std::fs::File::open(&path).unwrap();
        let live = LiveShell {
            writer: Mutex::new(shell.master.try_clone().unwrap()),
            pid: shell.child.id(),
            started: Instant::now(),
            record: Mutex::new(Some(ShellRecord {
                recorder: Recorder::from_file_for_test(full, path.clone()),
                input: Utf8Carry::default(),
                output: Utf8Carry::default(),
                hidden: false,
            })),
            failed: Mutex::new(None),
        };
        live.input(b"echo never\n");
        assert_eq!(
            *live.failed.lock().unwrap(),
            Some(orblx_audit::DenyReason::Recording)
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stopped = false;
        while Instant::now() < deadline {
            if shell.child.try_wait().unwrap().is_some() {
                stopped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(stopped, "the shell did not stop");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_login_needs_the_netmap_ca_and_the_key_and_a_revoke_ends_the_session() {
        use crate::cert::testkit;
        let dir = recording_fixture("cert");
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ca = testkit::key(11);
        testkit::write_netmap(&dir, &[testkit::ca_line(&ca)], &[], now);
        let addr = start_server(&dir).await;
        let key = testkit::key(12);
        let spec = testkit::Spec::user("oidc:alice", "laptop", 501, now);
        let cert = testkit::sign(&ca, &key, &spec);
        let request = |login: crate::client::CertLogin| SessionRequest {
            user: "alice".to_string(),
            addr,
            dst: SpiffeId::node("box").unwrap(),
            identity_dir: dir.join("alice"),
            peer_cert: dir.join("peer.pem"),
            command: "printf '%s\\n' \"$ORBLX_SSH_USER\"".to_string(),
            cert_login: Some(login),
        };
        let login = |key: &russh::keys::PrivateKey, cert: &russh::keys::Certificate| {
            crate::client::CertLogin {
                key: key.clone(),
                cert: cert.clone(),
            }
        };

        let ok = session_within(request(login(&key, &cert))).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&ok.stdout), "alice\n");
        assert_eq!(ok.exit_status, 0);
        // A wrong private key for the certificate gives deny.
        assert!(session_within(request(login(&testkit::key(13), &cert)))
            .await
            .is_err());
        // A certificate from a CA that is not in the netmap gives deny.
        let foreign = testkit::sign(&testkit::key(14), &key, &spec);
        assert!(session_within(request(login(&key, &foreign)))
            .await
            .is_err());
        // A CA that rotated out of the netmap gives deny at once.
        testkit::write_netmap(&dir, &[testkit::ca_line(&testkit::key(15))], &[], now);
        assert!(session_within(request(login(&key, &cert))).await.is_err());
        testkit::write_netmap(&dir, &[testkit::ca_line(&ca)], &[], now);
        assert!(session_within(request(login(&key, &cert))).await.is_ok());

        // A revoked serial in the netmap ends the open shell session.
        let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&output);
        let task = tokio::spawn(crate::client::run_shell(
            request(login(&key, &cert)),
            crate::client::ShellTerminal {
                term: "xterm".to_string(),
                cols: 80,
                rows: 24,
            },
            receiver,
            move |bytes: &[u8]| sink.lock().unwrap().extend_from_slice(bytes),
        ));
        sender
            .send(b"echo ready-$((40+2))\n".to_vec())
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !String::from_utf8_lossy(&output.lock().unwrap()).contains("ready-42") {
            assert!(Instant::now() < deadline, "the shell did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let revoked = orblx_datapath::SshRevoked {
            serial: spec.serial,
            key_id: spec.key_id.clone(),
        };
        let start = Instant::now();
        testkit::write_netmap(&dir, &[testkit::ca_line(&ca)], &[revoked], now);
        let ended = tokio::time::timeout(Duration::from_secs(60), task).await;
        let elapsed = start.elapsed();
        println!("revoke to session end ms {}", elapsed.as_millis());
        assert!(ended.is_ok(), "the session did not end in 60 s");
        assert!(elapsed < Duration::from_secs(60));
        drop(sender);
        // A new login with the revoked certificate gives deny.
        assert!(session_within(request(login(&key, &cert))).await.is_err());
        // A stale netmap refuses a new certificate login.
        let fresh = testkit::Spec::user("oidc:alice", "laptop", 502, now);
        let fresh_cert = testkit::sign(&ca, &key, &fresh);
        let ca_lines = [testkit::ca_line(&ca)];
        testkit::write_netmap_at(&dir, &ca_lines, &[], (now - 120) * 1000);
        assert!(session_within(request(login(&key, &fresh_cert)))
            .await
            .is_err());
        let chain = std::fs::read_to_string(dir.join("ssh-audit.jsonl")).unwrap();
        assert!(chain.contains("\"reason\":\"revoked\""), "{chain}");
        assert!(verify_file(&dir.join("ssh-audit.jsonl")).is_ok());
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
