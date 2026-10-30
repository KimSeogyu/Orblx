//! `orblx ssh` client.
//!
//! The client checks the server host key against the node SVID.
//! The client sends one SVID proof.
//! The client does not write an SSH key file.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use orblx_identity::{
    decode_certificate_pem, ed25519_public_key_from_certificate_pem, DenySet, SpiffeId, TrustBundle,
};
use russh::client::{self, Handler};
use russh::keys::PublicKeyOrCertificate;
use russh::{ChannelMsg, Disconnect};

use crate::auth::{command_ok, seal_login};
use crate::hostkey::ed25519_public_bytes;

/// One SSH command.
pub struct SessionRequest {
    /// Login name.
    pub user: String,
    /// Overlay socket.
    pub addr: SocketAddr,
    /// Destination node SPIFFE ID.
    pub dst: SpiffeId,
    /// Directory with `cert.pem`, `key.pem`, `bundle.pem`, and an optional `ticket.bin`.
    pub identity_dir: PathBuf,
    /// Node SVID certificate PEM.
    pub peer_cert: PathBuf,
    /// Remote command.
    pub command: String,
}

/// Remote command output.
pub struct SessionOutput {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Process status.
    pub exit_status: u32,
}

/// Open one SSH session and run the command.
pub async fn run_session(request: SessionRequest) -> Result<SessionOutput, String> {
    if !command_ok(&request.command) {
        return Err("The SSH command is not valid.".to_string());
    }
    let (handle, mut channel) = open_channel(&request).await?;
    channel
        .exec(true, request.command.into_bytes())
        .await
        .map_err(|_| "The SSH command did not start.".to_string())?;
    let mut stdout = Vec::new();
    let mut exit_status = 1u32;
    let mut saw_exit = false;
    let mut saw_eof = false;
    loop {
        let Some(message) = channel.wait().await else {
            break;
        };
        match message {
            ChannelMsg::Data { data } => append_capped(&mut stdout, &data),
            ChannelMsg::ExitStatus { exit_status: code } => {
                exit_status = code;
                saw_exit = true;
            }
            ChannelMsg::Eof => saw_eof = true,
            ChannelMsg::Close => break,
            ChannelMsg::Failure => {
                return Err("The SSH command did not start.".to_string());
            }
            _ => {}
        }
        if saw_exit && saw_eof {
            break;
        }
    }
    let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
    Ok(SessionOutput {
        stdout,
        exit_status,
    })
}

/// The terminal of one shell session.
pub struct ShellTerminal {
    /// Terminal type, for example `xterm`.
    pub term: String,
    /// Columns.
    pub cols: u32,
    /// Rows.
    pub rows: u32,
}

/// Open one SSH session with a PTY and a shell.
///
/// The function sends each chunk from `input` to the shell and gives each
/// output chunk to `output`. It returns the exit status of the shell.
/// The `command` field of the request is not used.
pub async fn run_shell(
    request: SessionRequest,
    terminal: ShellTerminal,
    mut input: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut output: impl FnMut(&[u8]) + Send,
) -> Result<u32, String> {
    let (handle, mut channel) = open_channel(&request).await?;
    channel
        .request_pty(
            true,
            &terminal.term,
            terminal.cols,
            terminal.rows,
            0,
            0,
            &[],
        )
        .await
        .map_err(|_| "The SSH shell did not start.".to_string())?;
    channel
        .request_shell(true)
        .await
        .map_err(|_| "The SSH shell did not start.".to_string())?;
    let mut writer = channel.make_writer();
    let mut input_open = true;
    let mut exit_status = 1u32;
    let mut started = false;
    let mut replies = 0u8;
    loop {
        tokio::select! {
            message = channel.wait() => {
                let Some(message) = message else {
                    break;
                };
                match message {
                    ChannelMsg::Data { data } => output(&data),
                    ChannelMsg::ExitStatus { exit_status: code } => exit_status = code,
                    // The first reply is for the PTY and the second is for the shell.
                    ChannelMsg::Success if !started => {
                        replies += 1;
                        started = replies == 2;
                    }
                    ChannelMsg::Failure if !started => {
                        return Err("The SSH shell was refused.".to_string());
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            chunk = input.recv(), if input_open => {
                match chunk {
                    Some(bytes) => {
                        if tokio::io::AsyncWriteExt::write_all(&mut writer, &bytes).await.is_err() {
                            break;
                        }
                    }
                    None => input_open = false,
                }
            }
        }
    }
    let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
    if !started {
        return Err("The SSH shell was refused.".to_string());
    }
    Ok(exit_status)
}

async fn open_channel(
    request: &SessionRequest,
) -> Result<(client::Handle<ClientHandler>, russh::Channel<client::Msg>), String> {
    let cert_pem = read_text(&request.identity_dir.join("cert.pem"))?;
    let key_pem = read_text(&request.identity_dir.join("key.pem"))?;
    let bundle_pem = read_text(&request.identity_dir.join("bundle.pem"))?;
    let peer_pem = read_text(&request.peer_cert)?;
    let bundle = TrustBundle::from_pem(&bundle_pem)
        .map_err(|_| "The trust bundle is not valid.".to_string())?;
    let peer_der =
        decode_certificate_pem(&peer_pem).map_err(|_| "The node SVID is not valid.".to_string())?;
    let peer_id = bundle
        .authenticate_leaf(&peer_der, SystemTime::now(), &DenySet::empty())
        .map_err(|_| "The node SVID is not valid.".to_string())?;
    if peer_id != request.dst {
        return Err("The node SVID does not match the destination.".to_string());
    }
    let host_key = ed25519_public_key_from_certificate_pem(&peer_pem)
        .map_err(|_| "The node SVID is not valid.".to_string())?;
    let leaf_der =
        decode_certificate_pem(&cert_pem).map_err(|_| "The SVID is not valid.".to_string())?;
    let ticket = fs::read(request.identity_dir.join("ticket.bin")).ok();
    let password = seal_login(
        &key_pem,
        &leaf_der,
        &host_key,
        &request.user,
        &request.dst,
        SystemTime::now(),
        ticket.as_deref(),
    )?;
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        ..client::Config::default()
    });
    let handler = ClientHandler { expect: host_key };
    let mut handle = client::connect(config, request.addr, handler)
        .await
        .map_err(|_| "The SSH session did not open.".to_string())?;
    let auth = handle
        .authenticate_password(&request.user, password)
        .await
        .map_err(|_| "The SSH session did not open.".to_string())?;
    if !auth.success() {
        return Err("The SSH session was refused.".to_string());
    }
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|_| "The SSH session did not open.".to_string())?;
    Ok((handle, channel))
}

fn append_capped(stdout: &mut Vec<u8>, data: &[u8]) {
    if stdout.len() >= 4096 {
        return;
    }
    let room = 4096 - stdout.len();
    let take = data.len().min(room);
    stdout.extend_from_slice(&data[..take]);
}

fn read_text(path: &std::path::Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|_| format!("The file {} did not open.", path.display()))
}

struct ClientHandler {
    expect: [u8; 32],
}

impl Handler for ClientHandler {
    type Error = ClientFail;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // The host key is a raw Ed25519 key. The client refuses an SSH certificate.
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            return Ok(false);
        };
        Ok(ed25519_public_bytes(key) == Some(self.expect))
    }
}

/// Client failure text.
///
/// The text does not include keys or proofs.
#[derive(Debug)]
struct ClientFail;

impl std::fmt::Display for ClientFail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("The SSH session failed.")
    }
}

impl std::error::Error for ClientFail {}

impl From<russh::Error> for ClientFail {
    fn from(_err: russh::Error) -> Self {
        Self
    }
}

/// Raw mode for the local terminal of a shell session.
///
/// The guard puts the old terminal mode back when it drops.
pub struct RawMode {
    saved: libc::termios,
}

impl RawMode {
    /// Put standard input in raw mode. Return `None` when it is not a terminal.
    pub fn enable() -> Option<Self> {
        // SAFETY: isatty reads only the descriptor number.
        if unsafe { libc::isatty(0) } != 1 {
            return None;
        }
        // SAFETY: termios is plain data. tcgetattr fills it.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: descriptor 0 is open and the pointer is valid.
        if unsafe { libc::tcgetattr(0, &mut saved) } != 0 {
            return None;
        }
        let mut raw = saved;
        // SAFETY: the pointer is valid.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: descriptor 0 is open and the pointer is valid.
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: descriptor 0 is open and the pointer is valid.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.saved);
        }
    }
}

/// Return the size of the local terminal, or 80 x 24.
pub fn local_terminal_size() -> (u32, u32) {
    // SAFETY: winsize is plain data. ioctl fills it.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: descriptor 1 is open and the pointer is valid.
    let status = unsafe { libc::ioctl(1, libc::TIOCGWINSZ as _, &mut size) };
    if status != 0 || size.ws_col == 0 || size.ws_row == 0 {
        return (80, 24);
    }
    (u32::from(size.ws_col), u32::from(size.ws_row))
}
