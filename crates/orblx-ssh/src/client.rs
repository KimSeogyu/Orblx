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
use russh::keys::ssh_key::PublicKey;
use russh::{ChannelMsg, CryptoVec, Disconnect};

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
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|_| "The SSH session did not open.".to_string())?;
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
            ChannelMsg::ExtendedData { .. } => {}
            ChannelMsg::ExitStatus { exit_status: code } => {
                exit_status = code;
                saw_exit = true;
            }
            ChannelMsg::Eof => saw_eof = true,
            ChannelMsg::Close => break,
            ChannelMsg::Failure => {
                return Err("The SSH command did not start.".to_string());
            }
            ChannelMsg::Open { .. }
            | ChannelMsg::RequestPty { .. }
            | ChannelMsg::RequestShell { .. }
            | ChannelMsg::Exec { .. }
            | ChannelMsg::Signal { .. }
            | ChannelMsg::RequestSubsystem { .. }
            | ChannelMsg::RequestX11 { .. }
            | ChannelMsg::SetEnv { .. }
            | ChannelMsg::WindowChange { .. }
            | ChannelMsg::AgentForward { .. }
            | ChannelMsg::XonXoff { .. }
            | ChannelMsg::Success
            | ChannelMsg::ExitSignal { .. }
            | ChannelMsg::WindowAdjusted { .. }
            | ChannelMsg::OpenFailure(_) => {}
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

fn append_capped(stdout: &mut Vec<u8>, data: &CryptoVec) {
    if stdout.len() >= 4096 {
        return;
    }
    let room = 4096 - stdout.len();
    let bytes: &[u8] = data;
    let take = bytes.len().min(room);
    stdout.extend_from_slice(&bytes[..take]);
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
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(ed25519_public_bytes(server_public_key) == Some(self.expect))
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
