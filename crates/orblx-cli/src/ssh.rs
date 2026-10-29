//! `orblx ssh`.
//!
//! The client signs in with an SVID.
//! The client does not read or write an SSH key file.

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use orblx_datapath::Netmap;
use orblx_identity::SpiffeId;
use orblx_ssh::{run_session, SessionRequest, SSH_PORT};

use super::take_value;

const DEFAULT_COMMAND: &str = "printf '%s\\n' \"$ORBLX_SSH_USER\"";

/// An SSH command.
#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Session(SessionOptions),
}

#[derive(Debug)]
pub(crate) struct SessionOptions {
    user: String,
    node: String,
    identity: PathBuf,
    netmap: PathBuf,
    peer_cert: PathBuf,
    command: String,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let mut target = None;
    let mut identity = None;
    let mut netmap = None;
    let mut peer_cert = None;
    let mut command = None;
    let mut index = 0;
    while index < args.len() {
        let item = args[index].as_str();
        if item.starts_with('-') {
            index += 1;
            let value = take_value(args, &mut index)?;
            match item {
                "--identity" => identity = Some(PathBuf::from(value)),
                "--netmap" => netmap = Some(PathBuf::from(value)),
                "--peer-cert" => peer_cert = Some(PathBuf::from(value)),
                "--command" => command = Some(value),
                other => return Err(format!("The flag {other} is not valid.\n{}", help())),
            }
        } else {
            if target.is_some() {
                return Err(format!("The command has one target.\n{}", help()));
            }
            target = Some(item.to_string());
            index += 1;
        }
    }
    let target = target.ok_or_else(|| format!("The command needs USER@NODE.\n{}", help()))?;
    let (user, node) = split_target(&target)?;
    let identity = identity.ok_or_else(|| format!("The command needs --identity.\n{}", help()))?;
    let netmap = netmap.ok_or_else(|| format!("The command needs --netmap.\n{}", help()))?;
    let peer_cert =
        peer_cert.ok_or_else(|| format!("The command needs --peer-cert.\n{}", help()))?;
    Ok(Command::Session(SessionOptions {
        user,
        node,
        identity,
        netmap,
        peer_cert,
        command: command.unwrap_or_else(|| DEFAULT_COMMAND.to_string()),
    }))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Session(options) => {
            let output = run_blocking(options)?;
            let mut stdout = io::stdout();
            stdout
                .write_all(&output.stdout)
                .map_err(|_| "The SSH output was not written.".to_string())?;
            if output.exit_status != 0 {
                return Err(format!(
                    "The SSH command exited with status {}.",
                    output.exit_status
                ));
            }
            Ok(())
        }
    }
}

fn run_blocking(options: SessionOptions) -> Result<orblx_ssh::SessionOutput, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "The SSH client did not start.".to_string())?;
    runtime.block_on(async move {
        let netmap = Netmap::from_path(&options.netmap).map_err(|err| err.to_string())?;
        let (addr, dst) = locate(&netmap, &options.node)?;
        run_session(SessionRequest {
            user: options.user,
            addr,
            dst,
            identity_dir: options.identity,
            peer_cert: options.peer_cert,
            command: options.command,
        })
        .await
    })
}

fn locate(netmap: &Netmap, node: &str) -> Result<(SocketAddr, SpiffeId), String> {
    let peer = netmap
        .peers
        .iter()
        .find(|peer| peer.name == node)
        .ok_or_else(|| format!("The node {node} is not in the netmap."))?;
    let overlay: Ipv4Addr = peer
        .overlay_ip
        .parse()
        .map_err(|_| format!("The overlay address {} is not valid.", peer.overlay_ip))?;
    let dst = SpiffeId::parse(&peer.svid)
        .map_err(|_| format!("The SPIFFE ID {} is not valid.", peer.svid))?;
    Ok((SocketAddr::from((overlay, SSH_PORT)), dst))
}

fn split_target(text: &str) -> Result<(String, String), String> {
    let Some((user, node)) = text.split_once('@') else {
        return Err(format!("The target {text} is not USER@NODE.\n{}", help()));
    };
    if user.is_empty() || node.is_empty() || user.contains('@') || node.contains('@') {
        return Err(format!("The target {text} is not USER@NODE.\n{}", help()));
    }
    Ok((user.to_string(), node.to_string()))
}

fn help() -> String {
    "\
orblx ssh USER@NODE --identity DIR --netmap FILE --peer-cert FILE [--command TEXT]

The client connects to the node overlay address on port 22.
The client checks the SSH host key against the node SVID in --peer-cert.
The client signs the login with the SVID in --identity.
An agent directory also holds ticket.bin.
The ticket is one shot for one host.
The command does not read authorized_keys.
The command does not write an SSH key file.
The default command prints ORBLX_SSH_USER.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    #[test]
    fn the_parser_requires_the_svid_paths() {
        let command = parse(&[
            "alice@box".to_string(),
            "--identity".to_string(),
            "id".to_string(),
            "--netmap".to_string(),
            "netmap.json".to_string(),
            "--peer-cert".to_string(),
            "peer.pem".to_string(),
        ])
        .unwrap();
        match command {
            Command::Session(options) => {
                assert_eq!(options.user, "alice");
                assert_eq!(options.node, "box");
                assert!(options.command.contains("ORBLX_SSH_USER"));
            }
            Command::Help => panic!("the parser did not select a session"),
        }
    }
}
