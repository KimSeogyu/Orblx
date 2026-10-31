//! `orblx ssh`.
//!
//! The client signs in with an SVID.
//! The client does not read or write an SSH key file.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use orblx_datapath::Netmap;
use orblx_identity::SpiffeId;
use orblx_ssh::{
    local_terminal_size, run_session, run_shell, CertLogin, RawMode, SessionRequest, ShellTerminal,
    SSH_PORT,
};

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
    /// W25-31: the node state directory. The client then signs in with a user certificate
    /// from the coordinator.
    state: Option<PathBuf>,
    peer_cert: PathBuf,
    command: String,
    shell: bool,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let mut target = None;
    let mut identity = None;
    let mut netmap = None;
    let mut state = None;
    let mut peer_cert = None;
    let mut command = None;
    let mut shell = false;
    let mut index = 0;
    while index < args.len() {
        let item = args[index].as_str();
        if item == "--shell" {
            shell = true;
            index += 1;
        } else if item.starts_with('-') {
            index += 1;
            let value = take_value(args, &mut index)?;
            match item {
                "--identity" => identity = Some(PathBuf::from(value)),
                "--netmap" => netmap = Some(PathBuf::from(value)),
                "--state" => state = Some(PathBuf::from(value)),
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
    let (identity, netmap) = match &state {
        Some(dir) => {
            if identity.is_some() || netmap.is_some() {
                return Err(format!(
                    "The flag --state does not go with --identity or --netmap.\n{}",
                    help()
                ));
            }
            (dir.clone(), dir.join("netmap.json"))
        }
        None => (
            identity.ok_or_else(|| format!("The command needs --identity.\n{}", help()))?,
            netmap.ok_or_else(|| format!("The command needs --netmap.\n{}", help()))?,
        ),
    };
    let peer_cert =
        peer_cert.ok_or_else(|| format!("The command needs --peer-cert.\n{}", help()))?;
    if shell && command.is_some() {
        return Err(format!(
            "The flags --shell and --command do not go together.\n{}",
            help()
        ));
    }
    Ok(Command::Session(SessionOptions {
        user,
        node,
        identity,
        netmap,
        state,
        peer_cert,
        command: command.unwrap_or_else(|| DEFAULT_COMMAND.to_string()),
        shell,
    }))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Session(options) if options.shell => {
            let code = run_shell_blocking(options)?;
            if code != 0 {
                return Err(format!("The SSH shell exited with status {code}."));
            }
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
        let cert_login = cert_login(options.state.as_deref())?;
        run_session(SessionRequest {
            user: options.user,
            addr,
            dst,
            identity_dir: options.identity,
            peer_cert: options.peer_cert,
            command: options.command,
            cert_login,
        })
        .await
    })
}

fn run_shell_blocking(options: SessionOptions) -> Result<u32, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "The SSH client did not start.".to_string())?;
    let netmap = Netmap::from_path(&options.netmap).map_err(|err| err.to_string())?;
    let (addr, dst) = locate(&netmap, &options.node)?;
    let cert_login = cert_login(options.state.as_deref())?;
    let (cols, rows) = local_terminal_size();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());
    let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(len) => {
                    if sender.blocking_send(buf[..len].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let raw = RawMode::enable();
    let result = runtime.block_on(run_shell(
        SessionRequest {
            user: options.user,
            addr,
            dst,
            identity_dir: options.identity,
            peer_cert: options.peer_cert,
            command: String::new(),
            cert_login,
        },
        ShellTerminal { term, cols, rows },
        receiver,
        |bytes| {
            let mut stdout = io::stdout();
            let _ = stdout.write_all(bytes);
            let _ = stdout.flush();
        },
    ));
    drop(raw);
    result
}

/// Ask the coordinator for one user certificate with the node SVID (W25-31).
///
/// Only root may ask: the node SVID key is root-only. The client makes a new key in memory.
/// The coordinator takes the user from the owner of this node. The request names no user.
fn cert_login(state: Option<&Path>) -> Result<Option<CertLogin>, String> {
    let Some(state) = state else {
        return Ok(None);
    };
    orblx_ssh::cert::require_root_caller(state)?;
    let coord: SocketAddr = fs::read_to_string(state.join("coord-addr"))
        .map_err(|_| "The node has no coordinator address.".to_string())?
        .trim()
        .parse()
        .map_err(|_| "The coordinator address is not valid.".to_string())?;
    let coord_name = fs::read_to_string(state.join("coord-name"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "coord".to_string());
    let bundle = fs::read_to_string(state.join("bundle.pem"))
        .map_err(|_| "The trust bundle did not open.".to_string())?;
    let key = orblx_coord::sshca::new_session_key();
    // The request runs its own runtime. Run it on a plain thread.
    let request_key = key.clone();
    let request_state = state.to_path_buf();
    let text = std::thread::spawn(move || {
        orblx_coord::ssh_cert_request_blocking(
            coord,
            &coord_name,
            &bundle,
            &request_state,
            &request_key,
        )
    })
    .join()
    .map_err(|_| "The SSH certificate request failed.".to_string())?
    .map_err(|err| err.public_text())?;
    let cert = orblx_ssh::SshUserCert::from_openssh(&text)
        .map_err(|_| "The SSH certificate is not valid.".to_string())?;
    Ok(Some(CertLogin { key, cert }))
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
orblx ssh USER@NODE --identity DIR --netmap FILE --peer-cert FILE [--command TEXT | --shell]
orblx ssh USER@NODE --state DIR --peer-cert FILE [--command TEXT | --shell]

With --state, the client asks the coordinator for one short SSH user certificate with the
node SVID in DIR, and signs in with that certificate. Only root can use --state.
The certificate names the user who owns this node. Do not enroll a multi-user host as a
personal node.

The client connects to the node overlay address on port 22.
The client checks the SSH host key against the node SVID in --peer-cert.
The client signs the login with the SVID in --identity.
An agent directory also holds ticket.bin.
The ticket is one shot for one host.
The command does not read authorized_keys.
The command does not write an SSH key file.
The default command prints ORBLX_SSH_USER.
--shell asks for a PTY and an interactive shell.
The client sends standard input to the shell and prints the shell output.
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

    #[test]
    fn the_shell_flag_takes_no_value_and_refuses_a_command() {
        let base = [
            "alice@box",
            "--shell",
            "--identity",
            "id",
            "--netmap",
            "netmap.json",
            "--peer-cert",
            "peer.pem",
        ];
        let args: Vec<String> = base.iter().map(|item| item.to_string()).collect();
        match parse(&args).unwrap() {
            Command::Session(options) => assert!(options.shell),
            Command::Help => panic!("the parser did not select a session"),
        }
        let mut both = args.clone();
        both.push("--command".to_string());
        both.push("id".to_string());
        assert!(parse(&both).is_err());
    }
}
