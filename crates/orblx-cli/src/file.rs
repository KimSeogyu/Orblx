//! `orblx file send` and `orblx file receive` (W23-3).
//!
//! The receiver admits a sender only when the coordinator-signed receiver grants
//! for this node allow the sender SPIFFE ID on TCP to the receiver port.
//! The commands print the sender, the name, the size, and the SHA-256 digest.
//! They do not print keys or signatures.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use orblx_coord::{decode_hex_32, verify_signed_grants, SignedGrants};
use orblx_datapath::Netmap;
use orblx_file::{
    name_ok, send_file, serve, FileError, Gate, ReceiverConfig, SendIdentity, DEFAULT_MAX_BYTES,
    FILE_AUDIT_FILE, FILE_PORT,
};
use orblx_identity::{decode_certificate_pem, DenyApply, DenySet, SpiffeId, TrustBundle};

use super::{parse_socket, take_value};

const DEFAULT_STATE: &str = "/var/lib/orblx";
const PROTO_TCP: u8 = 6;

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Send(SendOptions),
    Receive(ReceiveOptions),
}

#[derive(Debug)]
pub(crate) struct SendOptions {
    file: PathBuf,
    to: String,
    name: Option<String>,
    addr: Option<SocketAddr>,
    state: PathBuf,
    timeout_secs: u64,
}

#[derive(Debug)]
pub(crate) struct ReceiveOptions {
    dir: PathBuf,
    listen: Option<SocketAddr>,
    state: PathBuf,
    max_bytes: u64,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    match args[0].as_str() {
        "send" => parse_send(&args[1..]).map(Command::Send),
        "receive" => parse_receive(&args[1..]).map(Command::Receive),
        other => Err(format!("The mode {other} is not valid.\n{}", help())),
    }
}

fn parse_send(args: &[String]) -> Result<SendOptions, String> {
    let file = args
        .first()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| format!("The command needs a file.\n{}", help()))?;
    let mut options = SendOptions {
        file: PathBuf::from(file),
        to: String::new(),
        name: None,
        addr: None,
        state: PathBuf::from(DEFAULT_STATE),
        timeout_secs: 5,
    };
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].clone();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag.as_str() {
            "--to" => options.to = value,
            "--name" => options.name = Some(value),
            "--addr" => options.addr = Some(parse_socket(&value, FILE_PORT)?),
            "--state" => options.state = PathBuf::from(value),
            "--timeout" => {
                options.timeout_secs =
                    value
                        .parse()
                        .ok()
                        .filter(|secs| (1..=600).contains(secs))
                        .ok_or_else(|| "The timeout is 1 to 600 seconds.".to_string())?;
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    if options.to.is_empty() {
        return Err(format!("The command needs --to NODE.\n{}", help()));
    }
    Ok(options)
}

fn parse_receive(args: &[String]) -> Result<ReceiveOptions, String> {
    let mut options = ReceiveOptions {
        dir: PathBuf::new(),
        listen: None,
        state: PathBuf::from(DEFAULT_STATE),
        max_bytes: DEFAULT_MAX_BYTES,
    };
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].clone();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag.as_str() {
            "--dir" => options.dir = PathBuf::from(value),
            "--listen" => options.listen = Some(parse_socket(&value, FILE_PORT)?),
            "--state" => options.state = PathBuf::from(value),
            "--max-bytes" => {
                options.max_bytes = value
                    .parse()
                    .ok()
                    .filter(|bytes| *bytes > 0)
                    .ok_or_else(|| "The size limit is not valid.".to_string())?;
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    if options.dir.as_os_str().is_empty() {
        return Err(format!("The command needs --dir DIR.\n{}", help()));
    }
    Ok(options)
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Send(options) => run_send(&options),
        Command::Receive(options) => run_receive(options),
    }
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))
}

fn parse_ip(text: &str) -> Result<Ipv4Addr, String> {
    text.parse::<Ipv4Addr>()
        .map_err(|_| format!("The overlay address {text} is not valid."))
}

/// Find the receiver SPIFFE ID and overlay address in the local netmap.
fn find_peer(netmap: &Netmap, to: &str) -> Result<(SpiffeId, Ipv4Addr), String> {
    if netmap.self_node.name == to {
        let id = SpiffeId::node(to).map_err(|err| err.to_string())?;
        return Ok((id, parse_ip(&netmap.self_node.overlay_ip)?));
    }
    let peer = netmap
        .peers
        .iter()
        .find(|peer| peer.name == to)
        .ok_or_else(|| format!("The node {to} is not in the netmap."))?;
    let id = SpiffeId::parse(&peer.svid).map_err(|err| err.to_string())?;
    Ok((id, parse_ip(&peer.overlay_ip)?))
}

fn run_send(options: &SendOptions) -> Result<(), String> {
    let netmap = orblx_coord::read_node_netmap(&options.state).map_err(|err| err.public_text())?;
    let (dst, addr) = match (find_peer(&netmap, &options.to), options.addr) {
        (Ok((dst, _)), Some(addr)) => (dst, addr),
        (Ok((dst, overlay)), None) => (dst, SocketAddr::from((overlay, FILE_PORT))),
        // With --addr, a node that is not in the netmap is still a valid target name.
        (Err(_), Some(addr)) => (
            SpiffeId::node(&options.to).map_err(|err| err.to_string())?,
            addr,
        ),
        (Err(err), None) => return Err(err),
    };
    let name = match &options.name {
        Some(name) => name.clone(),
        None => options
            .file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    };
    if !name_ok(&name) {
        return Err(
            "The file name is not valid. Use A-Z a-z 0-9 . _ - and do not start with a dot."
                .to_string(),
        );
    }
    let identity = SendIdentity::from_pem(
        &read(&options.state.join("cert.pem"))?,
        &read(&options.state.join("key.pem"))?,
    )
    .map_err(|err| err.to_string())?;
    let sender = identity.spiffe_id().map_err(|err| err.to_string())?;
    let report = send_file(
        addr,
        &dst,
        &identity,
        &options.file,
        &name,
        Duration::from_secs(options.timeout_secs),
    )
    .map_err(|err| err.to_string())?;
    println!(
        "file_sent from {} to {} name {name} size {} sha256 {}",
        sender.as_uri(),
        dst.as_uri(),
        report.size,
        report.sha256
    );
    Ok(())
}

fn load_deny(path: &Path) -> DenySet {
    let mut deny = DenySet::empty();
    let Ok(bytes) = fs::read(path) else {
        return deny;
    };
    match deny.apply_json(&bytes) {
        Ok(DenyApply::Applied | DenyApply::IgnoredOlder) => deny,
        Err(_) => {
            eprintln!("The deny file is not valid.");
            DenySet::empty()
        }
    }
}

/// Load the checks for one connection from the state directory.
fn load_gate(state: &Path, self_id: &SpiffeId, port: u16) -> Result<Gate, FileError> {
    let fail = |text: &str| FileError(text.to_string());
    let bundle_pem = fs::read_to_string(state.join("bundle.pem"))
        .map_err(|_| fail("The trust bundle did not open."))?;
    let bundle =
        TrustBundle::from_pem(&bundle_pem).map_err(|_| fail("The trust bundle is not valid."))?;
    let deny = load_deny(&state.join("deny.json"));
    let public = fs::read_to_string(state.join("netmap.pub"))
        .ok()
        .and_then(|text| decode_hex_32(text.trim()).ok())
        .ok_or_else(|| fail("The netmap key did not open."))?;
    let signed: SignedGrants = fs::read(state.join("grants.signed.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| fail("The signed grants did not open."))?;
    verify_signed_grants(&signed, &public)
        .map_err(|_| fail("The grant signature is not valid."))?;
    if signed.grants.receiver != self_id.as_uri() {
        return Err(fail("The signed grants are for another node."));
    }
    let grants = signed.grants;
    Ok(Gate {
        bundle,
        deny,
        permits: Box::new(move |src: &SpiffeId| grants.permits(src, PROTO_TCP, port)),
    })
}

fn run_receive(options: ReceiveOptions) -> Result<(), String> {
    let state = options.state.clone();
    let leaf = decode_certificate_pem(&read(&state.join("cert.pem"))?)
        .map_err(|_| "The node SVID is not valid.".to_string())?;
    let self_id = orblx_identity::extract_spiffe_id(&leaf)
        .map_err(|_| "The node SVID is not valid.".to_string())?;
    let listen = match options.listen {
        Some(addr) => addr,
        None => {
            let netmap = orblx_coord::read_node_netmap(&state).map_err(|err| err.public_text())?;
            SocketAddr::from((parse_ip(&netmap.self_node.overlay_ip)?, FILE_PORT))
        }
    };
    let port = listen.port();
    load_gate(&state, &self_id, port).map_err(|err| err.to_string())?;
    let listener = TcpListener::bind(listen)
        .map_err(|err| format!("The file receiver did not bind {listen}. {err}"))?;
    println!("file_receive node {}", self_id.as_uri());
    let config = ReceiverConfig {
        self_id: self_id.clone(),
        inbox: options.dir,
        audit_path: state.join(FILE_AUDIT_FILE),
        max_bytes: options.max_bytes,
    };
    serve(listener, config, move || load_gate(&state, &self_id, port))
        .map_err(|err| err.to_string())
}

fn help() -> String {
    format!(
        "orblx file send FILE --to NODE [--name NAME] [--state DIR] [--addr IP:PORT] [--timeout SECS]
orblx file receive --dir DIR [--state DIR] [--listen IP:PORT] [--max-bytes N]

File send between your nodes (W23-3).
receive listens on the overlay address, TCP port {FILE_PORT}, and stores files in --dir.
The receiver admits a sender only when the coordinator-signed grants for this node allow
the sender on TCP to the receiver port. Add an ACL rule for port {FILE_PORT} to allow a sender.
The sender signs the receiver SPIFFE ID, the name, the size, and the SHA-256 digest with its SVID key.
The receiver stores the file only when the size and the digest match. It does not replace a file.
A refused file leaves no file and no part file. The receiver writes one record for each file
to {FILE_AUDIT_FILE} in the state directory. Use orblx audit verify-config --file FILE to check it.
The commands do not print keys or signatures."
    )
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn send_needs_a_file_and_a_node() {
        assert!(parse(&args(&["send", "--to", "b"])).is_err());
        assert!(parse(&args(&["send", "x.bin"])).is_err());
        let Command::Send(options) = parse(&args(&["send", "x.bin", "--to", "b"])).unwrap() else {
            panic!("expected send");
        };
        assert_eq!(options.to, "b");
        assert!(parse(&args(&["send", "x.bin", "--to", "b", "--timeout", "0"])).is_err());
    }

    #[test]
    fn receive_needs_a_dir() {
        assert!(parse(&args(&["receive"])).is_err());
        assert!(parse(&args(&["receive", "--dir", "/tmp/in"])).is_ok());
        assert!(parse(&args(&["receive", "--dir", "/tmp/in", "--max-bytes", "0"])).is_err());
    }
}
