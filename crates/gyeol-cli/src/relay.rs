use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use super::ticket_load;
use gyeol_edge::{
    relay_policy_port, run_relay_smoke, DirectIdentity, DirectRole, MemoryCandidateSink,
    PathMachine, RelayRequest, RelaySmokeMode, StunClient, STICK_AND_UPGRADE,
};
use gyeol_relay::{
    framing_name, RelayPreference, RelayServer, RelaySessionId, ServerConfig, RELAY_PORT,
};

use super::{parse_socket, take_value};

const DEFAULT_BUDGET: Duration = Duration::from_secs(8);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// A Relay command.
#[derive(Debug)]
pub(crate) enum Command {
    Help(String),
    Serve(ServeOptions),
    Peer(Box<PeerOptions>),
    Smoke(SmokeOptions),
}

#[derive(Debug)]
pub(crate) struct ServeOptions {
    udp: Option<SocketAddr>,
    tcp: Option<SocketAddr>,
    audit_absent: Option<Vec<u8>>,
    audit_path: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct PeerOptions {
    role: DirectRole,
    bind: SocketAddr,
    stun: SocketAddr,
    session_id: RelaySessionId,
    udp: SocketAddr,
    tcp: SocketAddr,
    preference: RelayPreference,
    cert: PathBuf,
    key: PathBuf,
    bundle: PathBuf,
    ticket: PathBuf,
    budget: Duration,
    udp_timeout: Duration,
    tcp_timeout: Duration,
    ready_file: Option<PathBuf>,
    wait_ready: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct SmokeOptions {
    mode: RelaySmokeMode,
    bind: Option<SocketAddr>,
}

pub(crate) fn parse_serve(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(serve_help()));
    }
    let mut udp = None;
    let mut tcp = None;
    let mut audit_absent = None;
    let mut audit_path = None;
    let mut saw_udp = false;
    let mut saw_tcp = false;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--udp" => {
                saw_udp = true;
                udp = Some(parse_socket(&value, RELAY_PORT)?);
            }
            "--tcp" => {
                saw_tcp = true;
                tcp = Some(parse_socket(&value, RELAY_PORT)?);
            }
            "--audit-absent" => audit_absent = Some(parse_hex_bytes(&value)?),
            "--audit-file" => audit_path = Some(PathBuf::from(value)),
            other => {
                return Err(format!("The flag {other} is not valid.\n{}", serve_help()));
            }
        }
    }
    if !saw_udp && !saw_tcp {
        let both = SocketAddr::from((Ipv4Addr::UNSPECIFIED, RELAY_PORT));
        udp = Some(both);
        tcp = Some(both);
    }
    Ok(Command::Serve(ServeOptions {
        udp,
        tcp,
        audit_absent,
        audit_path,
    }))
}

pub(crate) fn parse_peer(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(peer_help()));
    }
    let mut role = None;
    let mut bind = None;
    let mut stun = None;
    let mut session_id = None;
    let mut relay = None;
    let mut relay_tcp = None;
    let mut preference = None;
    let mut cert = None;
    let mut key = None;
    let mut bundle = None;
    let mut ticket = None;
    let mut budget = None;
    let mut udp_timeout = None;
    let mut ready_file = None;
    let mut wait_ready = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--role" => role = Some(parse_role(&value)?),
            "--bind" => bind = Some(parse_socket(&value, 0)?),
            "--stun" => stun = Some(parse_socket(&value, 3478)?),
            "--session" => {
                session_id = Some(RelaySessionId::parse_hex(&value).map_err(|err| err.to_string())?)
            }
            "--relay" => relay = Some(parse_socket(&value, RELAY_PORT)?),
            "--relay-tcp" => relay_tcp = Some(parse_socket(&value, RELAY_PORT)?),
            "--transport" => preference = Some(parse_preference(&value)?),
            "--cert" => cert = Some(PathBuf::from(value)),
            "--key" => key = Some(PathBuf::from(value)),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--ticket" => ticket = Some(PathBuf::from(value)),
            "--timeout" => budget = Some(parse_secs(&value)?),
            "--udp-timeout-ms" => udp_timeout = Some(parse_ms(&value)?),
            "--ready-file" => ready_file = Some(PathBuf::from(value)),
            "--wait-ready" => wait_ready = Some(PathBuf::from(value)),
            other => {
                return Err(format!("The flag {other} is not valid.\n{}", peer_help()));
            }
        }
    }
    let relay = relay.ok_or_else(|| format!("The command needs --relay.\n{}", peer_help()))?;
    Ok(Command::Peer(Box::new(PeerOptions {
        role: role.ok_or_else(|| format!("The command needs --role.\n{}", peer_help()))?,
        bind: bind.ok_or_else(|| format!("The command needs --bind.\n{}", peer_help()))?,
        stun: stun.ok_or_else(|| format!("The command needs --stun.\n{}", peer_help()))?,
        session_id: session_id
            .ok_or_else(|| format!("The command needs --session.\n{}", peer_help()))?,
        udp: relay,
        tcp: relay_tcp.unwrap_or(relay),
        preference: preference.unwrap_or(RelayPreference::Auto),
        cert: cert.ok_or_else(|| format!("The command needs --cert.\n{}", peer_help()))?,
        key: key.ok_or_else(|| format!("The command needs --key.\n{}", peer_help()))?,
        bundle: bundle.ok_or_else(|| format!("The command needs --bundle.\n{}", peer_help()))?,
        ticket: ticket.ok_or_else(|| format!("The command needs --ticket.\n{}", peer_help()))?,
        budget: budget.unwrap_or(DEFAULT_BUDGET),
        udp_timeout: udp_timeout.unwrap_or(DEFAULT_UDP_TIMEOUT),
        tcp_timeout: DEFAULT_TCP_TIMEOUT,
        ready_file,
        wait_ready,
    })))
}

pub(crate) fn parse_smoke(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(smoke_help()));
    }
    if args.is_empty() {
        return Err(smoke_help());
    }
    let mode = match args[0].as_str() {
        "udp" => RelaySmokeMode::Udp,
        "tcp" => RelaySmokeMode::Tcp,
        other => {
            return Err(format!(
                "The mode {other} is not udp or tcp.\n{}",
                smoke_help()
            ));
        }
    };
    let mut bind = None;
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--bind" => bind = Some(parse_socket(&value, RELAY_PORT)?),
            other => {
                return Err(format!("The flag {other} is not valid.\n{}", smoke_help()));
            }
        }
    }
    Ok(Command::Smoke(SmokeOptions { mode, bind }))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Serve(options) => run_serve(options),
        Command::Peer(options) => run_peer(*options),
        Command::Smoke(options) => run_smoke(options),
    }
}

fn run_serve(options: ServeOptions) -> Result<(), String> {
    let server = RelayServer::spawn(ServerConfig {
        udp_bind: options.udp,
        tcp_bind: options.tcp,
        audit_absent: options.audit_absent,
        audit_path: options.audit_path,
        udp_discard: false,
    })
    .map_err(|err| err.to_string())?;
    match server.udp_addr() {
        Some(addr) => println!("relay udp {addr}"),
        None => println!("relay udp off"),
    }
    match server.tcp_addr() {
        Some(addr) => println!("relay tcp {addr}"),
        None => println!("relay tcp off"),
    }
    println!("policy port {}", relay_policy_port());
    println!("tcp framing quic-style");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn run_peer(options: PeerOptions) -> Result<(), String> {
    let client = StunClient::bind(options.bind).map_err(|err| err.to_string())?;
    let mut machine = PathMachine::start_allocate();
    let mut sink = MemoryCandidateSink::default();
    let candidate = machine
        .gather_reflexive(&client, options.stun, STUN_TIMEOUT, &mut sink)
        .map_err(|err| err.to_string())?;
    let identity = load_identity(&options)?;
    let link = machine
        .begin_relay(RelayRequest {
            session_id: options.session_id,
            udp: options.udp,
            tcp: options.tcp,
            preference: options.preference,
            udp_timeout: options.udp_timeout,
            tcp_timeout: options.tcp_timeout,
            budget: options.budget,
        })
        .map_err(|err| err.to_string())?;
    if let Some(path) = &options.ready_file {
        write_ready(path)?;
    }
    if let Some(path) = &options.wait_ready {
        wait_ready(path, options.budget)?;
    }
    let proof = machine
        .finish_relay(link, options.role, &identity)
        .map_err(|err| err.to_string())?;
    println!("role {}", role_name(options.role));
    println!("direct_attempted false");
    println!("local {}", candidate.local);
    println!("reflexive {}", candidate.reflexive);
    println!("transport {}", proof.transport);
    println!("framing {}", proof.framing);
    println!("relay_is_up {}", machine.relay_is_up());
    println!("direct_is_up {}", machine.direct_is_up());
    println!("path_id {}", proof.path_id.to_hex());
    println!("session_id {}", proof.session_id);
    println!("elapsed_ms {}", proof.elapsed.as_millis());
    println!("echo ok true");
    println!("state {}", machine.state());
    println!("stick {STICK_AND_UPGRADE}");
    println!("tcp framing quic-style");
    if !machine.relay_is_up() {
        return Err("relay_is_up is false.".to_string());
    }
    if proof.framing != framing_name(proof.transport) {
        return Err("The framing name does not match the transport.".to_string());
    }
    Ok(())
}

fn run_smoke(options: SmokeOptions) -> Result<(), String> {
    let report = run_relay_smoke(options.mode, options.bind).map_err(|err| err.to_string())?;
    for line in report.lines() {
        println!("{line}");
    }
    if !report.server_relay_is_up || !report.client_relay_is_up || !report.echo_ok {
        return Err("The Relay path is not up.".to_string());
    }
    if !report.payload_opaque() {
        return Err("The Relay observed the probe plaintext.".to_string());
    }
    if report.forwards == 0 {
        return Err("The Relay did not forward a payload.".to_string());
    }
    Ok(())
}

fn write_ready(path: &Path) -> Result<(), String> {
    let tmp = tmp_path(path);
    fs::write(&tmp, b"attached\n")
        .map_err(|err| format!("The file {} was not written. {err}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|err| {
        format!(
            "The file {} was not renamed to {}. {err}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn wait_ready(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if path.is_file() {
            let text = fs::read_to_string(path)
                .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
            if !text.is_empty() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(format!("The ready file {} did not appear.", path.display()))
}

fn load_identity(options: &PeerOptions) -> Result<DirectIdentity, String> {
    let certificate_pem = fs::read_to_string(&options.cert)
        .map_err(|err| format!("The file {} did not open. {err}", options.cert.display()))?;
    let private_key_pem = fs::read_to_string(&options.key)
        .map_err(|err| format!("The file {} did not open. {err}", options.key.display()))?;
    let trust_pem = fs::read_to_string(&options.bundle)
        .map_err(|err| format!("The file {} did not open. {err}", options.bundle.display()))?;
    ticket_load::load_direct_identity(certificate_pem, private_key_pem, trust_pem, &options.ticket)
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

fn parse_role(text: &str) -> Result<DirectRole, String> {
    match text {
        "server" => Ok(DirectRole::Server),
        "client" => Ok(DirectRole::Client),
        _ => Err(format!("The role {text} is not server or client.")),
    }
}

fn role_name(role: DirectRole) -> &'static str {
    match role {
        DirectRole::Server => "server",
        DirectRole::Client => "client",
    }
}

fn parse_preference(text: &str) -> Result<RelayPreference, String> {
    match text {
        "auto" => Ok(RelayPreference::Auto),
        "udp" => Ok(RelayPreference::Udp),
        "tcp" => Ok(RelayPreference::Tcp),
        _ => Err(format!("The transport {text} is not auto, udp, or tcp.")),
    }
}

fn parse_secs(text: &str) -> Result<Duration, String> {
    let secs: u64 = text
        .parse()
        .map_err(|_| format!("The timeout {text} is not a whole number of seconds."))?;
    if secs == 0 {
        return Err("The timeout is zero.".to_string());
    }
    Ok(Duration::from_secs(secs))
}

fn parse_ms(text: &str) -> Result<Duration, String> {
    let millis: u64 = text
        .parse()
        .map_err(|_| format!("The timeout {text} is not a whole number of milliseconds."))?;
    if millis == 0 {
        return Err("The timeout is zero.".to_string());
    }
    Ok(Duration::from_millis(millis))
}

fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err("The audit needle hex is not valid.".to_string());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let pair = std::str::from_utf8(&bytes[index..index + 2])
            .map_err(|_| "The audit needle hex is not valid.".to_string())?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| "The audit needle hex is not valid.".to_string())?;
        out.push(byte);
        index += 2;
    }
    Ok(out)
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn serve_help() -> String {
    "\
gyeol relay [--udp ADDR] [--tcp ADDR] [--audit-absent HEX] [--audit-file PATH]
The command runs the gyeol Relay.
The Relay routes by session id.
The Relay forwards opaque payloads.
The Relay does not hold session keys.
The default socket is UDP port 443 and TCP port 443.
TCP uses a QUIC-style length prefix.
The audit scan does not decrypt.
"
    .to_string()
}

fn peer_help() -> String {
    "\
gyeol relay-peer --role server|client --bind ADDR --stun ADDR --session HEX --relay ADDR [--relay-tcp ADDR] [--transport auto|udp|tcp] --cert FILE --key FILE --bundle FILE --ticket FILE [--timeout SECS] [--udp-timeout-ms MS] [--ready-file FILE] [--wait-ready FILE]
The command gathers one reflexive address.
The command attaches to the gyeol Relay.
The preferred transport is UDP.
When UDP fails, auto uses TCP.
The command proves QUIC through the Relay.
The --ticket file is one identity ticket.
The command also reads FILE.mac and the ticket key files in that directory.
The command does not punch a direct path.
Stick and upgrade is deferred.
"
    .to_string()
}

fn smoke_help() -> String {
    "\
gyeol relay-smoke udp|tcp [--bind ADDR]
The udp mode fails Direct and then uses the Relay on UDP.
The tcp mode discards UDP and then uses TCP.
The TCP framing is QUIC-style.
The command checks that the probe plaintext is absent on the Relay.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse_peer, parse_serve, parse_smoke, Command};

    #[test]
    fn relay_defaults_to_udp_and_tcp_443() {
        let command = parse_serve(&[]).unwrap();
        match command {
            Command::Serve(options) => {
                assert_eq!(options.udp.unwrap().port(), 443);
                assert_eq!(options.tcp.unwrap().port(), 443);
            }
            Command::Help(_) | Command::Peer(_) | Command::Smoke(_) => {
                panic!("the parser did not select relay");
            }
        }
    }

    #[test]
    fn relay_peer_requires_session() {
        let err = parse_peer(&[]).unwrap_err();
        assert!(err.contains("--relay") || err.contains("--role") || err.contains("--session"));
    }

    #[test]
    fn relay_smoke_selects_tcp() {
        let command = parse_smoke(&["tcp".to_string()]).unwrap();
        match command {
            Command::Smoke(options) => {
                assert!(matches!(options.mode, gyeol_edge::RelaySmokeMode::Tcp));
                assert!(options.bind.is_none());
            }
            Command::Help(_) | Command::Serve(_) | Command::Peer(_) => {
                panic!("the parser did not select relay-smoke");
            }
        }
    }
}
