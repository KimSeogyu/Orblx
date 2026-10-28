use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use super::ticket_load;
use super::{parse_socket, take_value};
use gyeol_edge::{
    decode_candidate, encode_candidate, issue_direct_pair, DirectIdentity, DirectRequest,
    DirectRole, MemoryCandidateSink, PathMachine, PunchToken, StunClient, DIRECT_ATTEMPT_BUDGET,
};

const STUN_TIMEOUT: Duration = Duration::from_secs(5);
const PEER_WAIT: Duration = Duration::from_secs(10);
const DEFAULT_STUN_PORT: u16 = 3478;

/// A direct lab command.
#[derive(Debug)]
pub(crate) enum Command {
    Help(String),
    Issue(PathBuf),
    Peer(Box<PeerOptions>),
}

#[derive(Debug)]
pub(crate) struct PeerOptions {
    role: DirectRole,
    bind: SocketAddr,
    stun: SocketAddr,
    token: PunchToken,
    publish: PathBuf,
    peer_file: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    bundle: PathBuf,
    ticket: PathBuf,
    budget: Duration,
}

pub(crate) fn parse_issue(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(issue_help()));
    }
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--out" => out = Some(PathBuf::from(value)),
            other => {
                return Err(format!("The flag {other} is not valid.\n{}", issue_help()));
            }
        }
    }
    let out = out.ok_or_else(|| format!("The command needs --out.\n{}", issue_help()))?;
    Ok(Command::Issue(out))
}

pub(crate) fn parse_peer(args: &[String]) -> Result<Command, String> {
    if wants_help(args) {
        return Ok(Command::Help(peer_help()));
    }
    let mut role = None;
    let mut bind = None;
    let mut stun = None;
    let mut token = None;
    let mut publish = None;
    let mut peer_file = None;
    let mut cert = None;
    let mut key = None;
    let mut bundle = None;
    let mut ticket = None;
    let mut budget = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--role" => role = Some(parse_role(&value)?),
            "--bind" => bind = Some(parse_socket(&value, 0)?),
            "--stun" => stun = Some(parse_socket(&value, DEFAULT_STUN_PORT)?),
            "--token" => {
                token = Some(PunchToken::parse_hex(&value).map_err(|err| err.to_string())?)
            }
            "--publish" => publish = Some(PathBuf::from(value)),
            "--peer-file" => peer_file = Some(PathBuf::from(value)),
            "--cert" => cert = Some(PathBuf::from(value)),
            "--key" => key = Some(PathBuf::from(value)),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--ticket" => ticket = Some(PathBuf::from(value)),
            "--timeout" => budget = Some(parse_budget(&value)?),
            other => {
                return Err(format!("The flag {other} is not valid.\n{}", peer_help()));
            }
        }
    }
    let role = role.ok_or_else(|| format!("The command needs --role.\n{}", peer_help()))?;
    let bind = bind.ok_or_else(|| format!("The command needs --bind.\n{}", peer_help()))?;
    let stun = stun.ok_or_else(|| format!("The command needs --stun.\n{}", peer_help()))?;
    let token = token.ok_or_else(|| format!("The command needs --token.\n{}", peer_help()))?;
    let publish =
        publish.ok_or_else(|| format!("The command needs --publish.\n{}", peer_help()))?;
    let peer_file =
        peer_file.ok_or_else(|| format!("The command needs --peer-file.\n{}", peer_help()))?;
    let cert = cert.ok_or_else(|| format!("The command needs --cert.\n{}", peer_help()))?;
    let key = key.ok_or_else(|| format!("The command needs --key.\n{}", peer_help()))?;
    let bundle = bundle.ok_or_else(|| format!("The command needs --bundle.\n{}", peer_help()))?;
    let ticket = ticket.ok_or_else(|| format!("The command needs --ticket.\n{}", peer_help()))?;
    Ok(Command::Peer(Box::new(PeerOptions {
        role,
        bind,
        stun,
        token,
        publish,
        peer_file,
        cert,
        key,
        bundle,
        ticket,
        budget: budget.unwrap_or(DIRECT_ATTEMPT_BUDGET),
    })))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Issue(out) => run_issue(&out),
        Command::Peer(options) => run_peer(*options),
    }
}

fn run_issue(out: &Path) -> Result<(), String> {
    fs::create_dir_all(out)
        .map_err(|err| format!("The directory {} was not created. {err}", out.display()))?;
    let material = issue_direct_pair(SystemTime::now()).map_err(|err| err.to_string())?;
    write_file(
        &out.join("bundle.pem"),
        material.server.trust_pem.as_bytes(),
    )?;
    write_file(
        &out.join("server.pem"),
        material.server.certificate_pem.as_bytes(),
    )?;
    write_file(
        &out.join("server.key"),
        material.server.private_key_pem.as_bytes(),
    )?;
    write_file(
        &out.join("client.pem"),
        material.client.certificate_pem.as_bytes(),
    )?;
    write_file(
        &out.join("client.key"),
        material.client.private_key_pem.as_bytes(),
    )?;
    ticket_load::write_shared(out, &material.server)?;
    ticket_load::write_ticket(&out.join("server-ticket.bin"), &material.server)?;
    ticket_load::write_ticket(&out.join("client-ticket.bin"), &material.client)?;
    println!("out {}", out.display());
    Ok(())
}

fn run_peer(options: PeerOptions) -> Result<(), String> {
    let client = StunClient::bind(options.bind).map_err(|err| err.to_string())?;
    let mut machine = PathMachine::start_allocate();
    let mut sink = MemoryCandidateSink::default();
    let candidate = machine
        .gather_reflexive(&client, options.stun, STUN_TIMEOUT, &mut sink)
        .map_err(|err| err.to_string())?;
    publish_candidate(&options.publish, candidate)?;
    let remote = wait_for_candidate(&options.peer_file, PEER_WAIT)?;
    let identity = load_identity(&options)?;
    let socket = client.into_socket();
    let proof = machine
        .establish_direct(DirectRequest {
            role: options.role,
            remote,
            token: options.token,
            socket,
            identity,
            budget: options.budget,
        })
        .map_err(|err| err.to_string())?;
    println!("role {}", role_name(options.role));
    println!("local {candidate}", candidate = candidate.local);
    println!("reflexive {reflexive}", reflexive = candidate.reflexive);
    println!("punch packets {}", proof.packets_sent);
    println!("punch received {}", proof.packets_received);
    println!("quic port {}", proof.quic_port);
    println!("direct_is_up {}", machine.direct_is_up());
    println!("path_id {}", proof.path_id.to_hex());
    println!("elapsed_ms {}", proof.elapsed.as_millis());
    println!("echo ok true");
    if !machine.direct_is_up() {
        return Err("direct_is_up is false.".to_string());
    }
    if proof.packets_sent == 0 || proof.packets_received == 0 {
        return Err("The hole punch did not move a packet.".to_string());
    }
    Ok(())
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

fn publish_candidate(path: &Path, candidate: gyeol_edge::EndpointCandidate) -> Result<(), String> {
    let text = encode_candidate(candidate);
    let tmp = tmp_path(path);
    fs::write(&tmp, text)
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

fn wait_for_candidate(
    path: &Path,
    timeout: Duration,
) -> Result<gyeol_edge::EndpointCandidate, String> {
    let started = Instant::now();
    loop {
        if path.is_file() {
            let text = fs::read_to_string(path)
                .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
            if let Ok(candidate) = decode_candidate(&text) {
                return Ok(candidate);
            }
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "The peer candidate file {} did not appear.",
                path.display()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes)
        .map_err(|err| format!("The file {} was not written. {err}", path.display()))
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

fn parse_budget(text: &str) -> Result<Duration, String> {
    let secs: u64 = text
        .parse()
        .map_err(|_| format!("The timeout {text} is not a whole number of seconds."))?;
    if secs == 0 {
        return Err("The timeout is zero.".to_string());
    }
    Ok(Duration::from_secs(secs))
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn issue_help() -> String {
    "\
gyeol direct-issue --out DIR
The command writes a lab CA, two leaves, and two capability tickets.
The ticket files are server-ticket.bin and client-ticket.bin.
Each ticket file has a FILE.mac tag.
The directory holds ticket-verifier.pem, ticket-mac.key, ticket-not-before, ticket-not-after, and svid-ca.pub.
The leaves are for the Direct QUIC proof.
The command does not contact an OIDC provider.
"
    .to_string()
}

fn peer_help() -> String {
    "\
gyeol direct-peer --role server|client --bind ADDR --stun ADDR --token HEX --publish FILE --peer-file FILE --cert FILE --key FILE --bundle FILE --ticket FILE [--timeout SECS]
The command gathers one reflexive address.
The command writes the unsigned candidate.
The command waits for the peer candidate file.
The command sends hole-punch datagrams.
The command proves QUIC on the same UDP socket.
The --ticket file is one identity ticket.
The command also reads FILE.mac and the ticket key files in that directory.
The default timeout is 3 seconds.
The timeout is the Direct budget.
The command does not use Relay.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse_issue, parse_peer, Command};

    #[test]
    fn direct_issue_requires_out() {
        let err = parse_issue(&[]).unwrap_err();
        assert!(err.contains("--out"));
    }

    #[test]
    fn direct_peer_requires_role() {
        let err = parse_peer(&[]).unwrap_err();
        assert!(err.contains("--role"));
    }

    #[test]
    fn direct_peer_help_names_the_budget() {
        let command = parse_peer(&["--help".to_string()]).unwrap();
        match command {
            Command::Help(text) => {
                assert!(text.contains("hole-punch"));
                assert!(text.contains("3 seconds"));
            }
            Command::Issue(_) | Command::Peer(_) => panic!("the parser did not select help"),
        }
    }
}
