//! `orblx agent` asks for an agent JIT grant, uses it, and guards one service.
//!
//! The command does not print private keys, tickets, or enroll tokens.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use orblx_agent::{
    connect, new_nonce, plain_http_request, run_gateway, run_guard, seal_http_request, send_http,
    unix_millis, ConnectError, GrantFiles, GuardConfig,
};
use orblx_coord::{
    agent_grant_fetch_blocking, agent_grant_request_blocking, decode_hex_32, fetch_deny_blocking,
    GrantAsk, GrantFetch,
};
use orblx_identity::{SpiffeId, TicketVerifier, TrustBundle};
use serde_json::Value;

use super::{parse_socket, take_value};

const DEFAULT_STATE: &str = "/var/lib/orblx";
const EXIT_DENIED: i32 = 3;

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Request(Request),
    Fetch(Fetch),
    Connect(Connect),
    Guard(Guard),
    Gateway(Guard),
    Http(Http),
}

#[derive(Debug)]
pub(crate) struct Http {
    grant: Option<PathBuf>,
    to: Option<SocketAddr>,
    service: Option<String>,
    method: String,
    path: String,
    body: String,
    repeat: u32,
    timeout: Duration,
    every: Option<Duration>,
    max_wait: Duration,
    save_request: Option<PathBuf>,
    send_file: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct CoordFlags {
    state: PathBuf,
    coord: SocketAddr,
    coord_name: String,
    bundle: PathBuf,
}

#[derive(Debug)]
pub(crate) struct Request {
    coord: CoordFlags,
    ask: GrantAsk,
}

#[derive(Debug)]
pub(crate) struct Fetch {
    coord: CoordFlags,
    id: String,
    out: PathBuf,
    wait: Duration,
}

#[derive(Debug)]
pub(crate) struct Connect {
    grant: PathBuf,
    to: Option<SocketAddr>,
    service: Option<String>,
    send: Option<String>,
    timeout: Duration,
    every: Option<Duration>,
    max_wait: Duration,
}

#[derive(Debug)]
pub(crate) struct Guard {
    state: PathBuf,
    listen: SocketAddr,
    service: String,
    target: SocketAddr,
    audit: PathBuf,
    coord: Option<(SocketAddr, String, PathBuf)>,
    poll: Duration,
    stale: Duration,
}

/// The flags that each mode reads.
#[derive(Default)]
struct Flags {
    values: Vec<(String, String)>,
}

impl Flags {
    fn parse(args: &[String], allowed: &[&str]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].clone();
            index += 1;
            if !allowed.contains(&flag.as_str()) {
                return Err(format!("The flag {flag} is not valid.\n{}", help()));
            }
            let value = take_value(args, &mut index)?;
            values.push((flag, value));
        }
        Ok(Self { values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
    }

    fn need(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("The command needs {name}.\n{}", help()))
    }

    fn number<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.get(name) {
            Some(text) => text
                .parse::<T>()
                .map_err(|_| format!("The {name} value {text} is not valid.")),
            None => Ok(default),
        }
    }

    fn coord(&self) -> Result<CoordFlags, String> {
        let state = PathBuf::from(self.get("--state").unwrap_or(DEFAULT_STATE));
        let coord = parse_socket(self.need("--coord")?, 443)?;
        let bundle = self
            .get("--bundle")
            .map(PathBuf::from)
            .unwrap_or_else(|| state.join("bundle.pem"));
        Ok(CoordFlags {
            state,
            coord,
            coord_name: self.get("--coord-name").unwrap_or("coord").to_string(),
            bundle,
        })
    }
}

const COORD_FLAGS: [&str; 4] = ["--state", "--coord", "--coord-name", "--bundle"];

fn with_coord(extra: &[&'static str]) -> Vec<&'static str> {
    let mut list = COORD_FLAGS.to_vec();
    list.extend_from_slice(extra);
    list
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    match (args[0].as_str(), args.get(1).map(String::as_str)) {
        ("grant", Some("request")) => {
            let flags = Flags::parse(
                &args[2..],
                &with_coord(&[
                    "--agent",
                    "--node",
                    "--service",
                    "--port",
                    "--ttl",
                    "--path",
                ]),
            )?;
            let port: u16 = flags.number("--port", 0)?;
            if port == 0 {
                return Err(format!("The command needs --port.\n{}", help()));
            }
            Ok(Command::Request(Request {
                coord: flags.coord()?,
                ask: GrantAsk {
                    agent: flags.need("--agent")?.to_string(),
                    node: flags.need("--node")?.to_string(),
                    service: flags.need("--service")?.to_string(),
                    port,
                    ttl_secs: flags.number("--ttl", 300)?,
                    path_prefix: flags.get("--path").map(str::to_string),
                },
            }))
        }
        ("grant", Some("fetch")) => {
            let flags = Flags::parse(&args[2..], &with_coord(&["--id", "--out", "--wait"]))?;
            Ok(Command::Fetch(Fetch {
                coord: flags.coord()?,
                id: flags.need("--id")?.to_string(),
                out: PathBuf::from(flags.need("--out")?),
                wait: Duration::from_secs(flags.number("--wait", 0)?),
            }))
        }
        ("connect", _) => {
            let flags = Flags::parse(
                &args[1..],
                &[
                    "--grant",
                    "--to",
                    "--service",
                    "--send",
                    "--timeout",
                    "--every-ms",
                    "--max-wait",
                ],
            )?;
            let to = flags
                .get("--to")
                .map(|text| parse_socket(text, 0))
                .transpose()?;
            let every = match flags.get("--every-ms") {
                Some(_) => Some(Duration::from_millis(flags.number("--every-ms", 100)?)),
                None => None,
            };
            Ok(Command::Connect(Connect {
                grant: PathBuf::from(flags.need("--grant")?),
                to,
                service: flags.get("--service").map(str::to_string),
                send: flags.get("--send").map(str::to_string),
                timeout: Duration::from_secs(flags.number("--timeout", 5)?),
                every,
                max_wait: Duration::from_secs(flags.number("--max-wait", 400)?),
            }))
        }
        ("guard", _) => parse_guard(&args[1..]).map(Command::Guard),
        ("http", _) => {
            let flags = Flags::parse(
                &args[1..],
                &[
                    "--grant",
                    "--to",
                    "--service",
                    "--method",
                    "--path",
                    "--body",
                    "--repeat",
                    "--timeout",
                    "--every-ms",
                    "--max-wait",
                    "--save-request",
                    "--send-file",
                ],
            )?;
            let to = flags
                .get("--to")
                .map(|text| parse_socket(text, 0))
                .transpose()?;
            let grant = flags.get("--grant").map(PathBuf::from);
            let send_file = flags.get("--send-file").map(PathBuf::from);
            if send_file.is_some() && to.is_none() {
                return Err(format!("--send-file needs --to.\n{}", help()));
            }
            if grant.is_none() && to.is_none() {
                return Err(format!("The command needs --grant or --to.\n{}", help()));
            }
            let every = match flags.get("--every-ms") {
                Some(_) => Some(Duration::from_millis(flags.number("--every-ms", 100)?)),
                None => None,
            };
            let method = flags.get("--method").unwrap_or("GET").to_string();
            let path = flags.get("--path").unwrap_or("/").to_string();
            Ok(Command::Http(Http {
                grant,
                to,
                service: flags.get("--service").map(str::to_string),
                method,
                path,
                body: flags.get("--body").unwrap_or("").to_string(),
                repeat: flags.number("--repeat", 1)?,
                timeout: Duration::from_secs(flags.number("--timeout", 5)?),
                every,
                max_wait: Duration::from_secs(flags.number("--max-wait", 400)?),
                save_request: flags.get("--save-request").map(PathBuf::from),
                send_file,
            }))
        }
        _ => Err(format!("The mode is not valid.\n{}", help())),
    }
}

/// Parse the `orblx gateway` flags. They are the same as the guard flags.
pub(crate) fn parse_gateway(args: &[String]) -> Result<Command, String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    parse_guard(args).map(Command::Gateway)
}

fn parse_guard(args: &[String]) -> Result<Guard, String> {
    let flags = Flags::parse(
        args,
        &with_coord(&[
            "--listen",
            "--service",
            "--target",
            "--audit",
            "--poll-ms",
            "--stale-ms",
        ]),
    )?;
    let state = PathBuf::from(flags.get("--state").unwrap_or(DEFAULT_STATE));
    let coord = match flags.get("--coord") {
        Some(_) => {
            let parsed = flags.coord()?;
            Some((parsed.coord, parsed.coord_name, parsed.bundle))
        }
        None => None,
    };
    let audit = flags
        .get("--audit")
        .map(PathBuf::from)
        .unwrap_or_else(|| state.join("agent-audit.jsonl"));
    Ok(Guard {
        listen: parse_socket(flags.need("--listen")?, 0)?,
        service: flags.need("--service")?.to_string(),
        target: parse_socket(flags.need("--target")?, 0)?,
        audit,
        coord,
        poll: Duration::from_millis(flags.number("--poll-ms", 200)?),
        stale: Duration::from_millis(flags.number("--stale-ms", 2000)?),
        state,
    })
}

pub(crate) fn run(command: Command) -> Result<i32, String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(0)
        }
        Command::Request(request) => run_request(request),
        Command::Fetch(fetch) => run_fetch(fetch),
        Command::Connect(connect) => run_connect(connect),
        Command::Guard(guard) => run_guard_command(guard, false),
        Command::Gateway(guard) => run_guard_command(guard, true),
        Command::Http(http) => run_http(http),
    }
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))
}

fn now_ms() -> u64 {
    unix_millis(SystemTime::now()).unwrap_or(0)
}

fn run_request(request: Request) -> Result<i32, String> {
    let bundle = read_text(&request.coord.bundle)?;
    let detail = agent_grant_request_blocking(
        request.coord.coord,
        &request.coord.coord_name,
        &bundle,
        &request.coord.state,
        request.ask,
    )
    .map_err(|err| err.to_string())?;
    let value: Value = serde_json::from_str(&detail)
        .map_err(|_| "The coordinator response is not valid.".to_string())?;
    let field = |name: &str| value.get(name).and_then(Value::as_str).unwrap_or("?");
    println!("grant_id {}", field("id"));
    println!("grant_state {}", field("state"));
    println!("grant_agent {}", field("agent"));
    Ok(0)
}

fn run_fetch(fetch: Fetch) -> Result<i32, String> {
    let bundle = read_text(&fetch.coord.bundle)?;
    let started = Instant::now();
    loop {
        let result = agent_grant_fetch_blocking(
            fetch.coord.coord,
            &fetch.coord.coord_name,
            &bundle,
            &fetch.coord.state,
            &fetch.id,
        )
        .map_err(|err| err.to_string())?;
        match result {
            GrantFetch::Issued(files) => {
                files.write(&fetch.out).map_err(|err| err.to_string())?;
                let grant = &files.grant.grant;
                println!("grant_id {}", grant.id);
                println!("grant_state issued");
                println!("grant_agent {}", grant.agent);
                println!("grant_node {}", grant.node);
                println!("grant_addr {}", grant.addr);
                println!("grant_service {}", grant.service);
                println!("grant_port {}", grant.port);
                println!("grant_path {}", grant.path_prefix);
                println!("grant_approver {}", grant.approver);
                println!("grant_not_before {}", grant.not_before);
                println!("grant_expires {}", grant.expires);
                println!("grant_expires_ms {}", grant.expires.saturating_mul(1000));
                println!("grant_files {}", fetch.out.display());
                return Ok(0);
            }
            GrantFetch::Pending => {
                if started.elapsed() >= fetch.wait {
                    println!("grant_id {}", fetch.id);
                    println!("grant_state pending");
                    return Ok(EXIT_DENIED);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

fn run_connect(command: Connect) -> Result<i32, String> {
    let files = GrantFiles::load(&command.grant).map_err(|err| err.to_string())?;
    let grant = &files.grant.grant;
    let addr: Ipv4Addr = grant
        .addr
        .parse()
        .map_err(|_| "The grant address is not valid.".to_string())?;
    let to = command
        .to
        .unwrap_or_else(|| SocketAddr::from((addr, grant.port)));
    let service = command
        .service
        .clone()
        .unwrap_or_else(|| grant.service.clone());
    let node = SpiffeId::parse(&grant.node).map_err(|err| err.to_string())?;
    let Some(every) = command.every else {
        let started = now_ms();
        return match one_connect(&files, to, &node, &service, &command) {
            Ok(reply) => {
                println!("connect ok to {to} service {service} at_ms {started}");
                if let Some(line) = reply {
                    println!("reply {line}");
                }
                Ok(0)
            }
            Err(ConnectError::Denied(reason)) => {
                println!(
                    "connect denied reason {reason} to {to} service {service} at_ms {started}"
                );
                Ok(EXIT_DENIED)
            }
            Err(ConnectError::Failed(text)) => Err(text),
        };
    };
    // Loop mode: connect until the guard denies, and print the times.
    let limit = Instant::now() + command.max_wait;
    let mut last_ok: Option<u64> = None;
    let mut attempts = 0u64;
    loop {
        let at = now_ms();
        attempts += 1;
        match one_connect(&files, to, &node, &service, &command) {
            Ok(_) => last_ok = Some(at),
            Err(ConnectError::Denied(reason)) => {
                let done = now_ms();
                println!("loop attempts {attempts}");
                println!(
                    "loop last_ok_ms {}",
                    last_ok
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".into())
                );
                println!("loop first_deny_start_ms {at}");
                println!("loop first_deny_ms {done}");
                println!("loop deny_reason {reason}");
                println!(
                    "loop grant_expires_ms {}",
                    grant.expires.saturating_mul(1000)
                );
                return Ok(0);
            }
            Err(ConnectError::Failed(text)) => {
                println!("loop attempt {attempts} failed at_ms {at}: {text}");
            }
        }
        if Instant::now() >= limit {
            println!("loop attempts {attempts}");
            println!("loop no_deny_until_ms {}", now_ms());
            return Ok(EXIT_DENIED);
        }
        std::thread::sleep(every);
    }
}

fn one_connect(
    files: &GrantFiles,
    to: SocketAddr,
    node: &SpiffeId,
    service: &str,
    command: &Connect,
) -> Result<Option<String>, ConnectError> {
    let mut stream = connect(files, to, node, service, command.timeout)?;
    let Some(text) = &command.send else {
        return Ok(None);
    };
    let failed = |err: std::io::Error| ConnectError::Failed(err.to_string());
    stream
        .write_all(text.replace("\\r\\n", "\r\n").as_bytes())
        .map_err(failed)?;
    stream
        .set_read_timeout(Some(command.timeout))
        .map_err(failed)?;
    let mut raw = Vec::new();
    let _ = stream.take(64 * 1024).read_to_end(&mut raw);
    let reply = String::from_utf8_lossy(&raw);
    Ok(reply.lines().next().map(str::to_string))
}

fn run_guard_command(guard: Guard, http: bool) -> Result<i32, String> {
    let name = read_text(&guard.state.join("node-name"))?
        .trim()
        .to_string();
    let node = SpiffeId::node(&name).map_err(|err| err.to_string())?;
    let bundle = TrustBundle::from_pem(&read_text(&guard.state.join("trust-bundle.pem"))?)
        .map_err(|err| err.to_string())?;
    let verifier =
        TicketVerifier::from_public_pem(&read_text(&guard.state.join("ticket-verifier.pem"))?)
            .map_err(|err| err.to_string())?;
    let netmap_public = decode_hex_32(read_text(&guard.state.join("netmap.pub"))?.trim())
        .map_err(|_| "The netmap public key is not valid.".to_string())?;
    let state = guard.state.clone();
    let fetch: orblx_agent::DenyFetch = match guard.coord.clone() {
        Some((coord, coord_name, bundle_path)) => {
            let coord_bundle = read_text(&bundle_path)?;
            Box::new(move || {
                fetch_deny_blocking(coord, &coord_name, &coord_bundle, &state)
                    .map_err(|err| err.to_string())
            })
        }
        None => {
            let path = state.join("deny.json");
            Box::new(move || {
                std::fs::read_to_string(&path).map_err(|err| format!("deny.json: {err}"))
            })
        }
    };
    let config = GuardConfig {
        listen: guard.listen,
        service: guard.service,
        target: guard.target,
        node,
        bundle,
        verifier,
        netmap_public,
        audit_path: guard.audit,
        poll: guard.poll,
        stale_after: guard.stale,
    };
    if http {
        run_gateway(config, fetch).map_err(|err| err.to_string())?;
    } else {
        run_guard(config, fetch).map_err(|err| err.to_string())?;
    }
    Ok(0)
}

fn run_http(command: Http) -> Result<i32, String> {
    let files = match &command.grant {
        Some(dir) => Some(GrantFiles::load(dir).map_err(|err| err.to_string())?),
        None => None,
    };
    let (to, service, node, expires_ms) = match &files {
        Some(files) => {
            let grant = &files.grant.grant;
            let addr: Ipv4Addr = grant
                .addr
                .parse()
                .map_err(|_| "The grant address is not valid.".to_string())?;
            let node = SpiffeId::parse(&grant.node).map_err(|err| err.to_string())?;
            (
                command
                    .to
                    .unwrap_or_else(|| SocketAddr::from((addr, grant.port))),
                command
                    .service
                    .clone()
                    .unwrap_or_else(|| grant.service.clone()),
                Some(node),
                grant.expires.saturating_mul(1000),
            )
        }
        None => (
            command.to.ok_or("The command needs --to.")?,
            command.service.clone().unwrap_or_default(),
            None,
            0,
        ),
    };
    let build = || -> Result<Vec<u8>, String> {
        match (&files, &node) {
            (Some(files), Some(node)) => seal_http_request(
                files,
                to,
                node,
                &service,
                &command.method,
                &command.path,
                command.body.as_bytes(),
                new_nonce(),
                SystemTime::now(),
            )
            .map_err(|err| err.to_string()),
            _ => Ok(plain_http_request(
                to,
                &command.method,
                &command.path,
                command.body.as_bytes(),
            )),
        }
    };
    let send = |bytes: &[u8]| -> Result<(u16, String), String> {
        let reply = send_http(to, bytes, command.timeout)
            .map_err(|err| format!("The gateway request failed. {err}"))?;
        let reason = reply
            .first_body_line
            .strip_prefix("orblx-deny ")
            .map_or_else(|| "-".to_string(), str::to_string);
        Ok((
            reply.status,
            if reply.status == 200 {
                reply.first_body_line
            } else {
                reason
            },
        ))
    };
    let Some(every) = command.every else {
        // One request. With --repeat N the same bytes go N times on new connections.
        // --save-request keeps the bytes (mode 0600) and --send-file sends them again.
        // The bytes hold a use proof. The command does not print them.
        let bytes = match &command.send_file {
            Some(path) => std::fs::read(path)
                .map_err(|err| format!("The file {} did not open. {err}", path.display()))?,
            None => build()?,
        };
        if let Some(path) = &command.save_request {
            write_private(path, &bytes)?;
        }
        let mut code = 0;
        for attempt in 1..=command.repeat.max(1) {
            let at = now_ms();
            let (status, text) = send(&bytes)?;
            if status == 200 {
                println!(
                    "http attempt {attempt} status 200 method {} path {} at_ms {at} body {text}",
                    command.method,
                    path_only(&command.path)
                );
                code = 0;
            } else {
                println!(
                    "http attempt {attempt} status {status} reason {text} method {} path {} at_ms {at}",
                    command.method,
                    path_only(&command.path)
                );
                code = EXIT_DENIED;
            }
        }
        return Ok(code);
    };
    // Loop mode: a new nonce each time, until the gateway refuses.
    let limit = Instant::now() + command.max_wait;
    let mut last_ok: Option<u64> = None;
    let mut attempts = 0u64;
    loop {
        let at = now_ms();
        attempts += 1;
        let bytes = build()?;
        let (status, text) = send(&bytes)?;
        if status != 200 {
            let done = now_ms();
            println!("loop attempts {attempts}");
            println!(
                "loop last_ok_ms {}",
                last_ok.map_or_else(|| "none".to_string(), |value| value.to_string())
            );
            println!("loop first_deny_start_ms {at}");
            println!("loop first_deny_ms {done}");
            println!("loop deny_status {status}");
            println!("loop deny_reason {text}");
            println!("loop grant_expires_ms {expires_ms}");
            return Ok(0);
        }
        last_ok = Some(at);
        if Instant::now() >= limit {
            println!("loop attempts {attempts}");
            println!("loop no_deny_until_ms {}", now_ms());
            return Ok(EXIT_DENIED);
        }
        std::thread::sleep(every);
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
    file.write_all(bytes)
        .map_err(|err| format!("The file {} was not written. {err}", path.display()))
}

fn path_only(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or("")
}

fn help() -> String {
    "\
orblx agent grant request --agent NAME --node NODE --service NAME --port N [--ttl SECS] [--path PREFIX] --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx agent grant fetch --id ID --out DIR [--wait SECS] --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx agent connect --grant DIR [--to IP:PORT] [--service NAME] [--send TEXT] [--timeout SECS] [--every-ms MS] [--max-wait SECS]
orblx agent http [--grant DIR] [--to IP:PORT] [--service NAME] [--method M] [--path TARGET] [--body TEXT] [--repeat N] [--timeout SECS] [--every-ms MS] [--max-wait SECS] [--save-request FILE] [--send-file FILE]
orblx gateway --listen IP:PORT --service NAME --target ADDR [--audit FILE] [--poll-ms MS] [--stale-ms MS] [--coord ADDR] [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx agent guard --listen IP:PORT --service NAME --target ADDR [--audit FILE] [--poll-ms MS] [--stale-ms MS] [--coord ADDR] [--state DIR] [--coord-name NAME] [--bundle FILE]

grant request asks the coordinator for one agent grant with the node SVID in the state directory.
The grant covers one node, one service, and one TCP port. The life is 300 seconds or less.
An owner approves the grant with orblx admin grant-approve ID.
grant fetch gets the agent SVID, the agent ticket, and the signed grant one time.
grant fetch writes the files to DIR. The key and ticket files have mode 0600.
connect sends one use proof to the guard and prints the guard decision.
connect with --every-ms opens a new connection each MS until the guard denies.
It prints the times in Unix ms. first_deny_ms is the time of the deny reply.
connect exits with code 3 when the guard denies.
guard accepts a TCP connection on --listen only with a valid use proof, then forwards it to --target.
guard reads the deny set from the coordinator each --poll-ms with the node SVID.
guard refuses each connection when the last good deny read is older than --stale-ms.
guard writes each grant, use, deny, expiry, and revoke to the audit chain file.
gateway is an HTTP gateway. It reads one request per connection.
gateway forwards a request only with a valid grant proof, a new nonce, and a path inside the grant path prefix.
gateway refuses a request without a grant, out of scope, after the end time, or with a used nonce.
gateway removes the proof headers before it forwards the request. It does not log header values or the query.
http sends one HTTP request with a grant proof and a new nonce. Without --grant it sends no proof.
http with --repeat N sends the same request bytes N times. The second send is a replay.
http with --every-ms sends a new request each MS until the gateway refuses.
http with --save-request FILE keeps the request bytes in FILE (mode 0600). The bytes hold a use proof.
http with --send-file FILE --to IP:PORT sends those bytes again, for a replay test.
Use orblx audit verify-config --file FILE to check that chain.
The command does not print private keys or tickets.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn request_parses_the_scope() {
        let command = parse(&args(&[
            "grant",
            "request",
            "--agent",
            "bot",
            "--node",
            "b",
            "--service",
            "web",
            "--port",
            "8080",
            "--ttl",
            "20",
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap();
        match command {
            Command::Request(request) => {
                assert_eq!(request.ask.port, 8080);
                assert_eq!(request.ask.ttl_secs, 20);
                assert_eq!(request.ask.service, "web");
            }
            _ => panic!("the parser did not select request"),
        }
    }

    #[test]
    fn request_needs_a_port() {
        let err = parse(&args(&[
            "grant",
            "request",
            "--agent",
            "bot",
            "--node",
            "b",
            "--service",
            "web",
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap_err();
        assert!(err.contains("--port"));
    }

    #[test]
    fn guard_needs_listen() {
        let err = parse(&args(&[
            "guard",
            "--service",
            "web",
            "--target",
            "127.0.0.1:80",
        ]))
        .unwrap_err();
        assert!(err.contains("--listen"));
    }

    #[test]
    fn gateway_and_http_parse() {
        let command = super::parse_gateway(&args(&[
            "--listen",
            "100.64.0.3:8080",
            "--service",
            "api",
            "--target",
            "127.0.0.1:8081",
        ]))
        .unwrap();
        assert!(matches!(command, Command::Gateway(_)));
        let Command::Http(http) = parse(&args(&[
            "http", "--grant", "/tmp/g", "--path", "/api/x", "--repeat", "2",
        ]))
        .unwrap() else {
            panic!("not http");
        };
        assert_eq!(http.method, "GET");
        assert_eq!(http.path, "/api/x");
        assert_eq!(http.repeat, 2);
        assert!(parse(&args(&["http", "--path", "/"]))
            .unwrap_err()
            .contains("--to"));
        let Command::Http(saved) = parse(&args(&[
            "http",
            "--to",
            "100.64.0.3:8080",
            "--send-file",
            "/tmp/r",
            "--save-request",
            "/tmp/s",
        ]))
        .unwrap() else {
            panic!("not http");
        };
        assert_eq!(saved.send_file, Some(std::path::PathBuf::from("/tmp/r")));
        assert_eq!(saved.save_request, Some(std::path::PathBuf::from("/tmp/s")));
        assert!(parse(&args(&[
            "http",
            "--grant",
            "/tmp/g",
            "--send-file",
            "/tmp/r"
        ]))
        .unwrap_err()
        .contains("--send-file needs --to"));
    }

    #[test]
    fn saved_request_is_private() {
        let path = std::env::temp_dir().join(format!("orblx-req-{}", std::process::id()));
        super::write_private(&path, b"GET / HTTP/1.1\r\n\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
    }
}
