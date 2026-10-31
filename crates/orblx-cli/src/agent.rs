//! `orblx agent` asks for an agent JIT grant, uses it, and guards one service.
//!
//! The command does not print private keys, tickets, or enroll tokens.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use orblx_agent::{
    connect, new_nonce, plain_http_request, run_gateway, run_guard, seal_http_request, send_http,
    unix_millis, ConnectError, GrantDir, GrantFiles, GrantRefresh, GuardConfig, NodeDeny,
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
    state: PathBuf,
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
    headers: Vec<(String, String)>,
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
    state: PathBuf,
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
    nonce_file: Option<PathBuf>,
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

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.values
            .iter()
            .filter(move |(flag, _)| flag == name)
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
                    "--state",
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
                state: PathBuf::from(flags.get("--state").unwrap_or(DEFAULT_STATE)),
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
                    "--header",
                    "--state",
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
            let mut headers = Vec::new();
            for text in flags.all("--header") {
                let (name, value) = text
                    .split_once(':')
                    .ok_or_else(|| format!("A --header value needs NAME:VALUE.\n{}", help()))?;
                headers
                    .push(orblx_agent::request_header(name, value).map_err(|err| err.to_string())?);
            }
            let method = flags.get("--method").unwrap_or("GET").to_string();
            let path = flags.get("--path").unwrap_or("/").to_string();
            Ok(Command::Http(Http {
                grant,
                state: PathBuf::from(flags.get("--state").unwrap_or(DEFAULT_STATE)),
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
                headers,
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
            "--nonce-file",
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
        nonce_file: flags.get("--nonce-file").map(PathBuf::from),
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
    // Before each attempt the loop reads the grant directory again and takes
    // a newer grant with the same scope (W25-30). No restart is necessary.
    let mut dir = GrantDir::open(&command.grant, NodeDeny::new(&command.state))
        .map_err(|err| err.to_string())?;
    let limit = Instant::now() + command.max_wait;
    let mut last_ok: Option<u64> = None;
    let mut stats = LoopStats::default();
    let mut attempts = 0u64;
    loop {
        refresh_grant(&mut dir, &mut stats);
        let at = now_ms();
        attempts += 1;
        match one_connect(dir.files(), to, &node, &service, &command) {
            Ok(_) => {
                last_ok = Some(at);
                stats.ok(at);
            }
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
                    dir.files().grant.grant.expires.saturating_mul(1000)
                );
                stats.print();
                return Ok(0);
            }
            Err(ConnectError::Failed(text)) => {
                println!("loop attempt {attempts} failed at_ms {at}: {text}");
            }
        }
        if Instant::now() >= limit {
            println!("loop attempts {attempts}");
            stats.print();
            println!("loop no_deny_until_ms {}", now_ms());
            return Ok(EXIT_DENIED);
        }
        std::thread::sleep(every);
    }
}

/// Counters of one loop. They hold no key or ticket.
#[derive(Default)]
struct LoopStats {
    ok_count: u64,
    last_ok: Option<u64>,
    max_ok_gap_ms: u64,
    switches: u64,
}

impl LoopStats {
    fn ok(&mut self, at: u64) {
        if let Some(last) = self.last_ok {
            self.max_ok_gap_ms = self.max_ok_gap_ms.max(at.saturating_sub(last));
        }
        self.last_ok = Some(at);
        self.ok_count += 1;
    }

    fn print(&self) {
        println!("loop ok_attempts {}", self.ok_count);
        println!("loop max_ok_gap_ms {}", self.max_ok_gap_ms);
        println!("loop grant_switches {}", self.switches);
    }
}

/// Read the grant directory again and print a grant change.
fn refresh_grant(dir: &mut GrantDir, stats: &mut LoopStats) {
    match dir.refresh() {
        GrantRefresh::Same => {}
        GrantRefresh::Switched { from, to } => {
            stats.switches += 1;
            println!(
                "loop grant_switch from {from} to {to} at_ms {} expires_ms {}",
                now_ms(),
                dir.files().grant.grant.expires.saturating_mul(1000)
            );
        }
        GrantRefresh::Kept(reason) => {
            println!("loop grant_kept reason {reason} at_ms {}", now_ms());
        }
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
        // The TCP guard has no request nonce. The gateway default is AUDIT.nonces.
        nonce_path: if http { guard.nonce_file } else { None },
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
    let build = |files: Option<&GrantFiles>| -> Result<Vec<u8>, String> {
        match (files, &node) {
            (Some(files), Some(node)) => seal_http_request(
                files,
                to,
                node,
                &service,
                &command.method,
                &command.path,
                &command.headers,
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
            None => build(files.as_ref())?,
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
    // Before each request the loop reads the grant directory again and takes
    // a newer grant with the same scope (W25-30). No restart is necessary.
    let mut dir = match &command.grant {
        Some(path) => Some(
            GrantDir::open(path, NodeDeny::new(&command.state)).map_err(|err| err.to_string())?,
        ),
        None => None,
    };
    let limit = Instant::now() + command.max_wait;
    let mut last_ok: Option<u64> = None;
    let mut stats = LoopStats::default();
    let mut attempts = 0u64;
    loop {
        if let Some(dir) = dir.as_mut() {
            refresh_grant(dir, &mut stats);
        }
        let at = now_ms();
        attempts += 1;
        let bytes = build(dir.as_ref().map(GrantDir::files))?;
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
            println!(
                "loop grant_expires_ms {}",
                dir.as_ref().map_or(expires_ms, |dir| dir
                    .files()
                    .grant
                    .grant
                    .expires
                    .saturating_mul(1000))
            );
            stats.print();
            return Ok(0);
        }
        last_ok = Some(at);
        stats.ok(at);
        if Instant::now() >= limit {
            println!("loop attempts {attempts}");
            stats.print();
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
orblx agent connect --grant DIR [--to IP:PORT] [--service NAME] [--send TEXT] [--timeout SECS] [--every-ms MS] [--max-wait SECS] [--state DIR]
orblx agent http [--grant DIR] [--to IP:PORT] [--service NAME] [--method M] [--path TARGET] [--body TEXT] [--repeat N] [--timeout SECS] [--every-ms MS] [--max-wait SECS] [--save-request FILE] [--send-file FILE] [--header NAME:VALUE]... [--state DIR]
orblx gateway --listen IP:PORT --service NAME --target ADDR [--audit FILE] [--nonce-file FILE] [--poll-ms MS] [--stale-ms MS] [--coord ADDR] [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx agent guard --listen IP:PORT --service NAME --target ADDR [--audit FILE] [--poll-ms MS] [--stale-ms MS] [--coord ADDR] [--state DIR] [--coord-name NAME] [--bundle FILE]

grant request asks the coordinator for one agent grant with the node SVID in the state directory.
The grant covers one node, one service, and one TCP port. The life is 300 seconds or less.
An owner approves the grant with orblx admin grant-approve ID.
grant fetch gets the agent SVID, the agent ticket, and the signed grant one time.
grant fetch writes the files to DIR. The key and ticket files have mode 0600.
connect sends one use proof to the guard and prints the guard decision.
connect with --every-ms opens a new connection each MS until the guard denies.
Before each connection it reads DIR again. A newer grant with the same scope that grant fetch wrote to DIR replaces the current grant.
It never takes a grant that deny.json in the node state (--state, default /var/lib/orblx) revokes.
When it cannot read deny.json or ticket-verifier.pem there, it keeps the current grant.
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
gateway refuses a request with a header that is not the same as the signed header (each header except the proof).
gateway keeps used nonces in --nonce-file (default AUDIT.nonces), apart from the audit chain. A restart reads that file.
http sends one HTTP request with a grant proof and a new nonce. Without --grant it sends no proof.
http with --repeat N sends the same request bytes N times. The second send is a replay.
http with --every-ms sends a new request each MS until the gateway refuses. It reads DIR again before each request, as connect does.
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
        let Command::Http(with_headers) = parse(&args(&[
            "http",
            "--grant",
            "/tmp/g",
            "--header",
            "X-Kind: read",
            "--header",
            "X-Team:a",
        ]))
        .unwrap() else {
            panic!("not http");
        };
        assert_eq!(
            with_headers.headers,
            vec![
                ("x-kind".to_string(), "read".to_string()),
                ("x-team".to_string(), "a".to_string())
            ]
        );
        for bad in ["NoColon", "Host: h", "Orblx-Agent-Nonce: 00"] {
            assert!(parse(&args(&["http", "--grant", "/tmp/g", "--header", bad])).is_err());
        }
        let Command::Gateway(gateway) = super::parse_gateway(&args(&[
            "--listen",
            "100.64.0.3:8080",
            "--service",
            "api",
            "--target",
            "127.0.0.1:8081",
            "--nonce-file",
            "/tmp/n",
        ]))
        .unwrap() else {
            panic!("not gateway");
        };
        assert_eq!(gateway.nonce_file, Some(std::path::PathBuf::from("/tmp/n")));
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

/// W25-30 regression: a running `connect --every-ms` loop takes a new grant
/// from the grant directory and keeps access across the end of the old grant.
/// It never takes a revoked next grant or a next grant with another scope.
#[cfg(test)]
mod grant_end_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;
    use orblx_agent::{run_guard, sign_grant, AgentGrant, GrantFiles, GuardConfig, GRANT_VERSION};
    use orblx_audit::verify_config_file;
    use orblx_identity::{
        sign_agent_jit_ticket, ticket_hash, DenySet, Ipv4Destination, MiniCa, SpiffeId,
        TicketSigner,
    };

    use super::{run_connect, Connect, EXIT_DENIED};

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Write the node deny list with these revoked ticket nonces.
    fn write_deny(state: &Path, nonces: &[&str]) {
        let list: Vec<String> = nonces.iter().map(|nonce| format!("\"{nonce}\"")).collect();
        let text = format!(
            r#"{{"version":{},"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":[{}]}}"#,
            nonces.len() + 1,
            list.join(",")
        );
        std::fs::write(state.join("deny.json"), text).unwrap();
    }

    struct Issued {
        files: GrantFiles,
        end: u64,
        nonce: String,
    }

    struct Issuer {
        ca: MiniCa,
        signer: TicketSigner,
        netmap: SigningKey,
        node: SpiffeId,
        dest: Ipv4Destination,
    }

    impl Issuer {
        /// Issue one grant set that starts now, as the coordinator fetch does.
        fn issue(&self, id: &str, ttl: u64, service: &str) -> Issued {
            let now = SystemTime::now();
            let agent = SpiffeId::agent("bot").unwrap();
            let coord = SpiffeId::coord("coord").unwrap();
            let life = Duration::from_secs(ttl);
            let svid = self.ca.issue(&agent, now, life, &DenySet::empty()).unwrap();
            let ticket =
                sign_agent_jit_ticket(&self.signer, &coord, &agent, now, life, self.dest).unwrap();
            let start = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
            let grant = AgentGrant {
                version: GRANT_VERSION,
                id: id.to_string(),
                agent: agent.as_uri().to_string(),
                requester: SpiffeId::node("a").unwrap().as_uri().to_string(),
                approver: SpiffeId::node("owner").unwrap().as_uri().to_string(),
                node: self.node.as_uri().to_string(),
                addr: self.dest.addr.to_string(),
                service: service.to_string(),
                port: self.dest.port,
                path_prefix: "/".to_string(),
                not_before: start,
                expires: start + ttl,
                ticket_hash: hex(&ticket_hash(&ticket.bytes)),
            };
            Issued {
                files: GrantFiles {
                    cert_pem: svid.certificate_pem,
                    key_pem: svid.private_key_pem,
                    ticket: ticket.bytes,
                    grant: sign_grant(&self.netmap, &grant).unwrap(),
                },
                end: start + ttl,
                nonce: hex(&ticket.nonce),
            }
        }
    }

    /// A guard on 127.0.0.1, a local service, a node state, and a grant directory.
    /// The guard and the agent read the same node deny list.
    struct Rig {
        scratch: Scratch,
        issuer: Issuer,
        listen: SocketAddr,
    }

    impl Rig {
        fn start(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let scratch = Scratch(std::env::temp_dir().join(format!(
                "orblx-w25-30-{name}-{}-{nanos}",
                std::process::id()
            )));
            let _ = std::fs::remove_dir_all(&scratch.0);
            std::fs::create_dir_all(scratch.0.join("state")).unwrap();

            // The local service. Each connection closes at once.
            let service = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let target = service.local_addr().unwrap();
            std::thread::spawn(move || {
                for stream in service.incoming().flatten() {
                    drop(stream);
                }
            });

            let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let issuer = Issuer {
                ca: MiniCa::generate(SystemTime::now() - Duration::from_secs(60)).unwrap(),
                signer: TicketSigner::generate(),
                netmap: SigningKey::from_bytes(&[9u8; 32]),
                node: SpiffeId::node("b").unwrap(),
                dest: Ipv4Destination {
                    addr: Ipv4Addr::LOCALHOST,
                    proto: 6,
                    port,
                },
            };
            let state = scratch.0.join("state");
            std::fs::write(
                state.join("ticket-verifier.pem"),
                issuer.signer.public_key_pem(),
            )
            .unwrap();
            write_deny(&state, &[]);
            let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let config = GuardConfig {
                listen,
                service: "web".to_string(),
                target,
                node: issuer.node.clone(),
                bundle: issuer.ca.trust_bundle().clone(),
                verifier: issuer.signer.verifier(),
                netmap_public: issuer.netmap.verifying_key().to_bytes(),
                audit_path: scratch.0.join("agent-audit.jsonl"),
                nonce_path: None,
                poll: Duration::from_millis(200),
                stale_after: Duration::from_secs(2),
            };
            let deny_path = state.join("deny.json");
            std::thread::spawn(move || {
                let _ = run_guard(
                    config,
                    Box::new(move || {
                        std::fs::read_to_string(&deny_path).map_err(|err| err.to_string())
                    }),
                );
            });
            Self {
                scratch,
                issuer,
                listen,
            }
        }

        fn state(&self) -> PathBuf {
            self.scratch.0.join("state")
        }

        fn grant_dir(&self) -> PathBuf {
            self.scratch.0.join("grant")
        }

        fn audit(&self) -> PathBuf {
            self.scratch.0.join("agent-audit.jsonl")
        }

        /// Start a `connect --every-ms 100 --max-wait 6` loop on the grant directory.
        fn run_loop(&self) -> std::thread::JoinHandle<Result<i32, String>> {
            let connect = Connect {
                grant: self.grant_dir(),
                state: self.state(),
                to: Some(self.listen),
                service: None,
                send: None,
                timeout: Duration::from_secs(5),
                every: Some(Duration::from_millis(100)),
                max_wait: Duration::from_secs(6),
            };
            std::thread::spawn(move || run_connect(connect))
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn a_connect_loop_crosses_a_grant_end_with_a_new_grant() {
        let rig = Rig::start("cross");

        // Grant 1 ends 2 to 3 s from now.
        let first = rig.issuer.issue("00000000000000a1", 3, "web");
        first.files.write(&rig.grant_dir()).unwrap();
        let agent = rig.run_loop();

        // The owner approved grant 2. The agent fetches it to the same
        // directory before grant 1 ends.
        std::thread::sleep(Duration::from_secs(1));
        let second = rig.issuer.issue("00000000000000a2", 10, "web");
        assert!(second.end > first.end);
        second.files.write(&rig.grant_dir()).unwrap();

        // The loop runs for 6 s, past the end of grant 1.
        // Exit code 3 means that the guard did not deny before --max-wait.
        let result = agent.join().unwrap();
        assert_eq!(
            result,
            Ok(EXIT_DENIED),
            "the guard denied the loop (see the loop deny_reason line)"
        );
        assert!(
            now_secs() > first.end,
            "the loop must run past the end of grant 1"
        );

        // The guard chain is good, has uses of both grants, and has no deny.
        let verified = verify_config_file(&rig.audit()).unwrap();
        assert!(verified.records.len() >= 3);
        let text = std::fs::read_to_string(rig.audit()).unwrap();
        assert!(text.contains("00000000000000a1"));
        assert!(text.contains("00000000000000a2"));
        assert!(
            !text.contains("\"agent-deny\""),
            "the guard chain has a deny"
        );
    }

    /// W25-30 gate: a next grant with another scope or a revoked next grant is
    /// never taken. The loop stops at the end of grant 1 with deny `expired`.
    #[test]
    fn a_connect_loop_never_takes_a_revoked_or_other_scope_next_grant() {
        let rig = Rig::start("refuse");
        let first = rig.issuer.issue("00000000000000a1", 3, "web");
        first.files.write(&rig.grant_dir()).unwrap();
        let agent = rig.run_loop();

        // A newer grant for another service arrives first.
        std::thread::sleep(Duration::from_secs(1));
        let other = rig.issuer.issue("00000000000000b1", 10, "db");
        other.files.write(&rig.grant_dir()).unwrap();

        // Then a newer grant with the same scope, which the owner revoked.
        // The node deny list holds its ticket nonce before the agent sees it.
        std::thread::sleep(Duration::from_secs(1));
        let revoked = rig.issuer.issue("00000000000000a2", 10, "web");
        assert!(revoked.end > first.end);
        write_deny(&rig.state(), &[&revoked.nonce]);
        revoked.files.write(&rig.grant_dir()).unwrap();

        // The loop must stop with a deny (exit 0), not run to --max-wait (exit 3).
        let result = agent.join().unwrap();
        assert_eq!(result, Ok(0), "the loop must stop at the end of grant 1");
        assert!(now_secs() >= first.end);

        // The guard saw only grant 1. The deny reason is `expired`.
        let verified = verify_config_file(&rig.audit()).unwrap();
        assert!(verified.records.len() >= 2);
        let text = std::fs::read_to_string(rig.audit()).unwrap();
        assert!(text.contains("00000000000000a1"));
        assert!(!text.contains("00000000000000b1"), "another scope was used");
        assert!(
            !text.contains("00000000000000a2"),
            "a revoked grant was used"
        );
        assert!(text.contains("\"agent-deny\""));
        assert!(text.contains("expired"), "the deny reason is not expired");
        assert!(!text.contains("revoked"), "the guard saw a revoked grant");
    }
}
