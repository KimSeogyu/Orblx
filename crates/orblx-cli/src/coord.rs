use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use orblx_identity::{OidcMode, GOOGLE_CLIENT_ID_ENV, MAX_USER_TTL};

use super::{parse_socket, take_value};
use orblx_coord::{
    advertise_routes_blocking, enroll_with_oidc_blocking, enroll_with_token_blocking,
    fetch_netmap_blocking, fetch_policy_wait_blocking, oidc_config, serve_blocking, CoordConfig,
    Coordinator, OidcConfig, OidcEnroll,
};

const DEFAULT_PORT: u16 = 443;

/// How `orblx coord enroll` proves the right to enroll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollSecret {
    /// An enroll token file.
    Token(PathBuf),
    /// An OIDC ID token file and an optional nonce.
    IdToken {
        file: PathBuf,
        nonce: Option<String>,
        /// Try again while the user waits for owner approval (W25-15).
        wait_approval: Option<Duration>,
    },
}

/// A coordinator command.
#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Serve {
        state: PathBuf,
        listen: SocketAddr,
        name: String,
        policy: Option<PathBuf>,
        config: Option<PathBuf>,
    },
    TokenCreate {
        state: PathBuf,
        out: PathBuf,
        ttl: Duration,
    },
    Enroll {
        name: String,
        coord: SocketAddr,
        coord_name: String,
        bundle: PathBuf,
        secret: EnrollSecret,
        state: PathBuf,
        endpoints: Vec<String>,
        routes: Vec<String>,
    },
    Netmap {
        coord: SocketAddr,
        coord_name: String,
        bundle: PathBuf,
        state: PathBuf,
        /// W25-6: keep the files current with `policy-wait`.
        watch: bool,
    },
    Advertise {
        coord: SocketAddr,
        coord_name: String,
        bundle: PathBuf,
        state: PathBuf,
        routes: Vec<String>,
        exit_node: Option<bool>,
    },
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    match args[0].as_str() {
        "serve" => parse_serve(&args[1..]),
        "token" => parse_token(&args[1..]),
        "enroll" => parse_enroll(&args[1..]),
        "netmap" => parse_netmap(&args[1..]),
        "advertise" => parse_advertise(&args[1..]),
        other => Err(format!("The mode {other} is not valid.\n{}", help())),
    }
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Serve {
            state,
            listen,
            name,
            policy,
            config,
        } => {
            let from_file = match &config {
                Some(path) => CoordConfig::from_file(path)
                    .and_then(|parsed| parsed.oidc_config())
                    .map_err(|err| err.to_string())?,
                None => None,
            };
            let oidc = match from_file {
                Some(oidc) => {
                    if let OidcConfig::Issuer { issuer, .. } = &oidc {
                        println!(
                            "oidc issuer {} client_id {} allowed_domains {} allowed_emails {}",
                            issuer.issuer(),
                            issuer.client_id(),
                            issuer.allowed_domains().len(),
                            issuer.allowed_emails().len()
                        );
                    }
                    oidc
                }
                None => {
                    let mode = OidcMode::from_env().map_err(|err| err.to_string())?;
                    let client_id = std::env::var(GOOGLE_CLIENT_ID_ENV).ok();
                    if matches!(mode, OidcMode::Mock) {
                        println!(
                            "Mock mode does not enable laptop login on the coordinator. Token enrollment is ready."
                        );
                    }
                    oidc_config(mode, client_id).map_err(|err| err.to_string())?
                }
            };
            let coord = Coordinator::open(&state, &name, oidc).map_err(|err| err.to_string())?;
            if let Some(ttl) = node_svid_ttl_from_env()? {
                coord
                    .set_node_svid_ttl(ttl)
                    .map_err(|err| err.to_string())?;
                println!("node svid ttl {}", ttl.as_secs());
            }
            if let Some(policy) = policy {
                coord
                    .set_policy_file(&policy)
                    .map_err(|err| err.to_string())?;
            }
            println!("state {}", state.display());
            serve_blocking(&coord, listen).map_err(|err| err.to_string())
        }
        Command::TokenCreate { state, out, ttl } => {
            let name = stored_coord_name(&state)?;
            let coord = Coordinator::open(&state, &name, OidcConfig::TokenOnly)
                .map_err(|err| err.to_string())?;
            let created = coord.create_token(ttl).map_err(|err| err.to_string())?;
            write_secret(&out, &created.secret)?;
            println!("wrote one enroll token");
            println!("token_id {}", created.id);
            println!("expires_unix {}", created.expires_unix);
            println!("out {}", out.display());
            Ok(())
        }
        Command::Enroll {
            name,
            coord,
            coord_name,
            bundle,
            secret,
            state,
            endpoints,
            routes,
        } => {
            let bundle_pem = fs::read_to_string(&bundle)
                .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
            let result = match &secret {
                EnrollSecret::Token(token_file) => {
                    let token = fs::read_to_string(token_file)
                        .map_err(|err| format!("The enroll token file did not open. {err}"))?;
                    let token = token.trim();
                    if token.is_empty() {
                        return Err("The enroll token file is empty.".to_string());
                    }
                    enroll_with_token_blocking(
                        coord,
                        &coord_name,
                        &bundle_pem,
                        &name,
                        token,
                        &endpoints,
                        &routes,
                    )
                }
                EnrollSecret::IdToken {
                    file,
                    nonce,
                    wait_approval,
                } => {
                    let id_token = fs::read_to_string(file)
                        .map_err(|err| format!("The ID token file did not open. {err}"))?;
                    let id_token = id_token.trim();
                    if id_token.is_empty() {
                        return Err("The ID token file is empty.".to_string());
                    }
                    let enroll = || {
                        enroll_with_oidc_blocking(OidcEnroll {
                            coord,
                            coord_name: &coord_name,
                            bundle_pem: &bundle_pem,
                            name: &name,
                            id_token,
                            nonce: nonce.as_deref(),
                            endpoints: &endpoints,
                            routes: &routes,
                        })
                    };
                    match wait_approval {
                        Some(limit) => enroll_wait_approval(enroll, *limit),
                        None => enroll(),
                    }
                }
            }
            .map_err(|err| err.to_string())?;
            // W25-34: a new enrollment is the local reset of the last netmap seq.
            orblx_coord::reset_node_seq(&state).map_err(|err| err.to_string())?;
            result.write_state(&state).map_err(|err| err.to_string())?;
            remember_coord(&state, coord, &coord_name)?;
            print_enrolled(&result);
            Ok(())
        }
        Command::Advertise {
            coord,
            coord_name,
            bundle,
            state,
            routes,
            exit_node,
        } => {
            let bundle_pem = fs::read_to_string(&bundle)
                .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
            if !routes.is_empty() {
                let view =
                    advertise_routes_blocking(coord, &coord_name, &bundle_pem, &state, &routes)
                        .map_err(|err| err.to_string())?;
                for route in &view.approved_routes {
                    println!("approved route {route}");
                }
                for route in &view.advertised_routes {
                    if !view.approved_routes.iter().any(|item| item == route) {
                        println!("held route {route}");
                    }
                }
                println!("advertised {}", view.advertised_routes.len());
            }
            if let Some(enabled) = exit_node {
                let view = orblx_coord::advertise_exit_blocking(
                    coord,
                    &coord_name,
                    &bundle_pem,
                    &state,
                    enabled,
                )
                .map_err(|err| err.to_string())?;
                let state = if view.exit_approved {
                    "approved"
                } else if enabled {
                    "held"
                } else {
                    "off"
                };
                println!("exit_node {state}");
            }
            Ok(())
        }
        Command::Netmap {
            coord,
            coord_name,
            bundle,
            state,
            watch,
        } => {
            let bundle_pem = fs::read_to_string(&bundle)
                .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
            if watch {
                return watch_netmap(coord, &coord_name, &bundle_pem, &state);
            }
            let view = fetch_netmap_blocking(coord, &coord_name, &bundle_pem, &state)
                .map_err(|err| err.to_string())?;
            println!("netmap");
            println!("name {}", view.signed_netmap.netmap.self_node.name);
            println!(
                "overlay_ip {}",
                view.signed_netmap.netmap.self_node.overlay_ip
            );
            for peer in &view.signed_netmap.netmap.peers {
                println!("peer {} {}", peer.name, peer.overlay_ip);
            }
            println!("endpoints_ok {}", view.endpoints.len());
            println!("grants {}", view.signed_grants.grants.grants.len());
            Ok(())
        }
    }
}

/// Keep the netmap files of `state` current with `policy-wait` (W25-6).
///
/// The command prints one `policy_update UNIX_MS` line for each new netmap, grant set,
/// or deny list. It stops only on a signal.
fn watch_netmap(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state: &std::path::Path,
) -> Result<(), String> {
    let mut etag: Option<String> = None;
    loop {
        match fetch_policy_wait_blocking(coord, coord_name, bundle_pem, state, etag.as_deref()) {
            Ok(sync) => {
                let write = sync
                    .view
                    .write_state_checked(state)
                    .map_err(|err| err.public_text())?;
                // W25-34: a signed heartbeat changes only the stamp, so it prints no line.
                if write == orblx_coord::ViewWrite::Content {
                    let unix_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |since| since.as_millis());
                    println!("policy_update {unix_ms}");
                }
                etag = Some(sync.etag);
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(err) => {
                eprintln!("The policy wait failed. {}", err.public_text());
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn node_svid_ttl_from_env() -> Result<Option<Duration>, String> {
    let Ok(text) = std::env::var("ORBLX_SVID_TTL") else {
        return Ok(None);
    };
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let secs: u64 = text
        .parse()
        .map_err(|_| "ORBLX_SVID_TTL is not a number of seconds.".to_string())?;
    if secs == 0 || secs > MAX_USER_TTL.as_secs() {
        return Err(format!(
            "ORBLX_SVID_TTL must be from 1 to {} seconds.",
            MAX_USER_TTL.as_secs()
        ));
    }
    Ok(Some(Duration::from_secs(secs)))
}

fn remember_coord(state: &std::path::Path, coord: SocketAddr, name: &str) -> Result<(), String> {
    fs::write(state.join("coord-addr"), format!("{coord}\n")).map_err(|err| {
        format!(
            "The file {} was not written. {err}",
            state.join("coord-addr").display()
        )
    })?;
    fs::write(state.join("coord-name"), format!("{name}\n")).map_err(|err| {
        format!(
            "The file {} was not written. {err}",
            state.join("coord-name").display()
        )
    })?;
    Ok(())
}

fn stored_coord_name(state: &std::path::Path) -> Result<String, String> {
    let path = state.join("coord-name");
    if path.exists() {
        let text = fs::read_to_string(&path)
            .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
        let name = text.trim();
        if name.is_empty() {
            return Err("The coordinator name is empty.".to_string());
        }
        return Ok(name.to_string());
    }
    Ok("coord".to_string())
}

fn print_enrolled(result: &orblx_coord::EnrollResult) {
    println!("enrolled");
    println!("name {}", result.name);
    println!("overlay_ip {}", result.overlay_ip);
    println!("svid {}", result.svid);
    println!("peers {}", result.signed_netmap.netmap.peers.len());
}

fn write_secret(path: &std::path::Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("The directory {} did not open. {err}", parent.display()))?;
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
    let mut perms = file
        .metadata()
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    file.set_permissions(perms)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
    Ok(())
}

fn parse_serve(args: &[String]) -> Result<Command, String> {
    let mut state = None;
    let mut listen = None;
    let mut name = None;
    let mut policy = None;
    let mut config = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--state" => state = Some(PathBuf::from(value)),
            "--listen" => listen = Some(parse_socket(&value, DEFAULT_PORT)?),
            "--name" => name = Some(value),
            "--policy" => policy = Some(PathBuf::from(value)),
            "--config" => config = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Serve {
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        listen: listen.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))),
        name: name.unwrap_or_else(|| "coord".to_string()),
        policy,
        config,
    })
}

fn parse_token(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) != Some("create") {
        return Err(format!("The mode is not token create.\n{}", help()));
    }
    let mut state = None;
    let mut out = None;
    let mut ttl = Duration::from_secs(3600);
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--state" => state = Some(PathBuf::from(value)),
            "--out" => out = Some(PathBuf::from(value)),
            "--ttl" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|_| "The TTL is not a number of seconds.".to_string())?;
                ttl = Duration::from_secs(secs);
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::TokenCreate {
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        out: out.ok_or_else(|| "The command needs --out.".to_string())?,
        ttl,
    })
}

fn parse_enroll(args: &[String]) -> Result<Command, String> {
    let mut name = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut token_file = None;
    let mut id_token_file = None;
    let mut nonce = None;
    let mut wait_approval = None;
    let mut state = None;
    let mut endpoints = Vec::new();
    let mut routes = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--wait-approval" => wait_approval = Some(parse_wait_approval(&value)?),
            "--name" => name = Some(value),
            "--coord" => coord = Some(parse_socket(&value, DEFAULT_PORT)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--token-file" => token_file = Some(PathBuf::from(value)),
            "--id-token-file" => id_token_file = Some(PathBuf::from(value)),
            "--nonce" => nonce = Some(value),
            "--state" => state = Some(PathBuf::from(value)),
            "--endpoint" => endpoints.push(value),
            "--route" => routes.push(value),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Enroll {
        name: name.ok_or_else(|| "The command needs --name.".to_string())?,
        coord: coord.ok_or_else(|| "The command needs --coord.".to_string())?,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle: bundle.ok_or_else(|| "The command needs --bundle.".to_string())?,
        secret: match (token_file, id_token_file, nonce) {
            (Some(_), None, _) if wait_approval.is_some() => {
                return Err("The --wait-approval flag needs --id-token-file.".to_string())
            }
            (Some(file), None, None) => EnrollSecret::Token(file),
            (None, Some(file), nonce) => EnrollSecret::IdToken {
                file,
                nonce,
                wait_approval,
            },
            (Some(_), Some(_), _) => {
                return Err("Use --token-file or --id-token-file, not both.".to_string())
            }
            (Some(_), None, Some(_)) => {
                return Err("The --nonce flag needs --id-token-file.".to_string())
            }
            (None, None, _) => {
                return Err("The command needs --token-file or --id-token-file.".to_string())
            }
        },
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        endpoints,
        routes,
    })
}

/// The longest `--wait-approval` time: one hour.
const MAX_WAIT_APPROVAL_SECS: u64 = 3600;

/// The time between two enroll tries while the user waits for approval.
const APPROVAL_POLL: Duration = Duration::from_millis(250);

fn parse_wait_approval(value: &str) -> Result<Duration, String> {
    let secs: u64 = value
        .parse()
        .map_err(|_| "The --wait-approval value is not a number of seconds.".to_string())?;
    if !(1..=MAX_WAIT_APPROVAL_SECS).contains(&secs) {
        return Err(format!(
            "The --wait-approval value must be 1 to {MAX_WAIT_APPROVAL_SECS} seconds."
        ));
    }
    Ok(Duration::from_secs(secs))
}

/// Enroll again while the coordinator says that the user waits for approval (W25-15).
///
/// The ID token stays the same. The token expiry also ends the wait.
fn enroll_wait_approval<T>(
    mut enroll: impl FnMut() -> Result<T, orblx_coord::CoordError>,
    limit: Duration,
) -> Result<T, orblx_coord::CoordError> {
    let start = Instant::now();
    let mut told = false;
    loop {
        match enroll() {
            Err(orblx_coord::CoordError::Protocol(text))
                if text == orblx_coord::USER_PENDING_TEXT && start.elapsed() < limit =>
            {
                if !told {
                    println!("enroll pending: {text}");
                    told = true;
                }
                std::thread::sleep(APPROVAL_POLL);
            }
            other => {
                if told && other.is_ok() {
                    println!("approval_wait_ms {}", start.elapsed().as_millis());
                }
                return other;
            }
        }
    }
}

fn parse_advertise(args: &[String]) -> Result<Command, String> {
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut state = None;
    let mut routes = Vec::new();
    let mut exit_node = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--coord" => coord = Some(parse_socket(&value, DEFAULT_PORT)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--state" => state = Some(PathBuf::from(value)),
            "--route" => routes.push(value),
            "--exit-node" => {
                exit_node = Some(match value.as_str() {
                    "on" => true,
                    "off" => false,
                    _ => return Err("The --exit-node value must be on or off.".to_string()),
                })
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    if routes.is_empty() && exit_node.is_none() {
        return Err(format!(
            "The command needs --route or --exit-node.\n{}",
            help()
        ));
    }
    Ok(Command::Advertise {
        coord: coord.ok_or_else(|| "The command needs --coord.".to_string())?,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle: bundle.ok_or_else(|| "The command needs --bundle.".to_string())?,
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        routes,
        exit_node,
    })
}

fn parse_netmap(args: &[String]) -> Result<Command, String> {
    let mut watch = false;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut state = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--watch" {
            watch = true;
            continue;
        }
        let value = take_value(args, &mut index)?;
        match flag {
            "--coord" => coord = Some(parse_socket(&value, DEFAULT_PORT)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--state" => state = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Netmap {
        watch,
        coord: coord.ok_or_else(|| "The command needs --coord.".to_string())?,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle: bundle.ok_or_else(|| "The command needs --bundle.".to_string())?,
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
    })
}

fn help() -> String {
    "\
orblx coord serve --state DIR [--listen ADDR] [--name NAME] [--policy FILE] [--config FILE]
orblx coord token create --state DIR --out FILE [--ttl SECS]
orblx coord enroll --name NAME --coord ADDR --bundle FILE (--token-file FILE | --id-token-file FILE [--nonce HEX] [--wait-approval SECS]) --state DIR [--coord-name NAME] [--endpoint HOST:PORT] [--route CIDR]
orblx coord advertise --coord ADDR --bundle FILE --state DIR [--route CIDR]... [--exit-node on|off] [--coord-name NAME]
orblx coord netmap --coord ADDR --bundle FILE --state DIR [--coord-name NAME] [--watch]

The coordinator listens with QUIC.
The default listen address is 0.0.0.0:443.
The default coordinator name is coord.
The node SVID is spiffe://orblx.local/node/{name}.
The coordinator SVID is spiffe://orblx.local/coord/{name}.
An enroll token is one use.
The command writes the token only to --out.
The command does not print the token.
ORBLX_SVID_TTL sets the node leaf life in seconds.
The default life is 900 seconds.
The enroll command stores the coordinator address in the state directory.
The default policy file is DIR/policy.hujson.
A failed policy test keeps the last good policy.
The coordinator logs one error line for that failure.
orblx coord advertise stores subnet CIDRs for an enrolled node.
The signed netmap includes a route after the policy approves it.
A route that the policy does not approve stays out of the signed netmap.
The route 0.0.0.0/0 is an exit route.
--exit-node on offers this node as an exit node. --exit-node off clears the offer.
The coordinator writes each route change and exit-node change to config-audit.jsonl.
--config FILE reads the [oidc] section: issuer, client_id, allowed_domains, allowed_emails, ca_file.
preset = \"google\" selects Google as the issuer.
--id-token-file enrolls with an OIDC ID token from the configured issuer.
The command does not print the ID token.
A new OIDC user waits until an owner runs orblx admin user-approve.
A waiting or rejected user gets no SVID.
--wait-approval SECS tries the enroll again each 250 ms while the user waits, up to SECS (1 to 3600).
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    #[test]
    fn wait_approval_needs_an_id_token_and_a_valid_time() {
        let base = |extra: &[&str]| {
            let mut args: Vec<String> = [
                "enroll",
                "--name",
                "pc",
                "--coord",
                "127.0.0.1:443",
                "--bundle",
                "/tmp/b",
                "--state",
                "/tmp/s",
            ]
            .iter()
            .map(|text| text.to_string())
            .collect();
            args.extend(extra.iter().map(|text| text.to_string()));
            parse(&args)
        };
        match base(&["--id-token-file", "/tmp/t", "--wait-approval", "30"]).unwrap() {
            Command::Enroll {
                secret: super::EnrollSecret::IdToken { wait_approval, .. },
                ..
            } => assert_eq!(wait_approval, Some(std::time::Duration::from_secs(30))),
            _ => panic!("not an OIDC enroll"),
        }
        assert!(base(&["--token-file", "/tmp/t", "--wait-approval", "30"]).is_err());
        assert!(base(&["--id-token-file", "/tmp/t", "--wait-approval", "0"]).is_err());
        assert!(base(&["--id-token-file", "/tmp/t", "--wait-approval", "3601"]).is_err());
        assert!(base(&["--id-token-file", "/tmp/t", "--wait-approval", "x"]).is_err());
    }

    #[test]
    fn wait_approval_tries_again_only_while_the_user_is_pending() {
        use orblx_coord::CoordError;
        let mut calls = 0;
        let result = super::enroll_wait_approval(
            || {
                calls += 1;
                if calls < 3 {
                    Err(CoordError::Protocol(
                        orblx_coord::USER_PENDING_TEXT.to_string(),
                    ))
                } else {
                    Ok(calls)
                }
            },
            std::time::Duration::from_secs(5),
        );
        assert_eq!(result.unwrap(), 3);
        let mut rejected = 0;
        let result: Result<(), _> = super::enroll_wait_approval(
            || {
                rejected += 1;
                Err(CoordError::Protocol(
                    orblx_coord::USER_REJECTED_TEXT.to_string(),
                ))
            },
            std::time::Duration::from_secs(5),
        );
        assert!(result.is_err());
        assert_eq!(rejected, 1);
        let start = std::time::Instant::now();
        let result: Result<(), _> = super::enroll_wait_approval(
            || {
                Err(CoordError::Protocol(
                    orblx_coord::USER_PENDING_TEXT.to_string(),
                ))
            },
            std::time::Duration::from_secs(1),
        );
        assert!(result.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn token_create_requires_out() {
        let err = parse(&[
            "token".to_string(),
            "create".to_string(),
            "--state".to_string(),
            "/tmp/coord".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("--out"));
    }

    #[test]
    fn serve_defaults_to_udp_443() {
        let command = parse(&[
            "serve".to_string(),
            "--state".to_string(),
            "/tmp/coord".to_string(),
        ])
        .unwrap();
        match command {
            Command::Serve { listen, name, .. } => {
                assert_eq!(listen.port(), 443);
                assert_eq!(name, "coord");
            }
            Command::Help
            | Command::TokenCreate { .. }
            | Command::Enroll { .. }
            | Command::Netmap { .. }
            | Command::Advertise { .. } => {
                panic!("the parser did not select serve");
            }
        }
    }
}
