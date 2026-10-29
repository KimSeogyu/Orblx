use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

use orblx_identity::{OidcMode, GOOGLE_CLIENT_ID_ENV};

use super::{parse_socket, take_value};
use orblx_coord::{
    enroll_with_token_blocking, fetch_netmap_blocking, oidc_config, serve_blocking, Coordinator,
    OidcConfig,
};

const DEFAULT_PORT: u16 = 443;

/// A coordinator command.
#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Serve {
        state: PathBuf,
        listen: SocketAddr,
        name: String,
        policy: Option<PathBuf>,
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
        token_file: PathBuf,
        state: PathBuf,
        endpoints: Vec<String>,
        routes: Vec<String>,
    },
    Netmap {
        coord: SocketAddr,
        coord_name: String,
        bundle: PathBuf,
        state: PathBuf,
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
        } => {
            let mode = OidcMode::from_env().map_err(|err| err.to_string())?;
            let client_id = std::env::var(GOOGLE_CLIENT_ID_ENV).ok();
            if matches!(mode, OidcMode::Mock) {
                println!(
                    "Mock mode does not enable laptop login on the coordinator. Token enrollment is ready."
                );
            }
            let oidc = oidc_config(mode, client_id).map_err(|err| err.to_string())?;
            let coord = Coordinator::open(&state, &name, oidc).map_err(|err| err.to_string())?;
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
            token_file,
            state,
            endpoints,
            routes,
        } => {
            let bundle_pem = fs::read_to_string(&bundle)
                .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
            let token = fs::read_to_string(&token_file)
                .map_err(|err| format!("The enroll token file did not open. {err}"))?;
            let token = token.trim();
            if token.is_empty() {
                return Err("The enroll token file is empty.".to_string());
            }
            let result = enroll_with_token_blocking(
                coord,
                &coord_name,
                &bundle_pem,
                &name,
                token,
                &endpoints,
                &routes,
            )
            .map_err(|err| err.to_string())?;
            result.write_state(&state).map_err(|err| err.to_string())?;
            print_enrolled(&result);
            Ok(())
        }
        Command::Netmap {
            coord,
            coord_name,
            bundle,
            state,
        } => {
            let bundle_pem = fs::read_to_string(&bundle)
                .map_err(|err| format!("The file {} did not open. {err}", bundle.display()))?;
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
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Serve {
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        listen: listen.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))),
        name: name.unwrap_or_else(|| "coord".to_string()),
        policy,
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
    let mut state = None;
    let mut endpoints = Vec::new();
    let mut routes = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--name" => name = Some(value),
            "--coord" => coord = Some(parse_socket(&value, DEFAULT_PORT)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--token-file" => token_file = Some(PathBuf::from(value)),
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
        token_file: token_file.ok_or_else(|| "The command needs --token-file.".to_string())?,
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        endpoints,
        routes,
    })
}

fn parse_netmap(args: &[String]) -> Result<Command, String> {
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut state = None;
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
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Netmap {
        coord: coord.ok_or_else(|| "The command needs --coord.".to_string())?,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle: bundle.ok_or_else(|| "The command needs --bundle.".to_string())?,
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
    })
}

fn help() -> String {
    "\
orblx coord serve --state DIR [--listen ADDR] [--name NAME] [--policy FILE]
orblx coord token create --state DIR --out FILE [--ttl SECS]
orblx coord enroll --name NAME --coord ADDR --bundle FILE --token-file FILE --state DIR [--coord-name NAME] [--endpoint HOST:PORT] [--route CIDR]
orblx coord netmap --coord ADDR --bundle FILE --state DIR [--coord-name NAME]

The coordinator listens with QUIC.
The default listen address is 0.0.0.0:443.
The default coordinator name is coord.
The node SVID is spiffe://orblx.local/node/{name}.
The coordinator SVID is spiffe://orblx.local/coord/{name}.
An enroll token is one use.
The command writes the token only to --out.
The command does not print the token.
The default policy file is DIR/policy.hujson.
A failed policy test keeps the last good policy.
The coordinator logs one error line for that failure.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

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
            | Command::Netmap { .. } => {
                panic!("the parser did not select serve");
            }
        }
    }
}
