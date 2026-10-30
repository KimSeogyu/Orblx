//! `orblx serve` and `orblx funnel`.
//!
//! The commands change `serve.json` in the node state directory.
//! The node daemon opens and closes the listeners.
//! Each change appends one record to `serve-audit.jsonl`.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use orblx_identity::{DenySet, TrustBundle};
use orblx_serve::{
    disable_serve, enable_serve, set_funnel, ServeChange, ServeConfig, DEFAULT_HTTPS_PORT,
    DEFAULT_MAX_BODY_BYTES, SERVE_AUDIT_FILE,
};

use super::take_value;

const DEFAULT_STATE_DIR: &str = "/var/lib/orblx";

/// A serve or funnel command.
#[derive(Debug)]
pub(crate) enum Command {
    Help(String),
    Serve {
        state_dir: PathBuf,
        target_port: u16,
        https_port: u16,
        max_body_bytes: Option<u64>,
    },
    ServeOff {
        state_dir: PathBuf,
    },
    FunnelOn {
        state_dir: PathBuf,
        listen: Option<SocketAddr>,
    },
    FunnelOff {
        state_dir: PathBuf,
    },
    Status {
        state_dir: PathBuf,
    },
}

pub(crate) fn parse_serve(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help(serve_help()));
    }
    let (words, flags) = split(args)?;
    let state_dir = flags.state_dir.clone();
    match words.as_slice() {
        [word] if word == "off" => Ok(Command::ServeOff { state_dir }),
        [word] if word == "status" => Ok(Command::Status { state_dir }),
        [port] => {
            let target_port = parse_port(port)?;
            Ok(Command::Serve {
                state_dir,
                target_port,
                https_port: flags.https_port.unwrap_or(DEFAULT_HTTPS_PORT),
                max_body_bytes: flags.max_body_bytes,
            })
        }
        _ => Err(format!("The serve command is not valid.\n{}", serve_help())),
    }
}

pub(crate) fn parse_funnel(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help(funnel_help()));
    }
    let (words, flags) = split(args)?;
    let state_dir = flags.state_dir.clone();
    match words.as_slice() {
        [word] if word == "on" => Ok(Command::FunnelOn {
            state_dir,
            listen: flags.listen,
        }),
        [word] if word == "off" => Ok(Command::FunnelOff { state_dir }),
        [word] if word == "status" => Ok(Command::Status { state_dir }),
        _ => Err(format!(
            "The funnel command is not valid.\n{}",
            funnel_help()
        )),
    }
}

struct Flags {
    state_dir: PathBuf,
    https_port: Option<u16>,
    listen: Option<SocketAddr>,
    max_body_bytes: Option<u64>,
}

fn split(args: &[String]) -> Result<(Vec<String>, Flags), String> {
    let mut words = Vec::new();
    let mut state_dir = None;
    let mut https_port = None;
    let mut listen = None;
    let mut max_body_bytes = None;
    let mut index = 0;
    while index < args.len() {
        let item = args[index].as_str();
        if item.starts_with('-') {
            index += 1;
            let value = take_value(args, &mut index)?;
            match item {
                "--state-dir" | "--state" => state_dir = Some(PathBuf::from(value)),
                "--https-port" => https_port = Some(parse_port(&value)?),
                "--listen" => {
                    listen = Some(
                        value
                            .parse::<SocketAddr>()
                            .map_err(|_| "The --listen value is not ip:port.".to_string())?,
                    );
                }
                "--max-body" => match value.parse::<u64>() {
                    Ok(limit) if limit > 0 => max_body_bytes = Some(limit),
                    _ => {
                        return Err("The --max-body value is not a positive byte count.".to_string())
                    }
                },
                other => return Err(format!("The flag {other} is not valid.")),
            }
        } else {
            words.push(item.to_string());
            index += 1;
        }
    }
    Ok((
        words,
        Flags {
            state_dir: state_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
            https_port,
            listen,
            max_body_bytes,
        },
    ))
}

fn parse_port(text: &str) -> Result<u16, String> {
    match text.parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(format!("The port {text} is not valid.")),
    }
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Serve {
            state_dir,
            target_port,
            https_port,
            max_body_bytes,
        } => {
            let actor = actor(&state_dir)?;
            let change = enable_serve(&state_dir, target_port, https_port, max_body_bytes, &actor)?;
            report(&state_dir, &change)
        }
        Command::ServeOff { state_dir } => {
            let actor = actor(&state_dir)?;
            let change = disable_serve(&state_dir, &actor)?;
            report(&state_dir, &change)
        }
        Command::FunnelOn { state_dir, listen } => {
            let actor = actor(&state_dir)?;
            let change = set_funnel(&state_dir, true, listen, &actor)?;
            report(&state_dir, &change)
        }
        Command::FunnelOff { state_dir } => {
            let actor = actor(&state_dir)?;
            let change = set_funnel(&state_dir, false, None, &actor)?;
            report(&state_dir, &change)
        }
        Command::Status { state_dir } => {
            let config = ServeConfig::load(&state_dir)?;
            print_state(config.as_ref());
            Ok(())
        }
    }
}

fn report(state_dir: &Path, change: &ServeChange) -> Result<(), String> {
    print_state(change.config.as_ref());
    match change.record {
        Some(index) => println!(
            "audit record {index} in {}",
            state_dir.join(SERVE_AUDIT_FILE).display()
        ),
        None => println!("audit no change"),
    }
    Ok(())
}

fn print_state(config: Option<&ServeConfig>) {
    match config {
        None => {
            println!("serve off");
            println!("funnel off");
        }
        Some(config) => {
            println!(
                "serve on https_port {} target 127.0.0.1:{} max_body {}",
                config.https_port,
                config.target_port,
                config.body_limit()
            );
            match (config.funnel, config.funnel_listen) {
                (true, Some(addr)) => println!("funnel on listen {addr}"),
                _ => println!("funnel off"),
            }
        }
    }
}

/// The audit actor is the node SPIFFE ID from the node SVID.
fn actor(state_dir: &Path) -> Result<String, String> {
    let cert_pem = fs::read_to_string(state_dir.join("cert.pem"))
        .map_err(|_| "The node SVID did not open.".to_string())?;
    let bundle_pem = fs::read_to_string(state_dir.join("bundle.pem"))
        .map_err(|_| "The trust bundle did not open.".to_string())?;
    let bundle = TrustBundle::from_pem(&bundle_pem)
        .map_err(|_| "The trust bundle is not valid.".to_string())?;
    let der = orblx_identity::decode_certificate_pem(&cert_pem)
        .map_err(|_| "The node SVID is not valid.".to_string())?;
    let id = bundle
        .authenticate_leaf(&der, SystemTime::now(), &DenySet::empty())
        .map_err(|_| "The node SVID is not valid.".to_string())?;
    Ok(id.as_uri().to_string())
}

fn serve_help() -> String {
    format!(
        "\
orblx serve PORT [--https-port N] [--max-body BYTES] [--state-dir DIR]
orblx serve off [--state-dir DIR]
orblx serve status [--state-dir DIR]

serve publishes 127.0.0.1:PORT over HTTPS on the overlay address of this node.
The TLS certificate is the node SVID. The orblx.local CA signs it.
The policy file DIR/policy.hujson must allow the source on TCP at the HTTPS port.
The default is deny.
The default HTTPS port is {DEFAULT_HTTPS_PORT}.
serve reads each HTTP/1.1 request. It accepts Content-Length and chunked bodies.
A body above the limit gets 413. The default limit is {DEFAULT_MAX_BODY_BYTES} bytes.
Only a connection that comes in on the overlay TUN interface can use a peer address.
Funnel stays off. Use orblx funnel on to publish outside the overlay.
Each change appends one record to DIR/{SERVE_AUDIT_FILE}.
The default state directory is {DEFAULT_STATE_DIR}.
"
    )
}

fn funnel_help() -> String {
    format!(
        "\
orblx funnel on --listen IP:PORT [--state-dir DIR]
orblx funnel off [--state-dir DIR]
orblx funnel status [--state-dir DIR]

funnel publishes the serve port on one outside address.
Funnel is off by default. Only funnel on opens the outside listener.
Funnel needs serve on.
The listen address must not be 0.0.0.0 or an overlay address.
Any host that can reach the outside address can open the HTTPS port.
Each change appends one record to DIR/{SERVE_AUDIT_FILE}.
Check the chain with orblx audit verify-config --file DIR/{SERVE_AUDIT_FILE}.
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn parse_serve_and_funnel() {
        match parse_serve(&args("8080 --state-dir /tmp/x")) {
            Ok(Command::Serve {
                target_port: 8080,
                https_port: 443,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        match parse_serve(&args("8080 --https-port 8443")) {
            Ok(Command::Serve {
                https_port: 8443,
                max_body_bytes: None,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        match parse_serve(&args("8080 --max-body 4096")) {
            Ok(Command::Serve {
                max_body_bytes: Some(4096),
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        assert!(parse_serve(&args("8080 --max-body 0")).is_err());
        assert!(matches!(
            parse_serve(&args("off")),
            Ok(Command::ServeOff { .. })
        ));
        assert!(parse_serve(&args("0")).is_err());
        match parse_funnel(&args("on --listen 192.0.2.1:8443")) {
            Ok(Command::FunnelOn {
                listen: Some(addr), ..
            }) => assert_eq!(addr.port(), 8443),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_funnel(&args("off")),
            Ok(Command::FunnelOff { .. })
        ));
        assert!(parse_funnel(&args("maybe")).is_err());
    }
}
