//! `orblx ping` prints the path kind and the round-trip time.
//!
//! The node must be in the netmap.
//! A revoked node cannot send packets.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use orblx_coord::fetch_deny_blocking;
use orblx_datapath::{measure_hello_rtt, Netmap};
use orblx_identity::{DenySet, DenyStore, SpiffeId};
use orblx_relay::{encode_datagram, RelayKind, RelaySessionId};

use super::ticket_load;
use super::{parse_socket, take_value};

const DEFAULT_STATE: &str = "/var/lib/orblx";

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Ping(Options),
}

#[derive(Debug)]
pub(crate) struct Options {
    node: String,
    state: PathBuf,
    coord: Option<SocketAddr>,
    coord_name: String,
    bundle: Option<PathBuf>,
    relay: Option<SocketAddr>,
    timeout: Duration,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    if args[0].starts_with('-') {
        return Err(format!("The command needs a node name.\n{}", help()));
    }
    let node = args[0].clone();
    let mut state = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut relay = None;
    let mut timeout = None;
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--state" => state = Some(PathBuf::from(value)),
            "--coord" => coord = Some(parse_socket(&value, 443)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--relay" => relay = Some(parse_socket(&value, 443)?),
            "--timeout" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|_| format!("The timeout {value} is not valid."))?;
                if secs == 0 || secs > 30 {
                    return Err("The timeout is not valid.".to_string());
                }
                timeout = Some(Duration::from_secs(secs));
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Ping(Options {
        node,
        state: state.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE)),
        coord,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle,
        relay,
        timeout: timeout.unwrap_or(Duration::from_secs(5)),
    }))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Ping(options) => run_ping(options),
    }
}

fn run_ping(options: Options) -> Result<(), String> {
    let netmap = Netmap::from_path(&options.state.join("netmap.json"))
        .map_err(|err| format!("The node cannot send packets. The netmap did not open. {err}"))?;
    let peer = netmap
        .peers
        .iter()
        .find(|peer| peer.name == options.node)
        .ok_or_else(|| {
            format!(
                "The node cannot send packets. The node {} is not in the netmap.",
                options.node
            )
        })?;
    let deny = load_deny(&options)?;
    let self_id = SpiffeId::node(&netmap.self_node.name).map_err(|err| err.to_string())?;
    let peer_id = SpiffeId::parse(&peer.svid).map_err(|err| err.to_string())?;
    if deny.reject_uri(&self_id).is_err() || deny.reject_uri(&peer_id).is_err() {
        return Err(format!(
            "The node cannot send packets. The node {} is revoked.",
            options.node
        ));
    }
    let endpoint = peer
        .endpoints
        .first()
        .ok_or_else(|| "The peer has no endpoint.".to_string())?;
    let direct = resolve_endpoint(endpoint)?;
    let mut config = load_config(&options.state)?;
    // W25-38: the hello endpoint uses the same deny set as the check above.
    config.deny = deny;
    let src = parse_overlay(&netmap.self_node.overlay_ip)?;
    let dst = parse_overlay(&peer.overlay_ip)?;
    if let Ok(elapsed) = measure_hello_rtt(config, direct, options.timeout, src, dst) {
        println!("path direct");
        println!("rtt_ms {}", elapsed.as_millis());
        return Ok(());
    }
    if let Some(relay) = options.relay {
        let elapsed = relay_rtt(relay, options.timeout)?;
        println!("path relay");
        println!("rtt_ms {}", elapsed.as_millis());
        return Ok(());
    }
    Err(format!(
        "The node cannot send packets. The path to {} is down.",
        options.node
    ))
}

/// Load the deny set for one ping (W25-38).
///
/// The function fails closed. A deny file that is not valid, did not open, or is
/// missing after enroll stops the ping with an error. With `--coord`, the function
/// writes the fetched list first. A write error also stops the ping.
fn load_deny(options: &Options) -> Result<DenySet, String> {
    if let Some(coord) = options.coord {
        let bundle_path = options
            .bundle
            .clone()
            .unwrap_or_else(|| options.state.join("bundle.pem"));
        let bundle = fs::read_to_string(&bundle_path)
            .map_err(|err| format!("The file {} did not open. {err}", bundle_path.display()))?;
        let text = fetch_deny_blocking(coord, &options.coord_name, &bundle, &options.state)
            .map_err(|err| err.to_string())?;
        match orblx_identity::store_deny_file(&options.state, &text) {
            Ok(DenyStore::Written | DenyStore::Same) => {}
            Ok(DenyStore::KeptCurrent { current, offered }) => eprintln!(
                "The coordinator sent deny list version {offered}. The node keeps version {current}."
            ),
            Err(err) => {
                return Err(format!(
                    "The node cannot send packets. The node did not write the deny list. {err}"
                ))
            }
        }
    }
    orblx_identity::load_deny_file(&options.state)
        .map_err(|err| format!("The node cannot send packets. {err}"))
}

fn load_config(state: &Path) -> Result<orblx_datapath::HelloConfig, String> {
    let certificate_pem = fs::read_to_string(state.join("cert.pem"))
        .map_err(|err| format!("The node certificate did not open. {err}"))?;
    let private_key_pem = fs::read_to_string(state.join("key.pem"))
        .map_err(|err| format!("The node key did not open. {err}"))?;
    let bundle = fs::read_to_string(state.join("bundle.pem"))
        .map_err(|err| format!("The trust bundle did not open. {err}"))?;
    let trust = orblx_identity::TrustBundle::from_pem(&bundle).map_err(|err| err.to_string())?;
    ticket_load::load_hello_config(
        certificate_pem,
        private_key_pem,
        trust,
        &state.join("ticket.bin"),
    )
}

fn parse_overlay(text: &str) -> Result<Ipv4Addr, String> {
    text.parse::<Ipv4Addr>()
        .map_err(|_| format!("The overlay address {text} is not valid."))
}

fn resolve_endpoint(text: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let with_port = if text.contains(':') {
        text.to_string()
    } else {
        format!("{text}:443")
    };
    let mut addrs = with_port
        .to_socket_addrs_local()
        .map_err(|_| format!("The endpoint {text} is not valid."))?;
    addrs
        .next()
        .ok_or_else(|| format!("The endpoint {text} is not valid."))
}

trait ToSocket {
    fn to_socket_addrs_local(&self) -> std::io::Result<std::vec::IntoIter<SocketAddr>>;
}

impl ToSocket for String {
    fn to_socket_addrs_local(&self) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs()
    }
}

fn relay_rtt(addr: SocketAddr, timeout: Duration) -> Result<Duration, String> {
    let socket = std::net::UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|err| format!("The relay socket did not bind. {err}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("The relay socket did not start. {err}"))?;
    let session = RelaySessionId::generate().map_err(|err| err.to_string())?;
    let packet = encode_datagram(RelayKind::Attach, session, &[])
        .map_err(|_| "The relay probe is not valid.".to_string())?;
    let started = std::time::Instant::now();
    socket
        .send_to(&packet, addr)
        .map_err(|err| format!("The relay probe was not sent. {err}"))?;
    let mut buf = [0u8; 1500];
    socket
        .recv_from(&mut buf)
        .map_err(|_| "The relay did not answer.".to_string())?;
    Ok(started.elapsed())
}

fn help() -> String {
    "\
orblx ping NODE [--state DIR] [--coord ADDR] [--coord-name NAME] [--bundle FILE] [--relay ADDR] [--timeout SECS]

The command prints path direct or path relay.
The command prints the round-trip time in milliseconds.
A node that is not in the netmap cannot send packets.
A revoked node cannot send packets.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    #[test]
    fn ping_parses_the_node_and_relay() {
        let command = parse(&[
            "b".to_string(),
            "--state".to_string(),
            "/tmp/a".to_string(),
            "--relay".to_string(),
            "10.1.0.1".to_string(),
            "--timeout".to_string(),
            "3".to_string(),
        ])
        .unwrap();
        match command {
            Command::Ping(options) => {
                assert_eq!(options.node, "b");
                assert_eq!(options.relay.unwrap().port(), 443);
                assert_eq!(options.timeout.as_secs(), 3);
            }
            Command::Help => panic!("the parser did not select ping"),
        }
    }

    #[test]
    fn ping_needs_a_node_name() {
        let err = parse(&["--state".to_string(), "/tmp/a".to_string()]).unwrap_err();
        assert!(err.contains("node name"));
    }

    /// W25-38: ping refuses when the deny file of an enrolled node is not valid, is
    /// cut short, is missing, or does not open. It never uses an empty list.
    #[test]
    fn w25_38_ping_refuses_when_the_deny_file_is_corrupt_truncated_missing_or_unreadable() {
        let dir = std::env::temp_dir().join(format!("orblx-ping-w25-38-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(orblx_identity::ENROLL_MARKER_FILE), "a\n").unwrap();
        let path = dir.join("deny.json");
        let valid =
            r#"{"version":1,"generated_at":1,"revoked_uris":[],"revoked_ticket_nonces":[]}"#;
        let Command::Ping(options) = parse(&[
            "b".to_string(),
            "--state".to_string(),
            dir.display().to_string(),
        ])
        .unwrap() else {
            panic!("the parser did not select ping");
        };
        std::fs::write(&path, valid).unwrap();
        assert_eq!(super::load_deny(&options).unwrap().version(), Some(1));
        for kind in ["corrupt", "truncated", "missing", "unreadable"] {
            match kind {
                "corrupt" => std::fs::write(&path, b"not json {").unwrap(),
                "truncated" => std::fs::write(&path, &valid.as_bytes()[..valid.len() / 2]).unwrap(),
                "missing" => std::fs::remove_file(&path).unwrap(),
                _ => {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::create_dir(&path).unwrap();
                }
            }
            let err = super::load_deny(&options).unwrap_err();
            assert!(
                err.contains("The node cannot send packets. The deny file"),
                "{kind}: {err}"
            );
            if path.is_dir() {
                std::fs::remove_dir(&path).unwrap();
            }
            std::fs::write(&path, valid).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
