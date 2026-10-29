use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use orblx_coord::crate_name as coord_crate;
use orblx_crypto::crate_name as crypto_crate;
use orblx_datapath::crate_name as datapath_crate;
use orblx_datapath::{tun_capability_note, HelloRequest, HelloRole, TunConfig, DEFAULT_UDP_PORT};
use orblx_edge::crate_name as edge_crate;
use orblx_identity::crate_name as identity_crate;
use orblx_identity::TrustBundle;

mod admin;
mod audit;
mod connector;
mod coord;
mod direct;
mod edge;
mod login;
mod netcheck;
mod ping;
mod policy;
mod relay;
mod ssh;
mod status;
mod ticket_load;
mod up;

#[derive(Debug)]
enum Action {
    Hello,
    Version,
    HelpHelloQuic,
    HelloQuic(HelloQuicCommand),
    Edge(edge::EdgeCommand),
    Direct(direct::Command),
    Relay(relay::Command),
    Connector(connector::Command),
    Audit(audit::Command),
    Node(up::Command),
    Status(status::Command),
    Coord(coord::Command),
    Login(login::Command),
    Policy(policy::Command),
    Ssh(ssh::Command),
    Admin(admin::Command),
    Netcheck(netcheck::Command),
    Ping(ping::Command),
}

#[derive(Debug)]
struct HelloQuicCommand {
    mode: HelloMode,
    cert: PathBuf,
    key: PathBuf,
    bundle: PathBuf,
    ticket: PathBuf,
    listen: SocketAddr,
    connect: Option<SocketAddr>,
    tun_address: Option<Ipv4Addr>,
    tun_netmask: Ipv4Addr,
    tun_name: Option<String>,
}

#[derive(Debug)]
enum HelloMode {
    Server,
    Client,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match action_from_args(args) {
        Ok(Action::Hello) => println!("{}", hello_line()),
        Ok(Action::Version) => println!("orblx {}", env!("CARGO_PKG_VERSION")),
        Ok(Action::HelpHelloQuic) => println!("{}", hello_quic_help()),
        Ok(Action::HelloQuic(command)) => {
            if let Err(err) = run_hello_quic(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Edge(command)) => {
            if let Err(err) = edge::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Direct(command)) => {
            if let Err(err) = direct::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Relay(command)) => {
            if let Err(err) = relay::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Connector(command)) => {
            if let Err(err) = connector::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Audit(command)) => {
            if let Err(err) = audit::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Node(command)) => {
            if let Err(err) = up::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Coord(command)) => {
            if let Err(err) = coord::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Login(command)) => {
            if let Err(err) = login::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Policy(command)) => {
            if let Err(err) = policy::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Ssh(command)) => {
            if let Err(err) = ssh::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Status(command)) => {
            if let Err(err) = status::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Admin(command)) => {
            if let Err(err) = admin::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Netcheck(command)) => {
            if let Err(err) = netcheck::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Ok(Action::Ping(command)) => {
            if let Err(err) = ping::run(command) {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

fn action_from_args<I>(args: I) -> Result<Action, String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    if args.first().map(String::as_str) == Some("hello-quic") {
        return parse_hello_quic(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("stun") {
        return edge::parse_stun(&args[1..]).map(Action::Edge);
    }
    if args.first().map(String::as_str) == Some("stun-serve") {
        return edge::parse_stun_serve(&args[1..]).map(Action::Edge);
    }
    if args.first().map(String::as_str) == Some("edge-smoke") {
        return edge::parse_edge_smoke(&args[1..]).map(Action::Edge);
    }
    if args.first().map(String::as_str) == Some("direct-issue") {
        return direct::parse_issue(&args[1..]).map(Action::Direct);
    }
    if args.first().map(String::as_str) == Some("direct-peer") {
        return direct::parse_peer(&args[1..]).map(Action::Direct);
    }
    if args.first().map(String::as_str) == Some("relay") {
        return relay::parse_serve(&args[1..]).map(Action::Relay);
    }
    if args.first().map(String::as_str) == Some("relay-peer") {
        return relay::parse_peer(&args[1..]).map(Action::Relay);
    }
    if args.first().map(String::as_str) == Some("relay-smoke") {
        return relay::parse_smoke(&args[1..]).map(Action::Relay);
    }
    if args.first().map(String::as_str) == Some("stick-upgrade") {
        return relay::parse_stick(&args[1..]).map(Action::Relay);
    }
    if args.first().map(String::as_str) == Some("connector") {
        return connector::parse(&args[1..]).map(Action::Connector);
    }
    if args.first().map(String::as_str) == Some("audit") {
        return audit::parse(&args[1..]).map(Action::Audit);
    }
    if args.first().map(String::as_str) == Some("up") {
        return up::parse_up(&args[1..]).map(Action::Node);
    }
    if args.first().map(String::as_str) == Some("set") {
        return up::parse_set(&args[1..]).map(Action::Node);
    }
    if args.first().map(String::as_str) == Some("down") {
        return up::parse_down(&args[1..]).map(Action::Node);
    }
    if args.first().map(String::as_str) == Some("status") {
        return status::parse(&args[1..]).map(Action::Status);
    }
    if args.first().map(String::as_str) == Some("admin") {
        return admin::parse(&args[1..]).map(Action::Admin);
    }
    if args.first().map(String::as_str) == Some("netcheck") {
        return netcheck::parse(&args[1..]).map(Action::Netcheck);
    }
    if args.first().map(String::as_str) == Some("ping") {
        return ping::parse(&args[1..]).map(Action::Ping);
    }
    if args.first().map(String::as_str) == Some("node-issue") {
        return up::parse_issue(&args[1..]).map(Action::Node);
    }
    if args.first().map(String::as_str) == Some("coord") {
        return coord::parse(&args[1..]).map(Action::Coord);
    }
    if args.first().map(String::as_str) == Some("login") {
        return login::parse(&args[1..]).map(Action::Login);
    }
    if args.first().map(String::as_str) == Some("policy") {
        return policy::parse(&args[1..]).map(Action::Policy);
    }
    if args.first().map(String::as_str) == Some("ssh") {
        return ssh::parse(&args[1..]).map(Action::Ssh);
    }
    for arg in &args {
        if arg == "--version" || arg == "-V" {
            return Ok(Action::Version);
        }
    }
    Ok(Action::Hello)
}

fn hello_line() -> String {
    format!(
        "Hello from orblx. This is the week 1 build: {}, {}, {}, {}, {}",
        datapath_crate(),
        crypto_crate(),
        edge_crate(),
        identity_crate(),
        coord_crate(),
    )
}

fn hello_quic_help() -> String {
    format!(
        "\
orblx hello-quic server --cert FILE --key FILE --bundle FILE --ticket FILE [--listen ADDR] [--tun-address ADDR] [--tun-netmask ADDR] [--tun-name NAME]
orblx hello-quic client --cert FILE --key FILE --bundle FILE --ticket FILE --connect ADDR [--listen ADDR] [--tun-address ADDR] [--tun-netmask ADDR] [--tun-name NAME]

The command sends IPv4 packets as DATA frames.
The command checks the peer capability ticket before it accepts DATA.
The --ticket file is the identity ticket bytes.
The command also reads FILE.mac.
The ticket directory holds ticket-verifier.pem, ticket-mac.key, ticket-not-before, ticket-not-after, and svid-ca.pub.
The command uses one QUIC bidirectional stream.
The command uses UDP.
The default port is {port}.
{note}
The tests do not open a TUN device.
",
        port = DEFAULT_UDP_PORT,
        note = tun_capability_note(),
    )
}

fn parse_hello_quic(args: &[String]) -> Result<Action, String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Action::HelpHelloQuic);
    }
    if args.is_empty() {
        return Err(hello_quic_help());
    }
    let mode = match args[0].as_str() {
        "server" => HelloMode::Server,
        "client" => HelloMode::Client,
        other => {
            return Err(format!(
                "The mode {other} is not server or client.\n{}",
                hello_quic_help()
            ));
        }
    };
    let mut cert = None;
    let mut key = None;
    let mut bundle = None;
    let mut ticket = None;
    let mut listen = None;
    let mut connect = None;
    let mut tun_address = None;
    let mut tun_netmask = None;
    let mut tun_name = None;
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--cert" => cert = Some(PathBuf::from(value)),
            "--key" => key = Some(PathBuf::from(value)),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--ticket" => ticket = Some(PathBuf::from(value)),
            "--listen" => listen = Some(parse_socket(&value, DEFAULT_UDP_PORT)?),
            "--connect" => connect = Some(parse_socket(&value, DEFAULT_UDP_PORT)?),
            "--tun-address" => tun_address = Some(parse_ipv4(&value)?),
            "--tun-netmask" => tun_netmask = Some(parse_ipv4(&value)?),
            "--tun-name" => tun_name = Some(value),
            other => {
                return Err(format!(
                    "The flag {other} is not valid.\n{}",
                    hello_quic_help()
                ));
            }
        }
    }
    let cert = cert.ok_or_else(|| "The command needs --cert.".to_string())?;
    let key = key.ok_or_else(|| "The command needs --key.".to_string())?;
    let bundle = bundle.ok_or_else(|| "The command needs --bundle.".to_string())?;
    let ticket = ticket.ok_or_else(|| "The command needs --ticket.".to_string())?;
    if matches!(mode, HelloMode::Client) && connect.is_none() {
        return Err("The client needs --connect.".to_string());
    }
    let listen = listen.unwrap_or_else(|| {
        if matches!(mode, HelloMode::Server) {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_UDP_PORT))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        }
    });
    Ok(Action::HelloQuic(HelloQuicCommand {
        mode,
        cert,
        key,
        bundle,
        ticket,
        listen,
        connect,
        tun_address,
        tun_netmask: tun_netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
        tun_name,
    }))
}

pub(crate) fn take_value(args: &[String], index: &mut usize) -> Result<String, String> {
    let value = args
        .get(*index)
        .ok_or_else(|| "The flag needs a value.".to_string())?;
    if value.starts_with('-') {
        return Err("The flag needs a value.".to_string());
    }
    *index += 1;
    Ok(value.clone())
}

pub(crate) fn parse_socket(text: &str, default_port: u16) -> Result<SocketAddr, String> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let with_port = format!("{text}:{default_port}");
    with_port
        .parse::<SocketAddr>()
        .map_err(|_| format!("The address {text} is not valid."))
}

fn parse_ipv4(text: &str) -> Result<Ipv4Addr, String> {
    text.parse::<Ipv4Addr>()
        .map_err(|_| format!("The IPv4 address {text} is not valid."))
}

fn run_hello_quic(command: HelloQuicCommand) -> Result<(), String> {
    let certificate_pem = read_text(&command.cert)?;
    let private_key_pem = read_text(&command.key)?;
    let bundle_pem = read_text(&command.bundle)?;
    let trust = TrustBundle::from_pem(&bundle_pem).map_err(|err| err.to_string())?;
    let config =
        ticket_load::load_hello_config(certificate_pem, private_key_pem, trust, &command.ticket)?;
    let role = match command.mode {
        HelloMode::Server => HelloRole::Server {
            listen: command.listen,
        },
        HelloMode::Client => HelloRole::Client {
            bind: command.listen,
            peer: command
                .connect
                .ok_or_else(|| "The client needs --connect.".to_string())?,
        },
    };
    let tun = command.tun_address.map(|address| TunConfig {
        name: command.tun_name,
        address,
        netmask: command.tun_netmask,
    });
    orblx_datapath::run_hello(HelloRequest { config, role, tun }).map_err(|err| err.to_string())
}

fn read_text(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{action_from_args, hello_line, hello_quic_help, Action};

    #[test]
    fn version_flag_selects_version() {
        let action = action_from_args(["--version".to_string()]).unwrap();
        assert!(matches!(action, Action::Version));
    }

    #[test]
    fn short_version_flag_selects_version() {
        let action = action_from_args(["-V".to_string()]).unwrap();
        assert!(matches!(action, Action::Version));
    }

    #[test]
    fn empty_args_select_hello() {
        let action = action_from_args(std::iter::empty()).unwrap();
        assert!(matches!(action, Action::Hello));
    }

    #[test]
    fn hello_names_workspace_crates() {
        let line = hello_line();
        assert!(line.contains("orblx-datapath"));
        assert!(line.contains("orblx-crypto"));
        assert!(line.contains("orblx-edge"));
        assert!(line.contains("orblx-identity"));
        assert!(line.contains("orblx-coord"));
    }

    #[test]
    fn hello_quic_help_names_the_capability_and_port() {
        let help = hello_quic_help();
        #[cfg(target_os = "macos")]
        assert!(help.contains("root"));
        #[cfg(not(target_os = "macos"))]
        assert!(help.contains("CAP_NET_ADMIN"));
        assert!(help.contains("443"));
        let action = action_from_args(["hello-quic".to_string(), "--help".to_string()]).unwrap();
        assert!(matches!(action, Action::HelpHelloQuic));
    }

    #[test]
    fn hello_quic_server_defaults_to_port_443() {
        let action = action_from_args([
            "hello-quic".to_string(),
            "server".to_string(),
            "--cert".to_string(),
            "cert.pem".to_string(),
            "--key".to_string(),
            "key.pem".to_string(),
            "--bundle".to_string(),
            "bundle.pem".to_string(),
            "--ticket".to_string(),
            "ticket.bin".to_string(),
        ])
        .unwrap();
        match action {
            Action::HelloQuic(command) => {
                assert_eq!(command.listen.port(), 443);
                assert!(command.tun_address.is_none());
                assert!(command.connect.is_none());
            }
            other => panic!("the parser did not select hello-quic: {other:?}"),
        }
    }

    #[test]
    fn hello_quic_client_defaults_the_connect_port() {
        let action = action_from_args([
            "hello-quic".to_string(),
            "client".to_string(),
            "--cert".to_string(),
            "cert.pem".to_string(),
            "--key".to_string(),
            "key.pem".to_string(),
            "--bundle".to_string(),
            "bundle.pem".to_string(),
            "--ticket".to_string(),
            "ticket.bin".to_string(),
            "--connect".to_string(),
            "10.8.0.1".to_string(),
            "--tun-address".to_string(),
            "10.8.0.2".to_string(),
        ])
        .unwrap();
        match action {
            Action::HelloQuic(command) => {
                assert_eq!(command.connect.unwrap().port(), 443);
                assert_eq!(command.listen.port(), 0);
                assert_eq!(
                    command.tun_address.unwrap(),
                    std::net::Ipv4Addr::new(10, 8, 0, 2)
                );
            }
            other => panic!("the parser did not select hello-quic: {other:?}"),
        }
    }

    #[test]
    fn hello_quic_client_requires_connect() {
        let err = action_from_args([
            "hello-quic".to_string(),
            "client".to_string(),
            "--cert".to_string(),
            "cert.pem".to_string(),
            "--key".to_string(),
            "key.pem".to_string(),
            "--bundle".to_string(),
            "bundle.pem".to_string(),
            "--ticket".to_string(),
            "ticket.bin".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("--connect"));
    }
}
