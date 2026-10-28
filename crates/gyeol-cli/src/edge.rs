use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use gyeol_edge::{run_edge_smoke, EdgeError, LabStunServer, StunClient};

use super::{parse_socket, take_value};

const DEFAULT_STUN_PORT: u16 = 3478;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// An edge subcommand.
#[derive(Debug)]
pub(crate) enum EdgeCommand {
    StunHelp,
    Stun(StunOptions),
    StunServeHelp,
    StunServe(SocketAddr),
    EdgeSmokeHelp,
    EdgeSmoke,
}

#[derive(Debug)]
pub(crate) struct StunOptions {
    server: SocketAddr,
    bind: SocketAddr,
    timeout: Duration,
}

pub(crate) fn parse_stun(args: &[String]) -> Result<EdgeCommand, String> {
    if wants_help(args) {
        return Ok(EdgeCommand::StunHelp);
    }
    let mut server = None;
    let mut bind = None;
    let mut timeout = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--server" => server = Some(parse_socket(&value, DEFAULT_STUN_PORT)?),
            "--bind" => bind = Some(parse_socket(&value, 0)?),
            "--timeout" => timeout = Some(parse_timeout(&value)?),
            other => {
                return Err(format!("The flag {other} is not valid.\n{}", stun_help()));
            }
        }
    }
    let server = server.ok_or_else(|| format!("The command needs --server.\n{}", stun_help()))?;
    Ok(EdgeCommand::Stun(StunOptions {
        server,
        bind: bind.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
    }))
}

pub(crate) fn parse_stun_serve(args: &[String]) -> Result<EdgeCommand, String> {
    if wants_help(args) {
        return Ok(EdgeCommand::StunServeHelp);
    }
    let mut listen = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--listen" => listen = Some(parse_socket(&value, DEFAULT_STUN_PORT)?),
            other => {
                return Err(format!(
                    "The flag {other} is not valid.\n{}",
                    stun_serve_help()
                ));
            }
        }
    }
    Ok(EdgeCommand::StunServe(listen.unwrap_or_else(|| {
        SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_STUN_PORT))
    })))
}

pub(crate) fn parse_edge_smoke(args: &[String]) -> Result<EdgeCommand, String> {
    if wants_help(args) {
        return Ok(EdgeCommand::EdgeSmokeHelp);
    }
    if args.is_empty() {
        return Ok(EdgeCommand::EdgeSmoke);
    }
    Err(format!(
        "The flag {} is not valid.\n{}",
        args[0],
        edge_smoke_help()
    ))
}

pub(crate) fn run(command: EdgeCommand) -> Result<(), String> {
    match command {
        EdgeCommand::StunHelp => {
            println!("{}", stun_help());
            Ok(())
        }
        EdgeCommand::Stun(options) => run_stun(options),
        EdgeCommand::StunServeHelp => {
            println!("{}", stun_serve_help());
            Ok(())
        }
        EdgeCommand::StunServe(listen) => run_stun_serve(listen),
        EdgeCommand::EdgeSmokeHelp => {
            println!("{}", edge_smoke_help());
            Ok(())
        }
        EdgeCommand::EdgeSmoke => {
            let report = run_edge_smoke().map_err(|err| err.to_string())?;
            for line in report.lines() {
                println!("{line}");
            }
            Ok(())
        }
    }
}

fn run_stun(options: StunOptions) -> Result<(), String> {
    let client = StunClient::bind(options.bind).map_err(|err| err.to_string())?;
    let local = client.local_addr().map_err(|err| err.to_string())?;
    let reflexive = client
        .gather(options.server, options.timeout)
        .map_err(|err| err.to_string())?;
    println!("local {local}");
    println!("reflexive {reflexive}");
    Ok(())
}

fn run_stun_serve(listen: SocketAddr) -> Result<(), String> {
    let server = LabStunServer::bind(listen).map_err(|err| err.to_string())?;
    let bound = server.local_addr().map_err(|err| err.to_string())?;
    println!("listen {bound}");
    loop {
        match server.serve_one(Duration::from_secs(60)) {
            Ok(observed) => println!("observed {observed}"),
            Err(EdgeError::Timeout) => {}
            Err(err) => eprintln!("{err}"),
        }
    }
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn parse_timeout(text: &str) -> Result<Duration, String> {
    let secs: u64 = text
        .parse()
        .map_err(|_| format!("The timeout {text} is not a whole number of seconds."))?;
    if secs == 0 {
        return Err("The timeout is zero.".to_string());
    }
    Ok(Duration::from_secs(secs))
}

fn stun_help() -> String {
    "\
gyeol stun --server ADDR [--bind ADDR] [--timeout SECS]
The command sends one STUN Binding request.
The command prints the local socket.
The command prints the reflexive socket.
The default server port is 3478.
The default timeout is 2 seconds.
Week 4 does not check STUN credentials.
"
    .to_string()
}

fn stun_serve_help() -> String {
    "\
gyeol stun-serve [--listen ADDR]
The command answers STUN Binding requests.
The mapped address is the UDP source address.
The default listen socket is 127.0.0.1:3478.
The command is a lab server.
"
    .to_string()
}

fn edge_smoke_help() -> String {
    "\
gyeol edge-smoke
The command runs Allocate against a lab STUN server.
The command uses a userspace UDP NAT.
The command enters the Direct stub.
The command does not send hole-punch packets.
Week 5 completes the hole punch.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse_edge_smoke, parse_stun, parse_stun_serve, EdgeCommand};

    #[test]
    fn stun_requires_a_server() {
        let err = parse_stun(&[]).unwrap_err();
        assert!(err.contains("--server"));
    }

    #[test]
    fn stun_defaults_the_server_port_and_the_timeout() {
        let command = parse_stun(&["--server".to_string(), "127.0.0.1".to_string()]).unwrap();
        match command {
            EdgeCommand::Stun(options) => {
                assert_eq!(options.server.port(), 3478);
                assert_eq!(options.bind.port(), 0);
                assert_eq!(options.timeout.as_secs(), 2);
            }
            EdgeCommand::StunHelp
            | EdgeCommand::StunServeHelp
            | EdgeCommand::StunServe(_)
            | EdgeCommand::EdgeSmokeHelp
            | EdgeCommand::EdgeSmoke => panic!("the parser did not select stun"),
        }
    }

    #[test]
    fn stun_serve_defaults_to_localhost() {
        let command = parse_stun_serve(&[]).unwrap();
        match command {
            EdgeCommand::StunServe(listen) => {
                assert_eq!(listen.port(), 3478);
                assert!(listen.ip().is_loopback());
            }
            EdgeCommand::StunHelp
            | EdgeCommand::Stun(_)
            | EdgeCommand::StunServeHelp
            | EdgeCommand::EdgeSmokeHelp
            | EdgeCommand::EdgeSmoke => panic!("the parser did not select stun-serve"),
        }
    }

    #[test]
    fn edge_smoke_help_states_the_stub() {
        let command = parse_edge_smoke(&["--help".to_string()]).unwrap();
        assert!(matches!(command, EdgeCommand::EdgeSmokeHelp));
        let command = parse_edge_smoke(&[]).unwrap();
        assert!(matches!(command, EdgeCommand::EdgeSmoke));
    }

    #[test]
    fn edge_smoke_command_reaches_the_direct_stub() {
        super::run(EdgeCommand::EdgeSmoke).unwrap();
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let err = parse_stun(&[
            "--server".to_string(),
            "127.0.0.1:3478".to_string(),
            "--timeout".to_string(),
            "0".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("zero"));
    }
}
