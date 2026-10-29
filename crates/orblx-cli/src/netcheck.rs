//! `orblx netcheck` probes UDP, QUIC, and the Relay.
//!
//! The NAT kind comes from `orblx-edge` `NatKind`.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use orblx_edge::NatKind;
use orblx_relay::{encode_datagram, RelayKind, RelaySessionId};

use super::{parse_socket, take_value};

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Run(Options),
}

#[derive(Debug)]
pub(crate) struct Options {
    udp: Option<SocketAddr>,
    quic: Option<SocketAddr>,
    relay: Option<SocketAddr>,
    stun: Option<SocketAddr>,
    timeout: Duration,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let mut udp = None;
    let mut quic = None;
    let mut relay = None;
    let mut stun = None;
    let mut timeout = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--udp" => udp = Some(parse_socket(&value, 443)?),
            "--quic" => quic = Some(parse_socket(&value, 443)?),
            "--relay" => relay = Some(parse_socket(&value, 443)?),
            "--stun" => stun = Some(parse_socket(&value, 3478)?),
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
    if udp.is_none() && quic.is_none() && relay.is_none() {
        return Err(format!(
            "The command needs --udp, --quic, or --relay.\n{}",
            help()
        ));
    }
    Ok(Command::Run(Options {
        udp,
        quic,
        relay,
        stun,
        timeout: timeout.unwrap_or(Duration::from_secs(2)),
    }))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Run(options) => run_check(options),
    }
}

fn run_check(options: Options) -> Result<(), String> {
    let udp_ok = match options.udp {
        Some(addr) => {
            let ok = udp_replies(addr, options.timeout);
            println!("udp443 {}", mark(ok));
            ok
        }
        None => false,
    };
    if let Some(addr) = options.quic {
        let ok = udp_replies(addr, options.timeout);
        println!("quic443 {}", mark(ok));
    }
    if let Some(addr) = options.relay {
        let ok = relay_replies(addr, options.timeout).is_ok();
        println!("relay {}", mark(ok));
    }
    let (local_port, mapped_port) = stun_ports(options.stun, options.timeout);
    let kind = NatKind::classify(
        udp_ok || options.udp.is_none(),
        local_port,
        mapped_port,
        None,
    );
    let kind = if options.udp.is_some() {
        NatKind::classify(udp_ok, local_port, mapped_port, None)
    } else {
        kind
    };
    println!("nat {}", kind.slug());
    Ok(())
}

fn mark(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "fail"
    }
}

fn udp_replies(addr: SocketAddr, timeout: Duration) -> bool {
    let socket = match UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))) {
        Ok(socket) => socket,
        Err(_) => return false,
    };
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return false;
    }
    let packet = quic_probe();
    if socket.send_to(&packet, addr).is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    socket.recv_from(&mut buf).is_ok()
}

fn quic_probe() -> Vec<u8> {
    let mut packet = vec![0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 8];
    packet.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    packet.push(8);
    packet.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
    // A QUIC server drops an Initial shorter than 1200 bytes.
    packet.resize(1200, 0);
    packet
}

fn relay_replies(addr: SocketAddr, timeout: Duration) -> Result<Duration, String> {
    let socket = UdpSocket::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|err| format!("The relay probe did not bind. {err}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("The relay probe did not start. {err}"))?;
    let session = RelaySessionId::generate().map_err(|err| err.to_string())?;
    let packet = encode_datagram(RelayKind::Attach, session, &[])
        .map_err(|_| "The relay probe is not valid.".to_string())?;
    let started = Instant::now();
    socket
        .send_to(&packet, addr)
        .map_err(|err| format!("The relay probe was not sent. {err}"))?;
    let mut buf = [0u8; 1500];
    socket
        .recv_from(&mut buf)
        .map_err(|_| "The relay did not answer.".to_string())?;
    Ok(started.elapsed())
}

fn stun_ports(stun: Option<SocketAddr>, timeout: Duration) -> (Option<u16>, Option<u16>) {
    let Some(server) = stun else {
        return (None, None);
    };
    let Ok(client) =
        orblx_edge::StunClient::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
    else {
        return (None, None);
    };
    let Ok(local) = client.local_addr() else {
        return (None, None);
    };
    match client.gather(server, timeout) {
        Ok(mapped) => (Some(local.port()), Some(mapped.port())),
        Err(_) => (Some(local.port()), None),
    }
}

fn help() -> String {
    "\
orblx netcheck [--udp ADDR] [--quic ADDR] [--relay ADDR] [--stun ADDR] [--timeout SECS]

The command probes UDP port 443 and QUIC port 443.
The command probes Relay reachability.
The NAT kind comes from the orblx-edge NAT feed classifier.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    #[test]
    fn netcheck_requires_one_target() {
        let err = parse(&[]).unwrap_err();
        assert!(err.contains("--udp"));
    }

    #[test]
    fn netcheck_parses_udp_and_relay() {
        let command = parse(&[
            "--udp".to_string(),
            "10.0.0.1".to_string(),
            "--relay".to_string(),
            "10.0.0.2:443".to_string(),
        ])
        .unwrap();
        match command {
            Command::Run(options) => {
                assert_eq!(options.udp.unwrap().port(), 443);
                assert_eq!(options.relay.unwrap().port(), 443);
            }
            Command::Help => panic!("the parser did not select netcheck"),
        }
    }
}
