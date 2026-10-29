use std::net::SocketAddr;
use std::path::PathBuf;

use orblx_datapath::{
    issue_connector_lab, prove_two_https_apps, run_hub_dir, run_spoke_dir, serve_apps_dir,
    serve_userspace, TwoAppProof, APP_A_HOST, APP_B_HOST,
};

use super::{parse_socket, take_value};

const DEFAULT_HUB: &str = "127.0.0.1:7443";
const DEFAULT_INGRESS: &str = "127.0.0.1:8443";
const DEFAULT_CA: &str = "orblx-app-ca.pem";

/// A connector command.
#[derive(Debug)]
pub(crate) enum Command {
    Help(String),
    Smoke,
    Serve {
        ingress: SocketAddr,
        ca_out: PathBuf,
    },
    Issue(PathBuf),
    Hub {
        dir: PathBuf,
        listen: SocketAddr,
    },
    Spoke {
        dir: PathBuf,
        connect: SocketAddr,
        ingress: SocketAddr,
    },
    Apps {
        dir: PathBuf,
        bind_a: SocketAddr,
        bind_b: SocketAddr,
    },
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Err(help());
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help(help()));
    }
    match args[0].as_str() {
        "smoke" => parse_smoke(&args[1..]),
        "serve" => parse_serve(&args[1..]),
        "issue" => parse_issue(&args[1..]),
        "hub" => parse_hub(&args[1..]),
        "spoke" => parse_spoke(&args[1..]),
        "apps" => parse_apps(&args[1..]),
        other => Err(format!("The mode {other} is not valid.\n{}", help())),
    }
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Smoke => {
            let proof = prove_two_https_apps().map_err(|err| err.to_string())?;
            require_mesh(&proof)?;
            println!("{proof}");
            Ok(())
        }
        Command::Serve { ingress, ca_out } => {
            serve_userspace(ingress, &ca_out).map_err(|err| err.to_string())
        }
        Command::Issue(dir) => {
            issue_connector_lab(&dir).map_err(|err| err.to_string())?;
            println!("The Orblx connector lab is in {}.", dir.display());
            println!("The product name is Orblx. The command name is orblx.");
            println!(
                "Run the hub: cargo run -p orblx-cli -- connector hub --dir {} --listen {DEFAULT_HUB}",
                dir.display()
            );
            println!(
                "Run the spoke: cargo run -p orblx-cli -- connector spoke --dir {} --connect {DEFAULT_HUB} --ingress {DEFAULT_INGRESS}",
                dir.display()
            );
            println!(
                "Fetch app A: curl --resolve {APP_A_HOST}:8443:127.0.0.1 --cacert {}/app-ca.pem https://{APP_A_HOST}:8443/",
                dir.display()
            );
            println!(
                "Fetch app B: curl --resolve {APP_B_HOST}:8443:127.0.0.1 --cacert {}/app-ca.pem https://{APP_B_HOST}:8443/",
                dir.display()
            );
            Ok(())
        }
        Command::Hub { dir, listen } => run_hub_dir(&dir, listen).map_err(|err| err.to_string()),
        Command::Spoke {
            dir,
            connect,
            ingress,
        } => run_spoke_dir(&dir, connect, ingress).map_err(|err| err.to_string()),
        Command::Apps {
            dir,
            bind_a,
            bind_b,
        } => serve_apps_dir(&dir, bind_a, bind_b).map_err(|err| err.to_string()),
    }
}

fn require_mesh(proof: &TwoAppProof) -> Result<(), String> {
    if proof.app_a.status != 200 || proof.app_b.status != 200 {
        return Err(format!("An app did not return status 200.\n{proof}"));
    }
    if proof.app_a.mesh_to == 0
        || proof.app_a.mesh_from == 0
        || proof.app_b.mesh_to == 0
        || proof.app_b.mesh_from == 0
    {
        return Err(format!("The mesh path did not carry both apps.\n{proof}"));
    }
    if proof.app_a.dialed != proof.ingress || proof.app_b.dialed != proof.ingress {
        return Err(format!("The client did not dial the spoke.\n{proof}"));
    }
    if proof.ingress == proof.backend_a || proof.ingress == proof.backend_b {
        return Err(format!("The client dialed an app listener.\n{proof}"));
    }
    Ok(())
}

fn parse_smoke(args: &[String]) -> Result<Command, String> {
    if !args.is_empty() {
        return Err(format!("smoke does not take flags.\n{}", help()));
    }
    Ok(Command::Smoke)
}

fn parse_serve(args: &[String]) -> Result<Command, String> {
    let mut ingress = None;
    let mut ca_out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--ingress" => ingress = Some(parse_socket(&value, 8443)?),
            "--ca-out" => ca_out = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Serve {
        ingress: ingress.unwrap_or_else(|| must_socket(DEFAULT_INGRESS)),
        ca_out: ca_out.unwrap_or_else(|| PathBuf::from(DEFAULT_CA)),
    })
}

fn parse_issue(args: &[String]) -> Result<Command, String> {
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--out" => out = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let out = out.ok_or_else(|| format!("The command needs --out.\n{}", help()))?;
    Ok(Command::Issue(out))
}

fn parse_hub(args: &[String]) -> Result<Command, String> {
    let mut dir = None;
    let mut listen = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--dir" => dir = Some(PathBuf::from(value)),
            "--listen" => listen = Some(parse_socket(&value, 7443)?),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let dir = dir.ok_or_else(|| format!("The command needs --dir.\n{}", help()))?;
    Ok(Command::Hub {
        dir,
        listen: listen.unwrap_or_else(|| must_socket(DEFAULT_HUB)),
    })
}

fn parse_spoke(args: &[String]) -> Result<Command, String> {
    let mut dir = None;
    let mut connect = None;
    let mut ingress = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--dir" => dir = Some(PathBuf::from(value)),
            "--connect" => connect = Some(parse_socket(&value, 7443)?),
            "--ingress" => ingress = Some(parse_socket(&value, 8443)?),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let dir = dir.ok_or_else(|| format!("The command needs --dir.\n{}", help()))?;
    let connect = connect.ok_or_else(|| format!("The command needs --connect.\n{}", help()))?;
    Ok(Command::Spoke {
        dir,
        connect,
        ingress: ingress.unwrap_or_else(|| must_socket(DEFAULT_INGRESS)),
    })
}

fn parse_apps(args: &[String]) -> Result<Command, String> {
    let mut dir = None;
    let mut bind_a = None;
    let mut bind_b = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--dir" => dir = Some(PathBuf::from(value)),
            "--bind-a" => bind_a = Some(parse_socket(&value, 443)?),
            "--bind-b" => bind_b = Some(parse_socket(&value, 443)?),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let dir = dir.ok_or_else(|| format!("The command needs --dir.\n{}", help()))?;
    let bind_a = bind_a.ok_or_else(|| format!("The command needs --bind-a.\n{}", help()))?;
    let bind_b = bind_b.ok_or_else(|| format!("The command needs --bind-b.\n{}", help()))?;
    Ok(Command::Apps {
        dir,
        bind_a,
        bind_b,
    })
}

fn must_socket(text: &str) -> SocketAddr {
    text.parse().expect("the default address is valid")
}

fn help() -> String {
    "\
Orblx connector. The product name is Orblx. The command name is orblx.
The connector is the hub-spoke path for two HTTPS apps.
The apps are app-a.orblx.test and app-b.orblx.test.
The overlay addresses are 10.8.0.10 and 10.8.0.11.
The path uses one QUIC bidirectional stream.
The path carries the HTTPS bytes in ADR-0002 DATA frames.
The frames carry IPv4 TCP segments.
The userspace path does not open a TUN device.
The userspace path does not use WireGuard, Headscale, or DERP.

orblx connector smoke
orblx connector serve [--ingress ADDR] [--ca-out FILE]
orblx connector issue --out DIR
orblx connector hub --dir DIR [--listen ADDR]
orblx connector spoke --dir DIR --connect ADDR [--ingress ADDR]
orblx connector apps --dir DIR --bind-a ADDR --bind-b ADDR

smoke proves both apps in this process.
serve keeps the userspace path open for curl.
issue writes SVID PEM files, ticket files, and app certificates.
hub and spoke are two processes. They load those files from disk.
apps serves the two HTTPS apps on the given sockets.
apps does not open a TUN device.
Assign the overlay addresses before you bind them.
The TUN device needs CAP_NET_ADMIN on Linux.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use orblx_identity::TrustBundle;

    use super::super::ticket_load;
    use super::{parse, Command};

    #[test]
    fn smoke_selects_the_proof_command() {
        let command = parse(&["smoke".to_string()]).unwrap();
        assert!(matches!(command, Command::Smoke));
    }

    #[test]
    fn serve_uses_the_default_ingress() {
        let command = parse(&["serve".to_string()]).unwrap();
        match command {
            Command::Serve { ingress, ca_out } => {
                assert_eq!(ingress.port(), 8443);
                assert_eq!(ca_out.as_os_str(), "orblx-app-ca.pem");
            }
            Command::Help(_)
            | Command::Smoke
            | Command::Issue(_)
            | Command::Hub { .. }
            | Command::Spoke { .. }
            | Command::Apps { .. } => panic!("the parser did not select serve"),
        }
    }

    #[test]
    fn help_names_orblx_and_the_two_apps() {
        let command = parse(&["--help".to_string()]).unwrap();
        match command {
            Command::Help(text) => {
                assert!(text.contains("Orblx"));
                assert!(text.contains("app-a.orblx.test"));
                assert!(text.contains("app-b.orblx.test"));
                assert!(text.contains("CAP_NET_ADMIN"));
                assert!(text.contains("WireGuard"));
            }
            Command::Smoke
            | Command::Serve { .. }
            | Command::Issue(_)
            | Command::Hub { .. }
            | Command::Spoke { .. }
            | Command::Apps { .. } => panic!("the parser did not select help"),
        }
    }

    #[test]
    fn issue_files_load_through_the_hello_quic_loader() {
        let dir = temp_dir();
        orblx_datapath::issue_connector_lab(&dir).expect("the lab directory was not written");
        let bundle = fs::read_to_string(dir.join("trust-bundle.pem")).expect("the trust bundle");
        let trust = TrustBundle::from_pem(&bundle).expect("the trust bundle did not parse");
        let cert = fs::read_to_string(dir.join("hub-cert.pem")).expect("the hub certificate");
        let key = fs::read_to_string(dir.join("hub-key.pem")).expect("the hub key");
        let config = ticket_load::load_hello_config(cert, key, trust, &dir.join("hub-ticket.bin"))
            .expect("hello-quic did not load the ticket files");
        assert!(!config.certificate_pem.is_empty());
        assert!(!config.ticket_bytes.is_empty());
        assert!(dir.join("hub-ticket.bin.mac").is_file());
        assert!(dir.join("ticket-verifier.pem").is_file());
        assert!(dir.join("app-ca.pem").is_file());
        fs::remove_dir_all(&dir).expect("the lab directory was not removed");
    }

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is valid")
            .as_nanos();
        std::env::temp_dir().join(format!("orblx-w9-cli-{}-{nanos}", std::process::id()))
    }
}
