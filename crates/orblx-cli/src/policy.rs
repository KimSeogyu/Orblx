//! `orblx policy check`, `orblx policy test`, and `orblx policy enforce`.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use orblx_audit::AuditLog;
use orblx_coord::{decode_hex_32, verify_signed_grants, SignedGrants};
use orblx_datapath::enforce_receiver_tcp;
use orblx_identity::{Policy, SpiffeId};

use super::take_value;

/// A policy command.
#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Check {
        file: PathBuf,
    },
    Test {
        file: PathBuf,
    },
    Enforce {
        state: PathBuf,
        src: String,
        dst_ip: Ipv4Addr,
        ports: Vec<u16>,
        audit: PathBuf,
    },
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    match args[0].as_str() {
        "check" => parse_file(&args[1..]).map(|file| Command::Check { file }),
        "test" => parse_file(&args[1..]).map(|file| Command::Test { file }),
        "enforce" => parse_enforce(&args[1..]),
        other => Err(format!("The mode {other} is not valid.\n{}", help())),
    }
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Check { file } => {
            Policy::from_path(&file).map_err(|err| err.to_string())?;
            println!("policy ok");
            Ok(())
        }
        Command::Test { file } => {
            let policy = Policy::from_path(&file).map_err(|err| err.to_string())?;
            for assertion in policy.assertions() {
                println!("{}", assertion.line());
            }
            println!("policy ok");
            Ok(())
        }
        Command::Enforce {
            state,
            src,
            dst_ip,
            ports,
            audit,
        } => run_enforce(&state, &src, dst_ip, &ports, &audit),
    }
}

fn run_enforce(
    state: &std::path::Path,
    src: &str,
    dst_ip: Ipv4Addr,
    ports: &[u16],
    audit_path: &std::path::Path,
) -> Result<(), String> {
    let signed_text = std::fs::read_to_string(state.join("grants.signed.json")).map_err(|err| {
        format!(
            "The file {} did not open. {err}",
            state.join("grants.signed.json").display()
        )
    })?;
    let signed: SignedGrants =
        serde_json::from_str(&signed_text).map_err(|_| "The grants are not valid.".to_string())?;
    let public_text = std::fs::read_to_string(state.join("netmap.pub")).map_err(|err| {
        format!(
            "The file {} did not open. {err}",
            state.join("netmap.pub").display()
        )
    })?;
    let public = decode_hex_32(public_text.trim()).map_err(|err| err.to_string())?;
    verify_signed_grants(&signed, &public).map_err(|err| err.to_string())?;
    let src_id =
        SpiffeId::node(src).map_err(|_| "The source node name is not valid.".to_string())?;
    println!("src {}", src_id.as_uri());
    println!("dst {}", signed.grants.receiver);
    let mut audit = AuditLog::new();
    for port in ports {
        let allowed = enforce_receiver_tcp(&signed.grants, &src_id, dst_ip, *port, &mut audit)
            .map_err(|err| err.to_string())?;
        if allowed {
            println!("allow tcp {port}");
        } else {
            println!("deny tcp {port}");
        }
    }
    audit
        .write_jsonl(audit_path)
        .map_err(|err| err.to_string())?;
    println!("audit {}", audit_path.display());
    Ok(())
}

fn parse_file(args: &[String]) -> Result<PathBuf, String> {
    let mut file = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--file" => file = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    file.ok_or_else(|| format!("The command needs --file.\n{}", help()))
}

fn parse_enforce(args: &[String]) -> Result<Command, String> {
    let mut state = None;
    let mut src = None;
    let mut dst_ip = None;
    let mut ports = Vec::new();
    let mut audit = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--state" => state = Some(PathBuf::from(value)),
            "--src" => src = Some(value),
            "--dst-ip" => {
                dst_ip = Some(
                    value
                        .parse::<Ipv4Addr>()
                        .map_err(|_| "The destination address is not valid.".to_string())?,
                );
            }
            "--port" => {
                let port: u16 = value
                    .parse()
                    .map_err(|_| "The port is not valid.".to_string())?;
                if port == 0 {
                    return Err("The port is not valid.".to_string());
                }
                ports.push(port);
            }
            "--audit" => audit = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    if ports.is_empty() {
        return Err(format!("The command needs --port.\n{}", help()));
    }
    Ok(Command::Enforce {
        state: state.ok_or_else(|| format!("The command needs --state.\n{}", help()))?,
        src: src.ok_or_else(|| format!("The command needs --src.\n{}", help()))?,
        dst_ip: dst_ip.ok_or_else(|| format!("The command needs --dst-ip.\n{}", help()))?,
        ports,
        audit: audit.ok_or_else(|| format!("The command needs --audit.\n{}", help()))?,
    })
}

fn help() -> String {
    "\
orblx policy check --file FILE
orblx policy test --file FILE
orblx policy enforce --state DIR --src NAME --dst-ip ADDR --port PORT --audit FILE

The policy file is HuJSON.
The file may contain comments and trailing commas.
A group names SPIFFE IDs.
A tag names SPIFFE IDs and has one owner.
An accept rule names a source, a destination, and a port.
The default is deny.
An agent source needs one host, one protocol, and one port.
The tests in the file must pass.
A failed test rejects the file.
The enforce command checks the signed grants on the receiver.
An allow writes no audit record.
A deny appends one record to the audit hash chain.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    #[test]
    fn check_requires_a_file() {
        let err = parse(&["check".to_string()]).unwrap_err();
        assert!(err.contains("--file"));
    }

    #[test]
    fn enforce_collects_ports() {
        let command = parse(&[
            "enforce".to_string(),
            "--state".to_string(),
            "/var/lib/orblx".to_string(),
            "--src".to_string(),
            "mac".to_string(),
            "--dst-ip".to_string(),
            "100.64.0.1".to_string(),
            "--port".to_string(),
            "22".to_string(),
            "--port".to_string(),
            "5432".to_string(),
            "--audit".to_string(),
            "audit.jsonl".to_string(),
        ])
        .unwrap();
        match command {
            Command::Enforce { ports, src, .. } => {
                assert_eq!(ports, vec![22, 5432]);
                assert_eq!(src, "mac");
            }
            Command::Help | Command::Check { .. } | Command::Test { .. } => {
                panic!("the parser did not select enforce");
            }
        }
    }
}
