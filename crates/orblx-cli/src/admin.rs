//! `orblx admin` talks to the coordinator over the node mTLS API.
//!
//! The caller SVID must be an owner in the policy.
//! The command does not print private keys or enroll tokens.

use std::net::SocketAddr;
use std::path::PathBuf;

use orblx_coord::admin_blocking;
use serde_json::Value;

use super::{parse_socket, take_value};

const DEFAULT_STATE: &str = "/var/lib/orblx";

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Call(Call),
}

#[derive(Debug)]
pub(crate) struct Call {
    op: String,
    target: String,
    state: PathBuf,
    coord: SocketAddr,
    coord_name: String,
    bundle: PathBuf,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let op = match args[0].as_str() {
        "nodes" => "admin-nodes",
        "users" => "admin-users",
        "approve" => "admin-approve",
        "revoke" => "admin-revoke",
        "expire" => "admin-expire",
        "routes" => "admin-routes",
        other => return Err(format!("The mode {other} is not valid.\n{}", help())),
    };
    let mut target = String::new();
    let mut state = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut index = 1;
    if matches!(op, "admin-approve" | "admin-revoke" | "admin-expire") {
        let name = args
            .get(index)
            .ok_or_else(|| format!("The command needs a node name.\n{}", help()))?;
        if name.starts_with('-') {
            return Err(format!("The command needs a node name.\n{}", help()));
        }
        target = name.clone();
        index += 1;
    }
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--state" => state = Some(PathBuf::from(value)),
            "--coord" => coord = Some(parse_socket(&value, 443)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let state = state.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE));
    let coord = coord.ok_or_else(|| format!("The command needs --coord.\n{}", help()))?;
    let bundle = bundle.unwrap_or_else(|| state.join("bundle.pem"));
    Ok(Command::Call(Call {
        op: op.to_string(),
        target,
        state,
        coord,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle,
    }))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Call(call) => {
            let bundle = std::fs::read_to_string(&call.bundle)
                .map_err(|err| format!("The file {} did not open. {err}", call.bundle.display()))?;
            let detail = admin_blocking(
                call.coord,
                &call.coord_name,
                &bundle,
                &call.state,
                &call.op,
                &call.target,
            )
            .map_err(|err| err.to_string())?;
            let value: Value = serde_json::from_str(&detail)
                .map_err(|_| "The coordinator response is not valid.".to_string())?;
            print_admin(&call.op, &value)
        }
    }
}

fn print_admin(op: &str, value: &Value) -> Result<(), String> {
    match op {
        "admin-nodes" => {
            let nodes = value
                .get("nodes")
                .and_then(Value::as_array)
                .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
            for node in nodes {
                let name = text_field(node, "name")?;
                let ip = text_field(node, "overlay_ip")?;
                let state = if node.get("expired").and_then(Value::as_bool) == Some(true) {
                    "expired"
                } else if node.get("approved").and_then(Value::as_bool) == Some(true) {
                    "approved"
                } else {
                    "pending"
                };
                println!("node {name} {ip} {state}");
            }
            println!("nodes {}", nodes.len());
        }
        "admin-users" => {
            let users = value
                .get("users")
                .and_then(Value::as_array)
                .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
            for user in users {
                let subject = text_field(user, "subject")?;
                println!("user {subject}");
            }
            println!("users {}", users.len());
        }
        "admin-approve" => {
            println!("approved {}", text_field(value, "name")?);
        }
        "admin-revoke" => {
            println!("revoked {}", text_field(value, "name")?);
            let version = value
                .get("deny_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
            println!("deny_version {version}");
        }
        "admin-expire" => {
            println!("expired {}", text_field(value, "name")?);
        }
        "admin-routes" => {
            let nodes = value
                .get("nodes")
                .and_then(Value::as_array)
                .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
            for node in nodes {
                let name = text_field(node, "name")?;
                let advertised = node
                    .get("advertised")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let approved = node
                    .get("approved")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                println!("node {name} advertised {advertised} approved {approved}");
                if let Some(routes) = node.get("approved").and_then(Value::as_array) {
                    for route in routes {
                        if let Some(text) = route.as_str() {
                            println!("approved route {name} {text}");
                        }
                    }
                }
            }
        }
        _ => return Err("The admin operation is not valid.".to_string()),
    }
    Ok(())
}

fn text_field(value: &Value, name: &str) -> Result<String, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "The coordinator response is not valid.".to_string())
}

fn help() -> String {
    "\
orblx admin nodes --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin users --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin approve NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin revoke NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin expire NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin routes --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]

The command uses the node SVID in the state directory.
The coordinator accepts the call when that SVID is an owner.
approve puts the node into netmaps and grants.
revoke adds the node to the deny set.
expire removes the node from netmaps until approve.
The command does not print private keys or enroll tokens.
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    #[test]
    fn approve_parses_the_node_name() {
        let command = parse(&[
            "approve".to_string(),
            "laptop".to_string(),
            "--coord".to_string(),
            "127.0.0.1:443".to_string(),
            "--state".to_string(),
            "/tmp/owner".to_string(),
        ])
        .unwrap();
        match command {
            Command::Call(call) => {
                assert_eq!(call.op, "admin-approve");
                assert_eq!(call.target, "laptop");
                assert_eq!(call.coord.port(), 443);
            }
            Command::Help => panic!("the parser did not select approve"),
        }
    }

    #[test]
    fn nodes_needs_a_coordinator_address() {
        let err = parse(&["nodes".to_string()]).unwrap_err();
        assert!(err.contains("--coord"));
    }

    #[test]
    fn revoke_needs_a_node_name() {
        let err = parse(&[
            "revoke".to_string(),
            "--coord".to_string(),
            "127.0.0.1:443".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("node name"));
    }
}
