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
    json: bool,
    verify_only: bool,
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
        "audit" => "admin-audit",
        "grants" => "admin-grants",
        "grant-approve" => "admin-grant-approve",
        "grant-revoke" => "admin-grant-revoke",
        other => return Err(format!("The mode {other} is not valid.\n{}", help())),
    };
    let mut target = String::new();
    let mut state = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut json = false;
    let mut verify_only = false;
    let mut index = 1;
    if matches!(
        op,
        "admin-approve"
            | "admin-revoke"
            | "admin-expire"
            | "admin-grant-approve"
            | "admin-grant-revoke"
    ) {
        let what = if op.starts_with("admin-grant") {
            "a grant id"
        } else {
            "a node name"
        };
        let name = args
            .get(index)
            .ok_or_else(|| format!("The command needs {what}.\n{}", help()))?;
        if name.starts_with('-') {
            return Err(format!("The command needs {what}.\n{}", help()));
        }
        target = name.clone();
        index += 1;
    }
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if op == "admin-audit" && flag == "--json" {
            json = true;
            continue;
        }
        if op == "admin-audit" && flag == "--verify" {
            verify_only = true;
            continue;
        }
        let value = take_value(args, &mut index)?;
        match flag {
            "--since" if op == "admin-audit" => {
                target = parse_since(&value, now_unix()?)?.to_string();
            }
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
        json,
        verify_only,
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
            let started_ms = now_millis();
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
            if call.op == "admin-audit" {
                return print_audit(&value, call.json, call.verify_only);
            }
            print_admin(&call.op, &value)?;
            if call.op == "admin-grant-revoke" {
                println!("revoke_start_ms {started_ms}");
                println!("revoke_done_ms {}", now_millis());
            }
            Ok(())
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
        "admin-grants" => {
            let grants = value
                .get("grants")
                .and_then(Value::as_array)
                .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
            for grant in grants {
                let port = grant.get("port").and_then(Value::as_u64).unwrap_or(0);
                println!(
                    "grant {} {} agent {} node {} service {} port {port} ttl {}",
                    text_field(grant, "id")?,
                    text_field(grant, "state")?,
                    text_field(grant, "agent")?,
                    text_field(grant, "node")?,
                    text_field(grant, "service")?,
                    grant.get("ttl_secs").and_then(Value::as_u64).unwrap_or(0),
                );
            }
            println!("grants {}", grants.len());
        }
        "admin-grant-approve" => {
            let grant = value.get("grant").unwrap_or(&Value::Null);
            println!("approved_grant {}", text_field(grant, "id")?);
            println!("grant_state {}", text_field(grant, "state")?);
        }
        "admin-grant-revoke" => {
            let grant = value.get("grant").unwrap_or(&Value::Null);
            println!("revoked_grant {}", text_field(grant, "id")?);
            println!("revoked_agent {}", text_field(grant, "agent")?);
            println!("revoke_scope this grant only");
            println!("grant_state {}", text_field(grant, "state")?);
            if let Some(version) = value.get("deny_version").and_then(Value::as_u64) {
                println!("deny_version {version}");
            }
        }
        _ => return Err("The admin operation is not valid.".to_string()),
    }
    Ok(())
}

/// Print the config chain records and the chain check.
///
/// The command fails when the coordinator chain check fails.
fn print_audit(value: &Value, json: bool, verify_only: bool) -> Result<(), String> {
    let bad = || "The coordinator response is not valid.".to_string();
    let lines = value
        .get("lines")
        .and_then(Value::as_array)
        .ok_or_else(bad)?;
    let verify = value.get("verify").ok_or_else(bad)?;
    if !verify_only {
        for line in lines {
            let raw = line.as_str().ok_or_else(bad)?;
            if json {
                println!("{raw}");
                continue;
            }
            match serde_json::from_str::<Value>(raw) {
                Ok(record) => println!("{}", audit_line(&record)),
                Err(_) => println!("record invalid line"),
            }
        }
    }
    let ok = verify.get("ok").and_then(Value::as_bool) == Some(true);
    let summary = if ok {
        let records = verify.get("records").and_then(Value::as_u64).unwrap_or(0);
        let tip = verify.get("tip").and_then(Value::as_str).unwrap_or("");
        format!("verify ok records {records} tip {tip}")
    } else {
        let error = verify
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("The chain check failed.");
        format!("verify failed: {error}")
    };
    if json && !verify_only {
        eprintln!("{summary}");
    } else {
        println!("{summary}");
    }
    if ok {
        Ok(())
    } else {
        Err("The config audit chain check failed.".to_string())
    }
}

fn audit_line(record: &Value) -> String {
    let field = |name: &str| {
        record
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string()
    };
    let short = |name: &str| field(name).chars().take(16).collect::<String>();
    let index = record
        .get("index")
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_string());
    let mut line = format!(
        "record {index} {} {} {} actor {} before {} after {}",
        field("at_utc"),
        field("action"),
        field("target"),
        field("actor"),
        short("before"),
        short("after"),
    );
    let detail = field("detail");
    if !detail.is_empty() && detail != "?" {
        line.push_str(" detail ");
        line.push_str(&detail);
    }
    line
}

/// Parse `--since` as Unix seconds.
///
/// The value is Unix seconds, `YYYY-MM-DDTHH:MM:SSZ`, or an age such as `90s`, `30m`, `2h`, or `7d`.
fn parse_since(text: &str, now: u64) -> Result<u64, String> {
    let bad = || format!("The --since value {text} is not valid.");
    if let Some(at) = orblx_audit::parse_utc_text(text) {
        return Ok(at);
    }
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        return text.parse::<u64>().map_err(|_| bad());
    }
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(bad()),
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(bad());
    }
    let count: u64 = number.parse().map_err(|_| bad())?;
    let age = count.checked_mul(scale).ok_or_else(bad)?;
    Ok(now.saturating_sub(age))
}

fn now_unix() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "The system time is not valid.".to_string())
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
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
orblx admin grants --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin grant-approve ID --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin grant-revoke ID --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin audit --coord ADDR [--since TIME] [--json] [--verify] [--state DIR] [--coord-name NAME] [--bundle FILE]

The command uses the node SVID in the state directory.
The coordinator accepts the call when that SVID is an owner.
approve puts the node into netmaps and grants.
revoke adds the node to the deny set.
expire removes the node from netmaps until approve.
grants lists the agent JIT grants.
grant-approve lets the agent fetch the grant. Only an owner approves an agent grant.
grant-revoke ends grant ID only. The ticket nonce of the grant goes into the deny set.
Other grants for the same agent name stay valid. The coordinator can issue new grants for that name.
To stop all grants for an agent, revoke each grant ID.
audit prints the control-plane audit chain and the chain check.
TIME is Unix seconds, YYYY-MM-DDTHH:MM:SSZ, or an age such as 30m, 2h, or 7d.
--json prints one JSON record on each line.
--verify prints only the chain check.
audit fails when the chain check fails.
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
    fn audit_parses_since_json_and_verify() {
        let command = parse(&[
            "audit".to_string(),
            "--coord".to_string(),
            "127.0.0.1:443".to_string(),
            "--since".to_string(),
            "2026-10-29T23:59:59Z".to_string(),
            "--json".to_string(),
            "--verify".to_string(),
        ])
        .unwrap();
        match command {
            Command::Call(call) => {
                assert_eq!(call.op, "admin-audit");
                assert_eq!(call.target, "1793318399");
                assert!(call.json);
                assert!(call.verify_only);
            }
            Command::Help => panic!("the parser did not select audit"),
        }
    }

    #[test]
    fn since_accepts_unix_utc_and_age() {
        assert_eq!(super::parse_since("100", 1000).unwrap(), 100);
        assert_eq!(super::parse_since("2m", 1000).unwrap(), 880);
        assert_eq!(super::parse_since("1d", 1000).unwrap(), 0);
        assert_eq!(super::parse_since("1970-01-01T00:01:40Z", 0).unwrap(), 100);
        assert!(super::parse_since("2w", 1000).is_err());
        assert!(super::parse_since("", 1000).is_err());
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
