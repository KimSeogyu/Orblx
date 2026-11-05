//! `orblx admin` talks to the coordinator over the node mTLS API.
//!
//! The caller SVID must be an owner in the policy, or the caller gives a scoped
//! API token with `--token-file` (W25-3).
//! The command does not print private keys or enroll tokens.
//! It prints an API token only at `token-create` without `--out`.

use std::net::SocketAddr;
use std::path::PathBuf;

use orblx_coord::{admin_blocking, admin_token_blocking, parse_api_token_ttl, parse_scopes};
use serde_json::Value;

use super::{parse_socket, take_value};

const DEFAULT_STATE: &str = "/var/lib/orblx";

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Call(Box<Call>),
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
    token_file: Option<PathBuf>,
    out: Option<PathBuf>,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let op = match args[0].as_str() {
        "nodes" => "admin-nodes",
        "users" => "admin-users",
        "user-approve" => "admin-user-approve",
        "user-reject" => "admin-user-reject",
        "approve" => "admin-approve",
        "revoke" => "admin-revoke",
        "revoke-all" => "admin-revoke-all",
        "revoke-undo" => "admin-revoke-undo",
        "expire" => "admin-expire",
        "netmap-seq-reset" => "admin-netmap-seq-reset",
        "routes" => "admin-routes",
        "audit" => "admin-audit",
        "grants" => "admin-grants",
        "grant-approve" => "admin-grant-approve",
        "grant-revoke" => "admin-grant-revoke",
        "policy" => "admin-policy",
        "policy-set" => "admin-policy-set",
        "token-create" => "admin-token-create",
        "token-list" => "admin-token-list",
        "token-revoke" => "admin-token-revoke",
        "call" => "call",
        other => return Err(format!("The mode {other} is not valid.\n{}", help())),
    };
    let mut op = op.to_string();
    let mut token_file = None;
    let mut out = None;
    let mut scopes = None;
    let mut ttl = None;
    let mut policy_file = None;
    let mut target = String::new();
    let mut state = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut json = false;
    let mut verify_only = false;
    let mut index = 1;
    // A raw call sends ARG as the target and skips the local mode checks.
    let raw = op == "call";
    if raw {
        let wire = args
            .get(index)
            .filter(|name| name.starts_with("admin-"))
            .ok_or_else(|| format!("The command needs an admin operation.\n{}", help()))?;
        op = wire.clone();
        index += 1;
        if let Some(arg) = args.get(index).filter(|arg| !arg.starts_with("--")) {
            target = arg.clone();
            index += 1;
        }
    } else if op == "admin-token-revoke" || op == "admin-policy-set" {
        let what = if op == "admin-token-revoke" {
            "a token id"
        } else {
            "a policy file"
        };
        let name = args
            .get(index)
            .filter(|name| !name.starts_with('-'))
            .ok_or_else(|| format!("The command needs {what}.\n{}", help()))?;
        if op == "admin-token-revoke" {
            target = name.clone();
        } else {
            policy_file = Some(PathBuf::from(name));
        }
        index += 1;
    } else if matches!(
        op.as_str(),
        "admin-approve"
            | "admin-revoke"
            | "admin-revoke-all"
            | "admin-revoke-undo"
            | "admin-expire"
            | "admin-grant-approve"
            | "admin-grant-revoke"
            | "admin-user-approve"
            | "admin-user-reject"
    ) {
        let what = if op.starts_with("admin-grant") {
            "a grant id"
        } else if op.starts_with("admin-user-") {
            "a user (oidc:SUBJECT)"
        } else if op == "admin-revoke-all" || op == "admin-revoke-undo" {
            "a principal"
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
            "--token-file" => token_file = Some(PathBuf::from(value)),
            "--out" if op == "admin-token-create" && !raw => out = Some(PathBuf::from(value)),
            "--scope" if op == "admin-token-create" && !raw => {
                let list = parse_scopes(&value).map_err(|err| err.to_string())?;
                scopes = Some(list);
            }
            "--ttl" if op == "admin-token-create" && !raw => {
                ttl = Some(parse_api_token_ttl(&value)?)
            }
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
    if op == "admin-token-create" && !raw {
        let scopes = scopes.ok_or_else(|| format!("The command needs --scope.\n{}", help()))?;
        let ttl = ttl.ok_or_else(|| format!("The command needs --ttl.\n{}", help()))?;
        target = serde_json::json!({"scopes": scopes, "ttl_secs": ttl.as_secs()}).to_string();
    }
    if let Some(file) = policy_file {
        target = std::fs::read_to_string(&file)
            .map_err(|err| format!("The file {} did not open. {err}", file.display()))?;
    }
    Ok(Command::Call(Box::new(Call {
        op,
        target,
        json,
        verify_only,
        state,
        coord,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle,
        token_file,
        out,
    })))
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
            let detail = match &call.token_file {
                Some(file) => token_call(&call, &bundle, file)?,
                None => admin_blocking(
                    call.coord,
                    &call.coord_name,
                    &bundle,
                    &call.state,
                    &call.op,
                    &call.target,
                )
                .map_err(|err| err.to_string())?,
            };
            let value: Value = serde_json::from_str(&detail)
                .map_err(|_| "The coordinator response is not valid.".to_string())?;
            if call.op == "admin-audit" {
                return print_audit(&value, call.json, call.verify_only);
            }
            if call.op == "admin-token-create" {
                return print_created(&value, call.out.as_deref());
            }
            print_admin(&call.op, &value)?;
            if matches!(
                call.op.as_str(),
                "admin-grant-revoke" | "admin-revoke-all" | "admin-revoke-undo"
            ) {
                println!("revoke_start_ms {started_ms}");
                println!("revoke_done_ms {}", now_millis());
            }
            Ok(())
        }
    }
}

/// Send one admin call with the API token in `file`.
///
/// The command prints `status N done_ms MS`. It fails when the status is not 200.
fn token_call(call: &Call, bundle: &str, file: &std::path::Path) -> Result<String, String> {
    let token = std::fs::read_to_string(file)
        .map_err(|err| format!("The file {} did not open. {err}", file.display()))?;
    let reply = admin_token_blocking(
        call.coord,
        &call.coord_name,
        bundle,
        token.trim(),
        &call.op,
        &call.target,
    )
    .map_err(|err| err.to_string())?;
    println!("status {} done_ms {}", reply.status, now_millis());
    if reply.status != 200 {
        return Err(reply
            .error
            .unwrap_or_else(|| "The coordinator request failed.".to_string()));
    }
    reply
        .detail
        .ok_or_else(|| "The coordinator response is not valid.".to_string())
}

/// Write the new token to `out` with mode 0600, or print it one time.
fn print_created(value: &Value, out: Option<&std::path::Path>) -> Result<(), String> {
    let bad = || "The coordinator response is not valid.".to_string();
    let token = text_field(value, "token")?;
    let id = text_field(value, "id")?;
    let scopes: Vec<&str> = value
        .get("scopes")
        .and_then(Value::as_array)
        .ok_or_else(bad)?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expires = value
        .get("expires_unix_ms")
        .and_then(Value::as_u64)
        .ok_or_else(bad)?;
    match out {
        Some(path) => {
            write_private(path, &format!("{token}\n"))?;
            println!("wrote one api token");
            println!("out {}", path.display());
        }
        None => {
            println!("api_token {token}");
            println!(
                "The coordinator keeps only a digest. This is the only time the token is shown."
            );
        }
    }
    println!("token_id {id}");
    println!("scopes {}", scopes.join(","));
    println!("expires_unix_ms {expires}");
    Ok(())
}

fn write_private(path: &std::path::Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|err| format!("The file {} was not written. {err}", path.display()))
}

fn print_admin(op: &str, value: &Value) -> Result<(), String> {
    match op {
        "admin-token-list" => {
            let tokens = value
                .get("tokens")
                .and_then(Value::as_array)
                .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
            for token in tokens {
                let scopes: Vec<&str> = token
                    .get("scopes")
                    .and_then(Value::as_array)
                    .map(|list| list.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                println!(
                    "token {} {} scopes {} expires_unix_ms {}",
                    text_field(token, "id")?,
                    text_field(token, "state")?,
                    scopes.join(","),
                    token
                        .get("expires_unix_ms")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                );
            }
            println!("tokens {}", tokens.len());
        }
        "admin-token-revoke" => {
            println!("revoked_token {}", text_field(value, "id")?);
            let at = value
                .get("revoked_unix_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            println!("revoked_unix_ms {at}");
        }
        "admin-policy" => {
            if value.get("present").and_then(Value::as_bool) == Some(true) {
                println!("policy_sha256 {}", text_field(value, "sha256")?);
                print!("{}", text_field(value, "text")?);
            } else {
                println!("policy none");
            }
        }
        "admin-policy-set" => {
            println!("policy_set {}", text_field(value, "sha256")?);
        }
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
            let mut pending = 0usize;
            for user in users {
                let subject = text_field(user, "subject")?;
                let state = user
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("approved");
                if state == "pending" {
                    pending += 1;
                }
                let nodes = user
                    .get("nodes")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                println!("user {subject} {state} nodes {nodes}");
            }
            println!("users {}", users.len());
            println!("users_pending {pending}");
        }
        "admin-user-approve" => {
            println!("user_approved {}", text_field(value, "user")?);
        }
        "admin-user-reject" => {
            println!("user_rejected {}", text_field(value, "user")?);
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
        "admin-revoke-all" => {
            let bad = || "The coordinator response is not valid.".to_string();
            println!("revoked_all {}", text_field(value, "principal")?);
            println!("revoke_scope all");
            println!("svid_denied yes");
            let grants = value
                .get("grants")
                .and_then(Value::as_array)
                .ok_or_else(bad)?;
            for grant in grants {
                println!("revoked_grant {}", grant.as_str().ok_or_else(bad)?);
            }
            println!("grants_revoked {}", grants.len());
            let nonces = value
                .get("nonces")
                .and_then(Value::as_u64)
                .ok_or_else(bad)?;
            println!("grant_nonces_denied {nonces}");
            let version = value
                .get("deny_version")
                .and_then(Value::as_u64)
                .ok_or_else(bad)?;
            println!("deny_version {version}");
        }
        "admin-revoke-undo" => {
            println!("unrevoked {}", text_field(value, "principal")?);
            println!("svid_restored yes");
            let version = value
                .get("deny_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| "The coordinator response is not valid.".to_string())?;
            println!("deny_version {version}");
        }
        "admin-expire" => {
            println!("expired {}", text_field(value, "name")?);
        }
        "admin-netmap-seq-reset" => {
            let field = |key: &str| {
                value
                    .get(key)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "The coordinator response is not valid.".to_string())
            };
            println!(
                "netmap_seq_reset from {} to {}",
                field("from")?,
                field("to")?
            );
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
        _ => println!(
            "{}",
            serde_json::to_string(value).map_err(|err| err.to_string())?
        ),
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
orblx admin user-approve USER --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin user-reject USER --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin approve NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin revoke NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin revoke-all PRINCIPAL --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin revoke-undo PRINCIPAL --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin expire NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin netmap-seq-reset --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin routes --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin grants --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin grant-approve ID --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin grant-revoke ID --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin audit --coord ADDR [--since TIME] [--json] [--verify] [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin policy --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin policy-set FILE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin token-create --scope SCOPE[,SCOPE] --ttl TIME --coord ADDR [--out FILE] [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin token-list --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin token-revoke ID --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin call OP [ARG] --coord ADDR [--token-file FILE] [--state DIR] [--coord-name NAME] [--bundle FILE]

Each command except token-create, token-list, and token-revoke also accepts --token-file FILE.
With --token-file, the command sends the scoped API token in FILE and no client certificate.
The coordinator accepts the call only when the token has the scope of the operation.
The command then prints `status N done_ms MS`. 401: the token is not valid, expired, or revoked.
403: the token does not have the scope. Only an owner SVID can create, list, or revoke tokens.
Scopes: nodes:read (nodes, users, routes),
nodes:write (approve, revoke, revoke-all, revoke-undo, expire, user-approve, user-reject),
grants:read (grants), grants:write (grant-approve, grant-revoke), audit:read (audit),
lock:read and lock:write (node lock), policy:read (policy), policy:write (policy-set).
TIME for --ttl is seconds or an age such as 90s, 30m, 2h, or 7d. The maximum is 30d.
token-create prints the token one time. With --out, it writes the token to FILE (mode 0600) and does not print it.
The coordinator keeps only the SHA-256 digest of the token.
call sends one admin operation by its wire name, such as admin-lock-init. It is for scripts and tests.

The command uses the node SVID in the state directory.
The coordinator accepts the call when that SVID is an owner.
approve puts the node into netmaps and grants.
revoke adds the node to the deny set.
revoke-all stops all access of one principal with one deny change and one audit record:
the SVID, all agent grants of the principal, SSH, and file send.
PRINCIPAL is a node name or a SPIFFE URI of a node, a user, or an agent.
revoke-undo removes the SVID deny entry of the principal with one deny change and one audit record.
The grants that revoke-all revoked stay revoked.
expire removes the node from netmaps until approve.
netmap-seq-reset is for a coordinator clock that went forward and then back.
The coordinator then signs no netmap, because the stored netmap seq is more than 60 s
ahead of its clock. The command sets the stored seq to the clock time. It works only when
the stored seq is ahead of the clock. Only an owner SVID can run it (no API token).
It writes one netmap-seq-reset audit record (code 41).
users lists the OIDC users with the state pending, approved, or rejected.
A new OIDC user is pending. A pending or rejected user gets no SVID and cannot enroll a node.
user-approve lets USER enroll nodes. USER is oidc:SUBJECT or SUBJECT.
An owner can approve a user before the first sign-in.
user-reject refuses a pending or new USER. An owner user cannot be rejected.
Each user-approve and user-reject writes one audit record.
grants lists the agent JIT grants.
grant-approve lets the agent fetch the grant. Only an owner approves an agent grant.
grant-revoke ends grant ID only. The ticket nonce of the grant goes into the deny set.
Other grants for the same agent name stay valid. The coordinator can issue new grants for that name.
To stop all grants for an agent, use revoke-all with the agent URI.
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
    fn user_approve_and_reject_parse_the_user() {
        for (mode, op) in [
            ("user-approve", "admin-user-approve"),
            ("user-reject", "admin-user-reject"),
        ] {
            let command = parse(&[
                mode.to_string(),
                "oidc:nina".to_string(),
                "--coord".to_string(),
                "127.0.0.1:443".to_string(),
            ])
            .unwrap();
            match command {
                Command::Call(call) => {
                    assert_eq!(call.op, op);
                    assert_eq!(call.target, "oidc:nina");
                }
                Command::Help => panic!("help"),
            }
            let err = parse(&[
                mode.to_string(),
                "--coord".to_string(),
                "127.0.0.1:443".to_string(),
            ])
            .unwrap_err();
            assert!(err.contains("a user"), "{err}");
        }
    }

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
    fn revoke_all_parses_the_principal() {
        let command = parse(&[
            "revoke-all".to_string(),
            "spiffe://orblx.local/node/a".to_string(),
            "--coord".to_string(),
            "127.0.0.1:443".to_string(),
        ])
        .unwrap();
        match command {
            Command::Call(call) => {
                assert_eq!(call.op, "admin-revoke-all");
                assert_eq!(call.target, "spiffe://orblx.local/node/a");
            }
            Command::Help => panic!("the parser did not select revoke-all"),
        }
        let err = parse(&[
            "revoke-all".to_string(),
            "--coord".to_string(),
            "127.0.0.1:443".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("a principal"));
    }

    #[test]
    fn revoke_undo_parses_the_principal() {
        let command = parse(&[
            "revoke-undo".to_string(),
            "a".to_string(),
            "--coord".to_string(),
            "127.0.0.1:443".to_string(),
        ])
        .unwrap();
        match command {
            Command::Call(call) => {
                assert_eq!(call.op, "admin-revoke-undo");
                assert_eq!(call.target, "a");
            }
            Command::Help => panic!("the parser did not select revoke-undo"),
        }
        let err = parse(&[
            "revoke-undo".to_string(),
            "--coord".to_string(),
            "127.0.0.1:443".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("a principal"));
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

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn token_create_needs_known_scopes_and_a_life() {
        let command = parse(&args(&[
            "token-create",
            "--scope",
            "nodes:read,audit:read",
            "--ttl",
            "10m",
            "--out",
            "/tmp/t",
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap();
        match command {
            Command::Call(call) => {
                assert_eq!(call.op, "admin-token-create");
                assert_eq!(
                    call.target,
                    r#"{"scopes":["audit:read","nodes:read"],"ttl_secs":600}"#
                );
                assert_eq!(call.out.as_deref(), Some(std::path::Path::new("/tmp/t")));
            }
            Command::Help => panic!("the parser did not select token-create"),
        }
        let bad = parse(&args(&[
            "token-create",
            "--scope",
            "nodes:all",
            "--ttl",
            "10m",
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap_err();
        assert!(bad.contains("scope"));
        let no_ttl = parse(&args(&[
            "token-create",
            "--scope",
            "nodes:read",
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap_err();
        assert!(no_ttl.contains("--ttl"));
    }

    #[test]
    fn token_file_and_call_parse() {
        let command = parse(&args(&[
            "call",
            "admin-lock-init",
            "{}",
            "--token-file",
            "/tmp/t",
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap();
        match command {
            Command::Call(call) => {
                assert_eq!(call.op, "admin-lock-init");
                assert_eq!(call.target, "{}");
                assert_eq!(
                    call.token_file.as_deref(),
                    Some(std::path::Path::new("/tmp/t"))
                );
            }
            Command::Help => panic!("the parser did not select call"),
        }
        assert!(parse(&args(&["call", "nodes", "--coord", "127.0.0.1:443"])).is_err());
        let raw = r#"{"scopes":["nodes:write"],"ttl_secs":60}"#;
        let command = parse(&args(&[
            "call",
            "admin-token-create",
            raw,
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap();
        match command {
            Command::Call(call) => assert_eq!(call.target, raw),
            Command::Help => panic!("the parser did not select call"),
        }
        let command = parse(&args(&["token-revoke", "abcd", "--coord", "127.0.0.1:443"])).unwrap();
        match command {
            Command::Call(call) => assert_eq!(call.target, "abcd"),
            Command::Help => panic!("the parser did not select token-revoke"),
        }
    }
}
