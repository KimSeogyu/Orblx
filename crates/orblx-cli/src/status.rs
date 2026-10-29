//! `orblx status` and `orblx status --json`.

use orblx_datapath::read_status_text;
use serde_json::{json, Value};

use super::up;

#[derive(Debug)]
pub(crate) enum Command {
    Text(up::Command),
    Json(up::Command),
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    let json_out = args.iter().any(|arg| arg == "--json");
    let rest: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    let inner = up::parse_status(&rest)?;
    if json_out {
        Ok(Command::Json(inner))
    } else {
        Ok(Command::Text(inner))
    }
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Text(inner) => up::run(inner),
        Command::Json(inner) => {
            let up::Command::Status(options) = inner else {
                return up::run(inner);
            };
            let text = read_status_text(&options.state_dir).map_err(|err| err.to_string())?;
            let value = status_json(&text)?;
            println!("{value}");
            Ok(())
        }
    }
}

fn status_json(text: &str) -> Result<String, String> {
    let mut state = String::new();
    let mut name = String::new();
    let mut overlay_ip = String::new();
    let mut svid = String::new();
    let mut svid_expiry = Value::Null;
    let mut peers = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("state") => state = rest(parts),
            Some("name") => name = rest(parts),
            Some("overlay_ip") => overlay_ip = rest(parts),
            Some("svid") => svid = rest(parts),
            Some("svid_expiry") => {
                let text = rest(parts);
                svid_expiry = match text.parse::<u64>() {
                    Ok(value) => json!(value),
                    Err(_) => Value::Null,
                };
            }
            Some("peer") => peers.push(parse_peer(line)?),
            Some(_) | None => {}
        }
    }
    if state.is_empty() || name.is_empty() {
        return Err("The status text is not valid.".to_string());
    }
    let value = json!({
        "state": state,
        "name": name,
        "overlay_ip": overlay_ip,
        "svid": svid,
        "svid_expiry": svid_expiry,
        "peers": peers,
    });
    serde_json::to_string(&value).map_err(|_| "The status text is not valid.".to_string())
}

fn parse_peer(line: &str) -> Result<Value, String> {
    let mut parts = line.split_whitespace();
    let _peer = parts.next();
    let name = parts
        .next()
        .ok_or_else(|| "The status text is not valid.".to_string())?;
    let mut overlay_ip = String::new();
    let mut path = String::new();
    let mut svid = String::new();
    let mut svid_expiry = Value::Null;
    while let Some(key) = parts.next() {
        let value = parts
            .next()
            .ok_or_else(|| "The status text is not valid.".to_string())?;
        match key {
            "overlay_ip" => overlay_ip = value.to_string(),
            "path" => path = value.to_string(),
            "svid" => svid = value.to_string(),
            "svid_expiry" => {
                svid_expiry = match value.parse::<u64>() {
                    Ok(number) => json!(number),
                    Err(_) => Value::Null,
                };
            }
            _ => {}
        }
    }
    Ok(json!({
        "name": name,
        "overlay_ip": overlay_ip,
        "path": path,
        "svid": svid,
        "svid_expiry": svid_expiry,
    }))
}

fn rest<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts.collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{parse, status_json, Command};

    #[test]
    fn status_json_flag_selects_json() {
        let command = parse(&[
            "--json".to_string(),
            "--state-dir".to_string(),
            "/tmp/n".to_string(),
        ])
        .unwrap();
        assert!(matches!(command, Command::Json(_)));
    }

    #[test]
    fn status_text_becomes_json() {
        let text = "\
state up
name a
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/a
svid_expiry 100
peer b overlay_ip 100.64.0.2 path direct svid spiffe://orblx.local/node/b svid_expiry 200
";
        let json = status_json(text).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["state"], "up");
        assert_eq!(value["peers"][0]["path"], "direct");
        assert_eq!(value["peers"][0]["svid_expiry"], 200);
    }
}
