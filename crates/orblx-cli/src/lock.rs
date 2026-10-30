//! `orblx lock` sets up and changes node lock (W23-1).
//!
//! A node with a node lock file accepts a peer only when a trusted owner key signed that peer.
//! The owner private key stays in the owner key file. The commands print key fingerprints only.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use orblx_coord::admin_blocking;
use orblx_coord::nodelock::{
    fingerprint, read_node_lock, read_pub_file, trust_keys, LockState, OwnerKey, ACTION_REMOVE,
    ACTION_ROTATE,
};
use serde_json::{json, Value};

use super::{parse_socket, take_value};

const DEFAULT_STATE: &str = "/var/lib/orblx";

#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Run(Box<Options>),
}

#[derive(Debug)]
pub(crate) struct Options {
    mode: String,
    node: String,
    pubs: Vec<PathBuf>,
    key_file: Option<PathBuf>,
    new_key_file: Option<PathBuf>,
    out: Option<PathBuf>,
    state: PathBuf,
    coord: Option<SocketAddr>,
    coord_name: String,
    bundle: Option<PathBuf>,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let mode = args[0].clone();
    if !matches!(
        mode.as_str(),
        "keygen" | "trust" | "status" | "show" | "init" | "sign" | "rotate" | "remove"
    ) {
        return Err(format!("The mode {mode} is not valid.\n{}", help()));
    }
    let mut index = 1;
    let mut node = String::new();
    if mode == "sign" {
        let name = args
            .get(index)
            .filter(|name| !name.starts_with('-'))
            .ok_or_else(|| format!("The command needs a node name.\n{}", help()))?;
        node = name.clone();
        index += 1;
    }
    let mut options = Options {
        mode,
        node,
        pubs: Vec::new(),
        key_file: None,
        new_key_file: None,
        out: None,
        state: PathBuf::from(DEFAULT_STATE),
        coord: None,
        coord_name: "coord".to_string(),
        bundle: None,
    };
    while index < args.len() {
        let flag = args[index].clone();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag.as_str() {
            "--pub-file" => options.pubs.push(PathBuf::from(value)),
            "--key-file" => options.key_file = Some(PathBuf::from(value)),
            "--new-key-file" => options.new_key_file = Some(PathBuf::from(value)),
            "--out" => options.out = Some(PathBuf::from(value)),
            "--state" => options.state = PathBuf::from(value),
            "--coord" => options.coord = Some(parse_socket(&value, 443)?),
            "--coord-name" => options.coord_name = value,
            "--bundle" => options.bundle = Some(PathBuf::from(value)),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    let needs = |ok: bool, what: &str| -> Result<(), String> {
        if ok {
            Ok(())
        } else {
            Err(format!("The command needs {what}.\n{}", help()))
        }
    };
    match options.mode.as_str() {
        "keygen" => needs(options.out.is_some(), "--out")?,
        "trust" | "init" => needs(!options.pubs.is_empty(), "--pub-file")?,
        "sign" => needs(options.key_file.is_some(), "--key-file")?,
        "rotate" => needs(
            options.key_file.is_some() && options.new_key_file.is_some(),
            "--key-file and --new-key-file",
        )?,
        "remove" => needs(
            options.key_file.is_some() && options.pubs.len() == 1,
            "--key-file and one --pub-file",
        )?,
        _ => {}
    }
    if matches!(
        options.mode.as_str(),
        "show" | "init" | "sign" | "rotate" | "remove"
    ) {
        needs(options.coord.is_some(), "--coord")?;
    }
    Ok(Command::Run(Box::new(options)))
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    let options = match command {
        Command::Help => {
            println!("{}", help());
            return Ok(());
        }
        Command::Run(options) => *options,
    };
    match options.mode.as_str() {
        "keygen" => keygen(&options),
        "trust" => trust(&options),
        "status" => status(&options),
        "show" => show(&options),
        "init" => init(&options),
        "sign" => sign(&options),
        "rotate" => rotate(&options),
        "remove" => remove(&options),
        _ => Err(help()),
    }
}

fn keygen(options: &Options) -> Result<(), String> {
    let out = options.out.as_ref().ok_or_else(help)?;
    if out.exists() {
        return Err(format!("The file {} exists.", out.display()));
    }
    let key = OwnerKey::generate();
    key.write_files(out, &pub_path(out))
        .map_err(|err| err.to_string())?;
    println!("owner_key_fp {}", fingerprint(&key.key_id()));
    println!("pub_file {}", pub_path(out).display());
    Ok(())
}

fn pub_path(key: &Path) -> PathBuf {
    let mut name = key
        .file_name()
        .map(|v| v.to_os_string())
        .unwrap_or_default();
    name.push(".pub");
    key.with_file_name(name)
}

fn read_pubs(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    paths
        .iter()
        .map(|path| read_pub_file(path).map_err(|err| err.to_string()))
        .collect()
}

fn trust(options: &Options) -> Result<(), String> {
    let keys = read_pubs(&options.pubs)?;
    let state = trust_keys(&options.state, &keys).map_err(|err| err.to_string())?;
    print_state("node_lock", &state);
    Ok(())
}

fn status(options: &Options) -> Result<(), String> {
    match read_node_lock(&options.state).map_err(|err| err.to_string())? {
        Some(state) => print_state("node_lock", &state),
        None => println!("node_lock off"),
    }
    Ok(())
}

fn print_state(label: &str, state: &LockState) {
    println!(
        "{label} on version {} keys {}",
        state.version,
        state.keys.len()
    );
    for key in &state.keys {
        println!("trusted_key_fp {}", fingerprint(key));
    }
}

fn call(options: &Options, op: &str, name: &str) -> Result<Value, String> {
    let coord = options.coord.ok_or_else(help)?;
    let bundle_path = options
        .bundle
        .clone()
        .unwrap_or_else(|| options.state.join("bundle.pem"));
    let bundle = std::fs::read_to_string(&bundle_path)
        .map_err(|err| format!("The file {} did not open. {err}", bundle_path.display()))?;
    let detail = admin_blocking(
        coord,
        &options.coord_name,
        &bundle,
        &options.state,
        op,
        name,
    )
    .map_err(|err| err.to_string())?;
    serde_json::from_str(&detail).map_err(|_| "The coordinator response is not valid.".to_string())
}

fn coord_state(value: &Value) -> Result<LockState, String> {
    let bad = || "The coordinator response is not valid.".to_string();
    if value.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Err("Node lock is not set up on the coordinator.".to_string());
    }
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(bad)?
        .iter()
        .map(|key| key.as_str().map(str::to_string).ok_or_else(bad))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LockState {
        version: value
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(bad)?,
        keys,
        head: value
            .get("head")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_string(),
    })
}

fn signed_nodes(value: &Value) -> Vec<(String, String)> {
    value
        .get("signed")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some((
                        item.get("name")?.as_str()?.to_string(),
                        item.get("key_id")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn print_coord(value: &Value) -> Result<(), String> {
    let state = coord_state(value)?;
    print_state("coord_lock", &state);
    for (name, key) in signed_nodes(value) {
        println!("signed_node {name} key_fp {}", fingerprint(&key));
    }
    Ok(())
}

fn show(options: &Options) -> Result<(), String> {
    let value = call(options, "admin-lock", "")?;
    if value.get("enabled").and_then(Value::as_bool) != Some(true) {
        println!("coord_lock off");
        return Ok(());
    }
    print_coord(&value)
}

fn init(options: &Options) -> Result<(), String> {
    let keys = read_pubs(&options.pubs)?;
    let ask = json!({"keys": keys}).to_string();
    let value = call(options, "admin-lock-init", &ask)?;
    print_coord(&value)
}

fn load_key(path: Option<&PathBuf>) -> Result<OwnerKey, String> {
    let path = path.ok_or_else(help)?;
    OwnerKey::from_file(path).map_err(|err| err.to_string())
}

fn sign_one(options: &Options, key: &OwnerKey, name: &str) -> Result<u64, String> {
    let nodes = call(options, "admin-nodes", "")?;
    let node = nodes
        .get("nodes")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        })
        .ok_or_else(|| format!("The node {name} is not enrolled."))?;
    let field = |key: &str| {
        node.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "The coordinator response is not valid.".to_string())
    };
    let sig = key.sign_node(name, &field("svid")?, &field("overlay_ip")?);
    let ask = json!({"name": name, "key_id": sig.key_id, "sig": sig.sig}).to_string();
    let value = call(options, "admin-lock-sign", &ask)?;
    Ok(value.get("version").and_then(Value::as_u64).unwrap_or(0))
}

fn sign(options: &Options) -> Result<(), String> {
    let key = load_key(options.key_file.as_ref())?;
    let version = sign_one(options, &key, &options.node)?;
    println!(
        "lock_signed {} key_fp {} version {version}",
        options.node,
        fingerprint(&key.key_id())
    );
    Ok(())
}

fn send_update(options: &Options, update: &orblx_datapath::LockUpdate) -> Result<Value, String> {
    let text = serde_json::to_string(update).map_err(|_| "The update is not valid.".to_string())?;
    call(options, "admin-lock-update", &text)
}

fn rotate(options: &Options) -> Result<(), String> {
    let old = load_key(options.key_file.as_ref())?;
    let new = load_key(options.new_key_file.as_ref())?;
    let value = call(options, "admin-lock", "")?;
    let state = coord_state(&value)?;
    let old_id = old.key_id();
    let new_id = new.key_id();
    let mut keys: Vec<String> = state
        .keys
        .iter()
        .filter(|key| **key != old_id)
        .cloned()
        .collect();
    keys.push(new_id.clone());
    let update = old
        .sign_update(&state, ACTION_ROTATE, &keys)
        .map_err(|err| err.to_string())?;
    let after = send_update(options, &update)?;
    println!(
        "lock_rotated version {} old_fp {} new_fp {}",
        update.version,
        fingerprint(&old_id),
        fingerprint(&new_id)
    );
    for (name, key) in signed_nodes(&after) {
        if key == old_id {
            sign_one(options, &new, &name)?;
            println!("lock_resigned {name} key_fp {}", fingerprint(&new_id));
        }
    }
    Ok(())
}

fn remove(options: &Options) -> Result<(), String> {
    let signer = load_key(options.key_file.as_ref())?;
    let target = read_pubs(&options.pubs)?.remove(0);
    let value = call(options, "admin-lock", "")?;
    let state = coord_state(&value)?;
    let keys: Vec<String> = state
        .keys
        .iter()
        .filter(|key| **key != target)
        .cloned()
        .collect();
    let update = signer
        .sign_update(&state, ACTION_REMOVE, &keys)
        .map_err(|err| err.to_string())?;
    send_update(options, &update)?;
    println!(
        "lock_removed version {} removed_fp {} signer_fp {}",
        update.version,
        fingerprint(&target),
        fingerprint(&signer.key_id())
    );
    Ok(())
}

fn help() -> String {
    "orblx lock keygen --out FILE
orblx lock trust --pub-file FILE [--pub-file FILE] [--state DIR]
orblx lock status [--state DIR]
orblx lock show --coord ADDR [--state DIR] [--bundle FILE] [--coord-name NAME]
orblx lock init --pub-file FILE [--pub-file FILE] --coord ADDR [--state DIR]
orblx lock sign NODE --key-file FILE --coord ADDR [--state DIR]
orblx lock rotate --key-file OLD --new-key-file NEW --coord ADDR [--state DIR]
orblx lock remove --pub-file FILE --key-file SIGNER --coord ADDR [--state DIR]

Node lock (W23-1). A node with a node lock file accepts a peer only when a trusted owner key signed that peer.
keygen writes the owner key file (mode 0600) and FILE.pub. Keep the owner key file off the coordinator.
trust pins the first trusted owner keys on this node. Copy the .pub file to the node out of band.
init, sign, rotate, and remove use the owner node SVID in --state. The caller must be a policy owner.
rotate replaces the --key-file key with the --new-key-file key and signs the nodes again with the new key.
remove removes the --pub-file key. A different trusted key or the same key can sign the remove.
The commands print key fingerprints only. They do not print keys or signatures."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn sign_needs_a_node_and_a_key() {
        assert!(parse(&args(&[
            "sign",
            "--key-file",
            "k",
            "--coord",
            "127.0.0.1:443"
        ]))
        .is_err());
        assert!(parse(&args(&["sign", "b", "--coord", "127.0.0.1:443"])).is_err());
        let Command::Run(options) = parse(&args(&[
            "sign",
            "b",
            "--key-file",
            "k",
            "--coord",
            "127.0.0.1:443",
        ]))
        .unwrap() else {
            panic!("expected a run command");
        };
        assert_eq!(options.node, "b");
    }

    #[test]
    fn local_modes_need_no_coordinator() {
        assert!(parse(&args(&["trust", "--pub-file", "p"])).is_ok());
        assert!(parse(&args(&["status"])).is_ok());
        assert!(parse(&args(&["keygen"])).is_err());
        assert!(parse(&args(&["init", "--pub-file", "p"])).is_err());
        assert!(parse(&args(&[
            "remove",
            "--key-file",
            "k",
            "--coord",
            "127.0.0.1"
        ]))
        .is_err());
    }
}
