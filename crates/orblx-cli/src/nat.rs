//! `orblx nat` runs a node behind NAT and checks a candidate signature.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use orblx_coord::{publish_candidates_blocking, renew_svid_blocking};
use orblx_datapath::Netmap;
use orblx_edge::{
    decode_hex_key, prepare_nat_gateway, run_nat_node, verify_signed_candidate, HelloAuth,
    NatConfig, RenewFn, RenewedLeaf, SignedCandidate,
};
use orblx_identity::{
    decode_certificate_pem, ed25519_seed_from_private_pem, extract_spiffe_id, leaf_not_after,
    TrustBundle,
};

use super::{parse_socket, take_value};

/// A NAT command.
#[derive(Debug)]
pub(crate) enum Command {
    Help,
    Run(RunOptions),
    Verify(VerifyOptions),
}

#[derive(Debug)]
pub(crate) struct RunOptions {
    state: PathBuf,
    coord: SocketAddr,
    coord_name: String,
    bundle: PathBuf,
    stun: SocketAddr,
    stun_alt: Option<SocketAddr>,
    relay: SocketAddr,
    peer: String,
    gateway: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub(crate) struct VerifyOptions {
    name: String,
    endpoint: String,
    public: String,
    key_id: String,
    sig: String,
}

pub(crate) fn parse(args: &[String]) -> Result<Command, String> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    match args[0].as_str() {
        "run" => parse_run(&args[1..]),
        "verify-candidate" => parse_verify(&args[1..]),
        other => Err(format!("The mode {other} is not valid.\n{}", help())),
    }
}

pub(crate) fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!("{}", help());
            Ok(())
        }
        Command::Run(options) => run_node(options),
        Command::Verify(options) => verify(options),
    }
}

fn run_node(options: RunOptions) -> Result<(), String> {
    if let Some(gateway) = options.gateway {
        prepare_nat_gateway(gateway).map_err(|err| err.to_string())?;
    }
    let bundle_pem = fs::read_to_string(&options.bundle)
        .map_err(|err| format!("The file {} did not open. {err}", options.bundle.display()))?;
    orblx_coord::fetch_netmap_blocking(
        options.coord,
        &options.coord_name,
        &bundle_pem,
        &options.state,
    )
    .map_err(|err| err.to_string())?;
    let map_bytes = fs::read(options.state.join("netmap.json"))
        .map_err(|err| format!("The netmap file did not open. {err}"))?;
    let map = Netmap::from_slice(&map_bytes).map_err(|err| err.to_string())?;
    let peer = map
        .peers
        .iter()
        .find(|peer| peer.name == options.peer)
        .ok_or_else(|| format!("The peer {} is not in the netmap.", options.peer))?;
    let overlay = map
        .self_node
        .overlay_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| "The overlay address is not valid.".to_string())?;
    let peer_overlay = peer
        .overlay_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| "The peer overlay address is not valid.".to_string())?;
    let cert_pem = fs::read_to_string(options.state.join("node.crt.pem"))
        .map_err(|err| format!("The certificate file did not open. {err}"))?;
    let der = decode_certificate_pem(&cert_pem).map_err(|err| err.to_string())?;
    let svid = extract_spiffe_id(&der).map_err(|err| err.to_string())?;
    let expiry = leaf_not_after(&der).map_err(|err| err.to_string())?;
    let public_text = fs::read_to_string(options.state.join("netmap.pub"))
        .map_err(|err| format!("The netmap public key did not open. {err}"))?;
    let public = decode_hex_key(public_text.trim()).map_err(|err| err.to_string())?;
    let hello = hello_auth(&options.state, der, &peer.svid)?;
    let (_visibility, filter) =
        crate::up::load_grants(&options.state, &map.self_node.name, overlay)?;
    let renew = renewer(
        options.state.clone(),
        options.coord,
        &options.coord_name,
        &bundle_pem,
    );
    let state = options.state.clone();
    let coord = options.coord;
    let coord_name = options.coord_name.clone();
    let bundle = bundle_pem.clone();
    let publish = Box::new(move |endpoints: Vec<String>| {
        let view = publish_candidates_blocking(coord, &coord_name, &bundle, &state, &endpoints)
            .map_err(|err| err.to_string())?;
        Ok(view
            .endpoints
            .into_iter()
            .map(|item| SignedCandidate {
                name: item.name,
                endpoint: item.endpoint,
                sig: item.sig,
                key_id: item.key_id,
            })
            .collect())
    });
    let config = NatConfig {
        state_dir: options.state,
        name: map.self_node.name,
        overlay,
        svid: svid.as_uri().to_string(),
        svid_expiry: expiry,
        peer_name: peer.name.clone(),
        peer_overlay,
        peer_svid: peer.svid.clone(),
        stun: options.stun,
        stun_alt: options.stun_alt,
        relay_udp: options.relay,
        relay_tcp: options.relay,
        gateway: options.gateway,
        netmap_public: public,
        hello,
        publish,
        renew: Some(renew),
        filter,
    };
    run_nat_node(config).map_err(|err| err.to_string())
}

/// Renew the leaf SVID at the coordinator.
///
/// The coordinator call also stores the new state files.
/// The closure does not print the key.
fn renewer(state: PathBuf, coord: SocketAddr, coord_name: &str, bundle_pem: &str) -> RenewFn {
    let coord_name = coord_name.to_string();
    let bundle_pem = bundle_pem.to_string();
    Box::new(move || {
        let result = renew_svid_blocking(coord, &coord_name, &bundle_pem, &state)
            .map_err(|err| err.to_string())?;
        let cert_der =
            decode_certificate_pem(&result.certificate_pem).map_err(|err| err.to_string())?;
        let seed = ed25519_seed_from_private_pem(&result.private_key_pem)
            .map_err(|_| "The renewed key is not valid.".to_string())?;
        Ok(RenewedLeaf { cert_der, seed })
    })
}

/// Load the SVID material for the signed hello.
///
/// The function does not print the key.
fn hello_auth(
    state: &std::path::Path,
    cert_der: Vec<u8>,
    peer_svid: &str,
) -> Result<HelloAuth, String> {
    let key_pem = fs::read_to_string(state.join("node.key.pem"))
        .map_err(|err| format!("The node key file did not open. {err}"))?;
    let seed = ed25519_seed_from_private_pem(&key_pem)
        .map_err(|_| "The node key is not valid.".to_string())?;
    let bundle_pem = fs::read_to_string(state.join("trust-bundle.pem"))
        .map_err(|err| format!("The trust bundle file did not open. {err}"))?;
    let bundle = TrustBundle::from_pem(&bundle_pem).map_err(|err| err.to_string())?;
    Ok(HelloAuth::new(cert_der, &seed, bundle, peer_svid))
}

fn verify(options: VerifyOptions) -> Result<(), String> {
    let public = decode_hex_key(&options.public).map_err(|err| err.to_string())?;
    let signed = SignedCandidate {
        name: options.name,
        endpoint: options.endpoint,
        sig: options.sig,
        key_id: options.key_id,
    };
    verify_signed_candidate(&signed, &public).map_err(|err| err.to_string())?;
    println!("candidate ok");
    Ok(())
}

fn parse_run(args: &[String]) -> Result<Command, String> {
    let mut state = None;
    let mut coord = None;
    let mut coord_name = None;
    let mut bundle = None;
    let mut stun = None;
    let mut stun_alt = None;
    let mut relay = None;
    let mut peer = None;
    let mut gateway = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--state" => state = Some(PathBuf::from(value)),
            "--coord" => coord = Some(parse_socket(&value, 443)?),
            "--coord-name" => coord_name = Some(value),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--stun" => stun = Some(parse_socket(&value, 3478)?),
            "--stun-alt" => stun_alt = Some(parse_socket(&value, 3478)?),
            "--relay" => relay = Some(parse_socket(&value, 443)?),
            "--peer" => peer = Some(value),
            "--gateway" => {
                gateway = Some(
                    value
                        .parse::<Ipv4Addr>()
                        .map_err(|_| format!("The gateway {value} is not valid."))?,
                );
            }
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Run(RunOptions {
        state: state.ok_or_else(|| "The command needs --state.".to_string())?,
        coord: coord.ok_or_else(|| "The command needs --coord.".to_string())?,
        coord_name: coord_name.unwrap_or_else(|| "coord".to_string()),
        bundle: bundle.ok_or_else(|| "The command needs --bundle.".to_string())?,
        stun: stun.ok_or_else(|| "The command needs --stun.".to_string())?,
        stun_alt,
        relay: relay.ok_or_else(|| "The command needs --relay.".to_string())?,
        peer: peer.ok_or_else(|| "The command needs --peer.".to_string())?,
        gateway,
    }))
}

fn parse_verify(args: &[String]) -> Result<Command, String> {
    let mut name = None;
    let mut endpoint = None;
    let mut public = None;
    let mut key_id = None;
    let mut sig = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = take_value(args, &mut index)?;
        match flag {
            "--name" => name = Some(value),
            "--endpoint" => endpoint = Some(value),
            "--public" => public = Some(value),
            "--key-id" => key_id = Some(value),
            "--sig" => sig = Some(value),
            other => return Err(format!("The flag {other} is not valid.\n{}", help())),
        }
    }
    Ok(Command::Verify(VerifyOptions {
        name: name.ok_or_else(|| "The command needs --name.".to_string())?,
        endpoint: endpoint.ok_or_else(|| "The command needs --endpoint.".to_string())?,
        public: public.ok_or_else(|| "The command needs --public.".to_string())?,
        key_id: key_id.ok_or_else(|| "The command needs --key-id.".to_string())?,
        sig: sig.ok_or_else(|| "The command needs --sig.".to_string())?,
    }))
}

fn help() -> String {
    "\
orblx nat run --state DIR --coord ADDR --bundle FILE --stun ADDR --relay ADDR --peer NAME [--stun-alt ADDR] [--gateway IP] [--coord-name NAME]
orblx nat verify-candidate --name NAME --endpoint HOST:PORT --public HEX --key-id HEX --sig BASE64

The node gathers a reflexive address with STUN.
The coordinator signs that address with the netmap Ed25519 key.
The peer verifies the signature.
With --stun-alt, the node measures the NAT mapping kind and publishes two endpoints.
The peers punch UDP.
An endpoint-independent NAT and a symmetric NAT use bounded birthday probes.
Two symmetric NATs use the orblx Relay.
When the punch fails, the peers use the orblx Relay.
The hello carries the SVID. The peer checks it against the trust bundle.
A later direct path keeps the same overlay session.
orblx status prints the path kind for the peer.
The path kind is direct or relay.
The command does not log a private key or a signature.
"
    .to_string()
}
