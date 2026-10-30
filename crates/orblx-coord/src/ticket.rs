//! Capability tickets for enrolled nodes.
//!
//! The coordinator stores the ticket seed and the MAC key.
//! The enroll response carries the ticket.
//! The caller must not log the MAC key or the ticket seed.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_crypto::{mac_input, ticket_mac};
use orblx_identity::{
    sign_agent_jit_ticket, sign_ticket, Ipv4Destination, SignedTicket, SpiffeId, TicketClaims,
    TicketFlags, TicketSigner,
};

use crate::error::CoordError;
use crate::files::{read_text, write_bytes, write_text};
use crate::netmap::{decode_hex_32, encode_hex};

const SEED_FILE: &str = "ticket.seed";
const MAC_FILE: &str = "ticket.mac";
const WINDOW_FILE: &str = "ticket.window";
const KEY_LIFE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Ticket files for one node.
///
/// Debug output elides the MAC key.
pub struct IssuedTicket {
    pub bytes: Vec<u8>,
    pub mac: [u8; 32],
    pub verifier_pem: String,
    pub mac_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub svid_ca_pub: [u8; 32],
}

impl std::fmt::Debug for IssuedTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedTicket")
            .field("mac_key", &"[elided]")
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

pub(crate) struct TicketMaterial {
    signer: TicketSigner,
    mac_key: [u8; 32],
    not_before: u64,
    not_after: u64,
}

pub(crate) fn load_ticket_material(
    dir: &Path,
    ca_public: &[u8; 32],
    now: SystemTime,
) -> Result<TicketMaterial, CoordError> {
    let seed_path = dir.join(SEED_FILE);
    let mac_path = dir.join(MAC_FILE);
    let window_path = dir.join(WINDOW_FILE);
    if seed_path.exists() && mac_path.exists() && window_path.exists() {
        let seed = read_seed(&seed_path)?;
        let mac_key = read_seed(&mac_path)?;
        let (not_before, not_after) = read_window(&window_path)?;
        let signer = TicketSigner::from_seed(&seed);
        if signer.public_key() == *ca_public {
            return Err(CoordError::State);
        }
        return Ok(TicketMaterial {
            signer,
            mac_key,
            not_before,
            not_after,
        });
    }
    let now_unix = unix_now(now)?;
    let not_before = now_unix.saturating_sub(120);
    let not_after = now_unix.saturating_add(KEY_LIFE.as_secs());
    for _ in 0..4 {
        let signer = TicketSigner::generate();
        if signer.public_key() == *ca_public {
            continue;
        }
        let mut mac_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mac_key);
        write_bytes(&seed_path, &signer.seed(), 0o600)?;
        write_bytes(&mac_path, &mac_key, 0o600)?;
        write_text(&window_path, &format!("{not_before}\n{not_after}\n"), 0o644)?;
        return Ok(TicketMaterial {
            signer,
            mac_key,
            not_before,
            not_after,
        });
    }
    Err(CoordError::State)
}

pub fn issue_node_ticket(
    dir: &Path,
    ca_public: &[u8; 32],
    coord_name: &str,
    node_name: &str,
    now: SystemTime,
    ttl: Duration,
) -> Result<IssuedTicket, CoordError> {
    let material = load_ticket_material(dir, ca_public, now)?;
    let now_unix = unix_now(now)?;
    let ttl_secs = ttl.as_secs();
    if ttl_secs == 0 {
        return Err(CoordError::Time);
    }
    let claims = TicketClaims {
        issuer: SpiffeId::coord(coord_name)?,
        subject: SpiffeId::node(node_name)?,
        not_before: now_unix,
        expires: now_unix.saturating_add(ttl_secs),
        dst_cidr: "0.0.0.0/0".to_string(),
        proto: 0,
        dst_port: 0,
        flags: TicketFlags::none(),
    };
    let signed = sign_ticket(&material.signer, &claims)?;
    let mac =
        ticket_mac(&material.mac_key, mac_input(&signed.bytes)).map_err(|_| CoordError::State)?;
    Ok(IssuedTicket {
        bytes: signed.bytes,
        mac,
        verifier_pem: material.signer.public_key_pem(),
        mac_key: material.mac_key,
        not_before: material.not_before,
        not_after: material.not_after,
        svid_ca_pub: *ca_public,
    })
}

/// Sign one agent JIT ticket for one host and one port.
///
/// The ticket uses the node ticket key. The caller must not log the ticket.
pub(crate) fn issue_agent_ticket(
    dir: &Path,
    ca_public: &[u8; 32],
    coord_name: &str,
    agent: &SpiffeId,
    now: SystemTime,
    ttl: Duration,
    dest: Ipv4Destination,
) -> Result<SignedTicket, CoordError> {
    let material = load_ticket_material(dir, ca_public, now)?;
    let issuer = SpiffeId::coord(coord_name)?;
    Ok(sign_agent_jit_ticket(
        &material.signer,
        &issuer,
        agent,
        now,
        ttl,
        dest,
    )?)
}

fn read_seed(path: &Path) -> Result<[u8; 32], CoordError> {
    let bytes = std::fs::read(path).map_err(CoordError::io)?;
    bytes.try_into().map_err(|_| CoordError::State)
}

fn read_window(path: &Path) -> Result<(u64, u64), CoordError> {
    let text = read_text(path)?;
    let mut lines = text.lines();
    let not_before = lines
        .next()
        .ok_or(CoordError::State)?
        .trim()
        .parse::<u64>()
        .map_err(|_| CoordError::State)?;
    let not_after = lines
        .next()
        .ok_or(CoordError::State)?
        .trim()
        .parse::<u64>()
        .map_err(|_| CoordError::State)?;
    Ok((not_before, not_after))
}

fn unix_now(now: SystemTime) -> Result<u64, CoordError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoordError::Time)
}

pub fn ticket_response_fields(ticket: &IssuedTicket) -> TicketWire {
    TicketWire {
        ticket_hex: encode_hex(&ticket.bytes),
        ticket_mac_hex: encode_hex(&ticket.mac),
        ticket_verifier_pem: ticket.verifier_pem.clone(),
        ticket_mac_key_hex: encode_hex(&ticket.mac_key),
        ticket_not_before: ticket.not_before,
        ticket_not_after: ticket.not_after,
        svid_ca_pub_hex: encode_hex(&ticket.svid_ca_pub),
    }
}

pub struct TicketWire {
    pub ticket_hex: String,
    pub ticket_mac_hex: String,
    pub ticket_verifier_pem: String,
    pub ticket_mac_key_hex: String,
    pub ticket_not_before: u64,
    pub ticket_not_after: u64,
    pub svid_ca_pub_hex: String,
}

pub fn decode_ticket_wire(
    ticket_hex: &str,
    mac_hex: &str,
    verifier_pem: &str,
    mac_key_hex: &str,
    not_before: u64,
    not_after: u64,
    ca_hex: &str,
) -> Result<IssuedTicket, CoordError> {
    Ok(IssuedTicket {
        bytes: decode_hex(ticket_hex)?,
        mac: decode_hex_32(mac_hex)?,
        verifier_pem: verifier_pem.to_string(),
        mac_key: decode_hex_32(mac_key_hex)?,
        not_before,
        not_after,
        svid_ca_pub: decode_hex_32(ca_hex)?,
    })
}

pub(crate) fn decode_hex(text: &str) -> Result<Vec<u8>, CoordError> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(CoordError::Protocol("The ticket is not valid.".to_string()));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let pair = text
            .get(index..index + 2)
            .ok_or_else(|| CoordError::Protocol("The ticket is not valid.".to_string()))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| CoordError::Protocol("The ticket is not valid.".to_string()))?;
        out.push(byte);
        index += 2;
    }
    Ok(out)
}
