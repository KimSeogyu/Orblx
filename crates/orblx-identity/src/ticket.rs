use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::clock::{in_window, unix_time, whole_seconds, MAX_AGENT_TTL};
use crate::codec::{ed25519_raw_from_spki, ed25519_spki, encode_hex, pem_blocks, pem_encode};
use crate::deny::DenySet;
use crate::error::IdentityError;
use crate::spiffe::{SpiffeId, WorkloadKind};

const TICKET_VERSION: u8 = 1;
const NONCE_LEN: usize = 16;
const SIGNATURE_LEN: usize = 64;

/// Bit 0. The ticket names one IPv4 host and one port.
pub const FLAG_AGENT_JIT: u8 = 0b0000_0001;

/// Bit 1. The datapath may use the ticket one time.
pub const FLAG_ONE_SHOT: u8 = 0b0000_0010;

const KNOWN_FLAGS: u8 = FLAG_AGENT_JIT | FLAG_ONE_SHOT;

/// The flag byte of a capability ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketFlags {
    bits: u8,
}

impl TicketFlags {
    pub fn none() -> Self {
        Self { bits: 0 }
    }

    pub fn new(agent_jit: bool, one_shot: bool) -> Self {
        let mut bits = 0;
        if agent_jit {
            bits |= FLAG_AGENT_JIT;
        }
        if one_shot {
            bits |= FLAG_ONE_SHOT;
        }
        Self { bits }
    }

    pub fn from_bits(bits: u8) -> Result<Self, IdentityError> {
        if bits & !KNOWN_FLAGS != 0 {
            return Err(IdentityError::Ticket);
        }
        Ok(Self { bits })
    }

    pub fn bits(self) -> u8 {
        self.bits
    }

    pub fn agent_jit(self) -> bool {
        self.bits & FLAG_AGENT_JIT != 0
    }

    pub fn one_shot(self) -> bool {
        self.bits & FLAG_ONE_SHOT != 0
    }
}

/// The fields that the ticket signer covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketClaims {
    pub issuer: SpiffeId,
    pub subject: SpiffeId,
    pub not_before: u64,
    pub expires: u64,
    pub dst_cidr: String,
    pub proto: u8,
    pub dst_port: u16,
    pub flags: TicketFlags,
}

/// An Ed25519 key that signs capability tickets.
///
/// This key is separate from the SVID CA key.
pub struct TicketSigner {
    signing: SigningKey,
}

impl fmt::Debug for TicketSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TicketSigner")
            .field("public_key", &encode_hex(&self.public_key()))
            .finish()
    }
}

impl TicketSigner {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_key_pem(&self) -> String {
        pem_encode("PUBLIC KEY", &ed25519_spki(&self.public_key()))
    }

    pub fn verifier(&self) -> TicketVerifier {
        TicketVerifier {
            key: self.signing.verifying_key(),
        }
    }
}

/// The public half of a ticket key.
#[derive(Debug, Clone)]
pub struct TicketVerifier {
    key: VerifyingKey,
}

impl TicketVerifier {
    pub fn from_public_pem(pem: &str) -> Result<Self, IdentityError> {
        let blocks = pem_blocks(pem, "PUBLIC KEY").map_err(|_| IdentityError::Ticket)?;
        if blocks.len() != 1 {
            return Err(IdentityError::Ticket);
        }
        let raw = ed25519_raw_from_spki(&blocks[0]).map_err(|_| IdentityError::Ticket)?;
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| IdentityError::Ticket)?;
        Ok(Self { key })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// A signed ticket and the first 16 bytes of its SHA-256 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTicket {
    pub bytes: Vec<u8>,
    pub hash: [u8; 16],
    pub nonce: [u8; 16],
}

impl SignedTicket {
    pub fn hash_hex(&self) -> String {
        encode_hex(&self.hash)
    }
}

/// A ticket that passed the signature, time, and deny checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTicket {
    pub issuer: SpiffeId,
    pub subject: SpiffeId,
    pub not_before: u64,
    pub expires: u64,
    pub dst_cidr: String,
    pub proto: u8,
    pub dst_port: u16,
    pub flags: TicketFlags,
    pub nonce: [u8; 16],
    pub hash: [u8; 16],
}

/// One IPv4 host, protocol, and destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Destination {
    /// Destination address.
    pub addr: Ipv4Addr,
    /// IP protocol number.
    pub proto: u8,
    /// Destination port.
    pub port: u16,
}

/// Sign one agent JIT ticket.
///
/// The subject must be an agent SPIFFE ID.
/// The ticket life is at most 5 minutes.
/// The ticket names one IPv4 host and one port.
/// The ticket is separate from the agent SVID.
pub fn sign_agent_jit_ticket(
    signer: &TicketSigner,
    issuer: &SpiffeId,
    agent: &SpiffeId,
    now: SystemTime,
    ttl: Duration,
    dest: Ipv4Destination,
) -> Result<SignedTicket, IdentityError> {
    if agent.kind() != WorkloadKind::Agent {
        return Err(IdentityError::SpiffeId);
    }
    let ttl_secs = whole_seconds(ttl)?;
    if ttl > MAX_AGENT_TTL {
        return Err(IdentityError::Time);
    }
    if dest.port == 0 {
        return Err(IdentityError::Ticket);
    }
    let now_unix = unix_time(now)?;
    let expires = now_unix.checked_add(ttl_secs).ok_or(IdentityError::Time)?;
    let claims = TicketClaims {
        issuer: issuer.clone(),
        subject: agent.clone(),
        not_before: now_unix,
        expires,
        dst_cidr: format!("{}/32", dest.addr),
        proto: dest.proto,
        dst_port: dest.port,
        flags: TicketFlags::new(true, false),
    };
    sign_ticket(signer, &claims)
}

/// Allow one destination for an agent JIT ticket.
///
/// The function denies a ticket that does not set `FLAG_AGENT_JIT`.
/// The function denies every destination except the one named host, protocol, and port.
pub fn allow_agent_jit(
    flags: TicketFlags,
    dst_cidr: &str,
    proto: u8,
    dst_port: u16,
    dest: Ipv4Destination,
) -> Result<(), IdentityError> {
    if !flags.agent_jit() || dst_port == 0 || dest.port == 0 {
        return Err(IdentityError::Denied);
    }
    let host = host_from_prefix_32(dst_cidr)?;
    if dest.addr != host || dest.proto != proto || dest.port != dst_port {
        return Err(IdentityError::Denied);
    }
    Ok(())
}

fn host_from_prefix_32(cidr: &str) -> Result<Ipv4Addr, IdentityError> {
    let (addr, prefix) = cidr.split_once('/').ok_or(IdentityError::Denied)?;
    if prefix != "32" {
        return Err(IdentityError::Denied);
    }
    let labels: Vec<&str> = addr.split('.').collect();
    if labels.len() != 4 {
        return Err(IdentityError::Denied);
    }
    let mut octets = [0u8; 4];
    for (index, label) in labels.iter().enumerate() {
        octets[index] = ipv4_octet(label).map_err(|_| IdentityError::Denied)?;
    }
    Ok(Ipv4Addr::from(octets))
}

/// Return `SHA-256(ticket_bytes)[0..16]`.
pub fn ticket_hash(ticket_bytes: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(ticket_bytes);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// Sign one version-1 capability ticket.
pub fn sign_ticket(
    signer: &TicketSigner,
    claims: &TicketClaims,
) -> Result<SignedTicket, IdentityError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let body = encode_body(claims, &nonce)?;
    let signature = signer.signing.sign(&body);
    let mut bytes = body;
    bytes.extend_from_slice(&signature.to_bytes());
    let hash = ticket_hash(&bytes);
    Ok(SignedTicket { bytes, hash, nonce })
}

/// Check the signature, the time window, and the deny list.
pub fn verify_ticket(
    verifier: &TicketVerifier,
    ticket_bytes: &[u8],
    now: SystemTime,
    deny: &DenySet,
) -> Result<VerifiedTicket, IdentityError> {
    if ticket_bytes.len() < SIGNATURE_LEN + 1 {
        return Err(IdentityError::Ticket);
    }
    let split = ticket_bytes.len() - SIGNATURE_LEN;
    let (body, signature_bytes) = ticket_bytes.split_at(split);
    let signature_bytes =
        <[u8; SIGNATURE_LEN]>::try_from(signature_bytes).map_err(|_| IdentityError::Ticket)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifier
        .key
        .verify_strict(body, &signature)
        .map_err(|_| IdentityError::Signature)?;
    let parsed = decode_body(body)?;
    let now_unix = unix_time(now)?;
    in_window(now_unix, parsed.not_before, parsed.expires)?;
    deny.reject_nonce(&parsed.nonce)?;
    Ok(VerifiedTicket {
        issuer: parsed.issuer,
        subject: parsed.subject,
        not_before: parsed.not_before,
        expires: parsed.expires,
        dst_cidr: parsed.dst_cidr,
        proto: parsed.proto,
        dst_port: parsed.dst_port,
        flags: parsed.flags,
        nonce: parsed.nonce,
        hash: ticket_hash(ticket_bytes),
    })
}

struct ParsedBody {
    issuer: SpiffeId,
    subject: SpiffeId,
    not_before: u64,
    expires: u64,
    dst_cidr: String,
    proto: u8,
    dst_port: u16,
    flags: TicketFlags,
    nonce: [u8; 16],
}

fn encode_body(claims: &TicketClaims, nonce: &[u8; 16]) -> Result<Vec<u8>, IdentityError> {
    if claims.expires < claims.not_before {
        return Err(IdentityError::Ticket);
    }
    validate_destination(&claims.dst_cidr, claims.dst_port, claims.flags)?;
    let mut out = Vec::new();
    out.push(TICKET_VERSION);
    push_counted(&mut out, claims.issuer.as_uri().as_bytes())?;
    push_counted(&mut out, claims.subject.as_uri().as_bytes())?;
    out.extend_from_slice(&claims.not_before.to_be_bytes());
    out.extend_from_slice(&claims.expires.to_be_bytes());
    push_counted(&mut out, claims.dst_cidr.as_bytes())?;
    out.push(claims.proto);
    out.extend_from_slice(&claims.dst_port.to_be_bytes());
    out.push(claims.flags.bits());
    out.extend_from_slice(nonce);
    Ok(out)
}

fn decode_body(body: &[u8]) -> Result<ParsedBody, IdentityError> {
    let mut cursor = Cursor {
        input: body,
        index: 0,
    };
    let version = cursor.u8()?;
    if version != TICKET_VERSION {
        return Err(IdentityError::Ticket);
    }
    let issuer = SpiffeId::parse(cursor.str()?)?;
    let subject = SpiffeId::parse(cursor.str()?)?;
    let not_before = cursor.u64()?;
    let expires = cursor.u64()?;
    let dst_cidr = cursor.str()?.to_string();
    let proto = cursor.u8()?;
    let dst_port = cursor.u16()?;
    let flags = TicketFlags::from_bits(cursor.u8()?)?;
    let nonce_bytes = cursor.take(NONCE_LEN)?;
    let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes).map_err(|_| IdentityError::Ticket)?;
    if cursor.index != body.len() {
        return Err(IdentityError::Ticket);
    }
    if expires < not_before {
        return Err(IdentityError::Ticket);
    }
    validate_destination(&dst_cidr, dst_port, flags)?;
    Ok(ParsedBody {
        issuer,
        subject,
        not_before,
        expires,
        dst_cidr,
        proto,
        dst_port,
        flags,
        nonce,
    })
}

fn push_counted(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), IdentityError> {
    let len = u16::try_from(bytes.len()).map_err(|_| IdentityError::Encoding)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_destination(cidr: &str, port: u16, flags: TicketFlags) -> Result<(), IdentityError> {
    canonical_ipv4_cidr(cidr)?;
    if flags.agent_jit() && (!cidr.ends_with("/32") || port == 0) {
        return Err(IdentityError::Ticket);
    }
    Ok(())
}

fn canonical_ipv4_cidr(text: &str) -> Result<(), IdentityError> {
    let (addr, prefix_text) = text.split_once('/').ok_or(IdentityError::Ticket)?;
    if prefix_text.is_empty()
        || (prefix_text.len() > 1 && prefix_text.starts_with('0'))
        || !prefix_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(IdentityError::Ticket);
    }
    let prefix: u32 = prefix_text.parse().map_err(|_| IdentityError::Ticket)?;
    if prefix > 32 {
        return Err(IdentityError::Ticket);
    }
    let labels: Vec<&str> = addr.split('.').collect();
    if labels.len() != 4 {
        return Err(IdentityError::Ticket);
    }
    let mut octets = [0u8; 4];
    for (index, label) in labels.iter().enumerate() {
        octets[index] = ipv4_octet(label)?;
    }
    let host = u32::from(Ipv4Addr::from(octets));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if host & !mask != 0 {
        return Err(IdentityError::Ticket);
    }
    Ok(())
}

fn ipv4_octet(label: &str) -> Result<u8, IdentityError> {
    if label.is_empty()
        || label.len() > 3
        || (label.len() > 1 && label.starts_with('0'))
        || !label.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(IdentityError::Ticket);
    }
    let value: u16 = label.parse().map_err(|_| IdentityError::Ticket)?;
    u8::try_from(value).map_err(|_| IdentityError::Ticket)
}

struct Cursor<'a> {
    input: &'a [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, IdentityError> {
        let byte = *self.input.get(self.index).ok_or(IdentityError::Ticket)?;
        self.index += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, IdentityError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, IdentityError> {
        let bytes = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(raw))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], IdentityError> {
        let end = self.index.checked_add(len).ok_or(IdentityError::Ticket)?;
        if end > self.input.len() {
            return Err(IdentityError::Ticket);
        }
        let slice = &self.input[self.index..end];
        self.index = end;
        Ok(slice)
    }

    fn str(&mut self) -> Result<&'a str, IdentityError> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes).map_err(|_| IdentityError::Ticket)
    }
}
