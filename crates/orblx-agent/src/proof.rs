//! SVID proof for one grant use.
//!
//! This is the W19 SSH proof pattern.
//! The agent signs the target, the service, the port, a time stamp,
//! and the ticket fingerprint with its SVID key (Ed25519).
//! The blob carries the agent leaf, the signature, the ticket,
//! and the signed grant document.
//! The guard does not log the blob.

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use orblx_audit::DenyReason;
use orblx_identity::{
    allow_agent_jit, decode_certificate_pem, ed25519_seed_from_private_pem, extract_spiffe_id,
    leaf_ed25519_public_key, ticket_hash, verify_ticket, DenySet, IdentityError, Ipv4Destination,
    SpiffeId, TicketVerifier, TrustBundle, WorkloadKind,
};

use crate::grant::{verify_grant, AgentGrant, SignedAgentGrant};
use crate::hex::encode_hex;
use crate::AgentError;

const MAGIC: &[u8] = b"OBLXAGT1";
const USE_LABEL: &[u8] = b"orblx-agent-use-v1\n";
/// The largest clock difference between the proof stamp and the guard clock.
pub const PROOF_WINDOW_SECS: u64 = 60;
const MAX_LEAF: usize = 8 * 1024;
const MAX_TICKET: usize = 4 * 1024;
const MAX_GRANT: usize = 4 * 1024;
const TCP: u8 = 6;

/// The service that the guard protects.
#[derive(Debug, Clone, Copy)]
pub struct UseTarget<'a> {
    /// Target node SPIFFE ID.
    pub node: &'a SpiffeId,
    /// Target overlay address.
    pub addr: Ipv4Addr,
    /// Service name.
    pub service: &'a str,
    /// TCP port.
    pub port: u16,
}

/// The trust inputs of the guard.
#[derive(Debug, Clone, Copy)]
pub struct UseTrust<'a> {
    /// SVID trust bundle.
    pub bundle: &'a TrustBundle,
    /// Coordinator ticket key.
    pub verifier: &'a TicketVerifier,
    /// Coordinator netmap key.
    pub netmap_public: &'a [u8; 32],
    /// Current deny set.
    pub deny: &'a DenySet,
}

/// One admitted use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// Agent SPIFFE ID.
    pub agent: SpiffeId,
    /// The checked grant.
    pub grant: AgentGrant,
    /// Ticket fingerprint.
    pub ticket_hash: [u8; 16],
    /// Ticket nonce.
    pub nonce: [u8; 16],
    /// The proof stamp in Unix seconds.
    pub stamp: u64,
}

/// One refused use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The peer SPIFFE ID when the leaf parsed.
    pub peer: Option<SpiffeId>,
    /// Deny cause.
    pub reason: DenyReason,
    /// Ticket fingerprint. Zero when absent.
    pub ticket_hash: [u8; 16],
    /// Grant id when the grant document parsed.
    pub grant_id: Option<String>,
}

/// Build one proof line for a grant use.
///
/// `extra` binds the proof to request data. A TCP use passes an empty slice.
/// The result is base64. The caller must not write it to a log.
#[allow(clippy::too_many_arguments)]
pub fn seal_use(
    key_pem: &str,
    cert_pem: &str,
    ticket: &[u8],
    grant: &SignedAgentGrant,
    target: UseTarget<'_>,
    extra: &[u8],
    now: SystemTime,
) -> Result<String, AgentError> {
    let stamp = unix_secs(now)?;
    let seed = ed25519_seed_from_private_pem(key_pem).map_err(|_| AgentError::Key)?;
    let signing = SigningKey::from_bytes(&seed);
    let leaf = decode_certificate_pem(cert_pem).map_err(|_| AgentError::Key)?;
    let hash = ticket_hash(ticket);
    let message = use_message(target, stamp, &hash, extra);
    let signature = signing.sign(&message);
    let grant_bytes = serde_json::to_vec(grant).map_err(|_| AgentError::Grant)?;
    if leaf.len() > MAX_LEAF || ticket.len() > MAX_TICKET || grant_bytes.len() > MAX_GRANT {
        return Err(AgentError::Proof);
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&stamp.to_be_bytes());
    push_chunk(&mut out, &leaf);
    out.extend_from_slice(&signature.to_bytes());
    push_chunk(&mut out, ticket);
    push_chunk(&mut out, &grant_bytes);
    Ok(STANDARD.encode(out))
}

/// Check one proof line for `target`.
///
/// The grant end time is strict. The guard refuses a use at or after
/// `expires` without the 60 second certificate skew.
pub fn open_use(
    line: &str,
    target: UseTarget<'_>,
    trust: UseTrust<'_>,
    extra: &[u8],
    now: SystemTime,
) -> Result<Admitted, Refused> {
    let line = line.trim();
    if line.is_empty() {
        return Err(refuse(None, DenyReason::Missing, [0u8; 16], None));
    }
    let Ok(blob) = STANDARD.decode(line) else {
        return Err(refuse(None, DenyReason::Missing, [0u8; 16], None));
    };
    let Ok(parsed) = decode_blob(&blob) else {
        return Err(refuse(None, DenyReason::Missing, [0u8; 16], None));
    };
    let hash = ticket_hash(parsed.ticket);
    let grant: Option<SignedAgentGrant> = serde_json::from_slice(parsed.grant).ok();
    let grant_id = grant.as_ref().map(|signed| signed.grant.id.clone());
    let peer = extract_spiffe_id(parsed.leaf).ok();
    let fail = |reason: DenyReason| refuse(peer.clone(), reason, hash, grant_id.clone());
    let Ok(now_ms) = unix_millis(now) else {
        return Err(fail(DenyReason::Expired));
    };
    if (now_ms / 1000).abs_diff(parsed.stamp) > PROOF_WINDOW_SECS {
        return Err(fail(DenyReason::Expired));
    }
    let src = match trust.bundle.authenticate_leaf(parsed.leaf, now, trust.deny) {
        Ok(id) => id,
        Err(err) => return Err(fail(reason_from_identity(err))),
    };
    if src.kind() != WorkloadKind::Agent {
        return Err(fail(DenyReason::Destination));
    }
    let Ok(public) = leaf_ed25519_public_key(parsed.leaf) else {
        return Err(fail(DenyReason::Ticket));
    };
    let Ok(verify_key) = VerifyingKey::from_bytes(&public) else {
        return Err(fail(DenyReason::Ticket));
    };
    let Ok(raw) = <[u8; 64]>::try_from(parsed.signature) else {
        return Err(fail(DenyReason::Ticket));
    };
    let message = use_message(target, parsed.stamp, &hash, extra);
    if verify_key
        .verify_strict(&message, &Signature::from_bytes(&raw))
        .is_err()
    {
        return Err(fail(DenyReason::Ticket));
    }
    if parsed.ticket.is_empty() {
        return Err(fail(DenyReason::Missing));
    }
    let verified = match verify_ticket(trust.verifier, parsed.ticket, now, trust.deny) {
        Ok(verified) => verified,
        Err(err) => return Err(fail(reason_from_identity(err))),
    };
    if verified.subject != src
        || verified.issuer.kind() != WorkloadKind::Coord
        || !verified.flags.agent_jit()
    {
        return Err(fail(DenyReason::Ticket));
    }
    let not_before_ms = verified.not_before.saturating_mul(1000);
    let expires_ms = verified.expires.saturating_mul(1000);
    if now_ms >= expires_ms || now_ms < not_before_ms {
        return Err(fail(DenyReason::Expired));
    }
    let Some(signed) = grant else {
        return Err(fail(DenyReason::Missing));
    };
    if verify_grant(&signed, trust.netmap_public).is_err() {
        return Err(fail(DenyReason::Ticket));
    }
    let doc = signed.grant;
    if doc.ticket_hash != encode_hex(&hash)
        || doc.agent != src.as_uri()
        || doc.expires != verified.expires
        || doc.not_before != verified.not_before
    {
        return Err(fail(DenyReason::Ticket));
    }
    let dest = Ipv4Destination {
        addr: target.addr,
        proto: TCP,
        port: target.port,
    };
    if allow_agent_jit(
        verified.flags,
        &verified.dst_cidr,
        verified.proto,
        verified.dst_port,
        dest,
    )
    .is_err()
        || doc.node != target.node.as_uri()
        || doc.service != target.service
        || doc.port != target.port
        || doc.addr != target.addr.to_string()
    {
        return Err(fail(DenyReason::Destination));
    }
    Ok(Admitted {
        agent: src,
        grant: doc,
        ticket_hash: hash,
        nonce: verified.nonce,
        stamp: parsed.stamp,
    })
}

fn refuse(
    peer: Option<SpiffeId>,
    reason: DenyReason,
    ticket_hash: [u8; 16],
    grant_id: Option<String>,
) -> Refused {
    Refused {
        peer,
        reason,
        ticket_hash,
        grant_id,
    }
}

fn reason_from_identity(err: IdentityError) -> DenyReason {
    match err {
        IdentityError::Revoked => DenyReason::Revoked,
        IdentityError::Expired | IdentityError::NotYetValid | IdentityError::Time => {
            DenyReason::Expired
        }
        IdentityError::Denied => DenyReason::Destination,
        _ => DenyReason::Ticket,
    }
}

fn use_message(target: UseTarget<'_>, stamp: u64, hash: &[u8; 16], extra: &[u8]) -> Vec<u8> {
    let mut out = USE_LABEL.to_vec();
    push_chunk(&mut out, target.node.as_uri().as_bytes());
    out.extend_from_slice(&target.addr.octets());
    push_chunk(&mut out, target.service.as_bytes());
    out.extend_from_slice(&target.port.to_be_bytes());
    out.extend_from_slice(&stamp.to_be_bytes());
    out.extend_from_slice(hash);
    push_chunk(&mut out, extra);
    out
}

struct ParsedBlob<'a> {
    stamp: u64,
    leaf: &'a [u8],
    signature: &'a [u8],
    ticket: &'a [u8],
    grant: &'a [u8],
}

fn decode_blob(bytes: &[u8]) -> Result<ParsedBlob<'_>, ()> {
    if !bytes.starts_with(MAGIC) {
        return Err(());
    }
    let mut index = MAGIC.len();
    let stamp_bytes = read_fixed(bytes, &mut index, 8)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(stamp_bytes);
    let stamp = u64::from_be_bytes(raw);
    let leaf = read_chunk(bytes, &mut index, MAX_LEAF)?;
    let signature = read_fixed(bytes, &mut index, 64)?;
    let ticket = read_chunk(bytes, &mut index, MAX_TICKET)?;
    let grant = read_chunk(bytes, &mut index, MAX_GRANT)?;
    if index != bytes.len() {
        return Err(());
    }
    Ok(ParsedBlob {
        stamp,
        leaf,
        signature,
        ticket,
        grant,
    })
}

fn push_chunk(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_chunk<'a>(bytes: &'a [u8], index: &mut usize, max: usize) -> Result<&'a [u8], ()> {
    let len_bytes = read_fixed(bytes, index, 4)?;
    let mut raw = [0u8; 4];
    raw.copy_from_slice(len_bytes);
    let len = usize::try_from(u32::from_be_bytes(raw)).map_err(|_| ())?;
    if len > max {
        return Err(());
    }
    read_fixed(bytes, index, len)
}

fn read_fixed<'a>(bytes: &'a [u8], index: &mut usize, len: usize) -> Result<&'a [u8], ()> {
    let end = index.checked_add(len).ok_or(())?;
    if end > bytes.len() {
        return Err(());
    }
    let slice = &bytes[*index..end];
    *index = end;
    Ok(slice)
}

fn unix_secs(now: SystemTime) -> Result<u64, AgentError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AgentError::Time)
}

/// Return Unix milliseconds.
pub fn unix_millis(now: SystemTime) -> Result<u64, AgentError> {
    let millis = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentError::Time)?
        .as_millis();
    u64::try_from(millis).map_err(|_| AgentError::Time)
}
