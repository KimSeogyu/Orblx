//! SVID proof for one SSH login.
//!
//! The proof is a signature over the host key, the login name, and the destination.
//! The server does not log the proof.

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use orblx_audit::DenyReason;
use orblx_identity::{
    allow_agent_jit, ed25519_public_key_from_certificate_pem, ed25519_seed_from_private_pem,
    ticket_hash, verify_ticket, DenySet, IdentityError, Ipv4Destination, Policy, SpiffeId,
    TicketVerifier, TrustBundle, WorkloadKind,
};

const MAGIC: &[u8] = b"OBLXSSH1";
const PROOF_WINDOW_SECS: u64 = 60;
const MAX_LEAF: usize = 8 * 1024;
const MAX_TICKET: usize = 4 * 1024;
const MAX_COMMAND: usize = 200;

/// TCP port of the overlay SSH server.
pub const SSH_PORT: u16 = 22;

/// One accepted SSH login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedLogin {
    /// Client SPIFFE ID.
    pub src: SpiffeId,
    /// Check period in seconds.
    pub check_period: u64,
    /// Ticket fingerprint.
    ///
    /// A human login uses 16 zero bytes.
    pub ticket_hash: [u8; 16],
    /// Nonce to record when the ticket is one-shot.
    pub spend_nonce: Option<[u8; 16]>,
}

/// One refused SSH login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedLogin {
    /// Peer SPIFFE ID recorded in the audit chain.
    pub peer: SpiffeId,
    /// Deny cause.
    pub reason: DenyReason,
    /// Ticket fingerprint.
    pub ticket_hash: [u8; 16],
}

/// Return the listen address for one overlay host.
///
/// The address is `overlay:22`.
/// The unspecified address is rejected.
pub fn overlay_listen_addr(overlay: Ipv4Addr) -> Result<std::net::SocketAddr, String> {
    if overlay.is_unspecified() || overlay.is_broadcast() {
        return Err("The SSH server listens on the overlay address.".to_string());
    }
    Ok(std::net::SocketAddr::from((overlay, SSH_PORT)))
}

/// Return true when the command text can run.
#[must_use]
pub fn command_ok(command: &str) -> bool {
    let bytes = command.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_COMMAND
        && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
}

/// Build the password field for one SVID login.
///
/// The result is public base64 of a signature.
/// The caller must not write it to a log.
pub fn seal_login(
    key_pem: &str,
    leaf_der: &[u8],
    host_key: &[u8; 32],
    user: &str,
    dst: &SpiffeId,
    now: SystemTime,
    ticket: Option<&[u8]>,
) -> Result<String, String> {
    let stamp = unix_secs(now).map_err(|_| "The clock is not valid.".to_string())?;
    let seed = ed25519_seed_from_private_pem(key_pem)
        .map_err(|_| "The SVID key is not valid.".to_string())?;
    let signing = SigningKey::from_bytes(&seed);
    let ticket_bytes = ticket.unwrap_or(&[]);
    let fingerprint = fingerprint(ticket_bytes);
    let message = auth_message(host_key, user, dst.as_uri(), stamp, &fingerprint);
    let signature = signing.sign(&message);
    let blob = encode_blob(stamp, leaf_der, &signature.to_bytes(), ticket_bytes)?;
    Ok(STANDARD.encode(blob))
}

/// Check one SSH login proof.
#[allow(clippy::too_many_arguments)]
pub fn open_login(
    user: &str,
    password: &str,
    dst: &SpiffeId,
    overlay: Ipv4Addr,
    host_key: &[u8; 32],
    now: SystemTime,
    bundle: &TrustBundle,
    policy: &Policy,
    deny: &DenySet,
    verifier: Option<&TicketVerifier>,
    spent: &std::collections::BTreeSet<[u8; 16]>,
) -> Result<AdmittedLogin, RefusedLogin> {
    let fallback = dst.clone();
    let blob = match STANDARD.decode(password.trim()) {
        Ok(bytes) => bytes,
        Err(_) => return Err(refuse(fallback, DenyReason::Ticket, [0u8; 16])),
    };
    let parsed = match decode_blob(&blob) {
        Ok(parsed) => parsed,
        Err(_) => return Err(refuse(fallback, DenyReason::Ticket, [0u8; 16])),
    };
    let stamp_now = match unix_secs(now) {
        Ok(value) => value,
        Err(_) => {
            return Err(refuse(
                fallback,
                DenyReason::Expired,
                fingerprint(parsed.ticket),
            ))
        }
    };
    if stamp_now.abs_diff(parsed.stamp) > PROOF_WINDOW_SECS {
        return Err(refuse(
            fallback,
            DenyReason::Expired,
            fingerprint(parsed.ticket),
        ));
    }
    let src = match bundle.authenticate_leaf(parsed.leaf, now, deny) {
        Ok(id) => id,
        Err(err) => {
            let peer = orblx_identity::extract_spiffe_id(parsed.leaf).unwrap_or(fallback);
            return Err(refuse(
                peer,
                reason_from_identity(err),
                fingerprint(parsed.ticket),
            ));
        }
    };
    let public = match ed25519_public_key_from_certificate_pem_der(parsed.leaf) {
        Ok(key) => key,
        Err(_) => return Err(refuse(src, DenyReason::Ticket, fingerprint(parsed.ticket))),
    };
    let fingerprint = fingerprint(parsed.ticket);
    let message = auth_message(host_key, user, dst.as_uri(), parsed.stamp, &fingerprint);
    let verify_key = match VerifyingKey::from_bytes(&public) {
        Ok(key) => key,
        Err(_) => return Err(refuse(src, DenyReason::Ticket, fingerprint)),
    };
    let signature = match signature_bytes(parsed.signature) {
        Ok(signature) => signature,
        Err(_) => return Err(refuse(src, DenyReason::Ticket, fingerprint)),
    };
    if verify_key.verify_strict(&message, &signature).is_err() {
        return Err(refuse(src, DenyReason::Ticket, fingerprint));
    }
    let spend_nonce = match src.kind() {
        WorkloadKind::Agent => Some(agent_ticket(
            &src,
            overlay,
            now,
            parsed.ticket,
            deny,
            verifier,
            spent,
        )?),
        WorkloadKind::User | WorkloadKind::Node => {
            if !parsed.ticket.is_empty() {
                return Err(refuse(src, DenyReason::Ticket, fingerprint));
            }
            None
        }
        WorkloadKind::Coord => return Err(refuse(src, DenyReason::Destination, fingerprint)),
    };
    let Some(period) = policy.ssh_check_period(&src, dst, user) else {
        return Err(refuse(src, DenyReason::Destination, fingerprint));
    };
    Ok(AdmittedLogin {
        src,
        check_period: period,
        ticket_hash: fingerprint,
        spend_nonce,
    })
}

fn agent_ticket(
    src: &SpiffeId,
    overlay: Ipv4Addr,
    now: SystemTime,
    ticket: &[u8],
    deny: &DenySet,
    verifier: Option<&TicketVerifier>,
    spent: &std::collections::BTreeSet<[u8; 16]>,
) -> Result<[u8; 16], RefusedLogin> {
    let fingerprint = fingerprint(ticket);
    if ticket.is_empty() {
        return Err(refuse(src.clone(), DenyReason::Missing, fingerprint));
    }
    let Some(verifier) = verifier else {
        return Err(refuse(src.clone(), DenyReason::Ticket, fingerprint));
    };
    let verified = match verify_ticket(verifier, ticket, now, deny) {
        Ok(verified) => verified,
        Err(err) => return Err(refuse(src.clone(), reason_from_identity(err), fingerprint)),
    };
    if verified.subject != *src || !verified.flags.agent_jit() || !verified.flags.one_shot() {
        return Err(refuse(src.clone(), DenyReason::Ticket, fingerprint));
    }
    let dest = Ipv4Destination {
        addr: overlay,
        proto: 6,
        port: SSH_PORT,
    };
    if let Err(err) = allow_agent_jit(
        verified.flags,
        &verified.dst_cidr,
        verified.proto,
        verified.dst_port,
        dest,
    ) {
        return Err(refuse(src.clone(), reason_from_identity(err), fingerprint));
    }
    if spent.contains(&verified.nonce) {
        return Err(refuse(src.clone(), DenyReason::Ticket, fingerprint));
    }
    Ok(verified.nonce)
}

fn refuse(peer: SpiffeId, reason: DenyReason, ticket_hash: [u8; 16]) -> RefusedLogin {
    RefusedLogin {
        peer,
        reason,
        ticket_hash,
    }
}

fn reason_from_identity(err: IdentityError) -> DenyReason {
    match err {
        IdentityError::Revoked => DenyReason::Revoked,
        IdentityError::Expired | IdentityError::NotYetValid | IdentityError::Time => {
            DenyReason::Expired
        }
        IdentityError::Denied => DenyReason::Destination,
        IdentityError::Audience
        | IdentityError::Certificate
        | IdentityError::Config
        | IdentityError::DenyDocument
        | IdentityError::Encoding
        | IdentityError::File
        | IdentityError::Profile
        | IdentityError::Signature
        | IdentityError::SpiffeId
        | IdentityError::Ticket
        | IdentityError::Token => DenyReason::Ticket,
    }
}

fn ed25519_public_key_from_certificate_pem_der(der: &[u8]) -> Result<[u8; 32], IdentityError> {
    // The PEM helper parses one certificate. The DER path uses the same check
    // through a temporary PEM so the public key stays inside the identity crate.
    let pem = pem_certificate(der);
    ed25519_public_key_from_certificate_pem(&pem)
}

fn pem_certificate(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    text
}

struct ParsedBlob<'a> {
    stamp: u64,
    leaf: &'a [u8],
    signature: &'a [u8],
    ticket: &'a [u8],
}

fn encode_blob(
    stamp: u64,
    leaf: &[u8],
    signature: &[u8; 64],
    ticket: &[u8],
) -> Result<Vec<u8>, String> {
    if leaf.len() > MAX_LEAF || ticket.len() > MAX_TICKET {
        return Err("The SSH proof is too large.".to_string());
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&stamp.to_be_bytes());
    push_chunk(&mut out, leaf);
    out.extend_from_slice(signature);
    push_chunk(&mut out, ticket);
    Ok(out)
}

fn decode_blob(bytes: &[u8]) -> Result<ParsedBlob<'_>, ()> {
    if bytes.len() < MAGIC.len() + 8 + 4 + 64 + 4 || !bytes.starts_with(MAGIC) {
        return Err(());
    }
    let mut index = MAGIC.len();
    let stamp = read_u64(bytes, &mut index)?;
    let leaf = read_chunk(bytes, &mut index, MAX_LEAF)?;
    let signature = read_fixed(bytes, &mut index, 64)?;
    let ticket = read_chunk(bytes, &mut index, MAX_TICKET)?;
    if index != bytes.len() {
        return Err(());
    }
    Ok(ParsedBlob {
        stamp,
        leaf,
        signature,
        ticket,
    })
}

fn auth_message(
    host_key: &[u8; 32],
    user: &str,
    dst: &str,
    stamp: u64,
    ticket_hash: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"orblx-ssh-auth-v1\n");
    out.extend_from_slice(host_key);
    push_chunk(&mut out, user.as_bytes());
    push_chunk(&mut out, dst.as_bytes());
    out.extend_from_slice(&stamp.to_be_bytes());
    out.extend_from_slice(ticket_hash);
    out
}

fn fingerprint(ticket: &[u8]) -> [u8; 16] {
    if ticket.is_empty() {
        [0u8; 16]
    } else {
        ticket_hash(ticket)
    }
}

fn signature_bytes(bytes: &[u8]) -> Result<Signature, ()> {
    let raw: [u8; 64] = bytes.try_into().map_err(|_| ())?;
    Ok(Signature::from_bytes(&raw))
}

fn push_chunk(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_u64(bytes: &[u8], index: &mut usize) -> Result<u64, ()> {
    let raw = read_fixed(bytes, index, 8)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(raw);
    Ok(u64::from_be_bytes(buf))
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

fn unix_secs(now: SystemTime) -> Result<u64, ()> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use orblx_audit::DenyReason;
    use orblx_identity::{
        sign_ticket, DenySet, MiniCa, Policy, SpiffeId, TicketClaims, TicketFlags, TicketSigner,
        MAX_AGENT_TTL, MAX_USER_TTL,
    };

    use super::{command_ok, open_login, overlay_listen_addr, seal_login, SSH_PORT};

    struct Lab {
        bundle_pem: String,
        verifier_pem: String,
        node_key: [u8; 32],
        alice_cert: Vec<u8>,
        alice_key: String,
        alice: SpiffeId,
        mallory_cert: Vec<u8>,
        mallory_key: String,
        agent_cert: Vec<u8>,
        agent_key: String,
        agent: SpiffeId,
        ticket: Vec<u8>,
        box_id: SpiffeId,
        policy: Policy,
        now: SystemTime,
    }

    fn lab() -> Lab {
        let now = SystemTime::now();
        let ca = MiniCa::generate(now).unwrap();
        let signer = TicketSigner::generate();
        let alice = SpiffeId::user("alice").unwrap();
        let mallory = SpiffeId::user("mallory").unwrap();
        let agent = SpiffeId::agent("helper").unwrap();
        let box_id = SpiffeId::node("box").unwrap();
        let node = SpiffeId::node("box").unwrap();
        let issued_node = ca
            .issue(&node, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_alice = ca
            .issue(&alice, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_mallory = ca
            .issue(&mallory, now, MAX_USER_TTL, &DenySet::empty())
            .unwrap();
        let issued_agent = ca
            .issue(&agent, now, MAX_AGENT_TTL, &DenySet::empty())
            .unwrap();
        let node_key =
            orblx_identity::ed25519_public_key_from_certificate_pem(&issued_node.certificate_pem)
                .unwrap();
        let claims = TicketClaims {
            issuer: SpiffeId::coord("ssh").unwrap(),
            subject: agent.clone(),
            not_before: now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            expires: now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 60,
            dst_cidr: "127.0.0.1/32".to_string(),
            proto: 6,
            dst_port: SSH_PORT,
            flags: TicketFlags::new(true, true),
        };
        let signed = sign_ticket(&signer, &claims).unwrap();
        let policy = Policy::from_hujson(
            br#"{
                "ssh": [
                    {
                        "src": ["spiffe://orblx.local/user/alice"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["alice"],
                        "checkPeriod": "30s"
                    },
                    {
                        "src": ["spiffe://orblx.local/agent/helper"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["alice"],
                        "checkPeriod": "30s"
                    }
                ]
            }"#,
        )
        .unwrap();
        Lab {
            bundle_pem: ca.certificate_pem().to_string(),
            verifier_pem: signer.public_key_pem(),
            node_key,
            alice_cert: issued_alice.certificate_der,
            alice_key: issued_alice.private_key_pem,
            alice,
            mallory_cert: issued_mallory.certificate_der,
            mallory_key: issued_mallory.private_key_pem,
            agent_cert: issued_agent.certificate_der,
            agent_key: issued_agent.private_key_pem,
            agent,
            ticket: signed.bytes,
            box_id,
            policy,
            now,
        }
    }

    fn bundle(lab: &Lab) -> orblx_identity::TrustBundle {
        orblx_identity::TrustBundle::from_pem(&lab.bundle_pem).unwrap()
    }

    fn verifier(lab: &Lab) -> orblx_identity::TicketVerifier {
        orblx_identity::TicketVerifier::from_public_pem(&lab.verifier_pem).unwrap()
    }

    #[test]
    fn the_overlay_listener_uses_port_22() {
        let addr = overlay_listen_addr(Ipv4Addr::new(100, 64, 0, 2)).unwrap();
        assert_eq!(addr.port(), 22);
        assert!(overlay_listen_addr(Ipv4Addr::UNSPECIFIED).is_err());
    }

    #[test]
    fn a_user_svid_is_admitted_and_a_denied_user_is_refused() {
        let lab = lab();
        let bundle = bundle(&lab);
        let password = seal_login(
            &lab.alice_key,
            &lab.alice_cert,
            &lab.node_key,
            "alice",
            &lab.box_id,
            lab.now,
            None,
        )
        .unwrap();
        let admitted = open_login(
            "alice",
            &password,
            &lab.box_id,
            Ipv4Addr::LOCALHOST,
            &lab.node_key,
            lab.now,
            &bundle,
            &lab.policy,
            &DenySet::empty(),
            None,
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(admitted.src, lab.alice);
        assert_eq!(admitted.check_period, 30);
        assert!(admitted.spend_nonce.is_none());
        let mallory = seal_login(
            &lab.mallory_key,
            &lab.mallory_cert,
            &lab.node_key,
            "mallory",
            &lab.box_id,
            lab.now,
            None,
        )
        .unwrap();
        let refused = open_login(
            "mallory",
            &mallory,
            &lab.box_id,
            Ipv4Addr::LOCALHOST,
            &lab.node_key,
            lab.now,
            &bundle,
            &lab.policy,
            &DenySet::empty(),
            None,
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert_eq!(refused.reason, DenyReason::Destination);
    }

    #[test]
    fn a_revoked_svid_is_refused() {
        let lab = lab();
        let bundle = bundle(&lab);
        let password = seal_login(
            &lab.alice_key,
            &lab.alice_cert,
            &lab.node_key,
            "alice",
            &lab.box_id,
            lab.now,
            None,
        )
        .unwrap();
        let mut deny = DenySet::empty();
        let document = format!(
            r#"{{"version":1,"generated_at":1,"revoked_uris":["{}"],"revoked_ticket_nonces":[]}}"#,
            lab.alice.as_uri()
        );
        deny.apply_json(document.as_bytes()).unwrap();
        let refused = open_login(
            "alice",
            &password,
            &lab.box_id,
            Ipv4Addr::LOCALHOST,
            &lab.node_key,
            lab.now,
            &bundle,
            &lab.policy,
            &deny,
            None,
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert_eq!(refused.reason, DenyReason::Revoked);
    }

    #[test]
    fn an_agent_ticket_is_one_shot_for_one_host() {
        let lab = lab();
        let bundle = bundle(&lab);
        let verifier = verifier(&lab);
        let password = seal_login(
            &lab.agent_key,
            &lab.agent_cert,
            &lab.node_key,
            "alice",
            &lab.box_id,
            lab.now,
            Some(&lab.ticket),
        )
        .unwrap();
        let admitted = open_login(
            "alice",
            &password,
            &lab.box_id,
            Ipv4Addr::LOCALHOST,
            &lab.node_key,
            lab.now,
            &bundle,
            &lab.policy,
            &DenySet::empty(),
            Some(&verifier),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(admitted.src, lab.agent);
        let nonce = admitted.spend_nonce.unwrap();
        let mut spent = BTreeSet::new();
        spent.insert(nonce);
        let replay = open_login(
            "alice",
            &password,
            &lab.box_id,
            Ipv4Addr::LOCALHOST,
            &lab.node_key,
            lab.now,
            &bundle,
            &lab.policy,
            &DenySet::empty(),
            Some(&verifier),
            &spent,
        )
        .unwrap_err();
        assert_eq!(replay.reason, DenyReason::Ticket);
        let other_host = open_login(
            "alice",
            &password,
            &lab.box_id,
            Ipv4Addr::new(100, 64, 0, 9),
            &lab.node_key,
            lab.now,
            &bundle,
            &lab.policy,
            &DenySet::empty(),
            Some(&verifier),
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert_eq!(other_host.reason, DenyReason::Destination);
    }

    #[test]
    fn the_command_text_is_bounded() {
        assert!(command_ok("printf %s\\n \"$ORBLX_SSH_USER\""));
        assert!(!command_ok(""));
        assert!(!command_ok("echo\nsecret"));
    }

    #[test]
    fn a_stale_proof_is_expired() {
        let lab = lab();
        let bundle = bundle(&lab);
        let password = seal_login(
            &lab.alice_key,
            &lab.alice_cert,
            &lab.node_key,
            "alice",
            &lab.box_id,
            lab.now,
            None,
        )
        .unwrap();
        let later = lab.now + Duration::from_secs(120);
        let refused = open_login(
            "alice",
            &password,
            &lab.box_id,
            Ipv4Addr::LOCALHOST,
            &lab.node_key,
            later,
            &bundle,
            &lab.policy,
            &DenySet::empty(),
            None,
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert_eq!(refused.reason, DenyReason::Expired);
    }
}
