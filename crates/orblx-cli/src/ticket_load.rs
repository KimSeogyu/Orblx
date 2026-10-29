use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_crypto::{TicketKey, TicketRing};
use orblx_datapath::HelloConfig;
use orblx_edge::DirectIdentity;
use orblx_identity::{DenySet, TicketVerifier, TrustBundle};

struct TicketParts {
    ticket_bytes: Vec<u8>,
    ticket_mac: [u8; 32],
    ticket_verifier_pem: String,
    ticket_mac_key: [u8; 32],
    ticket_not_before: SystemTime,
    ticket_not_after: SystemTime,
    svid_ca_public: [u8; 32],
}

pub(crate) fn load_direct_identity(
    certificate_pem: String,
    private_key_pem: String,
    trust_pem: String,
    ticket: &Path,
) -> Result<DirectIdentity, String> {
    let parts = read_parts(ticket)?;
    Ok(DirectIdentity {
        certificate_pem,
        private_key_pem,
        trust_pem,
        ticket_bytes: parts.ticket_bytes,
        ticket_mac: parts.ticket_mac,
        ticket_verifier_pem: parts.ticket_verifier_pem,
        ticket_mac_key: parts.ticket_mac_key,
        ticket_not_before: parts.ticket_not_before,
        ticket_not_after: parts.ticket_not_after,
        svid_ca_public: parts.svid_ca_public,
    })
}

pub(crate) fn load_hello_config(
    certificate_pem: String,
    private_key_pem: String,
    trust: TrustBundle,
    ticket: &Path,
) -> Result<HelloConfig, String> {
    let parts = read_parts(ticket)?;
    let verifier = TicketVerifier::from_public_pem(&parts.ticket_verifier_pem)
        .map_err(|err| err.to_string())?;
    let key = TicketKey::new(
        verifier,
        parts.ticket_mac_key,
        parts.ticket_not_before,
        parts.ticket_not_after,
    )
    .map_err(|err| err.to_string())?;
    let ring = TicketRing::single(key, &parts.svid_ca_public).map_err(|err| err.to_string())?;
    Ok(HelloConfig {
        certificate_pem,
        private_key_pem,
        trust,
        ticket_bytes: parts.ticket_bytes,
        ticket_mac: parts.ticket_mac,
        ticket_ring: ring,
        deny: DenySet::empty(),
    })
}

pub(crate) fn write_shared(out: &Path, identity: &DirectIdentity) -> Result<(), String> {
    write_file(
        &out.join("ticket-verifier.pem"),
        identity.ticket_verifier_pem.as_bytes(),
    )?;
    write_file(&out.join("ticket-mac.key"), &identity.ticket_mac_key)?;
    write_file(&out.join("svid-ca.pub"), &identity.svid_ca_public)?;
    write_unix(&out.join("ticket-not-before"), identity.ticket_not_before)?;
    write_unix(&out.join("ticket-not-after"), identity.ticket_not_after)?;
    Ok(())
}

pub(crate) fn write_ticket(path: &Path, identity: &DirectIdentity) -> Result<(), String> {
    write_file(path, &identity.ticket_bytes)?;
    write_file(&mac_path(path), &identity.ticket_mac)?;
    Ok(())
}

fn read_parts(ticket: &Path) -> Result<TicketParts, String> {
    let directory = ticket.parent().unwrap_or_else(|| Path::new("."));
    Ok(TicketParts {
        ticket_bytes: read_file(ticket)?,
        ticket_mac: read_array(&mac_path(ticket))?,
        ticket_verifier_pem: read_text(&directory.join("ticket-verifier.pem"))?,
        ticket_mac_key: read_array(&directory.join("ticket-mac.key"))?,
        ticket_not_before: read_unix(&directory.join("ticket-not-before"))?,
        ticket_not_after: read_unix(&directory.join("ticket-not-after"))?,
        svid_ca_public: read_array(&directory.join("svid-ca.pub"))?,
    })
}

fn mac_path(ticket: &Path) -> PathBuf {
    let mut name = ticket.as_os_str().to_owned();
    name.push(".mac");
    PathBuf::from(name)
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("The file {} did not open. {err}", path.display()))
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map_err(|err| format!("The file {} did not open. {err}", path.display()))
}

fn read_array(path: &Path) -> Result<[u8; 32], String> {
    let bytes = read_file(path)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        format!(
            "The file {} has {} bytes and the reader needs 32 bytes.",
            path.display(),
            bytes.len()
        )
    })
}

fn read_unix(path: &Path) -> Result<SystemTime, String> {
    let text = read_text(path)?;
    let secs: u64 = text
        .trim()
        .parse()
        .map_err(|_| format!("The time in {} is not valid.", path.display()))?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

fn write_unix(path: &Path, time: SystemTime) -> Result<(), String> {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| format!("The time for {} is not valid.", path.display()))?;
    write_file(path, secs.as_secs().to_string().as_bytes())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes)
        .map_err(|err| format!("The file {} was not written. {err}", path.display()))
}
