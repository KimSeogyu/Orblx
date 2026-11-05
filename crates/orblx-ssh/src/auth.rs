//! The SSH listen address, the command check, and the record of one refused login.
//!
//! The only login method is a user certificate (W25-31). See [`crate::cert`].

use std::net::Ipv4Addr;

use orblx_audit::DenyReason;
use orblx_identity::SpiffeId;

const MAX_COMMAND: usize = 200;

/// TCP port of the overlay SSH server.
pub const SSH_PORT: u16 = 22;

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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{command_ok, overlay_listen_addr};

    #[test]
    fn the_overlay_listener_uses_port_22() {
        let addr = overlay_listen_addr(Ipv4Addr::new(100, 64, 0, 2)).unwrap();
        assert_eq!(addr.port(), 22);
        assert!(overlay_listen_addr(Ipv4Addr::UNSPECIFIED).is_err());
    }

    #[test]
    fn the_command_text_is_bounded() {
        assert!(command_ok("printf %s\\n \"$ORBLX_SSH_USER\""));
        assert!(!command_ok(""));
        assert!(!command_ok("echo\nsecret"));
    }
}
