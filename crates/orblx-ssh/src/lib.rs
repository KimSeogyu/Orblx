//! SSH on the overlay address.
//!
//! The node daemon runs an in-process russh server.
//! The server binds the node overlay address.
//! The client signs in with an SVID.
//! The server does not read `authorized_keys`.
//! The server does not write an SSH key file.
//! An agent presents one `FLAG_AGENT_JIT` and `FLAG_ONE_SHOT` ticket.
//! The ticket names one host.
//! The SSH policy names one user for that agent.
//! A rule with `"recording": "required"` records the session to a file.
//! The audit chain then holds the SHA-256 of that file.

mod auth;
pub mod cert;
mod client;
mod hostkey;
mod pty;
mod record;
mod server;

pub use auth::{overlay_listen_addr, SSH_PORT};
pub use client::{
    local_terminal_size, run_session, run_shell, CertLogin, RawMode, SessionOutput, SessionRequest,
    ShellTerminal,
};
pub use server::spawn_overlay_server;

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "orblx-ssh"
}

/// The OpenSSH user certificate type (W25-31).
pub use russh::keys::Certificate as SshUserCert;

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "orblx-ssh");
    }

    #[test]
    fn the_manifest_names_russh_and_no_forbidden_stack() {
        let text = include_str!("../Cargo.toml").to_ascii_lowercase();
        assert!(text.contains("russh"));
        for banned in ["wireguard", "headscale", "derp", "tailscale", "defguard"] {
            assert!(!text.contains(banned), "the ssh manifest names {banned}");
        }
    }
}
