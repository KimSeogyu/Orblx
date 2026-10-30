//! The orblx Relay.
//!
//! The Relay routes by session id only.
//! The payload is opaque.
//! The Relay does not hold session keys.
//! The Relay does not mint sessions.
//! The Relay does not terminate QUIC.
//! UDP port 443 is the preferred socket.
//! TCP port 443 carries the same datagram behind a length prefix.

mod batch;
mod error;
mod pipe;
mod server;
mod session;
mod wire;

pub use batch::{recv_batch, send_batch, BatchPeer, RecvBatch, UDP_BATCH};
pub use error::RelayError;
pub use pipe::{RelayPipe, RelaySender};
pub use server::{RelayServer, RelayStats, ServerConfig, PEER_IDLE};
pub use session::RelaySessionId;
pub use wire::{
    contains_needle, decode_datagram, encode_datagram, encode_tcp_record, framing_name,
    take_tcp_record, RelayDatagram, RelayKind, RelayPreference, RelayTransport, MAX_DATAGRAM_LEN,
    MAX_PAYLOAD_LEN, RELAY_HEADER_LEN, RELAY_PORT, RELAY_VERSION,
};

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "orblx-relay"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "orblx-relay");
    }

    #[test]
    fn relay_manifest_has_no_quic_stack_and_no_forbidden_stack() {
        let text = include_str!("../Cargo.toml").to_ascii_lowercase();
        for banned in [
            "quinn",
            "rustls",
            "wireguard",
            "boringtun",
            "headscale",
            "derp",
            "tailscale",
            "defguard",
        ] {
            assert!(!text.contains(banned), "the Relay manifest names {banned}");
        }
    }
}
