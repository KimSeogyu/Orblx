//! Handshake and key-schedule scaffold for gyeol-quic.
//!
//! Quinn and rustls own the QUIC TLS 1.3 flight and the record AEAD.
//! This crate records the handshake phase, the HKDF-SHA256 schedule, and the ticket check.
//! Read ADR 0004 before you change a primitive.

#![forbid(unsafe_code)]

mod binding;
mod error;
mod handshake;
mod schedule;
mod session;
mod suite;
mod ticket;

pub use binding::PolicyBinding;
pub use error::CryptoError;
pub use handshake::{Handshake, HandshakePhase, Role};
pub use schedule::{Direction, KeySchedule, ScheduleLabel, TrafficSecret, X25519Shared};
pub use session::{SessionLimit, MAX_SESSION};
pub use suite::{
    CipherSuite, Kdf, NamedGroup, SignatureScheme, Transport, HASH_LEN, KDF, NAMED_GROUP,
    SIGNATURE_SCHEME, TRANSPORT,
};
pub use ticket::{
    mac_input, ticket_hash, ticket_mac, verify_ticket, TicketKey, TicketProof, TicketRing,
    MAX_TICKET_KEY_OVERLAP,
};

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "gyeol-crypto"
}

#[cfg(test)]
mod tests {
    use super::crate_name;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "gyeol-crypto");
    }
}
