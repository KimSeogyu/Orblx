use gyeol_identity::{ticket_hash, SpiffeId};
use gyeol_relay::RelaySessionId;

use crate::{AuditLog, DenyReason, SessionEvent, SessionIds};

/// Relay session id for the demo deny.
pub const DEMO_DENY_RELAY: [u8; 16] = [0xde; 16];

/// Frame session id for the demo deny.
pub const DEMO_DENY_FRAME: u32 = 7;

/// Peer SPIFFE URI for the demo deny.
pub const DEMO_DENY_PEER: &str = "spiffe://gyeol.local/agent/worker";

/// Ticket bytes for the demo deny.
///
/// The chain stores `ticket_hash` of these bytes.
pub const DEMO_DENY_TICKET: &[u8] = b"w10-deny-ticket";

/// Unix time for the demo deny.
pub const DEMO_DENY_UNIX: u64 = 1_700_000_000;

/// Relay session id for the demo session.
pub const DEMO_OK_RELAY: [u8; 16] = [0x11; 16];

/// Frame session id for the demo session.
pub const DEMO_OK_FRAME: u32 = 42;

/// Peer SPIFFE URI for the demo session.
pub const DEMO_OK_PEER: &str = "spiffe://gyeol.local/user/ada";

/// Ticket bytes for the demo session.
///
/// The chain stores `ticket_hash` of these bytes.
pub const DEMO_OK_TICKET: &[u8] = b"w10-ok-ticket";

/// Unix time for the demo session start.
pub const DEMO_START_UNIX: u64 = 1_700_000_001;

/// Unix time for the demo session end.
pub const DEMO_END_UNIX: u64 = 1_700_000_061;

/// Record one deny and one successful session.
///
/// The deny is one agent destination refusal.
/// The successful session is one start and one end.
/// The times and the ids are fixed.
/// The function does not use the data path.
pub fn escape_demo() -> AuditLog {
    let mut log = AuditLog::new();
    log.append(demo_deny())
        .expect("the demo deny event is valid");
    let ids = demo_ok_ids();
    log.append(SessionEvent::Start {
        ids: ids.clone(),
        at_unix: DEMO_START_UNIX,
    })
    .expect("the demo start event is valid");
    log.append(SessionEvent::End {
        ids,
        at_unix: DEMO_END_UNIX,
    })
    .expect("the demo end event is valid");
    log
}

fn demo_deny() -> SessionEvent {
    SessionEvent::Deny {
        ids: SessionIds {
            relay: RelaySessionId::from_bytes(DEMO_DENY_RELAY),
            frame: DEMO_DENY_FRAME,
            peer: SpiffeId::parse(DEMO_DENY_PEER).expect("the demo deny peer is valid"),
            ticket_hash: ticket_hash(DEMO_DENY_TICKET),
        },
        at_unix: DEMO_DENY_UNIX,
        reason: DenyReason::Destination,
    }
}

fn demo_ok_ids() -> SessionIds {
    SessionIds {
        relay: RelaySessionId::from_bytes(DEMO_OK_RELAY),
        frame: DEMO_OK_FRAME,
        peer: SpiffeId::parse(DEMO_OK_PEER).expect("the demo session peer is valid"),
        ticket_hash: ticket_hash(DEMO_OK_TICKET),
    }
}
