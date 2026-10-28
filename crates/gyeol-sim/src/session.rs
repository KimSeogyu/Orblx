//! Session panels for the live harness.
//!
//! The panels start empty.
//! A level run writes peers, packets, and identity state.

use serde::Serialize;

/// The state of one session panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelState {
    /// The harness has no live value.
    None,
    /// The value is ready and not up.
    Ready,
    /// The path or the identity is up.
    Up,
    /// The path is down.
    Down,
    /// The check denied the peer.
    Denied,
    /// The SVID or the ticket expired.
    Expired,
    /// The deny list revoked the SVID.
    Revoked,
}

/// One session panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Panel {
    /// The panel state.
    pub state: PanelState,
    /// The panel sentence.
    pub detail: String,
}

/// One peer row for a later week.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerRow {
    /// The peer name from a real observation.
    pub name: String,
    /// The peer sentence from a real observation.
    pub detail: String,
}

/// One packet row for a later week.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PacketRow {
    /// The observation sequence.
    pub seq: u64,
    /// The packet sentence from a real observation.
    pub detail: String,
}

/// The session shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    /// Observed peers. The skeleton list is empty.
    pub peers: Vec<PeerRow>,
    /// The sentence for an empty peer list.
    pub peer_empty: &'static str,
    /// Observed packets. The skeleton list is empty.
    pub packets: Vec<PacketRow>,
    /// The sentence for an empty packet list.
    pub packet_empty: &'static str,
    /// The QUIC path panel.
    pub quic: Panel,
    /// The SVID panel.
    pub svid: Panel,
    /// The ticket panel.
    pub ticket: Panel,
}

impl SessionView {
    /// The placeholder shell.
    #[must_use]
    pub fn placeholder() -> Self {
        Self {
            peers: Vec::new(),
            peer_empty: "No peers. Select a level or press a smash button.",
            packets: Vec::new(),
            packet_empty: "No packets. Select a level or press a smash button.",
            quic: Panel {
                state: PanelState::None,
                detail: "The QUIC path is not up.".to_string(),
            },
            svid: Panel {
                state: PanelState::None,
                detail: "No SVID.".to_string(),
            },
            ticket: Panel {
                state: PanelState::None,
                detail: "No ticket.".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PanelState, SessionView};

    #[test]
    fn the_placeholder_is_empty() {
        let view = SessionView::placeholder();
        assert!(view.peers.is_empty());
        assert!(view.packets.is_empty());
        assert_eq!(view.quic.state, PanelState::None);
        assert_eq!(view.svid.state, PanelState::None);
        assert_eq!(view.ticket.state, PanelState::None);
        assert!(view.quic.detail.contains("not up"));
        assert!(view.svid.detail.contains("No SVID"));
        assert!(view.ticket.detail.contains("No ticket"));
    }
}
