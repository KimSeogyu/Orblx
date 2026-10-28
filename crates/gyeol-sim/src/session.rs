//! Placeholder session panels.
//!
//! The panels stay empty in this skeleton.
//! The harness does not invent peers, packets, or identity state.

use serde::Serialize;

/// The state of one session panel.
///
/// The skeleton has one variant.
/// A later week can add a variant when a real feed writes a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelState {
    /// The harness has no live value.
    None,
}

/// One session panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Panel {
    /// The panel state.
    pub state: PanelState,
    /// The panel sentence.
    pub detail: &'static str,
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
///
/// Smash actions do not write this value.
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
    pub const fn placeholder() -> Self {
        Self {
            peers: Vec::new(),
            peer_empty: "No peers. The harness does not open a session.",
            packets: Vec::new(),
            packet_empty: "No packets. The harness does not capture packets.",
            quic: Panel {
                state: PanelState::None,
                detail: "The harness does not open a QUIC path.",
            },
            svid: Panel {
                state: PanelState::None,
                detail: "The harness does not issue an SVID.",
            },
            ticket: Panel {
                state: PanelState::None,
                detail: "The harness does not issue a ticket.",
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
        assert!(view.quic.detail.contains("does not open a QUIC path"));
        assert!(view.svid.detail.contains("does not issue an SVID"));
        assert!(view.ticket.detail.contains("does not issue a ticket"));
    }
}
