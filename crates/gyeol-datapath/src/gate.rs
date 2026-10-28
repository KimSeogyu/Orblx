use std::time::SystemTime;

use gyeol_identity::{extract_spiffe_id, DenySet, SpiffeId, TrustBundle};

use crate::{is_ipv4_packet, Frame, FrameType, HelloError};

/// The peer SPIFFE ID for one hello-quic session.
///
/// DATA frames stay rejected until `bind_leaf` succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGate {
    peer: Option<SpiffeId>,
}

impl Default for PeerGate {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerGate {
    /// Create a gate with no peer.
    #[must_use]
    pub fn new() -> Self {
        Self { peer: None }
    }

    /// Create a gate that already has a peer.
    #[must_use]
    pub fn bound(peer: SpiffeId) -> Self {
        Self { peer: Some(peer) }
    }

    /// Return the bound SPIFFE ID.
    #[must_use]
    pub fn peer(&self) -> Option<&SpiffeId> {
        self.peer.as_ref()
    }

    /// Check the leaf and bind the SPIFFE ID.
    ///
    /// The function calls `TrustBundle::authenticate_leaf`.
    /// The function calls `extract_spiffe_id`.
    /// The two results must match.
    pub fn bind_leaf(
        &mut self,
        trust: &TrustBundle,
        leaf_der: &[u8],
        now: SystemTime,
        deny: &DenySet,
    ) -> Result<&SpiffeId, HelloError> {
        let authed = trust
            .authenticate_leaf(leaf_der, now, deny)
            .map_err(HelloError::Identity)?;
        let extracted = extract_spiffe_id(leaf_der).map_err(HelloError::Identity)?;
        if extracted != authed {
            return Err(HelloError::PeerRejected);
        }
        self.peer = Some(authed);
        self.peer.as_ref().ok_or(HelloError::PeerNotBound)
    }

    /// Return the peer or reject the DATA path.
    pub fn require_bound(&self) -> Result<&SpiffeId, HelloError> {
        self.peer.as_ref().ok_or(HelloError::PeerNotBound)
    }

    /// Build one DATA frame for an IPv4 packet.
    pub fn encode_data(
        &self,
        session_id: u32,
        seq: u64,
        ticket_hash: [u8; 16],
        packet: &[u8],
    ) -> Result<Frame, HelloError> {
        self.require_bound()?;
        if !is_ipv4_packet(packet) {
            return Err(HelloError::NotIpv4);
        }
        Ok(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            session_id,
            seq,
            ticket_hash,
            payload: packet.to_vec(),
        })
    }

    /// Return the IPv4 payload of one DATA frame.
    pub fn payload_from_data<'a>(&self, frame: &'a Frame) -> Result<&'a [u8], HelloError> {
        self.require_bound()?;
        match frame.frame_type {
            FrameType::Data => {}
            FrameType::Ctrl | FrameType::Ticket => return Err(HelloError::NotData),
        }
        if !is_ipv4_packet(&frame.payload) {
            return Err(HelloError::NotIpv4);
        }
        Ok(&frame.payload)
    }
}
