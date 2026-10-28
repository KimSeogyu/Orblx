use std::fmt;
use std::time::SystemTime;

use gyeol_crypto::{verify_ticket, TicketProof, TicketRing};
use gyeol_identity::{
    allow_agent_jit, extract_spiffe_id, DenySet, Ipv4Destination, SpiffeId, TrustBundle,
    WorkloadKind,
};

use crate::ipv4::tcp_udp_destination;
use crate::{is_ipv4_packet, Frame, FrameType, HelloError};

/// The peer SPIFFE ID and the admitted capability ticket.
///
/// DATA stays rejected until `bind_leaf` and `admit_ticket` succeed.
/// `payload_from_data` checks the ticket again before it accepts DATA.
/// An agent peer must present a JIT ticket.
/// That ticket allows one destination.
/// Every other agent destination is denied.
/// A human peer keeps the ticket check and does not use the agent allow.
#[derive(Clone)]
pub struct PeerGate {
    peer: Option<SpiffeId>,
    admitted: Option<AdmittedTicket>,
}

#[derive(Clone)]
struct AdmittedTicket {
    bytes: Vec<u8>,
    mac: [u8; 32],
    ring: TicketRing,
}

impl fmt::Debug for PeerGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerGate")
            .field("peer", &self.peer)
            .field("ticket", &self.admitted.as_ref().map(|_| "admitted"))
            .finish()
    }
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
        Self {
            peer: None,
            admitted: None,
        }
    }

    /// Create a gate that already has a peer.
    ///
    /// The gate has no capability ticket.
    /// DATA stays rejected until `admit_ticket` succeeds.
    #[must_use]
    pub fn bound(peer: SpiffeId) -> Self {
        Self {
            peer: Some(peer),
            admitted: None,
        }
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
        self.admitted = None;
        self.peer.as_ref().ok_or(HelloError::PeerNotBound)
    }

    /// Check one presented capability ticket and store it.
    ///
    /// Call this function after `bind_leaf`.
    /// The function calls `gyeol_crypto::verify_ticket`.
    /// `ticket_bytes` are the identity version-1 ticket bytes.
    /// `mac` is the HMAC tag over those bytes.
    /// An empty ticket is missing.
    /// A bad tag, a bad signature, an expired ticket, or a subject
    /// that differs from the peer is rejected.
    /// An agent ticket that does not set the JIT flag is denied after the ticket check.
    pub fn admit_ticket(
        &mut self,
        ring: &TicketRing,
        ticket_bytes: &[u8],
        mac: &[u8; 32],
        now: SystemTime,
        deny: &DenySet,
    ) -> Result<[u8; 16], HelloError> {
        let peer = self.require_bound()?.clone();
        if ticket_bytes.is_empty() {
            return Err(HelloError::TicketMissing);
        }
        let proof =
            verify_ticket(ring, ticket_bytes, mac, &peer, now, deny).map_err(HelloError::Ticket)?;
        let hash = *proof.hash();
        if hash != gyeol_crypto::ticket_hash(ticket_bytes) {
            return Err(HelloError::TicketHash);
        }
        if peer.kind() == WorkloadKind::Agent && !proof.flags().agent_jit() {
            return Err(HelloError::DestinationDenied);
        }
        self.admitted = Some(AdmittedTicket {
            bytes: ticket_bytes.to_vec(),
            mac: *mac,
            ring: ring.clone(),
        });
        Ok(hash)
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
    ///
    /// The function calls `gyeol_crypto::verify_ticket` again.
    /// The frame `ticket_hash` must equal `proof.hash`.
    /// A missing ticket, a bad ticket, or a different hash is rejected.
    /// The destination check runs after the ticket check.
    /// An agent packet to any other destination is rejected.
    pub fn payload_from_data<'a>(
        &self,
        frame: &'a Frame,
        now: SystemTime,
        deny: &DenySet,
    ) -> Result<&'a [u8], HelloError> {
        let peer = self.require_bound()?;
        match frame.frame_type {
            FrameType::Data => {}
            FrameType::Ctrl | FrameType::Ticket => return Err(HelloError::NotData),
        }
        let admitted = self.admitted.as_ref().ok_or(HelloError::TicketMissing)?;
        let proof = verify_ticket(
            &admitted.ring,
            &admitted.bytes,
            &admitted.mac,
            peer,
            now,
            deny,
        )
        .map_err(HelloError::Ticket)?;
        if frame.ticket_hash != *proof.hash() {
            return Err(HelloError::TicketHash);
        }
        if !is_ipv4_packet(&frame.payload) {
            return Err(HelloError::NotIpv4);
        }
        if peer.kind() == WorkloadKind::Agent {
            admit_agent_destination(&proof, &frame.payload)?;
        }
        Ok(&frame.payload)
    }
}

fn admit_agent_destination(proof: &TicketProof, packet: &[u8]) -> Result<(), HelloError> {
    if !proof.flags().agent_jit() {
        return Err(HelloError::DestinationDenied);
    }
    let parsed = tcp_udp_destination(packet).ok_or(HelloError::DestinationDenied)?;
    allow_agent_jit(
        proof.flags(),
        proof.dst_cidr(),
        proof.proto(),
        proof.dst_port(),
        Ipv4Destination {
            addr: parsed.addr,
            proto: parsed.proto,
            port: parsed.port,
        },
    )
    .map_err(|_| HelloError::DestinationDenied)
}
