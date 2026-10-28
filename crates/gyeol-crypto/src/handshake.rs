use std::fmt;
use std::time::SystemTime;

use gyeol_identity::{extract_spiffe_id, SpiffeId};
use sha2::{Digest, Sha256};

use crate::binding::PolicyBinding;
use crate::error::CryptoError;
use crate::session::SessionLimit;
use crate::suite::CipherSuite;
use crate::ticket::TicketProof;

/// The local role in the QUIC handshake.
///
/// Quinn owns who sends each TLS flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The endpoint that sends ClientHello.
    Client,
    /// The endpoint that sends ServerHello.
    Server,
}

/// The crypto phase for one peer session.
///
/// Datapath reads this phase before it sends DATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    /// No suite is selected.
    Start,
    /// The suite is one of the two locked suites.
    ServerHello,
    /// The peer leaf profile passed. The URI stays hidden.
    CertificateVerify,
    /// The caller has completed Finished. The URI is public.
    Finished,
    /// `ticket.subject` matches the peer URI.
    Bound,
    /// The session is closed.
    Closed,
}

/// Handshake state for one gyeol-quic session.
///
/// The type does not open a socket.
#[derive(Clone)]
#[must_use]
pub struct Handshake {
    role: Role,
    phase: HandshakePhase,
    suite: Option<CipherSuite>,
    peer: Option<SpiffeId>,
    ticket_hash: Option<[u8; 16]>,
    transcript: Sha256,
}

impl fmt::Debug for Handshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Handshake")
            .field("role", &self.role)
            .field("phase", &self.phase)
            .field("suite", &self.suite)
            .field("peer", &self.peer)
            .field("ticket_hash", &self.ticket_hash)
            .finish()
    }
}

impl Handshake {
    /// Create a client handshake in the Start phase.
    pub fn client() -> Self {
        Self::open(Role::Client)
    }

    /// Create a server handshake in the Start phase.
    pub fn server() -> Self {
        Self::open(Role::Server)
    }

    fn open(role: Role) -> Self {
        Self {
            role,
            phase: HandshakePhase::Start,
            suite: None,
            peer: None,
            ticket_hash: None,
            transcript: Sha256::new(),
        }
    }

    /// Return the local role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Return the current phase.
    pub fn phase(&self) -> HandshakePhase {
        self.phase
    }

    /// Return the selected suite.
    pub fn suite(&self) -> Option<CipherSuite> {
        self.suite
    }

    /// Append one handshake message to the transcript.
    ///
    /// Do not append application DATA.
    /// The function rejects updates at Finished, Bound, and Closed.
    pub fn record_message(&mut self, message: &[u8]) -> Result<(), CryptoError> {
        match self.phase {
            HandshakePhase::Start
            | HandshakePhase::ServerHello
            | HandshakePhase::CertificateVerify => {}
            HandshakePhase::Finished | HandshakePhase::Bound | HandshakePhase::Closed => {
                return Err(CryptoError::Phase);
            }
        }
        self.transcript.update(message);
        Ok(())
    }

    /// Return the current transcript hash.
    pub fn transcript_hash(&self) -> [u8; 32] {
        let digest = self.transcript.clone().finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Record the ServerHello suite.
    ///
    /// Call this function from the Start phase.
    pub fn select_suite(&mut self, suite: CipherSuite) -> Result<(), CryptoError> {
        match self.phase {
            HandshakePhase::Start => {}
            HandshakePhase::ServerHello
            | HandshakePhase::CertificateVerify
            | HandshakePhase::Finished
            | HandshakePhase::Bound
            | HandshakePhase::Closed => return Err(CryptoError::Phase),
        }
        self.suite = Some(suite);
        self.phase = HandshakePhase::ServerHello;
        Ok(())
    }

    /// Check the peer leaf and store the SPIFFE ID.
    ///
    /// The URI stays hidden until `note_finished`.
    pub fn note_certificate_verified(&mut self, leaf_der: &[u8]) -> Result<(), CryptoError> {
        match self.phase {
            HandshakePhase::ServerHello => {}
            HandshakePhase::Start
            | HandshakePhase::CertificateVerify
            | HandshakePhase::Finished
            | HandshakePhase::Bound
            | HandshakePhase::Closed => return Err(CryptoError::Phase),
        }
        let peer = extract_spiffe_id(leaf_der).map_err(CryptoError::Identity)?;
        self.peer = Some(peer);
        self.phase = HandshakePhase::CertificateVerify;
        Ok(())
    }

    /// Move to Finished and expose the peer URI.
    pub fn note_finished(&mut self) -> Result<&str, CryptoError> {
        match self.phase {
            HandshakePhase::CertificateVerify => {}
            HandshakePhase::Start
            | HandshakePhase::ServerHello
            | HandshakePhase::Finished
            | HandshakePhase::Bound
            | HandshakePhase::Closed => return Err(CryptoError::Phase),
        }
        if self.peer.is_none() {
            return Err(CryptoError::PeerUri);
        }
        self.phase = HandshakePhase::Finished;
        self.peer_spiffe_uri()
    }

    /// Return the peer SPIFFE URI.
    ///
    /// The function works in Finished and in Bound.
    /// Any other phase is an abort.
    pub fn peer_spiffe_uri(&self) -> Result<&str, CryptoError> {
        match self.phase {
            HandshakePhase::Finished | HandshakePhase::Bound => {}
            HandshakePhase::Start
            | HandshakePhase::ServerHello
            | HandshakePhase::CertificateVerify
            | HandshakePhase::Closed => return Err(CryptoError::Phase),
        }
        self.peer
            .as_ref()
            .map(SpiffeId::as_uri)
            .ok_or(CryptoError::PeerUri)
    }

    /// Bind `ticket.subject` to the peer URI.
    pub fn bind_ticket(&mut self, proof: &TicketProof) -> Result<(), CryptoError> {
        match self.phase {
            HandshakePhase::Finished => {}
            HandshakePhase::Start
            | HandshakePhase::ServerHello
            | HandshakePhase::CertificateVerify
            | HandshakePhase::Bound
            | HandshakePhase::Closed => return Err(CryptoError::Phase),
        }
        let peer = self.peer.as_ref().ok_or(CryptoError::PeerUri)?;
        if proof.subject() != peer {
            return Err(CryptoError::TicketSubject);
        }
        self.ticket_hash = Some(*proof.hash());
        self.phase = HandshakePhase::Bound;
        Ok(())
    }

    /// Return the bound ticket fingerprint.
    pub fn ticket_hash(&self) -> Result<&[u8; 16], CryptoError> {
        match self.phase {
            HandshakePhase::Bound => {}
            HandshakePhase::Start
            | HandshakePhase::ServerHello
            | HandshakePhase::CertificateVerify
            | HandshakePhase::Finished
            | HandshakePhase::Closed => return Err(CryptoError::Phase),
        }
        self.ticket_hash.as_ref().ok_or(CryptoError::TicketHash)
    }

    /// Build the policy context for `KeySchedule::export_binding`.
    pub fn policy_binding(&self) -> Result<PolicyBinding, CryptoError> {
        let ticket_hash = *self.ticket_hash()?;
        let suite = self.suite.ok_or(CryptoError::Suite)?;
        let peer = self.peer.as_ref().ok_or(CryptoError::PeerUri)?;
        Ok(PolicyBinding::new(
            suite,
            self.transcript_hash(),
            peer,
            ticket_hash,
        ))
    }

    /// Allow one DATA frame.
    ///
    /// The phase must be Bound.
    /// The session kind must match the peer.
    /// The frame hash must match the bound ticket.
    /// A due epoch returns `Rehandshake`.
    pub fn authorize_data(
        &self,
        limit: &SessionLimit,
        now: SystemTime,
        frame_ticket_hash: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let bound = self.ticket_hash()?;
        let peer = self.peer.as_ref().ok_or(CryptoError::PeerUri)?;
        if limit.kind() != peer.kind() {
            return Err(CryptoError::PeerUri);
        }
        if limit.must_rehandshake(now)? {
            return Err(CryptoError::Rehandshake);
        }
        if bound != frame_ticket_hash {
            return Err(CryptoError::TicketHash);
        }
        Ok(())
    }

    /// Close the handshake.
    ///
    /// A second call stays in Closed.
    pub fn close(&mut self) {
        self.phase = HandshakePhase::Closed;
    }
}
