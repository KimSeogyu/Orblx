use orblx_identity::SpiffeId;

use crate::error::CryptoError;
use crate::suite::CipherSuite;

/// The bytes that `export_binding` mixes into the policy binder.
///
/// The context binds the suite, the transcript, the ticket fingerprint, and the peer URI.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct PolicyBinding {
    suite: CipherSuite,
    transcript_hash: [u8; 32],
    peer_spiffe_uri: String,
    ticket_hash: [u8; 16],
}

impl PolicyBinding {
    /// Build a policy context from a parsed SPIFFE ID.
    pub fn new(
        suite: CipherSuite,
        transcript_hash: [u8; 32],
        peer: &SpiffeId,
        ticket_hash: [u8; 16],
    ) -> Self {
        Self {
            suite,
            transcript_hash,
            peer_spiffe_uri: peer.as_uri().to_string(),
            ticket_hash,
        }
    }

    /// Return the suite id recorded in this context.
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Return the transcript hash.
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// Return the peer SPIFFE URI.
    pub fn peer_spiffe_uri(&self) -> &str {
        &self.peer_spiffe_uri
    }

    /// Return the ticket fingerprint.
    pub fn ticket_hash(&self) -> &[u8; 16] {
        &self.ticket_hash
    }

    /// Encode the context for HKDF.
    ///
    /// The layout is `suite_id || transcript_hash || ticket_hash || uri_len || uri`.
    /// Lengths are big-endian.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let uri = self.peer_spiffe_uri.as_bytes();
        let uri_len = u16::try_from(uri.len()).map_err(|_| CryptoError::PeerUri)?;
        let mut out = Vec::with_capacity(2 + 32 + 16 + 2 + uri.len());
        out.extend_from_slice(&self.suite.iana().to_be_bytes());
        out.extend_from_slice(&self.transcript_hash);
        out.extend_from_slice(&self.ticket_hash);
        out.extend_from_slice(&uri_len.to_be_bytes());
        out.extend_from_slice(uri);
        Ok(out)
    }
}
