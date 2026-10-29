use std::net::SocketAddr;

use crate::EdgeError;

/// One local endpoint after STUN.
///
/// `local` is the socket the client bound.
/// `reflexive` is the server-reflexive socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointCandidate {
    /// The socket the client bound.
    pub local: SocketAddr,
    /// The server-reflexive socket.
    pub reflexive: SocketAddr,
}

/// An unsigned candidate set for a later Coordinator exchange.
///
/// ADR 0003 leaves the freeze, sign, and verify owner open.
/// This type does not sign the bytes.
/// This type does not verify the bytes.
/// This type does not choose the Coordinator owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedCandidateSet {
    /// The local candidate.
    pub candidate: EndpointCandidate,
}

/// A sink for an unsigned candidate set.
///
/// The sink does not freeze a Coordinator blob.
pub trait CandidateSink {
    /// Store one unsigned candidate set.
    ///
    /// The function does not sign the set.
    fn store_unsigned(&mut self, set: &UnsignedCandidateSet) -> Result<(), EdgeError>;
}

/// An in-memory sink for tests and the lab smoke.
///
/// The sink stores the set.
/// The sink does not sign the set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryCandidateSink {
    /// The last stored set.
    pub stored: Option<UnsignedCandidateSet>,
}

impl CandidateSink for MemoryCandidateSink {
    fn store_unsigned(&mut self, set: &UnsignedCandidateSet) -> Result<(), EdgeError> {
        self.stored = Some(*set);
        Ok(())
    }
}

/// Encode one unsigned candidate as text.
///
/// The text has no signature.
/// ADR 0003 does not name the owner of the Coordinator blob.
#[must_use]
pub fn encode_candidate(candidate: EndpointCandidate) -> String {
    format!(
        "local {}\nreflexive {}\n",
        candidate.local, candidate.reflexive
    )
}

/// The bytes the coordinator signs for one endpoint.
///
/// The text is `gyeol-endpoint-v1`, the node name, and `host:port`.
/// A newline in either value is rejected.
/// This function does not sign the bytes.
pub fn endpoint_sign_payload(node_name: &str, endpoint: &str) -> Result<String, EdgeError> {
    if node_name.is_empty()
        || endpoint.is_empty()
        || node_name.contains(['\n', '\r'])
        || endpoint.contains(['\n', '\r'])
    {
        return Err(EdgeError::BadCandidate);
    }
    Ok(format!("gyeol-endpoint-v1\n{node_name}\n{endpoint}\n"))
}

/// Decode one unsigned candidate from text.
///
/// The function does not verify a signature.
pub fn decode_candidate(text: &str) -> Result<EndpointCandidate, EdgeError> {
    let mut local = None;
    let mut reflexive = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return Err(EdgeError::BadCandidate);
        }
        let addr: SocketAddr = value.parse().map_err(|_| EdgeError::BadCandidate)?;
        match key {
            "local" => local = Some(addr),
            "reflexive" => reflexive = Some(addr),
            _ => return Err(EdgeError::BadCandidate),
        }
    }
    match (local, reflexive) {
        (Some(local), Some(reflexive)) => Ok(EndpointCandidate { local, reflexive }),
        _ => Err(EdgeError::BadCandidate),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::{decode_candidate, encode_candidate, endpoint_sign_payload, EndpointCandidate};

    #[test]
    fn candidate_text_round_trip_has_no_signature() {
        let candidate = EndpointCandidate {
            local: SocketAddr::from((Ipv4Addr::new(10, 20, 0, 2), 443)),
            reflexive: SocketAddr::from((Ipv4Addr::new(10, 30, 0, 2), 40000)),
        };
        let text = encode_candidate(candidate);
        assert!(!text.contains("signature"));
        assert_eq!(decode_candidate(&text).unwrap(), candidate);
        assert_eq!(
            decode_candidate("local 127.0.0.1:1\n"),
            Err(crate::EdgeError::BadCandidate)
        );
    }

    #[test]
    fn endpoint_sign_payload_rejects_a_newline() {
        let text = endpoint_sign_payload("server", "10.0.0.2:443").unwrap();
        assert_eq!(text, "gyeol-endpoint-v1\nserver\n10.0.0.2:443\n");
        assert_eq!(
            endpoint_sign_payload("bad\nname", "10.0.0.2:443"),
            Err(crate::EdgeError::BadCandidate)
        );
    }
}
