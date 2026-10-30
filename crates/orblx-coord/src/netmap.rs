use std::net::Ipv4Addr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use orblx_datapath::{Netmap, NetmapError};
use orblx_edge::endpoint_sign_payload;
use orblx_identity::ReceiverGrants;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::CoordError;
use crate::ippool::is_overlay_ip;

/// One signed netmap document.
///
/// `sig` is the base64 Ed25519 signature over the canonical JSON of `netmap`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetmap {
    pub netmap: Netmap,
    pub sig: String,
    pub key_id: String,
}

/// The receiver grant set, signed with the netmap key.
///
/// `sig` is the base64 Ed25519 signature over the canonical JSON of `grants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrants {
    pub grants: ReceiverGrants,
    pub sig: String,
    pub key_id: String,
}

/// One Ed25519 signature over [`endpoint_sign_payload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEndpoint {
    pub name: String,
    pub endpoint: String,
    pub sig: String,
    pub key_id: String,
}

/// The coordinator netmap key.
pub struct NetmapKey {
    signing: SigningKey,
}

impl std::fmt::Debug for NetmapKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetmapKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl NetmapKey {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn key_id(&self) -> String {
        encode_hex(&self.public())
    }

    pub fn sign_netmap(&self, payload: &Netmap) -> Result<SignedNetmap, CoordError> {
        validate_payload(payload)?;
        let bytes = canonical_payload(payload)?;
        let sig = STANDARD.encode(self.signing.sign(&bytes).to_bytes());
        Ok(SignedNetmap {
            netmap: payload.clone(),
            sig,
            key_id: self.key_id(),
        })
    }

    pub fn sign_grants(&self, grants: &ReceiverGrants) -> Result<SignedGrants, CoordError> {
        grants
            .check()
            .map_err(|err| CoordError::Protocol(err.to_string()))?;
        let bytes = serde_json::to_vec(grants)
            .map_err(|_| CoordError::Protocol("The grants are not valid.".to_string()))?;
        let sig = STANDARD.encode(self.signing.sign(&bytes).to_bytes());
        Ok(SignedGrants {
            grants: grants.clone(),
            sig,
            key_id: self.key_id(),
        })
    }

    pub(crate) fn sign_agent_grant(
        &self,
        grant: &orblx_agent::AgentGrant,
    ) -> Result<orblx_agent::SignedAgentGrant, CoordError> {
        orblx_agent::sign_grant(&self.signing, grant)
            .map_err(|err| CoordError::Protocol(err.to_string()))
    }

    pub fn sign_endpoint(&self, name: &str, endpoint: &str) -> Result<SignedEndpoint, CoordError> {
        let payload = endpoint_sign_payload(name, endpoint).map_err(|_| CoordError::Endpoint)?;
        let sig = STANDARD.encode(self.signing.sign(payload.as_bytes()).to_bytes());
        Ok(SignedEndpoint {
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            sig,
            key_id: self.key_id(),
        })
    }
}

pub fn verify_signed_netmap(signed: &SignedNetmap, public: &[u8; 32]) -> Result<(), CoordError> {
    if signed.key_id != encode_hex(public) {
        return Err(CoordError::Signature);
    }
    validate_payload(&signed.netmap)?;
    let bytes = canonical_payload(&signed.netmap)?;
    verify_b64(public, &bytes, &signed.sig)
}

pub fn verify_signed_grants(signed: &SignedGrants, public: &[u8; 32]) -> Result<(), CoordError> {
    if signed.key_id != encode_hex(public) {
        return Err(CoordError::Signature);
    }
    signed
        .grants
        .check()
        .map_err(|err| CoordError::Protocol(err.to_string()))?;
    let bytes = serde_json::to_vec(&signed.grants)
        .map_err(|_| CoordError::Protocol("The grants are not valid.".to_string()))?;
    verify_b64(public, &bytes, &signed.sig)
}

pub fn verify_signed_endpoint(
    signed: &SignedEndpoint,
    public: &[u8; 32],
) -> Result<(), CoordError> {
    if signed.key_id != encode_hex(public) {
        return Err(CoordError::Signature);
    }
    let payload =
        endpoint_sign_payload(&signed.name, &signed.endpoint).map_err(|_| CoordError::Endpoint)?;
    verify_b64(public, payload.as_bytes(), &signed.sig)
}

fn verify_b64(public: &[u8; 32], message: &[u8], sig_b64: &str) -> Result<(), CoordError> {
    let bytes = STANDARD
        .decode(sig_b64.as_bytes())
        .map_err(|_| CoordError::Signature)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| CoordError::Signature)?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| CoordError::Signature)?;
    key.verify(message, &signature)
        .map_err(|_| CoordError::Signature)
}

fn canonical_payload(payload: &Netmap) -> Result<Vec<u8>, CoordError> {
    serde_json::to_vec(payload).map_err(|_| CoordError::Protocol("The netmap is not valid.".into()))
}

fn validate_payload(payload: &Netmap) -> Result<(), CoordError> {
    payload.check().map_err(netmap_error)?;
    check_overlay(&payload.self_node.overlay_ip)?;
    for peer in &payload.peers {
        check_overlay(&peer.overlay_ip)?;
    }
    Ok(())
}

fn netmap_error(err: NetmapError) -> CoordError {
    match err {
        NetmapError::Route { .. } => CoordError::Route,
        NetmapError::Endpoint { .. } => CoordError::Endpoint,
        NetmapError::Name { .. } => CoordError::Name,
        NetmapError::Json { .. }
        | NetmapError::Version { .. }
        | NetmapError::Address { .. }
        | NetmapError::Svid { .. }
        | NetmapError::Duplicate { .. } => {
            CoordError::Protocol("The netmap is not valid.".to_string())
        }
        NetmapError::Owner { .. } => {
            CoordError::Protocol("The owner is not a DNS name.".to_string())
        }
    }
}

fn check_overlay(text: &str) -> Result<(), CoordError> {
    let ip: Ipv4Addr = text
        .parse()
        .map_err(|_| CoordError::Protocol("The overlay address is not valid.".into()))?;
    if !is_overlay_ip(ip) || text != ip.to_string() {
        return Err(CoordError::Protocol(
            "The overlay address is outside 100.64.0.0/10.".into(),
        ));
    }
    Ok(())
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

pub fn decode_hex_32(text: &str) -> Result<[u8; 32], CoordError> {
    if text.len() != 64 {
        return Err(CoordError::Signature);
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = text
            .get(index * 2..index * 2 + 2)
            .ok_or(CoordError::Signature)?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| CoordError::Signature)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use orblx_datapath::{Netmap, NetmapPeer, NetmapSelf};

    use super::{verify_signed_endpoint, verify_signed_netmap, NetmapKey};

    fn sample() -> Netmap {
        Netmap {
            version: 1,
            self_node: NetmapSelf {
                name: "server".to_string(),
                overlay_ip: "100.64.0.1".to_string(),
                owner: String::new(),
            },
            peers: vec![NetmapPeer {
                name: "laptop".to_string(),
                overlay_ip: "100.64.0.2".to_string(),
                svid: "spiffe://orblx.local/node/laptop".to_string(),
                endpoints: vec!["10.0.0.2:443".to_string()],
                routes: vec!["192.168.1.0/24".to_string()],
                exit_node: false,
                owner: String::new(),
                lock_sig: None,
            }],
            lock: Vec::new(),
            split_dns: Vec::new(),
        }
    }

    #[test]
    fn payload_json_matches_the_w18_schema() {
        let text = serde_json::to_string(&sample()).unwrap();
        assert_eq!(
            text,
            r#"{"version":1,"self":{"name":"server","overlay_ip":"100.64.0.1"},"peers":[{"name":"laptop","overlay_ip":"100.64.0.2","svid":"spiffe://orblx.local/node/laptop","endpoints":["10.0.0.2:443"],"routes":["192.168.1.0/24"]}]}"#
        );
    }

    #[test]
    fn tampered_netmap_is_rejected() {
        let key = NetmapKey::generate();
        let signed = key.sign_netmap(&sample()).unwrap();
        verify_signed_netmap(&signed, &key.public()).unwrap();
        let mut tampered = signed.clone();
        tampered.netmap.peers[0].overlay_ip = "100.64.0.9".to_string();
        assert!(verify_signed_netmap(&tampered, &key.public()).is_err());
        let mut bad_sig = signed.clone();
        bad_sig.sig.pop();
        assert!(verify_signed_netmap(&bad_sig, &key.public()).is_err());
    }

    #[test]
    fn tampered_grants_are_rejected() {
        use orblx_identity::{ReceiverGrant, ReceiverGrants};

        let key = NetmapKey::generate();
        let grants = ReceiverGrants {
            version: 1,
            receiver: "spiffe://orblx.local/node/box".to_string(),
            grants: vec![ReceiverGrant {
                src: "spiffe://orblx.local/node/mac".to_string(),
                proto: 6,
                port_start: 22,
                port_end: 22,
            }],
            reach: vec!["spiffe://orblx.local/node/mac".to_string()],
            filter: true,
            subnets: Vec::new(),
            guarded: Vec::new(),
        };
        let signed = key.sign_grants(&grants).unwrap();
        super::verify_signed_grants(&signed, &key.public()).unwrap();
        let mut tampered = signed.clone();
        tampered.grants.grants[0].port_start = 5432;
        tampered.grants.grants[0].port_end = 5432;
        assert!(super::verify_signed_grants(&tampered, &key.public()).is_err());
        let mut hidden = signed.clone();
        hidden.grants.reach.clear();
        assert!(super::verify_signed_grants(&hidden, &key.public()).is_err());
        let mut open = signed.clone();
        open.grants.filter = false;
        assert!(super::verify_signed_grants(&open, &key.public()).is_err());
    }

    #[test]
    fn tampered_endpoint_is_rejected() {
        let key = NetmapKey::generate();
        let signed = key.sign_endpoint("server", "10.0.0.2:443").unwrap();
        verify_signed_endpoint(&signed, &key.public()).unwrap();
        let mut tampered = signed.clone();
        tampered.endpoint = "10.0.0.9:443".to_string();
        assert!(verify_signed_endpoint(&tampered, &key.public()).is_err());
    }
}
