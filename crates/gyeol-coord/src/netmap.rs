use std::net::Ipv4Addr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gyeol_datapath::{Netmap, NetmapError};
use gyeol_edge::endpoint_sign_payload;
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
    use gyeol_datapath::{Netmap, NetmapPeer, NetmapSelf};

    use super::{verify_signed_endpoint, verify_signed_netmap, NetmapKey};

    fn sample() -> Netmap {
        Netmap {
            version: 1,
            self_node: NetmapSelf {
                name: "server".to_string(),
                overlay_ip: "100.64.0.1".to_string(),
            },
            peers: vec![NetmapPeer {
                name: "laptop".to_string(),
                overlay_ip: "100.64.0.2".to_string(),
                svid: "spiffe://gyeol.local/node/laptop".to_string(),
                endpoints: vec!["10.0.0.2:443".to_string()],
                routes: vec!["192.168.1.0/24".to_string()],
            }],
        }
    }

    #[test]
    fn payload_json_matches_the_w18_schema() {
        let text = serde_json::to_string(&sample()).unwrap();
        assert_eq!(
            text,
            r#"{"version":1,"self":{"name":"server","overlay_ip":"100.64.0.1"},"peers":[{"name":"laptop","overlay_ip":"100.64.0.2","svid":"spiffe://gyeol.local/node/laptop","endpoints":["10.0.0.2:443"],"routes":["192.168.1.0/24"]}]}"#
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
    fn tampered_endpoint_is_rejected() {
        let key = NetmapKey::generate();
        let signed = key.sign_endpoint("server", "10.0.0.2:443").unwrap();
        verify_signed_endpoint(&signed, &key.public()).unwrap();
        let mut tampered = signed.clone();
        tampered.endpoint = "10.0.0.9:443".to_string();
        assert!(verify_signed_endpoint(&tampered, &key.public()).is_err());
    }
}
