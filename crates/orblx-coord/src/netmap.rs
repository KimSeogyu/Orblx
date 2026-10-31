use std::net::Ipv4Addr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use orblx_datapath::{Netmap, NetmapError};
use orblx_edge::endpoint_sign_payload;
use orblx_identity::ReceiverGrants;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::CoordError;
use crate::ippool::is_overlay_ip;

/// One signed netmap document that passed the signature check, or that this coordinator signed.
///
/// `sig` is the base64 Ed25519 signature over the exact bytes of the `netmap` JSON object.
/// The type keeps those bytes (W25-34). The JSON text of the type puts those bytes back
/// unchanged. The type has no `Deserialize`: a reader gets the type only from
/// [`verify_netmap_wire`], which checks the signature over the received bytes first and
/// then parses them.
#[derive(Debug, Clone)]
pub struct SignedNetmap {
    pub netmap: Netmap,
    pub sig: String,
    pub key_id: String,
    signed_bytes: Box<RawValue>,
}

impl PartialEq for SignedNetmap {
    fn eq(&self, other: &Self) -> bool {
        self.netmap == other.netmap
            && self.sig == other.sig
            && self.key_id == other.key_id
            && self.signed_bytes.get() == other.signed_bytes.get()
    }
}

impl Eq for SignedNetmap {}

impl SignedNetmap {
    /// The exact signed bytes of the `netmap` object.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        self.signed_bytes.get().as_bytes()
    }

    /// The wire form with the exact signed bytes.
    #[must_use]
    pub fn to_wire(&self) -> SignedNetmapWire {
        SignedNetmapWire {
            netmap: self.signed_bytes.clone(),
            sig: self.sig.clone(),
            key_id: self.key_id.clone(),
        }
    }
}

impl Serialize for SignedNetmap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_wire().serialize(serializer)
    }
}

/// The received form of one signed netmap (W25-34).
///
/// `netmap` holds the received bytes of the JSON object, with no parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetmapWire {
    pub netmap: Box<RawValue>,
    pub sig: String,
    pub key_id: String,
}

/// The receiver grant set, signed with the netmap key.
///
/// `sig` is the base64 Ed25519 signature over the canonical JSON of `grants`.
/// The type keeps the exact signed bytes of `grants` (W25-34), as [`SignedNetmap`] does.
/// A reader gets the type only from [`verify_grants_wire`].
#[derive(Debug, Clone)]
pub struct SignedGrants {
    pub grants: ReceiverGrants,
    pub sig: String,
    pub key_id: String,
    signed_bytes: Box<RawValue>,
}

impl PartialEq for SignedGrants {
    fn eq(&self, other: &Self) -> bool {
        self.grants == other.grants
            && self.sig == other.sig
            && self.key_id == other.key_id
            && self.signed_bytes.get() == other.signed_bytes.get()
    }
}

impl Eq for SignedGrants {}

impl SignedGrants {
    /// The exact bytes that the signature covers.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        self.signed_bytes.get().as_bytes()
    }

    /// The SHA-256 of the signed bytes in lowercase hex (W25-34 grants binding).
    ///
    /// The coordinator puts this value in [`Netmap::grants_sha256`] of the signed netmap.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        encode_hex(&Sha256::digest(self.signed_bytes()))
    }

    /// The wire form with the exact signed bytes.
    #[must_use]
    pub fn to_wire(&self) -> SignedGrantsWire {
        SignedGrantsWire {
            grants: self.signed_bytes.clone(),
            sig: self.sig.clone(),
            key_id: self.key_id.clone(),
        }
    }
}

impl Serialize for SignedGrants {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_wire().serialize(serializer)
    }
}

/// The received form of one signed grant set (W25-34).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrantsWire {
    pub grants: Box<RawValue>,
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
            signed_bytes: raw_value(&bytes)?,
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
            signed_bytes: raw_value(&bytes)?,
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

/// Check the signature of one received netmap over the received bytes, then parse them (W25-34).
///
/// The parse uses `deny_unknown_fields`. There is no parse before the signature check.
pub fn verify_netmap_wire(
    wire: &SignedNetmapWire,
    public: &[u8; 32],
) -> Result<SignedNetmap, CoordError> {
    if wire.key_id != encode_hex(public) {
        return Err(CoordError::Signature);
    }
    let bytes = wire.netmap.get().as_bytes();
    verify_b64(public, bytes, &wire.sig)?;
    let netmap: Netmap = serde_json::from_slice(bytes)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    validate_payload(&netmap)?;
    Ok(SignedNetmap {
        netmap,
        sig: wire.sig.clone(),
        key_id: wire.key_id.clone(),
        signed_bytes: raw_value(bytes)?,
    })
}

/// Check the signature of one received grant set over the received bytes, then parse them
/// (W25-34).
pub fn verify_grants_wire(
    wire: &SignedGrantsWire,
    public: &[u8; 32],
) -> Result<SignedGrants, CoordError> {
    if wire.key_id != encode_hex(public) {
        return Err(CoordError::Signature);
    }
    let bytes = wire.grants.get().as_bytes();
    verify_b64(public, bytes, &wire.sig)?;
    let grants: ReceiverGrants = serde_json::from_slice(bytes)
        .map_err(|_| CoordError::Protocol("The grants are not valid.".to_string()))?;
    grants
        .check()
        .map_err(|err| CoordError::Protocol(err.to_string()))?;
    Ok(SignedGrants {
        grants,
        sig: wire.sig.clone(),
        key_id: wire.key_id.clone(),
        signed_bytes: raw_value(bytes)?,
    })
}

/// Parse and check one signed grant file text (W25-34).
pub fn grants_from_slice(bytes: &[u8], public: &[u8; 32]) -> Result<SignedGrants, CoordError> {
    let wire: SignedGrantsWire = serde_json::from_slice(bytes)
        .map_err(|_| CoordError::Protocol("The grants are not valid.".to_string()))?;
    verify_grants_wire(&wire, public)
}

/// Parse and check one signed netmap file text (W25-34).
pub fn netmap_from_slice(bytes: &[u8], public: &[u8; 32]) -> Result<SignedNetmap, CoordError> {
    let wire: SignedNetmapWire = serde_json::from_slice(bytes)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    verify_netmap_wire(&wire, public)
}

/// Check one signed netmap over its kept bytes.
///
/// The struct must be the parse of those bytes. A changed field makes the check fail.
pub fn verify_signed_netmap(signed: &SignedNetmap, public: &[u8; 32]) -> Result<(), CoordError> {
    let checked = verify_netmap_wire(&signed.to_wire(), public)?;
    if checked.netmap != signed.netmap || checked.sig != signed.sig {
        return Err(CoordError::Signature);
    }
    Ok(())
}

/// Check one signed grant set over its kept bytes.
pub fn verify_signed_grants(signed: &SignedGrants, public: &[u8; 32]) -> Result<(), CoordError> {
    let checked = verify_grants_wire(&signed.to_wire(), public)?;
    if checked.grants != signed.grants || checked.sig != signed.sig {
        return Err(CoordError::Signature);
    }
    Ok(())
}

/// Read and check the signed netmap in one node state directory (W25-34).
///
/// The function reads `netmap.signed.json` and `netmap.pub`, checks the signature over the
/// stored bytes, then parses them. An SSH certificate login uses the signed `issued_at_ms`
/// of the result with [`orblx_datapath::netmap_fresh`].
pub fn read_verified_netmap(state_dir: &std::path::Path) -> Result<SignedNetmap, CoordError> {
    let public_text =
        std::fs::read_to_string(state_dir.join("netmap.pub")).map_err(CoordError::io)?;
    let public = decode_hex_32(public_text.trim())?;
    let bytes = std::fs::read(state_dir.join("netmap.signed.json")).map_err(CoordError::io)?;
    netmap_from_slice(&bytes, &public)
}

fn raw_value(bytes: &[u8]) -> Result<Box<RawValue>, CoordError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoordError::Protocol("The signed bytes are not valid.".to_string()))?;
    RawValue::from_string(text.to_string())
        .map_err(|_| CoordError::Protocol("The signed bytes are not valid.".to_string()))
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

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

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
            seq: 0,
            issued_at_ms: 0,
            grants_sha256: String::new(),
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
    fn tampered_stamp_is_rejected() {
        // W25-34: seq and issued_at_ms are inside the existing netmap signature.
        let key = NetmapKey::generate();
        let mut stamped = sample();
        stamped.seq = 1_800_000_000_000;
        stamped.issued_at_ms = 1_800_000_000_000;
        let signed = key.sign_netmap(&stamped).unwrap();
        verify_signed_netmap(&signed, &key.public()).unwrap();
        let mut seq = signed.clone();
        seq.netmap.seq += 1;
        assert!(verify_signed_netmap(&seq, &key.public()).is_err());
        let mut issued = signed.clone();
        issued.netmap.issued_at_ms += 1;
        assert!(verify_signed_netmap(&issued, &key.public()).is_err());
        // The same change in the received bytes fails too.
        let text = serde_json::to_string(&signed).unwrap();
        let bumped = text.replace("1800000000000,", "1800000000001,");
        assert_ne!(bumped, text);
        assert!(super::netmap_from_slice(bumped.as_bytes(), &key.public()).is_err());
        let back = super::netmap_from_slice(text.as_bytes(), &key.public()).unwrap();
        assert_eq!(back, signed);
    }

    #[test]
    fn verify_uses_the_received_bytes_then_parses() {
        use ed25519_dalek::Signer;
        let key = NetmapKey::generate();
        // Bytes that are not the canonical form of the struct still verify: the check uses
        // the received bytes, not a new serialization.
        let pretty = serde_json::to_string_pretty(&sample()).unwrap();
        let sig = STANDARD.encode(key.signing.sign(pretty.as_bytes()).to_bytes());
        let wire = format!(
            r#"{{"netmap":{pretty},"sig":"{sig}","key_id":"{}"}}"#,
            key.key_id()
        );
        let signed = super::netmap_from_slice(wire.as_bytes(), &key.public()).unwrap();
        assert_eq!(signed.netmap, sample());
        assert_eq!(signed.signed_bytes(), pretty.as_bytes());
        assert_eq!(serde_json::to_string(&signed).unwrap(), wire);
        // A signed netmap with an unknown field fails the parse after the check.
        let extra = r#"{"version":1,"self":{"name":"server","overlay_ip":"100.64.0.1"},"peers":[],"extra":1}"#;
        let sig = STANDARD.encode(key.signing.sign(extra.as_bytes()).to_bytes());
        let wire = format!(
            r#"{{"netmap":{extra},"sig":"{sig}","key_id":"{}"}}"#,
            key.key_id()
        );
        assert!(super::netmap_from_slice(wire.as_bytes(), &key.public()).is_err());
        // A duplicate key is refused by the parse.
        let dup = r#"{"version":1,"version":1,"self":{"name":"server","overlay_ip":"100.64.0.1"},"peers":[]}"#;
        let sig = STANDARD.encode(key.signing.sign(dup.as_bytes()).to_bytes());
        let wire = format!(
            r#"{{"netmap":{dup},"sig":"{sig}","key_id":"{}"}}"#,
            key.key_id()
        );
        assert!(super::netmap_from_slice(wire.as_bytes(), &key.public()).is_err());
        // An unknown field next to the netmap is refused.
        let text = serde_json::to_string(&key.sign_netmap(&sample()).unwrap()).unwrap();
        let outer = text.replacen('{', r#"{"seq":9,"#, 1);
        assert!(super::netmap_from_slice(outer.as_bytes(), &key.public()).is_err());
    }

    #[test]
    fn grants_verify_uses_the_received_bytes() {
        use ed25519_dalek::Signer;
        let key = NetmapKey::generate();
        let grants =
            r#"{ "version": 1, "receiver": "spiffe://orblx.local/node/box", "grants": [] }"#;
        let sig = STANDARD.encode(key.signing.sign(grants.as_bytes()).to_bytes());
        let wire = format!(
            r#"{{"grants":{grants},"sig":"{sig}","key_id":"{}"}}"#,
            key.key_id()
        );
        let signed = super::grants_from_slice(wire.as_bytes(), &key.public()).unwrap();
        assert_eq!(signed.grants.receiver, "spiffe://orblx.local/node/box");
        super::verify_signed_grants(&signed, &key.public()).unwrap();
        assert_eq!(serde_json::to_string(&signed).unwrap(), wire);
        let tampered = wire.replace("\"grants\": []", "\"grants\":  []");
        assert!(super::grants_from_slice(tampered.as_bytes(), &key.public()).is_err());
    }

    /// W25-34 CI guard: the signed netmap and grant structs keep a strict JSON form.
    ///
    /// The test fails when one of these structs loses `deny_unknown_fields`, or gets a map,
    /// a float, `untagged`, or `flatten`, or when a new struct is not in the list.
    /// Crypto re-review: it also fails on a serde attribute that changes the parse
    /// (`from`, `try_from`, `transparent`, `remote`, `deserialize_with`, `with`, `alias`,
    /// `other`, `bound`), on a field that is not `pub`, and on a new grant struct in the
    /// identity crate that is not in the list.
    #[test]
    fn signed_structs_keep_a_strict_form() {
        let datapath = include_str!("../../orblx-datapath/src/netmap.rs");
        let identity = include_str!("../../orblx-identity/src/policy.rs");
        let coord = include_str!("netmap.rs");
        let datapath_types = [
            "Netmap",
            "SplitDns",
            "NodeLockSig",
            "LockUpdate",
            "NetmapSelf",
            "NetmapPeer",
        ];
        let identity_types = ["ReceiverGrants", "ReceiverGrant", "SubnetGrant"];
        let coord_types = ["SignedNetmapWire", "SignedGrantsWire"];
        let mut known: Vec<&str> = datapath_types.to_vec();
        known.extend(identity_types);
        known.extend(coord_types);
        for (text, names) in [
            (datapath, &datapath_types[..]),
            (identity, &identity_types[..]),
            (coord, &coord_types[..]),
        ] {
            for name in names {
                check_strict(text, name, &known);
            }
        }
        // Each struct in the datapath netmap file is in the list.
        for line in datapath.lines() {
            if let Some(rest) = line.strip_prefix("pub struct ") {
                let name = rest.split([' ', '{', '(']).next().unwrap();
                assert!(datapath_types.contains(&name), "add {name} to the guard");
            }
        }
        // Each grant struct in the identity policy file is in the list.
        for line in identity.lines() {
            if let Some(rest) = line.strip_prefix("pub struct ") {
                let name = rest.split([' ', '{', '(', '<']).next().unwrap();
                if name.contains("Grant") {
                    assert!(identity_types.contains(&name), "add {name} to the guard");
                }
            }
        }
    }

    /// The guard catches each parse-changing serde attribute and a private field.
    #[test]
    fn strict_form_guard_catches_parse_changing_attributes() {
        for attr in [
            "#[serde(from = \"Other\")]",
            "#[serde(try_from = \"Other\")]",
            "#[serde(transparent)]",
            "#[serde(remote = \"Other\")]",
        ] {
            let text = format!(
                "#[serde(deny_unknown_fields)]\n{attr}\npub struct Probe {{\n    pub a: u64,\n}}\n"
            );
            assert!(strict_problem(&text, "Probe", &[]).is_some(), "{attr}");
        }
        for field_attr in [
            "#[serde(deserialize_with = \"f\")]",
            "#[serde(with = \"m\")]",
            "#[serde(alias = \"b\")]",
            "#[serde(other)]",
            "#[serde(bound = \"\")]",
        ] {
            let text = format!(
                "#[serde(deny_unknown_fields)]\npub struct Probe {{\n    {field_attr}\n    pub a: u64,\n}}\n"
            );
            assert!(
                strict_problem(&text, "Probe", &[]).is_some(),
                "{field_attr}"
            );
        }
        let private = "#[serde(deny_unknown_fields)]\npub struct Probe {\n    a: u64,\n}\n";
        assert!(strict_problem(private, "Probe", &[]).is_some());
        let crate_field =
            "#[serde(deny_unknown_fields)]\npub struct Probe {\n    pub(crate) a: u64,\n}\n";
        assert!(strict_problem(crate_field, "Probe", &[]).is_some());
        let good = "#[serde(deny_unknown_fields)]\npub struct Probe {\n    #[serde(default, skip_serializing_if = \"is_zero\")]\n    pub a: u64,\n}\n";
        assert_eq!(strict_problem(good, "Probe", &[]), None);
    }

    fn check_strict(text: &str, name: &str, known: &[&str]) {
        if let Some(problem) = strict_problem(text, name, known) {
            panic!("{problem}");
        }
    }

    /// The serde attribute words that change how a struct or a field parses.
    const PARSE_CHANGING: [&str; 9] = [
        "from =",
        "try_from",
        "transparent",
        "remote",
        "deserialize_with",
        "with =",
        "alias",
        "other",
        "bound",
    ];

    fn strict_problem(text: &str, name: &str, known: &[&str]) -> Option<String> {
        let lines: Vec<&str> = text.lines().collect();
        let Some(start) = lines
            .iter()
            .position(|line| line.trim() == format!("pub struct {name} {{"))
        else {
            return Some(format!("the guard did not find {name}"));
        };
        let mut attrs = Vec::new();
        for line in lines[..start].iter().rev() {
            let line = line.trim();
            if line.starts_with("#[") {
                attrs.push(line);
            } else if !line.starts_with("///") {
                break;
            }
        }
        if !attrs.contains(&"#[serde(deny_unknown_fields)]") {
            return Some(format!("{name} has no deny_unknown_fields"));
        }
        for attr in attrs.iter().filter(|attr| attr.starts_with("#[serde(")) {
            if let Some(word) = PARSE_CHANGING.iter().find(|word| attr.contains(*word)) {
                return Some(format!("{name} has the serde attribute {word}"));
            }
        }
        let end = start + lines[start..].iter().position(|line| *line == "}")?;
        let body = lines[start..=end].join("\n");
        let body = body.replace("Box<RawValue>", "");
        for word in [
            "untagged", "flatten", "HashMap", "BTreeMap", "f32", "f64", "Value",
        ] {
            if body.contains(word) {
                return Some(format!("{name} has {word}"));
            }
        }
        for line in &lines[start + 1..end] {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            if line.starts_with("#[") {
                if line.starts_with("#[serde(") {
                    if let Some(word) = PARSE_CHANGING.iter().find(|word| line.contains(*word)) {
                        return Some(format!("{name} has the field serde attribute {word}"));
                    }
                }
                continue;
            }
            let Some(field) = line.strip_prefix("pub ") else {
                return Some(format!("{name} has a field that is not pub: {line}"));
            };
            let Some((_, ty)) = field.split_once(": ") else {
                return Some(format!("{name} has a field the guard cannot read: {line}"));
            };
            let ty = ty.trim_end_matches(',');
            if !allowed_type(ty, known) {
                return Some(format!("{name} has the field type {ty}"));
            }
        }
        None
    }

    fn allowed_type(ty: &str, known: &[&str]) -> bool {
        const PLAIN: [&str; 7] = ["String", "bool", "u8", "u16", "u32", "u64", "Box<RawValue>"];
        if PLAIN.contains(&ty) || known.contains(&ty) {
            return true;
        }
        for wrap in ["Vec<", "Option<"] {
            if let Some(inner) = ty.strip_prefix(wrap).and_then(|ty| ty.strip_suffix('>')) {
                return allowed_type(inner, known);
            }
        }
        false
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
