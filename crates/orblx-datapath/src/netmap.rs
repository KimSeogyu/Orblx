//! The node netmap.
//!
//! W18-2 writes the same JSON object.
//! The node reads the file. The node does not sign the file.

use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use orblx_identity::SpiffeId;
use serde::{Deserialize, Serialize};

/// One netmap document.
///
/// The JSON key for [`Netmap::self_node`] is `self`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Netmap {
    /// Document version. The node accepts version 1.
    pub version: u32,
    /// This node.
    #[serde(rename = "self")]
    pub self_node: NetmapSelf,
    /// The other nodes.
    pub peers: Vec<NetmapPeer>,
    /// Owner key updates for node lock (W23-1).
    ///
    /// Each update holds an owner signature. A node with a node lock file applies the updates.
    /// An empty list stays out of the JSON text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock: Vec<LockUpdate>,
    /// Split DNS zones from the policy (W24-F).
    ///
    /// The overlay DNS responder sends a query for a name in a zone to the zone nameserver.
    /// An empty list stays out of the JSON text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub split_dns: Vec<SplitDns>,
    /// The netmap sequence number (W25-34).
    ///
    /// The coordinator sets `seq = max(last seq + 1, issued_at_ms)`. The existing netmap
    /// signature covers the field. A node refuses a signed netmap with a lower `seq`.
    /// The value 0 means "no stamp": the node-local `netmap.json` copy has no stamp.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub seq: u64,
    /// The coordinator time of issue in Unix milliseconds (W25-34).
    ///
    /// The existing netmap signature covers the field. The SSH server uses it for the
    /// netmap age check ([`netmap_fresh`]). The value 0 means "no stamp".
    #[serde(default, skip_serializing_if = "is_zero")]
    pub issued_at_ms: u64,
}

/// The maximum netmap age for a new SSH certificate login in milliseconds (W25-34).
pub const NETMAP_MAX_AGE_MS: u64 = 60_000;

/// The maximum clock skew for a netmap stamp in milliseconds (W25-34).
///
/// A node refuses a netmap with `seq` or `issued_at_ms` more than this value in the future.
pub const NETMAP_MAX_SKEW_MS: u64 = 60_000;

/// Return true when a signed `issued_at_ms` is fresh at `now_ms` (W25-34).
///
/// The netmap is fresh when `now_ms - issued_at_ms <= 60 s` and
/// `issued_at_ms <= now_ms + 60 s`. A netmap with no stamp (0) is not fresh.
/// There is no other grace.
#[must_use]
pub fn netmap_fresh(issued_at_ms: u64, now_ms: u64) -> bool {
    issued_at_ms != 0
        && now_ms.saturating_sub(issued_at_ms) <= NETMAP_MAX_AGE_MS
        && issued_at_ms <= now_ms.saturating_add(NETMAP_MAX_SKEW_MS)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// The maximum number of split DNS zones in one netmap (W24-F).
pub const MAX_SPLIT_DNS_ZONES: usize = 32;

/// The maximum number of nameservers for one split DNS zone (W24-F).
pub const MAX_SPLIT_DNS_SERVERS: usize = 4;

/// One split DNS zone (W24-F).
///
/// The policy field `splitDns` maps a DNS domain to nameserver IPv4 addresses.
/// A nameserver is usually behind a subnet router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitDns {
    /// The DNS domain in lowercase, for example `corp.lan`.
    pub domain: String,
    /// The nameserver IPv4 addresses for the domain.
    pub nameservers: Vec<String>,
}

/// Check one split DNS domain (W24-F).
///
/// The domain is lowercase DNS labels. The `orblx` zone is not valid.
/// The root zone is not valid.
#[must_use]
pub fn valid_split_domain(domain: &str) -> bool {
    valid_owner_name(domain)
        && domain == domain.to_ascii_lowercase()
        && domain != "orblx"
        && !domain.ends_with(".orblx")
}

/// Check one split DNS nameserver (W24-F).
///
/// The nameserver is a unicast IPv4 address outside the overlay range 100.64.0.0/10
/// and outside 127.0.0.0/8.
#[must_use]
pub fn valid_split_nameserver(text: &str) -> bool {
    let Ok(ip) = parse_ipv4(text) else {
        return false;
    };
    let octets = ip.octets();
    let overlay = octets[0] == 100 && (octets[1] & 0xc0) == 64;
    ip.to_string() == text && !ip.is_loopback() && !overlay
}

/// The node lock file name in a node state directory.
///
/// The file holds the trusted owner keys. A node with this file accepts a peer
/// only when a trusted owner key signed that peer.
pub const NODE_LOCK_FILE: &str = "node-lock.json";

/// One owner signature for one node (W23-1 node lock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeLockSig {
    /// The owner public key as 64 hex characters.
    pub key_id: String,
    /// The base64 Ed25519 signature.
    pub sig: String,
}

/// One owner key update (W23-1 node lock).
///
/// `keys` is the full trusted key set after the update.
/// A key in the set before the update signs the update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockUpdate {
    /// The lock version after the update. The first update is version 1.
    pub version: u64,
    /// `rotate` or `remove`.
    pub action: String,
    /// The trusted owner keys after the update, as 64 hex characters each.
    pub keys: Vec<String>,
    /// The head hash before the update. Empty for version 1.
    pub prev: String,
    /// The owner key that signed the update.
    pub signer: String,
    /// The base64 Ed25519 signature.
    pub sig: String,
}

/// The local node in a netmap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetmapSelf {
    /// The node name.
    pub name: String,
    /// The overlay IPv4 address.
    pub overlay_ip: String,
    /// The DNS owner label.
    ///
    /// Empty means the node has no `<node>.<owner>.orblx` name.
    /// The short name is still the node name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner: String,
}

/// One remote node in a netmap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetmapPeer {
    /// The peer name.
    pub name: String,
    /// The peer overlay IPv4 address.
    pub overlay_ip: String,
    /// The peer SPIFFE ID. The value is `spiffe://orblx.local/node/{name}`.
    pub svid: String,
    /// Underlay `host:port` values for QUIC.
    pub endpoints: Vec<String>,
    /// Extra destination CIDRs that this peer owns.
    pub routes: Vec<String>,
    /// The coordinator published this peer as an approved exit node.
    ///
    /// The policy `autoApprovers.exitNode` class sets this flag.
    /// A false value stays out of the JSON text.
    #[serde(default, skip_serializing_if = "is_false")]
    pub exit_node: bool,
    /// The DNS owner label.
    ///
    /// Empty means the peer has no `<node>.<owner>.orblx` name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner: String,
    /// The owner signature for node lock (W23-1).
    ///
    /// None stays out of the JSON text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_sig: Option<NodeLockSig>,
}

/// A netmap document is not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetmapError {
    /// The file or the JSON text is not usable.
    Json {
        /// The decoder or file detail.
        detail: String,
    },
    /// The version is not 1.
    Version {
        /// The version from the file.
        version: u32,
    },
    /// The node name is not a SPIFFE name.
    Name {
        /// The rejected name.
        name: String,
    },
    /// The overlay address is not a usable IPv4 address.
    Address {
        /// The rejected address.
        address: String,
    },
    /// The SPIFFE ID does not match the peer name.
    Svid {
        /// The peer name.
        name: String,
        /// The SPIFFE ID from the file.
        svid: String,
    },
    /// The endpoint is not `host:port`.
    Endpoint {
        /// The rejected endpoint.
        endpoint: String,
    },
    /// The CIDR is not a canonical IPv4 prefix.
    Route {
        /// The rejected CIDR.
        route: String,
    },
    /// A name or an overlay address appears twice.
    Duplicate {
        /// The repeated value.
        value: String,
    },
    /// The owner is not a DNS name.
    Owner {
        /// The rejected owner.
        owner: String,
    },
}

impl std::fmt::Display for NetmapError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { detail } => write!(formatter, "The netmap is not valid. {detail}"),
            Self::Version { version } => {
                write!(formatter, "The netmap version is {version}. The node accepts version 1.")
            }
            Self::Name { name } => write!(formatter, "The node name {name} is not valid."),
            Self::Address { address } => {
                write!(formatter, "The overlay address {address} is not valid.")
            }
            Self::Svid { name, svid } => write!(
                formatter,
                "The SPIFFE ID for {name} is {svid}. The node requires spiffe://orblx.local/node/{name}."
            ),
            Self::Endpoint { endpoint } => {
                write!(formatter, "The endpoint {endpoint} is not valid.")
            }
            Self::Route { route } => write!(formatter, "The route {route} is not valid."),
            Self::Duplicate { value } => {
                write!(formatter, "The netmap repeats {value}.")
            }
            Self::Owner { owner } => write!(formatter, "The owner {owner} is not a DNS name."),
        }
    }
}

impl std::error::Error for NetmapError {}

impl Netmap {
    /// Read and check one netmap file.
    pub fn from_path(path: &Path) -> Result<Self, NetmapError> {
        let bytes = fs::read(path).map_err(|err| NetmapError::Json {
            detail: format!("The file {} did not open. {err}", path.display()),
        })?;
        Self::from_slice(&bytes)
    }

    /// Decode and check one netmap document.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, NetmapError> {
        let map: Self = serde_json::from_slice(bytes).map_err(|err| NetmapError::Json {
            detail: err.to_string(),
        })?;
        map.check()?;
        Ok(map)
    }

    /// Return a copy with no stamp (`seq` and `issued_at_ms` are 0) (W25-34).
    ///
    /// The node writes this copy to `netmap.json`. A heartbeat that changes only the stamp
    /// does not change the file, so the datapath does not reload.
    #[must_use]
    pub fn without_stamp(&self) -> Self {
        let mut copy = self.clone();
        copy.seq = 0;
        copy.issued_at_ms = 0;
        copy
    }

    /// Check the fields.
    pub fn check(&self) -> Result<(), NetmapError> {
        if self.version != 1 {
            return Err(NetmapError::Version {
                version: self.version,
            });
        }
        check_name(&self.self_node.name)?;
        check_owner(&self.self_node.owner)?;
        let self_ip = check_overlay(&self.self_node.overlay_ip)?;
        let mut names = HashSet::new();
        let mut addresses = HashSet::new();
        if !names.insert(self.self_node.name.clone()) {
            return Err(NetmapError::Duplicate {
                value: self.self_node.name.clone(),
            });
        }
        if !addresses.insert(self_ip) {
            return Err(NetmapError::Duplicate {
                value: self_ip.to_string(),
            });
        }
        for peer in &self.peers {
            check_name(&peer.name)?;
            check_owner(&peer.owner)?;
            let overlay = check_overlay(&peer.overlay_ip)?;
            check_svid(&peer.name, &peer.svid)?;
            if peer.endpoints.is_empty() {
                return Err(NetmapError::Endpoint {
                    endpoint: peer.name.clone(),
                });
            }
            for endpoint in &peer.endpoints {
                check_endpoint(endpoint)?;
            }
            for route in &peer.routes {
                parse_cidr(route)?;
            }
            if !names.insert(peer.name.clone()) {
                return Err(NetmapError::Duplicate {
                    value: peer.name.clone(),
                });
            }
            if !addresses.insert(overlay) {
                return Err(NetmapError::Duplicate {
                    value: overlay.to_string(),
                });
            }
        }
        check_split_dns(&self.split_dns)
    }
}

fn check_split_dns(zones: &[SplitDns]) -> Result<(), NetmapError> {
    if zones.len() > MAX_SPLIT_DNS_ZONES {
        return Err(NetmapError::Json {
            detail: "The netmap has too many split DNS zones.".to_string(),
        });
    }
    let mut seen = HashSet::new();
    for zone in zones {
        if !valid_split_domain(&zone.domain) {
            return Err(NetmapError::Owner {
                owner: zone.domain.clone(),
            });
        }
        if !seen.insert(zone.domain.clone()) {
            return Err(NetmapError::Duplicate {
                value: zone.domain.clone(),
            });
        }
        if zone.nameservers.is_empty() || zone.nameservers.len() > MAX_SPLIT_DNS_SERVERS {
            return Err(NetmapError::Json {
                detail: format!(
                    "The split DNS zone {} needs 1 to {MAX_SPLIT_DNS_SERVERS} nameservers.",
                    zone.domain
                ),
            });
        }
        for server in &zone.nameservers {
            if !valid_split_nameserver(server) {
                return Err(NetmapError::Address {
                    address: server.clone(),
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_ipv4(text: &str) -> Result<Ipv4Addr, NetmapError> {
    let address = text.parse::<Ipv4Addr>().map_err(|_| NetmapError::Address {
        address: text.to_string(),
    })?;
    if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
        return Err(NetmapError::Address {
            address: text.to_string(),
        });
    }
    Ok(address)
}

pub(crate) fn parse_cidr(text: &str) -> Result<(Ipv4Addr, u8), NetmapError> {
    let (addr, prefix_text) = text.split_once('/').ok_or_else(|| NetmapError::Route {
        route: text.to_string(),
    })?;
    if prefix_text.is_empty()
        || (prefix_text.len() > 1 && prefix_text.starts_with('0'))
        || !prefix_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(NetmapError::Route {
            route: text.to_string(),
        });
    }
    let prefix_len: u32 = prefix_text.parse().map_err(|_| NetmapError::Route {
        route: text.to_string(),
    })?;
    if prefix_len > 32 {
        return Err(NetmapError::Route {
            route: text.to_string(),
        });
    }
    let prefix_len = u8::try_from(prefix_len).map_err(|_| NetmapError::Route {
        route: text.to_string(),
    })?;
    let ip = addr.parse::<Ipv4Addr>().map_err(|_| NetmapError::Route {
        route: text.to_string(),
    })?;
    if u32::from(ip) & !ipv4_mask(prefix_len) != 0 {
        return Err(NetmapError::Route {
            route: text.to_string(),
        });
    }
    Ok((ip, prefix_len))
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn check_owner(owner: &str) -> Result<(), NetmapError> {
    if owner.is_empty() || valid_owner_name(owner) {
        return Ok(());
    }
    Err(NetmapError::Owner {
        owner: owner.to_string(),
    })
}

/// The owner is one or more DNS labels.
///
/// An empty owner is not valid here. The caller allows an empty owner.
pub(crate) fn valid_owner_name(owner: &str) -> bool {
    if owner.is_empty() || owner.len() > 253 {
        return false;
    }
    owner.split('.').all(valid_ldh_label)
}

fn valid_ldh_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn check_name(name: &str) -> Result<(), NetmapError> {
    SpiffeId::node(name)
        .map(|_| ())
        .map_err(|_| NetmapError::Name {
            name: name.to_string(),
        })
}

fn check_overlay(text: &str) -> Result<Ipv4Addr, NetmapError> {
    parse_ipv4(text)
}

fn check_svid(name: &str, svid: &str) -> Result<(), NetmapError> {
    let expected = SpiffeId::node(name).map_err(|_| NetmapError::Name {
        name: name.to_string(),
    })?;
    if svid != expected.as_uri() {
        return Err(NetmapError::Svid {
            name: name.to_string(),
            svid: svid.to_string(),
        });
    }
    Ok(())
}

fn check_endpoint(text: &str) -> Result<(), NetmapError> {
    let Some((host, port_text)) = text.rsplit_once(':') else {
        return Err(NetmapError::Endpoint {
            endpoint: text.to_string(),
        });
    };
    if host.is_empty() || host.contains(':') {
        return Err(NetmapError::Endpoint {
            endpoint: text.to_string(),
        });
    }
    let port: u16 = port_text.parse().map_err(|_| NetmapError::Endpoint {
        endpoint: text.to_string(),
    })?;
    if port == 0 {
        return Err(NetmapError::Endpoint {
            endpoint: text.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Netmap, NetmapError};

    fn sample() -> &'static str {
        r#"{
            "version": 1,
            "self": {"name": "a", "overlay_ip": "100.64.0.1"},
            "peers": [{
                "name": "b",
                "overlay_ip": "100.64.0.2",
                "svid": "spiffe://orblx.local/node/b",
                "endpoints": ["172.28.18.12:443"],
                "routes": ["10.1.0.0/24"]
            }]
        }"#
    }

    #[test]
    fn json_round_trip_keeps_the_self_key() {
        let map = Netmap::from_slice(sample().as_bytes()).unwrap();
        assert_eq!(map.version, 1);
        assert_eq!(map.self_node.name, "a");
        assert_eq!(map.peers[0].svid, "spiffe://orblx.local/node/b");
        let text = serde_json::to_string(&map).unwrap();
        assert!(text.contains("\"self\""));
        let again = Netmap::from_slice(text.as_bytes()).unwrap();
        assert_eq!(again, map);
    }

    #[test]
    fn version_2_is_rejected() {
        let text = sample().replace("\"version\": 1", "\"version\": 2");
        let err = Netmap::from_slice(text.as_bytes()).unwrap_err();
        assert_eq!(err, NetmapError::Version { version: 2 });
    }

    #[test]
    fn a_mismatched_svid_is_rejected() {
        let text = sample().replace(
            "spiffe://orblx.local/node/b",
            "spiffe://orblx.local/node/other",
        );
        let err = Netmap::from_slice(text.as_bytes()).unwrap_err();
        assert!(matches!(err, NetmapError::Svid { .. }));
    }

    #[test]
    fn a_host_bit_in_a_route_is_rejected() {
        let text = sample().replace("10.1.0.0/24", "10.1.0.9/24");
        let err = Netmap::from_slice(text.as_bytes()).unwrap_err();
        assert!(matches!(err, NetmapError::Route { .. }));
    }

    #[test]
    fn an_empty_owner_stays_out_of_the_json() {
        let map = Netmap::from_slice(sample().as_bytes()).unwrap();
        assert!(map.self_node.owner.is_empty());
        assert!(map.peers[0].owner.is_empty());
        let text = serde_json::to_string(&map).unwrap();
        assert!(!text.contains("owner"));
    }

    #[test]
    fn an_owner_round_trips() {
        let text = sample().replace(
            r#""name": "a", "overlay_ip": "100.64.0.1""#,
            r#""name": "a", "overlay_ip": "100.64.0.1", "owner": "lab""#,
        );
        let map = Netmap::from_slice(text.as_bytes()).unwrap();
        assert_eq!(map.self_node.owner, "lab");
        let again = serde_json::to_string(&map).unwrap();
        assert!(again.contains("\"owner\":\"lab\""));
    }

    #[test]
    fn a_bad_owner_is_rejected() {
        let text = sample().replace(
            r#""name": "a", "overlay_ip": "100.64.0.1""#,
            r#""name": "a", "overlay_ip": "100.64.0.1", "owner": "no owner""#,
        );
        let err = Netmap::from_slice(text.as_bytes()).unwrap_err();
        assert!(matches!(err, NetmapError::Owner { .. }));
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let text = sample().replace("\"version\": 1", "\"version\": 1, \"extra\": true");
        let err = Netmap::from_slice(text.as_bytes()).unwrap_err();
        assert!(matches!(err, NetmapError::Json { .. }));
    }

    fn with_split(zone: &str) -> String {
        sample().replace(
            "\"version\": 1,",
            &format!("\"version\": 1, \"split_dns\": [{zone}],"),
        )
    }

    #[test]
    fn a_split_dns_zone_round_trips() {
        let text = with_split(r#"{"domain": "corp.lan", "nameservers": ["10.88.0.53"]}"#);
        let map = Netmap::from_slice(text.as_bytes()).unwrap();
        assert_eq!(map.split_dns.len(), 1);
        assert_eq!(map.split_dns[0].domain, "corp.lan");
        let again = serde_json::to_string(&map).unwrap();
        assert!(again.contains("\"split_dns\""));
        assert_eq!(Netmap::from_slice(again.as_bytes()).unwrap(), map);
    }

    #[test]
    fn no_split_dns_stays_out_of_the_json() {
        let map = Netmap::from_slice(sample().as_bytes()).unwrap();
        let text = serde_json::to_string(&map).unwrap();
        assert!(!text.contains("split_dns"));
    }

    #[test]
    fn a_bad_split_dns_zone_is_rejected() {
        for zone in [
            r#"{"domain": "lab.orblx", "nameservers": ["10.88.0.53"]}"#,
            r#"{"domain": "orblx", "nameservers": ["10.88.0.53"]}"#,
            r#"{"domain": "Corp.lan", "nameservers": ["10.88.0.53"]}"#,
            r#"{"domain": "corp lan", "nameservers": ["10.88.0.53"]}"#,
            r#"{"domain": "corp.lan", "nameservers": []}"#,
            r#"{"domain": "corp.lan", "nameservers": ["100.64.0.9"]}"#,
            r#"{"domain": "corp.lan", "nameservers": ["127.0.0.1"]}"#,
            r#"{"domain": "corp.lan", "nameservers": ["10.88.0.053"]}"#,
            r#"{"domain": "corp.lan", "nameservers": ["10.88.0.53"]}, {"domain": "corp.lan", "nameservers": ["10.88.0.54"]}"#,
        ] {
            assert!(
                Netmap::from_slice(with_split(zone).as_bytes()).is_err(),
                "{zone}"
            );
        }
    }
}
