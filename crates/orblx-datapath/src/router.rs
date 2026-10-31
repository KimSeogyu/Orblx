//! The overlay router table.
//!
//! Each outbound TUN packet uses the destination address.
//! The longest matching prefix selects the peer.
//!
//! W25 HA subnet routers: two or more peers can own the same subnet prefix.
//! The table keeps all of them as candidates, sorted by name.
//! [`crate::RouteSelector`] picks the active candidate from the session health.
//! An overlay `/32` address always has one owner.

use std::net::Ipv4Addr;

use crate::ipv4::ipv4_destination;
use crate::netmap::{ipv4_mask, parse_cidr, parse_ipv4, Netmap, NetmapError};

/// One destination prefix that a peer owns.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    /// The peers that own the prefix, sorted by name.
    /// An overlay `/32` route has one peer.
    peers: Vec<String>,
    prefix: Ipv4Addr,
    prefix_len: u8,
    /// True when the prefix is the overlay address of a peer.
    overlay: bool,
}

/// The peers that can carry one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteMatch<'a> {
    /// The matched prefix, for example `10.88.0.0/24`.
    pub prefix: Ipv4Addr,
    /// The matched prefix length.
    pub prefix_len: u8,
    /// The candidate peers, sorted by name. The list is not empty.
    pub peers: &'a [String],
}

impl RouteMatch<'_> {
    /// Return true when two or more peers own the prefix (an HA route).
    #[must_use]
    pub fn is_ha(&self) -> bool {
        self.peers.len() > 1
    }
}

/// The routes from one netmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterTable {
    routes: Vec<Route>,
    exits: Vec<String>,
}

/// The router rejected a netmap route.
#[derive(Debug)]
pub enum RouterError {
    /// The netmap check failed.
    Netmap(NetmapError),
    /// Two peers own the same overlay address,
    /// or a subnet route covers exactly the overlay address of another peer.
    Ambiguous {
        /// The CIDR that two peers own.
        cidr: String,
    },
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Netmap(err) => write!(formatter, "{err}"),
            Self::Ambiguous { cidr } => {
                write!(formatter, "The CIDR {cidr} belongs to two peers.")
            }
        }
    }
}

impl std::error::Error for RouterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Netmap(err) => Some(err),
            Self::Ambiguous { .. } => None,
        }
    }
}

impl RouterTable {
    /// Build the table from a netmap.
    ///
    /// Each peer owns `overlay_ip/32`.
    /// Each peer also owns the CIDRs in `routes`.
    pub fn from_netmap(map: &Netmap) -> Result<Self, RouterError> {
        map.check().map_err(RouterError::Netmap)?;
        let mut table = Self {
            routes: Vec::new(),
            exits: Vec::new(),
        };
        for peer in &map.peers {
            let overlay = parse_ipv4(&peer.overlay_ip).map_err(RouterError::Netmap)?;
            table.insert(&peer.name, overlay, 32, &format!("{overlay}/32"), true)?;
            if peer.exit_node {
                table.exits.push(peer.name.clone());
            }
            for route in &peer.routes {
                let (prefix, prefix_len) = parse_cidr(route).map_err(RouterError::Netmap)?;
                if prefix_len == 0 {
                    continue;
                }
                table.insert(&peer.name, prefix, prefix_len, route, false)?;
            }
        }
        Ok(table)
    }

    /// Return true when the netmap lists `name` as an approved exit node.
    #[must_use]
    pub fn is_exit(&self, name: &str) -> bool {
        self.exits.iter().any(|peer| peer == name)
    }

    /// Return the peer that owns `dest`.
    ///
    /// The longest prefix wins.
    /// A prefix of length 0 is an exit route. This function skips it.
    /// The function returns `None` when no prefix owns `dest`.
    #[must_use]
    pub fn lookup(&self, dest: Ipv4Addr) -> Option<&str> {
        self.lookup_for(dest, true)
    }

    /// Return the peer that owns `dest` for the routes this node accepts.
    ///
    /// Overlay `/32` routes stay active.
    /// A subnet route is active when `accept_routes` is true.
    /// A prefix of length 0 stays outside the TUN.
    #[must_use]
    pub fn lookup_for(&self, dest: Ipv4Addr, accept_routes: bool) -> Option<&str> {
        self.lookup_exit(dest, accept_routes, None)
    }

    /// Return the peer that owns `dest`.
    ///
    /// `exit` is the selected exit node name.
    /// The function uses that peer for a destination with no longer prefix.
    /// A name that is not an approved exit node is not used.
    #[must_use]
    pub fn lookup_exit(
        &self,
        dest: Ipv4Addr,
        accept_routes: bool,
        exit: Option<&str>,
    ) -> Option<&str> {
        if let Some(found) = self.lookup_match(dest, accept_routes) {
            return found.peers.first().map(String::as_str);
        }
        let name = exit?;
        if self.is_exit(name) {
            Some(self.exits.iter().find(|peer| *peer == name)?.as_str())
        } else {
            None
        }
    }

    /// Return the longest prefix that owns `dest`, with all its candidate peers.
    ///
    /// The function skips a prefix of length 0.
    /// A subnet prefix is active only when `accept_routes` is true.
    #[must_use]
    pub fn lookup_match(&self, dest: Ipv4Addr, accept_routes: bool) -> Option<RouteMatch<'_>> {
        let dest_bits = u32::from(dest);
        let mut best: Option<&Route> = None;
        for route in &self.routes {
            if !route_is_active(route.prefix_len, accept_routes) {
                continue;
            }
            let mask = ipv4_mask(route.prefix_len);
            if dest_bits & mask != u32::from(route.prefix) {
                continue;
            }
            let replace = match best {
                Some(current) => route.prefix_len > current.prefix_len,
                None => true,
            };
            if replace {
                best = Some(route);
            }
        }
        best.map(|route| RouteMatch {
            prefix: route.prefix,
            prefix_len: route.prefix_len,
            peers: &route.peers,
        })
    }

    /// Return each prefix that two or more peers own, with the peers.
    #[must_use]
    pub fn ha_routes(&self) -> Vec<(String, Vec<String>)> {
        self.routes
            .iter()
            .filter(|route| route.peers.len() > 1)
            .map(|route| {
                (
                    format!("{}/{}", route.prefix, route.prefix_len),
                    route.peers.clone(),
                )
            })
            .collect()
    }

    /// Return the CIDRs that the kernel should send into the TUN device.
    #[must_use]
    pub fn destinations(&self) -> Vec<String> {
        self.install_cidrs(true)
    }

    /// Return the CIDRs to install on the TUN device.
    ///
    /// The node always installs overlay `/32` routes.
    /// The node installs a subnet route when `accept_routes` is true.
    /// The node does not install `0.0.0.0/0`.
    #[must_use]
    pub fn install_cidrs(&self, accept_routes: bool) -> Vec<String> {
        self.routes
            .iter()
            .filter(|route| route_is_active(route.prefix_len, accept_routes))
            .map(|route| format!("{}/{}", route.prefix, route.prefix_len))
            .collect()
    }

    fn insert(
        &mut self,
        peer: &str,
        prefix: Ipv4Addr,
        prefix_len: u8,
        cidr: &str,
        overlay: bool,
    ) -> Result<(), RouterError> {
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|route| route.prefix == prefix && route.prefix_len == prefix_len)
        {
            if existing.peers.iter().any(|name| name == peer) {
                existing.overlay |= overlay;
                return Ok(());
            }
            // An overlay address has one owner. Only subnet routes can have two routers.
            if existing.overlay || overlay {
                return Err(RouterError::Ambiguous {
                    cidr: cidr.to_string(),
                });
            }
            existing.peers.push(peer.to_string());
            existing.peers.sort();
            return Ok(());
        }
        self.routes.push(Route {
            peers: vec![peer.to_string()],
            prefix,
            prefix_len,
            overlay,
        });
        Ok(())
    }
}

fn route_is_active(prefix_len: u8, accept_routes: bool) -> bool {
    if prefix_len == 0 {
        return false;
    }
    prefix_len == 32 || accept_routes
}

/// Return the peer that owns the destination of one IPv4 packet.
///
/// The function returns `None` when the packet is not IPv4.
/// The function returns `None` when the table has no matching prefix.
/// `accept_routes` selects subnet prefixes. Overlay `/32` prefixes stay active.
#[must_use]
pub fn route_packet<'a>(
    table: &'a RouterTable,
    packet: &[u8],
    accept_routes: bool,
    exit: Option<&str>,
) -> Option<&'a str> {
    let dest = ipv4_destination(packet)?;
    table.lookup_exit(dest, accept_routes, exit)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{route_packet, RouterError, RouterTable};
    use crate::ipv4::ipv4_packet;
    use crate::netmap::Netmap;

    fn map_with(routes_b: &str, routes_c: &str) -> Netmap {
        let text = format!(
            r#"{{
                "version": 1,
                "self": {{"name": "a", "overlay_ip": "100.64.0.1"}},
                "peers": [
                    {{
                        "name": "b",
                        "overlay_ip": "100.64.0.2",
                        "svid": "spiffe://orblx.local/node/b",
                        "endpoints": ["172.28.18.12:443"],
                        "routes": [{routes_b}]
                    }},
                    {{
                        "name": "c",
                        "overlay_ip": "100.64.0.3",
                        "svid": "spiffe://orblx.local/node/c",
                        "endpoints": ["172.28.18.13:443"],
                        "routes": [{routes_c}]
                    }}
                ]
            }}"#
        );
        Netmap::from_slice(text.as_bytes()).unwrap()
    }

    #[test]
    fn overlay_addresses_route_to_the_owning_peer() {
        let table = RouterTable::from_netmap(&map_with("", "")).unwrap();
        assert_eq!(table.lookup(Ipv4Addr::new(100, 64, 0, 2)), Some("b"));
        assert_eq!(table.lookup(Ipv4Addr::new(100, 64, 0, 3)), Some("c"));
        assert_eq!(table.lookup(Ipv4Addr::new(100, 64, 0, 1)), None);
        assert_eq!(table.lookup(Ipv4Addr::new(8, 8, 8, 8)), None);
    }

    #[test]
    fn the_longer_prefix_wins() {
        let table =
            RouterTable::from_netmap(&map_with("\"10.1.0.0/24\"", "\"10.1.0.0/16\"")).unwrap();
        assert_eq!(table.lookup(Ipv4Addr::new(10, 1, 0, 9)), Some("b"));
        assert_eq!(table.lookup(Ipv4Addr::new(10, 1, 2, 9)), Some("c"));
        let packet = ipv4_packet(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(10, 1, 0, 9),
            b"ping",
        )
        .unwrap();
        assert_eq!(route_packet(&table, &packet, true, None), Some("b"));
        assert_eq!(route_packet(&table, &packet, false, None), None);
        assert_eq!(route_packet(&table, &[0x60, 0x00], true, None), None);
    }

    #[test]
    fn accept_routes_gates_subnet_prefixes_and_keeps_overlay_routes() {
        let table =
            RouterTable::from_netmap(&map_with("\"10.88.0.0/24\",\"0.0.0.0/0\"", "")).unwrap();
        assert_eq!(
            table.lookup_for(Ipv4Addr::new(100, 64, 0, 2), false),
            Some("b")
        );
        assert_eq!(table.lookup_for(Ipv4Addr::new(10, 88, 0, 5), false), None);
        assert_eq!(
            table.lookup_for(Ipv4Addr::new(10, 88, 0, 5), true),
            Some("b")
        );
        assert_eq!(table.lookup_for(Ipv4Addr::new(1, 1, 1, 1), true), None);
        let installed = table.install_cidrs(true);
        assert!(installed.iter().any(|cidr| cidr == "10.88.0.0/24"));
        assert!(installed.iter().any(|cidr| cidr == "100.64.0.2/32"));
        assert!(!installed.iter().any(|cidr| cidr == "0.0.0.0/0"));
        let overlay_only = table.install_cidrs(false);
        assert!(!overlay_only.iter().any(|cidr| cidr.contains("10.88")));
        assert!(overlay_only.iter().any(|cidr| cidr == "100.64.0.2/32"));
    }

    fn map_with_exit(exit_b: bool, exit_c: bool) -> Netmap {
        let flag_b = if exit_b { "true" } else { "false" };
        let flag_c = if exit_c { "true" } else { "false" };
        let text = format!(
            r#"{{
                "version": 1,
                "self": {{"name": "a", "overlay_ip": "100.64.0.1"}},
                "peers": [
                    {{
                        "name": "b",
                        "overlay_ip": "100.64.0.2",
                        "svid": "spiffe://orblx.local/node/b",
                        "endpoints": ["172.28.18.12:443"],
                        "routes": ["10.88.0.0/24"],
                        "exit_node": {flag_b}
                    }},
                    {{
                        "name": "c",
                        "overlay_ip": "100.64.0.3",
                        "svid": "spiffe://orblx.local/node/c",
                        "endpoints": ["172.28.18.13:443"],
                        "routes": [],
                        "exit_node": {flag_c}
                    }}
                ]
            }}"#
        );
        Netmap::from_slice(text.as_bytes()).unwrap()
    }

    #[test]
    fn an_approved_exit_node_owns_addresses_without_a_longer_prefix() {
        let table = RouterTable::from_netmap(&map_with_exit(true, false)).unwrap();
        assert!(table.is_exit("b"));
        assert!(!table.is_exit("c"));
        assert_eq!(
            table.lookup_exit(Ipv4Addr::new(1, 1, 1, 1), true, Some("b")),
            Some("b")
        );
        assert_eq!(
            table.lookup_exit(Ipv4Addr::new(10, 88, 0, 5), true, Some("b")),
            Some("b")
        );
        assert_eq!(
            table.lookup_exit(Ipv4Addr::new(100, 64, 0, 3), true, Some("b")),
            Some("c")
        );
        assert_eq!(
            table.lookup_exit(Ipv4Addr::new(1, 1, 1, 1), true, None),
            None
        );
        assert_eq!(
            table.lookup_exit(Ipv4Addr::new(1, 1, 1, 1), true, Some("c")),
            None
        );
        let packet = ipv4_packet(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            b"dns",
        )
        .unwrap();
        assert_eq!(route_packet(&table, &packet, false, Some("b")), Some("b"));
        assert_eq!(route_packet(&table, &packet, false, Some("missing")), None);
        let held = RouterTable::from_netmap(&map_with_exit(false, false)).unwrap();
        assert_eq!(
            held.lookup_exit(Ipv4Addr::new(8, 8, 8, 8), true, Some("b")),
            None
        );
    }

    #[test]
    fn the_same_prefix_for_one_peer_is_one_route() {
        let table = RouterTable::from_netmap(&map_with("\"100.64.0.2/32\"", "")).unwrap();
        assert_eq!(table.lookup(Ipv4Addr::new(100, 64, 0, 2)), Some("b"));
        let owned = table
            .destinations()
            .into_iter()
            .filter(|cidr| cidr == "100.64.0.2/32")
            .count();
        assert_eq!(owned, 1);
    }

    #[test]
    fn two_peers_can_own_one_subnet_prefix() {
        let table =
            RouterTable::from_netmap(&map_with("\"10.9.0.0/24\"", "\"10.9.0.0/24\"")).unwrap();
        let found = table
            .lookup_match(Ipv4Addr::new(10, 9, 0, 7), true)
            .unwrap();
        assert!(found.is_ha());
        assert_eq!(found.peers, ["b".to_string(), "c".to_string()]);
        assert_eq!(found.prefix_len, 24);
        assert_eq!(
            table.lookup_for(Ipv4Addr::new(10, 9, 0, 7), true),
            Some("b")
        );
        assert_eq!(table.lookup_for(Ipv4Addr::new(10, 9, 0, 7), false), None);
        let installed = table
            .install_cidrs(true)
            .into_iter()
            .filter(|cidr| cidr == "10.9.0.0/24")
            .count();
        assert_eq!(installed, 1);
        assert_eq!(
            table.ha_routes(),
            vec![(
                "10.9.0.0/24".to_string(),
                vec!["b".to_string(), "c".to_string()]
            )]
        );
        let single = table
            .lookup_match(Ipv4Addr::new(100, 64, 0, 2), true)
            .unwrap();
        assert!(!single.is_ha());
    }

    #[test]
    fn a_subnet_route_cannot_take_an_overlay_address() {
        let err = RouterTable::from_netmap(&map_with("\"100.64.0.3/32\"", "")).unwrap_err();
        match err {
            RouterError::Ambiguous { cidr } => assert_eq!(cidr, "100.64.0.3/32"),
            RouterError::Netmap(err) => panic!("the router returned a netmap error: {err}"),
        }
        let err = RouterTable::from_netmap(&map_with("", "\"100.64.0.2/32\"")).unwrap_err();
        match err {
            RouterError::Ambiguous { cidr } => assert_eq!(cidr, "100.64.0.2/32"),
            RouterError::Netmap(err) => panic!("the router returned a netmap error: {err}"),
        }
    }
}
