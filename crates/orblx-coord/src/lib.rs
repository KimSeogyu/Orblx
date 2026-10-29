//! Node enrollment, stable overlay addresses, and signed netmaps.
//!
//! A node enrolls one time.
//! The node receives `spiffe://orblx.local/node/{name}`.
//! The node receives one address from `100.64.0.0/10`.
//! The coordinator signs each netmap and each endpoint with Ed25519.
//! The coordinator also signs the receiver grant set with that key.
//! A policy file with a failed test does not replace the last good policy.
//! The listener uses QUIC on UDP 443 with the SVID `spiffe://orblx.local/coord/{name}`.
//! Enrollment uses server authentication because the node SVID does not exist yet.
//! A later netmap fetch uses the node SVID as the client certificate.
//! A later renew call uses the node SVID and returns a new leaf.

mod client;
mod error;

mod files;
mod http_util;
mod ippool;
mod netmap;
mod proto;
#[cfg(test)]
mod renew_test;
mod server;
mod state;
mod store;
mod tlsutil;

pub use client::{
    advertise_routes_blocking, enroll_with_oidc_blocking, enroll_with_token_blocking,
    fetch_netmap_blocking, netmap_json, renew_svid_blocking, OidcEnroll,
};
pub use error::CoordError;
pub use http_util::{fetch_google_jwks_blocking, post_google_token_blocking};
pub use netmap::{
    decode_hex_32, encode_hex, verify_signed_endpoint, verify_signed_grants, verify_signed_netmap,
    NetmapKey, SignedEndpoint, SignedGrants, SignedNetmap,
};
pub use server::serve_blocking;
pub use state::{
    oidc_config, read_node_material, Coordinator, EnrollResult, NetmapView, OidcConfig,
};
pub use store::CreatedToken;

/// This function returns the name of this crate.
pub fn crate_name() -> &'static str {
    "orblx-coord"
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    use orblx_identity::{IssueGate, MiniCa, MockOidc, OidcMode, MOCK_OIDC_ISSUER, OIDC_MODE_ENV};

    use super::{crate_name, verify_signed_netmap, Coordinator, OidcConfig};

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(crate_name(), "orblx-coord");
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let mut raw = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
            let path = std::env::temp_dir().join(format!("orblx-coord-{}", hex(&raw)));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::new();
        for byte in bytes {
            text.push(HEX[usize::from(byte >> 4)] as char);
            text.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        text
    }

    #[test]
    fn token_reuse_is_rejected_and_ips_survive_reopen() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        let first = coord
            .enroll_token(
                "server-a",
                &token.secret,
                &["server-a:443".to_string()],
                &["192.168.1.0/24".to_string()],
                now,
            )
            .unwrap();
        assert_eq!(first.overlay_ip, "100.64.0.1");
        assert_eq!(first.svid, "spiffe://orblx.local/node/server-a");
        let reused = coord.enroll_token("server-c", &token.secret, &[], &[], now);
        assert!(matches!(reused.unwrap_err(), super::CoordError::TokenUsed));
        let expired = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        let later = now.checked_add(Duration::from_secs(60)).unwrap();
        let stale = coord.enroll_token("server-d", &expired.secret, &[], &[], later);
        assert!(matches!(
            stale.unwrap_err(),
            super::CoordError::TokenExpired
        ));
        let store_text = fs::read_to_string(scratch.0.join("nodes.json")).unwrap();
        assert!(!store_text.contains("PRIVATE KEY"));
        assert!(!store_text.contains("ge1."));
        drop(coord);
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let view = coord.netmap_for("server-a").unwrap();
        assert_eq!(view.signed_netmap.netmap.self_node.overlay_ip, "100.64.0.1");
        verify_signed_netmap(&view.signed_netmap, &view.netmap_public).unwrap();
        let second = coord
            .create_token_at(Duration::from_secs(120), later)
            .unwrap();
        let other = coord
            .enroll_token(
                "server-b",
                &second.secret,
                &["server-b:443".to_string()],
                &[],
                later,
            )
            .unwrap();
        assert_eq!(other.overlay_ip, "100.64.0.2");
    }

    #[test]
    fn mock_oidc_mode_enrolls_a_node() {
        assert_eq!(OIDC_MODE_ENV, "ORBLX_OIDC_MODE");
        assert_eq!(OidcMode::parse(Some("mock")).unwrap(), OidcMode::Mock);
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
        let coord =
            Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
        let id_token = oidc
            .issue_id_token("alice", now, Duration::from_secs(600))
            .unwrap();
        let result = coord
            .enroll_oidc(
                "laptop",
                &id_token,
                None,
                &["laptop:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        assert_eq!(result.svid, "spiffe://orblx.local/node/laptop");
        assert_eq!(result.overlay_ip, "100.64.0.1");
        assert!(result
            .endpoints
            .iter()
            .any(|item| item.endpoint == "laptop:443"));
        let again = coord.enroll_oidc("laptop", &id_token, None, &[], &[], now);
        assert!(matches!(again.unwrap_err(), super::CoordError::Exists));
    }

    #[tokio::test]
    async fn two_nodes_keep_ips_after_restart() {
        let scratch = Scratch::new();
        let node_a = Scratch::new();
        let node_b = Scratch::new();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let token_a = coord.create_token(Duration::from_secs(600)).unwrap();
        let token_b = coord.create_token(Duration::from_secs(600)).unwrap();
        let (addr, handle) =
            super::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
        let first = super::client::enroll_with_token(
            addr,
            "coord",
            &bundle,
            "server-a",
            &token_a.secret,
            &["server-a:443".to_string()],
            &[],
        )
        .await
        .unwrap();
        first.write_state(&node_a.0).unwrap();
        let second = super::client::enroll_with_token(
            addr,
            "coord",
            &bundle,
            "server-b",
            &token_b.secret,
            &["server-b:443".to_string()],
            &[],
        )
        .await
        .unwrap();
        second.write_state(&node_b.0).unwrap();
        assert_eq!(first.overlay_ip, "100.64.0.1");
        assert_eq!(second.overlay_ip, "100.64.0.2");
        handle.abort();
        drop(coord);
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let (addr, handle) =
            super::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
        let view = super::client::fetch_netmap(addr, "coord", &bundle, &node_a.0)
            .await
            .unwrap();
        assert_eq!(view.signed_netmap.netmap.self_node.overlay_ip, "100.64.0.1");
        assert_eq!(view.signed_netmap.netmap.peers[0].name, "server-b");
        assert_eq!(view.signed_netmap.netmap.peers[0].overlay_ip, "100.64.0.2");
        let node_text = fs::read_to_string(node_a.0.join("netmap.json")).unwrap();
        let parsed = orblx_datapath::Netmap::from_slice(node_text.as_bytes()).unwrap();
        assert_eq!(parsed, view.signed_netmap.netmap);
        assert!(!node_text.contains("\"sig\""));
        let reused = super::client::enroll_with_token(
            addr,
            "coord",
            &bundle,
            "server-c",
            &token_a.secret,
            &[],
            &[],
        )
        .await;
        assert!(reused.unwrap_err().to_string().contains("already used"));
        handle.abort();
    }

    #[test]
    fn a_failing_policy_keeps_the_last_good_grants() {
        let scratch = Scratch::new();
        let good = r#"{
          "acls": [{
            "action": "accept",
            "src": ["spiffe://orblx.local/node/mac"],
            "proto": "tcp",
            "dst": ["spiffe://orblx.local/node/box:22"]
          }],
          "tests": [{
            "src": "spiffe://orblx.local/node/mac",
            "proto": "tcp",
            "accept": ["spiffe://orblx.local/node/box:22"],
            "deny": ["spiffe://orblx.local/node/box:5432"]
          }]
        }"#;
        fs::write(scratch.0.join("policy.hujson"), good).unwrap();
        let now = SystemTime::now();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        coord
            .enroll_token("box", &token.secret, &["box:443".to_string()], &[], now)
            .unwrap();
        let view = coord.netmap_for("box").unwrap();
        assert_eq!(view.signed_grants.grants.grants.len(), 1);
        assert_eq!(view.signed_grants.grants.grants[0].port_start, 22);
        verify_signed_netmap(&view.signed_netmap, &view.netmap_public).unwrap();
        super::verify_signed_grants(&view.signed_grants, &view.netmap_public).unwrap();
        let bad = r#"{
          "acls": [{
            "action": "accept",
            "src": ["spiffe://orblx.local/node/mac"],
            "proto": "tcp",
            "dst": ["spiffe://orblx.local/node/box:22"]
          }],
          "tests": [{
            "src": "spiffe://orblx.local/node/mac",
            "accept": ["spiffe://orblx.local/node/box:5432"]
          }]
        }"#;
        fs::write(scratch.0.join("policy.hujson"), bad).unwrap();
        let again = coord.netmap_for("box").unwrap();
        assert_eq!(again.signed_grants.grants, view.signed_grants.grants);
        drop(coord);
        let reopened = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let kept = reopened.netmap_for("box").unwrap();
        assert_eq!(kept.signed_grants.grants.grants[0].port_start, 22);
        assert!(scratch.0.join("policy.loaded.hujson").exists());
    }

    #[test]
    fn an_unapproved_route_stays_out_of_the_signed_netmap() {
        let scratch = Scratch::new();
        let policy = r#"{
          "tags": {
            "tag:router": ["spiffe://orblx.local/node/router"]
          },
          "tagOwners": {
            "tag:router": ["spiffe://orblx.local/node/client"]
          },
          "autoApprovers": {
            "routes": {
              "10.88.0.0/24": ["tag:router"]
            }
          }
        }"#;
        fs::write(scratch.0.join("policy.hujson"), policy).unwrap();
        let now = SystemTime::now();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let router_token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        let client_token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        coord
            .enroll_token(
                "router",
                &router_token.secret,
                &["router:443".to_string()],
                &["10.88.0.0/24".to_string(), "10.99.0.0/24".to_string()],
                now,
            )
            .unwrap();
        coord
            .enroll_token(
                "client",
                &client_token.secret,
                &["client:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        let client = coord.netmap_for("client").unwrap();
        let routes = &client.signed_netmap.netmap.peers[0].routes;
        assert_eq!(routes, &vec!["10.88.0.0/24".to_string()]);
        let router = coord
            .advertise_routes(
                "router",
                &[
                    "10.88.0.0/24".to_string(),
                    "10.99.0.0/24".to_string(),
                    "10.77.0.0/24".to_string(),
                ],
            )
            .unwrap();
        assert_eq!(router.approved_routes, vec!["10.88.0.0/24".to_string()]);
        assert!(router
            .advertised_routes
            .iter()
            .any(|route| route == "10.99.0.0/24"));
        assert!(router
            .advertised_routes
            .iter()
            .any(|route| route == "10.77.0.0/24"));
        let again = coord.netmap_for("client").unwrap();
        assert_eq!(
            again.signed_netmap.netmap.peers[0].routes,
            vec!["10.88.0.0/24".to_string()]
        );
        let exit = coord.advertise_routes("router", &["0.0.0.0/0".to_string()]);
        assert!(exit.unwrap_err().to_string().contains("exit route"));
    }
}
