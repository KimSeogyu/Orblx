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

mod admin;
mod agent;
mod apitoken;
mod client;
mod config;
mod error;

mod files;
mod http_util;
mod ippool;
#[cfg(test)]
mod issuer_test;
mod netmap;
pub mod nodelock;
mod proto;
#[cfg(test)]
mod renew_test;
mod server;
mod share;
#[cfg(test)]
mod share_test;
mod sink;
#[cfg(test)]
mod sshca_test;
pub mod sshca;
mod state;
mod store;
mod ticket;
mod tlsutil;
#[cfg(test)]
mod user_approval_test;
mod webhook;

pub use admin::{
    approve, audit, deny_etag, deny_json, deny_set, expire, nodes, revoke, revoke_all, revoke_undo,
    routes, users,
};
pub use apitoken::{
    admin_ops, all_scopes, parse_scopes, parse_ttl as parse_api_token_ttl, scope_of,
    API_TOKEN_FILE, API_TOKEN_PREFIX, MAX_API_TOKEN_TTL_SECS, OWNER_ONLY_OPS,
};
pub use client::{
    admin_blocking, admin_token_blocking, admin_token_expect_blocking, advertise_exit_blocking,
    advertise_routes_blocking, agent_grant_fetch_blocking, agent_grant_request_blocking,
    enroll_with_oidc_blocking, enroll_with_token_blocking, fetch_deny_blocking,
    fetch_deny_wait_blocking, fetch_netmap_blocking, fetch_policy_wait_blocking, netmap_json,
    publish_candidates_blocking, renew_svid_blocking, ssh_cert_request_blocking, AdminReply, GrantFetch, OidcEnroll,
    PolicySync, DENY_WAIT_HOLD,
};
pub use config::{CoordConfig, OidcSection};
pub use error::{CoordError, USER_PENDING_TEXT, USER_REJECTED_TEXT};
pub use http_util::{fetch_google_jwks_blocking, post_google_token_blocking};
pub use netmap::{
    decode_hex_32, encode_hex, verify_signed_endpoint, verify_signed_grants, verify_signed_netmap,
    NetmapKey, SignedEndpoint, SignedGrants, SignedNetmap,
};
pub use proto::{GrantAsk, SshCertAsk};
pub use server::serve_blocking;
pub use state::{
    oidc_config, read_node_material, Coordinator, EnrollResult, IssuerFetch, NetmapView,
    OidcConfig, SshIssueError, CONFIG_AUDIT_FILE, ISSUER_JWKS_TTL_SECS, ISSUER_REFETCH_SECS,
};
pub use store::{CreatedToken, StoredUser, UserState};

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
        coord.enable_config_audit().unwrap();
        let id_token = oidc
            .issue_id_token("alice", now, Duration::from_secs(600))
            .unwrap();
        // W25-15: a new user waits for the owner.
        let pending = coord.enroll_oidc(
            "laptop",
            &id_token,
            None,
            &["laptop:443".to_string()],
            &[],
            now,
        );
        assert!(matches!(
            pending.unwrap_err(),
            super::CoordError::UserPending
        ));
        coord
            .approve_user_by("oidc:alice", "spiffe://orblx.local/node/owner", now)
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

    /// W25-2: `deny-wait` replies at once for a new ETag, and holds the request
    /// until the deny list changes for a known ETag.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deny_wait_replies_when_the_list_changes() {
        let scratch = Scratch::new();
        let node = Scratch::new();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let (addr, handle) =
            super::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
        for name in ["wait-a", "wait-b"] {
            let token = coord.create_token(Duration::from_secs(600)).unwrap();
            let enrolled = super::client::enroll_with_token(
                addr,
                "coord",
                &bundle,
                name,
                &token.secret,
                &[format!("{name}:443")],
                &[],
            )
            .await
            .unwrap();
            if name == "wait-a" {
                enrolled.write_state(&node.0).unwrap();
            }
        }
        let wait = |etag: Option<String>| {
            let (dir, bundle) = (node.0.clone(), bundle.clone());
            tokio::task::spawn_blocking(move || {
                super::client::fetch_deny_wait_blocking(
                    addr,
                    "coord",
                    &bundle,
                    &dir,
                    etag.as_deref(),
                )
            })
        };
        let started = std::time::Instant::now();
        let first = wait(None).await.unwrap().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!first.contains("node/wait-b"));
        let waiter = wait(Some(super::deny_etag(&first)));
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(
            !waiter.is_finished(),
            "the coordinator did not hold the request"
        );
        let owner = orblx_identity::SpiffeId::node("owner").unwrap();
        super::revoke_all(&coord, "wait-b", owner.as_uri(), SystemTime::now()).unwrap();
        let revoked_at = std::time::Instant::now();
        let changed = waiter.await.unwrap().unwrap();
        assert!(
            revoked_at.elapsed() < Duration::from_secs(1),
            "the reply came {:?} after the revoke",
            revoked_at.elapsed()
        );
        assert!(changed.contains("spiffe://orblx.local/node/wait-b"));
        assert_ne!(super::deny_etag(&changed), super::deny_etag(&first));
        handle.abort();
    }

    /// W25-6: `policy-wait` replies at once for a new ETag. For a known ETag it holds the
    /// request until the netmap or the deny list changes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn policy_wait_replies_when_the_netmap_or_the_deny_list_changes() {
        let scratch = Scratch::new();
        let node = Scratch::new();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let (addr, handle) =
            super::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
        let enroll = |name: &'static str| {
            let token = coord.create_token(Duration::from_secs(600)).unwrap();
            let bundle = bundle.clone();
            async move {
                super::client::enroll_with_token(
                    addr,
                    "coord",
                    &bundle,
                    name,
                    &token.secret,
                    &[format!("{name}:443")],
                    &[],
                )
                .await
                .unwrap()
            }
        };
        enroll("sync-a").await.write_state(&node.0).unwrap();
        let wait = |etag: Option<String>| {
            let (dir, bundle) = (node.0.clone(), bundle.clone());
            tokio::task::spawn_blocking(move || {
                super::client::fetch_policy_wait_blocking(
                    addr,
                    "coord",
                    &bundle,
                    &dir,
                    etag.as_deref(),
                )
            })
        };
        let started = std::time::Instant::now();
        let first = wait(None).await.unwrap().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(first.view.signed_netmap.netmap.self_node.name, "sync-a");
        assert!(first.view.signed_netmap.netmap.peers.is_empty());
        // The same state gives the same ETag, so the coordinator holds the request.
        let waiter = wait(Some(first.etag.clone()));
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(
            !waiter.is_finished(),
            "the coordinator did not hold the request"
        );
        enroll("sync-b").await;
        let joined_at = std::time::Instant::now();
        // An enroll writes more than one state file. A reply can show a part of the
        // enroll (for example the endpoints first). The next request gets the rest.
        let mut joined = waiter.await.unwrap().unwrap();
        while !joined
            .view
            .signed_netmap
            .netmap
            .peers
            .iter()
            .any(|peer| peer.name == "sync-b")
        {
            assert!(joined_at.elapsed() < Duration::from_secs(1));
            joined = wait(Some(joined.etag.clone())).await.unwrap().unwrap();
        }
        assert!(
            joined_at.elapsed() < Duration::from_secs(1),
            "the peer came {:?} after the enroll",
            joined_at.elapsed()
        );
        assert_ne!(joined.etag, first.etag);
        let waiter = wait(Some(joined.etag.clone()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let owner = orblx_identity::SpiffeId::node("owner").unwrap();
        super::revoke_all(&coord, "sync-b", owner.as_uri(), SystemTime::now()).unwrap();
        let revoked_at = std::time::Instant::now();
        let mut revoked = waiter.await.unwrap().unwrap();
        while !revoked.deny.contains("spiffe://orblx.local/node/sync-b") {
            assert!(revoked_at.elapsed() < Duration::from_secs(1));
            revoked = wait(Some(revoked.etag.clone())).await.unwrap().unwrap();
        }
        assert!(
            revoked_at.elapsed() < Duration::from_secs(1),
            "the deny list came {:?} after the revoke",
            revoked_at.elapsed()
        );
        assert_ne!(revoked.etag, joined.etag);
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

    #[test]
    fn split_dns_follows_the_policy_file_without_a_restart() {
        let scratch = Scratch::new();
        let policy = r#"{
          "splitDns": {
            "corp.lan": ["10.88.0.53"]
          }
        }"#;
        fs::write(scratch.0.join("policy.hujson"), policy).unwrap();
        let now = SystemTime::now();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        coord
            .enroll_token(
                "client",
                &token.secret,
                &["client:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        let view = coord.netmap_for("client").unwrap();
        let zones = &view.signed_netmap.netmap.split_dns;
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].domain, "corp.lan");
        assert_eq!(zones[0].nameservers, vec!["10.88.0.53".to_string()]);
        fs::write(scratch.0.join("policy.hujson"), "{}").unwrap();
        let again = coord.netmap_for("client").unwrap();
        assert!(again.signed_netmap.netmap.split_dns.is_empty());
        let text = serde_json::to_string(&again.signed_netmap.netmap).unwrap();
        assert!(!text.contains("split_dns"));
    }

    #[test]
    fn an_unapproved_exit_node_stays_out_of_the_signed_netmap() {
        let scratch = Scratch::new();
        let policy = r#"{
          "tags": {
            "tag:exit": ["spiffe://orblx.local/node/exit"]
          },
          "tagOwners": {
            "tag:exit": ["spiffe://orblx.local/node/client"]
          },
          "autoApprovers": {
            "exitNode": ["tag:exit"]
          }
        }"#;
        fs::write(scratch.0.join("policy.hujson"), policy).unwrap();
        let now = SystemTime::now();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        let exit_token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        let client_token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
        coord
            .enroll_token(
                "exit",
                &exit_token.secret,
                &["exit:443".to_string()],
                &[],
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
        let held = coord.advertise_exit("other", true);
        assert!(held.is_err());
        let denied = coord.advertise_exit("client", true).unwrap();
        assert!(!denied.exit_approved);
        let client = coord.netmap_for("client").unwrap();
        assert!(!client.signed_netmap.netmap.peers[0].exit_node);
        let approved = coord.advertise_exit("exit", true).unwrap();
        assert!(approved.exit_approved);
        let again = coord.netmap_for("client").unwrap();
        let peer = again
            .signed_netmap
            .netmap
            .peers
            .iter()
            .find(|peer| peer.name == "exit")
            .unwrap();
        assert!(peer.exit_node);
        let cleared = coord.advertise_exit("exit", false).unwrap();
        assert!(!cleared.exit_approved);
    }

    #[test]
    fn node_approval_hides_a_node_until_approve_and_revoke_denies_it() {
        let scratch = Scratch::new();
        let policy = r#"{
          "nodeApproval": true,
          "owners": ["spiffe://orblx.local/node/owner"],
          "acls": [{
            "action": "accept",
            "src": ["spiffe://orblx.local/node/a"],
            "proto": "tcp",
            "dst": ["spiffe://orblx.local/node/b:22"]
          }]
        }"#;
        fs::write(scratch.0.join("policy.hujson"), policy).unwrap();
        let now = SystemTime::now();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        for name in ["owner", "a", "b"] {
            let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
            coord
                .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
                .unwrap();
        }
        let owner = coord.netmap_for("owner").unwrap();
        assert!(!owner
            .signed_netmap
            .netmap
            .peers
            .iter()
            .any(|peer| peer.name == "a"));
        assert!(owner.signed_grants.grants.grants.is_empty());
        let pending = coord.netmap_for("a").unwrap();
        assert!(pending.signed_netmap.netmap.peers.is_empty());
        assert!(pending.signed_grants.grants.grants.is_empty());
        coord.approve_node("a").unwrap();
        coord.approve_node("b").unwrap();
        let approved = coord.netmap_for("a").unwrap();
        assert!(approved
            .signed_netmap
            .netmap
            .peers
            .iter()
            .any(|peer| peer.name == "b"));
        assert!(approved
            .signed_netmap
            .netmap
            .peers
            .iter()
            .any(|peer| peer.name == "owner"));
        assert_eq!(approved.signed_grants.grants.reach.len(), 1);
        coord.expire_node("b").unwrap();
        let expired = coord.netmap_for("a").unwrap();
        assert!(!expired
            .signed_netmap
            .netmap
            .peers
            .iter()
            .any(|peer| peer.name == "b"));
        coord.approve_node("b").unwrap();
        let back = coord.netmap_for("a").unwrap();
        assert!(back
            .signed_netmap
            .netmap
            .peers
            .iter()
            .any(|peer| peer.name == "b"));
        let version =
            super::admin::revoke(&coord, "b", "spiffe://orblx.local/node/owner", now).unwrap();
        assert_eq!(version["deny_version"], 1);
        let deny = super::admin::deny_set(&coord, now).unwrap();
        let id = orblx_identity::SpiffeId::node("b").unwrap();
        assert!(deny.reject_uri(&id).is_err());
        let nodes = super::admin::nodes(&coord).unwrap();
        let text = nodes.to_string();
        assert!(text.contains("\"name\":\"b\""));
        assert!(text.contains("\"approved\":true"));
    }

    #[test]
    fn every_control_plane_change_writes_one_config_record() {
        use orblx_audit::{verify_config_file, ConfigAction, EMPTY_DIGEST};

        let scratch = Scratch::new();
        let owner = "spiffe://orblx.local/node/owner";
        let first = format!(
            r#"{{
              "nodeApproval": true,
              "owners": ["{owner}"],
              "tags": {{"tag:exit": ["spiffe://orblx.local/node/b"]}},
              "tagOwners": {{"tag:exit": ["{owner}"]}},
              "autoApprovers": {{
                "exitNode": ["tag:exit"],
                "routes": {{"10.9.0.0/24": ["tag:exit"]}}
              }}
            }}"#
        );
        fs::write(scratch.0.join("policy.hujson"), &first).unwrap();
        let now = SystemTime::now();
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        for name in ["owner", "a", "b"] {
            let token = coord.create_token_at(Duration::from_secs(60), now).unwrap();
            coord
                .enroll_token(name, &token.secret, &[format!("{name}:443")], &[], now)
                .unwrap();
        }
        super::admin::approve(&coord, "a", owner).unwrap();
        super::admin::approve(&coord, "b", owner).unwrap();
        coord
            .advertise_routes("b", &["10.9.0.0/24".to_string()])
            .unwrap();
        coord
            .advertise_routes("b", &["10.9.0.0/24".to_string()])
            .unwrap();
        coord.advertise_exit("b", true).unwrap();
        coord.advertise_exit("b", true).unwrap();
        super::admin::expire(&coord, "a", owner).unwrap();
        super::admin::revoke(&coord, "a", owner, now).unwrap();
        fs::write(scratch.0.join("policy.hujson"), "{ not hujson").unwrap();
        let _ = coord.node_list().unwrap();
        let _ = coord.node_list().unwrap();
        let second = first.replace("10.9.0.0/24", "10.9.1.0/24");
        fs::write(scratch.0.join("policy.hujson"), &second).unwrap();
        let _ = coord.node_list().unwrap();

        let path = scratch.0.join(super::CONFIG_AUDIT_FILE);
        let checked = verify_config_file(&path).unwrap();
        let actions: Vec<ConfigAction> = checked.records.iter().map(|r| r.event.action).collect();
        assert_eq!(
            actions,
            vec![
                ConfigAction::PolicyLoad,
                ConfigAction::Enroll,
                ConfigAction::Enroll,
                ConfigAction::Enroll,
                ConfigAction::Approve,
                ConfigAction::Approve,
                ConfigAction::Routes,
                ConfigAction::ExitNode,
                ConfigAction::Expire,
                ConfigAction::Revoke,
                ConfigAction::PolicyReject,
                ConfigAction::PolicyReplace,
            ]
        );
        let records = &checked.records;
        let load = &records[0].event;
        assert_eq!(load.actor, "spiffe://orblx.local/coord/coord");
        assert_eq!(load.before, EMPTY_DIGEST);
        assert_eq!(load.after, orblx_audit::sha256_digest(first.as_bytes()));
        assert!(records[1].event.actor.starts_with("token:"));
        assert_eq!(records[1].event.target, "owner");
        assert_eq!(records[1].event.before, EMPTY_DIGEST);
        assert!(records[2].event.detail.ends_with("pending"));
        for index in [4, 5, 8, 9] {
            assert_eq!(records[index].event.actor, owner);
            assert_ne!(records[index].event.before, records[index].event.after);
        }
        assert_eq!(records[4].event.target, "a");
        assert_eq!(records[6].event.actor, "spiffe://orblx.local/node/b");
        assert!(records[6].event.detail.contains("10.9.0.0/24"));
        assert_eq!(records[7].event.detail, "offer on");
        assert!(records[9].event.detail.contains("deny_version 1"));
        let reject = &records[10].event;
        assert_eq!(reject.before, load.after);
        assert_eq!(reject.after, orblx_audit::sha256_digest(b"{ not hujson"));
        assert!(!reject.detail.is_empty());
        let replace = &records[11].event;
        assert_eq!(replace.before, load.after);
        assert_eq!(replace.after, orblx_audit::sha256_digest(second.as_bytes()));

        let report = super::admin::audit(&coord, None).unwrap();
        assert_eq!(report["verify"]["ok"], true);
        assert_eq!(report["verify"]["records"], 12);
        assert_eq!(report["lines"].as_array().unwrap().len(), 12);
        let later = super::admin::audit(&coord, Some(u64::MAX)).unwrap();
        assert!(later["lines"].as_array().unwrap().is_empty());

        drop(coord);
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let reopened = verify_config_file(&path).unwrap();
        let restart = &reopened.records.last().unwrap().event;
        assert_eq!(restart.action, ConfigAction::PolicyLoad);
        assert_eq!(restart.before, replace.after);
        assert_eq!(restart.after, replace.after);

        let text = fs::read_to_string(&path).unwrap();
        let at = text.find("\"approve\"").unwrap() + 1;
        let mut bytes = text.into_bytes();
        bytes[at] = b'A';
        fs::write(&path, bytes).unwrap();
        let report = super::admin::audit(&coord, None).unwrap();
        assert_eq!(report["verify"]["ok"], false);
        drop(coord);
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        assert!(coord.enable_config_audit().is_err());
    }
}
