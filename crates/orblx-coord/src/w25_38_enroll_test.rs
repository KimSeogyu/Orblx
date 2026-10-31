//! W25-38: the enroll reply has no deny list. The node refuses each peer after enroll
//! until its first deny fetch over mutual TLS with the new node SVID. The enroll client
//! starts that fetch right after it gets the SVID.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use orblx_identity::{
    load_deny_file, DenyCache, DenyFileError, DenyReload, DenyStore, SpiffeId, DENY_FILE,
};

use crate::state::{Coordinator, EnrollResult, FirstDeny, OidcConfig};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orblx-w25-38-enroll-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn enroll(coord: &Coordinator, addr: SocketAddr, bundle: &str, name: &str) -> EnrollResult {
    let token = coord.create_token(Duration::from_secs(600)).unwrap();
    crate::client::enroll_with_token(
        addr,
        "coord",
        bundle,
        name,
        &token.secret,
        &[format!("{name}:443")],
        &[],
    )
    .await
    .unwrap()
}

async fn first_fetch(
    addr: SocketAddr,
    bundle: &str,
    dir: &Path,
) -> Result<DenyStore, crate::CoordError> {
    let bundle = bundle.to_string();
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::client::fetch_first_deny_blocking(addr, "coord", &bundle, &dir)
    })
    .await
    .unwrap()
}

/// Each reader of the node (SSH login and recheck, file receive, the datapath, `orblx up`,
/// and `orblx ping`) reads `deny.json` with `read_deny_file` (through `DenyCache` or
/// `load_deny_file`). The test checks both paths.
fn assert_refuses_each_peer(dir: &Path, peers: &[&SpiffeId]) {
    assert!(matches!(
        load_deny_file(dir),
        Err(DenyFileError::MissingAfterEnroll(_))
    ));
    let mut cache = DenyCache::new();
    assert!(matches!(cache.reload(dir), DenyReload::Stale { .. }));
    for peer in peers {
        assert!(cache.set().reject_uri(peer).is_err(), "{}", peer.as_uri());
    }
    assert!(cache.set().reject_nonce(&[7u8; 16]).is_err());
}

/// After enroll and before the first mutual TLS deny fetch, each reader refuses. After the
/// fetch, the readers use the valid list of the coordinator.
#[tokio::test]
async fn w25_38_after_enroll_every_reader_refuses_until_the_first_mtls_deny_fetch() {
    let scratch = Scratch::new();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let (addr, handle) = crate::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let _ = enroll(&coord, addr, &bundle, "revoked-a").await;
    let _ = enroll(&coord, addr, &bundle, "good-b").await;
    crate::admin::revoke(&coord, "revoked-a", "test", SystemTime::now()).unwrap();
    let revoked = SpiffeId::node("revoked-a").unwrap();
    let good = SpiffeId::node("good-b").unwrap();

    let node = Scratch::new();
    let mut result = enroll(&coord, addr, &bundle, "new-c").await;
    // The enroll client fetched the list over mutual TLS right after the enroll reply.
    let FirstDeny::Fetched { text, .. } = &result.first_deny else {
        panic!("no first deny fetch: {:?}", result.first_deny);
    };
    assert!(text.contains(revoked.as_uri()));
    // The state between the enroll reply and the first fetch: no deny list.
    result.first_deny = FirstDeny::NotFetched;
    result.write_state(&node.0).unwrap();
    assert!(!node.0.join(DENY_FILE).exists(), "enroll wrote a deny file");
    assert_refuses_each_peer(&node.0, &[&revoked, &good]);

    assert_eq!(
        first_fetch(addr, &bundle, &node.0).await.unwrap(),
        DenyStore::Written
    );
    let deny = load_deny_file(&node.0).unwrap();
    assert!(!deny.refuses_all());
    assert!(deny.version().is_some());
    assert!(deny.reject_uri(&revoked).is_err());
    assert!(deny.reject_uri(&good).is_ok());
    let mut cache = DenyCache::new();
    assert_eq!(cache.reload(&node.0), DenyReload::Changed);
    assert!(cache.set().reject_uri(&revoked).is_err());
    assert!(cache.set().reject_uri(&good).is_ok());
    handle.abort();
}

/// The refuse-all window from enroll (`node-name` written) to the first valid deny list.
/// Gate: each of 10 enrolls is 2 s or less.
#[tokio::test]
async fn w25_38_refuse_all_window_after_enroll_is_two_seconds_or_less() {
    let scratch = Scratch::new();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let (addr, handle) = crate::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let mut windows = Vec::new();
    for i in 0..10 {
        let node = Scratch::new();
        let result = enroll(&coord, addr, &bundle, &format!("win-{i}")).await;
        result.write_state(&node.0).unwrap();
        let FirstDeny::Fetched { cert_at, .. } = &result.first_deny else {
            panic!("no first deny fetch: {:?}", result.first_deny);
        };
        // From the SVID to a valid deny.json on disk.
        let ms = cert_at.elapsed().as_millis();
        assert!(!load_deny_file(&node.0).unwrap().refuses_all());
        println!("w25_38_refuse_all_window enroll {i} ms {ms}");
        windows.push(ms);
    }
    handle.abort();
    println!("w25_38_refuse_all_window all_ms {windows:?}");
    assert!(windows.iter().all(|ms| *ms <= 2000), "{windows:?}");
}

/// The coordinator is not reachable after enroll: the first fetch fails with a clear error
/// and the node stays refuse-all.
#[tokio::test]
async fn w25_38_unreachable_coordinator_after_enroll_keeps_the_node_refuse_all() {
    let scratch = Scratch::new();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let (addr, handle) = crate::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let node = Scratch::new();
    let mut result = enroll(&coord, addr, &bundle, "lost-d").await;
    handle.abort();
    let _ = handle.await;
    result.first_deny = FirstDeny::NotFetched;
    result.write_state(&node.0).unwrap();
    let start = Instant::now();
    let err = first_fetch(addr, &bundle, &node.0).await.unwrap_err();
    let spent = start.elapsed();
    println!("w25_38_unreachable ms {} error {err}", spent.as_millis());
    assert!(
        spent <= crate::client::DENY_FETCH_LIMIT + Duration::from_secs(5),
        "{spent:?}"
    );
    assert!(err.to_string().contains("coordinator"), "{err}");
    assert!(!node.0.join(DENY_FILE).exists());
    let peer = SpiffeId::node("any-e").unwrap();
    assert_refuses_each_peer(&node.0, &[&peer]);
}
