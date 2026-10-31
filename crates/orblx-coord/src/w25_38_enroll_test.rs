//! W25-38: the enroll reply has the deny list of the node.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use orblx_identity::{load_deny_file, DenySet, DENY_FILE};

use crate::proto::{self, Request};
use crate::state::{Coordinator, OidcConfig};

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

fn deny_text(version: u64) -> String {
    format!(
        r#"{{"version":{version},"generated_at":1,"revoked_uris":["spiffe://orblx.local/node/old"],"revoked_ticket_nonces":[]}}"#
    )
}

/// The deny list of an enroll reply uses the same version rule as a deny reload.
/// The list in `deny.json` never moves back.
#[tokio::test]
async fn w25_38_enroll_deny_list_never_moves_back() {
    let scratch = Scratch::new();
    let node = Scratch::new();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let token = coord.create_token(Duration::from_secs(600)).unwrap();
    let (addr, handle) = crate::server::spawn(&coord, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let result = crate::client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "seq-a",
        &token.secret,
        &["seq-a:443".to_string()],
        &[],
    )
    .await
    .unwrap();
    handle.abort();
    let sent = result
        .deny
        .clone()
        .expect("the enroll reply has a deny list");
    let sent_version = DenySet::from_json(sent.as_bytes())
        .unwrap()
        .version()
        .unwrap();

    result.write_state(&node.0).unwrap();
    assert_eq!(fs::read_to_string(node.0.join(DENY_FILE)).unwrap(), sent);

    // The node already has a higher version. The enroll list does not replace it.
    let newer = deny_text(sent_version + 100);
    fs::write(node.0.join(DENY_FILE), &newer).unwrap();
    result.write_state(&node.0).unwrap();
    assert_eq!(fs::read_to_string(node.0.join(DENY_FILE)).unwrap(), newer);
    assert_eq!(
        load_deny_file(&node.0).unwrap().version(),
        Some(sent_version + 100)
    );

    // A deny file that is not valid does not block the enroll list.
    fs::write(node.0.join(DENY_FILE), b"not json {").unwrap();
    result.write_state(&node.0).unwrap();
    assert_eq!(fs::read_to_string(node.0.join(DENY_FILE)).unwrap(), sent);
}

/// A new node and a coordinator before W25-38: the enroll reply has no deny list.
/// The enroll fails closed with a version mismatch error.
#[tokio::test]
async fn w25_38_enroll_with_an_old_coordinator_fails_closed_with_version_mismatch() {
    let scratch = Scratch::new();
    let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
    let token = coord.create_token(Duration::from_secs(600)).unwrap();
    let material = coord.tls_material().unwrap();
    let endpoint =
        crate::tlsutil::server_endpoint(&material, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let old = coord.clone();
    let server = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let request: Request = proto::read_json(&mut recv).await.unwrap();
        let result = old
            .enroll_token(
                &request.name,
                request.token.as_deref().unwrap(),
                &request.endpoints,
                &request.routes,
                SystemTime::now(),
            )
            .unwrap();
        // The enroll reply of a coordinator before W25-38: no deny list.
        let reply = crate::server::leaf_response(result);
        assert!(reply.detail.is_none());
        proto::write_json(&mut send, &reply).await.unwrap();
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
    });
    let bundle = fs::read_to_string(scratch.0.join("trust-bundle.pem")).unwrap();
    let err = crate::client::enroll_with_token(
        addr,
        "coord",
        &bundle,
        "old-a",
        &token.secret,
        &["old-a:443".to_string()],
        &[],
    )
    .await
    .unwrap_err()
    .to_string();
    server.await.unwrap();
    assert!(err.contains("Version mismatch"), "{err}");
    assert!(
        err.contains("Upgrade the coordinator and all nodes together."),
        "{err}"
    );
}
