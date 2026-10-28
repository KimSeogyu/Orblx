use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use gyeol_datapath::{
    issue_connector_lab, prove_lab_directory, prove_two_https_apps, AppFetch, TwoAppProof,
    APP_A_BODY, APP_A_HOST, APP_A_OVERLAY, APP_B_BODY, APP_B_HOST, APP_B_OVERLAY,
};

#[test]
fn two_https_apps_answer_through_the_mesh() {
    let proof = prove_two_https_apps().expect("the connector proof failed");
    assert_mesh(&proof);
}

#[test]
fn lab_directory_answers_through_the_mesh() {
    let dir = temp_dir("orblx-w9-lab");
    issue_connector_lab(&dir).expect("the lab directory was not written");
    let proof = prove_lab_directory(&dir).expect("the lab proof failed");
    assert_mesh(&proof);
    fs::remove_dir_all(&dir).expect("the lab directory was not removed");
}

fn assert_mesh(proof: &TwoAppProof) {
    assert_ne!(proof.ingress, proof.backend_a);
    assert_ne!(proof.ingress, proof.backend_b);
    assert_ne!(proof.backend_a, proof.backend_b);
    assert_eq!(proof.ingress.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(proof.backend_a.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(proof.backend_b.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(proof.quic_hub.port(), 0);
    assert_fetch(
        &proof.app_a,
        APP_A_HOST,
        APP_A_OVERLAY,
        APP_A_BODY,
        proof.ingress,
    );
    assert_fetch(
        &proof.app_b,
        APP_B_HOST,
        APP_B_OVERLAY,
        APP_B_BODY,
        proof.ingress,
    );
    assert_ne!(proof.app_a.body, proof.app_b.body);
    assert_ne!(proof.app_a.overlay, proof.app_b.overlay);
}

fn assert_fetch(
    fetch: &AppFetch,
    host: &str,
    overlay: Ipv4Addr,
    body: &str,
    ingress: std::net::SocketAddr,
) {
    assert_eq!(fetch.host, host);
    assert_eq!(fetch.overlay, overlay);
    assert_eq!(fetch.status, 200);
    assert_eq!(fetch.body, body);
    assert!(
        fetch.mesh_to > 0,
        "{host} did not send payload frames on the mesh"
    );
    assert!(
        fetch.mesh_from > 0,
        "{host} did not receive payload frames on the mesh"
    );
    assert_eq!(fetch.dialed, ingress);
    assert_ne!(overlay, Ipv4Addr::LOCALHOST);
}

fn temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is valid")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
