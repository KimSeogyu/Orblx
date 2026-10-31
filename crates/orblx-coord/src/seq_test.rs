//! W25-34 tests of the signed netmap stamp through the real coordinator and node write path.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use orblx_datapath::{netmap_fresh, Netmap};

use crate::netmap::NetmapKey;
use crate::seq::{read_node_seq, record_node_seq, unix_ms};
use crate::state::{NetmapView, ViewWrite};
use crate::{read_verified_netmap, Coordinator, OidcConfig};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut raw = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
        let path = std::env::temp_dir().join(format!(
            "orblx-seq-{name}-{}",
            crate::netmap::encode_hex(&raw)
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

fn enroll(coord: &Coordinator, name: &str) -> crate::EnrollResult {
    let token = coord.create_token(Duration::from_secs(600)).unwrap();
    coord
        .enroll_token(
            name,
            &token.secret,
            &[format!("{name}:443")],
            &[],
            SystemTime::now(),
        )
        .unwrap()
}

/// A copy of `view` with a new stamp, signed with `key`.
fn restamp(view: &NetmapView, key: &NetmapKey, seq: u64, issued_at_ms: u64) -> NetmapView {
    let mut netmap = view.signed_netmap.netmap.clone();
    netmap.seq = seq;
    netmap.issued_at_ms = issued_at_ms;
    NetmapView {
        signed_netmap: key.sign_netmap(&netmap).unwrap(),
        signed_grants: key.sign_grants(&view.signed_grants.grants).unwrap(),
        endpoints: view.endpoints.clone(),
        netmap_public: key.public(),
        approved_routes: view.approved_routes.clone(),
        advertised_routes: view.advertised_routes.clone(),
        exit_approved: view.exit_approved,
    }
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path).unwrap().modified().unwrap()
}

fn write_pub(dir: &Path, key: &NetmapKey) {
    fs::write(
        dir.join("netmap.pub"),
        format!("{}\n", crate::netmap::encode_hex(&key.public())),
    )
    .unwrap();
}

#[test]
fn coordinator_views_carry_a_rising_signed_stamp() {
    let coord_dir = Scratch::new("coord");
    let node = Scratch::new("node");
    let coord = Coordinator::open(&coord_dir.0, "coord", OidcConfig::TokenOnly).unwrap();
    let first = enroll(&coord, "seq-a");
    first.write_state(&node.0).unwrap();
    let stamp = first.signed_netmap.netmap.seq;
    assert!(stamp >= first.signed_netmap.netmap.issued_at_ms);
    assert!(netmap_fresh(
        first.signed_netmap.netmap.issued_at_ms,
        unix_ms(SystemTime::now())
    ));
    // The same content within the heartbeat time gets the same signed bytes.
    let again = coord.netmap_for("seq-a").unwrap();
    let again2 = coord.netmap_for("seq-a").unwrap();
    assert_eq!(again.signed_netmap, again2.signed_netmap);
    assert!(again.signed_netmap.netmap.seq >= stamp);
    // A peer joins: a new seq.
    enroll(&coord, "seq-b");
    let joined = coord.netmap_for("seq-a").unwrap();
    assert!(joined.signed_netmap.netmap.seq > again.signed_netmap.netmap.seq);
    assert_eq!(
        joined.write_state_checked(&node.0).unwrap(),
        ViewWrite::Content
    );
    // The local netmap file has no stamp.
    let local = Netmap::from_path(&node.0.join("netmap.json")).unwrap();
    assert_eq!((local.seq, local.issued_at_ms), (0, 0));
    assert_eq!(local.peers.len(), 1);
    let verified = read_verified_netmap(&node.0).unwrap();
    assert_eq!(verified.netmap.seq, joined.signed_netmap.netmap.seq);
    // The seq survives a coordinator restart.
    let last = coord.netmap_for("seq-b").unwrap().signed_netmap.netmap.seq;
    drop(coord);
    let coord = Coordinator::open(&coord_dir.0, "coord", OidcConfig::TokenOnly).unwrap();
    let after = coord.netmap_for("seq-a").unwrap();
    assert!(after.signed_netmap.netmap.seq > last);
}

#[test]
fn replay_of_an_older_view_keeps_the_peer_removed() {
    let coord_dir = Scratch::new("replay");
    let node = Scratch::new("replay-node");
    let coord = Coordinator::open(&coord_dir.0, "coord", OidcConfig::TokenOnly).unwrap();
    enroll(&coord, "rp-a").write_state(&node.0).unwrap();
    enroll(&coord, "rp-b");
    let with_peer = coord.netmap_for("rp-a").unwrap();
    with_peer.write_state(&node.0).unwrap();
    assert_eq!(
        Netmap::from_path(&node.0.join("netmap.json"))
            .unwrap()
            .peers
            .len(),
        1
    );
    crate::admin::expire(&coord, "rp-b", "test").unwrap();
    let without = coord.netmap_for("rp-a").unwrap();
    assert!(without.signed_netmap.netmap.peers.is_empty());
    assert_eq!(
        without.write_state_checked(&node.0).unwrap(),
        ViewWrite::Content
    );
    // An attacker replays the older signed view that still has the peer.
    assert!(with_peer.write_state(&node.0).is_err());
    let local = Netmap::from_path(&node.0.join("netmap.json")).unwrap();
    assert!(local.peers.is_empty(), "the removed peer came back");
    let (seq, _) = read_node_seq(&node.0).unwrap().unwrap();
    assert_eq!(seq, without.signed_netmap.netmap.seq);
}

#[test]
fn heartbeat_and_redelivery_change_no_datapath_file() {
    let node = Scratch::new("beat");
    let key = NetmapKey::generate();
    let coord_dir = Scratch::new("beat-coord");
    let coord = Coordinator::open(&coord_dir.0, "coord", OidcConfig::TokenOnly).unwrap();
    enroll(&coord, "hb-b");
    let base = enroll(&coord, "hb-a");
    let base = coord.netmap_for(&base.name).unwrap();
    write_pub(&node.0, &key);
    let now = unix_ms(SystemTime::now());
    // The first netmap was signed 50 s ago.
    let issued = now - 50_000;
    let first = restamp(&base, &key, issued, issued);
    assert_eq!(
        first.write_state_checked(&node.0).unwrap(),
        ViewWrite::Content
    );
    let files = [
        "netmap.json",
        "netmap.signed.json",
        "grants.json",
        "grants.signed.json",
        "endpoints.json",
    ];
    let before: Vec<_> = files.iter().map(|f| mtime(&node.0.join(f))).collect();
    std::thread::sleep(Duration::from_millis(20));
    // The 50 s re-delivery: the same seq and bytes. No file changes; the age does not reset.
    assert_eq!(first.write_state_checked(&node.0).unwrap(), ViewWrite::Same);
    let same: Vec<_> = files.iter().map(|f| mtime(&node.0.join(f))).collect();
    assert_eq!(before, same);
    let stored = read_verified_netmap(&node.0).unwrap();
    assert_eq!(stored.netmap.issued_at_ms, issued);
    assert!(netmap_fresh(stored.netmap.issued_at_ms, now));
    assert!(!netmap_fresh(stored.netmap.issued_at_ms, issued + 60_001));
    // A heartbeat: a new seq and issue time with the same content. Only the signed netmap
    // file changes. The datapath reads `netmap.json`, which does not change.
    let beat = restamp(&base, &key, now, now);
    assert_eq!(
        beat.write_state_checked(&node.0).unwrap(),
        ViewWrite::StampOnly
    );
    let after: Vec<_> = files.iter().map(|f| mtime(&node.0.join(f))).collect();
    for (index, file) in files.iter().enumerate() {
        if *file == "netmap.signed.json" {
            assert_ne!(before[index], after[index]);
        } else {
            assert_eq!(before[index], after[index], "{file} changed");
        }
    }
    assert_eq!(
        read_verified_netmap(&node.0).unwrap().netmap.issued_at_ms,
        now
    );
    // The same seq with other content is refused, and no file changes.
    let mut other = beat.signed_netmap.netmap.clone();
    other.peers.clear();
    let forged = NetmapView {
        signed_netmap: key.sign_netmap(&other).unwrap(),
        ..restamp(&base, &key, now, now)
    };
    assert!(forged.write_state(&node.0).is_err());
    // A lower seq is refused.
    assert!(first.write_state(&node.0).is_err());
    let last: Vec<_> = files.iter().map(|f| mtime(&node.0.join(f))).collect();
    assert_eq!(after, last);
}

#[test]
fn crash_after_the_seq_write_recovers_on_redelivery() {
    let node = Scratch::new("crash");
    let key = NetmapKey::generate();
    let coord_dir = Scratch::new("crash-coord");
    let coord = Coordinator::open(&coord_dir.0, "coord", OidcConfig::TokenOnly).unwrap();
    enroll(&coord, "cr-a");
    let base = coord.netmap_for("cr-a").unwrap();
    write_pub(&node.0, &key);
    let now = unix_ms(SystemTime::now());
    let view = restamp(&base, &key, now, now);
    // The node wrote the seq and stopped before the netmap files.
    record_node_seq(&node.0, &view.signed_netmap).unwrap();
    assert!(!node.0.join("netmap.signed.json").exists());
    assert_eq!(
        view.write_state_checked(&node.0).unwrap(),
        ViewWrite::Content
    );
    assert_eq!(
        read_verified_netmap(&node.0).unwrap().netmap.seq,
        view.signed_netmap.netmap.seq
    );
}

#[test]
fn write_state_sets_the_dir_mode_again() {
    let node = Scratch::new("mode");
    let coord_dir = Scratch::new("mode-coord");
    let coord = Coordinator::open(&coord_dir.0, "coord", OidcConfig::TokenOnly).unwrap();
    let enrolled = enroll(&coord, "md-a");
    enrolled.write_state(&node.0).unwrap();
    fs::set_permissions(&node.0, fs::Permissions::from_mode(0o755)).unwrap();
    coord
        .netmap_for("md-a")
        .unwrap()
        .write_state(&node.0)
        .unwrap();
    let mode = fs::metadata(&node.0).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}
