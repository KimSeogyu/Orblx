//! The source of the netmap that a running node reads (W25-36).
//!
//! A node with coordinator state reads only the signed netmap. The signature check
//! lives in `orblx-coord`, which depends on this crate. The coordinator crate installs
//! the check here with [`set_netmap_verifier`]. A node with coordinator state and no
//! installed check fails closed. It never reads `netmap.json`.
//! A node without coordinator state (a static `orblx issue` node) reads the netmap file.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::Netmap;

/// A check that reads and verifies the signed netmap in a state directory.
pub type NetmapVerifier = fn(&Path) -> Result<Netmap, String>;

static VERIFIER: OnceLock<NetmapVerifier> = OnceLock::new();

/// The signed netmap file of an enrolled node.
pub const SIGNED_NETMAP_FILE: &str = "netmap.signed.json";

/// Files that only `orblx up --coord` writes. One of them makes the node enrolled.
///
/// `netmap.pub` is not on the list. A static `orblx issue --policy` node also has it.
pub const COORDINATOR_STATE_FILES: [&str; 4] = [
    "node.crt.pem",
    SIGNED_NETMAP_FILE,
    "coord-addr",
    "node-name",
];

/// Install the signed netmap check. The first call sets the check. Later calls do nothing.
pub fn set_netmap_verifier(verifier: NetmapVerifier) {
    let _ = VERIFIER.set(verifier);
}

/// True when the state directory holds coordinator state.
pub fn has_coordinator_state(state_dir: &Path) -> bool {
    COORDINATOR_STATE_FILES
        .iter()
        .any(|name| state_dir.join(name).exists())
}

/// The file whose bytes change when the running netmap changes.
///
/// With coordinator state, this is the signed netmap. Else it is the netmap file.
pub fn netmap_source_file(state_dir: &Path, netmap_path: &Path) -> PathBuf {
    if has_coordinator_state(state_dir) {
        state_dir.join(SIGNED_NETMAP_FILE)
    } else {
        netmap_path.to_path_buf()
    }
}

/// Read the netmap for a running node.
///
/// With coordinator state, only the installed signature check gives the netmap.
/// The function never reads `netmap.json` in that state. The error does not hold secrets.
pub fn read_running_netmap(state_dir: &Path, netmap_path: &Path) -> Result<Netmap, String> {
    if has_coordinator_state(state_dir) {
        let Some(verify) = VERIFIER.get() else {
            return Err(
                "The node has coordinator state, but the signed netmap check is not installed. \
                 The node does not read netmap.json."
                    .to_string(),
            );
        };
        return verify(state_dir);
    }
    Netmap::from_path(netmap_path).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = r#"{"version":1,"self":{"name":"b","overlay_ip":"100.64.0.2"},"peers":[]}"#;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("orblx-netmap-source-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("temp dir"));
        dir
    }

    #[test]
    fn a_static_node_reads_the_netmap_file() {
        let dir = temp_dir("static");
        let path = dir.join("netmap.json");
        std::fs::write(&path, MAP).unwrap_or_else(|_| panic!("write"));
        // A static issue node with signed grants also has netmap.pub.
        std::fs::write(dir.join("netmap.pub"), "00\n").unwrap_or_else(|_| panic!("write"));
        assert!(!has_coordinator_state(&dir));
        assert_eq!(netmap_source_file(&dir, &path), path);
        let netmap = read_running_netmap(&dir, &path).unwrap_or_else(|_| panic!("read"));
        assert_eq!(netmap.self_node.name, "b");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn each_coordinator_file_makes_the_node_enrolled() {
        for name in COORDINATOR_STATE_FILES {
            let dir = temp_dir(&format!("marker-{}", name.replace('.', "-")));
            let path = dir.join("netmap.json");
            std::fs::write(&path, MAP).unwrap_or_else(|_| panic!("write"));
            std::fs::write(dir.join(name), "x").unwrap_or_else(|_| panic!("write"));
            assert!(has_coordinator_state(&dir), "{name}");
            assert_eq!(
                netmap_source_file(&dir, &path),
                dir.join(SIGNED_NETMAP_FILE)
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
