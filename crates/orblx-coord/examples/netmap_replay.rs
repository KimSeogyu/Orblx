//! W25-34 proof tool: give a saved older signed netmap to the real node intake path.
//!
//! This tool is for the Docker proof only. It is not in the release image.
//! Usage: `netmap_replay STATE_DIR SAVED_DIR`.
//! `SAVED_DIR` has `netmap.signed.json`, `grants.signed.json`, and `endpoints.json` that the
//! node wrote before. The tool checks the signatures with `STATE_DIR/netmap.pub` and calls
//! `NetmapView::write_state_checked` on `STATE_DIR`, as a `policy-wait` reply does.
//! It prints `replay_result refused ...` or `replay_result accepted ...`.
//! The exit code is 0 only when the node refused the replay.

use std::path::PathBuf;

use orblx_coord::{
    decode_hex_32, grants_from_slice, netmap_from_slice, NetmapView, SignedEndpoint,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: netmap_replay STATE_DIR SAVED_DIR");
        std::process::exit(2);
    }
    let state = PathBuf::from(&args[1]);
    let saved = PathBuf::from(&args[2]);
    let read = |path: PathBuf| {
        std::fs::read(&path).unwrap_or_else(|err| {
            eprintln!("The file {} did not open. {err}", path.display());
            std::process::exit(2);
        })
    };
    let public_text = String::from_utf8(read(state.join("netmap.pub"))).unwrap_or_default();
    let Ok(public) = decode_hex_32(public_text.trim()) else {
        eprintln!("The netmap key is not valid.");
        std::process::exit(2);
    };
    let netmap = match netmap_from_slice(&read(saved.join("netmap.signed.json")), &public) {
        Ok(netmap) => netmap,
        Err(err) => {
            eprintln!("The saved netmap is not valid. {err}");
            std::process::exit(2);
        }
    };
    let grants = match grants_from_slice(&read(saved.join("grants.signed.json")), &public) {
        Ok(grants) => grants,
        Err(err) => {
            eprintln!("The saved grants are not valid. {err}");
            std::process::exit(2);
        }
    };
    let endpoints: Vec<SignedEndpoint> =
        serde_json::from_slice(&read(saved.join("endpoints.json"))).unwrap_or_default();
    println!(
        "replay_input seq {} issued_at_ms {} peers {}",
        netmap.netmap.seq,
        netmap.netmap.issued_at_ms,
        netmap.netmap.peers.len()
    );
    let view = NetmapView {
        signed_netmap: netmap,
        signed_grants: grants,
        endpoints,
        netmap_public: public,
        approved_routes: Vec::new(),
        advertised_routes: Vec::new(),
        exit_approved: false,
    };
    match view.write_state_checked(&state) {
        Ok(write) => {
            println!("replay_result accepted {write:?}");
            std::process::exit(1);
        }
        Err(err) => println!("replay_result refused {err}"),
    }
}
