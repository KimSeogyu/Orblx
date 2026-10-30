//! Deny poll load tool (W25-2 gate 3).
//!
//! The tool runs the same deny fetch loop as `orblx up` for many enrolled node
//! state directories at the same time. It measures the poll cost at the coordinator.
//!
//! Usage: `deny_poll COORD_ADDR COORD_NAME INTERVAL_MS SECONDS STATE_DIR... [--mode poll|wait]`
//!
//! Mode `poll` fetches the list each INTERVAL_MS (the W24-D loop).
//! Mode `wait` uses `deny-wait` with the ETag of the last list, as `orblx up` does in W25-2.
//!
//! The tool prints one summary line. It prints no key, token, or bundle.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = "poll".to_string();
    if let Some(at) = args.iter().position(|arg| arg == "--mode") {
        mode = args.get(at + 1).cloned().unwrap_or_default();
        args.truncate(at);
    }
    if mode != "poll" && mode != "wait" {
        eprintln!("The mode is not known. Use poll or wait.");
        std::process::exit(2);
    }
    if args.len() < 5 {
        eprintln!("usage: deny_poll COORD_ADDR COORD_NAME INTERVAL_MS SECONDS STATE_DIR...");
        std::process::exit(2);
    }
    let Ok(coord) = args[0].parse::<SocketAddr>() else {
        eprintln!("The coordinator address is not valid.");
        std::process::exit(2);
    };
    let name = args[1].clone();
    let interval = Duration::from_millis(args[2].parse().unwrap_or(500));
    let seconds = Duration::from_secs(args[3].parse().unwrap_or(60));
    let dirs: Vec<PathBuf> = args[4..].iter().map(PathBuf::from).collect();
    let ok = Arc::new(AtomicU64::new(0));
    let fail = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + seconds;
    let mut handles = Vec::new();
    for (index, dir) in dirs.iter().enumerate() {
        let (ok, fail, name, dir, wait) = (
            Arc::clone(&ok),
            Arc::clone(&fail),
            name.clone(),
            dir.clone(),
            mode == "wait",
        );
        // Spread the start times over one interval, as independent nodes do.
        let offset = interval.mul_f64(index as f64 / dirs.len().max(1) as f64);
        handles.push(thread::spawn(move || {
            thread::sleep(offset);
            let mut etag: Option<String> = None;
            while Instant::now() < deadline {
                let start = Instant::now();
                let fetched = std::fs::read_to_string(dir.join("bundle.pem"))
                    .ok()
                    .and_then(|bundle| {
                        if wait {
                            orblx_coord::fetch_deny_wait_blocking(
                                coord,
                                &name,
                                &bundle,
                                &dir,
                                etag.as_deref(),
                            )
                            .ok()
                        } else {
                            orblx_coord::fetch_deny_blocking(coord, &name, &bundle, &dir).ok()
                        }
                    });
                if let Some(text) = fetched {
                    etag = Some(orblx_coord::deny_etag(&text));
                    ok.fetch_add(1, Ordering::Relaxed);
                } else {
                    fail.fetch_add(1, Ordering::Relaxed);
                }
                let gap = if wait {
                    Duration::from_millis(100)
                } else {
                    interval
                };
                thread::sleep(gap.saturating_sub(start.elapsed()));
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    println!(
        "deny_poll mode {mode} nodes {} interval_ms {} seconds {} ok {} fail {} client_cpu_ticks {}",
        dirs.len(),
        interval.as_millis(),
        seconds.as_secs(),
        ok.load(Ordering::Relaxed),
        fail.load(Ordering::Relaxed),
        own_cpu_ticks()
    );
}

/// Return utime plus stime of this process in clock ticks, from `/proc/self/stat`.
fn own_cpu_ticks() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/stat") else {
        return 0;
    };
    // The command name can hold spaces, so split after the last `)`.
    let Some((_, rest)) = text.rsplit_once(')') else {
        return 0;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Fields 14 and 15 of the stat line are utime and stime. `rest` starts at field 3.
    let utime = fields.get(11).and_then(|item| item.parse::<u64>().ok());
    let stime = fields.get(12).and_then(|item| item.parse::<u64>().ok());
    utime.unwrap_or(0) + stime.unwrap_or(0)
}
