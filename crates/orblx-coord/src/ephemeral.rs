//! Remove ephemeral nodes that stay offline too long (W25-18).
//!
//! - A node is ephemeral when it enrolls with an ephemeral token
//!   (`orblx coord token create --ephemeral`). The default is off.
//! - A node is online while it has an open request to the coordinator. A running node
//!   always holds one `policy-wait` request, and it opens the next request at most
//!   100 ms after a reply. A node is offline from the end of its last request.
//! - The tick removes an ephemeral node that is offline for longer than the limit `T`.
//!   The default limit is 10 minutes.
//! - A removal adds the SVID to the deny file, deletes the node record, and writes one
//!   `node-remove` config record with `reason ephemeral`. The overlay address becomes free.
//! - The tick never removes a node that is not ephemeral. The node store also refuses it.
//! - The file `ephemeral.json` keeps the offline time of each ephemeral node and the
//!   time of the last save. After a restart the coordinator keeps the offline time that
//!   the node had at the last save. The time that the coordinator was down does not count.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::state::Coordinator;

/// The default offline limit of an ephemeral node.
pub const DEFAULT_OFFLINE: Duration = Duration::from_secs(600);
/// The smallest offline limit.
pub const MIN_OFFLINE: Duration = Duration::from_secs(2);
/// The largest offline limit.
pub const MAX_OFFLINE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const PRESENCE_FILE: &str = "ephemeral.json";
const PRESENCE_VERSION: u32 = 1;
const TICK: Duration = Duration::from_millis(500);
const SAVE_EVERY_MS: u64 = 1000;

/// When each node was last online.
pub struct Presence {
    state: Mutex<PresenceState>,
}

impl Default for Presence {
    fn default() -> Self {
        Self {
            state: Mutex::new(PresenceState {
                offline: DEFAULT_OFFLINE,
                last_seen_ms: BTreeMap::new(),
                open: BTreeMap::new(),
                last_save_ms: 0,
            }),
        }
    }
}

struct PresenceState {
    offline: Duration,
    /// Unix milliseconds when the node was last online.
    last_seen_ms: BTreeMap<String, u64>,
    /// The number of open requests of each node.
    open: BTreeMap<String, u32>,
    last_save_ms: u64,
}

/// One open request of one node. The drop marks the node seen.
pub struct Seen<'a> {
    presence: &'a Presence,
    name: String,
}

impl Drop for Seen<'_> {
    fn drop(&mut self) {
        let now = now_ms(SystemTime::now());
        if let Ok(mut state) = self.presence.state.lock() {
            let count = state.open.get(&self.name).copied().unwrap_or(0);
            if count <= 1 {
                state.open.remove(&self.name);
            } else {
                state.open.insert(self.name.clone(), count - 1);
            }
            state.last_seen_ms.insert(self.name.clone(), now);
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PresenceFile {
    version: u32,
    /// Unix milliseconds of the save.
    saved_ms: u64,
    /// Unix milliseconds when each ephemeral node was last online.
    last_seen_ms: BTreeMap<String, u64>,
}

impl Presence {
    /// Set the offline limit.
    pub fn set_offline(&self, offline: Duration) -> Result<(), CoordError> {
        if offline < MIN_OFFLINE || offline > MAX_OFFLINE || offline.subsec_nanos() != 0 {
            return Err(CoordError::Time);
        }
        let mut state = self.state.lock().map_err(|_| CoordError::State)?;
        state.offline = offline;
        Ok(())
    }

    /// Return the offline limit.
    pub fn offline(&self) -> Duration {
        self.state
            .lock()
            .map(|state| state.offline)
            .unwrap_or(DEFAULT_OFFLINE)
    }

    /// Mark one request of node `name` open. The node is online until the guard drops.
    pub fn begin(&self, name: &str) -> Seen<'_> {
        let now = now_ms(SystemTime::now());
        if let Ok(mut state) = self.state.lock() {
            *state.open.entry(name.to_string()).or_insert(0) += 1;
            state.last_seen_ms.insert(name.to_string(), now);
        }
        Seen {
            presence: self,
            name: name.to_string(),
        }
    }

    /// Load the saved offline times of `dir`.
    ///
    /// A node keeps the offline time that it had at the save.
    fn load(&self, dir: &Path, now: u64) -> Result<usize, CoordError> {
        let path = dir.join(PRESENCE_FILE);
        if !path.exists() {
            return Ok(0);
        }
        let file: PresenceFile =
            serde_json::from_str(&read_text(&path)?).map_err(|_| CoordError::State)?;
        if file.version != PRESENCE_VERSION {
            return Err(CoordError::State);
        }
        let mut state = self.state.lock().map_err(|_| CoordError::State)?;
        for (name, seen) in &file.last_seen_ms {
            let offline_before = file.saved_ms.saturating_sub(*seen);
            state
                .last_seen_ms
                .insert(name.clone(), now.saturating_sub(offline_before));
        }
        Ok(file.last_seen_ms.len())
    }

    /// Return the ephemeral nodes that are offline for longer than the limit,
    /// with the offline time in milliseconds.
    ///
    /// A node with an open request is online. A node with no entry starts at `now`.
    fn due(&self, ephemeral: &[String], now: u64) -> Vec<(String, u64)> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        let limit = u64::try_from(state.offline.as_millis()).unwrap_or(u64::MAX);
        let mut due = Vec::new();
        for name in ephemeral {
            if state.open.contains_key(name) {
                state.last_seen_ms.insert(name.clone(), now);
                continue;
            }
            let seen = *state.last_seen_ms.entry(name.clone()).or_insert(now);
            let offline = now.saturating_sub(seen);
            if offline > limit {
                due.push((name.clone(), offline));
            }
        }
        due
    }

    /// Return the offline time of `name` when the node is still past the limit.
    fn still_due(&self, name: &str, now: u64) -> Option<u64> {
        let state = self.state.lock().ok()?;
        if state.open.contains_key(name) {
            return None;
        }
        let limit = u64::try_from(state.offline.as_millis()).unwrap_or(u64::MAX);
        let offline = now.saturating_sub(*state.last_seen_ms.get(name)?);
        (offline > limit).then_some(offline)
    }

    fn forget(&self, name: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.last_seen_ms.remove(name);
        }
    }

    /// Write the offline times of the ephemeral nodes when a save is due.
    fn save(
        &self,
        dir: &Path,
        ephemeral: &[String],
        now: u64,
        force: bool,
    ) -> Result<(), CoordError> {
        let file = {
            let mut state = self.state.lock().map_err(|_| CoordError::State)?;
            if !force && now.saturating_sub(state.last_save_ms) < SAVE_EVERY_MS {
                return Ok(());
            }
            state.last_save_ms = now;
            let mut last_seen_ms = BTreeMap::new();
            for name in ephemeral {
                if let Some(seen) = state.last_seen_ms.get(name) {
                    last_seen_ms.insert(name.clone(), *seen);
                }
            }
            PresenceFile {
                version: PRESENCE_VERSION,
                saved_ms: now,
                last_seen_ms,
            }
        };
        let path = dir.join(PRESENCE_FILE);
        if file.last_seen_ms.is_empty() && !path.exists() {
            return Ok(());
        }
        let text = serde_json::to_string_pretty(&file).map_err(|_| CoordError::State)?;
        write_text(&path, &text, 0o600)
    }
}

/// Load the saved offline times. The serve path calls this function one time.
pub(crate) fn start(coord: &Coordinator) -> Result<(), CoordError> {
    let dir = coord.state_dir()?;
    let loaded = coord
        .presence()
        .load(&dir, now_ms(SystemTime::now()))
        .map_err(|_| CoordError::Protocol("The ephemeral node file is not valid.".to_string()))?;
    println!(
        "ephemeral offline_secs {} loaded {loaded}",
        coord.presence().offline().as_secs()
    );
    Ok(())
}

/// Remove the ephemeral nodes that are offline for longer than the limit.
///
/// The function returns the removed node names.
pub(crate) fn remove_due(coord: &Coordinator, now: SystemTime) -> Result<Vec<String>, CoordError> {
    let dir = coord.state_dir()?;
    let at = now_ms(now);
    let ephemeral: Vec<String> = coord
        .node_list()?
        .into_iter()
        .filter(|node| node.ephemeral)
        .map(|node| node.name)
        .collect();
    let presence = coord.presence();
    let mut removed = Vec::new();
    for (name, _) in presence.due(&ephemeral, at) {
        let Some(offline) = presence.still_due(&name, at) else {
            continue;
        };
        remove_one(coord, &name, offline, now)?;
        presence.forget(&name);
        removed.push(name);
    }
    let left: Vec<String> = ephemeral
        .into_iter()
        .filter(|name| !removed.contains(name))
        .collect();
    presence.save(&dir, &left, at, !removed.is_empty())?;
    Ok(removed)
}

/// Deny the SVID, delete the record, and write one `node-remove` record.
fn remove_one(
    coord: &Coordinator,
    name: &str,
    offline_ms: u64,
    now: SystemTime,
) -> Result<(), CoordError> {
    let node = coord
        .node_list()?
        .into_iter()
        .find(|node| node.name == name)
        .ok_or_else(|| CoordError::Protocol("The node is not enrolled.".to_string()))?;
    if !node.ephemeral {
        return Err(CoordError::Protocol(
            "The node is not ephemeral.".to_string(),
        ));
    }
    let version = crate::admin::push_revoke(coord, &node.svid, now)?;
    let limit = coord.presence().offline().as_secs();
    let detail = format!("offline_ms {offline_ms} limit_secs {limit} deny_version {version}");
    let removed = coord.remove_ephemeral_node(name, &detail)?;
    println!(
        "ephemeral removed {} overlay_ip {} offline_ms {offline_ms} deny_version {version}",
        removed.name, removed.overlay_ip
    );
    Ok(())
}

/// Run [`remove_due`] each 500 ms.
pub(crate) async fn tick(coord: Coordinator) {
    let mut failed = false;
    loop {
        tokio::time::sleep(TICK).await;
        let step = coord.clone();
        let result =
            tokio::task::spawn_blocking(move || remove_due(&step, SystemTime::now())).await;
        match result {
            Ok(Ok(_)) => failed = false,
            Ok(Err(err)) if !failed => {
                failed = true;
                println!("coord ephemeral tick failed: {}", err.public_text());
            }
            _ => {}
        }
    }
}

fn now_ms(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn a_node_with_an_open_request_is_online() {
        let presence = Presence::default();
        presence.set_offline(Duration::from_secs(2)).unwrap();
        let guard = presence.begin("eph1");
        let later = now_ms(SystemTime::now()) + 60_000;
        assert!(presence.due(&names(&["eph1"]), later).is_empty());
        drop(guard);
        // The drop marks the node seen at the real time.
        let now = now_ms(SystemTime::now());
        assert!(presence.due(&names(&["eph1"]), now).is_empty());
        assert_eq!(presence.due(&names(&["eph1"]), now + 60_000).len(), 1);
    }

    #[test]
    fn a_new_node_starts_online_and_the_limit_is_strict() {
        let presence = Presence::default();
        presence.set_offline(Duration::from_secs(2)).unwrap();
        assert!(presence.due(&names(&["eph1"]), 10_000).is_empty());
        assert!(presence.due(&names(&["eph1"]), 12_000).is_empty());
        assert_eq!(presence.due(&names(&["eph1"]), 12_001).len(), 1);
    }

    #[test]
    fn the_limit_has_bounds() {
        let presence = Presence::default();
        assert_eq!(presence.offline(), DEFAULT_OFFLINE);
        assert!(presence.set_offline(Duration::from_secs(1)).is_err());
        assert!(presence.set_offline(Duration::from_millis(2500)).is_err());
        assert!(presence
            .set_offline(MAX_OFFLINE + Duration::from_secs(1))
            .is_err());
        assert!(presence.set_offline(Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn a_restart_keeps_the_offline_time_and_skips_the_down_time() {
        let dir = std::env::temp_dir().join(format!(
            "orblx-w25q-presence-{}-{}",
            std::process::id(),
            now_ms(SystemTime::now())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let first = Presence::default();
        first.set_offline(Duration::from_secs(10)).unwrap();
        // The node is offline from 1_000. The save is at 7_000, so it has 6 s.
        assert!(first.due(&names(&["eph1"]), 1_000).is_empty());
        first.save(&dir, &names(&["eph1"]), 7_000, true).unwrap();
        // The coordinator is down for 100 s and starts at 107_000.
        let second = Presence::default();
        second.set_offline(Duration::from_secs(10)).unwrap();
        assert_eq!(second.load(&dir, 107_000).unwrap(), 1);
        // No early removal: 6 s + 4 s is not more than 10 s.
        assert!(second.due(&names(&["eph1"]), 111_000).is_empty());
        // No missed removal: 6 s + 4.001 s is more than 10 s.
        assert_eq!(
            second.due(&names(&["eph1"]), 111_001),
            vec![("eph1".to_string(), 10_001)]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orblx-w25q-{label}-{}-{}",
            std::process::id(),
            now_ms(SystemTime::now())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn enroll(coord: &Coordinator, name: &str, ephemeral: bool, now: SystemTime) -> String {
        let ttl = Duration::from_secs(600);
        let token = if ephemeral {
            coord.create_ephemeral_token(ttl).unwrap()
        } else {
            coord.create_token(ttl).unwrap()
        };
        coord
            .enroll_token(
                name,
                &token.secret,
                &["127.0.0.1:443".to_string()],
                &[],
                now,
            )
            .unwrap()
            .overlay_ip
    }

    #[test]
    fn the_tick_removes_only_an_offline_ephemeral_node() {
        let dir = scratch("remove");
        let coord = Coordinator::open(&dir, "coord", crate::OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        coord.set_ephemeral_offline(Duration::from_secs(2)).unwrap();
        let start = SystemTime::now();
        let kept_ip = enroll(&coord, "steady", false, start);
        let eph_ip = enroll(&coord, "eph1", true, start);
        let nodes = coord.node_list().unwrap();
        assert!(!nodes
            .iter()
            .any(|node| node.name == "steady" && node.ephemeral));
        assert!(nodes
            .iter()
            .any(|node| node.name == "eph1" && node.ephemeral));
        assert!(remove_due(&coord, start).unwrap().is_empty());
        assert!(remove_due(&coord, start + Duration::from_secs(2))
            .unwrap()
            .is_empty());
        let removed = remove_due(&coord, start + Duration::from_millis(2_001)).unwrap();
        assert_eq!(removed, vec!["eph1".to_string()]);
        // The node that is not ephemeral stays after 10 times the limit.
        assert!(remove_due(&coord, start + Duration::from_secs(30))
            .unwrap()
            .is_empty());
        let names: Vec<String> = coord
            .node_list()
            .unwrap()
            .into_iter()
            .map(|node| node.name)
            .collect();
        assert_eq!(names, vec!["steady".to_string()]);
        let audit = coord.config_audit_text().unwrap();
        let removes: Vec<&str> = audit
            .lines()
            .filter(|line| line.contains("\"node-remove\""))
            .collect();
        assert_eq!(removes.len(), 1);
        assert!(removes[0].contains("reason ephemeral offline_ms 2001 limit_secs 2"));
        assert!(orblx_audit::ConfigLog::open(&dir.join(crate::state::CONFIG_AUDIT_FILE)).is_ok());
        let deny = crate::admin::deny_json(&coord, SystemTime::now()).unwrap();
        assert!(deny.contains("spiffe://orblx.local/node/eph1"));
        // The removed name cannot enroll again. The address is free for a new node.
        let token = coord
            .create_ephemeral_token(Duration::from_secs(600))
            .unwrap();
        assert!(coord
            .enroll_token(
                "eph1",
                &token.secret,
                &["127.0.0.1:443".to_string()],
                &[],
                start
            )
            .is_err());
        assert_eq!(enroll(&coord, "eph2", true, start), eph_ip);
        assert_ne!(enroll(&coord, "steady2", false, start), kept_ip);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
