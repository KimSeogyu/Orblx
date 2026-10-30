//! HA subnet routers (W25).
//!
//! Two or more peers can advertise the same subnet route.
//! The client sends the traffic for that route to one active router.
//! The client changes the active router only when the active router is not healthy.
//! A router that comes back does not take the route back. Thus the route does not flap.
//!
//! A router is healthy when the node has a session with it and received a frame from it
//! in the last [`HA_DEAD_AFTER`]. Each node sends a keepalive frame each 250 ms.
//! The selection uses only local data. It adds no frame and no netmap field.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use orblx_audit::{ConfigAction, ConfigEvent, ConfigLog, EMPTY_DIGEST};

/// The route failover audit chain in the node state directory (W25-10).
pub const ROUTE_AUDIT_FILE: &str = "route-audit.jsonl";

const AUDIT_QUEUE: usize = 64;

/// A router with no received frame for this long is not healthy.
///
/// This time is four keepalive intervals.
pub const HA_DEAD_AFTER: Duration = Duration::from_millis(1000);

/// One change of the active router for an HA route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteChange {
    /// The route, for example `10.88.0.0/24`.
    pub cidr: String,
    /// The router that had the route. `None` for the first selection.
    pub from: Option<String>,
    /// The router that has the route now.
    pub to: String,
}

/// Selects the active router for each HA subnet route.
#[derive(Debug, Default)]
pub struct RouteSelector {
    active: Mutex<HashMap<String, String>>,
}

impl RouteSelector {
    /// Make an empty selector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the router for `cidr` from `candidates`.
    ///
    /// `candidates` is sorted by name. `healthy` tells if a router is healthy now.
    /// 1. The active router stays when it is healthy (no failback, no flap).
    /// 2. Otherwise the first healthy candidate becomes active.
    /// 3. When no candidate is healthy, the active router stays.
    ///    With no active router, the first candidate gets the packet and the
    ///    selector records nothing.
    ///
    /// The second value is the change, when the active router changed.
    pub fn pick(
        &self,
        cidr: &str,
        candidates: &[String],
        healthy: impl Fn(&str) -> bool,
    ) -> (Option<String>, Option<RouteChange>) {
        let mut active = match self.active.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let current = active
            .get(cidr)
            .filter(|name| candidates.iter().any(|peer| peer == *name))
            .cloned();
        if let Some(name) = &current {
            if healthy(name) {
                return (current, None);
            }
        }
        if let Some(next) = candidates.iter().find(|peer| healthy(peer)) {
            active.insert(cidr.to_string(), next.clone());
            let change = RouteChange {
                cidr: cidr.to_string(),
                from: current,
                to: next.clone(),
            };
            return (Some(next.clone()), Some(change));
        }
        match current {
            Some(name) => (Some(name), None),
            None => (candidates.first().cloned(), None),
        }
    }

    /// Return the active router for `cidr`.
    #[must_use]
    pub fn active(&self, cidr: &str) -> Option<String> {
        let active = match self.active.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        active.get(cidr).cloned()
    }
}

/// Writes one `route-failover` record for each failover (W25-10).
///
/// The file is a config chain. `orblx audit verify-config --file FILE` checks it.
/// The records hold node names, the route, and times. They hold no keys.
pub struct RouteAudit {
    actor: String,
    tx: Option<SyncSender<ConfigEvent>>,
}

impl RouteAudit {
    /// Start the writer thread for `path`. `actor` is the SPIFFE ID of this node.
    #[must_use]
    pub fn spawn(path: PathBuf, actor: String) -> Self {
        let (tx, rx) = mpsc::sync_channel(AUDIT_QUEUE);
        let spawned = thread::Builder::new()
            .name("orblx-route-audit".to_string())
            .spawn(move || audit_loop(&path, &rx));
        let tx = match spawned {
            Ok(_) => Some(tx),
            Err(err) => {
                eprintln!("The route audit thread did not start. {err}");
                None
            }
        };
        Self { actor, tx }
    }

    /// Make a writer that writes nothing.
    #[must_use]
    pub fn off() -> Self {
        Self {
            actor: String::new(),
            tx: None,
        }
    }

    /// Queue one record. The first selection of a route is not a failover.
    ///
    /// `silent_ms` is the time since the last frame from the old router.
    /// `None` means the old router had no session.
    pub fn record(&self, change: &RouteChange, silent_ms: Option<u128>) {
        let (Some(tx), Some(from)) = (&self.tx, &change.from) else {
            return;
        };
        let silent = silent_ms.map_or_else(|| "no-session".to_string(), |ms| format!("{ms}"));
        let event = ConfigEvent {
            actor: self.actor.clone(),
            at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0),
            action: ConfigAction::RouteFailover,
            target: change.cidr.clone(),
            before: EMPTY_DIGEST,
            after: EMPTY_DIGEST,
            detail: format!("from {from} to {} old_silent_ms {silent}", change.to),
        };
        if tx.try_send(event).is_err() {
            eprintln!("The route audit queue is full. The node did not queue a record.");
        }
    }
}

fn audit_loop(path: &Path, rx: &Receiver<ConfigEvent>) {
    let mut log: Option<ConfigLog> = None;
    while let Ok(event) = rx.recv() {
        if log.is_none() {
            match ConfigLog::open(path) {
                Ok(opened) => log = Some(opened),
                Err(err) => {
                    eprintln!("The route audit chain did not open. {err}");
                    continue;
                }
            }
        }
        if let Some(log) = log.as_mut() {
            if let Err(err) = log.append(event) {
                eprintln!("The route audit record was not written. {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashSet;

    use super::{RouteAudit, RouteChange, RouteSelector};

    const CIDR: &str = "10.88.0.0/24";

    fn names() -> Vec<String> {
        vec!["router-a".to_string(), "router-b".to_string()]
    }

    #[test]
    fn the_first_healthy_router_takes_the_route() {
        let selector = RouteSelector::new();
        let (peer, change) = selector.pick(CIDR, &names(), |_| true);
        assert_eq!(peer.as_deref(), Some("router-a"));
        let change = change.unwrap();
        assert_eq!(change.from, None);
        assert_eq!(change.to, "router-a");
        let (peer, change) = selector.pick(CIDR, &names(), |_| true);
        assert_eq!(peer.as_deref(), Some("router-a"));
        assert!(change.is_none());
    }

    #[test]
    fn the_standby_takes_the_route_when_the_active_router_fails() {
        let selector = RouteSelector::new();
        let _ = selector.pick(CIDR, &names(), |_| true);
        let (peer, change) = selector.pick(CIDR, &names(), |name| name == "router-b");
        assert_eq!(peer.as_deref(), Some("router-b"));
        let change = change.unwrap();
        assert_eq!(change.from.as_deref(), Some("router-a"));
        assert_eq!(change.to, "router-b");
        assert_eq!(selector.active(CIDR).as_deref(), Some("router-b"));
    }

    #[test]
    fn a_router_that_comes_back_does_not_take_the_route_back() {
        let selector = RouteSelector::new();
        let _ = selector.pick(CIDR, &names(), |_| true);
        let _ = selector.pick(CIDR, &names(), |name| name == "router-b");
        let mut changes = 0;
        for _ in 0..1000 {
            let (peer, change) = selector.pick(CIDR, &names(), |_| true);
            assert_eq!(peer.as_deref(), Some("router-b"));
            changes += usize::from(change.is_some());
        }
        assert_eq!(changes, 0);
    }

    #[test]
    fn no_healthy_router_keeps_the_active_router_and_records_nothing() {
        let selector = RouteSelector::new();
        let (peer, change) = selector.pick(CIDR, &names(), |_| false);
        assert_eq!(peer.as_deref(), Some("router-a"));
        assert!(change.is_none());
        assert_eq!(selector.active(CIDR), None);
        let _ = selector.pick(CIDR, &names(), |name| name == "router-b");
        let (peer, change) = selector.pick(CIDR, &names(), |_| false);
        assert_eq!(peer.as_deref(), Some("router-b"));
        assert!(change.is_none());
    }

    #[test]
    fn a_router_that_leaves_the_netmap_loses_the_route() {
        let selector = RouteSelector::new();
        let _ = selector.pick(CIDR, &names(), |name| name == "router-b");
        let only_a = vec!["router-a".to_string()];
        let (peer, change) = selector.pick(CIDR, &only_a, |_| true);
        assert_eq!(peer.as_deref(), Some("router-a"));
        assert_eq!(change.unwrap().from, None);
    }

    #[test]
    fn each_route_has_its_own_active_router() {
        let selector = RouteSelector::new();
        let _ = selector.pick("10.88.0.0/24", &names(), |name| name == "router-b");
        let (peer, _) = selector.pick("10.99.0.0/24", &names(), |_| true);
        assert_eq!(peer.as_deref(), Some("router-a"));
        assert_eq!(selector.active("10.88.0.0/24").as_deref(), Some("router-b"));
    }

    #[test]
    fn health_that_toggles_on_the_standby_does_not_move_the_route() {
        // router-b is active. router-a goes up and down each call.
        let selector = RouteSelector::new();
        let _ = selector.pick(CIDR, &names(), |name| name == "router-b");
        let flip = RefCell::new(false);
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let a_up = {
                let mut flip = flip.borrow_mut();
                *flip = !*flip;
                *flip
            };
            let (peer, change) = selector.pick(CIDR, &names(), |name| name == "router-b" || a_up);
            assert!(change.is_none());
            seen.insert(peer.unwrap());
        }
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn a_failover_writes_one_verified_record_and_a_first_selection_writes_none() {
        let dir = std::env::temp_dir().join(format!("orblx-route-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(super::ROUTE_AUDIT_FILE);
        {
            let audit =
                RouteAudit::spawn(path.clone(), "spiffe://orblx.local/node/client".to_string());
            audit.record(
                &RouteChange {
                    cidr: CIDR.to_string(),
                    from: None,
                    to: "router-a".to_string(),
                },
                None,
            );
            audit.record(
                &RouteChange {
                    cidr: CIDR.to_string(),
                    from: Some("router-a".to_string()),
                    to: "router-b".to_string(),
                },
                Some(1003),
            );
        }
        let mut verified = None;
        for _ in 0..100 {
            if let Ok(chain) = orblx_audit::verify_config_file(&path) {
                if !chain.records.is_empty() {
                    verified = Some(chain);
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let chain = verified.unwrap();
        assert_eq!(chain.records.len(), 1);
        let event = &chain.records[0].event;
        assert_eq!(event.action.as_str(), "route-failover");
        assert_eq!(event.target, CIDR);
        assert_eq!(event.detail, "from router-a to router-b old_silent_ms 1003");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
