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
use std::sync::Mutex;
use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashSet;

    use super::RouteSelector;

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
}
