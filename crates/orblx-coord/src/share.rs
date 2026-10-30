//! Node sharing to a guest of another user (W25-1).
//!
//! The policy `guests` list makes tenants:
//!
//! - A node whose store owner is in `guests` is in the tenant of that owner.
//! - All other nodes are in the home tenant.
//!
//! A node sees a peer when both are in the same tenant, or when a share gives one to the other.
//! A policy without `guests` has one tenant, so all nodes see all nodes as before.
//!
//! The coordinator uses this rule for the netmap, the grants, and the deny list of each node.

use std::collections::BTreeSet;

use orblx_identity::{Policy, ReceiverGrant};

use crate::store::StoredNode;

/// Return the tenant of a node. The home tenant is the empty text.
fn tenant<'a>(policy: &Policy, node: &'a StoredNode) -> &'a str {
    if policy.is_guest_owner(&node.owner) {
        &node.owner
    } else {
        ""
    }
}

/// Return true when one share gives `node` to `guest`.
fn shared(policy: &Policy, node: &StoredNode, guest: &StoredNode) -> bool {
    policy.shares().iter().any(|share| {
        share.node.as_uri() == node.svid && share.guest.matches(&guest.owner, &guest.svid)
    })
}

/// Return true when `viewer` may see `peer`.
pub(crate) fn sees(policy: &Policy, viewer: &StoredNode, peer: &StoredNode) -> bool {
    if !policy.has_guests() || viewer.name == peer.name {
        return true;
    }
    tenant(policy, viewer) == tenant(policy, peer)
        || shared(policy, peer, viewer)
        || shared(policy, viewer, peer)
}

/// Return true when `viewer` and `peer` are in different tenants.
pub(crate) fn cross_tenant(policy: &Policy, viewer: &StoredNode, peer: &StoredNode) -> bool {
    policy.has_guests() && tenant(policy, viewer) != tenant(policy, peer)
}

/// Return the grants that shares give to `receiver`.
///
/// Each guest node gets the shared protocols and ports on the shared node.
pub(crate) fn share_grants(
    policy: &Policy,
    receiver: &StoredNode,
    nodes: &[StoredNode],
) -> Vec<ReceiverGrant> {
    let mut out = Vec::new();
    for share in policy.shares() {
        if share.node.as_uri() != receiver.svid {
            continue;
        }
        for guest in nodes {
            if guest.name == receiver.name || !share.guest.matches(&guest.owner, &guest.svid) {
                continue;
            }
            for proto in &share.protos {
                for (start, end) in &share.ranges {
                    out.push(ReceiverGrant {
                        src: guest.svid.clone(),
                        proto: *proto,
                        port_start: *start,
                        port_end: *end,
                    });
                }
            }
        }
    }
    out
}

/// Return the shared nodes that `viewer` may reach.
pub(crate) fn share_reach(policy: &Policy, viewer: &StoredNode) -> BTreeSet<String> {
    policy
        .shares()
        .iter()
        .filter(|share| {
            share.node.as_uri() != viewer.svid && share.guest.matches(&viewer.owner, &viewer.svid)
        })
        .map(|share| share.node.as_uri().to_string())
        .collect()
}

/// Return the SPIFFE IDs of the stored nodes that `viewer` does not see.
pub(crate) fn hidden_for(
    policy: &Policy,
    viewer: &StoredNode,
    nodes: &[StoredNode],
) -> Vec<String> {
    if !policy.has_guests() {
        return Vec::new();
    }
    let hidden: BTreeSet<String> = nodes
        .iter()
        .filter(|peer| !sees(policy, viewer, peer))
        .map(|peer| peer.svid.clone())
        .collect();
    hidden.into_iter().collect()
}

/// Return the stable share lines of a policy.
pub(crate) fn share_lines(policy: &Policy) -> BTreeSet<String> {
    policy.shares().iter().map(|share| share.line()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, owner: &str) -> StoredNode {
        StoredNode {
            name: name.to_string(),
            overlay_ip: String::new(),
            svid: format!("spiffe://orblx.local/node/{name}"),
            owner: owner.to_string(),
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            approved: true,
            expired: false,
            ephemeral: false,
        }
    }

    fn policy(text: &str) -> Policy {
        Policy::from_hujson(text.as_bytes()).unwrap()
    }

    #[test]
    fn guest_sees_only_the_shared_node() {
        let policy = policy(
            r#"{"guests": ["oidc:bob"],
                "shares": [{"dst": "spiffe://orblx.local/node/b:8080", "proto": "tcp", "with": ["oidc:bob"]}]}"#,
        );
        let a = node("a", "token:1");
        let b = node("b", "token:2");
        let g = node("g", "oidc:bob");
        let g2 = node("g2", "oidc:bob");
        let nodes = vec![a.clone(), b.clone(), g.clone(), g2.clone()];
        assert_eq!(
            hidden_for(&policy, &g, &nodes),
            vec!["spiffe://orblx.local/node/a".to_string()]
        );
        assert_eq!(
            hidden_for(&policy, &a, &nodes),
            vec![
                "spiffe://orblx.local/node/g".to_string(),
                "spiffe://orblx.local/node/g2".to_string()
            ]
        );
        assert!(hidden_for(&policy, &b, &nodes).is_empty());
        assert!(sees(&policy, &a, &b));
        assert!(sees(&policy, &g, &g2));
        let grants = share_grants(&policy, &b, &nodes);
        assert_eq!(grants.len(), 2);
        assert!(grants
            .iter()
            .all(|grant| grant.proto == 6 && grant.port_start == 8080 && grant.port_end == 8080));
        assert!(share_grants(&policy, &g, &nodes).is_empty());
        assert_eq!(
            share_reach(&policy, &g).into_iter().collect::<Vec<_>>(),
            vec!["spiffe://orblx.local/node/b".to_string()]
        );
        assert!(share_reach(&policy, &a).is_empty());
        assert!(cross_tenant(&policy, &g, &b));
        assert!(!cross_tenant(&policy, &a, &b));
    }

    #[test]
    fn share_back_gives_one_guest_node_to_one_owner_node() {
        let policy = policy(
            r#"{"guests": ["oidc:bob"],
                "shares": [{"dst": "spiffe://orblx.local/node/g:22", "with": ["spiffe://orblx.local/node/a"]}]}"#,
        );
        let a = node("a", "token:1");
        let c = node("c", "token:1");
        let g = node("g", "oidc:bob");
        let nodes = vec![a.clone(), c.clone(), g.clone()];
        assert!(sees(&policy, &a, &g));
        assert!(sees(&policy, &g, &a));
        assert!(!sees(&policy, &c, &g));
        assert_eq!(share_grants(&policy, &g, &nodes).len(), 2);
    }

    #[test]
    fn a_policy_without_guests_hides_nothing() {
        let policy = policy("{}");
        let a = node("a", "token:1");
        let g = node("g", "oidc:bob");
        assert!(hidden_for(&policy, &a, &[a.clone(), g.clone()]).is_empty());
        assert!(sees(&policy, &g, &a));
    }
}
