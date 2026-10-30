//! Node sharing to a guest of another user (W25-1).
//!
//! The policy names guest users in `guests` and node shares in `shares`.
//!
//! ```hujson
//! "guests": ["oidc:bob"],
//! "shares": [
//!   {"dst": "spiffe://orblx.local/node/b:8080", "proto": "tcp", "with": ["oidc:bob"]},
//! ],
//! ```
//!
//! A guest is an OIDC subject. The nodes that the subject enrolled are the guest nodes.
//! A guest node sees and reaches only the nodes that a share gives to it.
//! The other nodes do not see the guest nodes.
//! A share can also give a node of a guest to one node (`with` is a node SPIFFE ID).
//! This is a share back to the owner.
//!
//! A guest from another trust domain needs a federated trust bundle.
//! This version does not have one, so the policy refuses such a guest.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::policy::{parse_port_spec, parse_proto, split_target, PolicyError};
use crate::spiffe::{SpiffeId, WorkloadKind, TRUST_DOMAIN};

const MAX_SHARES: usize = 1024;
const MAX_SUBJECT: usize = 128;
const OIDC_PREFIX: &str = "oidc:";

/// One guest of a share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ShareGuest {
    /// All nodes that this OIDC subject enrolled. The value is the store owner `oidc:SUBJECT`.
    Oidc(String),
    /// One node.
    Node(SpiffeId),
}

impl ShareGuest {
    /// The text form: `oidc:SUBJECT` or the node SPIFFE ID.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Oidc(owner) => owner,
            Self::Node(id) => id.as_uri(),
        }
    }

    /// Return true when the node with this store owner and SVID is this guest.
    #[must_use]
    pub fn matches(&self, owner: &str, svid: &str) -> bool {
        match self {
            Self::Oidc(guest) => guest == owner,
            Self::Node(id) => id.as_uri() == svid,
        }
    }
}

/// One share: one node (all ports or some ports) for one guest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Share {
    /// The shared node.
    pub node: SpiffeId,
    /// IP protocol numbers. TCP is 6. UDP is 17.
    pub protos: Vec<u8>,
    /// Inclusive port ranges.
    pub ranges: Vec<(u16, u16)>,
    /// The guest.
    pub guest: ShareGuest,
}

impl Share {
    /// One stable text line for the audit record and for a diff.
    ///
    /// Example: `spiffe://orblx.local/node/b tcp 8080 with oidc:bob`.
    #[must_use]
    pub fn line(&self) -> String {
        let protos: Vec<&str> = self
            .protos
            .iter()
            .map(|proto| if *proto == 6 { "tcp" } else { "udp" })
            .collect();
        let ranges: Vec<String> = self
            .ranges
            .iter()
            .map(|(start, end)| {
                if start == end {
                    start.to_string()
                } else {
                    format!("{start}-{end}")
                }
            })
            .collect();
        format!(
            "{} {} {} with {}",
            self.node.as_uri(),
            protos.join(","),
            ranges.join(","),
            self.guest.label()
        )
    }
}

/// One share rule in the policy file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShareFile {
    dst: String,
    #[serde(default)]
    proto: Option<String>,
    with: Vec<String>,
}

/// Read the `guests` list. Each entry is `oidc:SUBJECT`.
pub(crate) fn compile_guests(guests: &[String]) -> Result<BTreeSet<String>, PolicyError> {
    let mut out = BTreeSet::new();
    for text in guests {
        if !out.insert(parse_oidc_guest(text)?) {
            return Err(PolicyError::new(format!(
                "The guest {} is in the guests list two times.",
                safe(text)
            )));
        }
    }
    Ok(out)
}

/// Read the `shares` list. The result has one share for each guest of each rule.
pub(crate) fn compile_shares(
    guests: &BTreeSet<String>,
    files: &[ShareFile],
) -> Result<Vec<Share>, PolicyError> {
    let mut shares = BTreeMap::new();
    for file in files {
        if file.with.is_empty() {
            return Err(PolicyError::new("The share needs a guest in with."));
        }
        let (selector, port_text) = split_target(&file.dst)?;
        let node = SpiffeId::parse(selector).map_err(|_| {
            PolicyError::new(format!(
                "The share destination {} is not a node SPIFFE ID.",
                safe(selector)
            ))
        })?;
        if node.kind() != WorkloadKind::Node {
            return Err(PolicyError::new(format!(
                "The share destination {} is not a node SPIFFE ID.",
                safe(selector)
            )));
        }
        let ranges = parse_port_spec(port_text)?;
        let protos = match &file.proto {
            Some(text) => vec![parse_proto(text)?],
            None => vec![6, 17],
        };
        for text in &file.with {
            let guest = parse_share_guest(guests, text)?;
            if let ShareGuest::Node(id) = &guest {
                if *id == node {
                    return Err(PolicyError::new(
                        "The share cannot give a node to the same node.",
                    ));
                }
            }
            let share = Share {
                node: node.clone(),
                protos: protos.clone(),
                ranges: ranges.clone(),
                guest,
            };
            shares.insert(share.line(), share);
            if shares.len() > MAX_SHARES {
                return Err(PolicyError::new("The policy has too many shares."));
            }
        }
    }
    Ok(shares.into_values().collect())
}

fn parse_share_guest(guests: &BTreeSet<String>, text: &str) -> Result<ShareGuest, PolicyError> {
    if text.starts_with(OIDC_PREFIX) {
        let owner = parse_oidc_guest(text)?;
        if !guests.contains(&owner) {
            return Err(PolicyError::new(format!(
                "The share guest {} is not in the guests list.",
                safe(text)
            )));
        }
        return Ok(ShareGuest::Oidc(owner));
    }
    if let Some(rest) = text.strip_prefix("spiffe://") {
        let domain = rest.split('/').next().unwrap_or_default();
        if domain != TRUST_DOMAIN {
            return Err(PolicyError::new(format!(
                "The share guest {} is in another trust domain. That needs a federated trust bundle. This version does not support it.",
                safe(text)
            )));
        }
        let id = SpiffeId::parse(text)
            .map_err(|_| PolicyError::new(format!("The SPIFFE ID {} is not valid.", safe(text))))?;
        if id.kind() != WorkloadKind::Node {
            return Err(PolicyError::new(format!(
                "The share guest {} is not a node. Use oidc:SUBJECT for a user.",
                safe(text)
            )));
        }
        return Ok(ShareGuest::Node(id));
    }
    Err(PolicyError::new(format!(
        "The share guest {} is not oidc:SUBJECT or a node SPIFFE ID.",
        safe(text)
    )))
}

fn parse_oidc_guest(text: &str) -> Result<String, PolicyError> {
    let Some(subject) = text.strip_prefix(OIDC_PREFIX) else {
        return Err(PolicyError::new(format!(
            "The guest {} is not oidc:SUBJECT.",
            safe(text)
        )));
    };
    // The same rule as the coordinator store uses for an OIDC owner.
    if subject.is_empty()
        || subject.len() > MAX_SUBJECT
        || subject.contains([':', '\n'])
        || subject.chars().any(char::is_control)
    {
        return Err(PolicyError::new(format!(
            "The guest {} is not oidc:SUBJECT.",
            safe(text)
        )));
    }
    Ok(text.to_string())
}

/// Return the policy rules as JSON text without the `shares` list.
///
/// The coordinator compares this text to see whether a new policy file changed only shares.
#[must_use]
pub fn rules_without_shares(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let json = crate::policy::hujson_to_json(text).ok()?;
    let mut value: serde_json::Value = serde_json::from_str(&json).ok()?;
    value.as_object_mut()?.remove("shares");
    serde_json::to_string(&value).ok()
}

fn safe(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control())
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::Policy;

    fn load(text: &str) -> Result<Policy, String> {
        Policy::from_hujson(text.as_bytes()).map_err(|err| err.to_string())
    }

    #[test]
    fn share_rules_compile_to_one_share_for_each_guest() {
        let policy = load(
            r#"{
              "guests": ["oidc:bob", "oidc:carol"],
              "shares": [
                {"dst": "spiffe://orblx.local/node/b:8080", "proto": "tcp", "with": ["oidc:bob", "oidc:carol"]},
                {"dst": "spiffe://orblx.local/node/g:*", "with": ["spiffe://orblx.local/node/a"]},
              ],
            }"#,
        )
        .unwrap();
        let lines: Vec<String> = policy.shares().iter().map(|share| share.line()).collect();
        assert_eq!(
            lines,
            vec![
                "spiffe://orblx.local/node/b tcp 8080 with oidc:bob",
                "spiffe://orblx.local/node/b tcp 8080 with oidc:carol",
                "spiffe://orblx.local/node/g tcp,udp 1-65535 with spiffe://orblx.local/node/a",
            ]
        );
        assert!(policy.is_guest_owner("oidc:bob"));
        assert!(!policy.is_guest_owner("oidc:alice"));
        assert!(!policy.is_guest_owner("token:1"));
    }

    #[test]
    fn bad_shares_are_refused() {
        let cases = [
            (
                r#"{"shares": [{"dst": "spiffe://orblx.local/node/b:80", "with": ["oidc:bob"]}]}"#,
                "not in the guests list",
            ),
            (
                r#"{"guests": ["oidc:bob"], "shares": [{"dst": "spiffe://other.example/node/b:80", "with": ["oidc:bob"]}]}"#,
                "not a node SPIFFE ID",
            ),
            (
                r#"{"guests": ["oidc:bob"], "shares": [{"dst": "spiffe://orblx.local/node/b:80", "with": ["spiffe://other.example/node/x"]}]}"#,
                "another trust domain",
            ),
            (
                r#"{"guests": ["oidc:bob"], "shares": [{"dst": "spiffe://orblx.local/node/b:80", "with": ["spiffe://orblx.local/user/bob"]}]}"#,
                "is not a node",
            ),
            (
                r#"{"guests": ["oidc:bob"], "shares": [{"dst": "spiffe://orblx.local/node/b:80", "with": []}]}"#,
                "needs a guest",
            ),
            (
                r#"{"guests": ["oidc:bob"], "shares": [{"dst": "spiffe://orblx.local/node/b", "with": ["oidc:bob"]}]}"#,
                "needs a port",
            ),
            (r#"{"guests": ["bob"]}"#, "not oidc:SUBJECT"),
            (r#"{"guests": ["oidc:bob", "oidc:bob"]}"#, "two times"),
            (
                r#"{"shares": [{"dst": "spiffe://orblx.local/node/b:80", "with": ["spiffe://orblx.local/node/b"]}]}"#,
                "same node",
            ),
        ];
        for (text, needle) in cases {
            let err = load(text).unwrap_err();
            assert!(err.contains(needle), "{text}: {err}");
        }
    }
}
