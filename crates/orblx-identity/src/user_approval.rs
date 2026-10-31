//! The `userApproval` policy object (W25-15).
//!
//! A new OIDC user waits until an owner approves the user.
//! `ownerUsers` names the owner OIDC users. An owner user never waits.
//! `autoApproveDomains` names email domains that the coordinator approves with no owner step.
//! The default is no owner users and no domains, so auto-approve is off.
//! A domain match needs a verified `email` claim.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::policy::PolicyError;
use crate::share::{oidc_user_ok, safe};

const MAX_OWNER_USERS: usize = 64;
const MAX_AUTO_DOMAINS: usize = 64;
const MAX_DOMAIN: usize = 253;

/// The `userApproval` object in the policy file.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserApprovalFile {
    #[serde(default, rename = "ownerUsers")]
    owner_users: Vec<String>,
    #[serde(default, rename = "autoApproveDomains")]
    auto_approve_domains: Vec<String>,
}

/// The checked `userApproval` object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserApproval {
    owner_users: BTreeSet<String>,
    auto_domains: BTreeSet<String>,
}

impl UserApproval {
    /// Return true when `user` (`oidc:SUBJECT`) is an owner user.
    #[must_use]
    pub fn is_owner_user(&self, user: &str) -> bool {
        self.owner_users.contains(user)
    }

    /// Return the auto-approve domain that matches a verified email, if any.
    ///
    /// An email that is not verified never matches.
    #[must_use]
    pub fn auto_domain(&self, email: Option<&str>, verified: bool) -> Option<&str> {
        if !verified {
            return None;
        }
        let (_, domain) = email?.rsplit_once('@')?;
        let domain = domain.to_ascii_lowercase();
        self.auto_domains
            .iter()
            .find(|allowed| **allowed == domain)
            .map(String::as_str)
    }

    /// Return true when the policy has an auto-approve domain.
    #[must_use]
    pub fn auto_approve_on(&self) -> bool {
        !self.auto_domains.is_empty()
    }

    /// Return the owner users count.
    #[must_use]
    pub fn owner_users_len(&self) -> usize {
        self.owner_users.len()
    }
}

pub(crate) fn compile_user_approval(file: &UserApprovalFile) -> Result<UserApproval, PolicyError> {
    if file.owner_users.len() > MAX_OWNER_USERS {
        return Err(PolicyError::new(format!(
            "The policy has more than {MAX_OWNER_USERS} owner users."
        )));
    }
    if file.auto_approve_domains.len() > MAX_AUTO_DOMAINS {
        return Err(PolicyError::new(format!(
            "The policy has more than {MAX_AUTO_DOMAINS} auto-approve domains."
        )));
    }
    let mut owner_users = BTreeSet::new();
    for user in &file.owner_users {
        if !oidc_user_ok(user) {
            return Err(PolicyError::new(format!(
                "The owner user {} is not oidc:SUBJECT.",
                safe(user)
            )));
        }
        if !owner_users.insert(user.clone()) {
            return Err(PolicyError::new(format!(
                "The owner user {} is in the list two times.",
                safe(user)
            )));
        }
    }
    let mut auto_domains = BTreeSet::new();
    for domain in &file.auto_approve_domains {
        let lower = domain.trim().to_ascii_lowercase();
        if !domain_ok(&lower) {
            return Err(PolicyError::new(format!(
                "The auto-approve domain {} is not a DNS name.",
                safe(domain)
            )));
        }
        if !auto_domains.insert(lower) {
            return Err(PolicyError::new(format!(
                "The auto-approve domain {} is in the list two times.",
                safe(domain)
            )));
        }
    }
    Ok(UserApproval {
        owner_users,
        auto_domains,
    })
}

/// A DNS name with at least two labels. No wildcard.
fn domain_ok(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > MAX_DOMAIN || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use crate::Policy;

    fn load(text: &str) -> Result<Policy, String> {
        Policy::from_hujson(text.as_bytes()).map_err(|err| err.to_string())
    }

    #[test]
    fn auto_approve_is_off_by_default() {
        let policy = load("{}").unwrap();
        let approval = policy.user_approval();
        assert!(!approval.auto_approve_on());
        assert_eq!(approval.owner_users_len(), 0);
        assert_eq!(approval.auto_domain(Some("ann@example.com"), true), None);
        assert!(!approval.is_owner_user("oidc:ann"));
    }

    #[test]
    fn auto_approve_matches_only_a_verified_email_domain() {
        let policy = load(
            r#"{"userApproval": {"ownerUsers": ["oidc:alice"], "autoApproveDomains": ["Example.com"]}}"#,
        )
        .unwrap();
        let approval = policy.user_approval();
        assert!(approval.auto_approve_on());
        assert!(approval.is_owner_user("oidc:alice"));
        assert!(!approval.is_owner_user("oidc:bob"));
        assert_eq!(
            approval.auto_domain(Some("bob@example.com"), true),
            Some("example.com")
        );
        assert_eq!(approval.auto_domain(Some("bob@example.com"), false), None);
        assert_eq!(
            approval.auto_domain(Some("bob@sub.example.com"), true),
            None
        );
        assert_eq!(approval.auto_domain(Some("bob@example.org"), true), None);
        assert_eq!(approval.auto_domain(None, true), None);
    }

    #[test]
    fn bad_user_approval_entries_are_refused() {
        for text in [
            r#"{"userApproval": {"ownerUsers": ["alice"]}}"#,
            r#"{"userApproval": {"ownerUsers": ["oidc:"]}}"#,
            r#"{"userApproval": {"ownerUsers": ["oidc:a", "oidc:a"]}}"#,
            r#"{"userApproval": {"autoApproveDomains": ["*.example.com"]}}"#,
            r#"{"userApproval": {"autoApproveDomains": ["com"]}}"#,
            r#"{"userApproval": {"autoApproveDomains": ["a.com", "A.com"]}}"#,
            r#"{"userApproval": {"autoApprove": true}}"#,
        ] {
            assert!(load(text).is_err(), "{text}");
        }
    }
}
