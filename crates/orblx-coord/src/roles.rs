//! Human admin roles for the admin API (candidate A).
//!
//! The coordinator stores one role for each OIDC user.
//! Each admin operation has a list of roles that can call it.
//! A policy owner SVID has the owner role.
//! A node of an OIDC user uses the role of that user.
//! An API token cannot do more than the role of its creator.

use orblx_audit::{ConfigAction, EMPTY_DIGEST};
use orblx_identity::SpiffeId;
use serde::Deserialize;

use crate::error::CoordError;
use crate::state::Coordinator;

const OWNER: u8 = 1 << 0;
const ADMIN: u8 = 1 << 1;
const NETWORK: u8 = 1 << 2;
const IT: u8 = 1 << 3;
const AUDITOR: u8 = 1 << 4;

/// One human admin role.
///
/// The names match the admin console roles: owner, admin, network admin,
/// IT admin, auditor, and member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    NetworkAdmin,
    ItAdmin,
    Auditor,
    Member,
}

impl Role {
    /// The stable role token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::NetworkAdmin => "network-admin",
            Self::ItAdmin => "it-admin",
            Self::Auditor => "auditor",
            Self::Member => "member",
        }
    }

    fn bit(self) -> u8 {
        match self {
            Self::Owner => OWNER,
            Self::Admin => ADMIN,
            Self::NetworkAdmin => NETWORK,
            Self::ItAdmin => IT,
            Self::Auditor => AUDITOR,
            Self::Member => 0,
        }
    }

    /// Return true when this role can call `op`.
    ///
    /// An unknown operation is refused.
    pub fn allows(self, op: &str) -> bool {
        OPS.iter()
            .find(|(name, _)| *name == op)
            .is_some_and(|(_, bits)| bits & self.bit() != 0)
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "network-admin" => Some(Self::NetworkAdmin),
            "it-admin" => Some(Self::ItAdmin),
            "auditor" => Some(Self::Auditor),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

/// The sentence for one role refusal.
///
/// A member gets the same sentence as a caller that is not an owner.
/// Existing proofs look for that sentence.
pub fn deny_text(role: Role) -> &'static str {
    match role {
        Role::Member => "The caller is not an owner.",
        Role::Owner => "The role owner cannot call this operation.",
        Role::Admin => "The role admin cannot call this operation.",
        Role::NetworkAdmin => "The role network-admin cannot call this operation.",
        Role::ItAdmin => "The role it-admin cannot call this operation.",
        Role::Auditor => "The role auditor cannot call this operation.",
    }
}

/// Parse a role token. The error does not echo unsafe text.
pub fn parse_admin_role(text: &str) -> Result<Role, CoordError> {
    Role::parse(text.trim()).ok_or_else(|| {
        let clean: String = text
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
            .take(32)
            .collect();
        let shown = if clean.is_empty() { "empty" } else { &clean };
        CoordError::Protocol(format!("The role {shown} is not valid."))
    })
}

/// Each admin operation and the roles that can call it.
///
/// The set is the same as `apitoken::admin_ops`. A new admin operation
/// must get a row here and a scope row (or an owner-only row).
const OPS: &[(&str, u8)] = &[
    ("admin-nodes", OWNER | ADMIN | NETWORK | IT | AUDITOR),
    ("admin-users", OWNER | ADMIN | NETWORK | IT | AUDITOR),
    ("admin-roles", OWNER | ADMIN | NETWORK | IT | AUDITOR),
    ("admin-routes", OWNER | ADMIN | NETWORK | IT | AUDITOR),
    ("admin-grants", OWNER | ADMIN | NETWORK | IT | AUDITOR),
    ("admin-lock", OWNER | ADMIN | NETWORK | IT | AUDITOR),
    ("admin-policy", OWNER | ADMIN | NETWORK | AUDITOR),
    ("admin-audit", OWNER | ADMIN | AUDITOR),
    ("admin-approve", OWNER | ADMIN | NETWORK | IT),
    ("admin-preauth-list", OWNER | ADMIN | NETWORK | IT | AUDITOR),
    ("admin-preauth-create", OWNER | ADMIN | NETWORK | IT),
    ("admin-preauth-revoke", OWNER | ADMIN | NETWORK | IT),
    ("admin-revoke", OWNER | ADMIN | NETWORK | IT),
    ("admin-revoke-all", OWNER | ADMIN | NETWORK | IT),
    ("admin-revoke-undo", OWNER | ADMIN | NETWORK | IT),
    ("admin-expire", OWNER | ADMIN | NETWORK | IT),
    ("admin-user-approve", OWNER | ADMIN | IT),
    ("admin-user-reject", OWNER | ADMIN | IT),
    ("admin-grant-approve", OWNER | ADMIN | NETWORK),
    ("admin-grant-revoke", OWNER | ADMIN | NETWORK),
    ("admin-lock-init", OWNER | ADMIN | NETWORK),
    ("admin-lock-sign", OWNER | ADMIN | NETWORK),
    ("admin-lock-update", OWNER | ADMIN | NETWORK),
    ("admin-policy-set", OWNER | ADMIN | NETWORK),
    ("admin-token-create", OWNER | ADMIN | NETWORK | IT),
    ("admin-token-list", OWNER | ADMIN),
    ("admin-token-revoke", OWNER | ADMIN | NETWORK | IT),
    ("admin-role-set", OWNER),
];

/// Return true when every operation in `scope` is allowed for `role`.
pub fn scope_fits(role: Role, scope: &str, ops: &[(&str, &str)]) -> bool {
    ops.iter()
        .filter(|(_, op_scope)| *op_scope == scope)
        .all(|(op, _)| role.allows(op))
}

/// The role of `actor` now.
///
/// A policy owner SVID is `owner`.
/// An enrolled node uses the approved role of its OIDC user, or `member`
/// when the node has no OIDC user or that user is not approved.
/// `None` means the actor is not a known node and not a policy owner.
pub fn live_role(coord: &Coordinator, actor: &str) -> Result<Option<Role>, CoordError> {
    if let Ok(id) = SpiffeId::parse(actor) {
        if coord.caller_is_owner(&id)? {
            return Ok(Some(Role::Owner));
        }
        let nodes = coord.node_list()?;
        if let Some(node) = nodes.into_iter().find(|node| node.svid == actor) {
            if let Some(user) = oidc_user(&node.owner) {
                return Ok(Some(approved_user_role(coord, &user)?));
            }
            return Ok(Some(Role::Member));
        }
        return Ok(None);
    }
    if let Some(user) = oidc_user(actor) {
        return Ok(Some(approved_user_role(coord, &user)?));
    }
    Ok(None)
}

/// The role of `actor` for a call that must fail closed.
///
/// An unknown actor is `member`.
pub fn require_live(coord: &Coordinator, actor: &str) -> Result<Role, CoordError> {
    Ok(live_role(coord, actor)?.unwrap_or(Role::Member))
}

/// The OIDC user that a new token must follow, or empty.
///
/// A policy owner SVID does not bind the token to a user.
/// Each later call reads that SVID from the current policy and the node store.
pub fn token_user(coord: &Coordinator, actor: &str) -> Result<String, CoordError> {
    if let Ok(id) = SpiffeId::parse(actor) {
        if coord.caller_is_owner(&id)? {
            return Ok(String::new());
        }
        if let Some(node) = coord
            .node_list()?
            .into_iter()
            .find(|node| node.svid == actor)
        {
            if let Some(user) = oidc_user(&node.owner) {
                return Ok(user);
            }
        }
    }
    Ok(String::new())
}

/// The role that blocks one token call, when the token would pass its scope.
///
/// The effective rights are the token scopes crossed with the creator's role now.
/// The stored create-time role does not grant rights.
/// A creator that is not in the current policy or the current user store grants nothing.
pub fn blocking_role(
    coord: &Coordinator,
    created_by: &str,
    created_user: &str,
    op: &str,
) -> Result<Option<Role>, CoordError> {
    let current = creator_role_now(coord, created_by, created_user)?;
    if current.allows(op) {
        Ok(None)
    } else {
        Ok(Some(current))
    }
}

/// The role a token uses at call time.
///
/// Every creator kind is read from the current policy and the current store.
/// A creator that is not found is `member`, which grants no admin call.
fn creator_role_now(
    coord: &Coordinator,
    created_by: &str,
    created_user: &str,
) -> Result<Role, CoordError> {
    if !created_user.is_empty() {
        return approved_user_role(coord, created_user);
    }
    Ok(live_role(coord, created_by)?.unwrap_or(Role::Member))
}

/// The current role of an approved user. Any other state grants `member`.
fn approved_user_role(coord: &Coordinator, user: &str) -> Result<Role, CoordError> {
    let (users, _) = coord.user_list()?;
    let Some(stored) = users.into_iter().find(|stored| stored.user == user) else {
        return Ok(Role::Member);
    };
    match stored.state {
        crate::store::UserState::Approved => Ok(Role::parse(&stored.role).unwrap_or(Role::Member)),
        crate::store::UserState::Pending | crate::store::UserState::Rejected => Ok(Role::Member),
    }
}

/// Allow one mTLS admin call, or write one `role-deny` record and refuse.
///
/// The operation does not run when this function returns an error.
/// A failed audit write also returns an error, so the call fails closed.
pub fn authorize(coord: &Coordinator, actor: &str, op: &str) -> Result<(), CoordError> {
    let role = require_live(coord, actor)?;
    if role.allows(op) {
        return Ok(());
    }
    write_deny(coord, actor, op, role)?;
    Err(CoordError::Protocol(deny_text(role).to_string()))
}

/// Write one `role-deny` record. The record has no secret.
pub fn write_deny(
    coord: &Coordinator,
    actor: &str,
    op: &str,
    role: Role,
) -> Result<(), CoordError> {
    let op = short_op(op);
    let detail = format!("op {op} role {} status 403", role.as_str());
    coord.record_change(
        actor,
        ConfigAction::RoleDeny,
        &op,
        EMPTY_DIGEST,
        EMPTY_DIGEST,
        &detail,
    )
}

/// Return true when `caller` can revoke the token created by `created_by`.
///
/// An owner and an admin can revoke any token.
/// A network admin and an IT admin can revoke only a token that they created.
pub fn can_revoke(caller: Role, actor: &str, created_by: &str) -> bool {
    match caller {
        Role::Owner | Role::Admin => true,
        Role::NetworkAdmin | Role::ItAdmin => actor == created_by,
        Role::Auditor | Role::Member => false,
    }
}

/// The `admin-role-set` body. The name field of the admin request holds this JSON.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAsk {
    pub user: String,
    pub role: String,
}

/// Change the role of one user. One `role-set` record.
///
/// A token cannot call this. The server also refuses a token before this function.
pub fn apply(
    coord: &Coordinator,
    ask: &SetAsk,
    actor: &str,
    now: std::time::SystemTime,
) -> Result<serde_json::Value, CoordError> {
    let user = canonical_user(&ask.user)?;
    let from = coord.set_user_role_by(&user, &ask.role, actor, now)?;
    let role = parse_admin_role(&ask.role)?;
    Ok(serde_json::json!({
        "op": "role-set",
        "user": user,
        "role": role.as_str(),
        "from": from
    }))
}

fn canonical_user(target: &str) -> Result<String, CoordError> {
    let target = target.trim();
    let user = if target.starts_with("oidc:") {
        target.to_string()
    } else {
        format!("oidc:{target}")
    };
    crate::store::check_user(&user)?;
    Ok(user)
}

fn oidc_user(owner: &str) -> Option<String> {
    if crate::store::check_user(owner).is_ok() {
        Some(owner.to_string())
    } else {
        None
    }
}

fn short_op(op: &str) -> String {
    let word: String = op
        .trim_start_matches("admin-")
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .take(32)
        .collect();
    if word.is_empty() {
        "none".to_string()
    } else {
        word
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    use orblx_identity::{IssueGate, MiniCa, MockOidc, MOCK_OIDC_ISSUER};

    use super::{apply, authorize, can_revoke, scope_fits, Role, SetAsk, OPS};
    use crate::apitoken::{self, admin_ops, CreateAsk};
    use crate::state::{Coordinator, OidcConfig};

    const ACTOR: &str = "spiffe://orblx.local/node/owner";

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "orblx-roles-{}-{}",
                std::process::id(),
                rand::random::<u64>()
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

    fn open(scratch: &Scratch) -> Coordinator {
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        coord
    }

    fn role_of(coord: &Coordinator, user: &str) -> String {
        let (users, _) = coord.user_list().unwrap();
        users
            .into_iter()
            .find(|stored| stored.user == user)
            .unwrap()
            .role
    }

    fn count(coord: &Coordinator, action: &str, target: &str) -> usize {
        coord
            .config_audit_text()
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|value| value["action"] == action && value["target"] == target)
            .count()
    }

    fn deny_reasons(coord: &Coordinator, reason: &str) -> usize {
        let needle = format!("reason {reason} ");
        coord
            .config_audit_text()
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|value| {
                value["action"] == "role-deny"
                    && value["target"] == "role-set"
                    && value["detail"]
                        .as_str()
                        .is_some_and(|detail| detail.contains(&needle))
            })
            .count()
    }

    #[test]
    fn the_role_table_covers_each_admin_operation() {
        let mut seen = BTreeSet::new();
        for (op, _) in OPS {
            assert!(seen.insert(*op), "duplicate {op}");
            assert!(!op.is_empty());
        }
        let mut from_api = admin_ops();
        from_api.sort_unstable();
        let mut from_roles: Vec<&str> = OPS.iter().map(|(op, _)| *op).collect();
        from_roles.sort_unstable();
        assert_eq!(from_api, from_roles);
        let reads = [
            "admin-nodes",
            "admin-preauth-list",
            "admin-users",
            "admin-roles",
            "admin-routes",
            "admin-grants",
            "admin-lock",
            "admin-policy",
            "admin-audit",
        ];
        let auditor: BTreeSet<&str> = OPS
            .iter()
            .filter(|(op, _)| Role::Auditor.allows(op))
            .map(|(op, _)| *op)
            .collect();
        assert_eq!(auditor, BTreeSet::from(reads));
        for (op, _) in OPS {
            assert!(Role::Owner.allows(op));
            assert!(!Role::Member.allows(op));
            assert_ne!(Role::Admin.allows(op), *op == "admin-role-set");
        }
        assert!(Role::NetworkAdmin.allows("admin-policy-set"));
        assert!(!Role::NetworkAdmin.allows("admin-user-approve"));
        assert!(Role::ItAdmin.allows("admin-user-approve"));
        assert!(!Role::ItAdmin.allows("admin-policy-set"));
        assert!(!Role::Auditor.allows("admin-approve"));
        assert!(scope_fits(
            Role::ItAdmin,
            "nodes:write",
            crate::apitoken::SCOPES
        ));
        assert!(!scope_fits(
            Role::NetworkAdmin,
            "nodes:write",
            crate::apitoken::SCOPES
        ));
        assert!(scope_fits(
            Role::NetworkAdmin,
            "policy:write",
            crate::apitoken::SCOPES
        ));
        assert!(!scope_fits(
            Role::ItAdmin,
            "policy:write",
            crate::apitoken::SCOPES
        ));
        assert!(!can_revoke(Role::Auditor, "a", "a"));
        assert!(can_revoke(Role::ItAdmin, "a", "a"));
        assert!(!can_revoke(Role::ItAdmin, "a", "b"));
        assert!(can_revoke(Role::Admin, "a", "b"));
    }

    #[test]
    fn the_last_owner_cannot_be_demoted_and_each_change_has_one_record() {
        let scratch = Scratch::new();
        let coord = open(&scratch);
        let now = SystemTime::now();
        coord.approve_user_by("oidc:ada", ACTOR, now).unwrap();
        coord.approve_user_by("oidc:ned", ACTOR, now).unwrap();
        assert_eq!(role_of(&coord, "oidc:ada"), "member");
        apply(
            &coord,
            &SetAsk {
                user: "ada".to_string(),
                role: "owner".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "oidc:ned".to_string(),
                role: "owner".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "oidc:ada".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let err = apply(
            &coord,
            &SetAsk {
                user: "oidc:ned".to_string(),
                role: "member".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap_err();
        assert!(err.to_string().contains("last owner"), "{err}");
        assert_eq!(role_of(&coord, "oidc:ned"), "owner");
        assert_eq!(role_of(&coord, "oidc:ada"), "admin");
        assert_eq!(count(&coord, "role-set", "oidc:ada"), 2);
        assert_eq!(count(&coord, "role-set", "oidc:ned"), 1);
        assert_eq!(count(&coord, "role-deny", "role-set"), 1);
        assert_eq!(deny_reasons(&coord, "last-owner"), 1);
        let detail = coord
            .config_audit_text()
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|value| value["action"] == "role-set" && value["target"] == "oidc:ada")
            .unwrap();
        assert_eq!(detail["detail"], "role member to owner");
        assert!(!coord.config_audit_text().unwrap().contains("PRIVATE KEY"));
    }

    #[test]
    fn an_owner_user_stays_an_owner() {
        let scratch = Scratch::new();
        let coord = open(&scratch);
        let now = SystemTime::now();
        let path = scratch.0.join("policy.hujson");
        fs::write(
            &path,
            r#"{"owners": [], "userApproval": {"ownerUsers": ["oidc:olivia"]}}"#,
        )
        .unwrap();
        coord.set_policy_file(&path).unwrap();
        coord.approve_user_by("oidc:olivia", ACTOR, now).unwrap();
        assert_eq!(role_of(&coord, "oidc:olivia"), "owner");
        let err = apply(
            &coord,
            &SetAsk {
                user: "oidc:olivia".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap_err();
        assert!(err.to_string().contains("owner user"), "{err}");
        assert_eq!(role_of(&coord, "oidc:olivia"), "owner");
        assert_eq!(count(&coord, "role-set", "oidc:olivia"), 0);
        assert_eq!(count(&coord, "role-deny", "role-set"), 1);
        assert_eq!(deny_reasons(&coord, "owner-user"), 1);
    }

    #[test]
    fn each_refused_role_change_writes_one_role_deny() {
        let scratch = Scratch::new();
        let coord = open(&scratch);
        let now = SystemTime::now();
        coord.approve_user_by("oidc:ada", ACTOR, now).unwrap();
        coord.approve_user_by("oidc:ned", ACTOR, now).unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "ada".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "ned".to_string(),
                role: "owner".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();

        let same = apply(
            &coord,
            &SetAsk {
                user: "oidc:ada".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap_err();
        assert!(same.to_string().contains("already has this role"), "{same}");
        assert_eq!(deny_reasons(&coord, "same-role"), 1);

        let unknown = apply(
            &coord,
            &SetAsk {
                user: "oidc:missing".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap_err();
        assert!(unknown.to_string().contains("not known"), "{unknown}");
        assert_eq!(deny_reasons(&coord, "unknown-user"), 1);

        let bad = apply(
            &coord,
            &SetAsk {
                user: "ada".to_string(),
                role: "nope".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap_err();
        assert!(bad.to_string().contains("not valid"), "{bad}");
        assert_eq!(deny_reasons(&coord, "bad-role"), 1);
        assert_eq!(role_of(&coord, "oidc:ada"), "admin");

        let path = scratch.0.join("policy.hujson");
        fs::write(
            &path,
            r#"{"owners": [], "userApproval": {"ownerUsers": ["oidc:ada"]}}"#,
        )
        .unwrap();
        coord.set_policy_file(&path).unwrap();
        let owner_user = apply(
            &coord,
            &SetAsk {
                user: "ada".to_string(),
                role: "member".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap_err();
        assert!(
            owner_user.to_string().contains("owner user"),
            "{owner_user}"
        );
        assert_eq!(deny_reasons(&coord, "owner-user"), 1);
        assert_eq!(role_of(&coord, "oidc:ada"), "admin");

        let last = apply(
            &coord,
            &SetAsk {
                user: "ned".to_string(),
                role: "member".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap_err();
        assert!(last.to_string().contains("last owner"), "{last}");
        assert_eq!(deny_reasons(&coord, "last-owner"), 1);
        assert_eq!(role_of(&coord, "oidc:ned"), "owner");
        assert_eq!(count(&coord, "role-deny", "role-set"), 5);
        assert_eq!(count(&coord, "role-set", "oidc:ada"), 1);
        assert_eq!(count(&coord, "role-set", "oidc:ned"), 1);
    }

    #[test]
    fn a_member_deny_has_one_record_and_the_old_sentence() {
        let scratch = Scratch::new();
        let coord = open(&scratch);
        let err = authorize(&coord, "spiffe://orblx.local/node/a", "admin-nodes").unwrap_err();
        assert_eq!(err.to_string(), "The caller is not an owner.");
        assert_eq!(count(&coord, "role-deny", "nodes"), 1);
        authorize(&coord, "spiffe://orblx.local/node/a", "admin-approve").unwrap_err();
        assert_eq!(count(&coord, "role-deny", "approve"), 1);
        assert_eq!(count(&coord, "role-deny", "nodes"), 1);
    }

    #[test]
    fn an_auditor_can_read_the_audit_log_and_cannot_write() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
        let coord =
            Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
        coord.enable_config_audit().unwrap();
        coord.approve_user_by("oidc:aud", ACTOR, now).unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "oidc:aud".to_string(),
                role: "auditor".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let token = oidc
            .issue_id_token("aud", now, Duration::from_secs(600))
            .unwrap();
        let enrolled = coord
            .enroll_oidc(
                "aud-pc",
                &token,
                None,
                &["aud-pc:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        authorize(&coord, &enrolled.svid, "admin-audit").unwrap();
        authorize(&coord, &enrolled.svid, "admin-nodes").unwrap();
        let err = authorize(&coord, &enrolled.svid, "admin-approve").unwrap_err();
        assert!(err.to_string().contains("role auditor"), "{err}");
        assert_eq!(count(&coord, "role-deny", "approve"), 1);
        let err = authorize(&coord, &enrolled.svid, "admin-role-set").unwrap_err();
        assert!(err.to_string().contains("role auditor"), "{err}");
        assert_eq!(count(&coord, "role-deny", "role-set"), 1);
        assert_eq!(count(&coord, "role-set", "oidc:aud"), 1);
    }

    #[test]
    fn a_token_cannot_exceed_the_creator_role_and_a_demotion_has_one_deny() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
        let coord =
            Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
        coord.enable_config_audit().unwrap();
        coord.approve_user_by("oidc:ita", ACTOR, now).unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "ita".to_string(),
                role: "it-admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let token = oidc
            .issue_id_token("ita", now, Duration::from_secs(600))
            .unwrap();
        let enrolled = coord
            .enroll_oidc(
                "ita-pc",
                &token,
                None,
                &["ita-pc:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        let ask = |scope: &str| CreateAsk {
            scopes: vec![scope.to_string()],
            ttl_secs: 60,
        };
        let refused = apitoken::create(
            &coord,
            &ask("policy:write"),
            &enrolled.svid,
            Role::ItAdmin,
            now,
        );
        assert!(refused.is_err(), "policy:write must not fit it-admin");
        let made = apitoken::create(
            &coord,
            &ask("nodes:write"),
            &enrolled.svid,
            Role::ItAdmin,
            now,
        )
        .unwrap();
        assert!(!made.secret.is_empty());
        let first =
            apitoken::check(&coord, &made.secret, "admin-approve", now, || Ok(None)).unwrap();
        assert!(first.result.is_ok());
        assert!(first.role_block.is_none());
        assert_eq!(count(&coord, "token-use", &made.id), 1);
        apply(
            &coord,
            &SetAsk {
                user: "oidc:ita".to_string(),
                role: "member".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let second =
            apitoken::check(&coord, &made.secret, "admin-approve", now, || Ok(None)).unwrap();
        assert!(second.result.is_ok());
        assert_eq!(second.role_block, Some(Role::Member));
        assert_eq!(count(&coord, "token-use", &made.id), 1);
        assert_eq!(count(&coord, "token-deny", &made.id), 0);
        assert_eq!(count(&coord, "role-deny", "approve"), 1);
        let body = made.secret.trim_start_matches(apitoken::API_TOKEN_PREFIX);
        let audit = coord.config_audit_text().unwrap();
        assert!(!audit.contains(body));
        assert!(!audit.contains(&token));
    }

    #[test]
    fn a_refused_token_create_writes_one_role_deny() {
        let scratch = Scratch::new();
        let coord = open(&scratch);
        let now = SystemTime::now();
        let ask = |scope: &str| CreateAsk {
            scopes: vec![scope.to_string()],
            ttl_secs: 60,
        };
        let mismatch = apitoken::create(&coord, &ask("nodes:read"), ACTOR, Role::Owner, now);
        assert!(mismatch.unwrap_err().to_string().contains("does not match"));
        assert_eq!(count(&coord, "role-deny", "token-create"), 1);

        let member = apitoken::create(&coord, &ask("nodes:read"), ACTOR, Role::Member, now);
        assert!(member.unwrap_err().to_string().contains("cannot create"));
        assert_eq!(count(&coord, "role-deny", "token-create"), 2);

        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
        let scratch_b = Scratch::new();
        let coord =
            Coordinator::open(&scratch_b.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
        coord.enable_config_audit().unwrap();
        coord.approve_user_by("oidc:ita", ACTOR, now).unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "ita".to_string(),
                role: "it-admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let id_token = oidc
            .issue_id_token("ita", now, Duration::from_secs(600))
            .unwrap();
        let enrolled = coord
            .enroll_oidc(
                "ita-pc",
                &id_token,
                None,
                &["ita-pc:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        let scope = apitoken::create(
            &coord,
            &ask("policy:write"),
            &enrolled.svid,
            Role::ItAdmin,
            now,
        );
        assert!(scope
            .unwrap_err()
            .to_string()
            .contains("cannot hold the scope"));
        assert_eq!(count(&coord, "role-deny", "token-create"), 1);
    }

    #[test]
    fn a_demoted_admin_token_follows_the_current_role() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
        let coord =
            Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
        coord.enable_config_audit().unwrap();
        coord.approve_user_by("oidc:ada", ACTOR, now).unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "ada".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let id_token = oidc
            .issue_id_token("ada", now, Duration::from_secs(600))
            .unwrap();
        let enrolled = coord
            .enroll_oidc(
                "ada-pc",
                &id_token,
                None,
                &["ada-pc:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        let made = apitoken::create(
            &coord,
            &CreateAsk {
                scopes: vec!["nodes:read".to_string(), "nodes:write".to_string()],
                ttl_secs: 60,
            },
            &enrolled.svid,
            Role::Admin,
            now,
        )
        .unwrap();
        let call = |op: &str| apitoken::check(&coord, &made.secret, op, now, || Ok(None)).unwrap();
        let before = call("admin-nodes");
        assert!(before.result.is_ok());
        assert!(before.role_block.is_none());
        let write = call("admin-approve");
        assert!(write.result.is_ok());
        assert!(write.role_block.is_none());

        // Auditor can read nodes and cannot approve. Member can call no admin operation.
        apply(
            &coord,
            &SetAsk {
                user: "oidc:ada".to_string(),
                role: "auditor".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let read = call("admin-nodes");
        assert!(read.result.is_ok());
        assert!(read.role_block.is_none());
        assert_eq!(count(&coord, "token-use", &made.id), 3);
        let denied = call("admin-approve");
        assert!(denied.result.is_ok());
        assert_eq!(denied.role_block, Some(Role::Auditor));
        assert_eq!(count(&coord, "role-deny", "approve"), 1);
        assert_eq!(count(&coord, "token-deny", &made.id), 0);

        apply(
            &coord,
            &SetAsk {
                user: "oidc:ada".to_string(),
                role: "member".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        assert!(OPS.iter().all(|(op, _)| !Role::Member.allows(op)));
        let member = call("admin-nodes");
        assert!(member.result.is_ok());
        assert_eq!(member.role_block, Some(Role::Member));
        assert_eq!(count(&coord, "role-deny", "nodes"), 1);
        assert_eq!(count(&coord, "token-use", &made.id), 3);
        assert_eq!(count(&coord, "token-deny", &made.id), 0);

        apply(
            &coord,
            &SetAsk {
                user: "oidc:ada".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let restored = call("admin-approve");
        assert!(restored.result.is_ok());
        assert!(restored.role_block.is_none());
        let outside = call("admin-policy-set");
        assert_eq!(outside.result, Err(apitoken::Refusal::Scope));
        assert!(outside.role_block.is_none());
        assert_eq!(count(&coord, "token-deny", &made.id), 1);
        assert_eq!(count(&coord, "role-deny", "policy-set"), 0);

        set_user_state(&scratch, "oidc:ada", Some("rejected"), true);
        let rejected = call("admin-approve");
        assert!(rejected.result.is_ok());
        assert_eq!(rejected.role_block, Some(Role::Member));
        assert_eq!(count(&coord, "role-deny", "approve"), 2);
        assert_eq!(count(&coord, "token-deny", &made.id), 1);

        set_user_state(&scratch, "oidc:ada", None, false);
        let removed = call("admin-nodes");
        assert!(removed.result.is_ok());
        assert_eq!(removed.role_block, Some(Role::Member));
        assert_eq!(count(&coord, "role-deny", "nodes"), 2);
        let audit = coord.config_audit_text().unwrap();
        let body = made.secret.trim_start_matches(apitoken::API_TOKEN_PREFIX);
        assert!(!audit.contains(body));
        assert!(!audit.contains(&id_token));
    }

    #[test]
    fn a_former_owner_node_uses_the_approved_user_role() {
        let scratch = Scratch::new();
        let now = SystemTime::now();
        let oidc = MockOidc::generate(MOCK_OIDC_ISSUER).unwrap();
        let gate = IssueGate::new(MiniCa::generate(now).unwrap(), &oidc).unwrap();
        let coord =
            Coordinator::open(&scratch.0, "coord", OidcConfig::Mock(Box::new(gate))).unwrap();
        coord.enable_config_audit().unwrap();
        coord.approve_user_by("oidc:ada", ACTOR, now).unwrap();
        apply(
            &coord,
            &SetAsk {
                user: "ada".to_string(),
                role: "admin".to_string(),
            },
            ACTOR,
            now,
        )
        .unwrap();
        let id_token = oidc
            .issue_id_token("ada", now, Duration::from_secs(600))
            .unwrap();
        let enrolled = coord
            .enroll_oidc(
                "ada-pc",
                &id_token,
                None,
                &["ada-pc:443".to_string()],
                &[],
                now,
            )
            .unwrap();
        let path = scratch.0.join("policy.hujson");
        let policy = |owner: &str| {
            format!(
                "{{\"owners\": [\"{owner}\"], \"acls\": [{{\"action\": \"accept\", \"src\": [\"{owner}\"], \"proto\": \"tcp\", \"dst\": [\"{owner}:1\"]}}]}}"
            )
        };
        fs::write(&path, policy(&enrolled.svid)).unwrap();
        coord.set_policy_file(&path).unwrap();
        let made = apitoken::create(
            &coord,
            &CreateAsk {
                scopes: vec!["nodes:read".to_string()],
                ttl_secs: 60,
            },
            &enrolled.svid,
            Role::Owner,
            now,
        )
        .unwrap();
        let call = |op: &str| apitoken::check(&coord, &made.secret, op, now, || Ok(None)).unwrap();
        assert!(call("admin-nodes").role_block.is_none());
        set_user_state(&scratch, "oidc:ada", Some("rejected"), true);
        fs::write(&path, policy(ACTOR)).unwrap();
        coord.set_policy_file(&path).unwrap();
        let blocked = call("admin-nodes");
        assert_eq!(blocked.role_block, Some(Role::Member));
        assert_eq!(count(&coord, "role-deny", "nodes"), 1);
        assert_eq!(count(&coord, "token-use", &made.id), 1);
        assert_eq!(count(&coord, "token-deny", &made.id), 0);
    }

    /// Edit one user in `nodes.json`. `state` sets the approval state.
    /// `keep` false removes the user. The role field stays as stored.
    fn set_user_state(scratch: &Scratch, user: &str, state: Option<&str>, keep: bool) {
        let path = scratch.0.join("nodes.json");
        let mut file: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let users = file
            .get_mut("users")
            .and_then(serde_json::Value::as_array_mut)
            .unwrap();
        if keep {
            let row = users.iter_mut().find(|row| row["user"] == user).unwrap();
            assert_eq!(row["role"], "admin");
            row["state"] = serde_json::Value::String(state.unwrap().to_string());
        } else {
            users.retain(|row| row["user"] != user);
        }
        fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
    }
}
