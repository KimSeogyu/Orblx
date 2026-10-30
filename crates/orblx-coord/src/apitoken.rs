//! Scoped API tokens for the admin API (W25-3).
//!
//! An owner with an owner SVID creates a token with a list of scopes and an
//! expiry time. The coordinator gives the token text to the owner one time.
//! The coordinator keeps only the SHA-256 digest of the token text.
//! This is the same method as the enroll token store.
//!
//! The admin API accepts a token call only when the token is known, not expired,
//! not revoked, and holds the scope of the operation. Token management
//! (`admin-token-*`) has no scope. Only an owner SVID can do it.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use orblx_audit::{sha256_digest, ConfigAction, EMPTY_DIGEST};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::netmap::encode_hex;
use crate::state::Coordinator;

/// The file in the coordinator state directory.
pub const API_TOKEN_FILE: &str = "api-tokens.json";

/// The first characters of each API token.
pub const API_TOKEN_PREFIX: &str = "orblx-at1.";

/// The longest token life. It is the same as the enroll token maximum.
pub const MAX_API_TOKEN_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Each admin operation and the scope that it needs.
///
/// An operation that is not in this table has no scope. A token cannot do it.
pub const SCOPES: &[(&str, &str)] = &[
    ("admin-nodes", "nodes:read"),
    ("admin-users", "nodes:read"),
    ("admin-routes", "nodes:read"),
    ("admin-approve", "nodes:write"),
    ("admin-revoke", "nodes:write"),
    ("admin-revoke-all", "nodes:write"),
    ("admin-revoke-undo", "nodes:write"),
    ("admin-expire", "nodes:write"),
    ("admin-grants", "grants:read"),
    ("admin-grant-approve", "grants:write"),
    ("admin-grant-revoke", "grants:write"),
    ("admin-audit", "audit:read"),
    ("admin-lock", "lock:read"),
    ("admin-lock-init", "lock:write"),
    ("admin-lock-sign", "lock:write"),
    ("admin-lock-update", "lock:write"),
    ("admin-policy", "policy:read"),
    ("admin-policy-set", "policy:write"),
];

/// Admin operations that only an owner SVID can do.
pub const OWNER_ONLY_OPS: &[&str] = &[
    "admin-token-create",
    "admin-token-list",
    "admin-token-revoke",
];

/// Every admin operation name.
pub fn admin_ops() -> Vec<&'static str> {
    SCOPES
        .iter()
        .map(|(op, _)| *op)
        .chain(OWNER_ONLY_OPS.iter().copied())
        .collect()
}

/// Return the scope of an admin operation.
pub fn scope_of(op: &str) -> Option<&'static str> {
    SCOPES
        .iter()
        .find(|(name, _)| *name == op)
        .map(|(_, scope)| *scope)
}

/// Every scope name, sorted, one time each.
pub fn all_scopes() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = SCOPES.iter().map(|(_, scope)| *scope).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The audit actor text of a token.
pub fn actor_of(id: &str) -> String {
    format!("api-token:{id}")
}

static FILE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenFile {
    version: u32,
    tokens: Vec<TokenRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRecord {
    id: String,
    hash_hex: String,
    scopes: Vec<String>,
    created_by: String,
    created_unix_ms: u64,
    expires_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_unix_ms: Option<u64>,
}

/// Why the coordinator refused a token call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The token text is not a known token (401).
    Unknown,
    /// The token is past its expiry time (401).
    Expired,
    /// An owner revoked the token (401).
    Revoked,
    /// The token does not hold the scope of the operation (403).
    Scope,
    /// The call would add, remove, or change a policy owner (403, W25-3b).
    /// Only an owner SVID (mTLS) can change the owners.
    Owners,
}

impl Refusal {
    /// The HTTP-style status code.
    pub fn status(self) -> u16 {
        match self {
            Self::Scope | Self::Owners => 403,
            _ => 401,
        }
    }

    /// The reason word in logs and audit records.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Scope => "scope",
            Self::Owners => "owners",
        }
    }

    /// A client-facing sentence. It does not hold the token text.
    pub fn text(self) -> &'static str {
        match self {
            Self::Unknown => "The API token is not valid.",
            Self::Expired => "The API token is expired.",
            Self::Revoked => "The API token is revoked.",
            Self::Scope => "The API token does not have the scope for this operation.",
            Self::Owners => {
                "An API token cannot change the policy owners. Only an owner SVID can do this."
            }
        }
    }
}

/// The result of one token check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// The token id. It is `unknown` when no token matched.
    pub id: String,
    /// The scope of the operation, or `none`.
    pub scope: &'static str,
    /// `Ok` when the call can go on.
    pub result: Result<(), Refusal>,
}

/// A new token. The caller shows `secret` one time and then drops it.
pub struct CreatedApiToken {
    pub id: String,
    pub secret: String,
    pub scopes: Vec<String>,
    pub expires_unix_ms: u64,
}

impl std::fmt::Debug for CreatedApiToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedApiToken")
            .field("id", &self.id)
            .field("secret", &"[elided]")
            .field("scopes", &self.scopes)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .finish()
    }
}

/// Parse a comma list of scopes. Each scope must be a known scope.
pub fn parse_scopes(text: &str) -> Result<Vec<String>, CoordError> {
    let known = all_scopes();
    let mut out = Vec::new();
    for item in text.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if !known.contains(&item) {
            return Err(CoordError::Protocol(format!(
                "The scope {} is not valid.",
                clean_word(item)
            )));
        }
        if !out.iter().any(|have: &String| have == item) {
            out.push(item.to_string());
        }
    }
    if out.is_empty() {
        return Err(CoordError::Protocol(
            "The token needs one or more scopes.".to_string(),
        ));
    }
    out.sort();
    Ok(out)
}

fn clean_word(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == ':' || *ch == '-')
        .take(32)
        .collect()
}

/// The token create request in the admin request name field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAsk {
    pub scopes: Vec<String>,
    pub ttl_secs: u64,
}

/// Create one token for an owner. The call writes one `token-create` record.
pub fn create(
    coord: &Coordinator,
    ask: &CreateAsk,
    actor: &str,
    now: SystemTime,
) -> Result<CreatedApiToken, CoordError> {
    let scopes = parse_scopes(&ask.scopes.join(","))?;
    if !(1..=MAX_API_TOKEN_TTL_SECS).contains(&ask.ttl_secs) {
        return Err(CoordError::Protocol(
            "The token life is not valid.".to_string(),
        ));
    }
    let now_ms = unix_ms(now)?;
    let expires_unix_ms = now_ms
        .checked_add(ask.ttl_secs.saturating_mul(1000))
        .ok_or(CoordError::Time)?;
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let secret = format!("{API_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    let hash_hex = token_hash(&secret);
    let id = hash_hex.get(..16).ok_or(CoordError::State)?.to_string();
    let dir = coord.state_dir()?;
    let guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
    let before = file_digest(&dir)?;
    let mut file = read_file(&dir)?;
    if file.tokens.iter().any(|token| token.id == id) {
        return Err(CoordError::State);
    }
    file.tokens.push(TokenRecord {
        id: id.clone(),
        hash_hex,
        scopes: scopes.clone(),
        created_by: actor.to_string(),
        created_unix_ms: now_ms,
        expires_unix_ms,
        revoked_unix_ms: None,
    });
    write_file(&dir, &file)?;
    let after = file_digest(&dir)?;
    drop(guard);
    coord.record_change(
        actor,
        ConfigAction::TokenCreate,
        &id,
        before,
        after,
        &format!(
            "scopes {} expires_unix_ms {expires_unix_ms}",
            scopes.join(",")
        ),
    )?;
    Ok(CreatedApiToken {
        id,
        secret,
        scopes,
        expires_unix_ms,
    })
}

/// Revoke one token. The call writes one `token-revoke` record.
pub fn revoke(
    coord: &Coordinator,
    id: &str,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    let now_ms = unix_ms(now)?;
    let dir = coord.state_dir()?;
    let guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
    let before = file_digest(&dir)?;
    let mut file = read_file(&dir)?;
    let record = file
        .tokens
        .iter_mut()
        .find(|token| token.id == id)
        .ok_or_else(|| CoordError::Protocol("The API token id is not known.".to_string()))?;
    if record.revoked_unix_ms.is_some() {
        return Err(CoordError::Protocol(
            "The API token is already revoked.".to_string(),
        ));
    }
    record.revoked_unix_ms = Some(now_ms);
    let id = record.id.clone();
    write_file(&dir, &file)?;
    let after = file_digest(&dir)?;
    drop(guard);
    coord.record_change(
        actor,
        ConfigAction::TokenRevoke,
        &id,
        before,
        after,
        &format!("revoked_unix_ms {now_ms}"),
    )?;
    Ok(json!({"op": "token-revoke", "id": id, "revoked_unix_ms": now_ms}))
}

/// List the tokens without the digests.
pub fn list(coord: &Coordinator, now: SystemTime) -> Result<Value, CoordError> {
    let now_ms = unix_ms(now)?;
    let dir = coord.state_dir()?;
    let file = {
        let _guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
        read_file(&dir)?
    };
    let tokens: Vec<Value> = file
        .tokens
        .iter()
        .map(|token| {
            json!({
                "id": token.id,
                "scopes": token.scopes,
                "created_by": token.created_by,
                "created_unix_ms": token.created_unix_ms,
                "expires_unix_ms": token.expires_unix_ms,
                "revoked_unix_ms": token.revoked_unix_ms,
                "state": state_word(token, now_ms),
            })
        })
        .collect();
    Ok(json!({"op": "token-list", "tokens": tokens}))
}

fn state_word(token: &TokenRecord, now_ms: u64) -> &'static str {
    if token.revoked_unix_ms.is_some() {
        "revoked"
    } else if now_ms >= token.expires_unix_ms {
        "expired"
    } else {
        "active"
    }
}

/// Check a token for one admin operation and write one audit record.
///
/// An allowed call writes `token-use`. A refused call writes `token-deny`.
/// The record holds the token id, never the token text.
///
/// `rule` runs only when the token and the scope are good (W25-3b). When it returns
/// a refusal, the call is refused and the record is `token-deny`, not `token-use`.
pub fn check(
    coord: &Coordinator,
    secret: &str,
    op: &str,
    now: SystemTime,
    rule: impl FnOnce() -> Result<Option<Refusal>, CoordError>,
) -> Result<Checked, CoordError> {
    let mut checked = decide(coord, secret, op, now)?;
    if checked.result.is_ok() {
        if let Some(refusal) = rule()? {
            checked.result = Err(refusal);
        }
    }
    let dir = coord.state_dir()?;
    let digest = file_digest(&dir)?;
    let (action, detail) = match checked.result {
        Ok(()) => (
            ConfigAction::TokenUse,
            format!("op {} scope {}", short_op(op), checked.scope),
        ),
        Err(refusal) => (
            ConfigAction::TokenDeny,
            format!(
                "op {} scope {} reason {} status {}",
                short_op(op),
                checked.scope,
                refusal.reason(),
                refusal.status()
            ),
        ),
    };
    coord.record_change(
        &actor_of(&checked.id),
        action,
        &checked.id,
        digest,
        digest,
        &detail,
    )?;
    Ok(checked)
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

/// Decide one token call without an audit record.
pub fn decide(
    coord: &Coordinator,
    secret: &str,
    op: &str,
    now: SystemTime,
) -> Result<Checked, CoordError> {
    let now_ms = unix_ms(now)?;
    let scope = scope_of(op).unwrap_or("none");
    let dir = coord.state_dir()?;
    let file = {
        let _guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
        read_file(&dir)?
    };
    let unknown = Checked {
        id: "unknown".to_string(),
        scope,
        result: Err(Refusal::Unknown),
    };
    if !secret.starts_with(API_TOKEN_PREFIX) || secret.len() > 128 {
        return Ok(unknown);
    }
    let hash = token_hash(secret);
    let mut found = None;
    for token in &file.tokens {
        if constant_eq(&token.hash_hex, &hash) {
            found = Some(token);
        }
    }
    let Some(token) = found else {
        return Ok(unknown);
    };
    let result = if token.revoked_unix_ms.is_some() {
        Err(Refusal::Revoked)
    } else if now_ms >= token.expires_unix_ms {
        Err(Refusal::Expired)
    } else if scope_of(op).is_some_and(|need| token.scopes.iter().any(|have| have == need)) {
        Ok(())
    } else {
        Err(Refusal::Scope)
    };
    Ok(Checked {
        id: token.id.clone(),
        scope,
        result,
    })
}

fn read_file(dir: &Path) -> Result<TokenFile, CoordError> {
    let path = dir.join(API_TOKEN_FILE);
    if !path.exists() {
        return Ok(TokenFile {
            version: 1,
            tokens: Vec::new(),
        });
    }
    let text = read_text(&path)?;
    if text.contains(API_TOKEN_PREFIX) {
        return Err(CoordError::State);
    }
    serde_json::from_str(&text).map_err(|_| CoordError::State)
}

fn write_file(dir: &Path, file: &TokenFile) -> Result<(), CoordError> {
    let text = serde_json::to_string_pretty(file).map_err(|_| CoordError::State)?;
    if text.contains(API_TOKEN_PREFIX) || text.contains("PRIVATE KEY") {
        return Err(CoordError::State);
    }
    write_text(&dir.join(API_TOKEN_FILE), &text, 0o600)
}

fn file_digest(dir: &Path) -> Result<[u8; 32], CoordError> {
    let path = dir.join(API_TOKEN_FILE);
    if !path.exists() {
        return Ok(EMPTY_DIGEST);
    }
    Ok(sha256_digest(read_text(&path)?.as_bytes()))
}

fn token_hash(secret: &str) -> String {
    encode_hex(Sha256::digest(secret.as_bytes()).as_slice())
}

fn constant_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in left.bytes().zip(right.bytes()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

fn unix_ms(now: SystemTime) -> Result<u64, CoordError> {
    let ms = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoordError::Time)?
        .as_millis();
    u64::try_from(ms).map_err(|_| CoordError::Time)
}

/// Parse a token life such as `90`, `90s`, `30m`, `2h`, or `7d`.
pub fn parse_ttl(text: &str) -> Result<Duration, String> {
    let bad = || format!("The token life {text} is not valid.");
    let (number, scale) = match text.chars().last() {
        Some('s') => (&text[..text.len() - 1], 1),
        Some('m') => (&text[..text.len() - 1], 60),
        Some('h') => (&text[..text.len() - 1], 3600),
        Some('d') => (&text[..text.len() - 1], 86_400),
        Some(ch) if ch.is_ascii_digit() => (text, 1),
        _ => return Err(bad()),
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(bad());
    }
    let count: u64 = number.parse().map_err(|_| bad())?;
    let secs = count.checked_mul(scale).ok_or_else(bad)?;
    if !(1..=MAX_API_TOKEN_TTL_SECS).contains(&secs) {
        return Err(bad());
    }
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    use super::{
        admin_ops, all_scopes, check, create, decide, list, parse_scopes, parse_ttl, revoke,
        scope_of, CreateAsk, Refusal, API_TOKEN_FILE, API_TOKEN_PREFIX, OWNER_ONLY_OPS,
    };
    use crate::state::{Coordinator, OidcConfig};

    const OWNER: &str = "spiffe://orblx.local/node/owner";

    fn no_rule() -> Result<Option<Refusal>, crate::error::CoordError> {
        Ok(None)
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let mut raw = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
            let name: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("orblx-apitoken-{name}"));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn audited(scratch: &Scratch) -> Coordinator {
        let coord = Coordinator::open(&scratch.0, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        coord
    }

    fn ask(scopes: &[&str], ttl_secs: u64) -> CreateAsk {
        CreateAsk {
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            ttl_secs,
        }
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

    #[test]
    fn each_scope_allows_only_its_own_operations() {
        let scratch = Scratch::new();
        let coord = audited(&scratch);
        let now = SystemTime::now();
        for scope in all_scopes() {
            let made = create(&coord, &ask(&[scope], 60), OWNER, now).unwrap();
            for op in admin_ops() {
                let checked = decide(&coord, &made.secret, op, now).unwrap();
                if scope_of(op) == Some(scope) {
                    assert_eq!(checked.result, Ok(()), "{scope} {op}");
                } else {
                    assert_eq!(checked.result, Err(Refusal::Scope), "{scope} {op}");
                }
            }
        }
    }

    #[test]
    fn token_management_has_no_scope() {
        for op in OWNER_ONLY_OPS {
            assert_eq!(scope_of(op), None);
        }
        let scratch = Scratch::new();
        let coord = audited(&scratch);
        let now = SystemTime::now();
        let every = all_scopes();
        let made = create(&coord, &ask(&every, 60), OWNER, now).unwrap();
        for op in OWNER_ONLY_OPS {
            let checked = decide(&coord, &made.secret, op, now).unwrap();
            assert_eq!(checked.result, Err(Refusal::Scope));
        }
        assert_eq!(
            decide(&coord, &made.secret, "admin-unknown", now)
                .unwrap()
                .result,
            Err(Refusal::Scope)
        );
    }

    #[test]
    fn an_expired_token_is_refused_from_the_expiry_millisecond() {
        let scratch = Scratch::new();
        let coord = audited(&scratch);
        let now = SystemTime::now();
        let made = create(&coord, &ask(&["nodes:read"], 1), OWNER, now).unwrap();
        let before = now + Duration::from_millis(999);
        let at = now + Duration::from_millis(1000);
        assert_eq!(
            decide(&coord, &made.secret, "admin-nodes", before)
                .unwrap()
                .result,
            Ok(())
        );
        assert_eq!(
            decide(&coord, &made.secret, "admin-nodes", at)
                .unwrap()
                .result,
            Err(Refusal::Expired)
        );
        assert_eq!(Refusal::Expired.status(), 401);
        assert_eq!(Refusal::Scope.status(), 403);
    }

    #[test]
    fn a_revoked_or_unknown_token_is_refused() {
        let scratch = Scratch::new();
        let coord = audited(&scratch);
        let now = SystemTime::now();
        let made = create(&coord, &ask(&["nodes:read"], 60), OWNER, now).unwrap();
        revoke(&coord, &made.id, OWNER, now).unwrap();
        assert_eq!(
            decide(&coord, &made.secret, "admin-nodes", now)
                .unwrap()
                .result,
            Err(Refusal::Revoked)
        );
        assert!(revoke(&coord, &made.id, OWNER, now).is_err());
        let mut forged = made.secret.clone();
        forged.pop();
        forged.push(if made.secret.ends_with('A') { 'B' } else { 'A' });
        let other = decide(&coord, &forged, "admin-nodes", now).unwrap();
        assert_eq!(other.result, Err(Refusal::Unknown));
        assert_eq!(other.id, "unknown");
        assert_eq!(
            decide(&coord, "", "admin-nodes", now).unwrap().result,
            Err(Refusal::Unknown)
        );
    }

    #[test]
    fn create_use_deny_and_revoke_write_one_record_each_and_no_secret() {
        let scratch = Scratch::new();
        let coord = audited(&scratch);
        let now = SystemTime::now();
        let made = create(&coord, &ask(&["nodes:read"], 60), OWNER, now).unwrap();
        assert!(made.secret.starts_with(API_TOKEN_PREFIX));
        assert_eq!(count(&coord, "token-create", &made.id), 1);
        let used = check(&coord, &made.secret, "admin-nodes", now, no_rule).unwrap();
        assert_eq!(used.result, Ok(()));
        assert_eq!(count(&coord, "token-use", &made.id), 1);
        let denied = check(&coord, &made.secret, "admin-policy-set", now, no_rule).unwrap();
        assert_eq!(denied.result, Err(Refusal::Scope));
        assert_eq!(count(&coord, "token-deny", &made.id), 1);
        revoke(&coord, &made.id, OWNER, now).unwrap();
        assert_eq!(count(&coord, "token-revoke", &made.id), 1);
        let late = check(&coord, &made.secret, "admin-nodes", now, no_rule).unwrap();
        assert_eq!(late.result, Err(Refusal::Revoked));
        assert_eq!(count(&coord, "token-deny", &made.id), 2);
        assert_eq!(count(&coord, "token-use", &made.id), 1);
        let body = made.secret.trim_start_matches(API_TOKEN_PREFIX);
        for entry in std::fs::read_dir(&scratch.0).unwrap() {
            let path = entry.unwrap().path();
            if let Ok(text) = std::fs::read_to_string(&path) {
                assert!(!text.contains(body), "{}", path.display());
            }
        }
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(scratch.0.join(API_TOKEN_FILE))
                .unwrap()
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        let shown = list(&coord, now).unwrap().to_string();
        assert!(!shown.contains(body));
        assert!(!shown.contains("hash"));
        assert!(shown.contains("revoked"));
        let audit = coord.config_audit_text().unwrap();
        let _ = orblx_audit::verify_config_jsonl(&audit).unwrap();
    }

    #[test]
    fn scopes_and_life_are_checked() {
        assert_eq!(
            parse_scopes("nodes:read, audit:read,nodes:read").unwrap(),
            vec!["audit:read".to_string(), "nodes:read".to_string()]
        );
        assert!(parse_scopes("").is_err());
        assert!(parse_scopes("nodes:delete").is_err());
        assert!(parse_scopes("tokens:write").is_err());
        assert_eq!(parse_ttl("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_ttl("0").is_err());
        assert!(parse_ttl("31d").is_err());
        assert!(parse_ttl("1w").is_err());
        let scratch = Scratch::new();
        let coord = audited(&scratch);
        let now = SystemTime::now();
        assert!(create(&coord, &ask(&["nodes:read"], 0), OWNER, now).is_err());
        assert!(create(&coord, &ask(&[], 60), OWNER, now).is_err());
    }
}
