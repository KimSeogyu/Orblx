//! Pre-auth keys for an agent node.
//!
//! An owner, or a scoped API token, creates a key. The key is one use unless
//! the caller sets a max use count. The life is 1 second to 1 hour.
//! The key can set fixed tags and one grant ceiling. It cannot grant more
//! than the caller can grant. The coordinator stores only the SHA-256 digest.
//! An agent enrolls with the key and then uses the existing agent grant path.
//! An ephemeral node is removed, and its SVID and grants are revoked, when it
//! stays offline past the grace or when the key expires.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use orblx_agent::{path_prefix_ok, service_name_ok, MAX_GRANT_SECS};
use orblx_audit::ConfigAction;
use orblx_identity::SpiffeId;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::CoordError;
use crate::files::{read_text, write_text};
use crate::netmap::encode_hex;
use crate::state::Coordinator;
use crate::store::{NodeGrantBound, PreauthStamp};

/// The file in the coordinator state directory.
pub const PREAUTH_FILE: &str = "preauth-keys.json";

/// The first characters of each pre-auth key.
pub const PREAUTH_PREFIX: &str = "orblx-pak1.";

/// The shortest key life.
pub const MIN_PREAUTH_TTL_SECS: u64 = 1;

/// The longest key life. A longer life is refused.
pub const MAX_PREAUTH_TTL_SECS: u64 = 60 * 60;

/// The most uses of one key.
pub const MAX_PREAUTH_USES: u32 = 16;

/// How long an ephemeral node may stay silent before it is removed.
pub const EPHEMERAL_GRACE: Duration = Duration::from_secs(15);

const MAX_KEYS: usize = 128;
const MAX_TAGS: usize = 8;
const FILE_VERSION: u32 = 1;

static FILE_LOCK: Mutex<()> = Mutex::new(());
static SEEN: Mutex<BTreeMap<(String, String), u64>> = Mutex::new(BTreeMap::new());
/// Last time an unknown key wrote one `preauth-deny`, per state directory.
static UNKNOWN_DENY_MS: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

/// Unknown-key denials share one audit record inside this window.
const UNKNOWN_DENY_WINDOW_MS: u64 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KeyFile {
    version: u32,
    keys: Vec<KeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyRecord {
    id: String,
    hash_hex: String,
    created_by: String,
    created_unix_ms: u64,
    expires_unix_ms: u64,
    max_uses: u32,
    uses: u32,
    ephemeral: bool,
    tags: Vec<String>,
    #[serde(default)]
    grant: Option<NodeGrantBound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantAsk {
    pub node: String,
    pub service: String,
    pub port: u16,
    pub path_prefix: String,
    pub max_ttl_secs: u64,
}

/// The create request in the admin name field.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAsk {
    pub ttl_secs: u64,
    #[serde(default = "one_use")]
    pub max_uses: u32,
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub grant: Option<GrantAsk>,
}

fn one_use() -> u32 {
    1
}

/// Who creates the key.
pub(crate) enum Creator {
    /// An owner SVID.
    Owner(SpiffeId),
    /// A scoped API token that already passed its scope check.
    Token { scopes: Vec<String> },
}

enum ScreenFail {
    Life,
    Tag,
    Grant,
}

impl ScreenFail {
    fn reason(&self) -> &'static str {
        match self {
            Self::Life => "life",
            Self::Tag => "tag",
            Self::Grant => "grant",
        }
    }

    fn text(&self) -> &'static str {
        match self {
            Self::Life => "The pre-auth key life is not valid.",
            Self::Tag => "The pre-auth key tag is outside the caller rights.",
            Self::Grant => "The pre-auth key grant is outside the caller rights.",
        }
    }

    fn refusal(&self) -> crate::apitoken::Refusal {
        match self {
            Self::Life => crate::apitoken::Refusal::Life,
            Self::Tag => crate::apitoken::Refusal::Tag,
            Self::Grant => crate::apitoken::Refusal::Grant,
        }
    }
}

/// How a grant request sits against the node ceiling.
pub(crate) enum Fit {
    /// The node did not enroll with a pre-auth key.
    Open,
    /// The request is inside the key ceiling. The text is the approver.
    Ready { approver: String },
    /// The request is outside the ceiling.
    Deny { key_id: String },
}

/// Check a create request. The function does not write a key or an audit record.
fn screen(coord: &Coordinator, creator: &Creator, ask: &CreateAsk) -> Result<(), ScreenFail> {
    if !(MIN_PREAUTH_TTL_SECS..=MAX_PREAUTH_TTL_SECS).contains(&ask.ttl_secs) {
        return Err(ScreenFail::Life);
    }
    if ask.max_uses == 0 || ask.max_uses > MAX_PREAUTH_USES {
        return Err(ScreenFail::Life);
    }
    if ask.tags.len() > MAX_TAGS {
        return Err(ScreenFail::Tag);
    }
    let mut seen = Vec::new();
    for tag in &ask.tags {
        if !tag_text_ok(tag) || seen.iter().any(|item: &String| item == tag) {
            return Err(ScreenFail::Tag);
        }
        seen.push(tag.clone());
        let known = coord.known_tag(tag).map_err(|_| ScreenFail::Tag)?;
        if !known {
            return Err(ScreenFail::Tag);
        }
        match creator {
            Creator::Owner(id) => {
                let owns = coord
                    .caller_owns_tag(tag, id)
                    .map_err(|_| ScreenFail::Tag)?;
                if !owns {
                    return Err(ScreenFail::Tag);
                }
            }
            Creator::Token { .. } => return Err(ScreenFail::Tag),
        }
    }
    if let Some(grant) = &ask.grant {
        if !grant_ok(coord, grant) {
            return Err(ScreenFail::Grant);
        }
        if let Creator::Token { scopes } = creator {
            if !scopes.iter().any(|scope| scope == "grants:write") {
                return Err(ScreenFail::Grant);
            }
        }
    }
    Ok(())
}

fn tag_text_ok(tag: &str) -> bool {
    let Some(label) = tag.strip_prefix("tag:") else {
        return false;
    };
    let mut chars = label.chars();
    match chars.next() {
        Some(ch) if ch.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    label.len() <= 63 && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn grant_ok(coord: &Coordinator, grant: &GrantAsk) -> bool {
    if SpiffeId::node(&grant.node).is_err() || !service_name_ok(&grant.service) {
        return false;
    }
    if grant.port == 0 || grant.path_prefix.is_empty() || !path_prefix_ok(&grant.path_prefix) {
        return false;
    }
    if grant.max_ttl_secs == 0 || grant.max_ttl_secs > MAX_GRANT_SECS {
        return false;
    }
    let Ok(nodes) = coord.node_list() else {
        return false;
    };
    nodes
        .iter()
        .any(|node| node.name == grant.node && node.approved && !node.expired && !node.removed)
}

/// Screen a token create call and write one `preauth-deny` when it fails.
///
/// Invalid JSON is not a deny. The create call then returns 400.
pub(crate) fn screen_token(
    coord: &Coordinator,
    secret: &str,
    name: &str,
    now: SystemTime,
) -> Result<Option<crate::apitoken::Refusal>, CoordError> {
    let ask: CreateAsk = match serde_json::from_str(name) {
        Ok(ask) => ask,
        Err(_) => return Ok(None),
    };
    let scopes = crate::apitoken::scopes_of(coord, secret)?;
    let fail = match screen(coord, &Creator::Token { scopes }, &ask) {
        Ok(()) => return Ok(None),
        Err(fail) => fail,
    };
    record_deny(coord, "preauth:new", "new", fail.reason(), now)?;
    Ok(Some(fail.refusal()))
}

/// Create one key. The reply holds the key text one time.
pub fn create(
    coord: &Coordinator,
    ask: &CreateAsk,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    let creator = creator_of(coord, actor)?;
    if let Err(fail) = screen(coord, &creator, ask) {
        record_deny(coord, actor, "new", fail.reason(), now)?;
        return Err(CoordError::Protocol(fail.text().to_string()));
    }
    let now_ms = unix_ms(now)?;
    let expires_unix_ms = now_ms
        .checked_add(ask.ttl_secs.saturating_mul(1000))
        .ok_or(CoordError::Time)?;
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let secret = format!("{PREAUTH_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    let hash_hex = key_hash(&secret);
    let id = hash_hex.get(..16).ok_or(CoordError::State)?.to_string();
    let grant = ask.grant.as_ref().map(|grant| NodeGrantBound {
        node: grant.node.clone(),
        service: grant.service.clone(),
        port: grant.port,
        path_prefix: grant.path_prefix.clone(),
        max_ttl_secs: grant.max_ttl_secs,
    });
    let dir = coord.state_dir()?;
    let _guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = read_file(&dir)?;
    if file.keys.len() >= MAX_KEYS {
        return Err(CoordError::Protocol(
            "The coordinator has too many pre-auth keys.".to_string(),
        ));
    }
    if file.keys.iter().any(|key| key.id == id) {
        return Err(CoordError::State);
    }
    file.keys.push(KeyRecord {
        id: id.clone(),
        hash_hex,
        created_by: actor.to_string(),
        created_unix_ms: now_ms,
        expires_unix_ms,
        max_uses: ask.max_uses,
        uses: 0,
        ephemeral: ask.ephemeral,
        tags: ask.tags.clone(),
        grant: grant.clone(),
        revoked_unix_ms: None,
    });
    write_file(&dir, &file)?;
    coord.record_change(
        actor,
        ConfigAction::PreauthCreate,
        &id,
        orblx_audit::EMPTY_DIGEST,
        orblx_audit::EMPTY_DIGEST,
        &format!(
            "uses {} ephemeral {} tags {} grant {} expires_unix_ms {expires_unix_ms}",
            ask.max_uses,
            u8::from(ask.ephemeral),
            ask.tags.len(),
            u8::from(grant.is_some())
        ),
    )?;
    println!("preauth create {id}");
    Ok(json!({
        "op": "preauth-create",
        "id": id,
        "key": secret,
        "max_uses": ask.max_uses,
        "ephemeral": ask.ephemeral,
        "tags": ask.tags,
        "expires_unix_ms": expires_unix_ms,
        "grant": grant.is_some(),
    }))
}

fn creator_of(coord: &Coordinator, actor: &str) -> Result<Creator, CoordError> {
    if let Some(id) = actor.strip_prefix("api-token:") {
        let scopes = crate::apitoken::scopes_by_id(coord, id)?;
        return Ok(Creator::Token { scopes });
    }
    let id = SpiffeId::parse(actor)
        .map_err(|_| CoordError::Protocol("The pre-auth key caller is not valid.".to_string()))?;
    Ok(Creator::Owner(id))
}

/// List keys. The reply has no key text and no digest.
pub fn list(coord: &Coordinator, now: SystemTime) -> Result<Value, CoordError> {
    let now_ms = unix_ms(now)?;
    let dir = coord.state_dir()?;
    let file = {
        let _guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
        read_file(&dir)?
    };
    let keys: Vec<Value> = file
        .keys
        .iter()
        .map(|key| {
            json!({
                "id": key.id,
                "state": state_word(key, now_ms),
                "uses": key.uses,
                "max_uses": key.max_uses,
                "ephemeral": key.ephemeral,
                "tags": key.tags,
                "created_by": key.created_by,
                "expires_unix_ms": key.expires_unix_ms,
                "revoked_unix_ms": key.revoked_unix_ms,
                "grant": key.grant.as_ref().map(|grant| json!({
                    "node": grant.node,
                    "service": grant.service,
                    "port": grant.port,
                    "path_prefix": grant.path_prefix,
                    "max_ttl_secs": grant.max_ttl_secs,
                })),
            })
        })
        .collect();
    Ok(json!({"op": "preauth-list", "keys": keys}))
}

fn state_word(key: &KeyRecord, now_ms: u64) -> &'static str {
    if key.revoked_unix_ms.is_some() {
        "revoked"
    } else if now_ms >= key.expires_unix_ms {
        "expired"
    } else if key.uses >= key.max_uses {
        "used"
    } else {
        "active"
    }
}

/// Revoke one key. A later enroll is refused.
pub fn revoke(
    coord: &Coordinator,
    id: &str,
    actor: &str,
    now: SystemTime,
) -> Result<Value, CoordError> {
    if id.len() != 16 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CoordError::Protocol(
            "The pre-auth key id is not valid.".to_string(),
        ));
    }
    let now_ms = unix_ms(now)?;
    let dir = coord.state_dir()?;
    let _guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
    let mut file = read_file(&dir)?;
    let record = file
        .keys
        .iter_mut()
        .find(|key| key.id == id)
        .ok_or_else(|| CoordError::Protocol("The pre-auth key id is not known.".to_string()))?;
    if record.revoked_unix_ms.is_some() {
        return Err(CoordError::Protocol(
            "The pre-auth key is already revoked.".to_string(),
        ));
    }
    record.revoked_unix_ms = Some(now_ms);
    let id = record.id.clone();
    write_file(&dir, &file)?;
    coord.record_change(
        actor,
        ConfigAction::PreauthRevoke,
        &id,
        orblx_audit::EMPTY_DIGEST,
        orblx_audit::EMPTY_DIGEST,
        &format!("revoked_unix_ms {now_ms}"),
    )?;
    println!("preauth revoke {id}");
    Ok(json!({"op": "preauth-revoke", "id": id, "revoked_unix_ms": now_ms}))
}

/// Enroll one node with a pre-auth key.
///
/// The node is pre-approved. The use count and the `preauth-use` record are
/// durable before the node enroll. If either write fails, the enroll does not
/// run. A one-use key cannot enroll a second node after a failed enroll.
/// The lock is process-local. One coordinator per state directory is atomic.
pub fn enroll(
    coord: &Coordinator,
    name: &str,
    secret: &str,
    endpoints: &[String],
    routes: &[String],
    now: SystemTime,
) -> Result<crate::state::EnrollResult, CoordError> {
    let _ = SpiffeId::node(name).map_err(|_| CoordError::Name)?;
    let _guard = FILE_LOCK.lock().map_err(|_| CoordError::State)?;
    let dir = coord.state_dir()?;
    let mut file = read_file(&dir)?;
    let now_ms = unix_ms(now)?;
    let hash = key_hash(secret);
    let index = match file
        .keys
        .iter()
        .position(|key| constant_eq(&key.hash_hex, &hash))
    {
        Some(index) => index,
        None => {
            record_unknown_deny(coord, now)?;
            return Err(CoordError::Protocol(
                "The pre-auth key is not valid.".to_string(),
            ));
        }
    };
    let key = &file.keys[index];
    let id = key.id.clone();
    if let Some(reason) = refuse_reason(key, now_ms) {
        record_deny(coord, &format!("preauth:{id}"), &id, reason, now)?;
        let text = match reason {
            "expired" => "The pre-auth key is expired.",
            "revoked" => "The pre-auth key is revoked.",
            "used" => "The pre-auth key is used up.",
            _ => "The pre-auth key is not valid.",
        };
        return Err(CoordError::Protocol(text.to_string()));
    }
    let stamp = PreauthStamp {
        tags: key.tags.clone(),
        ephemeral: key.ephemeral,
        preauth_id: id.clone(),
        preauth_actor: key.created_by.clone(),
        auth_expires_unix_ms: key.expires_unix_ms,
        grant_bound: key.grant.clone(),
    };
    file.keys[index].uses = file.keys[index].uses.saturating_add(1);
    let uses = file.keys[index].uses;
    let max_uses = file.keys[index].max_uses;
    write_file(&dir, &file)?;
    if let Err(err) = coord.record_change(
        &format!("preauth:{id}"),
        ConfigAction::PreauthUse,
        &id,
        orblx_audit::EMPTY_DIGEST,
        orblx_audit::EMPTY_DIGEST,
        &format!("node {name} uses {uses} max {max_uses}"),
    ) {
        file.keys[index].uses = file.keys[index].uses.saturating_sub(1);
        let _ = write_file(&dir, &file);
        return Err(err);
    }
    let enrolled = coord.enroll_preauth_stamp(name, &id, endpoints, routes, stamp, now)?;
    drop(_guard);
    let _ = note_seen(coord, name, now);
    println!("preauth enroll {name} key {id}");
    Ok(enrolled)
}

fn refuse_reason(key: &KeyRecord, now_ms: u64) -> Option<&'static str> {
    if key.revoked_unix_ms.is_some() {
        Some("revoked")
    } else if now_ms >= key.expires_unix_ms {
        Some("expired")
    } else if key.uses >= key.max_uses {
        Some("used")
    } else {
        None
    }
}

/// Compare one grant request with the pre-auth ceiling of `requester`.
pub(crate) fn fit_grant(
    coord: &Coordinator,
    requester: &str,
    ask: &crate::proto::GrantAsk,
    path: &str,
) -> Result<Fit, CoordError> {
    let nodes = coord.node_list()?;
    let Some(stored) = nodes.iter().find(|item| item.name == requester) else {
        return Ok(Fit::Open);
    };
    if stored.preauth_id.is_empty() {
        return Ok(Fit::Open);
    }
    let Some(bound) = &stored.grant_bound else {
        return Ok(Fit::Deny {
            key_id: stored.preauth_id.clone(),
        });
    };
    let fits = ask.agent == requester
        && bound.node == ask.node
        && bound.service == ask.service
        && bound.port == ask.port
        && bound.path_prefix == path
        && ask.ttl_secs > 0
        && ask.ttl_secs <= bound.max_ttl_secs;
    if fits {
        Ok(Fit::Ready {
            approver: stored.preauth_actor.clone(),
        })
    } else {
        Ok(Fit::Deny {
            key_id: stored.preauth_id.clone(),
        })
    }
}

/// Write one unknown-key deny, or skip it when this directory wrote one recently.
///
/// The enroll is still refused. The audit log grows by at most one record
/// per second per state directory.
fn record_unknown_deny(coord: &Coordinator, now: SystemTime) -> Result<(), CoordError> {
    let dir = coord.state_dir()?.to_string_lossy().to_string();
    let now_ms = unix_ms(now)?;
    let mut guard = UNKNOWN_DENY_MS.lock().map_err(|_| CoordError::State)?;
    let last = guard.entry(dir).or_insert(0);
    if *last != 0 && now_ms.saturating_sub(*last) < UNKNOWN_DENY_WINDOW_MS {
        return Ok(());
    }
    *last = now_ms;
    drop(guard);
    record_deny(coord, "preauth:unknown", "unknown", "unknown", now)
}

/// Write one `preauth-deny` record. The record has no key text.
pub(crate) fn record_deny(
    coord: &Coordinator,
    actor: &str,
    target: &str,
    reason: &str,
    now: SystemTime,
) -> Result<(), CoordError> {
    let _ = now;
    coord.record_change(
        actor,
        ConfigAction::PreauthDeny,
        target,
        orblx_audit::EMPTY_DIGEST,
        orblx_audit::EMPTY_DIGEST,
        &format!("reason {reason}"),
    )?;
    println!("preauth deny {target} reason {reason}");
    Ok(())
}

/// Remember that `name` called the coordinator.
pub fn note_seen(coord: &Coordinator, name: &str, now: SystemTime) -> Result<(), CoordError> {
    let dir = coord.state_dir()?;
    let now_ms = unix_ms(now)?;
    let dir_key = dir.to_string_lossy().to_string();
    let mut guard = SEEN.lock().map_err(|_| CoordError::State)?;
    let key = (dir_key, name.to_string());
    if guard
        .get(&key)
        .is_some_and(|prev| now_ms.saturating_sub(*prev) < 1000)
    {
        return Ok(());
    }
    guard.insert(key, now_ms);
    drop(guard);
    let mut seen = read_presence(&dir)?;
    seen.insert(name.to_string(), now_ms);
    write_presence(&dir, &seen)
}

/// Remove ephemeral nodes that are past the grace or past the key expiry.
///
/// Each removal revokes the node SVID and the issued agent SVIDs through the
/// existing deny path, then writes one `node-remove` record.
pub fn remove_due(coord: &Coordinator, now: SystemTime) -> Result<usize, CoordError> {
    let now_ms = unix_ms(now)?;
    let dir = coord.state_dir()?;
    let presence = read_presence(&dir)?;
    let nodes = coord.node_list()?;
    let mut count = 0;
    for node in nodes {
        if !node.ephemeral || node.removed {
            continue;
        }
        let seen = seen_ms(&dir, &node.name, &presence)
            .unwrap_or_else(|| node.enrolled_unix.saturating_mul(1000));
        let expired = node.auth_expires_unix_ms > 0 && now_ms >= node.auth_expires_unix_ms;
        let silent = now_ms >= seen.saturating_add(grace_ms());
        if !expired && !silent {
            continue;
        }
        let reason = if expired { "expiry" } else { "grace" };
        let node_id = SpiffeId::node(&node.name)?;
        let agents = crate::agent::issued_agent_names(coord, &node.name)?;
        let (mut version, mut uris) = deny_snapshot(coord, now)?;
        version = revoke_once(coord, &node_id, &mut uris, version, now)?;
        for agent in agents {
            let id = SpiffeId::agent(&agent)?;
            version = revoke_once(coord, &id, &mut uris, version, now)?;
        }
        coord.mark_removed(&node.name)?;
        let actor = coord.coord_actor()?;
        coord.record_change(
            &actor,
            ConfigAction::NodeRemove,
            &node.name,
            orblx_audit::EMPTY_DIGEST,
            orblx_audit::EMPTY_DIGEST,
            &format!(
                "ephemeral reason {reason} svid {} deny_version {version}",
                node.svid
            ),
        )?;
        println!("preauth remove {} reason {reason}", node.name);
        count += 1;
    }
    Ok(count)
}

fn deny_snapshot(coord: &Coordinator, now: SystemTime) -> Result<(u64, Vec<String>), CoordError> {
    let text = crate::admin::deny_json(coord, now)?;
    let value: Value = serde_json::from_str(&text).map_err(|_| CoordError::State)?;
    let version = value.get("version").and_then(Value::as_u64).unwrap_or(0);
    let uris = value
        .get("revoked_uris")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok((version, uris))
}

/// Revoke `id` once. A later retry does not add the URI again.
fn revoke_once(
    coord: &Coordinator,
    id: &SpiffeId,
    uris: &mut Vec<String>,
    version: u64,
    now: SystemTime,
) -> Result<u64, CoordError> {
    let uri = id.as_uri().to_string();
    if uris.iter().any(|item| item == &uri) {
        return Ok(version);
    }
    let revoked = crate::agent::revoke_principal(coord, id, now)?;
    uris.push(uri);
    Ok(revoked.deny_version)
}

fn seen_ms(dir: &Path, name: &str, file: &BTreeMap<String, u64>) -> Option<u64> {
    let dir_key = dir.to_string_lossy().to_string();
    if let Ok(guard) = SEEN.lock() {
        if let Some(ms) = guard.get(&(dir_key, name.to_string())) {
            return Some(*ms);
        }
    }
    file.get(name).copied()
}

fn grace_ms() -> u64 {
    u64::try_from(EPHEMERAL_GRACE.as_millis()).unwrap_or(15_000)
}

fn read_presence(dir: &Path) -> Result<BTreeMap<String, u64>, CoordError> {
    let path = dir.join("presence.json");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let text = read_text(&path)?;
    if text.contains(PREAUTH_PREFIX) || text.contains("PRIVATE KEY") {
        return Err(CoordError::State);
    }
    let file: PresenceFile = serde_json::from_str(&text).map_err(|_| CoordError::State)?;
    Ok(file.seen)
}

fn write_presence(dir: &Path, seen: &BTreeMap<String, u64>) -> Result<(), CoordError> {
    let text = serde_json::to_string(&PresenceFile { seen: seen.clone() })
        .map_err(|_| CoordError::State)?;
    if text.contains(PREAUTH_PREFIX) || text.contains("PRIVATE KEY") {
        return Err(CoordError::State);
    }
    write_text(&dir.join("presence.json"), &text, 0o600)
}

#[derive(Serialize, Deserialize, Default)]
struct PresenceFile {
    seen: BTreeMap<String, u64>,
}

fn read_file(dir: &Path) -> Result<KeyFile, CoordError> {
    let path = dir.join(PREAUTH_FILE);
    if !path.exists() {
        return Ok(KeyFile {
            version: FILE_VERSION,
            keys: Vec::new(),
        });
    }
    let text = read_text(&path)?;
    if text.contains(PREAUTH_PREFIX) || text.contains("PRIVATE KEY") {
        return Err(CoordError::State);
    }
    let file: KeyFile = serde_json::from_str(&text).map_err(|_| CoordError::State)?;
    if file.version != FILE_VERSION {
        return Err(CoordError::State);
    }
    Ok(file)
}

fn write_file(dir: &Path, file: &KeyFile) -> Result<(), CoordError> {
    let text = serde_json::to_string_pretty(file).map_err(|_| CoordError::State)?;
    if text.contains(PREAUTH_PREFIX) || text.contains("PRIVATE KEY") {
        return Err(CoordError::State);
    }
    write_text(&dir.join(PREAUTH_FILE), &text, 0o600)
}

fn key_hash(secret: &str) -> String {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use orblx_identity::SpiffeId;
    use serde_json::Value;

    use super::{
        create, enroll, fit_grant, list, remove_due, revoke, screen, CreateAsk, Creator, Fit,
        GrantAsk, PREAUTH_FILE, PREAUTH_PREFIX, UNKNOWN_DENY_WINDOW_MS,
    };
    use crate::agent::{fetch, request, Fetched};
    use crate::proto::GrantAsk as AgentAsk;
    use crate::roles::Role;
    use crate::{Coordinator, OidcConfig};

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "orblx-preauth-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    fn later(base: SystemTime, ms: u64) -> SystemTime {
        base + Duration::from_millis(ms)
    }

    /// Drop the process-local seen map for `dir`. A new process starts empty.
    fn forget_process_seen(dir: &Path) {
        let dir_key = dir.to_string_lossy().to_string();
        let mut guard = super::SEEN.lock().unwrap();
        guard.retain(|(key_dir, _), _| key_dir != &dir_key);
    }

    fn policy_with_tag() -> String {
        r#"{
            "owners": ["spiffe://orblx.local/node/owner"],
            "tags": {"tag:bot": ["spiffe://orblx.local/node/owner"]},
            "tagOwners": {"tag:bot": ["spiffe://orblx.local/node/owner"]},
            "nodeApproval": true
        }"#
        .to_string()
    }

    fn open_coord(dir: &Path) -> Coordinator {
        let coord = Coordinator::open(dir, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let policy = dir.join("policy.hujson");
        fs::write(&policy, policy_with_tag()).unwrap();
        coord.set_policy_file(&policy).unwrap();
        coord
    }

    fn ask_base() -> CreateAsk {
        CreateAsk {
            ttl_secs: 60,
            max_uses: 1,
            ephemeral: false,
            tags: Vec::new(),
            grant: None,
        }
    }

    fn key_text(value: &Value) -> String {
        value["key"].as_str().unwrap().to_string()
    }

    fn audit_lines(coord: &Coordinator) -> Vec<Value> {
        let text = coord.config_audit_text().unwrap();
        text.lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    }

    fn count_action(lines: &[Value], action: &str) -> usize {
        lines
            .iter()
            .filter(|line| line["action"].as_str() == Some(action))
            .count()
    }

    #[test]
    fn one_use_reusable_expiry_revoke_and_unknown_are_refused() {
        let dir = scratch("keys");
        let coord = open_coord(&dir.0);
        let owner = "spiffe://orblx.local/node/owner";
        let start = SystemTime::now();
        let made = create(&coord, &ask_base(), owner, start).unwrap();
        let secret = key_text(&made);
        let id = made["id"].as_str().unwrap();
        assert!(secret.starts_with(PREAUTH_PREFIX));
        assert_eq!(made["id"].as_str().unwrap().len(), 16);
        enroll(&coord, "bot", &secret, &["bot:443".to_string()], &[], start).unwrap();
        let again = enroll(
            &coord,
            "bot2",
            &secret,
            &["bot2:443".to_string()],
            &[],
            start,
        );
        assert!(again.unwrap_err().to_string().contains("used up"));
        let mut reusable = ask_base();
        reusable.max_uses = 2;
        let made = create(&coord, &reusable, owner, start).unwrap();
        let secret = key_text(&made);
        enroll(&coord, "r1", &secret, &["r1:443".to_string()], &[], start).unwrap();
        enroll(&coord, "r2", &secret, &["r2:443".to_string()], &[], start).unwrap();
        assert!(
            enroll(&coord, "r3", &secret, &["r3:443".to_string()], &[], start,)
                .unwrap_err()
                .to_string()
                .contains("used up")
        );
        let mut short = ask_base();
        short.ttl_secs = 2;
        let made = create(&coord, &short, owner, start).unwrap();
        let secret = key_text(&made);
        let late = later(start, 2000);
        assert!(enroll(
            &coord,
            "late",
            &secret,
            &["late:443".to_string()],
            &[],
            late,
        )
        .unwrap_err()
        .to_string()
        .contains("expired"));
        let early = later(start, 1999);
        enroll(
            &coord,
            "early",
            &secret,
            &["early:443".to_string()],
            &[],
            early,
        )
        .unwrap();
        let made = create(&coord, &ask_base(), owner, start).unwrap();
        let secret = key_text(&made);
        let kid = made["id"].as_str().unwrap().to_string();
        revoke(&coord, &kid, owner, start).unwrap();
        assert!(enroll(
            &coord,
            "revoked-node",
            &secret,
            &["revoked-node:443".to_string()],
            &[],
            start,
        )
        .unwrap_err()
        .to_string()
        .contains("revoked"));
        assert!(enroll(
            &coord,
            "nope",
            &format!("{PREAUTH_PREFIX}not-a-real-key"),
            &["nope:443".to_string()],
            &[],
            start,
        )
        .unwrap_err()
        .to_string()
        .contains("not valid"));
        let listed = list(&coord, start).unwrap();
        let text = listed.to_string();
        assert!(!text.contains(PREAUTH_PREFIX));
        assert!(text.contains(id));
        let file = fs::read_to_string(dir.0.join(PREAUTH_FILE)).unwrap();
        assert!(!file.contains(PREAUTH_PREFIX));
        assert!(!file.contains("PRIVATE KEY"));
        let mode = fs::metadata(dir.0.join(PREAUTH_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let lines = audit_lines(&coord);
        assert!(count_action(&lines, "preauth-create") >= 4);
        assert!(count_action(&lines, "preauth-use") >= 4);
        assert!(count_action(&lines, "preauth-revoke") >= 1);
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("preauth-deny")
                && line["detail"].as_str() == Some("reason used")
        }));
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("preauth-deny")
                && line["detail"].as_str() == Some("reason expired")
        }));
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("preauth-deny")
                && line["detail"].as_str() == Some("reason revoked")
        }));
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("preauth-deny")
                && line["detail"].as_str() == Some("reason unknown")
        }));
        let joined = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains(PREAUTH_PREFIX));
    }

    #[test]
    fn a_tag_or_grant_outside_the_caller_is_refused() {
        let dir = scratch("rights");
        let coord = open_coord(&dir.0);
        let owner_id = SpiffeId::node("owner").unwrap();
        let start = SystemTime::now();
        let mut tagged = ask_base();
        tagged.tags = vec!["tag:bot".to_string()];
        assert!(screen(&coord, &Creator::Owner(owner_id.clone()), &tagged).is_ok());
        create(&coord, &tagged, owner_id.as_uri(), start).unwrap();
        let mut foreign = ask_base();
        foreign.tags = vec!["tag:other".to_string()];
        assert!(create(&coord, &foreign, owner_id.as_uri(), start).is_err());
        let other = SpiffeId::node("other").unwrap();
        assert!(screen(&coord, &Creator::Owner(other), &tagged).is_err());
        assert!(screen(
            &coord,
            &Creator::Token {
                scopes: vec!["nodes:write".to_string(), "grants:write".to_string()],
            },
            &tagged,
        )
        .is_err());
        let srv = coord
            .create_token_at(Duration::from_secs(60), start)
            .unwrap();
        coord
            .enroll_token("srv", &srv.secret, &["srv:443".to_string()], &[], start)
            .unwrap();
        coord.approve_node_by("srv", owner_id.as_uri()).unwrap();
        let mut bound = ask_base();
        bound.grant = Some(GrantAsk {
            node: "srv".to_string(),
            service: "web".to_string(),
            port: 8080,
            path_prefix: "/".to_string(),
            max_ttl_secs: 60,
        });
        assert!(screen(
            &coord,
            &Creator::Token {
                scopes: vec!["nodes:write".to_string()],
            },
            &bound,
        )
        .is_err());
        assert!(screen(
            &coord,
            &Creator::Token {
                scopes: vec!["nodes:write".to_string(), "grants:write".to_string()],
            },
            &bound,
        )
        .is_ok());
        let mut wide = ask_base();
        wide.ttl_secs = super::MAX_PREAUTH_TTL_SECS + 1;
        assert!(create(&coord, &wide, owner_id.as_uri(), start).is_err());
        let lines = audit_lines(&coord);
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("preauth-deny")
                && line["detail"].as_str() == Some("reason tag")
        }));
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("preauth-deny")
                && line["detail"].as_str() == Some("reason life")
        }));
    }

    #[test]
    fn an_ephemeral_node_is_removed_on_grace_and_on_expiry() {
        let dir = scratch("eph");
        let coord = open_coord(&dir.0);
        let owner = "spiffe://orblx.local/node/owner";
        let start = SystemTime::now();
        let mut grace_key = ask_base();
        grace_key.ephemeral = true;
        grace_key.ttl_secs = 3600;
        let made = create(&coord, &grace_key, owner, start).unwrap();
        enroll(
            &coord,
            "quiet",
            &key_text(&made),
            &["quiet:443".to_string()],
            &[],
            start,
        )
        .unwrap();
        assert_eq!(remove_due(&coord, later(start, 14_999)).unwrap(), 0);
        assert_eq!(remove_due(&coord, later(start, 15_000)).unwrap(), 1);
        let nodes = coord.node_list().unwrap();
        let quiet = nodes.iter().find(|node| node.name == "quiet").unwrap();
        assert!(quiet.removed);
        let deny = crate::admin::deny_json(&coord, start).unwrap();
        assert!(deny.contains(&quiet.svid));
        let mut expiry_key = ask_base();
        expiry_key.ephemeral = true;
        expiry_key.ttl_secs = 5;
        let made = create(&coord, &expiry_key, owner, start).unwrap();
        enroll(
            &coord,
            "ending",
            &key_text(&made),
            &["ending:443".to_string()],
            &[],
            start,
        )
        .unwrap();
        super::note_seen(&coord, "ending", later(start, 5_000)).unwrap();
        assert_eq!(remove_due(&coord, later(start, 4_999)).unwrap(), 0);
        assert_eq!(remove_due(&coord, later(start, 5_000)).unwrap(), 1);
        let lines = audit_lines(&coord);
        let removes: Vec<_> = lines
            .iter()
            .filter(|line| line["action"].as_str() == Some("node-remove"))
            .collect();
        assert_eq!(removes.len(), 2);
        assert!(removes.iter().any(|line| {
            line["target"].as_str() == Some("quiet")
                && line["detail"].as_str().unwrap().contains("reason grace")
        }));
        assert!(removes.iter().any(|line| {
            line["target"].as_str() == Some("ending")
                && line["detail"].as_str().unwrap().contains("reason expiry")
        }));
        assert_eq!(remove_due(&coord, later(start, 20_000)).unwrap(), 0);
    }

    #[test]
    fn a_restart_resumes_grace_from_presence_json() {
        let dir = scratch("restart");
        let start = SystemTime::now();
        let seen_at = later(start, 5_000);
        let seen_ms = u64::try_from(
            seen_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        {
            let coord = open_coord(&dir.0);
            let mut ask = ask_base();
            ask.ephemeral = true;
            ask.ttl_secs = 3600;
            let made = create(&coord, &ask, "spiffe://orblx.local/node/owner", start).unwrap();
            enroll(
                &coord,
                "quiet",
                &key_text(&made),
                &["quiet:443".to_string()],
                &[],
                start,
            )
            .unwrap();
            super::note_seen(&coord, "quiet", seen_at).unwrap();
            let text = fs::read_to_string(dir.0.join("presence.json")).unwrap();
            let file: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(file["seen"]["quiet"].as_u64(), Some(seen_ms));
            assert_eq!(remove_due(&coord, later(seen_at, 14_999)).unwrap(), 0);
        }
        // A process restart drops the in-memory seen map. The file remains.
        forget_process_seen(&dir.0);
        let coord = open_coord(&dir.0);
        assert_eq!(remove_due(&coord, later(seen_at, 14_999)).unwrap(), 0);
        assert_eq!(remove_due(&coord, later(seen_at, 15_000)).unwrap(), 1);
        let nodes = coord.node_list().unwrap();
        let quiet = nodes.iter().find(|node| node.name == "quiet").unwrap();
        assert!(quiet.removed);
        let lines = audit_lines(&coord);
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("node-remove")
                && line["target"].as_str() == Some("quiet")
                && line["detail"].as_str().unwrap().contains("reason grace")
        }));
    }

    #[test]
    fn a_grant_inside_the_ceiling_is_preapproved_and_a_wider_grant_is_refused() {
        let dir = scratch("grant");
        let coord = open_coord(&dir.0);
        let owner = SpiffeId::node("owner").unwrap();
        let start = SystemTime::now();
        let srv = coord
            .create_token_at(Duration::from_secs(60), start)
            .unwrap();
        coord
            .enroll_token("srv", &srv.secret, &["srv:443".to_string()], &[], start)
            .unwrap();
        coord.approve_node_by("srv", owner.as_uri()).unwrap();
        let mut bound = ask_base();
        bound.grant = Some(GrantAsk {
            node: "srv".to_string(),
            service: "web".to_string(),
            port: 8080,
            path_prefix: "/".to_string(),
            max_ttl_secs: 30,
        });
        let made = create(&coord, &bound, owner.as_uri(), start).unwrap();
        enroll(
            &coord,
            "bot",
            &key_text(&made),
            &["bot:443".to_string()],
            &[],
            start,
        )
        .unwrap();
        let wide = AgentAsk {
            agent: "bot".to_string(),
            node: "srv".to_string(),
            service: "web".to_string(),
            port: 8080,
            ttl_secs: 31,
            path_prefix: Some("/".to_string()),
        };
        assert!(request(&coord, "bot", &wide, start).is_err());
        let ask = AgentAsk {
            ttl_secs: 30,
            ..wide
        };
        let reply = request(&coord, "bot", &ask, start).unwrap();
        assert_eq!(reply["state"], "approved");
        let id = reply["id"].as_str().unwrap();
        let Fetched::Issued(issued) = fetch(&coord, "bot", id, start).unwrap() else {
            panic!("the grant was not issued");
        };
        assert!(issued.0.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.0.private_key_pem.contains("PRIVATE KEY"));
        let plain = crate::proto::GrantAsk {
            agent: "srv".to_string(),
            node: "srv".to_string(),
            service: "web".to_string(),
            port: 8080,
            ttl_secs: 30,
            path_prefix: Some("/".to_string()),
        };
        match fit_grant(&coord, "srv", &plain, "/").unwrap() {
            Fit::Open => {}
            Fit::Ready { .. } | Fit::Deny { .. } => panic!("a normal node has no ceiling"),
        }
        let lines = audit_lines(&coord);
        assert_eq!(count_action(&lines, "preauth-use"), 1);
        assert!(lines.iter().any(|line| {
            line["action"].as_str() == Some("preauth-deny")
                && line["detail"].as_str() == Some("reason grant")
        }));
        assert!(lines
            .iter()
            .any(|line| line["action"].as_str() == Some("agent-approve")));
    }

    #[test]
    fn one_use_key_enrolls_exactly_one_node_under_parallel_calls() {
        let dir = scratch("race");
        let coord = open_coord(&dir.0);
        let start = SystemTime::now();
        let made = create(
            &coord,
            &ask_base(),
            "spiffe://orblx.local/node/owner",
            start,
        )
        .unwrap();
        let secret = key_text(&made);
        let mut handles = Vec::new();
        for index in 0..8 {
            let coord = coord.clone();
            let secret = secret.clone();
            handles.push(std::thread::spawn(move || {
                enroll(
                    &coord,
                    &format!("n{index}"),
                    &secret,
                    &[format!("n{index}:443")],
                    &[],
                    start,
                )
                .is_ok()
            }));
        }
        let wins = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(wins, 1);
        let listed = list(&coord, start).unwrap();
        assert_eq!(listed["keys"][0]["uses"], 1);
        let lines = audit_lines(&coord);
        assert_eq!(count_action(&lines, "preauth-use"), 1);
        assert_eq!(count_action(&lines, "preauth-deny"), 7);
        let joined = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains(PREAUTH_PREFIX));
    }

    #[test]
    fn a_token_refusal_in_create_writes_one_deny() {
        let dir = scratch("tokdeny");
        let coord = open_coord(&dir.0);
        let start = SystemTime::now();
        let token = crate::apitoken::create(
            &coord,
            &crate::apitoken::CreateAsk {
                scopes: vec!["nodes:write".to_string()],
                ttl_secs: 60,
            },
            "spiffe://orblx.local/node/owner",
            Role::Owner,
            start,
        )
        .unwrap();
        let mut ask = ask_base();
        ask.tags = vec!["tag:bot".to_string()];
        let err = create(&coord, &ask, &format!("api-token:{}", token.id), start).unwrap_err();
        assert!(err.to_string().contains("outside the caller rights"));
        let lines = audit_lines(&coord);
        let denies = lines
            .iter()
            .filter(|line| {
                line["action"].as_str() == Some("preauth-deny")
                    && line["detail"].as_str() == Some("reason tag")
            })
            .count();
        assert_eq!(denies, 1);
        let joined = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains(PREAUTH_PREFIX));
    }

    #[test]
    fn unknown_key_denies_share_one_record_per_second() {
        let dir = scratch("unknown");
        let coord = open_coord(&dir.0);
        let start = SystemTime::now();
        let bad = format!("{PREAUTH_PREFIX}not-a-real-key");
        for index in 0..6 {
            let err = enroll(
                &coord,
                &format!("u{index}"),
                &bad,
                &["u:443".to_string()],
                &[],
                start,
            )
            .unwrap_err();
            assert!(err.to_string().contains("not valid"));
        }
        let lines = audit_lines(&coord);
        assert_eq!(count_action(&lines, "preauth-deny"), 1);
        let err = enroll(
            &coord,
            "later",
            &bad,
            &["later:443".to_string()],
            &[],
            later(start, UNKNOWN_DENY_WINDOW_MS),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not valid"));
        let lines = audit_lines(&coord);
        assert_eq!(count_action(&lines, "preauth-deny"), 2);
        let joined = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains(PREAUTH_PREFIX));
    }

    #[test]
    fn an_ephemeral_removal_retry_does_not_duplicate_the_deny_entry() {
        let dir = scratch("retry");
        let coord = open_coord(&dir.0);
        let start = SystemTime::now();
        let mut ask = ask_base();
        ask.ephemeral = true;
        ask.ttl_secs = 3600;
        let made = create(&coord, &ask, "spiffe://orblx.local/node/owner", start).unwrap();
        enroll(
            &coord,
            "quiet",
            &key_text(&made),
            &["quiet:443".to_string()],
            &[],
            start,
        )
        .unwrap();
        let due = later(start, 15_000);
        let id = SpiffeId::node("quiet").unwrap();
        crate::agent::revoke_principal(&coord, &id, due).unwrap();
        let before = crate::admin::deny_json(&coord, due).unwrap();
        let svid = coord
            .node_list()
            .unwrap()
            .iter()
            .find(|node| node.name == "quiet")
            .unwrap()
            .svid
            .clone();
        assert_eq!(before.matches(&format!("\"{svid}\"")).count(), 1);
        assert_eq!(remove_due(&coord, due).unwrap(), 1);
        let after = crate::admin::deny_json(&coord, due).unwrap();
        assert_eq!(after.matches(&format!("\"{svid}\"")).count(), 1);
        assert_eq!(
            before
                .split("\"version\":")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .trim(),
            after
                .split("\"version\":")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .trim()
        );
        assert_eq!(remove_due(&coord, due).unwrap(), 0);
        let lines = audit_lines(&coord);
        assert_eq!(count_action(&lines, "node-remove"), 1);
        let final_deny = crate::admin::deny_json(&coord, due).unwrap();
        assert_eq!(final_deny.matches(&format!("\"{svid}\"")).count(), 1);
    }
}
