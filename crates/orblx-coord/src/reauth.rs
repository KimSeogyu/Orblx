//! Same-name re-auth after a long pause (W25-47).
//!
//! The marker file stores the first rc.3 wall second.
//! The used-token file stores `(iss, sub, nonce)` until `exp`.
//! Neither file stores a private key or an ID token.

#[cfg(test)]
use std::cell::Cell;
use std::fs;
use std::path::Path;
#[cfg(test)]
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use orblx_identity::{
    leaf_key_id, leaf_validity, ticket_nonce_and_expiry, DenySet, MAX_SKEW, MAX_USER_TTL,
};
use serde::{Deserialize, Serialize};

use crate::error::CoordError;
use crate::files::{read_text, write_durable};
use crate::netmap::encode_hex;
use crate::store::{LiveLeafKey, LiveTicketNonce, NodeGrantBound};

const RC3_START_FILE: &str = "rc3-start";
const USED_FILE: &str = "reauth-used.json";

/// The legacy wait. Ticket life is `svid_ttl`, and `store_svid_ttl` refuses a
/// life above `MAX_USER_TTL`, so this wait also covers a pre-rc.3 ticket.
pub(crate) fn legacy_wait_secs() -> u64 {
    MAX_USER_TTL.as_secs() + MAX_SKEW.as_secs()
}

/// Facts from a pre-auth key. The key text is not here.
pub(crate) struct PreauthFacts {
    pub id: String,
    pub created_by: String,
    pub nodes: Vec<String>,
    pub tags: Vec<String>,
    pub grant: Option<NodeGrantBound>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UsedEntry {
    iss: String,
    sub: String,
    nonce: String,
    expires: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UsedFile {
    entries: Vec<UsedEntry>,
}

#[cfg(test)]
thread_local! {
    static CRASH: Cell<u8> = const { Cell::new(0) };
    static RENEW_THIS_THREAD: Cell<bool> = const { Cell::new(false) };
    static DENY_THIS_THREAD: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
static RENEW_WAIT: Mutex<Option<std::sync::mpsc::Receiver<()>>> = Mutex::new(None);

#[cfg(test)]
static RENEW_READY: Mutex<Option<std::sync::mpsc::Sender<()>>> = Mutex::new(None);

#[cfg(test)]
static DENY_WAIT: Mutex<Option<std::sync::mpsc::Receiver<()>>> = Mutex::new(None);

#[cfg(test)]
static DENY_READY: Mutex<Option<std::sync::mpsc::Sender<()>>> = Mutex::new(None);

/// Mark this thread. Only a marked thread takes the renew hook.
#[cfg(test)]
pub(crate) fn mark_renew_wait() {
    RENEW_THIS_THREAD.with(|flag| flag.set(true));
}

/// Arm the renew hook. The marked renew call sends on the ready channel, then waits.
#[cfg(test)]
pub(crate) fn arm_renew_wait() -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel();
    *RENEW_READY
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(ready_tx);
    *RENEW_WAIT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(go_rx);
    (ready_rx, go_tx)
}

#[cfg(test)]
pub(crate) fn arm_crash(point: u8) {
    CRASH.with(|cell| cell.set(point));
}

/// Mark this thread. Only a marked thread takes the deny hook.
#[cfg(test)]
pub(crate) fn mark_deny_wait() {
    DENY_THIS_THREAD.with(|flag| flag.set(true));
}

/// Arm the deny hook. The marked call sends on the ready channel, then waits.
#[cfg(test)]
pub(crate) fn arm_deny_wait() -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel();
    *DENY_READY
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(ready_tx);
    *DENY_WAIT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(go_rx);
    (ready_rx, go_tx)
}

pub(crate) fn deny_hook() {
    #[cfg(test)]
    {
        let marked = DENY_THIS_THREAD.with(|flag| flag.replace(false));
        if !marked {
            return;
        }
        let ready = DENY_READY
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        let wait = DENY_WAIT
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        if let Some(wait) = wait {
            let _ = wait.recv();
        }
    }
}

pub(crate) fn renew_hook() {
    #[cfg(test)]
    {
        let marked = RENEW_THIS_THREAD.with(|flag| flag.replace(false));
        if !marked {
            return;
        }
        let ready = RENEW_READY
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        let wait = RENEW_WAIT
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        if let Some(wait) = wait {
            let _ = wait.recv();
        }
    }
}

pub(crate) fn crash_at(point: u8) -> Result<(), CoordError> {
    #[cfg(test)]
    {
        if CRASH.with(|cell| cell.get()) == point {
            CRASH.with(|cell| cell.set(0));
            return Err(CoordError::Protocol(
                "The re-auth stopped at a crash point.".to_string(),
            ));
        }
    }
    #[cfg(not(test))]
    {
        let _ = point;
    }
    Ok(())
}

/// Write the first-start wall second when the file is missing or does not parse.
///
/// A parsed non-zero value stays. The function does not write 0.
pub(crate) fn ensure_rc3_start(dir: &Path, now: SystemTime) -> Result<u64, CoordError> {
    let path = dir.join(RC3_START_FILE);
    if let Some(stored) = read_start(&path)? {
        return Ok(stored);
    }
    let secs = wall_secs(now)?;
    if secs == 0 {
        return Err(CoordError::Time);
    }
    write_durable(&path, format!("{secs}\n").as_bytes(), 0o644)?;
    Ok(secs)
}

pub(crate) fn read_rc3_start(dir: &Path) -> Result<u64, CoordError> {
    let path = dir.join(RC3_START_FILE);
    read_start(&path)?.ok_or(CoordError::State)
}

fn read_start(path: &Path) -> Result<Option<u64>, CoordError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = match read_text(path) {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };
    let Ok(value) = text.trim().parse::<u64>() else {
        return Ok(None);
    };
    if value == 0 {
        return Ok(None);
    }
    Ok(Some(value))
}

pub(crate) fn wall_secs(now: SystemTime) -> Result<u64, CoordError> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoordError::Time)
}

pub(crate) fn load_deny_or_refuse(dir: &Path) -> DenySet {
    let path = dir.join("deny.json");
    if !path.exists() {
        return DenySet::empty();
    }
    match fs::read(&path) {
        Ok(bytes) => DenySet::from_json(&bytes).unwrap_or_else(|_| DenySet::refuse_all()),
        Err(_) => DenySet::refuse_all(),
    }
}

pub(crate) fn issued_ids(
    pem: &str,
    ticket: &[u8],
) -> Result<(LiveLeafKey, LiveTicketNonce), CoordError> {
    let der = orblx_identity::decode_certificate_pem(pem).map_err(|_| CoordError::State)?;
    let key_id = leaf_key_id(&der).map_err(|_| CoordError::State)?;
    let (_not_before, not_after) = leaf_validity(&der).map_err(|_| CoordError::State)?;
    let (nonce, expires) = ticket_nonce_and_expiry(ticket).map_err(|_| CoordError::State)?;
    Ok((
        LiveLeafKey { key_id, not_after },
        LiveTicketNonce {
            nonce: encode_hex(&nonce),
            expires,
        },
    ))
}

pub(crate) fn prune_keys(keys: &[LiveLeafKey], now_unix: u64) -> Vec<LiveLeafKey> {
    keys.iter()
        .filter(|item| now_unix <= item.not_after.saturating_add(MAX_SKEW.as_secs()))
        .cloned()
        .collect()
}

pub(crate) fn prune_nonces(nonces: &[LiveTicketNonce], now_unix: u64) -> Vec<LiveTicketNonce> {
    nonces
        .iter()
        .filter(|item| now_unix <= item.expires)
        .cloned()
        .collect()
}

/// True when this re-auth must wait.
///
/// An absent leaf list is legacy. A node enrolled before the marker is also
/// legacy, so a renew that filled the list during the wait cannot skip it.
/// The wait then covers the pre-rc.3 ticket, whose life is at most `MAX_USER_TTL`.
pub(crate) fn legacy_wait_blocks(
    keys_absent: bool,
    enrolled_unix: u64,
    start: u64,
    now_unix: u64,
) -> bool {
    let legacy = keys_absent || enrolled_unix < start;
    legacy && now_unix < start.saturating_add(legacy_wait_secs())
}

/// Record one triple when it is new. Return false when it is already used.
///
/// The prune uses `now_unix`, the same clock as the check.
pub(crate) fn take_used_token(
    dir: &Path,
    iss: &str,
    sub: &str,
    nonce: &str,
    expires: u64,
    now_unix: u64,
) -> Result<bool, CoordError> {
    let mut file = read_used(dir)?;
    file.entries.retain(|entry| now_unix <= entry.expires);
    let used = file
        .entries
        .iter()
        .any(|entry| entry.iss == iss && entry.sub == sub && entry.nonce == nonce);
    if used {
        write_used(dir, &file)?;
        return Ok(false);
    }
    file.entries.push(UsedEntry {
        iss: iss.to_string(),
        sub: sub.to_string(),
        nonce: nonce.to_string(),
        expires,
    });
    write_used(dir, &file)?;
    Ok(true)
}

fn read_used(dir: &Path) -> Result<UsedFile, CoordError> {
    let path = dir.join(USED_FILE);
    if !path.exists() {
        return Ok(UsedFile {
            entries: Vec::new(),
        });
    }
    let text = read_text(&path)?;
    serde_json::from_str(&text).map_err(|_| CoordError::State)
}

fn write_used(dir: &Path, file: &UsedFile) -> Result<(), CoordError> {
    let text = serde_json::to_string(file).map_err(|_| CoordError::State)?;
    if text.contains("PRIVATE KEY") {
        return Err(CoordError::State);
    }
    write_durable(&dir.join(USED_FILE), text.as_bytes(), 0o600)
}

#[cfg(test)]
pub(crate) fn testing_write_rc3_start(dir: &Path, text: &str) {
    let _ = write_durable(dir.join(RC3_START_FILE).as_path(), text.as_bytes(), 0o644);
}
