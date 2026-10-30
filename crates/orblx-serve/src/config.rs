//! The serve state file and the audit records for each change.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use orblx_audit::{sha256_digest, ConfigAction, ConfigEvent, ConfigLog, EMPTY_DIGEST};
use serde::{Deserialize, Serialize};

/// The serve state file name in the node state directory.
pub const SERVE_FILE: &str = "serve.json";

/// The config audit chain file name in the node state directory.
pub const SERVE_AUDIT_FILE: &str = "serve-audit.jsonl";

/// The default HTTPS port on the overlay address.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// The default limit for one request body, in bytes (10 MiB).
///
/// A request with a larger body gets `413 Payload Too Large`.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 10 * 1024 * 1024;

/// The serve state.
///
/// The CLI writes the file. The node daemon reads it again every 300 ms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    /// Document version. The value is 1.
    pub version: u32,
    /// The local TCP port on `127.0.0.1` that serve publishes.
    pub target_port: u16,
    /// The HTTPS port on the overlay address.
    pub https_port: u16,
    /// True only after an explicit `orblx funnel on`.
    #[serde(default)]
    pub funnel: bool,
    /// The outside `ip:port` for funnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funnel_listen: Option<SocketAddr>,
    /// The limit for one request body, in bytes.
    ///
    /// `None` means [`DEFAULT_MAX_BODY_BYTES`]. A file without this field keeps
    /// the same bytes and the same audit digest as a W21-4 file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
}

impl ServeConfig {
    /// Read the serve state from `state_dir`.
    ///
    /// An absent file means that serve is off.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, String> {
        let path = state_dir.join(SERVE_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("The serve file did not open.".to_string()),
        };
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| "The serve file is not valid.".to_string())?;
        config.check()?;
        Ok(Some(config))
    }

    /// The limit for one request body, in bytes.
    #[must_use]
    pub fn body_limit(&self) -> u64 {
        self.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES)
    }

    /// Check the values.
    pub fn check(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err("The serve file version is not 1.".to_string());
        }
        if self.target_port == 0 || self.https_port == 0 {
            return Err("A serve port is 0.".to_string());
        }
        if self.max_body_bytes == Some(0) {
            return Err("The body limit is 0.".to_string());
        }
        if self.funnel && self.funnel_listen.is_none() {
            return Err("Funnel is on but it has no listen address.".to_string());
        }
        if let Some(addr) = self.funnel_listen {
            if addr.port() == 0 {
                return Err("The funnel port is 0.".to_string());
            }
            // An all-address or overlay listener would skip the policy check for overlay peers.
            if addr.ip().is_unspecified() || in_overlay_range(addr.ip()) {
                return Err(
                    "The funnel address must be one outside address, not 0.0.0.0 or an overlay address."
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| "The serve file did not encode.".to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn store(&self, state_dir: &Path) -> Result<(), String> {
        self.check()?;
        let bytes = self.to_bytes()?;
        let path = state_dir.join(SERVE_FILE);
        let tmp = state_dir.join(format!("{SERVE_FILE}.tmp"));
        fs::write(&tmp, bytes).map_err(|_| "The serve file did not write.".to_string())?;
        fs::rename(&tmp, &path).map_err(|_| "The serve file did not write.".to_string())
    }
}

/// The result of one CLI change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeChange {
    /// The state after the change. `None` means that serve is off.
    pub config: Option<ServeConfig>,
    /// The index of the new audit record. `None` means that nothing changed.
    pub record: Option<u64>,
}

/// Turn serve on, or change its ports or its body limit.
///
/// A new serve state has funnel off.
/// A port change keeps the funnel state.
/// `max_body_bytes: None` keeps the body limit that the state has.
pub fn enable_serve(
    state_dir: &Path,
    target_port: u16,
    https_port: u16,
    max_body_bytes: Option<u64>,
    actor: &str,
) -> Result<ServeChange, String> {
    let before = ServeConfig::load(state_dir)?;
    let mut next = before.clone().unwrap_or(ServeConfig {
        version: 1,
        target_port,
        https_port,
        funnel: false,
        funnel_listen: None,
        max_body_bytes: None,
    });
    next.target_port = target_port;
    next.https_port = https_port;
    if max_body_bytes.is_some() {
        next.max_body_bytes = max_body_bytes;
    }
    let mut detail = format!("serve target 127.0.0.1:{target_port} https {https_port}");
    if let Some(limit) = next.max_body_bytes {
        detail.push_str(&format!(" max_body {limit}"));
    }
    commit(
        state_dir,
        before.as_ref(),
        Some(next),
        ConfigAction::Serve,
        actor,
        &detail,
    )
}

/// Turn serve off. Funnel also goes off.
pub fn disable_serve(state_dir: &Path, actor: &str) -> Result<ServeChange, String> {
    let before = ServeConfig::load(state_dir)?;
    if before.is_none() {
        return Ok(ServeChange {
            config: None,
            record: None,
        });
    }
    let mut change = None;
    if before.as_ref().is_some_and(|config| config.funnel) {
        change = set_funnel(state_dir, false, None, actor)?.record;
    }
    let before = ServeConfig::load(state_dir)?;
    let result = commit(
        state_dir,
        before.as_ref(),
        None,
        ConfigAction::ServeOff,
        actor,
        "serve off",
    )?;
    Ok(ServeChange {
        config: None,
        record: result.record.or(change),
    })
}

/// Turn funnel on or off.
///
/// Funnel on needs serve on and a listen address.
/// A second `funnel on` with the same address writes no record.
pub fn set_funnel(
    state_dir: &Path,
    on: bool,
    listen: Option<SocketAddr>,
    actor: &str,
) -> Result<ServeChange, String> {
    let Some(before) = ServeConfig::load(state_dir)? else {
        if on {
            return Err("Serve is off. Run orblx serve PORT first.".to_string());
        }
        return Ok(ServeChange {
            config: None,
            record: None,
        });
    };
    let mut next = before.clone();
    next.funnel = on;
    if let Some(addr) = listen {
        next.funnel_listen = Some(addr);
    }
    if on && next.funnel_listen.is_none() {
        return Err("Funnel on needs --listen ADDR.".to_string());
    }
    let (action, detail) = if on {
        let addr = next
            .funnel_listen
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        (ConfigAction::FunnelOn, format!("funnel on listen {addr}"))
    } else {
        (ConfigAction::FunnelOff, "funnel off".to_string())
    };
    commit(state_dir, Some(&before), Some(next), action, actor, &detail)
}

fn commit(
    state_dir: &Path,
    before: Option<&ServeConfig>,
    next: Option<ServeConfig>,
    action: ConfigAction,
    actor: &str,
    detail: &str,
) -> Result<ServeChange, String> {
    if before == next.as_ref() {
        return Ok(ServeChange {
            config: next,
            record: None,
        });
    }
    let before_digest = digest_of(before)?;
    let after_digest = digest_of(next.as_ref())?;
    // Open and check the chain before the state changes.
    let mut log = ConfigLog::open(&state_dir.join(SERVE_AUDIT_FILE))
        .map_err(|err| format!("The serve audit chain is not valid. {err}"))?;
    match &next {
        Some(config) => config.store(state_dir)?,
        None => match fs::remove_file(state_dir.join(SERVE_FILE)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("The serve file did not delete.".to_string()),
        },
    }
    let record = log
        .append(ConfigEvent {
            actor: actor.to_string(),
            at_unix: unix_now(),
            action,
            target: SERVE_FILE.to_string(),
            before: before_digest,
            after: after_digest,
            detail: detail.to_string(),
        })
        .map_err(|err| format!("The serve audit record did not write. {err}"))?;
    Ok(ServeChange {
        config: next,
        record: Some(record.index),
    })
}

/// Return true for an address in 100.64.0.0/10, the overlay range.
fn in_overlay_range(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] & 0xC0) == 64
        }
        std::net::IpAddr::V6(_) => false,
    }
}

fn digest_of(config: Option<&ServeConfig>) -> Result<[u8; 32], String> {
    match config {
        Some(config) => Ok(sha256_digest(&config.to_bytes()?)),
        None => Ok(EMPTY_DIGEST),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orblx_audit::verify_config_file;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orblx-serve-{name}-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("temp dir"));
        dir
    }

    #[test]
    fn funnel_is_off_by_default_and_each_change_is_audited() {
        let dir = temp_dir("audit");
        let actor = "spiffe://orblx.local/node/b";
        let change =
            enable_serve(&dir, 8080, 443, None, actor).unwrap_or_else(|err| panic!("{err}"));
        let config = change.config.unwrap_or_else(|| panic!("serve config"));
        assert!(!config.funnel);
        assert_eq!(config.funnel_listen, None);
        assert_eq!(change.record, Some(0));

        // Funnel on needs one outside address.
        assert!(set_funnel(&dir, true, None, actor).is_err());
        for bad in ["0.0.0.0:8443", "100.64.0.2:8443"] {
            let bad: SocketAddr = bad.parse().unwrap_or_else(|_| panic!("addr"));
            assert!(set_funnel(&dir, true, Some(bad), actor).is_err());
        }
        let addr: SocketAddr = "192.0.2.10:8443".parse().unwrap_or_else(|_| panic!("addr"));
        let on = set_funnel(&dir, true, Some(addr), actor).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(on.record, Some(1));
        // The same state again writes no record.
        let again = set_funnel(&dir, true, None, actor).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(again.record, None);
        let off = set_funnel(&dir, false, None, actor).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(off.record, Some(2));
        let stored = ServeConfig::load(&dir)
            .unwrap_or_else(|err| panic!("{err}"))
            .unwrap_or_else(|| panic!("serve config"));
        assert!(!stored.funnel);

        let gone = disable_serve(&dir, actor).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(gone.record, Some(3));
        assert!(ServeConfig::load(&dir)
            .unwrap_or_else(|err| panic!("{err}"))
            .is_none());
        assert!(set_funnel(&dir, true, Some(addr), actor).is_err());

        let checked =
            verify_config_file(&dir.join(SERVE_AUDIT_FILE)).unwrap_or_else(|err| panic!("{err}"));
        let actions: Vec<_> = checked
            .records
            .iter()
            .map(|record| record.event.action)
            .collect();
        assert_eq!(
            actions,
            vec![
                ConfigAction::Serve,
                ConfigAction::FunnelOn,
                ConfigAction::FunnelOff,
                ConfigAction::ServeOff
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_w21_serve_file_loads_with_funnel_off_and_the_default_body_limit() {
        let dir = temp_dir("w21");
        // The W21-4 file has no funnel field and no body limit.
        fs::write(
            dir.join(SERVE_FILE),
            "{\"version\":1,\"target_port\":8080,\"https_port\":443}",
        )
        .unwrap_or_else(|_| panic!("write"));
        let config = ServeConfig::load(&dir)
            .unwrap_or_else(|err| panic!("{err}"))
            .unwrap_or_else(|| panic!("serve config"));
        assert!(!config.funnel);
        assert_eq!(config.funnel_listen, None);
        assert_eq!(config.body_limit(), DEFAULT_MAX_BODY_BYTES);
        // The default limit stays out of the file, so the W21-4 digests do not change.
        let text = String::from_utf8(config.to_bytes().unwrap_or_else(|err| panic!("{err}")))
            .unwrap_or_else(|_| panic!("utf8"));
        assert!(!text.contains("max_body_bytes"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_body_limit_change_is_audited_and_kept() {
        let dir = temp_dir("limit");
        let actor = "spiffe://orblx.local/node/b";
        let change =
            enable_serve(&dir, 8080, 443, Some(4096), actor).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(change.record, Some(0));
        let again =
            enable_serve(&dir, 8080, 443, None, actor).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(again.record, None);
        let config = again.config.unwrap_or_else(|| panic!("serve config"));
        assert_eq!(config.body_limit(), 4096);
        assert!(!config.funnel);
        assert!(enable_serve(&dir, 8080, 443, Some(0), actor).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_chain_blocks_the_change() {
        let dir = temp_dir("broken");
        let actor = "spiffe://orblx.local/node/b";
        enable_serve(&dir, 8080, 443, None, actor).unwrap_or_else(|err| panic!("{err}"));
        let path = dir.join(SERVE_AUDIT_FILE);
        let text = fs::read_to_string(&path).unwrap_or_else(|_| panic!("chain"));
        fs::write(&path, text.replace("8080", "9090")).unwrap_or_else(|_| panic!("write"));
        let addr: SocketAddr = "192.0.2.10:8443".parse().unwrap_or_else(|_| panic!("addr"));
        assert!(set_funnel(&dir, true, Some(addr), actor).is_err());
        let stored = ServeConfig::load(&dir)
            .unwrap_or_else(|err| panic!("{err}"))
            .unwrap_or_else(|| panic!("serve config"));
        assert!(!stored.funnel);
        let _ = fs::remove_dir_all(&dir);
    }
}
