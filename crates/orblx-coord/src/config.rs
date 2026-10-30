//! The coordinator config file.
//!
//! The file uses a small TOML subset.
//! Only the `[oidc]` section exists.
//! A value is a quoted string or a one-line array of quoted strings.
//!
//! ```text
//! [oidc]
//! issuer = "https://idp.example.com"
//! client_id = "orblx"
//! allowed_domains = ["example.com"]
//! allowed_emails = ["ops@partner.example"]
//! ca_file = "/etc/orblx/idp-ca.pem"
//! ```
//!
//! `preset = "google"` selects Google. The issuer is then `https://accounts.google.com`.

use std::path::{Path, PathBuf};

use orblx_identity::{google_client_id_ok, OidcIssuer, GOOGLE_ISSUER};

use crate::error::CoordError;
use crate::state::OidcConfig;

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_CA_BYTES: usize = 64 * 1024;

/// The `[oidc]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OidcSection {
    /// `google` or absent.
    pub preset: Option<String>,
    /// The issuer URL.
    pub issuer: Option<String>,
    /// The OAuth client id.
    pub client_id: Option<String>,
    /// Allowed email domains.
    pub allowed_domains: Vec<String>,
    /// Allowed email addresses.
    pub allowed_emails: Vec<String>,
    /// Extra TLS roots for the issuer, as a PEM file.
    pub ca_file: Option<PathBuf>,
}

/// The parsed config file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoordConfig {
    /// The `[oidc]` section, when the file has one.
    pub oidc: Option<OidcSection>,
}

fn bad(line: usize, text: &str) -> CoordError {
    CoordError::Protocol(format!("The config file line {line} is not valid: {text}"))
}

impl CoordConfig {
    /// Read and parse one config file.
    pub fn from_file(path: &Path) -> Result<Self, CoordError> {
        let text = std::fs::read_to_string(path).map_err(|_| {
            CoordError::Protocol(format!("The config file {} did not open.", path.display()))
        })?;
        Self::parse(&text)
    }

    /// Parse config text.
    pub fn parse(text: &str) -> Result<Self, CoordError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(CoordError::Protocol(
                "The config file is too large.".to_string(),
            ));
        }
        let mut config = Self::default();
        let mut section: Option<String> = None;
        for (number, raw) in text.lines().enumerate() {
            let line_no = number + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                let name = name.trim();
                if name != "oidc" {
                    return Err(bad(line_no, "the section is not known"));
                }
                if config.oidc.is_some() {
                    return Err(bad(line_no, "the section is repeated"));
                }
                config.oidc = Some(OidcSection::default());
                section = Some(name.to_string());
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(bad(line_no, "the line has no ="));
            };
            let key = key.trim();
            let value = value.trim();
            let (Some(_), Some(oidc)) = (section.as_ref(), config.oidc.as_mut()) else {
                return Err(bad(line_no, "the key is outside a section"));
            };
            match key {
                "preset" => set_once(&mut oidc.preset, parse_string(value, line_no)?, line_no)?,
                "issuer" => set_once(&mut oidc.issuer, parse_string(value, line_no)?, line_no)?,
                "client_id" => {
                    set_once(&mut oidc.client_id, parse_string(value, line_no)?, line_no)?
                }
                "ca_file" => {
                    let path = PathBuf::from(parse_string(value, line_no)?);
                    if oidc.ca_file.replace(path).is_some() {
                        return Err(bad(line_no, "the key is repeated"));
                    }
                }
                "allowed_domains" => oidc.allowed_domains = parse_array(value, line_no)?,
                "allowed_emails" => oidc.allowed_emails = parse_array(value, line_no)?,
                _ => return Err(bad(line_no, "the key is not known")),
            }
        }
        Ok(config)
    }

    /// Build the coordinator OIDC mode from the `[oidc]` section.
    ///
    /// The function returns `None` when the file has no `[oidc]` section.
    pub fn oidc_config(&self) -> Result<Option<OidcConfig>, CoordError> {
        let Some(section) = &self.oidc else {
            return Ok(None);
        };
        let not_valid = || CoordError::Protocol("The OIDC configuration is not valid.".to_string());
        let client_id = section.client_id.as_deref().ok_or_else(not_valid)?;
        let issuer = match section.preset.as_deref() {
            None => section.issuer.as_deref().ok_or_else(not_valid)?,
            Some("google") => {
                google_client_id_ok(client_id).map_err(|_| not_valid())?;
                match section.issuer.as_deref() {
                    None | Some(GOOGLE_ISSUER) => GOOGLE_ISSUER,
                    Some(_) => return Err(not_valid()),
                }
            }
            Some(_) => return Err(not_valid()),
        };
        let issuer = OidcIssuer::new(
            issuer,
            client_id,
            &section.allowed_domains,
            &section.allowed_emails,
        )
        .map_err(|_| not_valid())?;
        let extra_roots_pem = match &section.ca_file {
            None => None,
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|_| {
                    CoordError::Protocol(format!(
                        "The OIDC CA file {} did not open.",
                        path.display()
                    ))
                })?;
                if text.len() > MAX_CA_BYTES || !text.contains("-----BEGIN CERTIFICATE-----") {
                    return Err(not_valid());
                }
                Some(text)
            }
        };
        Ok(Some(OidcConfig::Issuer {
            issuer: Box::new(issuer),
            extra_roots_pem,
        }))
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..index],
            _ => {}
        }
    }
    line
}

fn set_once(slot: &mut Option<String>, value: String, line: usize) -> Result<(), CoordError> {
    if slot.replace(value).is_some() {
        return Err(bad(line, "the key is repeated"));
    }
    Ok(())
}

fn parse_string(value: &str, line: usize) -> Result<String, CoordError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| bad(line, "the value is not a quoted string"))?;
    if inner.contains(['"', '\\']) || inner.chars().any(char::is_control) {
        return Err(bad(
            line,
            "the string has a quote, a backslash, or a control character",
        ));
    }
    Ok(inner.to_string())
}

fn parse_array(value: &str, line: usize) -> Result<Vec<String>, CoordError> {
    let inner = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| bad(line, "the value is not an array"))?
        .trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let inner = inner.strip_suffix(',').unwrap_or(inner);
    inner
        .split(',')
        .map(|item| parse_string(item.trim(), line))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::CoordConfig;
    use crate::state::OidcConfig;

    #[test]
    fn the_oidc_section_parses() {
        let config = CoordConfig::parse(
            "# coordinator\n[oidc]\nissuer = \"https://idp.test:8443\" # the issuer\nclient_id = \"orblx\"\nallowed_domains = [\"example.com\", \"lab.test\",]\nallowed_emails = []\n",
        )
        .unwrap();
        let section = config.oidc.clone().unwrap();
        assert_eq!(section.issuer.as_deref(), Some("https://idp.test:8443"));
        assert_eq!(section.allowed_domains, vec!["example.com", "lab.test"]);
        let Some(OidcConfig::Issuer {
            issuer,
            extra_roots_pem,
        }) = config.oidc_config().unwrap()
        else {
            panic!("The config did not select a generic issuer.");
        };
        assert_eq!(issuer.client_id(), "orblx");
        assert!(extra_roots_pem.is_none());
    }

    #[test]
    fn google_is_a_preset() {
        let config = CoordConfig::parse(
            "[oidc]\npreset = \"google\"\nclient_id = \"123-abc.apps.googleusercontent.com\"\n",
        )
        .unwrap();
        let Some(OidcConfig::Issuer { issuer, .. }) = config.oidc_config().unwrap() else {
            panic!("The preset did not select an issuer.");
        };
        assert_eq!(issuer.issuer(), "https://accounts.google.com");
        let bad =
            CoordConfig::parse("[oidc]\npreset = \"google\"\nclient_id = \"orblx\"\n").unwrap();
        assert!(bad.oidc_config().is_err());
    }

    #[test]
    fn bad_files_are_rejected() {
        for text in [
            "[other]\n",
            "issuer = \"https://x\"\n",
            "[oidc]\nissuer = https://x\n",
            "[oidc]\nunknown = \"x\"\n",
            "[oidc]\nissuer = \"https://a\"\nissuer = \"https://b\"\n",
            "[oidc]\n[oidc]\n",
        ] {
            assert!(CoordConfig::parse(text).is_err(), "{text}");
        }
        for text in [
            "[oidc]\nclient_id = \"orblx\"\n",
            "[oidc]\nissuer = \"http://idp\"\nclient_id = \"orblx\"\n",
            "[oidc]\npreset = \"okta\"\nissuer = \"https://idp\"\nclient_id = \"orblx\"\n",
        ] {
            let config = CoordConfig::parse(text).unwrap();
            assert!(config.oidc_config().is_err(), "{text}");
        }
        assert!(CoordConfig::parse("")
            .unwrap()
            .oidc_config()
            .unwrap()
            .is_none());
    }
}
