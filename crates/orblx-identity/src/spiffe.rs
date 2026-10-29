use std::time::Duration;

use crate::clock::{MAX_AGENT_TTL, MAX_USER_TTL};
use crate::error::IdentityError;

/// The trust domain for this spike.
pub const TRUST_DOMAIN: &str = "orblx.local";

/// The kind of SPIFFE path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadKind {
    /// `spiffe://orblx.local/user/{name}`
    User,
    /// `spiffe://orblx.local/agent/{name}`
    Agent,
    /// `spiffe://orblx.local/node/{name}`
    Node,
    /// `spiffe://orblx.local/coord/{name}`
    Coord,
}

impl WorkloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkloadKind::User => "user",
            WorkloadKind::Agent => "agent",
            WorkloadKind::Node => "node",
            WorkloadKind::Coord => "coord",
        }
    }

    /// Return the longest certificate life for this kind.
    ///
    /// A node SVID and a coord SVID use the user limit in this spike.
    pub fn max_ttl(self) -> Duration {
        match self {
            WorkloadKind::Agent => MAX_AGENT_TTL,
            WorkloadKind::User | WorkloadKind::Node | WorkloadKind::Coord => MAX_USER_TTL,
        }
    }
}

/// One SPIFFE ID in the `orblx.local` trust domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    kind: WorkloadKind,
    name: String,
    uri: String,
}

impl SpiffeId {
    pub fn user(name: &str) -> Result<Self, IdentityError> {
        Self::new(WorkloadKind::User, name)
    }

    pub fn agent(name: &str) -> Result<Self, IdentityError> {
        Self::new(WorkloadKind::Agent, name)
    }

    pub fn node(name: &str) -> Result<Self, IdentityError> {
        Self::new(WorkloadKind::Node, name)
    }

    pub fn coord(name: &str) -> Result<Self, IdentityError> {
        Self::new(WorkloadKind::Coord, name)
    }

    pub fn new(kind: WorkloadKind, name: &str) -> Result<Self, IdentityError> {
        if !valid_name(name) {
            return Err(IdentityError::SpiffeId);
        }
        let uri = format!("spiffe://{TRUST_DOMAIN}/{}/{name}", kind.as_str());
        Ok(Self {
            kind,
            name: name.to_string(),
            uri,
        })
    }

    /// Parse one canonical SPIFFE URI.
    pub fn parse(uri: &str) -> Result<Self, IdentityError> {
        let prefix = format!("spiffe://{TRUST_DOMAIN}/");
        let rest = uri.strip_prefix(&prefix).ok_or(IdentityError::SpiffeId)?;
        let (kind_text, name) = rest.split_once('/').ok_or(IdentityError::SpiffeId)?;
        let kind = match kind_text {
            "user" => WorkloadKind::User,
            "agent" => WorkloadKind::Agent,
            "node" => WorkloadKind::Node,
            "coord" => WorkloadKind::Coord,
            _ => return Err(IdentityError::SpiffeId),
        };
        let parsed = Self::new(kind, name)?;
        if parsed.uri != uri {
            return Err(IdentityError::SpiffeId);
        }
        Ok(parsed)
    }

    pub fn kind(&self) -> WorkloadKind {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn as_uri(&self) -> &str {
        &self.uri
    }
}

fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 || name == "." || name == ".." {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}
