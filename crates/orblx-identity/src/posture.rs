//! Named device posture rules for accept grants and SSH rules.
//!
//! `os` and `clientVersion` are self-reported on the node channel.
//! `nodeLock` and `lastSeen` are facts the coordinator stores.
//! A missing fact fails closed. This module adds no signature and no new key.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::policy::PolicyError;
use crate::spiffe::SpiffeId;

/// The most posture rules in one policy.
const MAX_RULES: usize = 32;
/// The most predicates in one posture rule.
const MAX_PREDICATES: usize = 8;
/// The most posture tests in one policy.
const MAX_TESTS: usize = 64;

const OS_TOKENS: [&str; 7] = [
    "linux", "macos", "windows", "freebsd", "openbsd", "ios", "android",
];

/// Facts for one node at one time.
///
/// `None` means the coordinator does not know the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureFacts {
    /// Self-reported operating system token.
    pub os: Option<String>,
    /// Self-reported client version. The check uses the leading numbers.
    pub client_version: Option<String>,
    /// `Some(true)` when a current node-lock key signed the node.
    pub node_lock_signed: Option<bool>,
    /// Seconds since the last authenticated node message.
    pub last_seen_secs: Option<u64>,
}

impl PostureFacts {
    /// Every fact is unknown. Each posture rule fails closed.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            os: None,
            client_version: None,
            node_lock_signed: None,
            last_seen_secs: None,
        }
    }
}

/// Why one posture rule failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureFailure {
    /// Posture rule name.
    pub rule: String,
    /// `os`, `clientVersion`, `nodeLock`, or `lastSeen`.
    pub attr: &'static str,
    /// `unknown` or `mismatch`.
    pub reason: &'static str,
}

/// One `postureTests` row in the policy file.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureTestFile {
    /// Posture rule name.
    pub name: String,
    /// Self-reported OS. Omit the field for an unknown OS.
    #[serde(default)]
    pub os: Option<String>,
    /// Self-reported client version. Omit the field for an unknown version.
    #[serde(default, rename = "clientVersion")]
    pub client_version: Option<String>,
    /// `signed`, `unsigned`, or omitted when the fact is unknown.
    #[serde(default, rename = "nodeLock")]
    pub node_lock: Option<String>,
    /// Age text such as `10s`. Omit the field for an unknown age.
    #[serde(default, rename = "lastSeen")]
    pub last_seen: Option<String>,
    /// `allow` or `deny`.
    pub action: String,
}

/// One inline posture result for `orblx policy test`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureAssertion {
    /// Posture rule name.
    pub rule: String,
    /// True when the test expects an allow.
    pub allow: bool,
}

impl PostureAssertion {
    /// Return one short result line.
    #[must_use]
    pub fn line(&self) -> String {
        let verb = if self.allow { "allow" } else { "deny" };
        format!("{verb} posture {}", self.rule)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Clone, PartialEq, Eq)]
enum Predicate {
    OsIn(Vec<String>),
    ClientAtLeast(Version),
    NodeLockSigned(bool),
    LastSeenWithin(u64),
}

impl Predicate {
    fn attr(&self) -> &'static str {
        match self {
            Self::OsIn(_) => "os",
            Self::ClientAtLeast(_) => "clientVersion",
            Self::NodeLockSigned(_) => "nodeLock",
            Self::LastSeenWithin(_) => "lastSeen",
        }
    }

    fn check(&self, facts: &PostureFacts) -> Result<(), &'static str> {
        match self {
            Self::OsIn(list) => match facts.os.as_deref() {
                None => Err("unknown"),
                Some(os) if list.iter().any(|item| item == os) => Ok(()),
                Some(_) => Err("mismatch"),
            },
            Self::ClientAtLeast(want) => {
                match facts.client_version.as_deref().and_then(parse_version) {
                    None => Err("unknown"),
                    Some(got) if got >= *want => Ok(()),
                    Some(_) => Err("mismatch"),
                }
            }
            Self::NodeLockSigned(want) => match facts.node_lock_signed {
                None => Err("unknown"),
                Some(got) if got == *want => Ok(()),
                Some(_) => Err("mismatch"),
            },
            Self::LastSeenWithin(limit) => match facts.last_seen_secs {
                None => Err("unknown"),
                Some(age) if age <= *limit => Ok(()),
                Some(_) => Err("mismatch"),
            },
        }
    }
}

#[derive(Clone)]
pub(crate) struct GrantRow {
    pub src: SpiffeId,
    pub dst: SpiffeId,
    pub proto: u8,
    pub port_start: u16,
    pub port_end: u16,
    pub names: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct SubnetRow {
    pub src: SpiffeId,
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    pub proto: u8,
    pub port_start: u16,
    pub port_end: u16,
    pub names: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct SshRow {
    pub src: SpiffeId,
    pub dst: SpiffeId,
    pub user: String,
    pub names: Vec<String>,
}

#[derive(Clone)]
struct StoredPostureTest {
    rule: String,
    facts: PostureFacts,
    allow: bool,
}

/// Compiled posture rules and the grants that name them.
#[derive(Clone)]
pub(crate) struct PosturePlan {
    rules: BTreeMap<String, Vec<Predicate>>,
    grants: Vec<GrantRow>,
    subnets: Vec<SubnetRow>,
    ssh: Vec<SshRow>,
    tests: Vec<StoredPostureTest>,
}

impl PosturePlan {
    pub(crate) fn empty() -> Self {
        Self {
            rules: BTreeMap::new(),
            grants: Vec::new(),
            subnets: Vec::new(),
            ssh: Vec::new(),
            tests: Vec::new(),
        }
    }

    pub(crate) fn len_rules(&self) -> usize {
        self.rules.len()
    }

    pub(crate) fn compile(
        defined: &BTreeMap<String, Vec<String>>,
        tests: &[PostureTestFile],
        grants: Vec<GrantRow>,
        subnets: Vec<SubnetRow>,
        ssh: Vec<SshRow>,
    ) -> Result<Self, PolicyError> {
        if defined.len() > MAX_RULES {
            return Err(PolicyError::new(format!(
                "The policy has more than {MAX_RULES} posture rules."
            )));
        }
        let mut rules = BTreeMap::new();
        for (name, lines) in defined {
            if !rule_name_ok(name) {
                return Err(PolicyError::new("The posture name is not valid."));
            }
            if lines.is_empty() || lines.len() > MAX_PREDICATES {
                return Err(PolicyError::new(
                    "The posture rule needs 1 to 8 predicates.",
                ));
            }
            let mut predicates = Vec::new();
            for line in lines {
                predicates.push(parse_predicate(line)?);
            }
            rules.insert(name.clone(), predicates);
        }
        check_names(&rules, grants.iter().map(|row| row.names.as_slice()))?;
        check_names(&rules, subnets.iter().map(|row| row.names.as_slice()))?;
        check_names(&rules, ssh.iter().map(|row| row.names.as_slice()))?;
        if tests.len() > MAX_TESTS {
            return Err(PolicyError::new(format!(
                "The policy has more than {MAX_TESTS} posture tests."
            )));
        }
        let mut stored = Vec::new();
        for test in tests {
            if !rules.contains_key(&test.name) {
                return Err(PolicyError::new("The posture test names an unknown rule."));
            }
            let allow = match test.action.as_str() {
                "allow" => true,
                "deny" => false,
                _ => {
                    return Err(PolicyError::new(
                        "The posture test action is allow or deny.",
                    ))
                }
            };
            stored.push(StoredPostureTest {
                rule: test.name.clone(),
                facts: facts_from_test(test)?,
                allow,
            });
        }
        Ok(Self {
            rules,
            grants,
            subnets,
            ssh,
            tests: stored,
        })
    }

    pub(crate) fn run_tests(&self) -> Result<(), PolicyError> {
        for test in &self.tests {
            let passed = self.rule_passes(&test.rule, &test.facts).is_ok();
            if passed != test.allow {
                let outcome = if passed { "allowed" } else { "denied" };
                let expect = if test.allow { "allow" } else { "deny" };
                return Err(PolicyError::new(format!(
                    "The posture test failed. The rule {} is {outcome}. The test expects an {expect}.",
                    test.rule
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn assertions(&self) -> Vec<PostureAssertion> {
        self.tests
            .iter()
            .map(|test| PostureAssertion {
                rule: test.rule.clone(),
                allow: test.allow,
            })
            .collect()
    }

    /// True when no posture row covers the flow, or one covering row passes.
    pub(crate) fn allows_grant(
        &self,
        src: &SpiffeId,
        dst: &SpiffeId,
        proto: u8,
        port_start: u16,
        port_end: u16,
        facts: &PostureFacts,
    ) -> bool {
        let rows: Vec<&GrantRow> = self
            .grants
            .iter()
            .filter(|row| {
                row.src == *src
                    && row.dst == *dst
                    && row.proto == proto
                    && ranges_overlap(row.port_start, row.port_end, port_start, port_end)
            })
            .collect();
        allows_rows(rows.iter().map(|row| row.names.as_slice()), |names| {
            self.names_pass(names, facts)
        })
    }

    pub(crate) fn allows_subnet(
        &self,
        src: &SpiffeId,
        prefix: Ipv4Addr,
        prefix_len: u8,
        proto: u8,
        ports: (u16, u16),
        facts: &PostureFacts,
    ) -> bool {
        let rows: Vec<&SubnetRow> = self
            .subnets
            .iter()
            .filter(|row| {
                row.src == *src
                    && row.prefix == prefix
                    && row.prefix_len == prefix_len
                    && row.proto == proto
                    && ranges_overlap(row.port_start, row.port_end, ports.0, ports.1)
            })
            .collect();
        allows_rows(rows.iter().map(|row| row.names.as_slice()), |names| {
            self.names_pass(names, facts)
        })
    }

    pub(crate) fn allows_reach(
        &self,
        src: &SpiffeId,
        dst: &SpiffeId,
        facts: &PostureFacts,
    ) -> bool {
        let rows: Vec<&GrantRow> = self
            .grants
            .iter()
            .filter(|row| row.src == *src && row.dst == *dst)
            .collect();
        allows_rows(rows.iter().map(|row| row.names.as_slice()), |names| {
            self.names_pass(names, facts)
        })
    }

    /// The first failing posture that blocks a ticket for `src`.
    ///
    /// A flow with one row that has no posture does not block the ticket.
    pub(crate) fn ticket_failure(
        &self,
        src: &SpiffeId,
        facts: &PostureFacts,
    ) -> Option<PostureFailure> {
        for row in &self.grants {
            if row.src != *src || row.names.is_empty() {
                continue;
            }
            let open = self.grants.iter().any(|other| {
                other.src == *src
                    && other.dst == row.dst
                    && other.proto == row.proto
                    && ranges_overlap(
                        other.port_start,
                        other.port_end,
                        row.port_start,
                        row.port_end,
                    )
                    && other.names.is_empty()
            });
            if open {
                continue;
            }
            if let Err(failure) = self.names_pass(&row.names, facts) {
                return Some(failure);
            }
        }
        for row in &self.subnets {
            if row.src != *src || row.names.is_empty() {
                continue;
            }
            let open = self.subnets.iter().any(|other| {
                other.src == *src
                    && other.prefix == row.prefix
                    && other.prefix_len == row.prefix_len
                    && other.proto == row.proto
                    && ranges_overlap(
                        other.port_start,
                        other.port_end,
                        row.port_start,
                        row.port_end,
                    )
                    && other.names.is_empty()
            });
            if open {
                continue;
            }
            if let Err(failure) = self.names_pass(&row.names, facts) {
                return Some(failure);
            }
        }
        for row in &self.ssh {
            if row.src != *src || row.names.is_empty() {
                continue;
            }
            let open = self.ssh.iter().any(|other| {
                other.src == *src
                    && other.dst == row.dst
                    && other.user == row.user
                    && other.names.is_empty()
            });
            if open {
                continue;
            }
            if let Err(failure) = self.names_pass(&row.names, facts) {
                return Some(failure);
            }
        }
        None
    }

    /// Stable text of the failing rule names. Empty means the node is in posture.
    ///
    /// A flow that also has a row with no posture is not a failure.
    pub(crate) fn block_key(&self, src: &SpiffeId, facts: &PostureFacts) -> String {
        let mut names = Vec::new();
        let mut push = |row_names: &[String]| {
            if let Err(failure) = self.names_pass(row_names, facts) {
                if !names.contains(&failure.rule) {
                    names.push(failure.rule);
                }
            }
        };
        for row in &self.grants {
            if row.src != *src || row.names.is_empty() {
                continue;
            }
            let open = self.grants.iter().any(|other| {
                other.src == *src
                    && other.dst == row.dst
                    && other.proto == row.proto
                    && ranges_overlap(
                        other.port_start,
                        other.port_end,
                        row.port_start,
                        row.port_end,
                    )
                    && other.names.is_empty()
            });
            if !open {
                push(&row.names);
            }
        }
        for row in &self.subnets {
            if row.src != *src || row.names.is_empty() {
                continue;
            }
            let open = self.subnets.iter().any(|other| {
                other.src == *src
                    && other.prefix == row.prefix
                    && other.prefix_len == row.prefix_len
                    && other.proto == row.proto
                    && ranges_overlap(
                        other.port_start,
                        other.port_end,
                        row.port_start,
                        row.port_end,
                    )
                    && other.names.is_empty()
            });
            if !open {
                push(&row.names);
            }
        }
        for row in &self.ssh {
            if row.src != *src || row.names.is_empty() {
                continue;
            }
            let open = self.ssh.iter().any(|other| {
                other.src == *src
                    && other.dst == row.dst
                    && other.user == row.user
                    && other.names.is_empty()
            });
            if !open {
                push(&row.names);
            }
        }
        names.sort();
        names.join(",")
    }

    fn rule_passes(&self, name: &str, facts: &PostureFacts) -> Result<(), PostureFailure> {
        let owned = name.to_string();
        self.names_pass(std::slice::from_ref(&owned), facts)
    }

    fn names_pass(&self, names: &[String], facts: &PostureFacts) -> Result<(), PostureFailure> {
        for name in names {
            let Some(predicates) = self.rules.get(name) else {
                return Err(PostureFailure {
                    rule: name.clone(),
                    attr: "os",
                    reason: "unknown",
                });
            };
            for predicate in predicates {
                if let Err(reason) = predicate.check(facts) {
                    return Err(PostureFailure {
                        rule: name.clone(),
                        attr: predicate.attr(),
                        reason,
                    });
                }
            }
        }
        Ok(())
    }
}

fn allows_rows<'a, I, F>(rows: I, mut pass: F) -> bool
where
    I: Iterator<Item = &'a [String]>,
    F: FnMut(&[String]) -> Result<(), PostureFailure>,
{
    let mut saw = false;
    for names in rows {
        saw = true;
        if names.is_empty() || pass(names).is_ok() {
            return true;
        }
    }
    !saw
}

fn ranges_overlap(left_start: u16, left_end: u16, right_start: u16, right_end: u16) -> bool {
    left_start <= right_end && right_start <= left_end
}

/// Check `srcPosture` names. An empty list means the rule has no posture.
pub(crate) fn posture_names(
    defined: &BTreeMap<String, Vec<String>>,
    listed: &[String],
) -> Result<Vec<String>, PolicyError> {
    if listed.is_empty() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for name in listed {
        if !rule_name_ok(name) || !defined.contains_key(name) {
            return Err(PolicyError::new("The posture rule is not known."));
        }
        if names.iter().any(|item| item == name) {
            return Err(PolicyError::new("The posture list repeats a rule."));
        }
        names.push(name.clone());
    }
    Ok(names)
}

fn check_names<'a, I>(rules: &BTreeMap<String, Vec<Predicate>>, rows: I) -> Result<(), PolicyError>
where
    I: Iterator<Item = &'a [String]>,
{
    for names in rows {
        for name in names {
            if !rules.contains_key(name) {
                return Err(PolicyError::new("The posture rule is not known."));
            }
        }
    }
    Ok(())
}

fn facts_from_test(test: &PostureTestFile) -> Result<PostureFacts, PolicyError> {
    let os = match test.os.as_deref() {
        None => None,
        Some(os) if os_token_ok(os) => Some(os.to_string()),
        Some(_) => return Err(PolicyError::new("The posture test OS is not valid.")),
    };
    let client_version = match test.client_version.as_deref() {
        None => None,
        Some(text) if parse_version(text).is_some() => Some(text.to_string()),
        Some(_) => {
            return Err(PolicyError::new(
                "The posture test client version is not valid.",
            ))
        }
    };
    let node_lock_signed = match test.node_lock.as_deref() {
        None => None,
        Some("signed") => Some(true),
        Some("unsigned") => Some(false),
        Some(_) => {
            return Err(PolicyError::new(
                "The posture test node lock value is not valid.",
            ))
        }
    };
    let last_seen_secs =
        match test.last_seen.as_deref() {
            None => None,
            Some(text) => Some(parse_age(text).ok_or_else(|| {
                PolicyError::new("The posture test last-seen value is not valid.")
            })?),
        };
    Ok(PostureFacts {
        os,
        client_version,
        node_lock_signed,
        last_seen_secs,
    })
}

fn parse_predicate(line: &str) -> Result<Predicate, PolicyError> {
    let text = line.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(rest) = text.strip_prefix("os == ") {
        return one_os(rest).map(|os| Predicate::OsIn(vec![os]));
    }
    if let Some(rest) = text.strip_prefix("os in ") {
        return Ok(Predicate::OsIn(os_list(rest)?));
    }
    if let Some(rest) = text.strip_prefix("clientVersion >= ") {
        let version = parse_version(rest)
            .ok_or_else(|| PolicyError::new("The posture client version is not valid."))?;
        return Ok(Predicate::ClientAtLeast(version));
    }
    if text == "nodeLock == signed" {
        return Ok(Predicate::NodeLockSigned(true));
    }
    if text == "nodeLock == unsigned" {
        return Ok(Predicate::NodeLockSigned(false));
    }
    if let Some(rest) = text.strip_prefix("lastSeen <= ") {
        let age = parse_age(rest)
            .ok_or_else(|| PolicyError::new("The posture last-seen limit is not valid."))?;
        return Ok(Predicate::LastSeenWithin(age));
    }
    Err(PolicyError::new("The posture predicate is not valid."))
}

fn one_os(text: &str) -> Result<String, PolicyError> {
    if os_token_ok(text) {
        Ok(text.to_string())
    } else {
        Err(PolicyError::new("The posture OS is not valid."))
    }
}

fn os_list(text: &str) -> Result<Vec<String>, PolicyError> {
    let inner = text
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
        .ok_or_else(|| PolicyError::new("The posture OS list is not valid."))?;
    if inner.trim().is_empty() {
        return Err(PolicyError::new("The posture OS list is empty."));
    }
    let mut list = Vec::new();
    for part in inner.split(',') {
        let os = one_os(part.trim())?;
        if list.contains(&os) {
            return Err(PolicyError::new("The posture OS list repeats a value."));
        }
        list.push(os);
    }
    Ok(list)
}

fn parse_age(text: &str) -> Option<u64> {
    let digits = text.strip_suffix('s').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn parse_version(text: &str) -> Option<Version> {
    let (major, minor, patch) = parse_version_parts(text)?;
    Some(Version {
        major,
        minor,
        patch,
    })
}

fn parse_version_parts(text: &str) -> Option<(u64, u64, u64)> {
    let head = text.split(['-', '+']).next()?;
    if head.is_empty() {
        return None;
    }
    let mut parts = head.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = match parts.next() {
        Some(part) => part.parse().ok()?,
        None => 0,
    };
    let patch = match parts.next() {
        Some(part) => part.parse().ok()?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

pub(crate) fn rule_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && name.len() <= 32
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
}

pub(crate) fn os_token_ok(text: &str) -> bool {
    OS_TOKENS.contains(&text)
}

/// Keep a self-reported OS token. Any other text is unknown.
#[must_use]
pub fn clean_os(text: &str) -> Option<String> {
    os_token_ok(text).then(|| text.to_string())
}

/// Keep a self-reported version. A text that has no leading numbers is unknown.
#[must_use]
pub fn clean_version(text: &str) -> Option<String> {
    if text.len() > 32 || parse_version(text).is_none() {
        return None;
    }
    Some(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_linux() -> PostureFacts {
        PostureFacts {
            os: Some("linux".to_string()),
            client_version: Some("0.1.0-rc.3-dev".to_string()),
            node_lock_signed: Some(true),
            last_seen_secs: Some(5),
        }
    }

    #[test]
    fn a_version_suffix_does_not_change_the_numbers() {
        assert_eq!(parse_version_parts("0.1.0-rc.3-dev"), Some((0, 1, 0)));
        assert!(
            parse_version_parts("0.1.0").unwrap() <= parse_version_parts("0.1.0-rc.3-dev").unwrap()
        );
        assert!(parse_version_parts("0.0.9").unwrap() < parse_version_parts("0.1.0").unwrap());
        assert!(parse_version_parts("nope").is_none());
    }

    #[test]
    fn an_unknown_fact_fails_closed() {
        let mut facts = facts_linux();
        facts.os = None;
        let predicate = parse_predicate("os in [linux, macos]").unwrap();
        assert_eq!(predicate.check(&facts), Err("unknown"));
        facts.os = Some("windows".to_string());
        assert_eq!(predicate.check(&facts), Err("mismatch"));
        facts.os = Some("macos".to_string());
        assert_eq!(predicate.check(&facts), Ok(()));
    }

    #[test]
    fn inline_posture_tests_fail_closed_and_cover_each_fact() {
        let bytes = br#"{
          "postures": {
            "desk": [
              "os in [linux, macos]",
              "clientVersion >= 0.1.0",
              "nodeLock == signed",
              "lastSeen <= 30s"
            ]
          },
          "postureTests": [
            {"name": "desk", "os": "linux", "clientVersion": "0.1.0-rc.3-dev", "nodeLock": "signed", "lastSeen": "5s", "action": "allow"},
            {"name": "desk", "os": "windows", "clientVersion": "0.1.0", "nodeLock": "signed", "lastSeen": "5s", "action": "deny"},
            {"name": "desk", "clientVersion": "0.1.0", "nodeLock": "signed", "lastSeen": "5s", "action": "deny"},
            {"name": "desk", "os": "linux", "nodeLock": "signed", "lastSeen": "5s", "action": "deny"},
            {"name": "desk", "os": "linux", "clientVersion": "0.1.0", "nodeLock": "unsigned", "lastSeen": "5s", "action": "deny"},
            {"name": "desk", "os": "linux", "clientVersion": "0.1.0", "nodeLock": "signed", "lastSeen": "31s", "action": "deny"}
          ],
          "groups": {"group:humans": ["spiffe://orblx.local/node/a"]},
          "acls": [{
            "action": "accept",
            "src": ["group:humans"],
            "proto": "tcp",
            "dst": ["spiffe://orblx.local/node/b:22"],
            "srcPosture": ["desk"]
          }],
          "ssh": [{
            "src": ["group:humans"],
            "dst": ["spiffe://orblx.local/node/b"],
            "users": ["root"],
            "checkPeriod": "30s",
            "srcPosture": ["desk"]
          }]
        }"#;
        let policy = crate::Policy::from_hujson(bytes).unwrap();
        let src = crate::SpiffeId::node("a").unwrap();
        let dst = crate::SpiffeId::node("b").unwrap();
        let good = facts_linux();
        assert!(policy.posture_allows_grant(&src, &dst, 6, 22, 22, &good));
        assert!(policy.posture_ticket_failure(&src, &good).is_none());
        assert!(policy.posture_block_key(&src, &good).is_empty());
        let mut unknown = good.clone();
        unknown.os = None;
        assert!(!policy.posture_allows_grant(&src, &dst, 6, 22, 22, &unknown));
        let failure = policy.posture_ticket_failure(&src, &unknown).unwrap();
        assert_eq!(failure.attr, "os");
        assert_eq!(failure.reason, "unknown");
        assert_eq!(policy.posture_assertions().len(), 6);
        let missing = br#"{"acls":[{"action":"accept","src":["spiffe://orblx.local/node/a"],"proto":"tcp","dst":["spiffe://orblx.local/node/b:22"],"srcPosture":["missing"]}]}"#;
        assert!(crate::Policy::from_hujson(missing).is_err());
    }

    #[test]
    fn node_lock_and_last_seen_use_coordinator_facts() {
        let mut facts = facts_linux();
        let signed = parse_predicate("nodeLock == signed").unwrap();
        assert_eq!(signed.check(&facts), Ok(()));
        facts.node_lock_signed = Some(false);
        assert_eq!(signed.check(&facts), Err("mismatch"));
        facts.node_lock_signed = None;
        assert_eq!(signed.check(&facts), Err("unknown"));
        let age = parse_predicate("lastSeen <= 30s").unwrap();
        facts.last_seen_secs = Some(30);
        assert_eq!(age.check(&facts), Ok(()));
        facts.last_seen_secs = Some(31);
        assert_eq!(age.check(&facts), Err("mismatch"));
        facts.last_seen_secs = None;
        assert_eq!(age.check(&facts), Err("unknown"));
    }
}
