//! HuJSON policy for groups, tags, receiver grants, subnet route approval, and SSH.
//!
//! The file is JSON with `//` comments, `/* */` comments, and trailing commas.
//! A rule names a source, a destination, and a port.
//! The default is deny.
//! An agent source needs one host, one protocol, and one port.
//! A human source may use a group, a tag, and a port range.
//! `ssh` names a source, a destination, the login users, and a check period.
//! An agent SSH source needs one destination and one user.
//! `tests` lists allow and deny assertions.
//! `sshTests` lists SSH allow and deny assertions.
//! A failed assertion rejects the file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::Deserialize;

use crate::spiffe::{SpiffeId, WorkloadKind};

const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_GRANTS: usize = 4096;
const MAX_TEST_PORTS: usize = 128;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// One policy did not load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    sentence: String,
}

impl PolicyError {
    fn new(sentence: impl Into<String>) -> Self {
        Self {
            sentence: sentence.into(),
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.sentence)
    }
}

impl std::error::Error for PolicyError {}

/// One allow or deny assertion from a loaded policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAssertion {
    /// Source SPIFFE ID.
    pub src: String,
    /// Destination SPIFFE ID.
    pub dst: String,
    /// IP protocol number. TCP is 6. UDP is 17.
    pub proto: u8,
    /// Destination port.
    pub port: u16,
    /// True when the policy allows the flow.
    pub allow: bool,
}

impl PolicyAssertion {
    /// Return one short result line.
    #[must_use]
    pub fn line(&self) -> String {
        let verb = if self.allow { "allow" } else { "deny" };
        format!(
            "{verb} {} {} {} {}",
            self.src,
            proto_name(self.proto),
            self.dst,
            self.port
        )
    }
}

/// One grant row for the node that receives the packet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverGrant {
    /// Source SPIFFE ID.
    pub src: String,
    /// IP protocol number. TCP is 6. UDP is 17.
    pub proto: u8,
    /// First destination port. The value is inclusive.
    pub port_start: u16,
    /// Last destination port. The value is inclusive.
    pub port_end: u16,
}

/// The allow set for one receiving node.
///
/// The coordinator signs this document with the netmap key.
/// The receiver permits a packet only when one grant matches.
/// `reach` lists the peers this node may reach.
/// The DNS responder reads that list from this same document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverGrants {
    /// Document version. The value is 1.
    pub version: u32,
    /// Receiver SPIFFE ID.
    pub receiver: String,
    /// Allow rows for this receiver.
    pub grants: Vec<ReceiverGrant>,
    /// Destination SPIFFE IDs this node may reach.
    ///
    /// The coordinator fills the list from the same policy that builds `grants`.
    /// An empty list means this node can reach no peer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reach: Vec<String>,
}

impl ReceiverGrants {
    /// Check the document.
    pub fn check(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::new(
                "The grant document version is not version 1.",
            ));
        }
        let _ = SpiffeId::parse(&self.receiver)
            .map_err(|_| PolicyError::new("The grant receiver SPIFFE ID is not valid."))?;
        for grant in &self.grants {
            let _ = SpiffeId::parse(&grant.src)
                .map_err(|_| PolicyError::new("The grant source SPIFFE ID is not valid."))?;
            if grant.proto != PROTO_TCP && grant.proto != PROTO_UDP {
                return Err(PolicyError::new("The grant protocol is not TCP or UDP."));
            }
            if grant.port_start == 0 || grant.port_start > grant.port_end {
                return Err(PolicyError::new("The grant port range is not valid."));
            }
        }
        for (index, dst) in self.reach.iter().enumerate() {
            let _ = SpiffeId::parse(dst)
                .map_err(|_| PolicyError::new("The grant reach SPIFFE ID is not valid."))?;
            if self.reach[..index].iter().any(|item| item == dst) {
                return Err(PolicyError::new(
                    "The grant reach list repeats a SPIFFE ID.",
                ));
            }
        }
        Ok(())
    }

    /// Return true when one grant allows the source, protocol, and port.
    #[must_use]
    pub fn permits(&self, src: &SpiffeId, proto: u8, port: u16) -> bool {
        self.grants.iter().any(|grant| {
            grant.src == src.as_uri()
                && grant.proto == proto
                && port >= grant.port_start
                && port <= grant.port_end
        })
    }

    /// Return true when this node may reach `dst`.
    ///
    /// The check uses the `reach` list.
    /// The packet filter uses [`ReceiverGrants::permits`].
    #[must_use]
    pub fn reaches(&self, dst: &SpiffeId) -> bool {
        self.reach.iter().any(|item| item == dst.as_uri())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CompiledGrant {
    src: SpiffeId,
    dst: SpiffeId,
    proto: u8,
    port_start: u16,
    port_end: u16,
}

#[derive(Clone)]
struct StoredTest {
    src: SpiffeId,
    proto: u8,
    accept: Vec<(SpiffeId, u16)>,
    deny: Vec<(SpiffeId, u16)>,
}

#[derive(Clone, PartialEq, Eq)]
struct RouteRule {
    src: SpiffeId,
    prefix: Ipv4Addr,
    prefix_len: u8,
    exact: bool,
}

/// One SSH allow or deny assertion from a loaded policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAssertion {
    /// Source SPIFFE ID.
    pub src: String,
    /// Destination SPIFFE ID.
    pub dst: String,
    /// Login name.
    pub user: String,
    /// True when the policy allows the session.
    pub allow: bool,
    /// Check period in seconds.
    ///
    /// A deny assertion uses 0.
    pub check_period: u64,
}

impl SshAssertion {
    /// Return one short result line.
    #[must_use]
    pub fn line(&self) -> String {
        let verb = if self.allow { "allow" } else { "deny" };
        format!(
            "{verb} ssh {} {} {} {}",
            self.src, self.user, self.dst, self.check_period
        )
    }
}

/// A loaded policy whose inline tests passed.
#[derive(Clone)]
pub struct Policy {
    grants: Vec<CompiledGrant>,
    tests: Vec<StoredTest>,
    routes: Vec<RouteRule>,
    ssh: Vec<SshGrant>,
    ssh_tests: Vec<StoredSshTest>,
}

#[derive(Clone, PartialEq, Eq)]
struct SshGrant {
    src: SpiffeId,
    dst: SpiffeId,
    user: String,
    check_period: u64,
}

#[derive(Clone)]
struct StoredSshTest {
    src: SpiffeId,
    dst: SpiffeId,
    user: String,
    allow: bool,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Policy")
            .field("grants", &self.grants.len())
            .field("tests", &self.tests.len())
            .field("routes", &self.routes.len())
            .field("ssh", &self.ssh.len())
            .finish()
    }
}

impl Policy {
    /// A policy with no grants.
    ///
    /// Every flow is denied.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            grants: Vec::new(),
            tests: Vec::new(),
            routes: Vec::new(),
            ssh: Vec::new(),
            ssh_tests: Vec::new(),
        }
    }

    /// Read one HuJSON policy file and run its tests.
    pub fn from_path(path: &Path) -> Result<Self, PolicyError> {
        let bytes =
            fs::read(path).map_err(|_| PolicyError::new("The policy file did not open."))?;
        Self::from_hujson(&bytes)
    }

    /// Parse HuJSON bytes and run the inline tests.
    pub fn from_hujson(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::new("The policy file is too large."));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| PolicyError::new("The policy file is not UTF-8."))?;
        let json = hujson_to_json(text)?;
        let file: PolicyFile = serde_json::from_str(&json).map_err(|err| {
            let detail = err
                .to_string()
                .chars()
                .filter(|ch| !ch.is_control())
                .take(120)
                .collect::<String>();
            PolicyError::new(format!("The policy file is not valid. {detail}"))
        })?;
        let policy = compile(&file)?;
        policy.run_tests()?;
        Ok(policy)
    }

    /// Return true when a grant allows the flow.
    #[must_use]
    pub fn allows(&self, src: &SpiffeId, dst: &SpiffeId, proto: u8, port: u16) -> bool {
        self.grants.iter().any(|grant| {
            grant.src == *src
                && grant.dst == *dst
                && grant.proto == proto
                && port >= grant.port_start
                && port <= grant.port_end
        })
    }

    /// Build the signed body for one receiving node.
    ///
    /// `grants` lists sources that may reach this node.
    /// `reach` lists destinations this node may reach.
    /// Both lists come from this policy.
    #[must_use]
    pub fn receiver_grants(&self, receiver: &SpiffeId) -> ReceiverGrants {
        let mut grants = Vec::new();
        let mut reach = BTreeSet::new();
        for grant in &self.grants {
            if grant.src == *receiver {
                reach.insert(grant.dst.as_uri().to_string());
            }
            if grant.dst != *receiver {
                continue;
            }
            grants.push(ReceiverGrant {
                src: grant.src.as_uri().to_string(),
                proto: grant.proto,
                port_start: grant.port_start,
                port_end: grant.port_end,
            });
        }
        ReceiverGrants {
            version: 1,
            receiver: receiver.as_uri().to_string(),
            grants,
            reach: reach.into_iter().collect(),
        }
    }

    /// Return true when the policy approves `cidr` for `node`.
    ///
    /// `autoApprovers` approves the listed prefix and a longer prefix inside it.
    /// `routeApprovals` approves one exact CIDR.
    /// `0.0.0.0/0` is an exit route. This function returns false for that prefix.
    #[must_use]
    pub fn approves_route(&self, node: &SpiffeId, cidr: &str) -> bool {
        let Ok((prefix, prefix_len)) = parse_route_cidr(cidr) else {
            return false;
        };
        if prefix_len == 0 {
            return false;
        }
        self.routes
            .iter()
            .any(|rule| rule.src == *node && route_matches(rule, prefix, prefix_len))
    }

    /// Return the inline assertions.
    ///
    /// The assertions passed when [`Policy::from_hujson`] returned this value.
    #[must_use]
    pub fn assertions(&self) -> Vec<PolicyAssertion> {
        let mut lines = Vec::new();
        for test in &self.tests {
            for (dst, port) in &test.accept {
                lines.push(PolicyAssertion {
                    src: test.src.as_uri().to_string(),
                    dst: dst.as_uri().to_string(),
                    proto: test.proto,
                    port: *port,
                    allow: true,
                });
            }
            for (dst, port) in &test.deny {
                lines.push(PolicyAssertion {
                    src: test.src.as_uri().to_string(),
                    dst: dst.as_uri().to_string(),
                    proto: test.proto,
                    port: *port,
                    allow: false,
                });
            }
        }
        lines
    }

    /// Return the SSH check period in seconds when the session is allowed.
    ///
    /// The default is deny.
    /// Two matching rules use the shorter period.
    #[must_use]
    pub fn ssh_check_period(&self, src: &SpiffeId, dst: &SpiffeId, user: &str) -> Option<u64> {
        self.ssh
            .iter()
            .filter(|grant| grant.src == *src && grant.dst == *dst && grant.user == user)
            .map(|grant| grant.check_period)
            .min()
    }

    /// Return the inline SSH assertions.
    ///
    /// The assertions passed when [`Policy::from_hujson`] returned this value.
    #[must_use]
    pub fn ssh_assertions(&self) -> Vec<SshAssertion> {
        self.ssh_tests
            .iter()
            .map(|test| {
                let check_period = if test.allow {
                    self.ssh_check_period(&test.src, &test.dst, &test.user)
                        .unwrap_or(0)
                } else {
                    0
                };
                SshAssertion {
                    src: test.src.as_uri().to_string(),
                    dst: test.dst.as_uri().to_string(),
                    user: test.user.clone(),
                    allow: test.allow,
                    check_period,
                }
            })
            .collect()
    }
}

impl Policy {
    fn run_tests(&self) -> Result<(), PolicyError> {
        for test in &self.tests {
            for (dst, port) in &test.accept {
                if !self.allows(&test.src, dst, test.proto, *port) {
                    return Err(test_failure(&test.src, dst, test.proto, *port, true));
                }
            }
            for (dst, port) in &test.deny {
                if self.allows(&test.src, dst, test.proto, *port) {
                    return Err(test_failure(&test.src, dst, test.proto, *port, false));
                }
            }
        }
        for test in &self.ssh_tests {
            let allowed = self
                .ssh_check_period(&test.src, &test.dst, &test.user)
                .is_some();
            if allowed != test.allow {
                return Err(ssh_test_failure(
                    &test.src, &test.dst, &test.user, test.allow,
                ));
            }
        }
        Ok(())
    }
}

fn ssh_test_failure(src: &SpiffeId, dst: &SpiffeId, user: &str, expect_allow: bool) -> PolicyError {
    let outcome = if expect_allow { "denied" } else { "allowed" };
    let expect = if expect_allow { "allow" } else { "deny" };
    PolicyError::new(format!(
        "The SSH policy test failed. The source {} to {} as user {} is {outcome}. The test expects an {expect}.",
        src.as_uri(),
        dst.as_uri(),
        safe_label(user)
    ))
}

fn test_failure(
    src: &SpiffeId,
    dst: &SpiffeId,
    proto: u8,
    port: u16,
    expect_allow: bool,
) -> PolicyError {
    let outcome = if expect_allow { "denied" } else { "allowed" };
    let expect = if expect_allow { "allow" } else { "deny" };
    PolicyError::new(format!(
        "The policy test failed. The source {} to {} on {} port {port} is {outcome}. The test expects an {expect}.",
        src.as_uri(),
        dst.as_uri(),
        proto_name(proto)
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    tags: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "tagOwners")]
    tag_owners: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    acls: Vec<AclFile>,
    #[serde(default, rename = "autoApprovers")]
    auto_approvers: AutoApproversFile,
    #[serde(default, rename = "routeApprovals")]
    route_approvals: Vec<RouteApprovalFile>,
    #[serde(default)]
    tests: Vec<TestFile>,
    #[serde(default)]
    ssh: Vec<SshRuleFile>,
    #[serde(default, rename = "sshTests")]
    ssh_tests: Vec<SshTestFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshRuleFile {
    src: Vec<String>,
    dst: Vec<String>,
    users: Vec<String>,
    #[serde(rename = "checkPeriod")]
    check_period: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshTestFile {
    src: String,
    dst: String,
    user: String,
    action: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AutoApproversFile {
    #[serde(default)]
    routes: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteApprovalFile {
    src: Vec<String>,
    routes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AclFile {
    action: String,
    src: Vec<String>,
    dst: Vec<String>,
    #[serde(default)]
    proto: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestFile {
    src: String,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    accept: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

struct Catalog {
    groups: BTreeMap<String, Vec<SpiffeId>>,
    tags: BTreeMap<String, Vec<SpiffeId>>,
}

fn compile(file: &PolicyFile) -> Result<Policy, PolicyError> {
    let catalog = catalog(file)?;
    let mut grants = Vec::new();
    for rule in &file.acls {
        if rule.action != "accept" {
            return Err(PolicyError::new(
                "The policy action is accept. Other actions are rejected.",
            ));
        }
        if rule.src.is_empty() || rule.dst.is_empty() {
            return Err(PolicyError::new(
                "The policy rule needs a source and a destination.",
            ));
        }
        let protos = match &rule.proto {
            Some(text) => vec![parse_proto(text)?],
            None => vec![PROTO_TCP, PROTO_UDP],
        };
        for src_text in &rule.src {
            let sources = expand(&catalog, src_text)?;
            for dst_text in &rule.dst {
                let (selector, port_text) = split_target(dst_text)?;
                let dests = expand(&catalog, selector)?;
                let ranges = parse_port_spec(port_text)?;
                for src in &sources {
                    for dst in &dests {
                        for proto in &protos {
                            for (start, end) in &ranges {
                                let agent_broad = dests.len() != 1
                                    || ranges.len() != 1
                                    || rule.dst.len() != 1
                                    || start != end
                                    || rule.proto.is_none();
                                if src.kind() == WorkloadKind::Agent && agent_broad {
                                    return Err(PolicyError::new(format!(
                                        "The agent {} needs one host, one protocol, and one port.",
                                        src.as_uri()
                                    )));
                                }
                                if grants.len() >= MAX_GRANTS {
                                    return Err(PolicyError::new(
                                        "The policy has too many grants.",
                                    ));
                                }
                                grants.push(CompiledGrant {
                                    src: src.clone(),
                                    dst: dst.clone(),
                                    proto: *proto,
                                    port_start: *start,
                                    port_end: *end,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    grants.sort_by(|left, right| {
        (
            left.src.as_uri(),
            left.dst.as_uri(),
            left.proto,
            left.port_start,
            left.port_end,
        )
            .cmp(&(
                right.src.as_uri(),
                right.dst.as_uri(),
                right.proto,
                right.port_start,
                right.port_end,
            ))
    });
    grants.dedup();
    let mut tests = Vec::new();
    for test in &file.tests {
        tests.push(compile_test(&catalog, test)?);
    }
    let routes = compile_routes(&catalog, file)?;
    let ssh = compile_ssh(&catalog, &file.ssh)?;
    let mut ssh_tests = Vec::new();
    for test in &file.ssh_tests {
        ssh_tests.push(compile_ssh_test(&catalog, test)?);
    }
    Ok(Policy {
        grants,
        tests,
        routes,
        ssh,
        ssh_tests,
    })
}

fn compile_ssh(catalog: &Catalog, rules: &[SshRuleFile]) -> Result<Vec<SshGrant>, PolicyError> {
    let mut grants = Vec::new();
    for rule in rules {
        if rule.src.is_empty() || rule.dst.is_empty() || rule.users.is_empty() {
            return Err(PolicyError::new(
                "The SSH rule needs a source, a destination, a user, and a check period.",
            ));
        }
        let period = parse_check_period(&rule.check_period)?;
        let mut users = Vec::new();
        for user in &rule.users {
            let name = parse_ssh_user(user)?;
            if users.iter().any(|item: &String| item == &name) {
                return Err(PolicyError::new("The SSH rule repeats a user."));
            }
            users.push(name);
        }
        for src_text in &rule.src {
            let sources = expand(catalog, src_text)?;
            for dst_text in &rule.dst {
                let dests = expand(catalog, dst_text)?;
                for src in &sources {
                    let agent_broad = src.kind() == WorkloadKind::Agent
                        && (sources.len() != 1
                            || dests.len() != 1
                            || users.len() != 1
                            || rule.src.len() != 1
                            || rule.dst.len() != 1
                            || rule.users.len() != 1);
                    if agent_broad {
                        return Err(PolicyError::new(format!(
                            "The agent {} needs one host and one user.",
                            src.as_uri()
                        )));
                    }
                    for dst in &dests {
                        for user in &users {
                            if grants.len() >= MAX_GRANTS {
                                return Err(PolicyError::new("The policy has too many grants."));
                            }
                            grants.push(SshGrant {
                                src: src.clone(),
                                dst: dst.clone(),
                                user: user.clone(),
                                check_period: period,
                            });
                        }
                    }
                }
            }
        }
    }
    grants.sort_by(|left, right| {
        (
            left.src.as_uri(),
            left.dst.as_uri(),
            left.user.as_str(),
            left.check_period,
        )
            .cmp(&(
                right.src.as_uri(),
                right.dst.as_uri(),
                right.user.as_str(),
                right.check_period,
            ))
    });
    grants.dedup();
    Ok(grants)
}

fn compile_ssh_test(catalog: &Catalog, test: &SshTestFile) -> Result<StoredSshTest, PolicyError> {
    let allow = match test.action.as_str() {
        "accept" => true,
        "deny" => false,
        _ => {
            return Err(PolicyError::new(
                "The SSH policy test action is accept or deny.",
            ))
        }
    };
    let user = parse_ssh_user(&test.user)?;
    let sources = expand(catalog, &test.src)?;
    let dests = expand(catalog, &test.dst)?;
    let src = one_ssh_id(&sources, "source")?;
    let dst = one_ssh_id(&dests, "destination")?;
    Ok(StoredSshTest {
        src,
        dst,
        user,
        allow,
    })
}

fn one_ssh_id(ids: &[SpiffeId], role: &str) -> Result<SpiffeId, PolicyError> {
    if ids.len() != 1 {
        return Err(PolicyError::new(format!(
            "The SSH policy test {role} names one SPIFFE ID."
        )));
    }
    Ok(ids[0].clone())
}

fn parse_ssh_user(text: &str) -> Result<String, PolicyError> {
    let bytes = text.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'_'
        });
    if !ok {
        return Err(PolicyError::new(format!(
            "The SSH user {} is not valid.",
            safe_label(text)
        )));
    }
    Ok(text.to_string())
}

fn parse_check_period(text: &str) -> Result<u64, PolicyError> {
    let (number, unit) = text
        .strip_suffix('s')
        .map(|number| (number, 1u64))
        .or_else(|| text.strip_suffix('m').map(|number| (number, 60u64)))
        .ok_or_else(|| PolicyError::new("The SSH check period is not valid."))?;
    if number.is_empty()
        || (number.len() > 1 && number.starts_with('0'))
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PolicyError::new("The SSH check period is not valid."));
    }
    let value: u64 = number
        .parse()
        .map_err(|_| PolicyError::new("The SSH check period is not valid."))?;
    let seconds = value
        .checked_mul(unit)
        .ok_or_else(|| PolicyError::new("The SSH check period is not valid."))?;
    if seconds == 0 || seconds > 24 * 60 * 60 {
        return Err(PolicyError::new("The SSH check period is not valid."));
    }
    Ok(seconds)
}

fn compile_routes(catalog: &Catalog, file: &PolicyFile) -> Result<Vec<RouteRule>, PolicyError> {
    let mut routes = Vec::new();
    for (cidr, selectors) in &file.auto_approvers.routes {
        push_route_rules(catalog, &mut routes, cidr, selectors, false)?;
    }
    for approval in &file.route_approvals {
        if approval.src.is_empty() || approval.routes.is_empty() {
            return Err(PolicyError::new(
                "The route approval needs a source and a route.",
            ));
        }
        for cidr in &approval.routes {
            push_route_rules(catalog, &mut routes, cidr, &approval.src, true)?;
        }
    }
    routes.sort_by(|left, right| {
        (
            left.src.as_uri(),
            left.prefix_len,
            u32::from(left.prefix),
            left.exact,
        )
            .cmp(&(
                right.src.as_uri(),
                right.prefix_len,
                u32::from(right.prefix),
                right.exact,
            ))
    });
    routes.dedup();
    Ok(routes)
}

fn push_route_rules(
    catalog: &Catalog,
    routes: &mut Vec<RouteRule>,
    cidr: &str,
    selectors: &[String],
    exact: bool,
) -> Result<(), PolicyError> {
    if selectors.is_empty() {
        return Err(PolicyError::new("The route approval needs a source."));
    }
    let (prefix, prefix_len) = parse_route_cidr(cidr)
        .map_err(|_| PolicyError::new(format!("The route {} is not valid.", safe_label(cidr))))?;
    if prefix_len == 0 {
        return Err(PolicyError::new("The route 0.0.0.0/0 is an exit route."));
    }
    for selector in selectors {
        for src in expand(catalog, selector)? {
            if routes.len() >= MAX_GRANTS {
                return Err(PolicyError::new("The policy has too many grants."));
            }
            routes.push(RouteRule {
                src,
                prefix,
                prefix_len,
                exact,
            });
        }
    }
    Ok(())
}

fn route_matches(rule: &RouteRule, prefix: Ipv4Addr, prefix_len: u8) -> bool {
    if rule.exact {
        return rule.prefix == prefix && rule.prefix_len == prefix_len;
    }
    if prefix_len < rule.prefix_len {
        return false;
    }
    let mask = ipv4_mask(rule.prefix_len);
    u32::from(prefix) & mask == u32::from(rule.prefix)
}

fn parse_route_cidr(text: &str) -> Result<(Ipv4Addr, u8), ()> {
    let (addr, prefix_text) = text.split_once('/').ok_or(())?;
    if prefix_text.is_empty()
        || (prefix_text.len() > 1 && prefix_text.starts_with('0'))
        || !prefix_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(());
    }
    let prefix_len: u32 = prefix_text.parse().map_err(|_| ())?;
    if prefix_len > 32 {
        return Err(());
    }
    let prefix_len = u8::try_from(prefix_len).map_err(|_| ())?;
    let ip = addr.parse::<Ipv4Addr>().map_err(|_| ())?;
    if u32::from(ip) & !ipv4_mask(prefix_len) != 0 {
        return Err(());
    }
    Ok((ip, prefix_len))
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn compile_test(catalog: &Catalog, test: &TestFile) -> Result<StoredTest, PolicyError> {
    if test.accept.is_empty() && test.deny.is_empty() {
        return Err(PolicyError::new(
            "The policy test needs an allow or a deny.",
        ));
    }
    let src = SpiffeId::parse(&test.src)
        .map_err(|_| PolicyError::new("The policy test source SPIFFE ID is not valid."))?;
    let proto = match &test.proto {
        Some(text) => parse_proto(text)?,
        None => PROTO_TCP,
    };
    let accept = expand_test_targets(catalog, &test.accept)?;
    let deny = expand_test_targets(catalog, &test.deny)?;
    for left in &accept {
        if deny.contains(left) {
            return Err(PolicyError::new(
                "The policy test lists one target as allow and deny.",
            ));
        }
    }
    Ok(StoredTest {
        src,
        proto,
        accept,
        deny,
    })
}

fn expand_test_targets(
    catalog: &Catalog,
    targets: &[String],
) -> Result<Vec<(SpiffeId, u16)>, PolicyError> {
    let mut out = Vec::new();
    for target in targets {
        let (selector, port_text) = split_target(target)?;
        let dests = expand(catalog, selector)?;
        let ranges = parse_port_spec(port_text)?;
        for dst in dests {
            for (start, end) in &ranges {
                let width = u32::from(*end) - u32::from(*start) + 1;
                if width > MAX_TEST_PORTS as u32 {
                    return Err(PolicyError::new("The policy test port range is too wide."));
                }
                for port in *start..=*end {
                    if out.len() >= MAX_TEST_PORTS {
                        return Err(PolicyError::new("The policy test has too many ports."));
                    }
                    out.push((dst.clone(), port));
                }
            }
        }
    }
    Ok(out)
}

fn catalog(file: &PolicyFile) -> Result<Catalog, PolicyError> {
    let mut groups = BTreeMap::new();
    for (name, members) in &file.groups {
        check_selector_name("group:", name)?;
        if members.is_empty() {
            return Err(PolicyError::new(format!("The group {name} has no member.")));
        }
        let mut ids = Vec::new();
        for member in members {
            ids.push(require_spiffe(member)?);
        }
        groups.insert(name.clone(), ids);
    }
    let mut tags = BTreeMap::new();
    for (name, members) in &file.tags {
        check_selector_name("tag:", name)?;
        if members.is_empty() {
            return Err(PolicyError::new(format!("The tag {name} has no member.")));
        }
        let mut ids = Vec::new();
        for member in members {
            ids.push(require_spiffe(member)?);
        }
        tags.insert(name.clone(), ids);
    }
    let catalog = Catalog { groups, tags };
    for (name, owners) in &file.tag_owners {
        check_selector_name("tag:", name)?;
        if !catalog.tags.contains_key(name) {
            return Err(PolicyError::new(format!(
                "The tag owner entry {name} has no tag."
            )));
        }
        if owners.is_empty() {
            return Err(PolicyError::new(format!("The tag {name} has no owner.")));
        }
        for owner in owners {
            let ids = expand(&catalog, owner)?;
            if ids.is_empty() {
                return Err(PolicyError::new(format!("The tag {name} has no owner.")));
            }
        }
    }
    for name in catalog.tags.keys() {
        if !file.tag_owners.contains_key(name) {
            return Err(PolicyError::new(format!("The tag {name} has no owner.")));
        }
    }
    Ok(catalog)
}

fn expand(catalog: &Catalog, selector: &str) -> Result<Vec<SpiffeId>, PolicyError> {
    if let Some(name) = selector.strip_prefix("group:") {
        let key = format!("group:{name}");
        return catalog
            .groups
            .get(&key)
            .cloned()
            .ok_or_else(|| PolicyError::new(format!("The group {key} is not defined.")));
    }
    if let Some(name) = selector.strip_prefix("tag:") {
        let key = format!("tag:{name}");
        return catalog
            .tags
            .get(&key)
            .cloned()
            .ok_or_else(|| PolicyError::new(format!("The tag {key} is not defined.")));
    }
    if selector.starts_with("spiffe://") {
        return Ok(vec![require_spiffe(selector)?]);
    }
    Err(PolicyError::new(format!(
        "The policy selector {} is not valid.",
        safe_label(selector)
    )))
}

fn require_spiffe(text: &str) -> Result<SpiffeId, PolicyError> {
    SpiffeId::parse(text)
        .map_err(|_| PolicyError::new(format!("The SPIFFE ID {} is not valid.", safe_label(text))))
}

fn check_selector_name(prefix: &str, name: &str) -> Result<(), PolicyError> {
    let Some(label) = name.strip_prefix(prefix) else {
        return Err(PolicyError::new(format!(
            "The name {} is not valid.",
            safe_label(name)
        )));
    };
    if !valid_label(label) {
        return Err(PolicyError::new(format!(
            "The name {} is not valid.",
            safe_label(name)
        )));
    }
    Ok(())
}

fn valid_label(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(ch) if ch.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    text.len() <= 63 && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn safe_label(text: &str) -> String {
    let trimmed: String = text
        .chars()
        .filter(|ch| !ch.is_control())
        .take(180)
        .collect();
    if trimmed.contains("ge1.") || trimmed.contains("PRIVATE") || trimmed.contains("BEGIN ") {
        return "a selector".to_string();
    }
    trimmed
}

fn parse_proto(text: &str) -> Result<u8, PolicyError> {
    match text {
        "tcp" => Ok(PROTO_TCP),
        "udp" => Ok(PROTO_UDP),
        _ => Err(PolicyError::new("The policy protocol is tcp or udp.")),
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        _ => "other",
    }
}

fn split_target(text: &str) -> Result<(&str, &str), PolicyError> {
    let bytes = text.as_bytes();
    let mut index = bytes.len();
    while index > 0 {
        index -= 1;
        if bytes[index] != b':' {
            continue;
        }
        let port = &text[index + 1..];
        if index > 0 && is_port_spec(port) {
            return Ok((&text[..index], port));
        }
    }
    Err(PolicyError::new("The policy destination needs a port."))
}

fn is_port_spec(text: &str) -> bool {
    if text == "*" {
        return true;
    }
    if text.is_empty() {
        return false;
    }
    text.split(',').all(|part| match part.split_once('-') {
        Some((left, right)) => match (parse_port(left), parse_port(right)) {
            (Ok(start), Ok(end)) => start <= end,
            _ => false,
        },
        None => parse_port(part).is_ok(),
    })
}

fn parse_port_spec(text: &str) -> Result<Vec<(u16, u16)>, PolicyError> {
    if text == "*" {
        return Ok(vec![(1, 65535)]);
    }
    let mut ranges = Vec::new();
    for part in text.split(',') {
        if let Some((left, right)) = part.split_once('-') {
            let start =
                parse_port(left).map_err(|_| PolicyError::new("The policy port is not valid."))?;
            let end =
                parse_port(right).map_err(|_| PolicyError::new("The policy port is not valid."))?;
            if start > end {
                return Err(PolicyError::new("The policy port range is not valid."));
            }
            ranges.push((start, end));
        } else {
            let port =
                parse_port(part).map_err(|_| PolicyError::new("The policy port is not valid."))?;
            ranges.push((port, port));
        }
    }
    if ranges.is_empty() {
        return Err(PolicyError::new("The policy destination needs a port."));
    }
    Ok(ranges)
}

fn parse_port(text: &str) -> Result<u16, ()> {
    if text.is_empty()
        || text.len() > 5
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(());
    }
    let value: u32 = text.parse().map_err(|_| ())?;
    if value == 0 || value > 65535 {
        return Err(());
    }
    u16::try_from(value).map_err(|_| ())
}

fn hujson_to_json(text: &str) -> Result<String, PolicyError> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    let mut in_string = false;
    let mut escape = false;
    while index < chars.len() {
        let ch = chars[index];
        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            index += 1;
            continue;
        }
        if ch == '/' && chars.get(index + 1) == Some(&'/') {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if ch == '/' && chars.get(index + 1) == Some(&'*') {
            index += 2;
            let mut closed = false;
            while index + 1 < chars.len() {
                if chars[index] == '*' && chars[index + 1] == '/' {
                    index += 2;
                    closed = true;
                    break;
                }
                index += 1;
            }
            if !closed {
                return Err(PolicyError::new("The policy comment is not closed."));
            }
            continue;
        }
        out.push(ch);
        index += 1;
    }
    if in_string {
        return Err(PolicyError::new("The policy file is not valid."));
    }
    Ok(strip_trailing_commas(&out))
}

fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    let mut in_string = false;
    let mut escape = false;
    while index < chars.len() {
        let ch = chars[index];
        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            index += 1;
            continue;
        }
        if ch == ',' {
            let mut look = index + 1;
            while look < chars.len() && chars[look].is_whitespace() {
                look += 1;
            }
            if look < chars.len() && (chars[look] == '}' || chars[look] == ']') {
                index += 1;
                continue;
            }
        }
        out.push(ch);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Policy, PROTO_TCP};

    const MAC: &str = "spiffe://orblx.local/node/mac";
    const BOX: &str = "spiffe://orblx.local/node/box";
    const AGENT: &str = "spiffe://orblx.local/agent/helper";

    fn sample() -> &'static str {
        r#"
        {
          // Humans reach the box on SSH.
          "groups": {
            "group:humans": ["spiffe://orblx.local/node/mac"],
          },
          "tags": {
            "tag:box": ["spiffe://orblx.local/node/box"],
          },
          "tagOwners": {
            "tag:box": ["group:humans"],
          },
          "acls": [
            {
              "action": "accept",
              "src": ["group:humans"],
              "proto": "tcp",
              "dst": ["tag:box:22"],
            },
            {
              "action": "accept",
              "src": ["spiffe://orblx.local/agent/helper"],
              "proto": "tcp",
              "dst": ["spiffe://orblx.local/node/box:22"],
            },
          ],
          "tests": [
            {
              "src": "spiffe://orblx.local/node/mac",
              "proto": "tcp",
              "accept": ["tag:box:22"],
              "deny": ["spiffe://orblx.local/node/box:5432"],
            },
            {
              "src": "spiffe://orblx.local/agent/helper",
              "proto": "tcp",
              "accept": ["spiffe://orblx.local/node/box:22"],
              "deny": ["spiffe://orblx.local/node/box:5432"],
            },
          ],
        }
        "#
    }

    #[test]
    fn allow_deny_tag_and_agent_assertions_pass() {
        let policy = Policy::from_hujson(sample().as_bytes()).unwrap();
        let mac = super::SpiffeId::parse(MAC).unwrap();
        let box_id = super::SpiffeId::parse(BOX).unwrap();
        let agent = super::SpiffeId::parse(AGENT).unwrap();
        assert!(policy.allows(&mac, &box_id, PROTO_TCP, 22));
        assert!(!policy.allows(&mac, &box_id, PROTO_TCP, 5432));
        assert!(policy.allows(&agent, &box_id, PROTO_TCP, 22));
        assert!(!policy.allows(&agent, &box_id, PROTO_TCP, 80));
        let grants = policy.receiver_grants(&box_id);
        assert_eq!(grants.grants.len(), 2);
        assert!(grants.reach.is_empty());
        assert!(!serde_json::to_string(&grants).unwrap().contains("reach"));
        assert!(grants.permits(&mac, PROTO_TCP, 22));
        assert!(!grants.permits(&mac, PROTO_TCP, 5432));
        let mac_grants = policy.receiver_grants(&mac);
        assert!(mac_grants.reaches(&box_id));
        assert!(!mac_grants.reaches(&mac));
        let lines: Vec<String> = policy.assertions().iter().map(|item| item.line()).collect();
        assert!(lines
            .iter()
            .any(|line| line.contains("allow") && line.contains("22")));
        assert!(lines
            .iter()
            .any(|line| line.contains("deny") && line.contains("5432")));
    }

    #[test]
    fn a_failing_assertion_rejects_the_file() {
        let text = r#"{
          "acls": [{
            "action": "accept",
            "src": ["spiffe://orblx.local/node/mac"],
            "proto": "tcp",
            "dst": ["spiffe://orblx.local/node/box:22"]
          }],
          "tests": [{
            "src": "spiffe://orblx.local/node/mac",
            "proto": "tcp",
            "accept": ["spiffe://orblx.local/node/box:5432"]
          }]
        }"#;
        let err = Policy::from_hujson(text.as_bytes()).unwrap_err();
        let sentence = err.to_string();
        assert!(sentence.contains("The policy test failed."));
        assert!(sentence.contains("5432"));
        assert!(!sentence.contains("ge1."));
    }

    #[test]
    fn a_broad_agent_rule_is_rejected() {
        let text = r#"{
          "acls": [{
            "action": "accept",
            "src": ["spiffe://orblx.local/agent/helper"],
            "dst": ["spiffe://orblx.local/node/box:*"]
          }]
        }"#;
        let err = Policy::from_hujson(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("The agent"));
        assert!(err.to_string().contains("one port"));
    }

    #[test]
    fn a_tag_without_an_owner_is_rejected() {
        let text = r#"{
          "tags": { "tag:box": ["spiffe://orblx.local/node/box"] }
        }"#;
        let err = Policy::from_hujson(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("no owner"));
    }

    #[test]
    fn comments_and_trailing_commas_parse() {
        let text = r#"{
          "groups": { "group:humans": ["spiffe://orblx.local/node/mac"], },
          /* block comment */
          "tests": [],
        }"#;
        let policy = Policy::from_hujson(text.as_bytes()).unwrap();
        assert!(policy.assertions().is_empty());
        let mac = super::SpiffeId::parse(MAC).unwrap();
        let box_id = super::SpiffeId::parse(BOX).unwrap();
        assert!(!policy.allows(&mac, &box_id, PROTO_TCP, 22));
    }

    #[test]
    fn auto_approvers_accept_a_contained_route_and_reject_the_rest() {
        let text = r#"{
          "tags": {
            "tag:router": ["spiffe://orblx.local/node/router"]
          },
          "tagOwners": {
            "tag:router": ["spiffe://orblx.local/node/mac"]
          },
          "autoApprovers": {
            "routes": {
              "10.88.0.0/16": ["tag:router"]
            }
          },
          "routeApprovals": [{
            "src": ["spiffe://orblx.local/node/router"],
            "routes": ["192.168.50.0/24"]
          }]
        }"#;
        let policy = Policy::from_hujson(text.as_bytes()).unwrap();
        let router = super::SpiffeId::parse("spiffe://orblx.local/node/router").unwrap();
        let mac = super::SpiffeId::parse(MAC).unwrap();
        assert!(policy.approves_route(&router, "10.88.0.0/16"));
        assert!(policy.approves_route(&router, "10.88.9.0/24"));
        assert!(!policy.approves_route(&router, "10.89.0.0/24"));
        assert!(!policy.approves_route(&router, "10.0.0.0/8"));
        assert!(policy.approves_route(&router, "192.168.50.0/24"));
        assert!(!policy.approves_route(&router, "192.168.50.0/25"));
        assert!(!policy.approves_route(&mac, "10.88.0.0/16"));
        assert!(!policy.approves_route(&router, "0.0.0.0/0"));
    }

    #[test]
    fn an_exit_route_in_auto_approvers_is_rejected() {
        let text = r#"{
          "autoApprovers": {
            "routes": {
              "0.0.0.0/0": ["spiffe://orblx.local/node/router"]
            }
          }
        }"#;
        let err = Policy::from_hujson(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("exit route"));
    }

    #[test]
    fn ssh_rules_allow_one_user_and_reject_the_rest() {
        let text = r#"{
          // Alice may open SSH on the box.
          "groups": {
            "group:people": ["spiffe://orblx.local/user/alice"],
          },
          "tags": {
            "tag:box": ["spiffe://orblx.local/node/box"],
          },
          "tagOwners": {
            "tag:box": ["group:people"],
          },
          "ssh": [
            {
              "src": ["group:people"],
              "dst": ["tag:box"],
              "users": ["alice", "root"],
              "checkPeriod": "30s",
            },
            {
              "src": ["spiffe://orblx.local/agent/helper"],
              "dst": ["spiffe://orblx.local/node/box"],
              "users": ["alice"],
              "checkPeriod": "1m",
            },
          ],
          "sshTests": [
            {
              "src": "spiffe://orblx.local/user/alice",
              "dst": "spiffe://orblx.local/node/box",
              "user": "alice",
              "action": "accept",
            },
            {
              "src": "spiffe://orblx.local/user/mallory",
              "dst": "spiffe://orblx.local/node/box",
              "user": "mallory",
              "action": "deny",
            },
            {
              "src": "spiffe://orblx.local/user/alice",
              "dst": "spiffe://orblx.local/node/mac",
              "user": "alice",
              "action": "deny",
            },
            {
              "src": "spiffe://orblx.local/agent/helper",
              "dst": "spiffe://orblx.local/node/box",
              "user": "alice",
              "action": "accept",
            },
            {
              "src": "spiffe://orblx.local/agent/helper",
              "dst": "spiffe://orblx.local/node/box",
              "user": "root",
              "action": "deny",
            },
          ],
        }"#;
        let policy = Policy::from_hujson(text.as_bytes()).unwrap();
        let alice = super::SpiffeId::user("alice").unwrap();
        let mallory = super::SpiffeId::user("mallory").unwrap();
        let agent = super::SpiffeId::agent("helper").unwrap();
        let box_id = super::SpiffeId::node("box").unwrap();
        let mac = super::SpiffeId::node("mac").unwrap();
        assert_eq!(policy.ssh_check_period(&alice, &box_id, "alice"), Some(30));
        assert_eq!(policy.ssh_check_period(&alice, &box_id, "root"), Some(30));
        assert_eq!(policy.ssh_check_period(&mallory, &box_id, "mallory"), None);
        assert_eq!(policy.ssh_check_period(&alice, &mac, "alice"), None);
        assert_eq!(policy.ssh_check_period(&agent, &box_id, "alice"), Some(60));
        assert_eq!(policy.ssh_check_period(&agent, &box_id, "root"), None);
        let lines: Vec<String> = policy
            .ssh_assertions()
            .iter()
            .map(|item| item.line())
            .collect();
        assert!(lines.iter().any(|line| line.starts_with("allow ssh ")));
        assert!(lines.iter().any(|line| line.starts_with("deny ssh ")));
    }

    #[test]
    fn a_failing_ssh_assertion_rejects_the_file() {
        let text = r#"{
          "ssh": [{
            "src": ["spiffe://orblx.local/user/alice"],
            "dst": ["spiffe://orblx.local/node/box"],
            "users": ["alice"],
            "checkPeriod": "30s"
          }],
          "sshTests": [{
            "src": "spiffe://orblx.local/user/alice",
            "dst": "spiffe://orblx.local/node/box",
            "user": "root",
            "action": "accept"
          }]
        }"#;
        let err = Policy::from_hujson(text.as_bytes()).unwrap_err();
        let sentence = err.to_string();
        assert!(sentence.contains("The SSH policy test failed."));
        assert!(sentence.contains("root"));
    }

    #[test]
    fn a_broad_agent_ssh_rule_is_rejected() {
        let text = r#"{
          "ssh": [{
            "src": ["spiffe://orblx.local/agent/helper"],
            "dst": ["spiffe://orblx.local/node/box"],
            "users": ["alice", "root"],
            "checkPeriod": "30s"
          }]
        }"#;
        let err = Policy::from_hujson(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("one host and one user"));
    }

    #[test]
    fn an_ssh_check_period_must_name_seconds_or_minutes() {
        let text = r#"{
          "ssh": [{
            "src": ["spiffe://orblx.local/user/alice"],
            "dst": ["spiffe://orblx.local/node/box"],
            "users": ["alice"],
            "checkPeriod": "30"
          }]
        }"#;
        let err = Policy::from_hujson(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("check period"));
    }
}
