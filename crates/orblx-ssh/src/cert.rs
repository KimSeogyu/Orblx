//! SSH user certificate checks on the node SSH server (W25-31).
//!
//! The coordinator issues one OpenSSH user certificate to a node. The certificate names the
//! user who owns that node. The SSH server reads the CA set and the revoked list from the
//! signed netmap of this node, with no cache, at each login.
//!
//! russh checks the validity with no skew, the CA signature, and the userauth signature before
//! it calls the handler. Then [`check_cert`] does the checks in this order:
//!
//! 1. The certificate is a user certificate.
//! 2. The CA key is in the `ssh_user_ca` list of the current netmap.
//! 3. The time is in the validity window, with a skew of [`CERT_SKEW_SECS`] or less.
//! 4. The CA signature is valid. (The userauth signature check is in russh.)
//! 5. The certificate has one principal `oidc:SUBJECT`, and the policy gives that user the
//!    login on this node.
//! 6. The `source-address` option contains the peer address. Another critical option gives deny.
//! 7. The serial and the key ID are not in the revoked list.
//!
//! Then the server checks the deny list for the user and for the client node, and the age of
//! the netmap.

use std::net::IpAddr;

use orblx_audit::DenyReason;
use orblx_datapath::{Netmap, SshRevoked};
use orblx_identity::{DenySet, Policy, SpiffeId};
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::{Certificate, PublicKey};

/// The largest clock skew for the validity window in seconds.
pub const CERT_SKEW_SECS: u64 = 60;

/// The oldest signed netmap for a new certificate login in seconds (W25-34 `NETMAP_MAX_AGE_MS`).
pub const NETMAP_MAX_AGE_SECS: u64 = orblx_datapath::NETMAP_MAX_AGE_MS / 1000;

/// Why the server refused one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRefuse {
    /// The certificate is a host certificate.
    NotUser,
    /// The CA key is not in the netmap CA set.
    UnknownCa,
    /// The time is outside the validity window.
    Validity,
    /// The CA signature is not valid.
    Signature,
    /// The certificate does not have exactly one `oidc:` principal.
    Principal,
    /// The policy gives the principal no login on this node.
    Policy,
    /// The peer address is not in `source-address`, or the option is absent.
    SourceAddress,
    /// The certificate has a critical option that the server does not know.
    CriticalOption,
    /// The serial or the key ID is in the revoked list.
    RevokedSerial,
    /// The deny list has the user or the client node.
    Revoked,
    /// The key ID does not name a node SVID.
    KeyId,
    /// The signed netmap is older than 60 s, has no stamp, is absent, or fails the signature check.
    StaleNetmap,
    /// The signed netmap `issued_at_ms` is more than 60 s after the node clock (Crypto C3).
    FutureNetmap,
}

impl CertRefuse {
    /// The stable token for the log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotUser => "not-user-cert",
            Self::UnknownCa => "unknown-ca",
            Self::Validity => "validity",
            Self::Signature => "signature",
            Self::Principal => "principal",
            Self::Policy => "policy",
            Self::SourceAddress => "source-address",
            Self::CriticalOption => "critical-option",
            Self::RevokedSerial => "revoked-serial",
            Self::Revoked => "revoked",
            Self::KeyId => "key-id",
            Self::StaleNetmap => "stale-netmap",
            Self::FutureNetmap => "future-netmap",
        }
    }

    /// The audit reason.
    #[must_use]
    pub fn audit_reason(self) -> DenyReason {
        match self {
            Self::Validity | Self::StaleNetmap | Self::FutureNetmap => DenyReason::Expired,
            Self::Policy | Self::SourceAddress => DenyReason::Destination,
            Self::RevokedSerial | Self::Revoked => DenyReason::Revoked,
            Self::NotUser
            | Self::UnknownCa
            | Self::Signature
            | Self::Principal
            | Self::CriticalOption
            | Self::KeyId => DenyReason::Ticket,
        }
    }
}

/// The inputs of one certificate check.
pub struct CertInput<'a> {
    pub cert: &'a Certificate,
    /// The local login name.
    pub login: &'a str,
    /// The address of the TCP peer.
    pub peer_ip: IpAddr,
    pub now_unix: u64,
    /// The `ssh_user_ca` list of the current netmap.
    pub ca_set: &'a [String],
    /// The `ssh_revoked` list of the current netmap.
    pub revoked: &'a [SshRevoked],
    pub policy: &'a Policy,
    /// The SVID of this node.
    pub node_id: &'a SpiffeId,
    pub deny: &'a DenySet,
}

/// One admitted certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertAdmit {
    /// The user SPIFFE ID of the principal.
    pub src: SpiffeId,
    /// The principal, `oidc:SUBJECT`.
    pub principal: String,
    pub serial: u64,
    pub key_id: String,
    /// The node SVID that asked for the certificate.
    pub client_node: SpiffeId,
    /// The policy check period in seconds.
    pub check_period: u64,
    /// The certificate has the `permit-pty` extension.
    pub pty: bool,
}

/// Check one certificate in the fixed order.
pub fn check_cert(input: &CertInput<'_>) -> Result<CertAdmit, CertRefuse> {
    let cert = input.cert;
    // 1. A user certificate.
    if cert.cert_type() != CertType::User {
        return Err(CertRefuse::NotUser);
    }
    // 2. The CA is in the netmap CA set. No cache: the caller reads the netmap now.
    let signer = PublicKey::new(cert.signature_key().clone(), "");
    let in_set = input.ca_set.iter().any(|line| {
        PublicKey::from_openssh(line)
            .map(|ca| ca.key_data() == signer.key_data())
            .unwrap_or(false)
    });
    if !in_set {
        return Err(CertRefuse::UnknownCa);
    }
    // 3. The validity window with a small skew.
    if input.now_unix.saturating_add(CERT_SKEW_SECS) < cert.valid_after()
        || input.now_unix >= cert.valid_before().saturating_add(CERT_SKEW_SECS)
    {
        return Err(CertRefuse::Validity);
    }
    // 4. The CA signature.
    if cert.verify_signature().is_err() {
        return Err(CertRefuse::Signature);
    }
    // 5. One principal, and the policy gives that user this login on this node.
    let [principal] = cert.valid_principals() else {
        return Err(CertRefuse::Principal);
    };
    let src = principal
        .strip_prefix("oidc:")
        .and_then(|subject| SpiffeId::user(subject).ok())
        .ok_or(CertRefuse::Principal)?;
    let check_period = input
        .policy
        .ssh_check_period(&src, input.node_id, input.login)
        .ok_or(CertRefuse::Policy)?;
    // 6. source-address contains the peer. No other critical option.
    let mut source_ok = false;
    for (name, value) in cert.critical_options().iter() {
        if name != "source-address" {
            return Err(CertRefuse::CriticalOption);
        }
        source_ok = source_contains(value, input.peer_ip);
    }
    if !source_ok {
        return Err(CertRefuse::SourceAddress);
    }
    // 7. Not revoked.
    if input
        .revoked
        .iter()
        .any(|item| item.serial == cert.serial() || item.key_id == cert.key_id())
    {
        return Err(CertRefuse::RevokedSerial);
    }
    let client_node = orblx_datapath::ssh_key_id_node(cert.key_id())
        .and_then(|uri| uri.strip_prefix("spiffe://orblx.local/node/"))
        .and_then(|name| SpiffeId::node(name).ok())
        .ok_or(CertRefuse::KeyId)?;
    if input.deny.reject_uri(&src).is_err() || input.deny.reject_uri(&client_node).is_err() {
        return Err(CertRefuse::Revoked);
    }
    Ok(CertAdmit {
        src,
        principal: principal.clone(),
        serial: cert.serial(),
        key_id: cert.key_id().to_string(),
        client_node,
        check_period,
        pty: cert.extensions().contains_key("permit-pty"),
    })
}

/// Return true when one `source-address` list contains `peer`.
///
/// The list has comma-separated addresses or IPv4 or IPv6 prefixes.
#[must_use]
pub fn source_contains(list: &str, peer: IpAddr) -> bool {
    let peer = match peer {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        other => other,
    };
    list.split(',').any(|item| {
        let item = item.trim();
        let (addr, bits) = match item.split_once('/') {
            Some((addr, bits)) => (addr, bits.parse::<u32>().ok()),
            None => (item, None),
        };
        let Ok(addr) = addr.parse::<IpAddr>() else {
            return false;
        };
        match (addr, peer) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let bits = bits.unwrap_or(32);
                if bits > 32 {
                    return false;
                }
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let bits = bits.unwrap_or(128);
                if bits > 128 {
                    return false;
                }
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    })
}

/// Read the signed netmap of this node and check its age (W25-31, Crypto C3).
///
/// The function uses only the signed `issued_at_ms` of `netmap.signed.json`
/// ([`orblx_coord::read_verified_netmap`] and [`orblx_datapath::netmap_fresh`]).
/// It refuses a new certificate login when the signature check fails, when the netmap has no
/// stamp or is older than 60 s ([`CertRefuse::StaleNetmap`]), or when `issued_at_ms` is more
/// than 60 s after `now_ms` ([`CertRefuse::FutureNetmap`]).
pub fn fresh_netmap(state_dir: &std::path::Path, now_ms: u64) -> Result<Netmap, CertRefuse> {
    let signed =
        orblx_coord::read_verified_netmap(state_dir).map_err(|_| CertRefuse::StaleNetmap)?;
    let issued_at_ms = signed.netmap.issued_at_ms;
    if issued_at_ms > now_ms.saturating_add(orblx_datapath::NETMAP_MAX_SKEW_MS) {
        return Err(CertRefuse::FutureNetmap);
    }
    if !orblx_datapath::netmap_fresh(issued_at_ms, now_ms) {
        return Err(CertRefuse::StaleNetmap);
    }
    Ok(signed.netmap)
}

/// Refuse a caller that is not root (W25-31).
///
/// The node SVID key signs the certificate request. Only root may use it. Thus a local user on
/// a node cannot get a certificate for the owner of the node.
pub fn require_root(euid: u32) -> Result<(), String> {
    if euid != 0 {
        return Err(
            "The SSH certificate request needs root. The node SVID key is root-only.".to_string(),
        );
    }
    Ok(())
}

/// Refuse a node SVID key file that is not mode 0600 with the owner root (W25-31).
pub fn check_key_owner_mode(uid: u32, mode: u32) -> Result<(), String> {
    if uid != 0 || mode & 0o077 != 0 {
        return Err(
            "The node SVID key file must have the owner root and the mode 0600.".to_string(),
        );
    }
    Ok(())
}

/// Check the caller and the node SVID key file in `state_dir` (W25-31).
pub fn require_root_caller(state_dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no arguments and no failure.
    let euid = unsafe { libc::geteuid() };
    require_root(euid)?;
    let meta = std::fs::metadata(state_dir.join("key.pem"))
        .map_err(|_| "The node SVID key did not open.".to_string())?;
    check_key_owner_mode(meta.uid(), meta.mode())
}

/// Test helpers that make user certificates with the `ssh-key` builder (W25-31).
#[cfg(test)]
pub(crate) mod testkit {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::ssh_key::{Certificate, PrivateKey, PublicKey};

    /// One fixed ed25519 key.
    pub(crate) fn key(byte: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[byte; 32]))
    }

    /// The OpenSSH public line of one CA key.
    pub(crate) fn ca_line(ca: &PrivateKey) -> String {
        PublicKey::new(ca.public_key().key_data().clone(), "")
            .to_openssh()
            .unwrap()
            .trim()
            .to_string()
    }

    /// The fields of one test certificate.
    pub(crate) struct Spec {
        pub(crate) principals: Vec<String>,
        pub(crate) serial: u64,
        pub(crate) key_id: String,
        pub(crate) valid_after: u64,
        pub(crate) valid_before: u64,
        pub(crate) options: Vec<(String, String)>,
        pub(crate) cert_type: CertType,
    }

    impl Spec {
        /// A user certificate like the coordinator issues for `owner` from node `node`.
        pub(crate) fn user(owner: &str, node: &str, serial: u64, now: u64) -> Self {
            Self {
                principals: vec![owner.to_string()],
                serial,
                key_id: orblx_datapath::ssh_key_id(
                    &format!("spiffe://orblx.local/node/{node}"),
                    owner,
                    serial,
                ),
                valid_after: now - 60,
                valid_before: now + 900,
                options: vec![("source-address".to_string(), "127.0.0.1/32".to_string())],
                cert_type: CertType::User,
            }
        }
    }

    /// Sign one certificate for `subject` with `ca`.
    pub(crate) fn sign(ca: &PrivateKey, subject: &PrivateKey, spec: &Spec) -> Certificate {
        let mut builder = Builder::new(
            vec![7u8; 32],
            subject.public_key().key_data().clone(),
            spec.valid_after,
            spec.valid_before,
        )
        .unwrap();
        builder.serial(spec.serial).unwrap();
        builder.cert_type(spec.cert_type).unwrap();
        builder.key_id(spec.key_id.clone()).unwrap();
        for principal in &spec.principals {
            builder.valid_principal(principal.clone()).unwrap();
        }
        for (name, value) in &spec.options {
            builder
                .critical_option(name.clone(), value.clone())
                .unwrap();
        }
        builder.extension("permit-pty", "").unwrap();
        builder.sign(ca).unwrap()
    }

    /// Write a signed netmap with the CA set and the revoked list, issued at `now` (Unix s).
    pub(crate) fn write_netmap(
        dir: &std::path::Path,
        ca: &[String],
        revoked: &[orblx_datapath::SshRevoked],
        now: u64,
    ) {
        write_netmap_at(dir, ca, revoked, now.saturating_mul(1000));
    }

    /// Write a signed netmap with the CA set, the revoked list, and one `issued_at_ms`.
    ///
    /// The test key signs the netmap. `netmap.pub` holds its public key.
    pub(crate) fn write_netmap_at(
        dir: &std::path::Path,
        ca: &[String],
        revoked: &[orblx_datapath::SshRevoked],
        issued_at_ms: u64,
    ) {
        let map = serde_json::json!({
            "version": 1,
            "self": {"name": "box", "overlay_ip": "100.64.0.10"},
            "peers": [],
            "ssh_user_ca": ca,
            "ssh_revoked": revoked,
        });
        let mut netmap: orblx_datapath::Netmap = serde_json::from_value(map).unwrap();
        netmap.seq = issued_at_ms.max(1);
        netmap.issued_at_ms = issued_at_ms;
        let key = orblx_coord::NetmapKey::from_seed(&[7; 32]);
        let signed = key.sign_netmap(&netmap).unwrap();
        std::fs::write(
            dir.join("netmap.pub"),
            format!("{}\n", orblx_coord::encode_hex(&key.public())),
        )
        .unwrap();
        let tmp = dir.join("netmap.signed.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&signed).unwrap()).unwrap();
        std::fs::rename(&tmp, dir.join("netmap.signed.json")).unwrap();
        let tmp = dir.join("netmap.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&netmap.without_stamp()).unwrap()).unwrap();
        std::fs::rename(&tmp, dir.join("netmap.json")).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::from_hujson(
            br#"{
                "ssh": [
                    {
                        "src": ["spiffe://orblx.local/user/alice"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["alice"],
                        "checkPeriod": "30s"
                    },
                    {
                        "src": ["spiffe://orblx.local/user/sharee"],
                        "dst": ["spiffe://orblx.local/node/box"],
                        "users": ["sharee"],
                        "checkPeriod": "30s"
                    }
                ]
            }"#,
        )
        .unwrap()
    }

    struct Case {
        ca_set: Vec<String>,
        revoked: Vec<SshRevoked>,
        deny: DenySet,
        policy: Policy,
        node: SpiffeId,
        now: u64,
    }

    impl Case {
        fn new(ca: &russh::keys::ssh_key::PrivateKey) -> Self {
            Self {
                ca_set: vec![testkit::ca_line(ca)],
                revoked: Vec::new(),
                deny: DenySet::empty(),
                policy: policy(),
                node: SpiffeId::node("box").unwrap(),
                now: 1_800_000_000,
            }
        }

        fn check(&self, cert: &Certificate, login: &str) -> Result<CertAdmit, CertRefuse> {
            check_cert(&CertInput {
                cert,
                login,
                peer_ip: "127.0.0.1".parse().unwrap(),
                now_unix: self.now,
                ca_set: &self.ca_set,
                revoked: &self.revoked,
                policy: &self.policy,
                node_id: &self.node,
                deny: &self.deny,
            })
        }
    }

    #[test]
    fn a_good_certificate_is_admitted_with_the_owner_and_the_client_node() {
        let ca = testkit::key(1);
        let case = Case::new(&ca);
        let spec = testkit::Spec::user("oidc:alice", "laptop", 42, case.now);
        let cert = testkit::sign(&ca, &testkit::key(2), &spec);
        let admit = case.check(&cert, "alice").unwrap();
        assert_eq!(admit.principal, "oidc:alice");
        assert_eq!(admit.src, SpiffeId::user("alice").unwrap());
        assert_eq!(admit.client_node, SpiffeId::node("laptop").unwrap());
        assert_eq!(admit.serial, 42);
        assert!(admit.pty);
    }

    #[test]
    fn a_ca_that_is_not_in_the_netmap_or_rotated_out_is_refused_at_once() {
        let ca = testkit::key(1);
        let next = testkit::key(3);
        let mut case = Case::new(&ca);
        let spec = testkit::Spec::user("oidc:alice", "laptop", 1, case.now);
        let other = testkit::sign(&testkit::key(9), &testkit::key(2), &spec);
        assert_eq!(case.check(&other, "alice"), Err(CertRefuse::UnknownCa));
        let cert = testkit::sign(&ca, &testkit::key(2), &spec);
        case.ca_set = vec![testkit::ca_line(&ca), testkit::ca_line(&next)];
        assert!(case.check(&cert, "alice").is_ok());
        // Rotation: the netmap now has [next, new]. No cache keeps the old CA.
        case.ca_set = vec![testkit::ca_line(&next), testkit::ca_line(&testkit::key(4))];
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::UnknownCa));
        case.ca_set.clear();
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::UnknownCa));
    }

    #[test]
    fn the_validity_window_has_a_skew_of_60_seconds_only() {
        let ca = testkit::key(1);
        let mut case = Case::new(&ca);
        let spec = testkit::Spec::user("oidc:alice", "laptop", 1, case.now);
        let cert = testkit::sign(&ca, &testkit::key(2), &spec);
        let (after, before) = (spec.valid_after, spec.valid_before);
        case.now = before + 59;
        assert!(case.check(&cert, "alice").is_ok());
        case.now = before + 60;
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Validity));
        case.now = after - 60;
        assert!(case.check(&cert, "alice").is_ok());
        case.now = after - 61;
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Validity));
    }

    #[test]
    fn a_host_certificate_is_refused() {
        let ca = testkit::key(1);
        let case = Case::new(&ca);
        let mut spec = testkit::Spec::user("oidc:alice", "laptop", 1, case.now);
        spec.cert_type = russh::keys::ssh_key::certificate::CertType::Host;
        let cert = testkit::sign(&ca, &testkit::key(2), &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::NotUser));
    }

    #[test]
    fn the_principal_must_be_one_owner_that_the_policy_allows_on_this_node() {
        let ca = testkit::key(1);
        let case = Case::new(&ca);
        let key = testkit::key(2);
        // mallory: no ssh rule.
        let spec = testkit::Spec::user("oidc:mallory", "mnode", 1, case.now);
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Policy));
        assert_eq!(case.check(&cert, "mallory"), Err(CertRefuse::Policy));
        // The sharee gets only the sharee login, never the login of the sharer.
        let spec = testkit::Spec::user("oidc:sharee", "snode", 2, case.now);
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Policy));
        assert_eq!(
            case.check(&cert, "sharee").unwrap().principal,
            "oidc:sharee"
        );
        // Two principals, or a principal that is not an owner, give deny.
        let mut spec = testkit::Spec::user("oidc:alice", "laptop", 3, case.now);
        spec.principals.push("oidc:sharee".to_string());
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Principal));
        let mut spec = testkit::Spec::user("oidc:alice", "laptop", 4, case.now);
        spec.principals = vec!["alice".to_string()];
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Principal));
        // A node on another box does not get this node.
        let mut other = Case::new(&ca);
        other.node = SpiffeId::node("other").unwrap();
        let spec = testkit::Spec::user("oidc:alice", "laptop", 5, case.now);
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(other.check(&cert, "alice"), Err(CertRefuse::Policy));
    }

    #[test]
    fn source_address_must_hold_the_peer_and_other_critical_options_give_deny() {
        let ca = testkit::key(1);
        let case = Case::new(&ca);
        let key = testkit::key(2);
        let mut spec = testkit::Spec::user("oidc:alice", "laptop", 1, case.now);
        spec.options = vec![("source-address".to_string(), "100.64.0.9/32".to_string())];
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::SourceAddress));
        spec.options.clear();
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::SourceAddress));
        spec.options = vec![
            ("source-address".to_string(), "127.0.0.1/32".to_string()),
            ("force-command".to_string(), "id".to_string()),
        ];
        let cert = testkit::sign(&ca, &key, &spec);
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::CriticalOption));
    }

    #[test]
    fn a_revoked_serial_key_id_user_or_client_node_is_refused() {
        let ca = testkit::key(1);
        let mut case = Case::new(&ca);
        let spec = testkit::Spec::user("oidc:alice", "laptop", 77, case.now);
        let cert = testkit::sign(&ca, &testkit::key(2), &spec);
        case.revoked = vec![SshRevoked {
            serial: 77,
            key_id: "other".to_string(),
        }];
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::RevokedSerial));
        case.revoked = vec![SshRevoked {
            serial: 1,
            key_id: spec.key_id.clone(),
        }];
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::RevokedSerial));
        case.revoked.clear();
        case.deny
            .apply_json(br#"{"version":1,"generated_at":1,"revoked_uris":["spiffe://orblx.local/node/laptop"],"revoked_ticket_nonces":[]}"#)
            .unwrap();
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Revoked));
        let mut case = Case::new(&ca);
        case.deny
            .apply_json(br#"{"version":1,"generated_at":1,"revoked_uris":["spiffe://orblx.local/user/alice"],"revoked_ticket_nonces":[]}"#)
            .unwrap();
        assert_eq!(case.check(&cert, "alice"), Err(CertRefuse::Revoked));
    }

    #[test]
    fn a_stale_or_absent_netmap_refuses_new_logins() {
        let dir = std::env::temp_dir().join(format!("orblx-ssh-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now_ms = 1_800_000_000_000;
        let ca = [testkit::ca_line(&testkit::key(1))];
        // No signed netmap.
        assert_eq!(
            fresh_netmap(&dir, now_ms).unwrap_err(),
            CertRefuse::StaleNetmap
        );
        testkit::write_netmap_at(&dir, &ca, &[], now_ms);
        assert_eq!(
            fresh_netmap(&dir, now_ms + 60_000)
                .unwrap()
                .ssh_user_ca
                .len(),
            1
        );
        // Crypto C3: an age above 60 s is refused.
        assert_eq!(
            fresh_netmap(&dir, now_ms + 60_001).unwrap_err(),
            CertRefuse::StaleNetmap
        );
        // A changed signed netmap fails the signature check.
        let path = dir.join("netmap.signed.json");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("100.64.0.10", "100.64.0.11")).unwrap();
        assert_eq!(
            fresh_netmap(&dir, now_ms).unwrap_err(),
            CertRefuse::StaleNetmap
        );
        // A netmap with no stamp is refused.
        testkit::write_netmap_at(&dir, &ca, &[], 0);
        assert_eq!(
            fresh_netmap(&dir, now_ms).unwrap_err(),
            CertRefuse::StaleNetmap
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_netmap_issued_more_than_60_s_ahead_refuses_new_logins() {
        // Crypto C3: the signed issued_at_ms more than 60 s after the node clock is refused.
        let dir = std::env::temp_dir().join(format!("orblx-ssh-future-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now_ms = 1_800_000_000_000;
        let ca = [testkit::ca_line(&testkit::key(1))];
        testkit::write_netmap_at(&dir, &ca, &[], now_ms + 60_000);
        assert!(fresh_netmap(&dir, now_ms).is_ok());
        testkit::write_netmap_at(&dir, &ca, &[], now_ms + 60_001);
        assert_eq!(
            fresh_netmap(&dir, now_ms).unwrap_err(),
            CertRefuse::FutureNetmap
        );
        assert_eq!(CertRefuse::FutureNetmap.as_str(), "future-netmap");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_caller_that_is_not_root_is_refused() {
        assert!(require_root(1000).is_err());
        assert!(require_root(65534).is_err());
        assert!(require_root(0).is_ok());
        // SAFETY: geteuid has no arguments and no failure.
        if unsafe { libc::geteuid() } != 0 {
            let dir = std::env::temp_dir();
            let err = require_root_caller(&dir).unwrap_err();
            assert!(err.contains("needs root"), "{err}");
        }
    }

    #[test]
    fn a_key_file_that_is_not_root_0600_is_refused() {
        assert!(check_key_owner_mode(0, 0o100600).is_ok());
        assert!(check_key_owner_mode(0, 0o100400).is_ok());
        assert!(check_key_owner_mode(0, 0o100640).is_err());
        assert!(check_key_owner_mode(0, 0o100604).is_err());
        assert!(check_key_owner_mode(1000, 0o100600).is_err());
    }

    #[test]
    fn source_address_lists_match_the_peer_only() {
        let peer: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(source_contains("100.64.0.1/32", peer));
        assert!(source_contains("10.0.0.0/8,100.64.0.0/10", peer));
        assert!(source_contains("100.64.0.1", peer));
        assert!(!source_contains("100.64.0.2/32", peer));
        assert!(!source_contains("", peer));
        assert!(!source_contains("100.64.0.1/33", peer));
        let mapped: IpAddr = "::ffff:100.64.0.1".parse().unwrap();
        assert!(source_contains("100.64.0.1/32", mapped));
    }
}
