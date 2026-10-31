use serde::{Deserialize, Serialize};

use crate::error::CoordError;
use crate::netmap::{SignedEndpoint, SignedGrantsWire, SignedNetmapWire};

pub const MAX_MESSAGE: usize = 256 * 1024;

/// The node protocol version that a client sends with each request (W25-34).
///
/// Version 1: the client checks the signed netmap `seq` and `issued_at_ms`.
/// A request with no version is from an older node.
pub const NODE_PROTO: u32 = 1;

/// The start of the error text when the coordinator and the node have different versions.
pub const VERSION_MISMATCH: &str = "version mismatch, upgrade";

/// The ops that the coordinator serves to an older node (W25-34).
///
/// They carry only the deny list, so an older node still gets each revoke.
/// All other ops refuse an older node with [`VERSION_MISMATCH`].
pub const OLD_NODE_OPS: [&str; 2] = ["deny", "deny-wait"];

/// One request on the wire, with the node protocol version (W25-34).
#[derive(Serialize)]
struct Outgoing<'a> {
    #[serde(flatten)]
    request: &'a Request,
    proto: u32,
}

/// One request that the coordinator reads. An older node sends no `proto` (0).
#[derive(Deserialize)]
pub struct Incoming {
    #[serde(flatten)]
    pub request: Request,
    #[serde(default)]
    pub proto: u32,
}

/// Refuse an older node, except for [`OLD_NODE_OPS`] (W25-34).
pub fn version_gate(op: &str, proto: u32) -> Result<(), CoordError> {
    if proto >= NODE_PROTO || OLD_NODE_OPS.contains(&op) {
        return Ok(());
    }
    Err(CoordError::Protocol(format!(
        "{VERSION_MISMATCH}: the node is older than the coordinator (no signed netmap seq). \
         Upgrade the coordinator and all nodes together."
    )))
}

/// The error when a coordinator sends a netmap with no signed `seq` (W25-34).
#[must_use]
pub fn old_coordinator_error() -> CoordError {
    CoordError::Protocol(format!(
        "{VERSION_MISMATCH}: the coordinator is older than the node (no signed netmap seq). \
         Upgrade the coordinator and all nodes together."
    ))
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub op: String,
    pub name: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub exit_node: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantAsk>,
    /// A scoped admin API token (W25-3). The caller then needs no client certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,
    /// The ETag of the deny list that the node has (W25-2 `deny-wait`).
    /// For `policy-wait` (W25-6), the ETag of the netmap, grants, and deny list that the node has.
    /// An old coordinator ignores the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_etag: Option<String>,
    /// W25-9: `admin-policy-set` writes only when the live policy has this sha256.
    /// The text `none` means that no policy file is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_sha256: Option<String>,
}

/// One agent grant request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantAsk {
    /// Agent name. The SVID is `spiffe://orblx.local/agent/{agent}`.
    pub agent: String,
    /// Target node name.
    pub node: String,
    /// Service name.
    pub service: String,
    /// TCP port.
    pub port: u16,
    /// Grant life in seconds. The maximum is 300.
    pub ttl_secs: u64,
    /// HTTP path prefix. The default is `/`.
    #[serde(default)]
    pub path_prefix: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Response {
    pub ok: bool,
    /// The HTTP-style status of an admin call: 200, 400, 401, or 403 (W25-3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundle_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netmap_pub_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netmap: Option<SignedNetmapWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<SignedEndpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<SignedGrantsWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_routes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertised_routes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_mac_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_verifier_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_mac_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_not_before: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_not_after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svid_ca_pub_hex: Option<String>,
    /// The ETag of a `policy-wait` reply (W25-6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_etag: Option<String>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Response")
            .field("ok", &self.ok)
            .field("status", &self.status)
            .field("error", &self.error)
            .field("private_key_pem", &"[elided]")
            .finish()
    }
}

pub async fn write_json(
    send: &mut quinn::SendStream,
    value: &impl Serialize,
) -> Result<(), CoordError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| CoordError::Protocol("The coordinator request failed.".to_string()))?;
    if bytes.len() > MAX_MESSAGE {
        return Err(CoordError::Protocol(
            "The coordinator request failed.".to_string(),
        ));
    }
    let len = u32::try_from(bytes.len())
        .map_err(|_| CoordError::Protocol("The coordinator request failed.".to_string()))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|err| CoordError::Tls(err.to_string()))?;
    send.write_all(&bytes)
        .await
        .map_err(|err| CoordError::Tls(err.to_string()))?;
    Ok(())
}

/// Write one request with the node protocol version (W25-34).
pub async fn write_request(
    send: &mut quinn::SendStream,
    request: &Request,
) -> Result<(), CoordError> {
    write_json(
        send,
        &Outgoing {
            request,
            proto: NODE_PROTO,
        },
    )
    .await
}

pub async fn read_json<T: for<'de> Deserialize<'de>>(
    recv: &mut quinn::RecvStream,
) -> Result<T, CoordError> {
    let bytes = read_message(recv).await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| CoordError::Protocol("The request is not valid.".to_string()))
}

async fn read_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, CoordError> {
    let mut prefix = [0u8; 4];
    read_exact(recv, &mut prefix).await?;
    let len = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| CoordError::Protocol("The request is not valid.".to_string()))?;
    if len > MAX_MESSAGE {
        return Err(CoordError::Protocol(
            "The request is not valid.".to_string(),
        ));
    }
    let mut body = vec![0u8; len];
    read_exact(recv, &mut body).await?;
    Ok(body)
}

async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<(), CoordError> {
    match recv.read_exact(buf).await {
        Ok(()) => Ok(()),
        Err(quinn::ReadExactError::FinishedEarly(_)) => Err(CoordError::Protocol(
            "The response ended early.".to_string(),
        )),
        Err(quinn::ReadExactError::ReadError(err)) => Err(CoordError::Tls(format!("read: {err}"))),
    }
}

#[cfg(test)]
mod version_tests {
    use super::{
        old_coordinator_error, version_gate, Incoming, Outgoing, Request, NODE_PROTO,
        VERSION_MISMATCH,
    };

    fn request(op: &str) -> Request {
        serde_json::from_str(&format!(r#"{{"op":"{op}","name":"a"}}"#)).unwrap()
    }

    #[test]
    fn a_new_client_sends_the_protocol_version() {
        let wanted = request("policy-wait");
        let bytes = serde_json::to_vec(&Outgoing {
            request: &wanted,
            proto: NODE_PROTO,
        })
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["proto"], NODE_PROTO);
        assert_eq!(value["op"], "policy-wait");
        // An older coordinator reads the same bytes as a plain request (it ignores `proto`).
        let old: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(old.op, "policy-wait");
        let read: Incoming = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(read.proto, NODE_PROTO);
        assert_eq!(read.request.name, "a");
    }

    #[test]
    fn an_old_node_gets_only_the_deny_list() {
        let read: Incoming = serde_json::from_str(r#"{"op":"policy-wait","name":"a"}"#).unwrap();
        assert_eq!(read.proto, 0);
        for op in [
            "enroll",
            "renew",
            "netmap",
            "policy-wait",
            "advertise",
            "admin-revoke",
        ] {
            let err = version_gate(op, 0).unwrap_err().public_text();
            assert!(err.starts_with(VERSION_MISMATCH), "{op}: {err}");
            assert!(err.contains("Upgrade the coordinator and all nodes together."));
        }
        for op in ["deny", "deny-wait"] {
            assert!(version_gate(op, 0).is_ok(), "{op}");
        }
        assert!(version_gate("policy-wait", NODE_PROTO).is_ok());
    }

    #[test]
    fn the_old_coordinator_text_is_public() {
        let text = old_coordinator_error().public_text();
        assert!(text.starts_with(VERSION_MISMATCH), "{text}");
        assert!(text.contains("the coordinator is older than the node"));
    }
}
