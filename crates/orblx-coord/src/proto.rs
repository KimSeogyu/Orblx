use serde::{Deserialize, Serialize};

use crate::error::CoordError;
use crate::netmap::{SignedEndpoint, SignedGrants, SignedNetmap};

pub const MAX_MESSAGE: usize = 256 * 1024;

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
    /// W25-16: for `policy-wait`, the node keeps the view of `deny_etag`. When the hold ends
    /// and the ETag did not change, the coordinator replies with only the deny list and the
    /// ETag, without the view. An old coordinator ignores the field and sends the full reply.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unchanged_ok: bool,
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
    pub netmap: Option<SignedNetmap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<SignedEndpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<SignedGrants>,
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
    let bytes = encode_json(value)?;
    write_bytes(send, &bytes).await
}

/// Encode one message as JSON.
pub fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, CoordError> {
    serde_json::to_vec(value)
        .map_err(|_| CoordError::Protocol("The coordinator request failed.".to_string()))
}

/// Write one message that is JSON already, with its length prefix (W25-16).
pub async fn write_bytes(send: &mut quinn::SendStream, bytes: &[u8]) -> Result<(), CoordError> {
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
    send.write_all(bytes)
        .await
        .map_err(|err| CoordError::Tls(err.to_string()))?;
    Ok(())
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
