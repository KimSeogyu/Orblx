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
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
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
}

impl std::fmt::Debug for Response {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Response")
            .field("ok", &self.ok)
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
