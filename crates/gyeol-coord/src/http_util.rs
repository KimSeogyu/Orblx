use std::sync::Arc;
use std::time::Duration;

use gyeol_identity::{GOOGLE_JWKS_URL, GOOGLE_TOKEN_ENDPOINT};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::CoordError;

const MAX_BODY: usize = 64 * 1024;

/// Fetch the Google JWKS document.
///
/// This function requests only [`GOOGLE_JWKS_URL`].
pub async fn fetch_google_jwks() -> Result<String, CoordError> {
    let bytes = https_exchange(
        "www.googleapis.com",
        "GET /oauth2/v3/certs HTTP/1.1\r\nHost: www.googleapis.com\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
    )
    .await?;
    if GOOGLE_JWKS_URL != "https://www.googleapis.com/oauth2/v3/certs" {
        return Err(CoordError::Protocol(
            "The OIDC configuration is not valid.".to_string(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| CoordError::Oidc)
}

/// Post a Google token request.
///
/// `body` contains the client secret.
/// This function does not include `body` in an error.
/// This function requests only [`GOOGLE_TOKEN_ENDPOINT`].
pub async fn post_google_token(body: &str) -> Result<String, CoordError> {
    if body.len() > MAX_BODY {
        return Err(CoordError::Oidc);
    }
    let header = format!(
        "POST /token HTTP/1.1\r\nHost: oauth2.googleapis.com\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request = header.into_bytes();
    request.extend_from_slice(body.as_bytes());
    let bytes = https_exchange("oauth2.googleapis.com", &String::from_utf8_lossy(&request)).await?;
    if GOOGLE_TOKEN_ENDPOINT != "https://oauth2.googleapis.com/token" {
        return Err(CoordError::Protocol(
            "The OIDC configuration is not valid.".to_string(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| CoordError::Oidc)
}

async fn https_exchange(host: &str, request: &str) -> Result<Vec<u8>, CoordError> {
    let provider = crate::tlsutil::crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| CoordError::Tls(err.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect((host, 443)))
        .await
        .map_err(|_| CoordError::Oidc)?
        .map_err(|_| CoordError::Oidc)?;
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| CoordError::Oidc)?;
    let mut tls =
        tokio::time::timeout(Duration::from_secs(20), connector.connect(server_name, tcp))
            .await
            .map_err(|_| CoordError::Oidc)?
            .map_err(|_| CoordError::Oidc)?;
    tls.write_all(request.as_bytes())
        .await
        .map_err(|_| CoordError::Oidc)?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw)
        .await
        .map_err(|_| CoordError::Oidc)?;
    split_http_body(&raw)
}

pub fn split_http_body(raw: &[u8]) -> Result<Vec<u8>, CoordError> {
    let header_end = raw
        .windows(4)
        .position(|mark| mark == b"\r\n\r\n")
        .ok_or(CoordError::Oidc)?;
    let head = std::str::from_utf8(&raw[..header_end]).map_err(|_| CoordError::Oidc)?;
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(CoordError::Oidc)?;
    let code = status.split_whitespace().nth(1).ok_or(CoordError::Oidc)?;
    if code != "200" {
        return Err(CoordError::Oidc);
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| CoordError::Oidc)?,
            );
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.trim().eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }
    let mut body = &raw[header_end + 4..];
    if chunked {
        return decode_chunks(body);
    }
    if let Some(length) = content_length {
        if length > MAX_BODY || body.len() < length {
            return Err(CoordError::Oidc);
        }
        body = &body[..length];
    }
    if body.len() > MAX_BODY {
        return Err(CoordError::Oidc);
    }
    Ok(body.to_vec())
}

fn decode_chunks(mut body: &[u8]) -> Result<Vec<u8>, CoordError> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|mark| mark == b"\r\n")
            .ok_or(CoordError::Oidc)?;
        let line = std::str::from_utf8(&body[..line_end]).map_err(|_| CoordError::Oidc)?;
        let size = usize::from_str_radix(line.trim(), 16).map_err(|_| CoordError::Oidc)?;
        body = &body[line_end + 2..];
        if size == 0 {
            break;
        }
        if size > MAX_BODY || body.len() < size + 2 || out.len() + size > MAX_BODY {
            return Err(CoordError::Oidc);
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size..];
        if !body.starts_with(b"\r\n") {
            return Err(CoordError::Oidc);
        }
        body = &body[2..];
    }
    Ok(out)
}

pub fn fetch_google_jwks_blocking() -> Result<String, CoordError> {
    block_on(fetch_google_jwks())
}

pub fn post_google_token_blocking(body: &str) -> Result<String, CoordError> {
    let body = body.to_string();
    block_on(async move { post_google_token(&body).await })
}

fn block_on<T>(
    future: impl std::future::Future<Output = Result<T, CoordError>>,
) -> Result<T, CoordError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CoordError::io)?;
    runtime.block_on(future)
}

#[cfg(test)]
mod tests {
    use super::split_http_body;

    #[test]
    fn content_length_body_is_returned() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(split_http_body(raw).unwrap(), b"hello");
    }

    #[test]
    fn chunked_body_is_returned() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(split_http_body(raw).unwrap(), b"hello");
    }

    #[test]
    fn non_200_is_rejected_without_the_body() {
        let raw = b"HTTP/1.1 400 Bad\r\nContent-Length: 3\r\n\r\nnope";
        assert!(split_http_body(raw).is_err());
    }
}
