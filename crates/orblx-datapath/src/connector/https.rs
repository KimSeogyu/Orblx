use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, PKCS_ED25519,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::{fail, install_ring, AppFetch};
use crate::HelloError;

const CHUNK: usize = 2048;

/// One generated HTTPS application.
pub(crate) struct AppIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

/// The app CA and the two leaf certificates.
pub(crate) struct AppMaterial {
    pub ca_pem: String,
    pub app_a: AppIdentity,
    pub app_b: AppIdentity,
}

/// A running HTTPS listener.
pub(crate) struct AppListener {
    pub local: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for AppListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Issue one app CA and two leaf certificates.
pub(crate) fn issue_app_material(host_a: &str, host_b: &str) -> Result<AppMaterial, HelloError> {
    let ca_key = KeyPair::generate_for(&PKCS_ED25519).map_err(|err| fail(err.to_string()))?;
    let mut ca_params = CertificateParams::default();
    let (not_before, not_after) = cert_window()?;
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Orblx App CA");
    ca_params.distinguished_name = name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.extended_key_usages.clear();
    ca_params.subject_alt_names.clear();
    ca_params.use_authority_key_identifier_extension = false;
    let app_a = issue_leaf(host_a, &ca_params, &ca_key, not_before, not_after)?;
    let app_b = issue_leaf(host_b, &ca_params, &ca_key, not_before, not_after)?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|err| fail(err.to_string()))?;
    Ok(AppMaterial {
        ca_pem: ca_cert.pem(),
        app_a,
        app_b,
    })
}

fn issue_leaf(
    host: &str,
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<AppIdentity, HelloError> {
    let key = KeyPair::generate_for(&PKCS_ED25519).map_err(|err| fail(err.to_string()))?;
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, host);
    params.distinguished_name = name;
    let dns = Ia5String::try_from(host).map_err(|err| fail(err.to_string()))?;
    params.subject_alt_names = vec![SanType::DnsName(dns)];
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let issuer = Issuer::from_params(ca_params, ca_key);
    let certificate = params
        .signed_by(&key, &issuer)
        .map_err(|err| fail(err.to_string()))?;
    Ok(AppIdentity {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
    })
}

fn cert_window() -> Result<(OffsetDateTime, OffsetDateTime), HelloError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| fail(err.to_string()))?
        .as_secs();
    let secs = i64::try_from(secs).map_err(|_| fail("The clock value is not valid."))?;
    let now = OffsetDateTime::from_unix_timestamp(secs).map_err(|err| fail(err.to_string()))?;
    let not_before = now
        .checked_sub(time::Duration::days(1))
        .ok_or_else(|| fail("The certificate start time is not valid."))?;
    let not_after = now
        .checked_add(time::Duration::days(30))
        .ok_or_else(|| fail("The certificate end time is not valid."))?;
    Ok((not_before, not_after))
}

/// Bind one HTTPS server.
///
/// The server returns `body` for every HTTP/1.1 request.
pub(crate) async fn serve_https(
    bind: SocketAddr,
    cert_pem: &str,
    key_pem: &str,
    body: String,
) -> Result<AppListener, HelloError> {
    install_ring();
    let config = server_config(cert_pem, key_pem)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|err| fail(format!("The app listener did not bind on {bind}. {err}")))?;
    let local = listener
        .local_addr()
        .map_err(|err| fail(format!("The app listener has no address. {err}")))?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            let acceptor = acceptor.clone();
            let body = body.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let _ = answer_http(&mut tls, &body).await;
                }
            });
        }
    });
    Ok(AppListener { local, task })
}

async fn answer_http<S>(stream: &mut S, body: &str) -> Result<(), HelloError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; CHUNK];
    loop {
        if buf.windows(4).any(|window| window == b"\r\n\r\n") || buf.len() > 65_536 {
            break;
        }
        let size = stream
            .read(&mut tmp)
            .await
            .map_err(|err| fail(format!("The app did not read the request. {err}")))?;
        if size == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..size]);
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|err| fail(format!("The app did not write the response. {err}")))?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Fetch one HTTPS URL through a TCP socket.
///
/// `dial` is the spoke ingress.
/// The TLS server name is `host`.
pub(crate) async fn fetch_https(
    dial: SocketAddr,
    host: &str,
    overlay: std::net::Ipv4Addr,
    ca_pem: &str,
) -> Result<AppFetch, HelloError> {
    install_ring();
    let tcp = TcpStream::connect(dial)
        .await
        .map_err(|err| fail(format!("The client did not dial {dial}. {err}")))?;
    tcp.set_nodelay(true)
        .map_err(|err| fail(format!("The client socket option failed. {err}")))?;
    let dialed = tcp
        .peer_addr()
        .map_err(|err| fail(format!("The client socket has no peer. {err}")))?;
    let config = client_config(ca_pem)?;
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| fail(format!("The server name {host} is not valid.")))?;
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|err| fail(format!("The TLS handshake to {host} failed. {err}")))?;
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .await
        .map_err(|err| fail(format!("The client did not write the request. {err}")))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; CHUNK];
    loop {
        let size = tls
            .read(&mut tmp)
            .await
            .map_err(|err| fail(format!("The client did not read the response. {err}")))?;
        if size == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..size]);
    }
    let (status, body) = parse_response(&buf)?;
    Ok(AppFetch {
        host: host.to_string(),
        overlay,
        status,
        body,
        mesh_to: 0,
        mesh_from: 0,
        dialed,
    })
}

fn parse_response(bytes: &[u8]) -> Result<(u16, String), HelloError> {
    let text = std::str::from_utf8(bytes).map_err(|_| fail("The HTTP response is not UTF-8."))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| fail("The HTTP response has no header end."))?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| fail("The HTTP response has no status line."))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| fail("The HTTP status code is missing."))?;
    let status = status
        .parse::<u16>()
        .map_err(|_| fail("The HTTP status code is not a number."))?;
    Ok((status, body.to_string()))
}

pub(crate) fn server_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<rustls::ServerConfig, HelloError> {
    install_ring();
    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| fail(format!("The app TLS certificate was rejected. {err}")))
}

fn client_config(ca_pem: &str) -> Result<rustls::ClientConfig, HelloError> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_pem)? {
        roots
            .add(cert)
            .map_err(|err| fail(format!("The app CA was rejected. {err}")))?;
    }
    if roots.is_empty() {
        return Err(fail("The app CA file has no certificate."));
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, HelloError> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| fail(format!("The certificate PEM did not parse. {err}")))
}

fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>, HelloError> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|err| fail(format!("The private key PEM did not parse. {err}")))?
        .ok_or_else(|| fail("The private key PEM is empty."))
}
