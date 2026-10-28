use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use super::fail;
use crate::HelloError;

/// Read one TLS record from `stream`.
pub(crate) async fn read_tls_record(stream: &mut TcpStream) -> Result<Vec<u8>, HelloError> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| fail(format!("The TLS record header did not arrive. {err}")))?;
    if header[0] != 0x16 {
        return Err(fail("The first TLS record is not a handshake."));
    }
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len == 0 || len > 16_384 {
        return Err(fail("The TLS record length is not valid."));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|err| fail(format!("The TLS record body did not arrive. {err}")))?;
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&header);
    record.extend_from_slice(&body);
    Ok(record)
}

/// Return the DNS server name from one TLS ClientHello record.
pub(crate) fn tls_server_name(record: &[u8]) -> Option<String> {
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    let handshake = record.get(5..5 + record_len)?;
    if handshake.first().copied() != Some(0x01) || handshake.len() < 4 {
        return None;
    }
    let hello_len = read_u24(&handshake[1..4])?;
    let hello = handshake.get(4..4 + hello_len)?;
    // client_version (2) + random (32)
    if hello.len() < 35 {
        return None;
    }
    let mut index = 34;
    let session_len = usize::from(*hello.get(index)?);
    index = index.checked_add(1 + session_len)?;
    let cipher_len = usize::from(u16::from_be_bytes([
        *hello.get(index)?,
        *hello.get(index + 1)?,
    ]));
    index = index.checked_add(2 + cipher_len)?;
    let compression_len = usize::from(*hello.get(index)?);
    index = index.checked_add(1 + compression_len)?;
    let extension_len = usize::from(u16::from_be_bytes([
        *hello.get(index)?,
        *hello.get(index + 1)?,
    ]));
    index = index.checked_add(2)?;
    let extension_end = index.checked_add(extension_len)?;
    if hello.len() < extension_end {
        return None;
    }
    while index + 4 <= extension_end {
        let kind = u16::from_be_bytes([hello[index], hello[index + 1]]);
        let size = usize::from(u16::from_be_bytes([hello[index + 2], hello[index + 3]]));
        index += 4;
        let next = index.checked_add(size)?;
        if next > extension_end {
            return None;
        }
        if kind == 0 {
            return server_name_host(&hello[index..next]);
        }
        index = next;
    }
    None
}

fn read_u24(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 3 {
        return None;
    }
    Some((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
}

fn server_name_host(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let list = data.get(2..2 + list_len)?;
    if list.first().copied() != Some(0) {
        return None;
    }
    let name_len = usize::from(u16::from_be_bytes([list[1], list[2]]));
    let name = list.get(3..3 + name_len)?;
    let text = std::str::from_utf8(name).ok()?;
    if text.is_empty() {
        return None;
    }
    Some(text.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use rustls::RootCertStore;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use super::{read_tls_record, tls_server_name};
    use crate::connector::install_ring;

    #[test]
    fn empty_record_has_no_server_name() {
        assert!(tls_server_name(&[]).is_none());
        assert!(tls_server_name(&[0x17, 0, 0, 0, 0]).is_none());
    }

    #[tokio::test]
    async fn parser_reads_the_rustls_client_hello_name() {
        install_ring();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let name = ServerName::try_from("app-a.orblx.test".to_string()).unwrap();
            let _ = connector.connect(name, tcp).await;
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let record = read_tls_record(&mut stream).await.unwrap();
        assert_eq!(
            tls_server_name(&record).as_deref(),
            Some("app-a.orblx.test")
        );
        drop(stream);
        let _ = client.await;
    }
}
