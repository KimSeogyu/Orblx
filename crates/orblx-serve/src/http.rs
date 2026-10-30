//! The HTTP/1.1 proxy behind the serve and funnel TLS listeners.
//!
//! The proxy reads each request with hyper. hyper decodes `Content-Length` and chunked bodies.
//! The proxy reads the whole body before it opens the local port.
//! A body above the limit gets `413 Payload Too Large`. The local web app does not see it.
//! The proxy sends the body to `127.0.0.1:PORT` with one `Content-Length` header and no
//! `Transfer-Encoding` header, so the local web app reads one clear body length.
//! The proxy removes hop-by-hop headers in both directions.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Either, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;

/// The time limit to read the request head.
const HEAD_LIMIT: Duration = Duration::from_secs(10);
/// The time limit to read one request body.
const BODY_LIMIT_TIME: Duration = Duration::from_secs(60);
/// After a body goes above the limit, the proxy reads and drops at most this many more bytes.
/// Then the client can read the 413 response before the connection closes.
const DRAIN_BYTES: u64 = 1024 * 1024;
/// The time limit for the drop read after a body goes above the limit.
const DRAIN_TIME: Duration = Duration::from_secs(5);

/// Hop-by-hop headers (RFC 9110 section 7.6.1). The proxy does not forward them.
const HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

/// One proxied connection.
#[derive(Clone, Copy)]
pub(crate) struct Target {
    /// The log prefix: `serve` or `funnel`.
    pub(crate) face: &'static str,
    /// The local TCP port on `127.0.0.1`.
    pub(crate) port: u16,
    /// The limit for one request body, in bytes.
    pub(crate) body_limit: u64,
    /// The source address of the client connection.
    pub(crate) client: IpAddr,
}

type ProxyBody = Either<Full<Bytes>, Incoming>;

/// Serve HTTP/1.1 on one client stream until the client closes it.
///
/// The function returns when the connection ends.
/// When the caller drops this future, the open upstream connections also stop.
pub(crate) async fn serve_connection<S>(io: S, target: Target)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The upstream connection tasks stop when `_stop` drops.
    let (_stop, stop_rx) = watch::channel(());
    let service = hyper::service::service_fn(move |request| {
        let stop_rx = stop_rx.clone();
        async move { Ok::<_, Infallible>(proxy(request, target, stop_rx).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEAD_LIMIT)
        .keep_alive(true);
    let _ = builder.serve_connection(TokioIo::new(io), service).await;
}

async fn proxy(
    request: Request<Incoming>,
    target: Target,
    stop: watch::Receiver<()>,
) -> Response<ProxyBody> {
    if request.headers().contains_key(hyper::header::UPGRADE) {
        return status(StatusCode::NOT_IMPLEMENTED, "Upgrade is not supported.\n");
    }
    let declared = match declared_length(request.headers()) {
        Ok(declared) => declared,
        Err(()) => {
            return closing(
                StatusCode::BAD_REQUEST,
                "The Content-Length is not valid.\n",
            )
        }
    };
    let expects_continue = request
        .headers()
        .get(hyper::header::EXPECT)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"));
    let (parts, body) = request.into_parts();
    let body = match declared {
        // A declared length above the limit gets 413 before the proxy reads the body.
        // With `Expect: 100-continue`, the proxy does not read the body, so hyper sends no
        // `100 Continue` and the client does not send the body.
        Some(length) if length > target.body_limit => {
            if !expects_continue {
                drain(body, DRAIN_BYTES).await;
            }
            return too_large(target);
        }
        _ => match read_body(body, target.body_limit).await {
            Ok(bytes) => bytes,
            Err(BodyError::TooLarge(rest)) => {
                drain(rest, DRAIN_BYTES).await;
                return too_large(target);
            }
            Err(BodyError::Slow) => {
                return closing(
                    StatusCode::REQUEST_TIMEOUT,
                    "The request body was too slow.\n",
                )
            }
            Err(BodyError::Broken) => {
                return closing(StatusCode::BAD_REQUEST, "The request body is not valid.\n")
            }
        },
    };

    let mut upstream = Request::builder()
        .method(parts.method.clone())
        .uri(origin_form(&parts.uri))
        .version(Version::HTTP_11);
    if let Some(headers) = upstream.headers_mut() {
        copy_end_to_end(&parts.headers, headers);
        if !headers.contains_key(HOST) {
            if let Some(authority) = parts.uri.authority() {
                if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
                    headers.insert(HOST, value);
                }
            }
        }
        headers.remove(CONTENT_LENGTH);
        if !body.is_empty() || declared.is_some() || parts.method == hyper::Method::POST {
            headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        }
        // The proxy sets these values. A client value is not kept.
        headers.remove("forwarded");
        headers.remove("x-forwarded-for");
        headers.remove("x-forwarded-proto");
        if let Ok(value) = HeaderValue::from_str(&target.client.to_string()) {
            headers.insert("x-forwarded-for", value);
        }
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    }
    let Ok(upstream) = upstream.body(Full::new(body)) else {
        return closing(StatusCode::BAD_REQUEST, "The request is not valid.\n");
    };

    let Ok(stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, target.port)).await else {
        eprintln!(
            "The local port 127.0.0.1:{} did not accept the connection.",
            target.port
        );
        return status(StatusCode::BAD_GATEWAY, "The local web app is not open.\n");
    };
    let Ok((mut sender, conn)) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream)).await
    else {
        return status(
            StatusCode::BAD_GATEWAY,
            "The local web app did not answer.\n",
        );
    };
    let mut stop = stop;
    tokio::spawn(async move {
        tokio::select! {
            _ = conn => {}
            _ = stop.changed() => {}
        }
    });
    let Ok(response) = sender.send_request(upstream).await else {
        return status(
            StatusCode::BAD_GATEWAY,
            "The local web app did not answer.\n",
        );
    };
    let (mut parts, body) = response.into_parts();
    let mut headers = HeaderMap::new();
    copy_end_to_end(&parts.headers, &mut headers);
    parts.headers = headers;
    // The client connection has its own HTTP version. hyper writes HTTP/1.0 to an HTTP/1.0 client.
    parts.version = Version::HTTP_11;
    Response::from_parts(parts, Either::Right(body))
}

enum BodyError {
    /// The body went above the limit. The value is the rest of the body.
    TooLarge(Incoming),
    Slow,
    Broken,
}

/// Read the whole body. Data frames count toward the limit. Trailers are dropped.
async fn read_body(mut body: Incoming, limit: u64) -> Result<Bytes, BodyError> {
    let mut buf = BytesMut::new();
    let read = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| BodyError::Broken)?;
            if let Ok(data) = frame.into_data() {
                if (buf.len() as u64).saturating_add(data.len() as u64) > limit {
                    return Ok(false);
                }
                buf.extend_from_slice(&data);
            }
        }
        Ok(true)
    };
    match tokio::time::timeout(BODY_LIMIT_TIME, read).await {
        Ok(Ok(true)) => Ok(buf.freeze()),
        Ok(Ok(false)) => Err(BodyError::TooLarge(body)),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(BodyError::Slow),
    }
}

/// Read and drop at most `max` more body bytes, for at most `DRAIN_TIME`.
async fn drain(mut body: Incoming, max: u64) {
    let read = async {
        let mut seen = 0u64;
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                seen = seen.saturating_add(data.len() as u64);
                if seen > max {
                    return;
                }
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN_TIME, read).await;
}

/// The declared `Content-Length`. hyper refuses a request with two different values.
fn declared_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    match headers.get(CONTENT_LENGTH) {
        None => Ok(None),
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .map(Some)
            .ok_or(()),
    }
}

fn origin_form(uri: &Uri) -> Uri {
    uri.path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .parse()
        .unwrap_or_else(|_| Uri::from_static("/"))
}

/// Copy the headers that are not hop-by-hop.
/// The headers that the `Connection` header names are hop-by-hop too.
fn copy_end_to_end(from: &HeaderMap, to: &mut HeaderMap) {
    let named: Vec<HeaderName> = from
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for (name, value) in from {
        if HOP_HEADERS.contains(&name.as_str()) || named.contains(name) {
            continue;
        }
        to.append(name.clone(), value.clone());
    }
}

fn too_large(target: Target) -> Response<ProxyBody> {
    let limit = target.body_limit;
    println!(
        "{}_too_large from {} limit {limit}",
        target.face, target.client
    );
    closing(
        StatusCode::PAYLOAD_TOO_LARGE,
        &format!("The request body is larger than {limit} bytes.\n"),
    )
}

fn status(code: StatusCode, text: &str) -> Response<ProxyBody> {
    let mut response = Response::new(Either::Left(Full::new(Bytes::from(text.to_string()))));
    *response.status_mut() = code;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// A response that also closes the connection.
fn closing(code: StatusCode, text: &str) -> Response<ProxyBody> {
    let mut response = status(code, text);
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A local web app that returns the method, the body length, and the framing headers
    /// that it got. It reads one request on each connection.
    async fn echo_app() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|_| panic!("bind"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|_| panic!("addr"))
            .port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let service =
                        hyper::service::service_fn(|request: Request<Incoming>| async move {
                            let te = request.headers().contains_key("transfer-encoding");
                            let cl = request
                                .headers()
                                .get(CONTENT_LENGTH)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("none")
                                .to_string();
                            let xff = request
                                .headers()
                                .get("x-forwarded-for")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("none")
                                .to_string();
                            let method = request.method().to_string();
                            let body = request
                                .into_body()
                                .collect()
                                .await
                                .map(|body| body.to_bytes())
                                .unwrap_or_default();
                            let text = format!(
                                "method {method} got {} te {te} cl {cl} xff {xff} sum {}\n",
                                body.len(),
                                body.iter().map(|byte| u64::from(*byte)).sum::<u64>()
                            );
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(text))))
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (port, task)
    }

    /// Start the proxy on a TCP port and return the port.
    async fn proxy_on(app_port: u16, body_limit: u64) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|_| panic!("bind"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|_| panic!("addr"))
            .port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    return;
                };
                let target = Target {
                    face: "serve",
                    port: app_port,
                    body_limit,
                    client: peer.ip(),
                };
                tokio::spawn(serve_connection(stream, target));
            }
        });
        port
    }

    /// Send raw bytes, half-close nothing, and read until the server closes or a full
    /// response with `Connection: close` arrives.
    async fn exchange(port: u16, request: &[u8]) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap_or_else(|_| panic!("connect"));
        let (mut read, mut write) = stream.split();
        let send = async {
            let _ = write.write_all(request).await;
        };
        let mut out = Vec::new();
        let recv = async {
            let _ = tokio::time::timeout(Duration::from_secs(20), read.read_to_end(&mut out)).await;
        };
        tokio::join!(send, recv);
        String::from_utf8_lossy(&out).to_string()
    }

    fn chunked(body: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in body.chunks(chunk) {
            out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            out.extend_from_slice(part);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("runtime"))
    }

    #[test]
    fn a_chunked_body_reaches_the_app_with_one_content_length() {
        runtime().block_on(async {
            let (app, _task) = echo_app().await;
            let port = proxy_on(app, 1024).await;
            let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
            let sum: u64 = body.iter().map(|byte| u64::from(*byte)).sum();
            let mut request = b"POST /up HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: 6.6.6.6\r\nConnection: close\r\n\r\n".to_vec();
            request.extend_from_slice(&chunked(&body, 97));
            let reply = exchange(port, &request).await;
            assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
            assert!(
                reply.contains(&format!(
                    "method POST got 1000 te false cl 1000 xff 127.0.0.1 sum {sum}"
                )),
                "{reply}"
            );
        });
    }

    #[test]
    fn a_body_at_the_limit_works_and_one_byte_more_gets_413() {
        runtime().block_on(async {
            let (app, _task) = echo_app().await;
            let port = proxy_on(app, 1024).await;
            let mut at_limit =
                b"POST / HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec();
            at_limit.extend_from_slice(&chunked(&[7u8; 1024], 100));
            let reply = exchange(port, &at_limit).await;
            assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
            assert!(reply.contains("got 1024 te false cl 1024"), "{reply}");

            let mut over =
                b"POST / HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            over.extend_from_slice(&chunked(&[7u8; 1025], 100));
            let reply = exchange(port, &over).await;
            assert!(reply.starts_with("HTTP/1.1 413 Payload Too Large"), "{reply}");
            assert!(!reply.contains("got "), "{reply}");
        });
    }

    #[test]
    fn a_declared_length_above_the_limit_gets_413_before_the_body() {
        runtime().block_on(async {
            let (app, _task) = echo_app().await;
            let port = proxy_on(app, 1024).await;
            // With Expect: 100-continue the client sends no body. The proxy must not send 100.
            let reply = exchange(
                port,
                b"POST / HTTP/1.1\r\nHost: b\r\nContent-Length: 999999999\r\nExpect: 100-continue\r\n\r\n",
            )
            .await;
            assert!(reply.starts_with("HTTP/1.1 413 Payload Too Large"), "{reply}");
            assert!(!reply.contains("100 Continue"), "{reply}");

            let mut request =
                b"POST / HTTP/1.1\r\nHost: b\r\nContent-Length: 2000\r\n\r\n".to_vec();
            request.extend_from_slice(&[1u8; 2000]);
            let reply = exchange(port, &request).await;
            assert!(reply.starts_with("HTTP/1.1 413 Payload Too Large"), "{reply}");
        });
    }

    #[test]
    fn a_content_length_body_and_a_get_work() {
        runtime().block_on(async {
            let (app, _task) = echo_app().await;
            let port = proxy_on(app, 1024).await;
            let mut request =
                b"PUT /x HTTP/1.1\r\nHost: b\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                    .to_vec();
            let reply = exchange(port, &request).await;
            assert!(reply.contains("method PUT got 5 te false cl 5"), "{reply}");
            request = b"GET / HTTP/1.0\r\nHost: b\r\n\r\n".to_vec();
            let reply = exchange(port, &request).await;
            assert!(reply.starts_with("HTTP/1.0 200 OK"), "{reply}");
            assert!(
                reply.contains("method GET got 0 te false cl none"),
                "{reply}"
            );
        });
    }

    #[test]
    fn a_request_with_two_framing_headers_does_not_reach_the_app() {
        runtime().block_on(async {
            let (app, _task) = echo_app().await;
            let port = proxy_on(app, 1024).await;
            let reply = exchange(
                port,
                b"POST / HTTP/1.1\r\nHost: b\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await;
            assert!(!reply.contains("got "), "{reply}");
            assert!(reply.is_empty() || reply.starts_with("HTTP/1.1 400"), "{reply}");
        });
    }
}
