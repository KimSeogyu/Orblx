//! The HTTP/1.1 proxy behind the serve and funnel TLS listeners.
//!
//! The proxy reads each request with hyper. hyper decodes `Content-Length` and chunked bodies.
//! The proxy reads the whole body before it opens the local port.
//! A body above the limit gets `413 Payload Too Large`. The local web app does not see it.
//! The proxy sends the body to `127.0.0.1:PORT` with one `Content-Length` header and no
//! `Transfer-Encoding` header, so the local web app reads one clear body length.
//! The proxy removes hop-by-hop headers in both directions.
//!
//! W25-4: a WebSocket upgrade (`GET`, HTTP/1.1, `Upgrade: websocket`, `Connection: upgrade`,
//! `Sec-WebSocket-Key`, `Sec-WebSocket-Version`, and no body) goes to the local web app.
//! When the app answers `101 Switching Protocols` with `Upgrade: websocket`, the proxy copies
//! the bytes in both directions on the same TLS connection. There is no second listener.
//! Each other upgrade (for example `h2c`) still gets `501 Not Implemented`.
//! The ingress checks and the ACL check in `server.rs` run before TLS, so they apply to
//! upgrade requests too. The proxy does not log the request path or the WebSocket key.

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Either, Full};
use hyper::body::Incoming;
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING,
    UPGRADE,
};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

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

/// The byte copy of one upgraded WebSocket connection.
type Tunnel = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What `serve_connection` gives to each request.
#[derive(Clone)]
struct Conn {
    target: Target,
    stop: watch::Receiver<()>,
    tunnels: mpsc::UnboundedSender<Tunnel>,
}

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
    // An upgraded WebSocket connection sends its byte copy here.
    // This future owns the copies. When the caller drops this future, the copies stop too.
    let (tunnel_tx, mut tunnel_rx) = mpsc::unbounded_channel::<Tunnel>();
    let conn = Conn {
        target,
        stop: stop_rx,
        tunnels: tunnel_tx,
    };
    let service = hyper::service::service_fn(move |request| {
        let conn = conn.clone();
        async move { Ok::<_, Infallible>(proxy(request, conn).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEAD_LIMIT)
        .keep_alive(true);
    let mut http = Box::pin(
        builder
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades(),
    );
    let mut tunnels = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut http => break,
            Some(tunnel) = tunnel_rx.recv() => {
                tunnels.spawn(tunnel);
            }
        }
    }
    // The HTTP connection ended or gave its stream to an upgrade. Drop it, then run the
    // byte copies to their end.
    drop(http);
    while let Ok(tunnel) = tunnel_rx.try_recv() {
        tunnels.spawn(tunnel);
    }
    while tunnels.join_next().await.is_some() {}
}

async fn proxy(request: Request<Incoming>, conn: Conn) -> Response<ProxyBody> {
    let target = conn.target;
    let stop = conn.stop.clone();
    if request.headers().contains_key(UPGRADE) {
        if !is_websocket(&request) {
            println!("{}_upgrade_refused from {}", target.face, target.client);
            return status(StatusCode::NOT_IMPLEMENTED, "Upgrade is not supported.\n");
        }
        return websocket(request, conn).await;
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

    let mut upstream = upstream_head(&parts, target);
    if let Some(headers) = upstream.headers_mut() {
        if !body.is_empty() || declared.is_some() || parts.method == hyper::Method::POST {
            headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        }
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

/// The request line and the end-to-end headers for the local web app.
///
/// The head has no `Content-Length`. The proxy sets `X-Forwarded-For` and `X-Forwarded-Proto`.
fn upstream_head(
    parts: &hyper::http::request::Parts,
    target: Target,
) -> hyper::http::request::Builder {
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
        // The proxy sets these values. A client value is not kept.
        headers.remove("forwarded");
        headers.remove("x-forwarded-for");
        headers.remove("x-forwarded-proto");
        if let Ok(value) = HeaderValue::from_str(&target.client.to_string()) {
            headers.insert("x-forwarded-for", value);
        }
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    }
    upstream
}

/// True when one header has the token `token` (case-insensitive, comma-separated list).
fn has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| item.trim().eq_ignore_ascii_case(token))
}

/// True for a WebSocket opening request (RFC 6455 section 4.1) with no body.
///
/// The `Upgrade` header must name only `websocket`. A list such as `websocket, h2c` is refused.
fn is_websocket(request: &Request<Incoming>) -> bool {
    let headers = request.headers();
    let upgrade: Vec<&str> = headers
        .get_all(UPGRADE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect();
    let only_websocket = upgrade.len() == 1 && upgrade[0].eq_ignore_ascii_case("websocket");
    let no_body = !headers.contains_key(TRANSFER_ENCODING)
        && headers
            .get(CONTENT_LENGTH)
            .is_none_or(|value| value.as_bytes() == b"0");
    request.method() == hyper::Method::GET
        && request.version() == Version::HTTP_11
        && only_websocket
        && has_token(headers, CONNECTION, "upgrade")
        && headers.contains_key("sec-websocket-key")
        && headers.contains_key("sec-websocket-version")
        && no_body
}

/// Send a WebSocket opening request to the local web app.
///
/// On `101` with `Upgrade: websocket`, the function sends the byte copy to `serve_connection`
/// and returns the `101` response. Any other app response goes back to the client as it is.
async fn websocket(mut request: Request<Incoming>, conn: Conn) -> Response<ProxyBody> {
    let target = conn.target;
    let client_upgrade = hyper::upgrade::on(&mut request);
    let (parts, _body) = request.into_parts();
    let mut upstream = upstream_head(&parts, target);
    if let Some(headers) = upstream.headers_mut() {
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    }
    let Ok(upstream) = upstream.body(Full::new(Bytes::new())) else {
        return closing(StatusCode::BAD_REQUEST, "The request is not valid.\n");
    };
    let Ok(stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, target.port)).await else {
        eprintln!(
            "The local port 127.0.0.1:{} did not accept the connection.",
            target.port
        );
        return status(StatusCode::BAD_GATEWAY, "The local web app is not open.\n");
    };
    let Ok((mut sender, app_conn)) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream)).await
    else {
        return status(
            StatusCode::BAD_GATEWAY,
            "The local web app did not answer.\n",
        );
    };
    let mut stop = conn.stop.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = app_conn.with_upgrades() => {}
            _ = stop.changed() => {}
        }
    });
    let Ok(mut response) = sender.send_request(upstream).await else {
        return status(
            StatusCode::BAD_GATEWAY,
            "The local web app did not answer.\n",
        );
    };
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        // The app refused the upgrade. The client gets the app response.
        let (mut parts, body) = response.into_parts();
        let mut headers = HeaderMap::new();
        copy_end_to_end(&parts.headers, &mut headers);
        parts.headers = headers;
        parts.version = Version::HTTP_11;
        return Response::from_parts(parts, Either::Right(body));
    }
    let only_websocket = response
        .headers()
        .get(UPGRADE)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if !only_websocket {
        return closing(
            StatusCode::BAD_GATEWAY,
            "The local web app switched to a protocol that is not WebSocket.\n",
        );
    }
    let app_upgrade = hyper::upgrade::on(&mut response);
    let mut headers = HeaderMap::new();
    copy_end_to_end(response.headers(), &mut headers);
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    let mut reply = Response::new(Either::Left(Full::new(Bytes::new())));
    *reply.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *reply.headers_mut() = headers;
    let face = target.face;
    let client = target.client;
    let tunnel: Tunnel = Box::pin(async move {
        let (Ok(client_io), Ok(app_io)) = tokio::join!(client_upgrade, app_upgrade) else {
            println!("{face}_ws_failed from {client}");
            return;
        };
        let mut client_io = TokioIo::new(client_io);
        let mut app_io = TokioIo::new(app_io);
        match tokio::io::copy_bidirectional(&mut client_io, &mut app_io).await {
            Ok((up, down)) => println!("{face}_ws_closed from {client} up {up} down {down}"),
            Err(_) => println!("{face}_ws_closed from {client} error"),
        }
    });
    if conn.tunnels.send(tunnel).is_err() {
        return closing(
            StatusCode::SERVICE_UNAVAILABLE,
            "The connection is closing.\n",
        );
    }
    println!("{face}_ws_open from {client}");
    reply
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

    /// A local app that answers an upgrade with `101` and then echoes raw bytes.
    /// It counts the requests that reach it. `refuse` makes it answer `403` instead.
    async fn upgrade_app(refuse: bool) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|_| panic!("bind"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|_| panic!("addr"))
            .port();
        let seen = std::sync::Arc::new(AtomicUsize::new(0));
        let count = std::sync::Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let count = std::sync::Arc::clone(&count);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                    if refuse {
                        let _ = stream
                            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nno\n")
                            .await;
                        return;
                    }
                    assert!(text.contains("upgrade: websocket"), "{text}");
                    assert!(text.contains("connection: upgrade"), "{text}");
                    assert!(text.contains("x-forwarded-for: 127.0.0.1"), "{text}");
                    let _ = stream
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
                        .await;
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        (port, seen)
    }

    const WS_HEAD: &[u8] = b"GET /chat HTTP/1.1\r\nHost: b\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

    async fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).await.is_err() {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).to_string()
    }

    #[test]
    fn a_websocket_upgrade_passes_100_messages_both_ways() {
        runtime().block_on(async {
            let (app, seen) = upgrade_app(false).await;
            let port = proxy_on(app, 1024).await;
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap_or_else(|_| panic!("connect"));
            stream
                .write_all(WS_HEAD)
                .await
                .unwrap_or_else(|_| panic!("write"));
            let head = read_head(&mut stream).await;
            assert!(
                head.starts_with("HTTP/1.1 101 Switching Protocols"),
                "{head}"
            );
            let lower = head.to_ascii_lowercase();
            assert!(lower.contains("upgrade: websocket"), "{head}");
            assert!(lower.contains("sec-websocket-accept: test"), "{head}");
            for index in 0..100u32 {
                // The byte stream is above the body limit in total. Upgraded bytes have no body limit.
                let message = format!("message {index} {}\n", "x".repeat(index as usize));
                stream
                    .write_all(message.as_bytes())
                    .await
                    .unwrap_or_else(|_| panic!("write"));
                let mut echo = vec![0u8; message.len()];
                tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echo))
                    .await
                    .unwrap_or_else(|_| panic!("echo timeout"))
                    .unwrap_or_else(|_| panic!("echo"));
                assert_eq!(echo, message.as_bytes());
            }
            assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn an_upgrade_that_is_not_websocket_gets_501_and_does_not_reach_the_app() {
        runtime().block_on(async {
            let (app, seen) = upgrade_app(false).await;
            let port = proxy_on(app, 1024).await;
            let cases: [&[u8]; 6] = [
                b"GET / HTTP/1.1\r\nHost: b\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: b\r\nConnection: Upgrade\r\nUpgrade: websocket, h2c\r\nSec-WebSocket-Key: a\r\nSec-WebSocket-Version: 13\r\n\r\n",
                b"POST / HTTP/1.1\r\nHost: b\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: a\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: b\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: b\r\nConnection: keep-alive\r\nUpgrade: websocket\r\nSec-WebSocket-Key: a\r\nSec-WebSocket-Version: 13\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: b\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: a\r\nSec-WebSocket-Version: 13\r\nContent-Length: 4\r\n\r\nabcd",
            ];
            for case in cases {
                let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .unwrap_or_else(|_| panic!("connect"));
                stream.write_all(case).await.unwrap_or_else(|_| panic!("write"));
                let head = read_head(&mut stream).await;
                assert!(head.starts_with("HTTP/1.1 501 Not Implemented"), "{head}");
            }
            assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn an_app_that_refuses_the_upgrade_sends_its_answer_and_no_tunnel() {
        runtime().block_on(async {
            let (app, seen) = upgrade_app(true).await;
            let port = proxy_on(app, 1024).await;
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap_or_else(|_| panic!("connect"));
            stream
                .write_all(WS_HEAD)
                .await
                .unwrap_or_else(|_| panic!("write"));
            let head = read_head(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 403 Forbidden"), "{head}");
            assert!(!head.to_ascii_lowercase().contains("upgrade:"), "{head}");
            assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn dropping_the_connection_stops_the_tunnel() {
        runtime().block_on(async {
            let (app, _seen) = upgrade_app(false).await;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap_or_else(|_| panic!("bind"));
            let port = listener
                .local_addr()
                .unwrap_or_else(|_| panic!("addr"))
                .port();
            let task = tokio::spawn(async move {
                let Ok((stream, peer)) = listener.accept().await else {
                    return;
                };
                let target = Target {
                    face: "serve",
                    port: app,
                    body_limit: 1024,
                    client: peer.ip(),
                };
                serve_connection(stream, target).await;
            });
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap_or_else(|_| panic!("connect"));
            stream
                .write_all(WS_HEAD)
                .await
                .unwrap_or_else(|_| panic!("write"));
            let head = read_head(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 101"), "{head}");
            stream
                .write_all(b"ping\n")
                .await
                .unwrap_or_else(|_| panic!("write"));
            let mut echo = [0u8; 5];
            stream
                .read_exact(&mut echo)
                .await
                .unwrap_or_else(|_| panic!("echo"));
            // The listener closes (for example, serve off): the caller aborts the connection task.
            task.abort();
            let _ = task.await;
            let mut rest = Vec::new();
            let read =
                tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
            assert!(
                matches!(read, Ok(Ok(0)) | Ok(Err(_))),
                "the tunnel did not stop"
            );
        });
    }
}
