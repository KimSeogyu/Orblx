//! Local Prometheus text for the node and the Relay.
//!
//! The listener binds a loopback address.
//! The default address is `127.0.0.1:9464`.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// The default metrics port.
pub const DEFAULT_METRICS_PORT: u16 = 9464;

/// The default metrics address.
#[must_use]
pub fn default_metrics_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_METRICS_PORT))
}

/// One Prometheus counter or gauge line.
#[must_use]
pub fn sample_line(name: &str, kind: &str, value: u64) -> String {
    format!("# TYPE {name} {kind}\n{name} {value}\n")
}

/// Bind `addr` and serve `GET /metrics`.
///
/// `addr` must use a loopback address.
/// The function returns the bound address.
/// A later request calls `render`.
pub fn spawn_metrics_server(
    addr: SocketAddr,
    render: impl Fn() -> String + Send + Sync + 'static,
) -> Result<SocketAddr, String> {
    if !addr.ip().is_loopback() {
        return Err("The metrics address must use the local host.".to_string());
    }
    let listener = TcpListener::bind(addr)
        .map_err(|err| format!("The metrics listener did not bind. {err}"))?;
    let bound = listener
        .local_addr()
        .map_err(|err| format!("The metrics listener did not bind. {err}"))?;
    let render = Arc::new(render);
    thread::spawn(move || accept_loop(listener, render));
    Ok(bound)
}

fn accept_loop(listener: TcpListener, render: Arc<dyn Fn() -> String + Send + Sync>) {
    let _ = listener.set_nonblocking(false);
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let render = Arc::clone(&render);
        thread::spawn(move || serve_one(stream, render));
    }
}

fn serve_one(mut stream: TcpStream, render: Arc<dyn Fn() -> String + Send + Sync>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf);
    let body = render();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}
