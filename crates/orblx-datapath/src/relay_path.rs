//! A QUIC session carried by the orblx Relay.
//!
//! The Relay sees opaque packets.
//! UDP is the first attempt.
//! TCP port 443 is the fallback.
//! The session id comes from the two node names. The Relay does not mint it.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use orblx_relay::{RelayPipe, RelaySessionId, RelayTransport};
use sha2::{Digest, Sha256};

use crate::quic::{HelloConfig, HelloEndpoint, HelloSocketRole};
use crate::HelloError;

/// The longest time that a bridge blocks before it checks the stop flag.
const BRIDGE_WAIT: Duration = Duration::from_millis(50);
const UDP_TIMEOUT: Duration = Duration::from_millis(400);
const TCP_TIMEOUT: Duration = Duration::from_secs(4);

/// One Relay attachment that carries QUIC.
pub struct RelayFace {
    stop: Arc<AtomicBool>,
    bridge: Option<JoinHandle<()>>,
    /// The QUIC endpoint bound to the loopback face.
    pub endpoint: HelloEndpoint,
    /// The address the client dials on this host.
    pub face_addr: SocketAddr,
    /// UDP or TCP.
    pub transport: RelayTransport,
}

impl Drop for RelayFace {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.bridge.take() {
            let _ = handle.join();
        }
    }
}

/// Attach to `relay` and bridge QUIC through that path.
///
/// `accept` selects the QUIC server role.
/// The function tries UDP and then TCP.
pub fn open_relay(
    config: HelloConfig,
    relay: SocketAddr,
    session_id: RelaySessionId,
    accept: bool,
) -> Result<RelayFace, HelloError> {
    let pipe = match RelayPipe::connect_udp(relay, session_id, UDP_TIMEOUT) {
        Ok(pipe) => pipe,
        Err(_) => RelayPipe::connect_tcp(relay, session_id, TCP_TIMEOUT)
            .map_err(|err| HelloError::Node(format!("The Relay path failed. {err}")))?,
    };
    let transport = pipe.transport();
    let quinn = UdpSocket::bind(loopback()).map_err(|err| HelloError::Io(err.to_string()))?;
    let face = UdpSocket::bind(loopback()).map_err(|err| HelloError::Io(err.to_string()))?;
    let quinn_addr = quinn
        .local_addr()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    let face_addr = face
        .local_addr()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    face.connect(quinn_addr)
        .map_err(|err| HelloError::Io(err.to_string()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let bridge = Some(spawn_bridge(pipe, face, Arc::clone(&stop)));
    let role = if accept {
        HelloSocketRole::Server
    } else {
        HelloSocketRole::Client { peer: face_addr }
    };
    let endpoint = HelloEndpoint::from_std_socket(config, quinn, role)?;
    Ok(RelayFace {
        stop,
        bridge,
        endpoint,
        face_addr,
        transport,
    })
}

/// The same two names always produce the same session id.
#[must_use]
pub fn relay_session_id(left: &str, right: &str) -> RelaySessionId {
    let (first, second) = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"orblx-exit-relay-v1\0");
    hasher.update(first.as_bytes());
    hasher.update(b"\0");
    hasher.update(second.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    RelaySessionId::from_bytes(bytes)
}

fn spawn_bridge(mut pipe: RelayPipe, face: UdpSocket, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = face.set_nonblocking(true);
        let mut buf = [0u8; 65_535];
        while !stop.load(Ordering::Relaxed) {
            let mut idle = true;
            match face.recv(&mut buf) {
                Ok(size) => {
                    idle = false;
                    if pipe.send_opaque(&buf[..size]).is_err() {
                        break;
                    }
                }
                Err(err) if is_idle(&err) => {}
                Err(_) => break,
            }
            loop {
                match pipe.recv_opaque() {
                    Ok(Some(payload)) => {
                        idle = false;
                        if !send_face(&face, &payload) {
                            pipe.detach();
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        pipe.detach();
                        return;
                    }
                }
            }
            if idle {
                // Block until the face or the Relay has data. The limit sets the stop check.
                if pipe.wait_readable_or(&face, BRIDGE_WAIT).is_err() {
                    break;
                }
            }
        }
        pipe.detach();
    })
}

fn send_face(face: &UdpSocket, payload: &[u8]) -> bool {
    let started = std::time::Instant::now();
    loop {
        match face.send(payload) {
            Ok(size) if size == payload.len() => return true,
            Ok(_) => return false,
            Err(err) if is_idle(&err) => {
                if started.elapsed() > Duration::from_millis(200) {
                    return false;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return false,
        }
    }
}

fn is_idle(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[cfg(test)]
mod tests {
    use super::relay_session_id;

    #[test]
    fn the_relay_session_id_depends_on_the_pair_and_not_the_order() {
        assert_eq!(
            relay_session_id("client", "exit"),
            relay_session_id("exit", "client")
        );
        assert_ne!(
            relay_session_id("client", "exit"),
            relay_session_id("client", "relay")
        );
    }
}
