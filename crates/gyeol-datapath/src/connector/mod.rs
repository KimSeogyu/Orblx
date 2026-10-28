//! Connector hub-spoke path for two HTTPS apps.
//!
//! The product name is Orblx.
//! The path uses one QUIC bidirectional stream.
//! The stream carries ADR-0002 DATA frames.
//! Each DATA payload is one IPv4 TCP segment.
//! The spoke reads the TLS server name and selects the overlay address.
//! The hub forwards the TCP bytes to the app listener.
//! The userspace path does not open a TUN device.

mod https;
mod lab;
mod relay;
mod sni;

use std::fmt;

pub use lab::{
    issue_connector_lab, prove_lab_directory, prove_two_https_apps, run_hub_dir, run_spoke_dir,
    serve_apps_dir, serve_userspace,
};

/// The host name for application A.
pub const APP_A_HOST: &str = "app-a.orblx.test";

/// The host name for application B.
pub const APP_B_HOST: &str = "app-b.orblx.test";

/// The HTTP body for application A.
pub const APP_A_BODY: &str = "app-a";

/// The HTTP body for application B.
pub const APP_B_BODY: &str = "app-b";

/// The overlay address for application A.
pub const APP_A_OVERLAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 8, 0, 10);

/// The overlay address for application B.
pub const APP_B_OVERLAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 8, 0, 11);

/// The overlay TCP port for both apps.
pub const APP_OVERLAY_PORT: u16 = 443;

/// The overlay address of the spoke.
pub const SPOKE_OVERLAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 8, 0, 2);

/// One HTTPS fetch through the spoke ingress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppFetch {
    /// TLS server name.
    pub host: String,
    /// Overlay address in the DATA frames.
    pub overlay: std::net::Ipv4Addr,
    /// HTTP status code.
    pub status: u16,
    /// HTTP body.
    pub body: String,
    /// DATA frames that carried bytes toward the app.
    pub mesh_to: u64,
    /// DATA frames that carried bytes from the app.
    pub mesh_from: u64,
    /// The socket that the client dialed.
    pub dialed: std::net::SocketAddr,
}

/// The proof that both apps answered through the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoAppProof {
    /// The spoke ingress.
    pub ingress: std::net::SocketAddr,
    /// The hub QUIC socket.
    pub quic_hub: std::net::SocketAddr,
    /// The local listener for application A.
    pub backend_a: std::net::SocketAddr,
    /// The local listener for application B.
    pub backend_b: std::net::SocketAddr,
    /// The fetch for application A.
    pub app_a: AppFetch,
    /// The fetch for application B.
    pub app_b: AppFetch,
}

impl fmt::Display for AppFetch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{host} status {status} body {body} overlay {overlay} mesh_to {mesh_to} mesh_from {mesh_from} dialed {dialed}",
            host = self.host,
            status = self.status,
            body = self.body,
            overlay = self.overlay,
            mesh_to = self.mesh_to,
            mesh_from = self.mesh_from,
            dialed = self.dialed,
        )
    }
}

impl fmt::Display for TwoAppProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "{}", self.app_a)?;
        writeln!(formatter, "{}", self.app_b)?;
        writeln!(formatter, "ingress {}", self.ingress)?;
        writeln!(formatter, "quic_hub {}", self.quic_hub)?;
        writeln!(formatter, "backend_a {}", self.backend_a)?;
        write!(formatter, "backend_b {}", self.backend_b)
    }
}

pub(crate) fn fail(detail: impl fmt::Display) -> crate::HelloError {
    crate::HelloError::Connector(detail.to_string())
}

pub(crate) fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
