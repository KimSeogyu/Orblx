use std::net::SocketAddr;

use crate::quic::pump_packets;
use crate::{
    tun_capability_note, HelloConfig, HelloEndpoint, HelloError, HelloSession, TunBridge, TunConfig,
};

/// The role of one hello-quic process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloRole {
    /// Listen for one peer.
    Server {
        /// Local UDP address. The default port is 443.
        listen: SocketAddr,
    },
    /// Connect to one peer.
    Client {
        /// Local UDP address.
        bind: SocketAddr,
        /// Remote UDP address. The default port is 443.
        peer: SocketAddr,
    },
}

/// The inputs for one hello-quic process.
pub struct HelloRequest {
    /// Leaf, trust bundle, and capability ticket.
    pub config: HelloConfig,
    /// Server or client.
    pub role: HelloRole,
    /// TUN settings. `None` keeps the packet path off.
    pub tun: Option<TunConfig>,
}

/// Run one hello-quic process until the peer closes or the TUN path stops.
pub fn run_hello(request: HelloRequest) -> Result<(), HelloError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| HelloError::Io(err.to_string()))?;
    runtime.block_on(run_hello_async(request))
}

async fn run_hello_async(request: HelloRequest) -> Result<(), HelloError> {
    let bridge = open_optional_tun(request.tun.as_ref())?;
    match request.role {
        HelloRole::Server { listen } => {
            let endpoint = HelloEndpoint::bind_server(request.config, listen)?;
            println!("The command listens on UDP {}.", endpoint.local_addr()?);
            let session = endpoint.accept_one().await?;
            println!("The peer SPIFFE ID is {}.", session.peer_id().as_uri());
            drive(session, bridge).await
        }
        HelloRole::Client { bind, peer } => {
            let endpoint = HelloEndpoint::bind_client(request.config, bind)?;
            println!("The local UDP socket is {}.", endpoint.local_addr()?);
            println!("The command connects to UDP {peer}.");
            let session = endpoint.connect_one(peer).await?;
            println!("The peer SPIFFE ID is {}.", session.peer_id().as_uri());
            drive(session, bridge).await
        }
    }
}

fn open_optional_tun(config: Option<&TunConfig>) -> Result<Option<TunBridge>, HelloError> {
    match config {
        Some(config) => {
            println!("{}", tun_capability_note());
            let bridge = crate::tun_dev::open_tun(config)?;
            println!("The TUN device is open. The address is {}.", config.address);
            Ok(Some(bridge))
        }
        None => {
            println!("The command did not open a TUN device. Set --tun-address.");
            println!("{}", tun_capability_note());
            Ok(None)
        }
    }
}

async fn drive(session: HelloSession, bridge: Option<TunBridge>) -> Result<(), HelloError> {
    match bridge {
        Some(bridge) => pump_packets(session, bridge.from_tun, bridge.to_tun).await,
        None => {
            println!("The command waits. The command does not move IPv4 packets.");
            session.wait_closed().await;
            Ok(())
        }
    }
}
