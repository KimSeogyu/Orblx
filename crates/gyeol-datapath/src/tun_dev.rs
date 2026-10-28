use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::HelloError;

/// The default UDP port for hello-quic.
pub const DEFAULT_UDP_PORT: u16 = 443;

/// The operator note for the TUN capability.
#[must_use]
pub fn tun_capability_note() -> &'static str {
    "The TUN device needs CAP_NET_ADMIN on Linux. The command opens the device when you set --tun-address."
}

/// The address of one userspace TUN device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Optional interface name.
    pub name: Option<String>,
    /// IPv4 address.
    pub address: Ipv4Addr,
    /// IPv4 netmask.
    pub netmask: Ipv4Addr,
}

/// Channels that move packets to and from a TUN device.
pub struct TunBridge {
    /// Packets that the TUN device reads.
    pub from_tun: mpsc::Receiver<Vec<u8>>,
    /// Packets that the TUN device writes.
    pub to_tun: mpsc::Sender<Vec<u8>>,
}

/// Open a Linux TUN device and start the packet thread.
///
/// The process needs CAP_NET_ADMIN.
/// The device does not add a packet-information header.
/// The bytes are the IPv4 packet.
pub fn open_tun(config: &TunConfig) -> Result<TunBridge, HelloError> {
    #[cfg(target_os = "linux")]
    {
        linux::open(config)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(HelloError::Tun(format!(
            "{}. This host is not Linux.",
            tun_capability_note()
        )))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{tun_capability_note, Duration, HelloError, TunBridge, TunConfig};
    use std::io::ErrorKind;
    use tokio::sync::mpsc::{self, error::TryRecvError};

    pub(super) fn open(config: &TunConfig) -> Result<TunBridge, HelloError> {
        let device = open_device(config)?;
        let (from_tun_tx, from_tun_rx) = mpsc::channel(32);
        let (to_tun_tx, to_tun_rx) = mpsc::channel(32);
        std::thread::Builder::new()
            .name("gyeol-tun".to_string())
            .spawn(move || tun_loop(device, from_tun_tx, to_tun_rx))
            .map_err(|err| HelloError::Tun(err.to_string()))?;
        Ok(TunBridge {
            from_tun: from_tun_rx,
            to_tun: to_tun_tx,
        })
    }

    fn open_device(config: &TunConfig) -> Result<tun::Device, HelloError> {
        let mut device_config = tun::Configuration::default();
        device_config
            .address(config.address)
            .netmask(config.netmask)
            .mtu(1500)
            .up();
        if let Some(name) = &config.name {
            device_config.tun_name(name);
        }
        device_config.platform_config(|platform| {
            platform.ensure_root_privileges(true);
        });
        tun::create(&device_config)
            .map_err(|err| HelloError::Tun(format!("{} {err}", tun_capability_note())))
    }

    fn tun_loop(
        device: tun::Device,
        from_tun: mpsc::Sender<Vec<u8>>,
        mut to_tun: mpsc::Receiver<Vec<u8>>,
    ) {
        let mut buf = vec![0u8; 65_535];
        loop {
            match device.recv_timeout(&mut buf, Duration::from_millis(50)) {
                Ok(size) => {
                    if from_tun.blocking_send(buf[..size].to_vec()).is_err() {
                        return;
                    }
                }
                Err(err)
                    if err.kind() == ErrorKind::TimedOut
                        || err.kind() == ErrorKind::Interrupted => {}
                Err(err) => {
                    eprintln!("The TUN device stopped. {err}");
                    return;
                }
            }
            loop {
                match to_tun.try_recv() {
                    Ok(packet) => {
                        if let Err(err) = device.send(&packet) {
                            eprintln!("The TUN device write failed. {err}");
                            return;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
        }
    }
}
