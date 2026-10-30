use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::time::Duration;

use tokio::sync::mpsc;

use crate::HelloError;

/// The default UDP port for hello-quic.
pub const DEFAULT_UDP_PORT: u16 = 443;

/// The Linux TUN device name for `orblx up`.
pub const LINUX_TUN_NAME: &str = "orblx0";

/// The operator note for the TUN privilege.
#[must_use]
pub fn tun_capability_note() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "The utun device needs root on macOS. The command opens the device when you set --tun-address."
    }
    #[cfg(not(target_os = "macos"))]
    {
        "The TUN device needs CAP_NET_ADMIN on Linux. The command opens the device when you set --tun-address."
    }
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
    /// The kernel interface name.
    pub name: String,
}

/// Open a TUN device and start the packet thread.
///
/// On Linux the process needs CAP_NET_ADMIN.
/// On macOS the process needs root. The device is a utun interface.
/// The bytes are the IPv4 packet.
/// The macOS utun header stays inside `tun_macos`.
pub fn open_tun(config: &TunConfig) -> Result<TunBridge, HelloError> {
    #[cfg(target_os = "linux")]
    {
        linux::open(config)
    }
    #[cfg(target_os = "macos")]
    {
        crate::tun_macos::open(config)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = config;
        Err(HelloError::Tun(format!(
            "{}. This host is not Linux or macOS.",
            tun_capability_note()
        )))
    }
}

/// Open one Linux TUN device with the same configuration as [`open_tun`].
///
/// The caller owns the device.
/// The bench uses this function.
/// The hello-quic path uses [`open_tun`].
#[cfg(target_os = "linux")]
pub(crate) fn open_linux_device(config: &TunConfig) -> Result<tun::Device, HelloError> {
    linux::open_device(config)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{tun_capability_note, Duration, HelloError, TunBridge, TunConfig};
    use std::io::ErrorKind;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tun::AbstractDevice;

    pub(super) fn open(config: &TunConfig) -> Result<TunBridge, HelloError> {
        let device = open_device(config)?;
        let name = device
            .tun_name()
            .map_err(|err| HelloError::Tun(err.to_string()))?;
        let (from_tun_tx, from_tun_rx) = mpsc::channel(32);
        let (to_tun_tx, to_tun_rx) = mpsc::channel(32);
        // Two threads: a read poll must not delay a write.
        let device = Arc::new(device);
        let reader = Arc::clone(&device);
        std::thread::Builder::new()
            .name("orblx-tun-read".to_string())
            .spawn(move || tun_read_loop(reader, from_tun_tx))
            .map_err(|err| HelloError::Tun(err.to_string()))?;
        std::thread::Builder::new()
            .name("orblx-tun-write".to_string())
            .spawn(move || tun_write_loop(device, to_tun_rx))
            .map_err(|err| HelloError::Tun(err.to_string()))?;
        Ok(TunBridge {
            from_tun: from_tun_rx,
            to_tun: to_tun_tx,
            name,
        })
    }

    pub(super) fn open_device(config: &TunConfig) -> Result<tun::Device, HelloError> {
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

    /// Read packets from the TUN device.
    ///
    /// This thread only reads. The read timeout lets the thread see a closed channel.
    /// The read timeout does not delay a write, because [`tun_write_loop`] writes on a different thread.
    fn tun_read_loop(device: Arc<tun::Device>, from_tun: mpsc::Sender<Vec<u8>>) {
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
                        || err.kind() == ErrorKind::Interrupted =>
                {
                    if from_tun.is_closed() {
                        return;
                    }
                }
                Err(err) => {
                    eprintln!("The TUN device stopped. {err}");
                    return;
                }
            }
        }
    }

    /// Write packets to the TUN device as soon as they arrive.
    fn tun_write_loop(device: Arc<tun::Device>, mut to_tun: mpsc::Receiver<Vec<u8>>) {
        while let Some(packet) = to_tun.blocking_recv() {
            if let Err(err) = device.send(&packet) {
                eprintln!("The TUN device write failed. {err}");
                return;
            }
        }
    }
}
