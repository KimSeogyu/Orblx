//! macOS utun device.
//!
//! The bridge carries one IPv4 packet.
//! The 4-byte utun family header stays in this module.
//! Address assignment and the overlay route go through [`RouteInstaller`].

#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

use std::net::Ipv4Addr;

/// The utun MTU. This matches the Linux TUN MTU.
const UTUN_MTU: u16 = 1500;

/// `AF_INET` in network byte order. Darwin uses this 4-byte utun header.
const IPV4_UTUN_HEADER: [u8; 4] = [0, 0, 0, 2];

const IFCONFIG: &str = "/sbin/ifconfig";
const ROUTE: &str = "/sbin/route";
const READ_WAIT_MS: i32 = 50;

/// One utun address assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddressAssignment {
    /// Interface name. The name is `utun` plus a number.
    pub interface: String,
    /// Overlay IPv4 address.
    pub address: Ipv4Addr,
    /// Point-to-point destination. This path uses the overlay address.
    pub destination: Ipv4Addr,
    /// Overlay netmask.
    pub netmask: Ipv4Addr,
    /// Interface MTU.
    pub mtu: u16,
}

/// One overlay route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverlayRoute {
    /// Interface name. The name is `utun` plus a number.
    pub interface: String,
    /// Network address. This is the address masked by the netmask.
    pub network: Ipv4Addr,
    /// Overlay netmask.
    pub netmask: Ipv4Addr,
    /// Prefix length of `netmask`.
    pub prefix_len: u8,
}

/// The address assignment and the overlay route for one utun device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverlayPlan {
    /// Address command.
    pub address: AddressAssignment,
    /// Route command.
    pub route: OverlayRoute,
}

/// Assigns an overlay address and adds one route.
pub(crate) trait RouteInstaller {
    /// Assign the overlay address on the utun interface.
    fn assign_address(&mut self, assignment: &AddressAssignment) -> Result<(), String>;

    /// Add the overlay route.
    fn add_route(&mut self, route: &OverlayRoute) -> Result<(), String>;
}

/// Runs one system command.
trait CommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), String>;
}

/// Installs the address with `/sbin/ifconfig` and the route with `/sbin/route`.
struct ShellInstaller<R> {
    runner: R,
}

impl<R: CommandRunner> RouteInstaller for ShellInstaller<R> {
    fn assign_address(&mut self, assignment: &AddressAssignment) -> Result<(), String> {
        self.runner.run(IFCONFIG, &ifconfig_args(assignment))
    }

    fn add_route(&mut self, route: &OverlayRoute) -> Result<(), String> {
        let args = route_args(route)?;
        match self.runner.run(ROUTE, &args) {
            Ok(()) => Ok(()),
            Err(detail) if route_already_present(&detail) => Ok(()),
            Err(detail) => Err(detail),
        }
    }
}

/// Build the address assignment and the overlay route.
pub(crate) fn plan_overlay(
    interface: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<OverlayPlan, String> {
    validate_utun_name(interface)?;
    validate_unicast(address)?;
    let prefix_len = prefix_len(netmask)?;
    let network = Ipv4Addr::from(u32::from(address) & u32::from(netmask));
    Ok(OverlayPlan {
        address: AddressAssignment {
            interface: interface.to_string(),
            address,
            destination: address,
            netmask,
            mtu: UTUN_MTU,
        },
        route: OverlayRoute {
            interface: interface.to_string(),
            network,
            netmask,
            prefix_len,
        },
    })
}

#[cfg(target_os = "macos")]
pub(crate) use device::install_destination_route;

/// Assign the address and add the route.
pub(crate) fn apply_overlay<R: RouteInstaller>(
    installer: &mut R,
    interface: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<(), String> {
    let plan = plan_overlay(interface, address, netmask)?;
    installer.assign_address(&plan.address)?;
    installer.add_route(&plan.route)?;
    Ok(())
}

/// Darwin `ioctl` read-write request code.
///
/// The size is the third argument. The group is one ASCII byte.
pub(crate) fn bsd_ioctl_readwrite(group: u8, number: u8, size: u32) -> u32 {
    const IOC_INOUT: u32 = 0xc000_0000;
    IOC_INOUT | (size << 16) | (u32::from(group) << 8) | u32::from(number)
}

/// Control unit for `utunN`.
///
/// `None` asks the kernel to choose the interface.
/// `utunN` uses control unit `N + 1`.
pub(crate) fn requested_control_unit(name: Option<&str>) -> Result<u32, String> {
    let Some(name) = name else {
        return Ok(0);
    };
    let index = utun_index(name)?;
    index
        .checked_add(1)
        .ok_or_else(|| "The utun unit is too large.".to_string())
}

fn ifconfig_args(assignment: &AddressAssignment) -> Vec<String> {
    vec![
        assignment.interface.clone(),
        "inet".to_string(),
        assignment.address.to_string(),
        assignment.destination.to_string(),
        "netmask".to_string(),
        assignment.netmask.to_string(),
        "mtu".to_string(),
        assignment.mtu.to_string(),
        "up".to_string(),
    ]
}

fn route_args(route: &OverlayRoute) -> Result<Vec<String>, String> {
    let prefix = prefix_len(route.netmask)?;
    if prefix != route.prefix_len {
        return Err("The route prefix does not match the netmask.".to_string());
    }
    Ok(vec![
        "-n".to_string(),
        "add".to_string(),
        "-net".to_string(),
        route.network.to_string(),
        "-netmask".to_string(),
        route.netmask.to_string(),
        "-interface".to_string(),
        route.interface.clone(),
    ])
}

fn route_already_present(detail: &str) -> bool {
    let text = detail.to_ascii_lowercase();
    text.contains("file exists") || text.contains("route already in table")
}

fn validate_utun_name(name: &str) -> Result<(), String> {
    utun_index(name).map(|_| ())
}

fn utun_index(name: &str) -> Result<u32, String> {
    let Some(rest) = name.strip_prefix("utun") else {
        return Err(format!("The macOS interface name {name} must be utunN."));
    };
    if rest.is_empty()
        || rest.len() > 5
        || !rest.bytes().all(|byte| byte.is_ascii_digit())
        || (rest.len() > 1 && rest.starts_with('0'))
    {
        return Err(format!("The macOS interface name {name} must be utunN."));
    }
    rest.parse::<u32>()
        .map_err(|_| format!("The macOS interface name {name} must be utunN."))
}

fn validate_unicast(address: Ipv4Addr) -> Result<(), String> {
    if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
        return Err(format!(
            "The overlay address {address} is not a unicast address."
        ));
    }
    Ok(())
}

fn prefix_len(netmask: Ipv4Addr) -> Result<u8, String> {
    let bits = u32::from(netmask);
    let ones = bits.leading_ones();
    let zeros = bits.trailing_zeros();
    if ones + zeros != 32 {
        return Err(format!("The netmask {netmask} is not contiguous."));
    }
    u8::try_from(ones).map_err(|_| "The prefix length is not valid.".to_string())
}

/// Darwin `ctl_info`. The name field is 96 bytes.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

/// Darwin `sockaddr_ctl`.
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

#[cfg(target_os = "macos")]
mod device {
    use std::io::ErrorKind;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use tokio::sync::mpsc::{self, error::TryRecvError};

    use super::{
        apply_overlay, bsd_ioctl_readwrite, prefix_len, requested_control_unit, utun_index,
        validate_utun_name, CtlInfo, OverlayRoute, RouteInstaller, ShellInstaller, SockaddrCtl,
        IPV4_UTUN_HEADER,
    };
    use crate::tun_dev::{TunBridge, TunConfig};
    use crate::HelloError;

    const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

    pub(crate) fn open(config: &TunConfig) -> Result<TunBridge, HelloError> {
        let (fd, name) = open_utun_fd(config.name.as_deref())?;
        let mut installer = ShellInstaller {
            runner: SystemCommand,
        };
        apply_overlay(&mut installer, &name, config.address, config.netmask)
            .map_err(HelloError::Tun)?;
        let (from_tun_tx, from_tun_rx) = mpsc::channel(32);
        let (to_tun_tx, to_tun_rx) = mpsc::channel(32);
        std::thread::Builder::new()
            .name("gyeol-tun".to_string())
            .spawn(move || utun_loop(fd, from_tun_tx, to_tun_rx))
            .map_err(|err| HelloError::Tun(err.to_string()))?;
        Ok(TunBridge {
            from_tun: from_tun_rx,
            to_tun: to_tun_tx,
            name,
        })
    }

    /// Add one peer prefix route on an open utun device.
    ///
    /// `open` already assigns the overlay address and the address route.
    pub(crate) fn install_destination_route(
        interface: &str,
        network: std::net::Ipv4Addr,
        netmask: std::net::Ipv4Addr,
    ) -> Result<(), HelloError> {
        validate_utun_name(interface).map_err(HelloError::Tun)?;
        let prefix_len = prefix_len(netmask).map_err(HelloError::Tun)?;
        let route = OverlayRoute {
            interface: interface.to_string(),
            network,
            netmask,
            prefix_len,
        };
        let mut installer = ShellInstaller {
            runner: SystemCommand,
        };
        installer.add_route(&route).map_err(HelloError::Tun)
    }

    struct SystemCommand;

    impl super::CommandRunner for SystemCommand {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), String> {
            let output = std::process::Command::new(program)
                .args(args)
                .output()
                .map_err(|err| format!("The command {program} did not start. {err}"))?;
            if output.status.success() {
                return Ok(());
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("{program} failed. {stdout}{stderr}"))
        }
    }

    fn open_utun_fd(requested_name: Option<&str>) -> Result<(OwnedFd, String), HelloError> {
        let unit = requested_control_unit(requested_name).map_err(HelloError::Tun)?;
        let raw =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw < 0 {
            return Err(macos_io_error("The utun socket"));
        }
        // SAFETY: `raw` is an open socket and this function owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_cloexec(fd.as_raw_fd())?;
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        info.ctl_name[..CONTROL_NAME.len()].copy_from_slice(CONTROL_NAME);
        debug_assert_eq!(std::mem::size_of::<CtlInfo>(), 100);
        debug_assert_eq!(
            libc::CTLIOCGINFO,
            libc::c_ulong::from(bsd_ioctl_readwrite(b'N', 3, 100))
        );
        let rc = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                libc::CTLIOCGINFO,
                std::ptr::from_mut(&mut info),
            )
        };
        if rc < 0 {
            return Err(macos_io_error("The utun control lookup"));
        }
        let family = u8::try_from(libc::AF_SYSTEM)
            .map_err(|_| HelloError::Tun("The utun address family is not valid.".to_string()))?;
        let sysaddr = u16::try_from(libc::AF_SYS_CONTROL)
            .map_err(|_| HelloError::Tun("The utun system address is not valid.".to_string()))?;
        debug_assert_eq!(libc::AF_INET, 2);
        let addr = SockaddrCtl {
            sc_len: size_u8::<SockaddrCtl>()?,
            sc_family: family,
            ss_sysaddr: sysaddr,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };
        let addr_len: libc::socklen_t = size_u32::<SockaddrCtl>()?;
        let rc =
            unsafe { libc::connect(fd.as_raw_fd(), std::ptr::from_ref(&addr).cast(), addr_len) };
        if rc < 0 {
            return Err(macos_io_error("The utun connect"));
        }
        let name = interface_name(fd.as_raw_fd())?;
        utun_index(&name).map_err(HelloError::Tun)?;
        if let Some(requested) = requested_name {
            if name != requested {
                return Err(HelloError::Tun(format!(
                    "The utun name is {name}. The requested name is {requested}."
                )));
            }
        }
        set_nonblock(fd.as_raw_fd())?;
        Ok((fd, name))
    }

    fn interface_name(fd: libc::c_int) -> Result<String, HelloError> {
        let mut buffer = [0u8; 64];
        let mut len = libc::socklen_t::try_from(buffer.len())
            .map_err(|_| HelloError::Tun("The utun name buffer is too large.".to_string()))?;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                buffer.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc < 0 {
            return Err(macos_io_error("The utun name read"));
        }
        let end = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        let name = std::str::from_utf8(&buffer[..end])
            .map_err(|err| HelloError::Tun(format!("The utun name is not UTF-8. {err}")))?;
        if name.is_empty() {
            return Err(HelloError::Tun("The utun name is empty.".to_string()));
        }
        Ok(name.to_string())
    }

    fn set_cloexec(fd: libc::c_int) -> Result<(), HelloError> {
        set_fd_flag(fd, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)
    }

    fn set_nonblock(fd: libc::c_int) -> Result<(), HelloError> {
        set_fd_flag(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    }

    fn set_fd_flag(
        fd: libc::c_int,
        get: libc::c_int,
        set: libc::c_int,
        flag: libc::c_int,
    ) -> Result<(), HelloError> {
        let flags = unsafe { libc::fcntl(fd, get) };
        if flags < 0 {
            return Err(macos_io_error("The utun flag read"));
        }
        let rc = unsafe { libc::fcntl(fd, set, flags | flag) };
        if rc < 0 {
            return Err(macos_io_error("The utun flag write"));
        }
        Ok(())
    }

    fn size_u32<T>() -> Result<u32, HelloError> {
        u32::try_from(std::mem::size_of::<T>())
            .map_err(|_| HelloError::Tun("The utun structure size is not valid.".to_string()))
    }

    fn size_u8<T>() -> Result<u8, HelloError> {
        u8::try_from(std::mem::size_of::<T>())
            .map_err(|_| HelloError::Tun("The utun structure size is not valid.".to_string()))
    }

    enum PacketRead {
        Ipv4(Vec<u8>),
        Other,
        Closed,
    }

    fn utun_loop(
        fd: OwnedFd,
        from_tun: mpsc::Sender<Vec<u8>>,
        mut to_tun: mpsc::Receiver<Vec<u8>>,
    ) {
        let raw = fd.as_raw_fd();
        loop {
            match read_ipv4(raw) {
                Ok(PacketRead::Ipv4(packet)) => {
                    if from_tun.blocking_send(packet).is_err() {
                        return;
                    }
                }
                Ok(PacketRead::Other) => {}
                Ok(PacketRead::Closed) => return,
                Err(err) if is_wait(err.kind()) => {}
                Err(err) => {
                    eprintln!("The utun device stopped. {err}");
                    return;
                }
            }
            loop {
                match to_tun.try_recv() {
                    Ok(packet) => {
                        if let Err(err) = write_ipv4(raw, &packet) {
                            eprintln!("The utun device write failed. {err}");
                            return;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
        }
    }

    fn is_wait(kind: ErrorKind) -> bool {
        matches!(
            kind,
            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
        )
    }

    fn read_ipv4(fd: libc::c_int) -> std::io::Result<PacketRead> {
        if !wait_fd(fd, libc::POLLIN, super::READ_WAIT_MS)? {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "The utun read timed out.",
            ));
        }
        let mut raw = vec![0u8; 4 + 65_535];
        let rc = unsafe { libc::read(fd, raw.as_mut_ptr().cast(), raw.len()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if rc == 0 {
            return Ok(PacketRead::Closed);
        }
        let length = usize::try_from(rc).map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("The utun read length is not valid. {err}"),
            )
        })?;
        if length < IPV4_UTUN_HEADER.len() {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "The utun header is short.",
            ));
        }
        if raw[..IPV4_UTUN_HEADER.len()] != IPV4_UTUN_HEADER {
            return Ok(PacketRead::Other);
        }
        Ok(PacketRead::Ipv4(
            raw[IPV4_UTUN_HEADER.len()..length].to_vec(),
        ))
    }

    fn write_ipv4(fd: libc::c_int, packet: &[u8]) -> std::io::Result<()> {
        let mut framed = Vec::with_capacity(IPV4_UTUN_HEADER.len() + packet.len());
        framed.extend_from_slice(&IPV4_UTUN_HEADER);
        framed.extend_from_slice(packet);
        match write_once(fd, &framed) {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if !wait_fd(fd, libc::POLLOUT, super::READ_WAIT_MS)? {
                    return Err(std::io::Error::new(
                        ErrorKind::WouldBlock,
                        "The utun write timed out.",
                    ));
                }
                write_once(fd, &framed)
            }
            other => other,
        }
    }

    fn write_once(fd: libc::c_int, framed: &[u8]) -> std::io::Result<()> {
        let rc = unsafe { libc::write(fd, framed.as_ptr().cast(), framed.len()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let written = usize::try_from(rc).map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("The utun write length is not valid. {err}"),
            )
        })?;
        if written != framed.len() {
            return Err(std::io::Error::new(
                ErrorKind::WriteZero,
                "The utun write was short.",
            ));
        }
        Ok(())
    }

    fn wait_fd(
        fd: libc::c_int,
        events: libc::c_short,
        timeout_ms: libc::c_int,
    ) -> std::io::Result<bool> {
        let mut poll_fd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        loop {
            let rc = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Ok(rc > 0);
        }
    }

    fn macos_io_error(action: &str) -> HelloError {
        let err = std::io::Error::last_os_error();
        let needs_root = matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES));
        if needs_root {
            HelloError::Tun(format!(
                "The utun device needs root on macOS. {action} failed. {err}"
            ))
        } else {
            HelloError::Tun(format!("{action} failed. {err}"))
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use device::open;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    use super::{
        apply_overlay, bsd_ioctl_readwrite, ifconfig_args, plan_overlay, requested_control_unit,
        route_already_present, route_args, CommandRunner, CtlInfo, ShellInstaller, SockaddrCtl,
        IFCONFIG, IPV4_UTUN_HEADER, READ_WAIT_MS, ROUTE, UTUN_MTU,
    };

    struct ScriptedRunner {
        results: VecDeque<Result<(), String>>,
        calls: Vec<(String, Vec<String>)>,
    }

    impl CommandRunner for ScriptedRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), String> {
            self.calls.push((program.to_string(), args.to_vec()));
            self.results
                .pop_front()
                .unwrap_or_else(|| Err("The test runner has no result.".to_string()))
        }
    }

    fn address() -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, 2)
    }

    fn mask() -> Ipv4Addr {
        Ipv4Addr::new(255, 255, 255, 0)
    }

    #[test]
    fn plan_masks_the_overlay_prefix() {
        let plan = plan_overlay("utun4", address(), mask()).unwrap();
        assert_eq!(plan.address.address, address());
        assert_eq!(plan.address.destination, address());
        assert_eq!(plan.address.netmask, mask());
        assert_eq!(plan.address.mtu, UTUN_MTU);
        assert_eq!(plan.route.network, Ipv4Addr::new(100, 64, 0, 0));
        assert_eq!(plan.route.prefix_len, 24);
        assert_eq!(plan.route.interface, "utun4");
    }

    #[test]
    fn plan_keeps_a_host_prefix() {
        let host_mask = Ipv4Addr::new(255, 255, 255, 255);
        let plan = plan_overlay("utun0", address(), host_mask).unwrap();
        assert_eq!(plan.route.network, address());
        assert_eq!(plan.route.prefix_len, 32);
    }

    #[test]
    fn plan_rejects_a_bad_name_mask_or_address() {
        let bad_names = ["tun0", "utun", "utun01", "utunX", "utun0;id", ""];
        for name in bad_names {
            assert!(plan_overlay(name, address(), mask()).is_err(), "{name}");
        }
        assert!(plan_overlay("utun0", address(), Ipv4Addr::new(255, 0, 255, 0)).is_err());
        assert!(plan_overlay("utun0", Ipv4Addr::UNSPECIFIED, mask()).is_err());
        assert!(plan_overlay("utun0", Ipv4Addr::BROADCAST, mask()).is_err());
        assert!(plan_overlay("utun0", Ipv4Addr::new(224, 0, 0, 1), mask()).is_err());
    }

    #[test]
    fn control_unit_follows_the_utun_index() {
        assert_eq!(requested_control_unit(None).unwrap(), 0);
        assert_eq!(requested_control_unit(Some("utun0")).unwrap(), 1);
        assert_eq!(requested_control_unit(Some("utun4")).unwrap(), 5);
        assert!(requested_control_unit(Some("utun")).is_err());
    }

    #[test]
    fn ioctl_code_matches_the_darwin_control_lookup() {
        assert_eq!(std::mem::size_of::<CtlInfo>(), 100);
        assert_eq!(std::mem::size_of::<SockaddrCtl>(), 32);
        assert_eq!(bsd_ioctl_readwrite(b'N', 3, 100), 0xc064_4e03);
        assert_eq!(IPV4_UTUN_HEADER, [0, 0, 0, 2]);
        assert_eq!(READ_WAIT_MS, 50);
    }

    #[test]
    fn commands_use_ifconfig_and_route() {
        let plan = plan_overlay("utun3", address(), mask()).unwrap();
        assert_eq!(
            ifconfig_args(&plan.address),
            [
                "utun3",
                "inet",
                "100.64.0.2",
                "100.64.0.2",
                "netmask",
                "255.255.255.0",
                "mtu",
                "1500",
                "up",
            ]
        );
        assert_eq!(
            route_args(&plan.route).unwrap(),
            [
                "-n",
                "add",
                "-net",
                "100.64.0.0",
                "-netmask",
                "255.255.255.0",
                "-interface",
                "utun3",
            ]
        );
    }

    #[test]
    fn installer_assigns_the_address_before_the_route() {
        let mut installer = ShellInstaller {
            runner: ScriptedRunner {
                results: VecDeque::from([Ok(()), Ok(())]),
                calls: Vec::new(),
            },
        };
        apply_overlay(&mut installer, "utun3", address(), mask()).unwrap();
        assert_eq!(installer.runner.calls.len(), 2);
        assert_eq!(installer.runner.calls[0].0, IFCONFIG);
        assert_eq!(installer.runner.calls[1].0, ROUTE);
        assert_eq!(installer.runner.calls[0].1[0], "utun3");
        assert_eq!(installer.runner.calls[1].1[3], "100.64.0.0");
    }

    #[test]
    fn installer_stops_when_the_address_command_fails() {
        let mut installer = ShellInstaller {
            runner: ScriptedRunner {
                results: VecDeque::from([Err("ifconfig failed. permission".to_string())]),
                calls: Vec::new(),
            },
        };
        let err = apply_overlay(&mut installer, "utun3", address(), mask()).unwrap_err();
        assert!(err.contains("permission"));
        assert_eq!(installer.runner.calls.len(), 1);
        assert_eq!(installer.runner.calls[0].0, IFCONFIG);
    }

    #[test]
    fn installer_accepts_an_existing_route() {
        assert!(route_already_present("route failed. File exists"));
        assert!(route_already_present("ROUTE ALREADY IN TABLE"));
        assert!(!route_already_present(
            "route failed. Network is unreachable"
        ));
        let mut installer = ShellInstaller {
            runner: ScriptedRunner {
                results: VecDeque::from([Ok(()), Err("route failed. File exists".to_string())]),
                calls: Vec::new(),
            },
        };
        apply_overlay(&mut installer, "utun3", address(), mask()).unwrap();
        assert_eq!(installer.runner.calls.len(), 2);
    }
}
