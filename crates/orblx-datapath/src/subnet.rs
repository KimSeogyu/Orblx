//! Kernel forwarding for a subnet router.
//!
//! The router node writes an overlay packet into the TUN device.
//! Linux then forwards that packet to the connected LAN interface.
//! `iptables` MASQUERADE rewrites the source to the LAN address.
//! Return traffic is restored and enters the TUN device.
//! The node sends that packet to the overlay peer.
//!
//! This path uses the kernel. It does not use a userspace NAT.
//! `0.0.0.0/0` is an exit route. This module does not forward it.
//! A route that is not a connected LAN route is left unchanged.

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use crate::netmap::parse_cidr;
use crate::HelloError;

/// Enable IPv4 forwarding and masquerade for each connected route.
pub fn enable_kernel_forward(routes: &[String]) -> Result<(), HelloError> {
    #[cfg(target_os = "linux")]
    {
        linux_forward(routes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = routes;
        Err(HelloError::Node(
            "Subnet forwarding runs on Linux.".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_forward(routes: &[String]) -> Result<(), HelloError> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").map_err(|err| {
        HelloError::Node(format!("The node did not enable IPv4 forwarding. {err}"))
    })?;
    relax_rp_filter();
    for route in routes {
        forward_one(route)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn relax_rp_filter() {
    let Ok(entries) = std::fs::read_dir("/proc/sys/net/ipv4/conf") else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("rp_filter");
        let _ = std::fs::write(path, "0\n");
    }
}

#[cfg(target_os = "linux")]
fn forward_one(route: &str) -> Result<(), HelloError> {
    let (prefix, prefix_len) =
        parse_cidr(route).map_err(|err| HelloError::Node(err.to_string()))?;
    if prefix_len == 0 {
        return Err(HelloError::Node(
            "The route 0.0.0.0/0 is an exit route.".to_string(),
        ));
    }
    let probe = probe_address(prefix, prefix_len);
    let output = Command::new("ip")
        .args(["route", "get", &probe.to_string()])
        .output()
        .map_err(|err| HelloError::Node(format!("The ip command did not start. {err}")))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(HelloError::Node(format!(
            "The node did not find a route for {route}. {detail}"
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let Some(device) = connected_device(&text) else {
        println!("The route {route} is not a local network. The node does not forward it.");
        return Ok(());
    };
    if device == "orblx0" || device.starts_with("utun") {
        println!("The route {route} is not a local network. The node does not forward it.");
        return Ok(());
    }
    let destination = format!("{prefix}/{prefix_len}");
    ensure_rule(
        &[
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            "100.64.0.0/10",
            "-d",
            &destination,
            "-o",
            &device,
            "-j",
            "MASQUERADE",
        ],
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "100.64.0.0/10",
            "-d",
            &destination,
            "-o",
            &device,
            "-j",
            "MASQUERADE",
        ],
    )?;
    ensure_rule(
        &["-C", "FORWARD", "-d", &destination, "-j", "ACCEPT"],
        &["-A", "FORWARD", "-d", &destination, "-j", "ACCEPT"],
    )?;
    ensure_rule(
        &["-C", "FORWARD", "-s", &destination, "-j", "ACCEPT"],
        &["-A", "FORWARD", "-s", &destination, "-j", "ACCEPT"],
    )?;
    println!("The node forwards {destination} on {device}.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_rule(check: &[&str], add: &[&str]) -> Result<(), HelloError> {
    if iptables_ok(check)? {
        return Ok(());
    }
    iptables_must(add)
}

#[cfg(target_os = "linux")]
fn iptables_ok(args: &[&str]) -> Result<bool, HelloError> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|err| HelloError::Node(format!("The iptables command did not start. {err}")))?;
    Ok(output.status.success())
}

#[cfg(target_os = "linux")]
fn iptables_must(args: &[&str]) -> Result<(), HelloError> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|err| HelloError::Node(format!("The iptables command did not start. {err}")))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    Err(HelloError::Node(format!(
        "The iptables command failed. iptables {} {detail}",
        args.join(" ")
    )))
}

#[cfg(target_os = "linux")]
fn probe_address(prefix: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len >= 31 {
        return prefix;
    }
    Ipv4Addr::from(u32::from(prefix) | 1)
}

/// Return the output device when `ip route get` shows a connected route.
#[cfg(any(test, target_os = "linux"))]
fn connected_device(text: &str) -> Option<String> {
    if text.contains(" via ") {
        return None;
    }
    let mut parts = text.split_whitespace();
    while let Some(word) = parts.next() {
        if word == "dev" {
            return parts
                .next()
                .filter(|name| !name.is_empty())
                .map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::connected_device;

    #[test]
    fn a_connected_route_names_the_device() {
        let text = "10.88.0.1 dev eth1 src 10.88.0.2 uid 0 cache\n";
        assert_eq!(connected_device(text).as_deref(), Some("eth1"));
    }

    #[test]
    fn a_gateway_route_is_not_local() {
        let text = "10.99.0.1 via 172.18.0.1 dev eth0 src 172.18.0.3 uid 0 cache\n";
        assert_eq!(connected_device(text), None);
    }
}
