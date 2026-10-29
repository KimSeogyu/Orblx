//! Host routes for a client that uses an exit node.
//!
//! `0.0.0.0/0` goes to the TUN device through a dedicated routing table.
//! Coordinator, Relay, and peer underlay addresses stay on the physical path.
//! `--exit-node-allow-lan-access` keeps connected LAN prefixes on that path.

use std::net::Ipv4Addr;

/// Routing table for the exit-node default route.
#[cfg(target_os = "linux")]
pub const EXIT_TABLE: u32 = 5200;

/// One plan for the exit-node routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRoutePlan {
    /// The default route in the exit table uses the TUN device.
    pub default_via_tun: bool,
    /// Underlay addresses that stay outside the tunnel.
    pub exceptions: Vec<Ipv4Addr>,
    /// Connected prefixes that stay on the local interface.
    pub local_prefixes: Vec<String>,
}

/// Build the route plan for one selected exit node.
///
/// `connected` holds CIDRs of local interfaces.
/// `underlay` holds coordinator, Relay, and peer endpoint addresses.
/// `allow_lan` keeps `connected` on the local interface.
#[must_use]
pub fn plan_exit_routes(
    allow_lan: bool,
    connected: &[String],
    underlay: &[Ipv4Addr],
) -> ExitRoutePlan {
    let mut exceptions = underlay.to_vec();
    exceptions.sort_by_key(|ip| u32::from(*ip));
    exceptions.dedup();
    let local_prefixes = if allow_lan {
        let mut prefixes = connected.to_vec();
        prefixes.sort();
        prefixes.dedup();
        prefixes
    } else {
        Vec::new()
    };
    ExitRoutePlan {
        default_via_tun: true,
        exceptions,
        local_prefixes,
    }
}

/// Collect IPv4 underlay addresses from `host:port` endpoints.
#[must_use]
pub fn underlay_addresses(endpoints: &[String], extra: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let mut addresses = extra.to_vec();
    for endpoint in endpoints {
        if let Some(ip) = endpoint_ipv4(endpoint) {
            addresses.push(ip);
        }
    }
    addresses.sort_by_key(|ip| u32::from(*ip));
    addresses.dedup();
    addresses
}

fn endpoint_ipv4(endpoint: &str) -> Option<Ipv4Addr> {
    let (host, port) = endpoint.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    host.parse().ok()
}

/// Install the exit-node routing table.
///
/// The guard removes the rule when the node stops.
pub fn install_exit_routes(
    tun: &str,
    allow_lan: bool,
    underlay: &[Ipv4Addr],
) -> Result<ExitRouteGuard, crate::HelloError> {
    #[cfg(target_os = "linux")]
    {
        linux_install(tun, allow_lan, underlay)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tun, allow_lan, underlay);
        Err(crate::HelloError::Node(
            "Exit node routes run on Linux.".to_string(),
        ))
    }
}

/// Removes the exit-node routing rule.
pub struct ExitRouteGuard {
    #[cfg(target_os = "linux")]
    installed: bool,
}

impl Drop for ExitRouteGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.installed {
            let _ = run_ip(&["rule", "del", "pref", &EXIT_TABLE.to_string()]);
            let _ = run_ip(&["route", "flush", "table", &EXIT_TABLE.to_string()]);
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_install(
    tun: &str,
    allow_lan: bool,
    underlay: &[Ipv4Addr],
) -> Result<ExitRouteGuard, crate::HelloError> {
    use std::process::Command;

    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .map_err(|err| crate::HelloError::Node(format!("The ip command did not start. {err}")))?;
    if !output.status.success() {
        return Err(crate::HelloError::Node(
            "The node did not read the default route.".to_string(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let Some((gateway, device)) = default_path(&text) else {
        return Err(crate::HelloError::Node(
            "The node did not find a default route outside the tunnel.".to_string(),
        ));
    };
    if device == tun {
        return Err(crate::HelloError::Node(
            "The default route already uses the TUN device.".to_string(),
        ));
    }
    let connected = connected_prefixes();
    let plan = plan_exit_routes(allow_lan, &connected, underlay);
    let table = EXIT_TABLE.to_string();
    let _ = run_ip(&["route", "flush", "table", &table]);
    let _ = run_ip(&["rule", "del", "pref", &table]);
    for prefix in &plan.local_prefixes {
        if let Some(dev) = connected_device_for(prefix) {
            if dev == tun || dev == "lo" {
                continue;
            }
            run_ip(&["route", "replace", prefix, "dev", &dev, "table", &table])?;
        }
    }
    for address in &plan.exceptions {
        let cidr = format!("{address}/32");
        match gateway {
            Some(gateway) => {
                run_ip(&[
                    "route",
                    "replace",
                    &cidr,
                    "via",
                    &gateway.to_string(),
                    "dev",
                    &device,
                    "onlink",
                    "table",
                    &table,
                ])?;
            }
            None => {
                run_ip(&["route", "replace", &cidr, "dev", &device, "table", &table])?;
            }
        }
        println!("The node keeps {cidr} outside the tunnel.");
    }
    run_ip(&["route", "replace", "default", "dev", tun, "table", &table])?;
    run_ip(&["rule", "add", "pref", &table, "lookup", &table])?;
    Ok(ExitRouteGuard { installed: true })
}

#[cfg(target_os = "linux")]
fn connected_prefixes() -> Vec<String> {
    let Ok(output) = std::process::Command::new("ip")
        .args(["-4", "route", "show", "proto", "kernel", "scope", "link"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut prefixes = Vec::new();
    for line in text.lines() {
        let Some(prefix) = line.split_whitespace().next() else {
            continue;
        };
        if prefix.contains('/') {
            prefixes.push(prefix.to_string());
        }
    }
    prefixes
}

#[cfg(target_os = "linux")]
fn connected_device_for(prefix: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "route", "show", prefix])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    device_after_dev(&text)
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> Result<(), crate::HelloError> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|err| crate::HelloError::Node(format!("The ip command did not start. {err}")))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    Err(crate::HelloError::Node(format!(
        "The ip command failed. ip {} {detail}",
        args.join(" ")
    )))
}

/// Read `default via GATEWAY dev DEVICE` or `default dev DEVICE`.
#[cfg(any(test, target_os = "linux"))]
fn default_path(text: &str) -> Option<(Option<Ipv4Addr>, String)> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("default") {
            continue;
        }
        let mut gateway = None;
        let mut device = None;
        while let Some(word) = parts.next() {
            if word == "via" {
                gateway = parts.next().and_then(|text| text.parse().ok());
            } else if word == "dev" {
                device = parts.next().map(str::to_string);
            }
        }
        if let Some(device) = device {
            if device != "orblx0" && !device.starts_with("utun") {
                return Some((gateway, device));
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn device_after_dev(text: &str) -> Option<String> {
    let mut parts = text.split_whitespace();
    while let Some(word) = parts.next() {
        if word == "dev" {
            return parts.next().map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{default_path, plan_exit_routes, underlay_addresses};

    #[test]
    fn the_exit_plan_keeps_underlay_addresses_and_optional_lan_prefixes() {
        let underlay = [Ipv4Addr::new(172, 30, 19, 2), Ipv4Addr::new(172, 30, 19, 5)];
        let connected = ["172.30.19.0/24".to_string(), "10.0.0.0/24".to_string()];
        let blocked = plan_exit_routes(false, &connected, &underlay);
        assert!(blocked.default_via_tun);
        assert!(blocked.local_prefixes.is_empty());
        assert_eq!(blocked.exceptions, underlay);
        let open = plan_exit_routes(true, &connected, &underlay);
        assert_eq!(
            open.local_prefixes,
            vec!["10.0.0.0/24".to_string(), "172.30.19.0/24".to_string()]
        );
        assert_eq!(open.exceptions.len(), 2);
    }

    #[test]
    fn underlay_addresses_keep_ipv4_endpoints() {
        let extra = [Ipv4Addr::new(172, 30, 19, 2)];
        let addresses = underlay_addresses(
            &[
                "172.30.19.3:443".to_string(),
                "exit.example:443".to_string(),
                "172.30.19.3:443".to_string(),
            ],
            &extra,
        );
        assert_eq!(
            addresses,
            vec![Ipv4Addr::new(172, 30, 19, 2), Ipv4Addr::new(172, 30, 19, 3)]
        );
    }

    #[test]
    fn the_default_route_parser_skips_the_tunnel() {
        let text = "default dev orblx0\ndefault via 172.30.19.1 dev eth0\n";
        let (gateway, device) = default_path(text).unwrap();
        assert_eq!(gateway, Some(Ipv4Addr::new(172, 30, 19, 1)));
        assert_eq!(device, "eth0");
    }
}
