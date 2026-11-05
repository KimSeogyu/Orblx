//! Router port mapping for one UDP socket.
//!
//! The client asks the default gateway for a stable external UDP port.
//! It tries PCP, then NAT-PMP, then UPnP IGD.
//! Each try has a short wait. The whole probe has one budget.
//! A mapped port is a candidate that every peer can send to.
//! The client renews the map before the lifetime ends.
//! The client deletes the map on drop (clean shutdown).

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::EdgeError;

/// The wait for one mapping protocol.
///
/// The gateway is one hop away. A missing answer ends the try.
pub const PORT_MAP_SERVICE_WAIT: Duration = Duration::from_millis(250);

/// The longest probe when every protocol is silent.
///
/// Three tries use this budget. The Relay path waits no longer than this.
pub const PORT_MAP_BUDGET: Duration = Duration::from_millis(750);

/// The lifetime the client requests, in seconds.
///
/// NAT-PMP uses two hours. PCP uses the same value.
pub const PORT_MAP_LIFETIME_SECS: u32 = 7_200;

const PXP_PORT: u16 = 5_351;
const UPNP_PORT: u16 = 1_900;
const PCP_VERSION: u8 = 2;
const PCP_MAP: u8 = 1;
const PCP_REPLY: u8 = 0x80;
const PCP_UDP: u8 = 17;
const PCP_PACKET_LEN: usize = 60;
const PMP_VERSION: u8 = 0;
const PMP_OP_ADDR: u8 = 0;
const PMP_OP_UDP: u8 = 1;
const PMP_REPLY: u8 = 0x80;
const MAP_DESCRIPTION: &str = "orblx";

/// Which protocols the node may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMapChoice {
    /// PCP, then NAT-PMP, then UPnP IGD.
    Auto,
    /// Do not send a probe.
    Off,
    /// Send one protocol only.
    Only(PortMapProto),
}

/// One mapping protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMapProto {
    /// Port Control Protocol (RFC 6887) on UDP 5351.
    Pcp,
    /// NAT Port Mapping Protocol (RFC 6886) on UDP 5351.
    NatPmp,
    /// UPnP Internet Gateway Device.
    Upnp,
}

impl PortMapProto {
    /// The log word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pcp => "pcp",
            Self::NatPmp => "nat-pmp",
            Self::Upnp => "upnp",
        }
    }
}

/// Inputs for one probe.
#[derive(Debug, Clone, Copy)]
pub struct ProbeRequest {
    /// Auto, off, or one protocol.
    pub choice: PortMapChoice,
    /// The router address. `None` reads the default route.
    pub gateway: Option<Ipv4Addr>,
    /// The local UDP port to map.
    pub internal_port: u16,
    /// The lifetime to request, in seconds. Zero selects [`PORT_MAP_LIFETIME_SECS`].
    ///
    /// A value above [`PORT_MAP_LIFETIME_SECS`] is capped.
    pub lifetime_secs: u32,
    /// The longest wait for the whole probe.
    pub budget: Duration,
    /// A nonce kept across process starts.
    ///
    /// `Some` sends a delete for the previous map before the new map.
    /// The same nonce lets PCP remove the map after a crash.
    /// `None` creates a new nonce and does not send that delete.
    pub nonce: Option<[u8; 12]>,
}

/// Keep a nonce in `dir` so a later process can delete the same PCP map.
pub fn load_port_map_nonce(dir: &Path) -> Result<[u8; 12], EdgeError> {
    let path = dir.join("port-map-nonce");
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(nonce) = bytes.try_into() {
            return Ok(nonce);
        }
    }
    let nonce = random_nonce()?;
    fs::write(&path, nonce).map_err(|err| EdgeError::Io(err.to_string()))?;
    Ok(nonce)
}

/// The lifetime the client may request.
///
/// Zero and any value above [`PORT_MAP_LIFETIME_SECS`] become 7200 seconds.
fn bound_lifetime(requested: u32) -> u32 {
    if requested == 0 || requested > PORT_MAP_LIFETIME_SECS {
        PORT_MAP_LIFETIME_SECS
    } else {
        requested
    }
}

/// The result of one probe.
#[derive(Debug)]
pub struct ProbeReport {
    /// The time from the start of the probe to the end.
    pub elapsed: Duration,
    /// The map, when a router answered.
    pub mapping: Option<ActiveMap>,
}

/// A mapping that the router granted.
#[derive(Debug)]
pub struct ActiveMap {
    proto: PortMapProto,
    local_ip: Ipv4Addr,
    internal_port: u16,
    external: SocketAddr,
    lifetime_secs: u32,
    nonce: [u8; 12],
    control_url: String,
    service_urn: String,
    socket: Option<UdpSocket>,
    deleted: bool,
}

impl ActiveMap {
    /// The protocol that created the map.
    #[must_use]
    pub const fn protocol(&self) -> PortMapProto {
        self.proto
    }

    /// The external socket that peers send to.
    #[must_use]
    pub const fn external(&self) -> SocketAddr {
        self.external
    }

    /// The granted lifetime, in seconds.
    #[must_use]
    pub const fn lifetime_secs(&self) -> u32 {
        self.lifetime_secs
    }

    /// Ask the router to keep the same map.
    ///
    /// The call updates the external socket and the lifetime when the router changes them.
    pub fn renew(&mut self) -> Result<(), EdgeError> {
        if self.deleted {
            return Err(EdgeError::Io(
                "The port map is already deleted.".to_string(),
            ));
        }
        match self.proto {
            PortMapProto::Pcp => self.renew_pcp(),
            PortMapProto::NatPmp => self.renew_natpmp(),
            PortMapProto::Upnp => self.renew_upnp(),
        }
    }

    /// Tell the router to remove the map.
    ///
    /// A second call does nothing.
    pub fn delete(&mut self) -> Result<(), EdgeError> {
        if self.deleted {
            return Ok(());
        }
        self.deleted = true;
        match self.proto {
            PortMapProto::Pcp => self.delete_pcp(),
            PortMapProto::NatPmp => self.delete_natpmp(),
            PortMapProto::Upnp => self.delete_upnp(),
        }
    }

    fn renew_pcp(&mut self) -> Result<(), EdgeError> {
        let granted = pcp_exchange(
            self.socket()?,
            &self.pcp_body(self.external.port(), self.lifetime_secs),
            Instant::now() + PORT_MAP_SERVICE_WAIT,
            true,
        )?;
        self.external = granted.external;
        self.lifetime_secs = granted.lifetime_secs;
        Ok(())
    }

    fn renew_natpmp(&mut self) -> Result<(), EdgeError> {
        let granted = natpmp_map(
            self.socket()?,
            self.internal_port,
            self.external.port(),
            self.lifetime_secs,
            Instant::now() + PORT_MAP_SERVICE_WAIT,
        )?;
        self.external.set_port(granted.port);
        self.lifetime_secs = granted.lifetime_secs;
        Ok(())
    }

    fn renew_upnp(&mut self) -> Result<(), EdgeError> {
        upnp_add(
            &self.control_url,
            &self.service_urn,
            self.local_ip,
            self.internal_port,
            self.external.port(),
            self.lifetime_secs,
            PORT_MAP_SERVICE_WAIT,
        )?;
        Ok(())
    }

    fn delete_pcp(&mut self) -> Result<(), EdgeError> {
        let _ = pcp_exchange(
            self.socket()?,
            &self.pcp_body(self.external.port(), 0),
            Instant::now() + PORT_MAP_SERVICE_WAIT,
            false,
        )?;
        Ok(())
    }

    fn delete_natpmp(&mut self) -> Result<(), EdgeError> {
        let _ = natpmp_map(
            self.socket()?,
            self.internal_port,
            self.external.port(),
            0,
            Instant::now() + PORT_MAP_SERVICE_WAIT,
        )?;
        Ok(())
    }

    fn delete_upnp(&mut self) -> Result<(), EdgeError> {
        upnp_delete(
            &self.control_url,
            &self.service_urn,
            self.external.port(),
            PORT_MAP_SERVICE_WAIT,
        )
    }

    fn pcp_body(&self, suggest_port: u16, lifetime: u32) -> PcpBody {
        PcpBody {
            local_ip: self.local_ip,
            internal_port: self.internal_port,
            suggest_port,
            lifetime,
            nonce: self.nonce,
        }
    }

    fn socket(&self) -> Result<&UdpSocket, EdgeError> {
        self.socket
            .as_ref()
            .ok_or_else(|| EdgeError::Io("The port map socket is closed.".to_string()))
    }
}

impl Drop for ActiveMap {
    fn drop(&mut self) {
        if self.deleted {
            return;
        }
        if let Err(err) = self.delete() {
            eprintln!("The port map delete failed. {err}");
            return;
        }
        println!("The port map was deleted.");
    }
}

/// The endpoint list that the node publishes.
///
/// A mapped port is published twice.
/// The peer reads two equal ports as an endpoint-independent mapping.
/// The peer then punches that port.
/// Without a map, the list is the STUN list.
#[must_use]
pub fn candidate_texts(stun: &[String], mapped: Option<SocketAddr>) -> Vec<String> {
    match mapped {
        Some(addr) => {
            let text = addr.to_string();
            vec![text.clone(), text]
        }
        None => stun.to_vec(),
    }
}

/// Probe the gateway. The call does not retry a protocol that failed.
pub fn probe_port_map(request: ProbeRequest) -> ProbeReport {
    probe_with_ports(request, PXP_PORT, UPNP_PORT)
}

/// Probe on caller-selected ports. Tests use a free local port.
fn probe_with_ports(request: ProbeRequest, pxp_port: u16, upnp_port: u16) -> ProbeReport {
    let started = Instant::now();
    if matches!(request.choice, PortMapChoice::Off) {
        return ProbeReport {
            elapsed: Duration::ZERO,
            mapping: None,
        };
    }
    let lifetime = bound_lifetime(request.lifetime_secs);
    let Some(gateway) = request.gateway.or_else(default_gateway) else {
        return ProbeReport {
            elapsed: started.elapsed(),
            mapping: None,
        };
    };
    let Ok(local_ip) = local_ipv4(gateway) else {
        return ProbeReport {
            elapsed: started.elapsed(),
            mapping: None,
        };
    };
    let deadline = started + request.budget;
    let ctx = ProbeCtx {
        gateway,
        local_ip,
        internal_port: request.internal_port,
        lifetime,
        nonce: request.nonce,
        pxp_port,
        upnp_port,
    };
    release_previous(&ctx, request.choice, deadline);
    let mapping = match request.choice {
        PortMapChoice::Off => None,
        PortMapChoice::Only(proto) => try_proto(&ctx, proto, deadline),
        PortMapChoice::Auto => try_auto(&ctx, deadline),
    };
    ProbeReport {
        elapsed: started.elapsed(),
        mapping,
    }
}

/// How long a delete of a previous map may wait.
///
/// The delete runs before the new map. It does not block the relay path.
const RELEASE_WAIT: Duration = Duration::from_millis(100);

struct ProbeCtx {
    gateway: Ipv4Addr,
    local_ip: Ipv4Addr,
    internal_port: u16,
    lifetime: u32,
    nonce: Option<[u8; 12]>,
    pxp_port: u16,
    upnp_port: u16,
}

/// Delete a map left by a crashed process.
///
/// PCP matches the saved nonce. NAT-PMP matches the internal UDP port.
/// UPnP deletes the same external port the client requests.
fn release_previous(ctx: &ProbeCtx, choice: PortMapChoice, deadline: Instant) {
    let Some(nonce) = ctx.nonce else {
        return;
    };
    let limit = (Instant::now() + RELEASE_WAIT).min(deadline);
    println!("The previous port map delete was sent.");
    if matches!(
        choice,
        PortMapChoice::Auto | PortMapChoice::Only(PortMapProto::Pcp)
    ) {
        if let Ok(socket) = udp_client(ctx.local_ip, SocketAddr::from((ctx.gateway, ctx.pxp_port)))
        {
            let body = PcpBody {
                local_ip: ctx.local_ip,
                internal_port: ctx.internal_port,
                suggest_port: ctx.internal_port,
                lifetime: 0,
                nonce,
            };
            let _ = pcp_exchange(&socket, &body, limit, false);
        }
    }
    if matches!(
        choice,
        PortMapChoice::Auto | PortMapChoice::Only(PortMapProto::NatPmp)
    ) {
        if let Ok(socket) = udp_client(ctx.local_ip, SocketAddr::from((ctx.gateway, ctx.pxp_port)))
        {
            let _ = natpmp_map(&socket, ctx.internal_port, ctx.internal_port, 0, limit);
        }
    }
    if matches!(
        choice,
        PortMapChoice::Auto | PortMapChoice::Only(PortMapProto::Upnp)
    ) {
        if let Ok(location) = upnp_location(ctx.local_ip, ctx.gateway, ctx.upnp_port, limit) {
            if let Ok((urn, control)) = upnp_control(&location, limit) {
                let _ = upnp_delete(
                    &control,
                    &urn,
                    ctx.internal_port,
                    limit.saturating_duration_since(Instant::now()),
                );
            }
        }
    }
}

fn try_auto(ctx: &ProbeCtx, deadline: Instant) -> Option<ActiveMap> {
    for proto in [PortMapProto::Pcp, PortMapProto::NatPmp, PortMapProto::Upnp] {
        if Instant::now() >= deadline {
            return None;
        }
        let slice = Instant::now() + PORT_MAP_SERVICE_WAIT;
        let limit = if slice < deadline { slice } else { deadline };
        if let Some(mapping) = try_proto(ctx, proto, limit) {
            return Some(mapping);
        }
    }
    None
}

fn try_proto(ctx: &ProbeCtx, proto: PortMapProto, deadline: Instant) -> Option<ActiveMap> {
    match proto {
        PortMapProto::Pcp => try_pcp(ctx, deadline),
        PortMapProto::NatPmp => try_natpmp(ctx, deadline),
        PortMapProto::Upnp => try_upnp(ctx, deadline),
    }
}

struct Granted {
    external: SocketAddr,
    lifetime_secs: u32,
    nonce: [u8; 12],
}

fn try_pcp(ctx: &ProbeCtx, deadline: Instant) -> Option<ActiveMap> {
    let socket = udp_client(ctx.local_ip, SocketAddr::from((ctx.gateway, ctx.pxp_port))).ok()?;
    let nonce = match ctx.nonce {
        Some(nonce) => nonce,
        None => random_nonce().ok()?,
    };
    let body = PcpBody {
        local_ip: ctx.local_ip,
        internal_port: ctx.internal_port,
        suggest_port: ctx.internal_port,
        lifetime: ctx.lifetime,
        nonce,
    };
    let granted = pcp_exchange(&socket, &body, deadline, true).ok()?;
    Some(ActiveMap {
        proto: PortMapProto::Pcp,
        local_ip: ctx.local_ip,
        internal_port: ctx.internal_port,
        external: granted.external,
        lifetime_secs: granted.lifetime_secs,
        nonce: granted.nonce,
        control_url: String::new(),
        service_urn: String::new(),
        socket: Some(socket),
        deleted: false,
    })
}

fn try_natpmp(ctx: &ProbeCtx, deadline: Instant) -> Option<ActiveMap> {
    let socket = udp_client(ctx.local_ip, SocketAddr::from((ctx.gateway, ctx.pxp_port))).ok()?;
    let external_ip = natpmp_external(&socket, deadline).ok()?;
    let mapped = natpmp_map(
        &socket,
        ctx.internal_port,
        ctx.internal_port,
        ctx.lifetime,
        deadline,
    )
    .ok()?;
    Some(ActiveMap {
        proto: PortMapProto::NatPmp,
        local_ip: ctx.local_ip,
        internal_port: ctx.internal_port,
        external: SocketAddr::from((external_ip, mapped.port)),
        lifetime_secs: mapped.lifetime_secs,
        nonce: [0; 12],
        control_url: String::new(),
        service_urn: String::new(),
        socket: Some(socket),
        deleted: false,
    })
}

fn try_upnp(ctx: &ProbeCtx, deadline: Instant) -> Option<ActiveMap> {
    let location = upnp_location(ctx.local_ip, ctx.gateway, ctx.upnp_port, deadline).ok()?;
    let (urn, control) = upnp_control(&location, deadline).ok()?;
    let external_ip = upnp_external_ip(&control, &urn, deadline).ok()?;
    upnp_add(
        &control,
        &urn,
        ctx.local_ip,
        ctx.internal_port,
        ctx.internal_port,
        ctx.lifetime,
        deadline.saturating_duration_since(Instant::now()),
    )
    .ok()?;
    Some(ActiveMap {
        proto: PortMapProto::Upnp,
        local_ip: ctx.local_ip,
        internal_port: ctx.internal_port,
        external: SocketAddr::from((external_ip, ctx.internal_port)),
        lifetime_secs: ctx.lifetime,
        nonce: [0; 12],
        control_url: control,
        service_urn: urn,
        socket: None,
        deleted: false,
    })
}

struct PcpBody {
    local_ip: Ipv4Addr,
    internal_port: u16,
    suggest_port: u16,
    lifetime: u32,
    nonce: [u8; 12],
}

fn pcp_exchange(
    socket: &UdpSocket,
    body: &PcpBody,
    deadline: Instant,
    require_external: bool,
) -> Result<Granted, EdgeError> {
    let packet = pcp_request(
        body.local_ip,
        body.internal_port,
        body.suggest_port,
        body.lifetime,
        body.nonce,
    );
    socket
        .send(&packet)
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let buf = recv_until(socket, deadline)?;
    parse_pcp_response(&buf, body.nonce, require_external)
}

fn pcp_request(
    local_ip: Ipv4Addr,
    internal_port: u16,
    suggest_port: u16,
    lifetime: u32,
    nonce: [u8; 12],
) -> [u8; PCP_PACKET_LEN] {
    let mut packet = [0u8; PCP_PACKET_LEN];
    packet[0] = PCP_VERSION;
    packet[1] = PCP_MAP;
    packet[4..8].copy_from_slice(&lifetime.to_be_bytes());
    packet[8..24].copy_from_slice(&ipv4_mapped(local_ip));
    packet[24..36].copy_from_slice(&nonce);
    packet[36] = PCP_UDP;
    packet[40..42].copy_from_slice(&internal_port.to_be_bytes());
    packet[42..44].copy_from_slice(&suggest_port.to_be_bytes());
    packet
}

fn parse_pcp_response(
    buf: &[u8],
    nonce: [u8; 12],
    require_external: bool,
) -> Result<Granted, EdgeError> {
    if buf.len() < PCP_PACKET_LEN || buf[0] != PCP_VERSION || buf[1] != (PCP_MAP | PCP_REPLY) {
        return Err(EdgeError::Io(
            "The PCP response is not a MAP reply.".to_string(),
        ));
    }
    if buf[3] != 0 {
        return Err(EdgeError::Io(format!("The PCP result code is {}.", buf[3])));
    }
    if buf[24..36] != nonce {
        return Err(EdgeError::Io("The PCP nonce does not match.".to_string()));
    }
    let lifetime_secs = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let port = u16::from_be_bytes([buf[42], buf[43]]);
    let ip = ipv4_from_pcp(&buf[44..60]).unwrap_or(Ipv4Addr::UNSPECIFIED);
    if require_external && (port == 0 || ip.is_unspecified()) {
        return Err(EdgeError::Io(
            "The PCP map has no external socket.".to_string(),
        ));
    }
    Ok(Granted {
        external: SocketAddr::from((ip, port)),
        lifetime_secs,
        nonce,
    })
}

struct NatPmpPort {
    port: u16,
    lifetime_secs: u32,
}

fn natpmp_external(socket: &UdpSocket, deadline: Instant) -> Result<Ipv4Addr, EdgeError> {
    socket
        .send(&[PMP_VERSION, PMP_OP_ADDR])
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let buf = recv_until(socket, deadline)?;
    if buf.len() < 12 || buf[0] != PMP_VERSION || buf[1] != (PMP_OP_ADDR | PMP_REPLY) {
        return Err(EdgeError::Io(
            "The NAT-PMP address response is not valid.".to_string(),
        ));
    }
    let code = u16::from_be_bytes([buf[2], buf[3]]);
    if code != 0 {
        return Err(EdgeError::Io(format!(
            "The NAT-PMP address result code is {code}."
        )));
    }
    Ok(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

fn natpmp_map(
    socket: &UdpSocket,
    internal_port: u16,
    suggest_port: u16,
    lifetime: u32,
    deadline: Instant,
) -> Result<NatPmpPort, EdgeError> {
    let mut packet = [0u8; 12];
    packet[0] = PMP_VERSION;
    packet[1] = PMP_OP_UDP;
    packet[4..6].copy_from_slice(&internal_port.to_be_bytes());
    packet[6..8].copy_from_slice(&suggest_port.to_be_bytes());
    packet[8..12].copy_from_slice(&lifetime.to_be_bytes());
    socket
        .send(&packet)
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let buf = recv_until(socket, deadline)?;
    if buf.len() < 16 || buf[0] != PMP_VERSION || buf[1] != (PMP_OP_UDP | PMP_REPLY) {
        return Err(EdgeError::Io(
            "The NAT-PMP map response is not valid.".to_string(),
        ));
    }
    let code = u16::from_be_bytes([buf[2], buf[3]]);
    if code != 0 {
        return Err(EdgeError::Io(format!(
            "The NAT-PMP map result code is {code}."
        )));
    }
    let port = u16::from_be_bytes([buf[10], buf[11]]);
    let lifetime_secs = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if lifetime != 0 && (port == 0 || lifetime_secs == 0) {
        return Err(EdgeError::Io(
            "The NAT-PMP map has no external port.".to_string(),
        ));
    }
    Ok(NatPmpPort {
        port,
        lifetime_secs,
    })
}

fn upnp_location(
    local_ip: Ipv4Addr,
    gateway: Ipv4Addr,
    upnp_port: u16,
    deadline: Instant,
) -> Result<String, EdgeError> {
    let socket = UdpSocket::bind(SocketAddr::from((local_ip, 0)))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let _ = socket.set_multicast_ttl_v4(1);
    let gateway_dest = SocketAddr::from((gateway, upnp_port));
    send_search(&socket, gateway_dest, &format!("{gateway}:{upnp_port}"))?;
    if upnp_port == UPNP_PORT {
        let multi = SocketAddr::from((Ipv4Addr::new(239, 255, 255, 250), UPNP_PORT));
        let _ = send_search(&socket, multi, "239.255.255.250:1900");
    }
    let buf = recv_from_until(&socket, deadline)?;
    let text = String::from_utf8_lossy(&buf);
    ssdp_location(&text)
        .map(str::to_string)
        .ok_or_else(|| EdgeError::Io("The UPnP search has no LOCATION.".to_string()))
}

fn send_search(socket: &UdpSocket, dest: SocketAddr, host: &str) -> Result<(), EdgeError> {
    let body = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {host}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    );
    socket
        .send_to(body.as_bytes(), dest)
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    Ok(())
}

fn ssdp_location(text: &str) -> Option<&str> {
    for line in text.split(['\r', '\n']) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("location") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn upnp_control(location: &str, deadline: Instant) -> Result<(String, String), EdgeError> {
    let xml = http_get(location, deadline.saturating_duration_since(Instant::now()))?;
    let (urn, control) = pick_service(&xml).ok_or_else(|| {
        EdgeError::Io("The UPnP description has no WAN connection service.".to_string())
    })?;
    let absolute = absolute_control(location, &control)?;
    Ok((urn, absolute))
}

fn pick_service(xml: &str) -> Option<(String, String)> {
    let mut best: Option<(u8, String, String)> = None;
    let mut rest = xml;
    while let Some(start) = rest.find("<service>") {
        let after = &rest[start + "<service>".len()..];
        let end = after.find("</service>").unwrap_or(after.len());
        let block = &after[..end];
        if let (Some(kind), Some(url)) = (
            tag_text(block, "serviceType"),
            tag_text(block, "controlURL"),
        ) {
            if let Some(rank) = service_rank(&kind) {
                let replace = best.as_ref().is_none_or(|(old, _, _)| rank < *old);
                if replace {
                    best = Some((rank, kind, url));
                }
            }
        }
        rest = &after[end..];
    }
    best.map(|(_, kind, url)| (kind, url))
}

fn service_rank(kind: &str) -> Option<u8> {
    if kind.contains("WANIPConnection:1") {
        Some(0)
    } else if kind.contains("WANIPConnection:2") {
        Some(1)
    } else if kind.contains("WANPPPConnection:1") {
        Some(2)
    } else if kind.contains("WANPPPConnection:2") {
        Some(3)
    } else {
        None
    }
}

fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(xml[start..end].trim().to_string())
}

fn absolute_control(location: &str, control: &str) -> Result<String, EdgeError> {
    if control.starts_with("http://") {
        return Ok(control.to_string());
    }
    let base = http_origin(location)?;
    if let Some(path) = control.strip_prefix('/') {
        return Ok(format!("{base}/{path}"));
    }
    Ok(format!("{base}/{control}"))
}

fn upnp_external_ip(control: &str, urn: &str, deadline: Instant) -> Result<Ipv4Addr, EdgeError> {
    let body = soap_envelope(urn, "GetExternalIPAddress", "");
    let response = soap_post(
        control,
        urn,
        "GetExternalIPAddress",
        &body,
        deadline.saturating_duration_since(Instant::now()),
    )?;
    let text = tag_text(&response, "NewExternalIPAddress")
        .ok_or_else(|| EdgeError::Io("The UPnP response has no external address.".to_string()))?;
    text.parse::<Ipv4Addr>()
        .map_err(|_| EdgeError::Io("The UPnP external address is not IPv4.".to_string()))
}

fn upnp_add(
    control: &str,
    urn: &str,
    local_ip: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
    timeout: Duration,
) -> Result<(), EdgeError> {
    let inner = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>{internal_port}</NewInternalPort><NewInternalClient>{local_ip}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{MAP_DESCRIPTION}</NewPortMappingDescription><NewLeaseDuration>{lifetime}</NewLeaseDuration>"
    );
    let body = soap_envelope(urn, "AddPortMapping", &inner);
    let _ = soap_post(control, urn, "AddPortMapping", &body, timeout)?;
    Ok(())
}

fn upnp_delete(
    control: &str,
    urn: &str,
    external_port: u16,
    timeout: Duration,
) -> Result<(), EdgeError> {
    let inner = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort><NewProtocol>UDP</NewProtocol>"
    );
    let body = soap_envelope(urn, "DeletePortMapping", &inner);
    let _ = soap_post(control, urn, "DeletePortMapping", &body, timeout)?;
    Ok(())
}

fn soap_envelope(urn: &str, action: &str, inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{urn}\">{inner}</u:{action}></s:Body></s:Envelope>"
    )
}

fn soap_post(
    control: &str,
    urn: &str,
    action: &str,
    body: &str,
    timeout: Duration,
) -> Result<String, EdgeError> {
    let url = parse_http_url(control)?;
    let mut stream = tcp_connect(&url, timeout)?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHOST: {host}:{port}\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nSOAPACTION: \"{urn}#{action}\"\r\nCONTENT-LENGTH: {len}\r\nCONNECTION: close\r\n\r\n",
        path = url.path,
        host = url.host,
        port = url.port,
        len = body.len(),
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    stream
        .write_all(body.as_bytes())
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let response = read_http(&mut stream)?;
    if !http_ok(&response) {
        return Err(EdgeError::Io(format!("The UPnP {action} call failed.")));
    }
    Ok(response)
}

fn http_get(url: &str, timeout: Duration) -> Result<String, EdgeError> {
    let parsed = parse_http_url(url)?;
    let mut stream = tcp_connect(&parsed, timeout)?;
    let head = format!(
        "GET {path} HTTP/1.1\r\nHOST: {host}:{port}\r\nCONNECTION: close\r\n\r\n",
        path = parsed.path,
        host = parsed.host,
        port = parsed.port,
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    let response = read_http(&mut stream)?;
    if !http_ok(&response) {
        return Err(EdgeError::Io(
            "The UPnP description request failed.".to_string(),
        ));
    }
    Ok(response)
}

struct HttpUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(text: &str) -> Result<HttpUrl, EdgeError> {
    let Some(rest) = text.strip_prefix("http://") else {
        return Err(EdgeError::Io(
            "The UPnP URL is not an HTTP URL.".to_string(),
        ));
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| EdgeError::Io("The UPnP URL port is not valid.".to_string()))?;
            (host.to_string(), port)
        }
        None => (host_port.to_string(), 80),
    };
    if host.is_empty() {
        return Err(EdgeError::Io("The UPnP URL host is empty.".to_string()));
    }
    Ok(HttpUrl { host, port, path })
}

fn http_origin(location: &str) -> Result<String, EdgeError> {
    let url = parse_http_url(location)?;
    Ok(format!("http://{}:{}", url.host, url.port))
}

fn tcp_connect(url: &HttpUrl, timeout: Duration) -> Result<TcpStream, EdgeError> {
    let timeout = if timeout.is_zero() {
        Duration::from_millis(1)
    } else {
        timeout
    };
    let addr = format!("{}:{}", url.host, url.port);
    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|_| EdgeError::Io("The UPnP host is not a socket address.".to_string()))?,
        timeout,
    )
    .map_err(|err| EdgeError::Io(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    Ok(stream)
}

fn read_http(stream: &mut TcpStream) -> Result<String, EdgeError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if buf.len() > 65_536 {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => buf.extend_from_slice(&chunk[..size]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => break,
            Err(err) => return Err(EdgeError::Io(err.to_string())),
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn http_ok(response: &str) -> bool {
    let status = response.lines().next().unwrap_or("");
    status.contains(" 200 ") && !response.contains(":Fault") && !response.contains("<Fault")
}

fn udp_client(local_ip: Ipv4Addr, dest: SocketAddr) -> Result<UdpSocket, EdgeError> {
    let socket = UdpSocket::bind(SocketAddr::from((local_ip, 0)))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    socket
        .connect(dest)
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    Ok(socket)
}

fn recv_from_until(socket: &UdpSocket, deadline: Instant) -> Result<Vec<u8>, EdgeError> {
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(EdgeError::Timeout);
        }
        socket
            .set_read_timeout(Some(left))
            .map_err(|err| EdgeError::Io(err.to_string()))?;
        match socket.recv_from(&mut buf) {
            Ok((size, _)) => return Ok(buf[..size].to_vec()),
            Err(err) if is_timeout(&err) => return Err(EdgeError::Timeout),
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Err(EdgeError::Timeout);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(EdgeError::Io(err.to_string())),
        }
    }
}

fn recv_until(socket: &UdpSocket, deadline: Instant) -> Result<Vec<u8>, EdgeError> {
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(EdgeError::Timeout);
        }
        socket
            .set_read_timeout(Some(left))
            .map_err(|err| EdgeError::Io(err.to_string()))?;
        match socket.recv(&mut buf) {
            Ok(size) => return Ok(buf[..size].to_vec()),
            Err(err) if is_timeout(&err) => return Err(EdgeError::Timeout),
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Err(EdgeError::Timeout);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(EdgeError::Io(err.to_string())),
        }
    }
}

fn is_timeout(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut
}

fn ipv4_mapped(ip: Ipv4Addr) -> [u8; 16] {
    let oct = ip.octets();
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..].copy_from_slice(&oct);
    out
}

fn ipv4_from_pcp(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() != 16 {
        return None;
    }
    let mapped =
        bytes[0..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff;
    let plain = bytes[0..12].iter().all(|byte| *byte == 0);
    if mapped || plain {
        Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else {
        None
    }
}

fn random_nonce() -> Result<[u8; 12], EdgeError> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|err| EdgeError::Io(err.to_string()))?;
    Ok(nonce)
}

fn local_ipv4(gateway: Ipv4Addr) -> Result<Ipv4Addr, EdgeError> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    socket
        .connect(SocketAddr::from((gateway, 1)))
        .map_err(|err| EdgeError::Io(err.to_string()))?;
    match socket
        .local_addr()
        .map_err(|err| EdgeError::Io(err.to_string()))?
        .ip()
    {
        IpAddr::V4(ip) if !ip.is_unspecified() => Ok(ip),
        _ => Err(EdgeError::Io(
            "The node did not find a local IPv4 address.".to_string(),
        )),
    }
}

fn default_gateway() -> Option<Ipv4Addr> {
    let text = fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        if let Some(ip) = gateway_from_route_line(line) {
            return Some(ip);
        }
    }
    None
}

fn gateway_from_route_line(line: &str) -> Option<Ipv4Addr> {
    let mut cols = line.split_whitespace();
    let _iface = cols.next()?;
    let dest = cols.next()?;
    let gateway = cols.next()?;
    if dest != "00000000" {
        return None;
    }
    let raw = u32::from_str_radix(gateway, 16).ok()?;
    if raw == 0 {
        return None;
    }
    Some(Ipv4Addr::from(raw.to_le_bytes()))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        bound_lifetime, candidate_texts, gateway_from_route_line, pcp_request, probe_port_map,
        ssdp_location, PortMapChoice, PortMapProto, ProbeRequest, PCP_PACKET_LEN, PORT_MAP_BUDGET,
        PORT_MAP_LIFETIME_SECS, PORT_MAP_SERVICE_WAIT,
    };
    use crate::birthday::{peer_kind, strategy, MappingKind, Strategy};

    #[test]
    fn route_line_decodes_a_little_endian_gateway() {
        let line = "eth0 00000000 0101A8C0 0003 0 0 0 00000000 0 0 0";
        assert_eq!(
            gateway_from_route_line(line),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(gateway_from_route_line("eth0 00000001 0101A8C0"), None);
    }

    #[test]
    fn lifetime_request_is_capped_at_two_hours() {
        assert_eq!(bound_lifetime(0), PORT_MAP_LIFETIME_SECS);
        assert_eq!(bound_lifetime(40), 40);
        assert_eq!(bound_lifetime(u32::MAX), PORT_MAP_LIFETIME_SECS);
    }

    #[test]
    fn pcp_request_uses_the_rfc_fields() {
        let nonce = [9u8; 12];
        let packet = pcp_request(Ipv4Addr::new(10, 1, 2, 3), 443, 443, 40, nonce);
        assert_eq!(packet.len(), PCP_PACKET_LEN);
        assert_eq!(packet[0], 2);
        assert_eq!(packet[1], 1);
        assert_eq!(&packet[4..8], &40u32.to_be_bytes());
        assert_eq!(&packet[8..18], &[0u8; 10]);
        assert_eq!(&packet[18..20], &[0xff, 0xff]);
        assert_eq!(&packet[20..24], &[10, 1, 2, 3]);
        assert_eq!(&packet[24..36], &nonce);
        assert_eq!(packet[36], 17);
        assert_eq!(&packet[40..42], &443u16.to_be_bytes());
        assert_eq!(&packet[42..44], &443u16.to_be_bytes());
    }

    #[test]
    fn mapped_candidates_read_as_endpoint_independent() {
        let stun = vec![
            "203.0.113.5:40000".to_string(),
            "203.0.113.5:40010".to_string(),
        ];
        let mapped = "203.0.113.8:443".parse().unwrap();
        let texts = candidate_texts(&stun, Some(mapped));
        assert_eq!(texts, vec!["203.0.113.8:443", "203.0.113.8:443"]);
        let addrs: Vec<_> = texts.iter().map(|text| text.parse().unwrap()).collect();
        assert_eq!(peer_kind(&addrs), MappingKind::Easy);
        assert_eq!(
            strategy(MappingKind::Easy, MappingKind::Hard),
            Strategy::Spray
        );
        assert_eq!(
            strategy(MappingKind::Hard, MappingKind::Easy),
            Strategy::Sockets
        );
        assert_eq!(candidate_texts(&stun, None), stun);
    }

    #[test]
    fn ssdp_location_reads_the_header() {
        let text = "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1:5000/rootDesc.xml\r\nST: x\r\n";
        assert_eq!(
            ssdp_location(text),
            Some("http://10.0.0.1:5000/rootDesc.xml")
        );
    }

    #[test]
    fn off_does_not_wait() {
        let started = Instant::now();
        let report = probe_port_map(ProbeRequest {
            choice: PortMapChoice::Off,
            gateway: Some(Ipv4Addr::LOCALHOST),
            internal_port: 443,
            lifetime_secs: 40,
            budget: PORT_MAP_BUDGET,
            nonce: None,
        });
        assert!(report.mapping.is_none());
        assert!(report.elapsed.is_zero());
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn silent_pcp_stops_at_the_service_wait() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let started = Instant::now();
        let report = probe_port_map_at(PortMapChoice::Only(PortMapProto::Pcp), port, port, 400);
        assert!(report.mapping.is_none());
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(200));
        assert!(elapsed < PORT_MAP_SERVICE_WAIT + Duration::from_millis(800));
        drop(socket);
    }

    #[test]
    fn pcp_server_grants_renews_and_deletes() {
        let seen = Arc::new(Mutex::new(Vec::<u32>::new()));
        let seen_thread = Arc::clone(&seen);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
            for _ in 0..3 {
                let Ok((size, from)) = socket.recv_from(&mut buf) else {
                    return;
                };
                if size < 48 {
                    continue;
                }
                let lifetime = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                seen_thread.lock().unwrap().push(lifetime);
                let mut reply = [0u8; 60];
                reply[0] = 2;
                reply[1] = 0x81;
                reply[4..8].copy_from_slice(&lifetime.to_be_bytes());
                reply[24..36].copy_from_slice(&buf[24..36]);
                reply[36] = 17;
                reply[40..42].copy_from_slice(&buf[40..42]);
                reply[42..44].copy_from_slice(&40000u16.to_be_bytes());
                reply[44 + 10] = 0xff;
                reply[44 + 11] = 0xff;
                reply[44 + 12] = 203;
                reply[44 + 13] = 0;
                reply[44 + 14] = 113;
                reply[44 + 15] = 9;
                let _ = socket.send_to(&reply, from);
            }
        });
        let mut report =
            probe_port_map_at(PortMapChoice::Only(PortMapProto::Pcp), port, port, 2_000);
        let mapping = report.mapping.as_mut().expect("pcp map");
        assert_eq!(mapping.protocol(), PortMapProto::Pcp);
        assert_eq!(mapping.external().to_string(), "203.0.113.9:40000");
        assert_eq!(mapping.lifetime_secs(), 40);
        mapping.renew().unwrap();
        mapping.delete().unwrap();
        let lifetimes = seen.lock().unwrap().clone();
        assert_eq!(lifetimes.first().copied(), Some(40));
        assert!(lifetimes.contains(&40));
        assert!(lifetimes.contains(&0));
    }

    #[test]
    fn a_restart_sends_a_pcp_delete_with_the_saved_nonce() {
        let seen = Arc::new(Mutex::new(Vec::<(u32, [u8; 12])>::new()));
        let seen_thread = Arc::clone(&seen);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
            for _ in 0..4 {
                let Ok((size, from)) = socket.recv_from(&mut buf) else {
                    return;
                };
                if size < 48 {
                    continue;
                }
                let lifetime = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&buf[24..36]);
                seen_thread.lock().unwrap().push((lifetime, nonce));
                let mut reply = [0u8; 60];
                reply[0] = 2;
                reply[1] = 0x81;
                reply[4..8].copy_from_slice(&lifetime.to_be_bytes());
                reply[24..36].copy_from_slice(&nonce);
                reply[36] = 17;
                reply[40..42].copy_from_slice(&buf[40..42]);
                if lifetime == 0 {
                    reply[42..44].copy_from_slice(&0u16.to_be_bytes());
                } else {
                    reply[42..44].copy_from_slice(&40000u16.to_be_bytes());
                    reply[44 + 10] = 0xff;
                    reply[44 + 11] = 0xff;
                    reply[44 + 12] = 203;
                    reply[44 + 13] = 0;
                    reply[44 + 14] = 113;
                    reply[44 + 15] = 9;
                }
                let _ = socket.send_to(&reply, from);
            }
        });
        let nonce = [7u8; 12];
        let mut request = ProbeRequest {
            choice: PortMapChoice::Only(PortMapProto::Pcp),
            gateway: Some(Ipv4Addr::LOCALHOST),
            internal_port: 443,
            lifetime_secs: 40,
            budget: Duration::from_millis(2_000),
            nonce: Some(nonce),
        };
        let report = super::probe_with_ports(request, port, port);
        let mapping = report.mapping.expect("pcp map");
        assert_eq!(mapping.external().port(), 40_000);
        // A crash skips Drop. The next start must delete the old map.
        std::mem::forget(mapping);
        request.lifetime_secs = 9_999;
        let report = super::probe_with_ports(request, port, port);
        let mapping = report.mapping.expect("pcp map after restart");
        assert_eq!(mapping.lifetime_secs(), PORT_MAP_LIFETIME_SECS);
        std::mem::forget(mapping);
        let rows = seen.lock().unwrap().clone();
        assert!(rows.len() >= 4);
        assert_eq!(rows[0], (0, nonce));
        assert_eq!(rows[1].0, 40);
        assert_eq!(rows[1].1, nonce);
        assert_eq!(rows[2], (0, nonce));
        assert_eq!(rows[3].0, PORT_MAP_LIFETIME_SECS);
        assert_eq!(rows[3].1, nonce);
        assert_eq!(rows[1].1, rows[0].1);
    }

    #[test]
    fn natpmp_server_grants_a_port() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 64];
            let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
            for _ in 0..2 {
                let Ok((size, from)) = socket.recv_from(&mut buf) else {
                    return;
                };
                if size >= 2 && buf[1] == 0 {
                    let mut reply = [0u8; 12];
                    reply[1] = 128;
                    reply[8..12].copy_from_slice(&[203, 0, 113, 8]);
                    let _ = socket.send_to(&reply, from);
                } else if size >= 12 && buf[1] == 1 {
                    let mut reply = [0u8; 16];
                    reply[1] = 129;
                    reply[8..10].copy_from_slice(&buf[4..6]);
                    reply[10..12].copy_from_slice(&50000u16.to_be_bytes());
                    reply[12..16].copy_from_slice(&buf[8..12]);
                    let _ = socket.send_to(&reply, from);
                }
            }
        });
        let report =
            probe_port_map_at(PortMapChoice::Only(PortMapProto::NatPmp), port, port, 2_000);
        let mapping = report.mapping.expect("nat-pmp map");
        assert_eq!(mapping.external().to_string(), "203.0.113.8:50000");
        assert_eq!(mapping.lifetime_secs(), 40);
    }

    #[test]
    fn upnp_server_grants_the_requested_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let http_port = listener.local_addr().unwrap().port();
        let ssdp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ssdp_port = ssdp.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let _ = ssdp.set_read_timeout(Some(Duration::from_secs(2)));
            if let Ok((_, from)) = ssdp.recv_from(&mut buf) {
                let text = format!(
                    "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{http_port}/rootDesc.xml\r\n\r\n"
                );
                let _ = ssdp.send_to(text.as_bytes(), from);
            }
        });
        thread::spawn(move || {
            let _ = listener.set_nonblocking(false);
            for _ in 0..3 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 4096];
                let Ok(size) = stream.read(&mut buf) else {
                    return;
                };
                let req = String::from_utf8_lossy(&buf[..size]);
                let body = if req.contains("rootDesc.xml") {
                    "<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service></root>".to_string()
                } else if req.contains("GetExternalIPAddress") {
                    "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>".to_string()
                } else {
                    "<ok/>".to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nCONTENT-LENGTH: {}\r\nCONNECTION: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let report =
            probe_port_map_at(PortMapChoice::Only(PortMapProto::Upnp), 9, ssdp_port, 2_000);
        let mapping = report.mapping.expect("upnp map");
        assert_eq!(mapping.protocol(), PortMapProto::Upnp);
        assert_eq!(mapping.external().to_string(), "203.0.113.7:443");
    }

    fn probe_port_map_at(
        choice: PortMapChoice,
        pxp_port: u16,
        upnp_port: u16,
        budget_ms: u64,
    ) -> super::ProbeReport {
        super::probe_with_ports(
            ProbeRequest {
                choice,
                gateway: Some(Ipv4Addr::LOCALHOST),
                internal_port: 443,
                lifetime_secs: 40,
                budget: Duration::from_millis(budget_ms),
                nonce: None,
            },
            pxp_port,
            upnp_port,
        )
    }
}
