use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use orblx_identity::SpiffeId;

use crate::error::CoordError;
use crate::netmap::{
    decode_hex_32, verify_signed_endpoint, verify_signed_grants, verify_signed_netmap, SignedNetmap,
};
use crate::proto::{self, Request, Response};
use crate::state::{read_node_material, EnrollResult, NetmapView, NodeMaterial};
use crate::ticket::{decode_ticket_wire, IssuedTicket};
use crate::tlsutil::{self, ClientTls};

/// Enroll with a one-use token.
pub async fn enroll_with_token(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    name: &str,
    token: &str,
    endpoints: &[String],
    routes: &[String],
) -> Result<EnrollResult, CoordError> {
    let request = Request {
        op: "enroll".to_string(),
        name: name.to_string(),
        token: Some(token.to_string()),
        id_token: None,
        nonce: None,
        endpoints: endpoints.to_vec(),
        routes: routes.to_vec(),
    };
    round_trip(coord, coord_name, bundle_pem, None, request, None, true).await
}

/// Enroll with a one-use token.
///
/// Call this function outside a Tokio runtime.
pub fn enroll_with_token_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    name: &str,
    token: &str,
    endpoints: &[String],
    routes: &[String],
) -> Result<EnrollResult, CoordError> {
    block_on(enroll_with_token(
        coord, coord_name, bundle_pem, name, token, endpoints, routes,
    ))
}

/// One OIDC enrollment.
///
/// `id_token` is secret. The caller must not log it.
pub struct OidcEnroll<'a> {
    pub coord: SocketAddr,
    pub coord_name: &'a str,
    pub bundle_pem: &'a str,
    pub name: &'a str,
    pub id_token: &'a str,
    pub nonce: &'a str,
    pub endpoints: &'a [String],
    pub routes: &'a [String],
}

/// Enroll with an ID token.
///
/// The caller must not log `id_token`.
pub async fn enroll_with_oidc(input: OidcEnroll<'_>) -> Result<EnrollResult, CoordError> {
    let request = Request {
        op: "enroll".to_string(),
        name: input.name.to_string(),
        token: None,
        id_token: Some(input.id_token.to_string()),
        nonce: Some(input.nonce.to_string()),
        endpoints: input.endpoints.to_vec(),
        routes: input.routes.to_vec(),
    };
    round_trip(
        input.coord,
        input.coord_name,
        input.bundle_pem,
        None,
        request,
        None,
        true,
    )
    .await
}

/// Enroll with an ID token.
///
/// Call this function outside a Tokio runtime.
/// The caller must not log `id_token`.
pub fn enroll_with_oidc_blocking(input: OidcEnroll<'_>) -> Result<EnrollResult, CoordError> {
    block_on(enroll_with_oidc(input))
}

/// Replace the advertised routes and store the fresh netmap.
///
/// Call this function outside a Tokio runtime.
pub fn advertise_routes_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    routes: &[String],
) -> Result<NetmapView, CoordError> {
    block_on(advertise_routes(
        coord, coord_name, bundle_pem, state_dir, routes,
    ))
}

/// Replace the advertised routes and store the fresh netmap.
pub async fn advertise_routes(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    routes: &[String],
) -> Result<NetmapView, CoordError> {
    let material = read_node_material(state_dir)?;
    let pinned = material.netmap_public;
    let request = Request {
        op: "advertise".to_string(),
        name: material.name.clone(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: Vec::new(),
        routes: routes.to_vec(),
    };
    let result = round_trip(
        coord,
        coord_name,
        bundle_pem,
        Some(material),
        request,
        Some(pinned),
        false,
    )
    .await?;
    let view = view_from_result(result);
    view.write_state(state_dir)?;
    Ok(view)
}

/// Fetch a fresh netmap with the stored node SVID.
pub async fn fetch_netmap(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
) -> Result<NetmapView, CoordError> {
    let material = read_node_material(state_dir)?;
    let pinned = material.netmap_public;
    let request = Request {
        op: "netmap".to_string(),
        name: material.name.clone(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: Vec::new(),
        routes: Vec::new(),
    };
    let result = round_trip(
        coord,
        coord_name,
        bundle_pem,
        Some(material),
        request,
        Some(pinned),
        false,
    )
    .await?;
    let view = view_from_result(result);
    view.write_state(state_dir)?;
    Ok(view)
}

fn view_from_result(result: EnrollResult) -> NetmapView {
    NetmapView {
        signed_netmap: result.signed_netmap,
        signed_grants: result.signed_grants,
        endpoints: result.endpoints,
        netmap_public: result.netmap_public,
        approved_routes: result.approved_routes,
        advertised_routes: result.advertised_routes,
    }
}

/// Renew the node SVID with the stored leaf.
///
/// The function writes the new leaf into `state_dir`.
/// The caller must not log the private key.
pub async fn renew_svid(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
) -> Result<EnrollResult, CoordError> {
    let material = read_node_material(state_dir)?;
    let pinned = material.netmap_public;
    let request = Request {
        op: "renew".to_string(),
        name: material.name.clone(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: Vec::new(),
        routes: Vec::new(),
    };
    let result = round_trip(
        coord,
        coord_name,
        bundle_pem,
        Some(material),
        request,
        Some(pinned),
        true,
    )
    .await?;
    result.write_state(state_dir)?;
    Ok(result)
}

/// Renew the node SVID with the stored leaf.
///
/// Call this function outside a Tokio runtime.
/// The caller must not log the private key.
pub fn renew_svid_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
) -> Result<EnrollResult, CoordError> {
    block_on(renew_svid(coord, coord_name, bundle_pem, state_dir))
}

/// Fetch a fresh netmap with the stored node SVID.
///
/// Call this function outside a Tokio runtime.
/// Call one admin operation with the node SVID in `state_dir`.
///
/// The coordinator accepts the call only when that SVID is an owner.
/// The caller must not log the returned document when it can hold a secret.
/// Admin documents do not hold secrets.
pub fn admin_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    op: &str,
    name: &str,
) -> Result<String, CoordError> {
    block_on(admin_call(
        coord, coord_name, bundle_pem, state_dir, op, name,
    ))
}

/// Fetch the deny document with the node SVID in `state_dir`.
pub fn fetch_deny_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
) -> Result<String, CoordError> {
    block_on(fetch_deny(coord, coord_name, bundle_pem, state_dir))
}

async fn admin_call(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    op: &str,
    name: &str,
) -> Result<String, CoordError> {
    let material = read_node_material(state_dir)?;
    let request = Request {
        op: op.to_string(),
        name: name.to_string(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: Vec::new(),
        routes: Vec::new(),
    };
    authed_detail(coord, coord_name, bundle_pem, material, request).await
}

async fn fetch_deny(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
) -> Result<String, CoordError> {
    let material = read_node_material(state_dir)?;
    let request = Request {
        op: "deny".to_string(),
        name: material.name.clone(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: Vec::new(),
        routes: Vec::new(),
    };
    authed_detail(coord, coord_name, bundle_pem, material, request).await
}

async fn authed_detail(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    material: NodeMaterial,
    request: Request,
) -> Result<String, CoordError> {
    let expect_coord = SpiffeId::coord(coord_name)?;
    let client_tls = ClientTls {
        trust_pem: bundle_pem.to_string(),
        expect_coord,
        certificate_pem: Some(material.certificate_pem),
        private_key_pem: Some(material.private_key_pem),
    };
    let endpoint =
        tlsutil::client_endpoint(&client_tls, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let connecting = endpoint
        .connect(coord, tlsutil::SERVER_NAME)
        .map_err(|err| CoordError::Tls(format!("connect: {err}")))?;
    let connection = connecting
        .await
        .map_err(|err| CoordError::Tls(format!("handshake: {err}")))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| CoordError::Tls(format!("open: {err}")))?;
    proto::write_json(&mut send, &request).await?;
    let _ = send.finish();
    let response: Response = proto::read_json(&mut recv).await?;
    connection.close(quinn::VarInt::from_u32(0), b"done");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.wait_idle()).await;
    if !response.ok {
        let text = response
            .error
            .unwrap_or_else(|| "The coordinator request failed.".to_string());
        return Err(CoordError::Protocol(text));
    }
    response
        .detail
        .ok_or_else(|| CoordError::Protocol("The coordinator request failed.".to_string()))
}

pub fn fetch_netmap_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
) -> Result<NetmapView, CoordError> {
    block_on(fetch_netmap(coord, coord_name, bundle_pem, state_dir))
}

async fn round_trip(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    material: Option<NodeMaterial>,
    request: Request,
    pinned_public: Option<[u8; 32]>,
    require_leaf: bool,
) -> Result<EnrollResult, CoordError> {
    let expect_coord = SpiffeId::coord(coord_name)?;
    let client_tls = ClientTls {
        trust_pem: bundle_pem.to_string(),
        expect_coord,
        certificate_pem: material.as_ref().map(|item| item.certificate_pem.clone()),
        private_key_pem: material.map(|item| item.private_key_pem),
    };
    let endpoint =
        tlsutil::client_endpoint(&client_tls, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let connecting = endpoint
        .connect(coord, tlsutil::SERVER_NAME)
        .map_err(|err| CoordError::Tls(format!("connect: {err}")))?;
    let connection = connecting
        .await
        .map_err(|err| CoordError::Tls(format!("handshake: {err}")))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| CoordError::Tls(format!("open: {err}")))?;
    proto::write_json(&mut send, &request).await?;
    let _ = send.finish();
    let response: Response = proto::read_json(&mut recv).await?;
    connection.close(quinn::VarInt::from_u32(0), b"done");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.wait_idle()).await;
    enroll_from_response(response, bundle_pem, pinned_public, require_leaf)
}

fn enroll_from_response(
    response: Response,
    bundle_pem: &str,
    pinned_public: Option<[u8; 32]>,
    require_leaf: bool,
) -> Result<EnrollResult, CoordError> {
    if !response.ok {
        let text = response
            .error
            .unwrap_or_else(|| "The coordinator request failed.".to_string());
        return Err(CoordError::Protocol(text));
    }
    let ticket = ticket_from_parts(
        response.ticket_hex.clone(),
        response.ticket_mac_hex.clone(),
        response.ticket_verifier_pem.clone(),
        response.ticket_mac_key_hex.clone(),
        response.ticket_not_before,
        response.ticket_not_after,
        response.svid_ca_pub_hex.clone(),
    )?;
    let signed = response
        .netmap
        .ok_or_else(|| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    let endpoints = response.endpoints.unwrap_or_default();
    let public = match pinned_public {
        Some(public) => public,
        None => decode_hex_32(
            response
                .netmap_pub_hex
                .as_deref()
                .ok_or_else(|| CoordError::Protocol("The netmap is not valid.".to_string()))?,
        )?,
    };
    if let Some(hex) = response.netmap_pub_hex.as_deref() {
        if decode_hex_32(hex)? != public {
            return Err(CoordError::Signature);
        }
    }
    verify_signed_netmap(&signed, &public)?;
    let grants = response
        .grants
        .ok_or_else(|| CoordError::Protocol("The grants are not valid.".to_string()))?;
    verify_signed_grants(&grants, &public)?;
    let receiver = format!("spiffe://orblx.local/node/{}", signed.netmap.self_node.name);
    if grants.grants.receiver != receiver {
        return Err(CoordError::Protocol(
            "The grant receiver does not match the node.".to_string(),
        ));
    }
    for endpoint in &endpoints {
        verify_signed_endpoint(endpoint, &public)?;
    }
    if let Some(trust) = response.trust_bundle_pem.as_deref() {
        if trust != bundle_pem {
            return Err(CoordError::Protocol(
                "The trust bundle does not match.".to_string(),
            ));
        }
    }
    let certificate_pem = response.certificate_pem.unwrap_or_default();
    let private_key_pem = response.private_key_pem.unwrap_or_default();
    if require_leaf && (certificate_pem.trim().is_empty() || private_key_pem.trim().is_empty()) {
        return Err(CoordError::Protocol(
            "The coordinator request failed.".to_string(),
        ));
    }
    Ok(EnrollResult {
        name: signed.netmap.self_node.name.clone(),
        overlay_ip: signed.netmap.self_node.overlay_ip.clone(),
        svid: format!("spiffe://orblx.local/node/{}", signed.netmap.self_node.name),
        certificate_pem,
        private_key_pem,
        trust_bundle_pem: bundle_pem.to_string(),
        netmap_public: public,
        signed_netmap: signed,
        signed_grants: grants,
        endpoints,
        approved_routes: response.approved_routes.unwrap_or_default(),
        advertised_routes: response.advertised_routes.unwrap_or_default(),
        ticket,
    })
}

fn ticket_from_parts(
    ticket_hex: Option<String>,
    mac: Option<String>,
    verifier: Option<String>,
    mac_key: Option<String>,
    not_before: Option<u64>,
    not_after: Option<u64>,
    ca: Option<String>,
) -> Result<Option<IssuedTicket>, CoordError> {
    let Some(ticket_hex) = ticket_hex else {
        return Ok(None);
    };
    let mac = mac.ok_or_else(|| CoordError::Protocol("The ticket is not valid.".to_string()))?;
    let verifier =
        verifier.ok_or_else(|| CoordError::Protocol("The ticket is not valid.".to_string()))?;
    let mac_key =
        mac_key.ok_or_else(|| CoordError::Protocol("The ticket is not valid.".to_string()))?;
    let not_before =
        not_before.ok_or_else(|| CoordError::Protocol("The ticket is not valid.".to_string()))?;
    let not_after =
        not_after.ok_or_else(|| CoordError::Protocol("The ticket is not valid.".to_string()))?;
    let ca = ca.ok_or_else(|| CoordError::Protocol("The ticket is not valid.".to_string()))?;
    Ok(Some(decode_ticket_wire(
        &ticket_hex,
        &mac,
        &verifier,
        &mac_key,
        not_before,
        not_after,
        &ca,
    )?))
}

pub fn netmap_json(signed: &SignedNetmap) -> Result<String, CoordError> {
    let text = serde_json::to_string(&signed.netmap)
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    orblx_datapath::Netmap::from_slice(text.as_bytes())
        .map_err(|_| CoordError::Protocol("The netmap is not valid.".to_string()))?;
    Ok(text)
}

fn block_on<T>(
    future: impl std::future::Future<Output = Result<T, CoordError>>,
) -> Result<T, CoordError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CoordError::io)?;
    runtime.block_on(future)
}
