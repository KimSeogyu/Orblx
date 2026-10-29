use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use orblx_identity::SpiffeId;

use crate::error::CoordError;
use crate::netmap::{decode_hex_32, verify_signed_endpoint, verify_signed_netmap, SignedNetmap};
use crate::proto::{self, Request, Response};
use crate::state::{read_node_material, EnrollResult, NetmapView, NodeMaterial};
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
    let view = NetmapView {
        signed_netmap: result.signed_netmap,
        endpoints: result.endpoints,
        netmap_public: result.netmap_public,
    };
    view.write_state(state_dir)?;
    Ok(view)
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
        endpoints,
    })
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
