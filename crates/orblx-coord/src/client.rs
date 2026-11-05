use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use orblx_identity::SpiffeId;

use crate::error::CoordError;
use crate::netmap::{
    decode_hex_32, verify_grants_wire, verify_netmap_wire, verify_signed_endpoint, SignedNetmap,
};
use crate::proto::{self, GrantAsk, Request, Response};
use crate::state::{read_node_material, EnrollResult, NetmapView, NodeMaterial};
use crate::ticket::{decode_hex, decode_ticket_wire, IssuedTicket};
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
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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
    /// The nonce from the sign-in request.
    ///
    /// A generic issuer accepts `None` when the token has no `nonce` claim.
    pub nonce: Option<&'a str>,
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
        nonce: input.nonce.map(str::to_string),
        endpoints: input.endpoints.to_vec(),
        routes: input.routes.to_vec(),
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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
        exit_approved: result.exit_approved,
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
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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

/// Publish reflexive endpoints and store the fresh signed view.
///
/// Call this function outside a Tokio runtime.
pub fn publish_candidates_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    endpoints: &[String],
) -> Result<NetmapView, CoordError> {
    block_on(publish_candidates(
        coord, coord_name, bundle_pem, state_dir, endpoints,
    ))
}

/// Publish reflexive endpoints and store the fresh signed view.
pub async fn publish_candidates(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    endpoints: &[String],
) -> Result<NetmapView, CoordError> {
    let material = read_node_material(state_dir)?;
    let pinned = material.netmap_public;
    let request = Request {
        op: "candidates".to_string(),
        name: material.name.clone(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: endpoints.to_vec(),
        routes: Vec::new(),
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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

/// Register this node as an exit node and store the fresh netmap.
///
/// Call this function outside a Tokio runtime.
pub fn advertise_exit_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    enabled: bool,
) -> Result<NetmapView, CoordError> {
    block_on(advertise_exit(
        coord, coord_name, bundle_pem, state_dir, enabled,
    ))
}

/// Register this node as an exit node and store the fresh netmap.
pub async fn advertise_exit(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    enabled: bool,
) -> Result<NetmapView, CoordError> {
    let material = read_node_material(state_dir)?;
    let pinned = material.netmap_public;
    let request = Request {
        op: "exit".to_string(),
        name: material.name.clone(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: Vec::new(),
        routes: Vec::new(),
        exit_node: enabled,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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

/// The reply of one admin call with an API token (W25-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminReply {
    /// 200, 400, 401, 403, or 409.
    pub status: u16,
    /// The reply document when the status is 200.
    pub detail: Option<String>,
    /// The error sentence when the status is not 200.
    pub error: Option<String>,
}

/// Send one admin call with a scoped API token and no client certificate.
///
/// The token goes only in the request. This function does not print it.
pub fn admin_token_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    api_token: &str,
    op: &str,
    name: &str,
) -> Result<AdminReply, CoordError> {
    admin_token_expect_blocking(coord, coord_name, bundle_pem, api_token, op, name, None)
}

/// Send one admin call with a scoped API token and an expected policy sha256 (W25-9).
///
/// `admin-policy-set` then writes only when the live policy has the sha256 `expect`.
/// A stale call gets status 409. The token goes only in the request.
pub fn admin_token_expect_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    api_token: &str,
    op: &str,
    name: &str,
    expect: Option<&str>,
) -> Result<AdminReply, CoordError> {
    block_on(async move {
        let expect_coord = SpiffeId::coord(coord_name)?;
        let client_tls = ClientTls {
            trust_pem: bundle_pem.to_string(),
            expect_coord,
            certificate_pem: None,
            private_key_pem: None,
        };
        let request = Request {
            op: op.to_string(),
            name: name.to_string(),
            token: None,
            id_token: None,
            nonce: None,
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            grant: None,
            api_token: Some(api_token.to_string()),
            deny_etag: None,
            expect_sha256: expect.map(str::to_string),
            unchanged_ok: false,
        };
        let endpoint =
            tlsutil::client_endpoint(&client_tls, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
        let connection = endpoint
            .connect(coord, tlsutil::SERVER_NAME)
            .map_err(|err| CoordError::Tls(format!("connect: {err}")))?
            .await
            .map_err(|err| CoordError::Tls(format!("handshake: {err}")))?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|err| CoordError::Tls(format!("open: {err}")))?;
        proto::write_request(&mut send, &request).await?;
        let _ = send.finish();
        let response: Response = proto::read_json(&mut recv).await?;
        close_and_wait(&connection, &endpoint).await;
        let status = response
            .status
            .unwrap_or(if response.ok { 200 } else { 400 });
        Ok(AdminReply {
            status,
            detail: response.detail,
            error: response.error,
        })
    })
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

/// Wait for a new deny list of this node (W25-2).
///
/// The coordinator replies at once when the ETag of its deny list for this node is not
/// `etag`. Otherwise it holds the request until the list changes, or for at most
/// [`DENY_WAIT_HOLD`]. The function stops after the hold time plus 10 s.
/// An old coordinator does not know the op and returns an error. Then use
/// [`fetch_deny_blocking`].
pub fn fetch_deny_wait_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    etag: Option<&str>,
) -> Result<String, CoordError> {
    block_on(async {
        let material = read_node_material(state_dir)?;
        let request = Request {
            op: "deny-wait".to_string(),
            name: material.name.clone(),
            token: None,
            id_token: None,
            nonce: None,
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            grant: None,
            api_token: None,
            deny_etag: etag.map(str::to_string),
            expect_sha256: None,
            unchanged_ok: false,
        };
        let limit = DENY_WAIT_HOLD + std::time::Duration::from_secs(10);
        tokio::time::timeout(
            limit,
            authed_detail(coord, coord_name, bundle_pem, material, request),
        )
        .await
        .map_err(|_| CoordError::Tls("The deny wait timed out.".to_string()))?
    })
}

/// One `policy-wait` reply (W25-6).
#[derive(Clone)]
pub struct PolicySync {
    /// The signed netmap and grants. The client checked the signatures with the pinned key.
    pub view: NetmapView,
    /// The deny list text of this node.
    pub deny: String,
    /// The ETag to send with the next wait.
    pub etag: String,
}

/// Wait for a new netmap, grant set, or deny list of this node (W25-6).
///
/// The coordinator replies at once when the ETag of the three is not `etag`. Otherwise it
/// holds the request until one of them changes, or for at most [`DENY_WAIT_HOLD`].
/// The client checks the netmap and grant signatures with the netmap key from enrollment.
/// The function does not write files. An old coordinator returns an error.
pub fn fetch_policy_wait_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    etag: Option<&str>,
) -> Result<PolicySync, CoordError> {
    block_on(async {
        let material = read_node_material(state_dir)?;
        let pinned = material.netmap_public;
        let request = policy_wait_request(&material.name, etag);
        let limit = DENY_WAIT_HOLD + std::time::Duration::from_secs(10);
        let response = tokio::time::timeout(
            limit,
            authed_response(coord, coord_name, bundle_pem, material, request),
        )
        .await
        .map_err(|_| CoordError::Tls("The policy wait timed out.".to_string()))?
        .map_err(unknown_op_is_old_coordinator)?;
        policy_sync_from(response, bundle_pem, pinned)
    })
}

/// The reply of a coordinator to an op that it does not know.
const UNKNOWN_OP_TEXT: &str = "The request is not valid.";

/// A coordinator before W25-6 (for example the v0.1.0-rc.2 tag) does not know `policy-wait`.
/// It replies [`UNKNOWN_OP_TEXT`]. The node shows the version mismatch for it (W25-34).
fn unknown_op_is_old_coordinator(err: CoordError) -> CoordError {
    match &err {
        CoordError::Protocol(text) if text == UNKNOWN_OP_TEXT => proto::old_coordinator_error(),
        _ => err,
    }
}

/// The longest time that the coordinator holds one `deny-wait` request.
pub const DENY_WAIT_HOLD: std::time::Duration = std::time::Duration::from_secs(20);

/// The shortest time between two `deny-wait` or `policy-wait` requests of a node (W25-2).
///
/// It is the poll interval of the node policy loop in `orblx up`.
pub const POLICY_WAIT_GAP: std::time::Duration = std::time::Duration::from_millis(100);

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
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: None,
        expect_sha256: None,
        unchanged_ok: false,
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
    authed_response(coord, coord_name, bundle_pem, material, request)
        .await?
        .detail
        .ok_or_else(|| CoordError::Protocol("The coordinator request failed.".to_string()))
}

async fn authed_response(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    material: NodeMaterial,
    request: Request,
) -> Result<Response, CoordError> {
    let (endpoint, connection) = node_connect(
        coord,
        coord_name,
        bundle_pem,
        material.certificate_pem,
        material.private_key_pem,
    )
    .await?;
    let response = exchange(&connection, &request).await;
    close_and_wait(&connection, &endpoint).await;
    response_ok(response?)
}

/// Open a QUIC connection to the coordinator with the node SVID.
async fn node_connect(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    certificate_pem: String,
    private_key_pem: String,
) -> Result<(quinn::Endpoint, quinn::Connection), CoordError> {
    let expect_coord = SpiffeId::coord(coord_name)?;
    let client_tls = ClientTls {
        trust_pem: bundle_pem.to_string(),
        expect_coord,
        certificate_pem: Some(certificate_pem),
        private_key_pem: Some(private_key_pem),
    };
    let endpoint =
        tlsutil::client_endpoint(&client_tls, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let connecting = endpoint
        .connect(coord, tlsutil::SERVER_NAME)
        .map_err(|err| CoordError::Tls(format!("connect: {err}")))?;
    let connection = connecting
        .await
        .map_err(|err| CoordError::Tls(format!("handshake: {err}")))?;
    Ok((endpoint, connection))
}

/// Send one request on a new stream of `connection` and read the reply.
async fn exchange(
    connection: &quinn::Connection,
    request: &Request,
) -> Result<Response, CoordError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|err| CoordError::Tls(format!("open: {err}")))?;
    proto::write_request(&mut send, request).await?;
    let _ = send.finish();
    proto::read_json(&mut recv).await
}

fn response_ok(response: Response) -> Result<Response, CoordError> {
    if !response.ok {
        let text = response
            .error
            .unwrap_or_else(|| "The coordinator request failed.".to_string());
        return Err(CoordError::Protocol(text));
    }
    Ok(response)
}

/// A `policy-wait` client that keeps one QUIC connection to the coordinator (W25-16).
///
/// Each wait uses a new stream on the same connection, so a wait needs no new TLS handshake.
/// The client opens a new connection when the connection closes, when a request on it fails,
/// or when the node certificate or the trust bundle changes (for example after a renewal).
/// The coordinator authenticates the node leaf again for each request.
pub struct PolicyWaiter {
    coord: SocketAddr,
    coord_name: String,
    runtime: tokio::runtime::Runtime,
    link: Option<PolicyLink>,
    /// The last checked reply. With it, the waiter accepts a reply without the view when
    /// the ETag did not change.
    last: Option<PolicySync>,
}

struct PolicyLink {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    bundle_pem: String,
    certificate_pem: String,
}

impl PolicyLink {
    fn close(self) {
        self.connection.close(quinn::VarInt::from_u32(0), b"done");
        drop(self.endpoint);
    }
}

impl PolicyWaiter {
    /// Make a waiter for the coordinator at `coord`. The waiter connects on the first wait.
    pub fn new(coord: SocketAddr, coord_name: &str) -> Result<Self, CoordError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(CoordError::io)?;
        Ok(Self {
            coord,
            coord_name: coord_name.to_string(),
            runtime,
            link: None,
            last: None,
        })
    }

    /// The stable id of the open connection, or `None` before the first wait.
    pub fn connection_id(&self) -> Option<usize> {
        self.link.as_ref().map(|item| item.connection.stable_id())
    }

    /// Do one wait like [`fetch_policy_wait_blocking`].
    pub fn wait(
        &mut self,
        bundle_pem: &str,
        state_dir: &Path,
        etag: Option<&str>,
    ) -> Result<PolicySync, CoordError> {
        let material = read_node_material(state_dir)?;
        let pinned = material.netmap_public;
        let mut request = policy_wait_request(&material.name, etag);
        // The waiter keeps the view of `etag` only for the bundle and the leaf of that view.
        let kept = self.last.as_ref().is_some_and(|last| {
            Some(last.etag.as_str()) == etag
                && self.link.as_ref().is_some_and(|item| {
                    item.bundle_pem == bundle_pem
                        && item.certificate_pem == material.certificate_pem
                })
        });
        if !kept {
            self.last = None;
        }
        request.unchanged_ok = kept;
        let limit = DENY_WAIT_HOLD + std::time::Duration::from_secs(10);
        let coord = self.coord;
        let coord_name = self.coord_name.clone();
        let link = &mut self.link;
        let outcome = self.runtime.block_on(async {
            let reuse = link.as_ref().is_some_and(|item| {
                item.bundle_pem == bundle_pem
                    && item.certificate_pem == material.certificate_pem
                    && item.connection.close_reason().is_none()
            });
            if reuse {
                if let Some(item) = link.as_ref() {
                    // The connection can be gone, for example after a coordinator restart.
                    // Then the waiter tries one time more on a new connection.
                    let sent = tokio::time::timeout(limit, exchange(&item.connection, &request));
                    if let Ok(Ok(response)) = sent.await {
                        return Ok(response);
                    }
                }
            }
            if let Some(item) = link.take() {
                item.close();
            }
            let fresh = async {
                let (endpoint, connection) = node_connect(
                    coord,
                    &coord_name,
                    bundle_pem,
                    material.certificate_pem.clone(),
                    material.private_key_pem.clone(),
                )
                .await?;
                *link = Some(PolicyLink {
                    endpoint,
                    connection: connection.clone(),
                    bundle_pem: bundle_pem.to_string(),
                    certificate_pem: material.certificate_pem.clone(),
                });
                exchange(&connection, &request).await
            };
            tokio::time::timeout(limit, fresh)
                .await
                .map_err(|_| CoordError::Tls("The policy wait timed out.".to_string()))?
        });
        let response = match outcome {
            Ok(response) => response,
            Err(err) => {
                if let Some(item) = self.link.take() {
                    item.close();
                }
                self.last = None;
                return Err(err);
            }
        };
        // W25-34: a coordinator before W25-6 does not know `policy-wait`.
        let response = response_ok(response).map_err(unknown_op_is_old_coordinator)?;
        if response.netmap.is_none() {
            // A reply without the view: the view of the ETag did not change (W25-16).
            let invalid = || CoordError::Protocol("The coordinator request failed.".to_string());
            let etag = response.policy_etag.ok_or_else(invalid)?;
            let deny = response.detail.ok_or_else(invalid)?;
            let Some(last) = self.last.as_mut().filter(|last| last.etag == etag) else {
                self.last = None;
                return Err(invalid());
            };
            last.deny = deny;
            return Ok(last.clone());
        }
        let sync = policy_sync_from(response, bundle_pem, pinned)?;
        self.last = Some(sync.clone());
        Ok(sync)
    }
}

impl Drop for PolicyWaiter {
    fn drop(&mut self) {
        if let Some(item) = self.link.take() {
            let _guard = self.runtime.enter();
            item.close();
        }
    }
}

fn policy_wait_request(name: &str, etag: Option<&str>) -> Request {
    Request {
        op: "policy-wait".to_string(),
        name: name.to_string(),
        token: None,
        id_token: None,
        nonce: None,
        endpoints: Vec::new(),
        routes: Vec::new(),
        exit_node: false,
        grant: None,
        api_token: None,
        deny_etag: etag.map(str::to_string),
        expect_sha256: None,
        unchanged_ok: false,
    }
}

fn policy_sync_from(
    mut response: Response,
    bundle_pem: &str,
    pinned: [u8; 32],
) -> Result<PolicySync, CoordError> {
    let invalid = || CoordError::Protocol("The coordinator request failed.".to_string());
    let deny = response.detail.take().ok_or_else(invalid)?;
    let etag = response.policy_etag.take().ok_or_else(invalid)?;
    let result = enroll_from_response(response, bundle_pem, Some(pinned), false)?;
    Ok(PolicySync {
        view: view_from_result(result),
        deny,
        etag,
    })
}

/// Ask for one agent JIT grant with the node SVID in `state_dir`.
///
/// The result is the reply document with the grant id.
pub fn agent_grant_request_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    ask: GrantAsk,
) -> Result<String, CoordError> {
    block_on(async move {
        let material = read_node_material(state_dir)?;
        let request = Request {
            op: "agent-grant".to_string(),
            name: material.name.clone(),
            token: None,
            id_token: None,
            nonce: None,
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            grant: Some(ask),
            api_token: None,
            deny_etag: None,
            expect_sha256: None,
            unchanged_ok: false,
        };
        authed_detail(coord, coord_name, bundle_pem, material, request).await
    })
}

/// The reply of one grant fetch.
pub enum GrantFetch {
    /// The grant waits for an owner.
    Pending,
    /// The grant files. The caller must not log them.
    Issued(Box<orblx_agent::GrantFiles>),
}

impl std::fmt::Debug for GrantFetch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => formatter.write_str("Pending"),
            Self::Issued(_) => formatter.write_str("Issued([elided])"),
        }
    }
}

/// Fetch the material of one approved grant with the node SVID in `state_dir`.
///
/// The coordinator returns the material one time.
pub fn agent_grant_fetch_blocking(
    coord: SocketAddr,
    coord_name: &str,
    bundle_pem: &str,
    state_dir: &Path,
    id: &str,
) -> Result<GrantFetch, CoordError> {
    block_on(async move {
        let material = read_node_material(state_dir)?;
        let request = Request {
            op: "agent-grant-fetch".to_string(),
            name: id.to_string(),
            token: None,
            id_token: None,
            nonce: None,
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            grant: None,
            api_token: None,
            deny_etag: None,
            expect_sha256: None,
            unchanged_ok: false,
        };
        let response = authed_response(coord, coord_name, bundle_pem, material, request).await?;
        let invalid = || CoordError::Protocol("The grant reply is not valid.".to_string());
        let (Some(cert_pem), Some(key_pem), Some(ticket_hex), Some(detail)) = (
            response.certificate_pem,
            response.private_key_pem,
            response.ticket_hex,
            response.detail.clone(),
        ) else {
            return Ok(GrantFetch::Pending);
        };
        let grant: orblx_agent::SignedAgentGrant =
            serde_json::from_str(&detail).map_err(|_| invalid())?;
        let ticket = decode_hex(&ticket_hex).map_err(|_| invalid())?;
        Ok(GrantFetch::Issued(Box::new(orblx_agent::GrantFiles {
            cert_pem,
            key_pem,
            ticket,
            grant,
        })))
    })
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

#[cfg(test)]
tokio::task_local! {
    /// W25-21, tests only: a future that runs in `CLOSE_WAITS.scope` gets the close-wait time
    /// of each coordinator call that it makes.
    pub(crate) static CLOSE_WAITS: std::cell::RefCell<Vec<std::time::Duration>>;
}

/// Closes a coordinator call and waits up to 2 s for the endpoint to become idle, so that the
/// coordinator gets the close. W25-21: with ORBLX_TRACE_COORD=1 it prints the time of this
/// wait. The line has no request or response data.
async fn close_and_wait(connection: &quinn::Connection, endpoint: &quinn::Endpoint) {
    let started = std::time::Instant::now();
    connection.close(quinn::VarInt::from_u32(0), b"done");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.wait_idle()).await;
    #[cfg(test)]
    let _ = CLOSE_WAITS.try_with(|waits| waits.borrow_mut().push(started.elapsed()));
    if std::env::var("ORBLX_TRACE_COORD").as_deref() == Ok("1") {
        eprintln!(
            "orblx coord_call close_wait_ms {:.1} rtt_ms {:.1}",
            started.elapsed().as_secs_f64() * 1000.0,
            connection.rtt().as_secs_f64() * 1000.0
        );
    }
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
    proto::write_request(&mut send, &request).await?;
    let _ = send.finish();
    let response: Response = proto::read_json(&mut recv).await?;
    close_and_wait(&connection, &endpoint).await;
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
    let wire = response
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
    // W25-34: check the signature over the received bytes, then parse them.
    let signed = verify_netmap_wire(&wire, &public)?;
    // W25-34: an older coordinator signs no seq. The node does not use its netmap.
    if signed.netmap.seq == 0 || signed.netmap.issued_at_ms == 0 {
        return Err(proto::old_coordinator_error());
    }
    let grants = response
        .grants
        .ok_or_else(|| CoordError::Protocol("The grants are not valid.".to_string()))?;
    let grants = verify_grants_wire(&grants, &public)?;
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
        exit_approved: response.exit_approved.unwrap_or(false),
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

#[cfg(test)]
mod version_tests {
    use super::{unknown_op_is_old_coordinator, CoordError, UNKNOWN_OP_TEXT};

    /// W25-34: a coordinator that does not know `policy-wait` gives the version mismatch.
    #[test]
    fn unknown_policy_wait_op_is_a_version_mismatch() {
        let err = unknown_op_is_old_coordinator(CoordError::Protocol(UNKNOWN_OP_TEXT.to_string()));
        assert!(err
            .public_text()
            .starts_with(crate::proto::VERSION_MISMATCH));
        let other =
            unknown_op_is_old_coordinator(CoordError::Protocol("The node is revoked.".to_string()));
        assert_eq!(other.public_text(), "The node is revoked.");
    }
}
