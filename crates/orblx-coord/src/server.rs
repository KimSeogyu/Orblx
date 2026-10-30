use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::sync::watch;

use orblx_identity::{GoogleJwks, OidcJwks, TrustBundle, WorkloadKind};
use rustls::pki_types::CertificateDer;

use crate::admin;
use crate::agent;
use crate::apitoken;
use crate::error::CoordError;
use crate::http_util::{fetch_google_jwks, https_get};
use crate::netmap::encode_hex;
use crate::proto::{self, Request, Response};
use crate::state::{Coordinator, IssuerFetch};
use crate::ticket::ticket_response_fields;
use crate::tlsutil;

/// Run the coordinator until the process stops.
pub fn serve_blocking(coord: &Coordinator, listen: SocketAddr) -> Result<(), CoordError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CoordError::io)?;
    runtime.block_on(serve(coord, listen))
}

/// Accept QUIC connections on `listen`.
pub async fn serve(coord: &Coordinator, listen: SocketAddr) -> Result<(), CoordError> {
    warm_jwks(coord).await;
    let (addr, handle) = spawn(coord, listen).await?;
    println!("coord listen {addr}");
    let material = coord.tls_material()?;
    println!("coord svid {}", material.coord_id.as_uri());
    let _ = handle.await;
    Ok(())
}

/// Bind and accept in the background.
pub async fn spawn(
    coord: &Coordinator,
    listen: SocketAddr,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), CoordError> {
    coord.enable_config_audit()?;
    crate::webhook::start(coord);
    let material = coord.tls_material()?;
    let endpoint = tlsutil::server_endpoint(&material, listen)?;
    let addr = endpoint.local_addr().map_err(CoordError::io)?;
    let tick_coord = coord.clone();
    tokio::spawn(async move {
        expire_tick(tick_coord).await;
    });
    let (stamp_tx, stamp_rx) = watch::channel(0u64);
    let stamp_coord = coord.clone();
    tokio::spawn(async move {
        stamp_tick(stamp_coord, stamp_tx).await;
    });
    let coord = coord.clone();
    let handle = tokio::spawn(async move {
        let _ = accept_loop(endpoint, coord, stamp_rx).await;
    });
    Ok((addr, handle))
}

/// The time between two agent grant expiry checks.
const EXPIRE_TICK: std::time::Duration = std::time::Duration::from_millis(500);

/// Record agent grant expiry in the config chain without an admin call.
async fn expire_tick(coord: Coordinator) {
    let mut failed = false;
    loop {
        tokio::time::sleep(EXPIRE_TICK).await;
        let step = coord.clone();
        let result =
            tokio::task::spawn_blocking(move || agent::expire_due(&step, SystemTime::now())).await;
        match result {
            Ok(Ok(_)) => failed = false,
            Ok(Err(err)) if !failed => {
                failed = true;
                println!("coord agent expire tick failed: {}", err.public_text());
            }
            _ => {}
        }
    }
}

/// The time between two checks of the files that make the deny list (W25-2).
const STAMP_TICK: std::time::Duration = std::time::Duration::from_millis(100);

/// Wake the `deny-wait` requests when a file that makes the deny list changes.
///
/// The files are the deny file, the config audit chain, the node store, and the policy file.
/// The tick reads only the file size and change time.
async fn stamp_tick(coord: Coordinator, stamp: watch::Sender<u64>) {
    let mut last = None;
    loop {
        tokio::time::sleep(STAMP_TICK).await;
        let (Ok(dir), Ok(policy)) = (coord.state_dir(), coord.policy_file()) else {
            continue;
        };
        let now = [
            dir.join("deny.json"),
            dir.join(crate::state::CONFIG_AUDIT_FILE),
            dir.join("nodes.json"),
            policy,
        ]
        .iter()
        .map(|path| {
            std::fs::metadata(path)
                .ok()
                .map(|meta| (meta.len(), meta.modified().ok()))
        })
        .collect::<Vec<_>>();
        if last.as_ref() != Some(&now) {
            last = Some(now);
            stamp.send_modify(|value| *value = value.wrapping_add(1));
        }
    }
}

/// Reply with the deny list of one node when its ETag is not `known` (W25-2).
///
/// Otherwise hold the request until a deny file input changes and the ETag changes,
/// or until [`crate::DENY_WAIT_HOLD`] ends. Then reply with the same list.
async fn deny_wait(
    coord: &Coordinator,
    name: &str,
    known: Option<&str>,
    mut stamp: watch::Receiver<u64>,
) -> Result<String, CoordError> {
    let deadline = tokio::time::Instant::now() + crate::DENY_WAIT_HOLD;
    loop {
        stamp.borrow_and_update();
        let text = admin::deny_json_for(coord, name, SystemTime::now())?;
        if known != Some(admin::deny_etag(&text).as_str()) {
            return Ok(text);
        }
        match tokio::time::timeout_at(deadline, stamp.changed()).await {
            Ok(Ok(())) => {}
            _ => return Ok(text),
        }
    }
}

/// Reply with the signed netmap, the signed grants, and the deny list of one node (W25-6).
///
/// The reply comes at once when the ETag of the three is not `known`.
/// Otherwise the request waits like `deny-wait`: until an input file changes and the ETag
/// changes, or until [`crate::DENY_WAIT_HOLD`] ends.
async fn policy_wait(
    coord: &Coordinator,
    name: &str,
    known: Option<&str>,
    mut stamp: watch::Receiver<u64>,
) -> Result<Response, CoordError> {
    let deadline = tokio::time::Instant::now() + crate::DENY_WAIT_HOLD;
    loop {
        stamp.borrow_and_update();
        // W25-16: the view comes from the cache when its inputs did not change.
        let cached = coord.netmap_cached(name)?;
        let deny = admin::deny_json_for(coord, name, SystemTime::now())?;
        let etag = policy_etag(&cached.digest, &deny);
        let changed = known != Some(etag.as_str());
        if changed
            || !matches!(
                tokio::time::timeout_at(deadline, stamp.changed()).await,
                Ok(Ok(()))
            )
        {
            let mut response = netmap_response(&cached.view);
            response.detail = Some(deny);
            response.policy_etag = Some(etag);
            return Ok(response);
        }
    }
}

/// The SHA-256 of the view digest and the deny list ETag, in hex (W25-6, W25-16).
///
/// The view digest covers the signed netmap, the signed grants, the endpoints, and the routes.
/// Ed25519 signatures are deterministic, so the same view gives the same ETag.
fn policy_etag(view_digest: &[u8; 32], deny: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(view_digest);
    hasher.update(b"\0");
    hasher.update(admin::deny_etag(deny).as_bytes());
    encode_hex(&hasher.finalize())
}

async fn warm_jwks(coord: &Coordinator) {
    let Some(client_id) = coord.google_client_id_for_fetch().ok().flatten() else {
        return;
    };
    let _ = client_id;
    match fetch_google_jwks().await {
        Ok(text) => match GoogleJwks::from_json(&text) {
            Ok(jwks) => match coord.install_google_jwks(jwks) {
                Ok(()) => println!("Google JWKS is loaded."),
                Err(_) => println!("Google JWKS is not loaded. Token enrollment is ready."),
            },
            Err(_) => println!("Google JWKS is not loaded. Token enrollment is ready."),
        },
        Err(_) => println!("Google JWKS is not loaded. Token enrollment is ready."),
    }
}

async fn refresh_issuer_jwks(coord: &Coordinator, plan: IssuerFetch) {
    let roots = plan.extra_roots_pem.as_deref();
    let result = async {
        let discovery = https_get(&plan.issuer.discovery_url(), roots)
            .await
            .map_err(|step| ("discovery", step))?;
        let jwks_uri = plan
            .issuer
            .jwks_uri_from_discovery(&discovery)
            .map_err(|_| ("discovery", "document"))?;
        let text = https_get(&jwks_uri, roots)
            .await
            .map_err(|step| ("jwks", step))?;
        OidcJwks::from_json(&text).map_err(|_| ("jwks", "document"))
    }
    .await;
    match result {
        Ok(jwks) => {
            let kids = jwks.kids().join(" ");
            match coord.install_issuer_jwks(jwks, SystemTime::now()) {
                Ok(()) => println!("oidc jwks loaded {} kids {kids}", plan.reason),
                Err(_) => println!("oidc jwks not loaded {}", plan.reason),
            }
        }
        Err((stage, step)) => {
            println!("oidc jwks fetch failed {} {stage} {step}", plan.reason)
        }
    }
}

async fn accept_loop(
    endpoint: quinn::Endpoint,
    coord: Coordinator,
    stamp: watch::Receiver<u64>,
) -> Result<(), CoordError> {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let coord = coord.clone();
        let stamp = stamp.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = handle_connection(&coord, connection, stamp).await {
                        println!("coord request failed: {}", err.public_text());
                    }
                }
                Err(_) => println!("coord handshake failed"),
            }
        });
    }
    Ok(())
}

/// Serve the requests of one connection (W25-16).
///
/// A connection can carry many requests. Each request uses its own bidirectional stream.
/// The coordinator authenticates the peer leaf again for each request, at the time of that
/// request and with the deny list of that time. The connection ends when the client closes it
/// or after the idle timeout.
async fn handle_connection(
    coord: &Coordinator,
    connection: quinn::Connection,
    stamp: watch::Receiver<u64>,
) -> Result<(), CoordError> {
    let mut first = true;
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(_) if !first => return Ok(()),
            Err(_) => {
                println!("coord rejected: the stream did not open");
                return Err(CoordError::Protocol(
                    "The request is not valid.".to_string(),
                ));
            }
        };
        first = false;
        let coord = coord.clone();
        let connection = connection.clone();
        let stamp = stamp.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(&coord, &connection, send, recv, stamp).await {
                println!("coord request failed: {}", err.public_text());
            }
        });
    }
}

async fn handle_stream(
    coord: &Coordinator,
    connection: &quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    stamp: watch::Receiver<u64>,
) -> Result<(), CoordError> {
    let request = proto::read_json::<Request>(&mut recv).await?;
    let response = match dispatch(coord, connection, request, stamp).await {
        Ok(response) => response,
        Err(err) => {
            println!("coord rejected: {}", err.public_text());
            Response {
                ok: false,
                error: Some(err.public_text()),
                ..Response::default()
            }
        }
    };
    proto::write_json(&mut send, &response).await?;
    let _ = send.finish();
    Ok(())
}

async fn dispatch(
    coord: &Coordinator,
    connection: &quinn::Connection,
    request: Request,
    stamp: watch::Receiver<u64>,
) -> Result<Response, CoordError> {
    let now = SystemTime::now();
    match request.op.as_str() {
        "enroll" => {
            let result = match (&request.token, &request.id_token) {
                (Some(token), None) => coord.enroll_token(
                    &request.name,
                    token,
                    &request.endpoints,
                    &request.routes,
                    now,
                )?,
                (None, Some(id_token)) => {
                    if coord.google_client_id_for_fetch()?.is_some() {
                        warm_jwks(coord).await;
                    }
                    let kid = orblx_identity::token_kid(id_token);
                    if let Some(plan) = coord.issuer_fetch_plan(kid.as_deref(), now)? {
                        refresh_issuer_jwks(coord, plan).await;
                    }
                    coord.enroll_oidc(
                        &request.name,
                        id_token,
                        request.nonce.as_deref(),
                        &request.endpoints,
                        &request.routes,
                        now,
                    )?
                }
                _ => {
                    return Err(CoordError::Protocol(
                        "The enrollment request is not valid.".to_string(),
                    ))
                }
            };
            println!("enrolled {}", result.name);
            Ok(leaf_response(result))
        }
        "renew" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let result = coord.renew_node(&request.name, now)?;
            println!("renewed {}", result.name);
            Ok(leaf_response(result))
        }
        "advertise" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let view = coord.advertise_routes(&request.name, &request.routes)?;
            Ok(netmap_response(&view))
        }
        "candidates" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let view = coord.set_candidates(&request.name, &request.endpoints)?;
            Ok(netmap_response(&view))
        }
        "exit" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let view = coord.advertise_exit(&request.name, request.exit_node)?;
            Ok(netmap_response(&view))
        }
        "netmap" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let view = coord.netmap_for(&request.name)?;
            println!("netmap {}", request.name);
            Ok(netmap_response(&view))
        }
        "deny" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let detail = admin::deny_json_for(coord, &request.name, now)?;
            Ok(Response {
                ok: true,
                detail: Some(detail),
                ..Response::default()
            })
        }
        "deny-wait" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let detail =
                deny_wait(coord, &request.name, request.deny_etag.as_deref(), stamp).await?;
            Ok(Response {
                ok: true,
                detail: Some(detail),
                ..Response::default()
            })
        }
        "policy-wait" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            policy_wait(coord, &request.name, request.deny_etag.as_deref(), stamp).await
        }
        "agent-grant" => {
            let peer = peer_node(coord, connection)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let ask = request.grant.as_ref().ok_or_else(|| {
                CoordError::Protocol("The grant request is not valid.".to_string())
            })?;
            let value = agent::request(coord, &peer, ask, now)?;
            println!("agent grant request from {peer}");
            detail_response(&value)
        }
        "agent-grant-fetch" => {
            let peer = peer_node(coord, connection)?;
            match agent::fetch(coord, &peer, &request.name, now)? {
                agent::Fetched::Pending(value) => detail_response(&value),
                agent::Fetched::Issued(issued) => {
                    let (material, signed) = *issued;
                    let detail = serde_json::to_string(&signed)
                        .map_err(|_| CoordError::Protocol("The grant is not valid.".to_string()))?;
                    println!("agent grant issued to {peer}");
                    Ok(Response {
                        ok: true,
                        certificate_pem: Some(material.certificate_pem),
                        private_key_pem: Some(material.private_key_pem),
                        trust_bundle_pem: Some(material.trust_bundle_pem),
                        ticket_hex: Some(encode_hex(&material.ticket.bytes)),
                        detail: Some(detail),
                        ..Response::default()
                    })
                }
            }
        }
        op if apitoken::admin_ops().contains(&op) => {
            dispatch_admin(coord, connection, &request, now)
        }
        _ => Err(CoordError::Protocol(
            "The request is not valid.".to_string(),
        )),
    }
}

fn dispatch_admin(
    coord: &Coordinator,
    connection: &quinn::Connection,
    request: &Request,
    now: SystemTime,
) -> Result<Response, CoordError> {
    if let Some(secret) = request.api_token.as_deref() {
        return Ok(dispatch_token(coord, request, secret, now));
    }
    let caller = peer_id(coord, connection)?;
    if !coord.caller_is_owner(&caller)? {
        return Err(CoordError::Protocol(
            "The caller is not an owner.".to_string(),
        ));
    }
    let policy_lock = policy_lock_for(&request.op)?;
    let value = run_admin(
        coord,
        request,
        Caller::Owner(caller.as_uri()),
        policy_lock.as_ref(),
        now,
    )?;
    let detail = serde_json::to_string(&value)
        .map_err(|_| CoordError::Protocol("The request is not valid.".to_string()))?;
    println!("admin {}", request.op.trim_start_matches("admin-"));
    Ok(Response {
        ok: true,
        detail: Some(detail),
        ..Response::default()
    })
}

/// Who makes an admin call.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// An owner SVID (mTLS). The text is the SPIFFE URI.
    Owner(&'a str),
    /// A scoped API token. The text is the audit actor `api-token:ID`.
    Token(&'a str),
}

impl Caller<'_> {
    fn actor(&self) -> &str {
        match self {
            Self::Owner(actor) | Self::Token(actor) => actor,
        }
    }
}

/// Run one admin call with an API token (W25-3).
///
/// The token decides the caller. A client certificate on the same connection
/// does not add rights. Each call writes one `token-use` or `token-deny` record.
fn dispatch_token(
    coord: &Coordinator,
    request: &Request,
    secret: &str,
    now: SystemTime,
) -> Response {
    let op = request.op.trim_start_matches("admin-");
    let Ok(policy_lock) = policy_lock_for(&request.op) else {
        println!("admin token check failed op {op}: policy lock");
        return status_response(500, "The coordinator request failed.".to_string());
    };
    // W25-3b: a token cannot change the policy owners. The owner check and the
    // write use the same lock.
    // W25-7: a token cannot change the audit webhooks. A token that could remove a
    // webhook could hide its later calls from the receiver.
    // W25-13: a token cannot change the SIEM sinks, for the same reason.
    let rule = || match &policy_lock {
        Some(lock) if !admin::policy_keeps_owners(coord, lock, &request.name)? => {
            Ok(Some(apitoken::Refusal::Owners))
        }
        Some(lock) if !admin::policy_keeps_webhooks(coord, lock, &request.name)? => {
            Ok(Some(apitoken::Refusal::Webhooks))
        }
        Some(lock) if !admin::policy_keeps_sinks(coord, lock, &request.name)? => {
            Ok(Some(apitoken::Refusal::Sinks))
        }
        _ => Ok(None),
    };
    let checked = match apitoken::check(coord, secret, &request.op, now, rule) {
        Ok(checked) => checked,
        Err(err) => {
            println!("admin token check failed op {op}: {}", err.public_text());
            return status_response(500, "The coordinator request failed.".to_string());
        }
    };
    if let Err(refusal) = checked.result {
        println!(
            "admin token deny {} op {op} reason {} status {}",
            checked.id,
            refusal.reason(),
            refusal.status()
        );
        return status_response(refusal.status(), refusal.text().to_string());
    }
    let actor = apitoken::actor_of(&checked.id);
    let value = match run_admin(
        coord,
        request,
        Caller::Token(&actor),
        policy_lock.as_ref(),
        now,
    ) {
        Ok(value) => value,
        Err(err) => {
            // W25-9: a stale policy-set is a conflict (409), not a bad request.
            let status = if matches!(err, CoordError::Conflict) {
                409
            } else {
                400
            };
            println!("admin token use {} op {op} status {status}", checked.id);
            return status_response(status, err.public_text());
        }
    };
    let Ok(detail) = serde_json::to_string(&value) else {
        return status_response(500, "The coordinator request failed.".to_string());
    };
    println!("admin token use {} op {op} status 200", checked.id);
    Response {
        ok: true,
        status: Some(200),
        detail: Some(detail),
        ..Response::default()
    }
}

/// Take the policy write lock for `admin-policy-set` only.
fn policy_lock_for(op: &str) -> Result<Option<admin::PolicyWrite>, CoordError> {
    if op == "admin-policy-set" {
        admin::policy_write_lock().map(Some)
    } else {
        Ok(None)
    }
}

fn status_response(status: u16, error: String) -> Response {
    Response {
        ok: false,
        status: Some(status),
        error: Some(error),
        ..Response::default()
    }
}

fn run_admin(
    coord: &Coordinator,
    request: &Request,
    caller: Caller<'_>,
    policy_lock: Option<&admin::PolicyWrite>,
    now: SystemTime,
) -> Result<serde_json::Value, CoordError> {
    let actor = caller.actor();
    let owner_only = || match caller {
        Caller::Owner(_) => Ok(()),
        Caller::Token(_) => Err(CoordError::Protocol(
            "The caller is not an owner.".to_string(),
        )),
    };
    let value = match request.op.as_str() {
        "admin-nodes" => admin::nodes(coord)?,
        "admin-users" => admin::users(coord)?,
        "admin-approve" => admin::approve(coord, &request.name, actor)?,
        "admin-revoke" => admin::revoke(coord, &request.name, actor, now)?,
        "admin-revoke-all" => admin::revoke_all(coord, &request.name, actor, now)?,
        "admin-revoke-undo" => admin::revoke_undo(coord, &request.name, actor, now)?,
        "admin-expire" => admin::expire(coord, &request.name, actor)?,
        "admin-routes" => admin::routes(coord)?,
        "admin-audit" => admin::audit(coord, parse_since(&request.name)?)?,
        "admin-grants" => agent::list(coord, now)?,
        "admin-grant-approve" => agent::approve(coord, &request.name, actor, now)?,
        "admin-grant-revoke" => agent::revoke(coord, &request.name, actor, now)?,
        "admin-lock" => coord.lock_show()?,
        "admin-lock-init" => {
            let ask: LockInitAsk = lock_json(&request.name)?;
            coord.lock_init(&ask.keys, actor)?
        }
        "admin-lock-sign" => {
            let ask: LockSignAsk = lock_json(&request.name)?;
            let sig = orblx_datapath::NodeLockSig {
                key_id: ask.key_id,
                sig: ask.sig,
            };
            coord.lock_sign(&ask.name, sig, actor)?
        }
        "admin-lock-update" => {
            let update: orblx_datapath::LockUpdate = lock_json(&request.name)?;
            coord.lock_update(update, actor)?
        }
        "admin-policy" => admin::policy_show(coord)?,
        "admin-policy-set" => {
            let lock = policy_lock.ok_or(CoordError::State)?;
            admin::policy_set(coord, lock, &request.name, request.expect_sha256.as_deref())?
        }
        "admin-token-create" => {
            owner_only()?;
            let ask: apitoken::CreateAsk = serde_json::from_str(&request.name)
                .map_err(|_| CoordError::Protocol("The token request is not valid.".to_string()))?;
            let made = apitoken::create(coord, &ask, actor, now)?;
            serde_json::json!({
                "op": "token-create",
                "id": made.id,
                "token": made.secret,
                "scopes": made.scopes,
                "expires_unix_ms": made.expires_unix_ms
            })
        }
        "admin-token-list" => {
            owner_only()?;
            apitoken::list(coord, now)?
        }
        "admin-token-revoke" => {
            owner_only()?;
            apitoken::revoke(coord, request.name.trim(), actor, now)?
        }
        _ => {
            return Err(CoordError::Protocol(
                "The request is not valid.".to_string(),
            ))
        }
    };
    Ok(value)
}

fn detail_response(value: &serde_json::Value) -> Result<Response, CoordError> {
    let detail = serde_json::to_string(value)
        .map_err(|_| CoordError::Protocol("The request is not valid.".to_string()))?;
    Ok(Response {
        ok: true,
        detail: Some(detail),
        ..Response::default()
    })
}

/// The node lock admin calls put one JSON document in the name field.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LockInitAsk {
    keys: Vec<String>,
}

/// One owner signature for one node.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LockSignAsk {
    name: String,
    key_id: String,
    sig: String,
}

fn lock_json<T: for<'de> serde::Deserialize<'de>>(text: &str) -> Result<T, CoordError> {
    serde_json::from_str(text)
        .map_err(|_| CoordError::Protocol("The node lock request is not valid.".to_string()))
}

/// The admin audit call puts the `since` Unix time in the name field.
fn parse_since(text: &str) -> Result<Option<u64>, CoordError> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse::<u64>()
        .map(Some)
        .map_err(|_| CoordError::Protocol("The audit time is not valid.".to_string()))
}

fn leaf_response(result: crate::state::EnrollResult) -> Response {
    let wire = result.ticket.as_ref().map(ticket_response_fields);
    Response {
        ok: true,
        certificate_pem: Some(result.certificate_pem),
        private_key_pem: Some(result.private_key_pem),
        trust_bundle_pem: Some(result.trust_bundle_pem),
        netmap_pub_hex: Some(encode_hex(&result.netmap_public)),
        netmap: Some(result.signed_netmap),
        endpoints: Some(result.endpoints),
        grants: Some(result.signed_grants),
        approved_routes: Some(result.approved_routes),
        advertised_routes: Some(result.advertised_routes),
        exit_approved: Some(result.exit_approved),
        ticket_hex: wire.as_ref().map(|item| item.ticket_hex.clone()),
        ticket_mac_hex: wire.as_ref().map(|item| item.ticket_mac_hex.clone()),
        ticket_verifier_pem: wire.as_ref().map(|item| item.ticket_verifier_pem.clone()),
        ticket_mac_key_hex: wire.as_ref().map(|item| item.ticket_mac_key_hex.clone()),
        ticket_not_before: wire.as_ref().map(|item| item.ticket_not_before),
        ticket_not_after: wire.as_ref().map(|item| item.ticket_not_after),
        svid_ca_pub_hex: wire.as_ref().map(|item| item.svid_ca_pub_hex.clone()),
        ..Response::default()
    }
}

fn netmap_response(view: &crate::state::NetmapView) -> Response {
    Response {
        ok: true,
        netmap_pub_hex: Some(encode_hex(&view.netmap_public)),
        netmap: Some(view.signed_netmap.clone()),
        endpoints: Some(view.endpoints.clone()),
        grants: Some(view.signed_grants.clone()),
        approved_routes: Some(view.approved_routes.clone()),
        advertised_routes: Some(view.advertised_routes.clone()),
        exit_approved: Some(view.exit_approved),
        ..Response::default()
    }
}

fn peer_node(coord: &Coordinator, connection: &quinn::Connection) -> Result<String, CoordError> {
    let id = peer_id(coord, connection)?;
    if id.kind() != WorkloadKind::Node {
        return Err(CoordError::Peer);
    }
    Ok(id.name().to_string())
}

fn peer_id(
    coord: &Coordinator,
    connection: &quinn::Connection,
) -> Result<orblx_identity::SpiffeId, CoordError> {
    let Some(identity) = connection.peer_identity() else {
        return Err(CoordError::Peer);
    };
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| CoordError::Peer)?;
    let Some(leaf) = chain.first() else {
        return Err(CoordError::Peer);
    };
    let material = coord.tls_material()?;
    let trust = TrustBundle::from_pem(&material.trust_pem)?;
    let deny = admin::deny_set(coord, SystemTime::now())?;
    let id = trust.authenticate_leaf(leaf.as_ref(), SystemTime::now(), &deny)?;
    if id.kind() != WorkloadKind::Node && id.kind() != WorkloadKind::User {
        return Err(CoordError::Peer);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{dispatch_token, run_admin, Caller, Request};
    use crate::apitoken::{self, admin_ops, all_scopes, scope_of, CreateAsk};
    use crate::state::{Coordinator, OidcConfig};

    fn call(op: &str, secret: &str) -> Request {
        call_with(op, "", secret)
    }

    fn call_with(op: &str, name: &str, secret: &str) -> Request {
        Request {
            op: op.to_string(),
            name: name.to_string(),
            token: None,
            id_token: None,
            nonce: None,
            endpoints: Vec::new(),
            routes: Vec::new(),
            exit_node: false,
            grant: None,
            api_token: Some(secret.to_string()),
            deny_etag: None,
            expect_sha256: None,
        }
    }

    /// The W25-3 kill check: no token runs an operation outside its scope.
    #[test]
    fn a_token_gets_403_for_every_operation_outside_its_scope() {
        let dir = std::env::temp_dir().join(format!("orblx-server-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let coord = Coordinator::open(&dir, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let now = SystemTime::now();
        for scope in all_scopes() {
            let ask = CreateAsk {
                scopes: vec![scope.to_string()],
                ttl_secs: 60,
            };
            let made =
                apitoken::create(&coord, &ask, "spiffe://orblx.local/node/owner", now).unwrap();
            for op in admin_ops() {
                let reply = dispatch_token(&coord, &call(op, &made.secret), &made.secret, now);
                let status = reply.status.unwrap();
                if scope_of(op) == Some(scope) {
                    assert!(status == 200 || status == 400, "{scope} {op} {status}");
                } else {
                    assert_eq!(status, 403, "{scope} {op}");
                    assert!(!reply.ok);
                    assert!(reply.detail.is_none());
                }
            }
        }
        let made = apitoken::create(
            &coord,
            &CreateAsk {
                scopes: vec!["nodes:read".to_string()],
                ttl_secs: 60,
            },
            "spiffe://orblx.local/node/owner",
            now,
        )
        .unwrap();
        let reply = dispatch_token(
            &coord,
            &call("admin-nodes", &made.secret),
            &made.secret,
            now,
        );
        assert_eq!(reply.status, Some(200));
        assert!(reply.detail.unwrap().contains("\"op\":\"nodes\""));
        let reply = dispatch_token(
            &coord,
            &call("admin-nodes", "orblx-at1.x"),
            "orblx-at1.x",
            now,
        );
        assert_eq!(reply.status, Some(401));
        let _ = std::fs::remove_dir_all(&dir);
    }

    const OWNER: &str = "spiffe://orblx.local/node/owner";
    const NODE_A: &str = "spiffe://orblx.local/node/a";

    fn policy_text(owners: &[&str], port: u16) -> String {
        let owners: Vec<String> = owners.iter().map(|id| format!("\"{id}\"")).collect();
        format!(
            "{{\"owners\": [{}], \"acls\": [{{\"action\": \"accept\", \"src\": [\"{NODE_A}\"], \"proto\": \"tcp\", \"dst\": [\"{OWNER}:{port}\"]}}]}}",
            owners.join(", ")
        )
    }

    fn sha(path: &std::path::Path) -> String {
        match std::fs::read(path) {
            Ok(bytes) => crate::netmap::encode_hex(&orblx_audit::sha256_digest(&bytes)),
            Err(_) => "missing".to_string(),
        }
    }

    fn deny_count(coord: &Coordinator, id: &str, reason: &str) -> usize {
        coord
            .config_audit_text()
            .unwrap()
            .lines()
            .filter(|line| {
                line.contains("\"token-deny\"")
                    && line.contains(&format!("\"target\":\"{id}\""))
                    && line.contains(&format!("reason {reason} status 403"))
            })
            .count()
    }

    /// W25-13: no token adds, removes, or changes a SIEM sink.
    #[test]
    fn a_token_cannot_change_the_siem_sinks() {
        let dir = std::env::temp_dir().join(format!("orblx-server-sinks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let coord = Coordinator::open(&dir, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let sinks = |list: &[&str], port: u16| {
            let base = policy_text(&[OWNER], port);
            format!("{{\"auditSinks\": [{}], {}", list.join(", "), &base[1..])
        };
        let hec = r#"{"name": "hec", "type": "https", "url": "https://siem:8088/services/collector", "format": "splunk-hec", "credentialFile": "hec.token"}"#;
        let hec_new_url = r#"{"name": "hec", "type": "https", "url": "https://other:8088/services/collector", "format": "splunk-hec", "credentialFile": "hec.token"}"#;
        let syslog = r#"{"name": "sys", "type": "syslog-tls", "address": "siem:6514"}"#;
        let policy_path = dir.join("policy.hujson");
        std::fs::write(&policy_path, sinks(&[hec], 22)).unwrap();
        coord.set_policy_file(&policy_path).unwrap();
        assert_eq!(coord.audit_sinks().unwrap().len(), 1);
        let now = SystemTime::now();
        let made = apitoken::create(
            &coord,
            &CreateAsk {
                scopes: all_scopes().iter().map(|s| s.to_string()).collect(),
                ttl_secs: 60,
            },
            OWNER,
            now,
        )
        .unwrap();
        let before = sha(&policy_path);
        for list in [vec![], vec![hec, syslog], vec![hec_new_url]] {
            let ask = call_with("admin-policy-set", &sinks(&list, 22), &made.secret);
            let reply = dispatch_token(&coord, &ask, &made.secret, now);
            assert_eq!(reply.status, Some(403), "{list:?}");
        }
        assert_eq!(sha(&policy_path), before);
        assert_eq!(deny_count(&coord, &made.id, "sinks"), 3);
        // The same sinks in a new policy is allowed.
        let ask = call_with("admin-policy-set", &sinks(&[hec], 2222), &made.secret);
        let reply = dispatch_token(&coord, &ask, &made.secret, now);
        assert_eq!(reply.status, Some(200));
        assert_ne!(sha(&policy_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// W25-7: no token adds, removes, or changes an audit webhook URL.
    #[test]
    fn a_token_cannot_change_the_audit_webhooks() {
        let dir = std::env::temp_dir().join(format!("orblx-server-hooks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let coord = Coordinator::open(&dir, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let hooks = |urls: &[&str], port: u16| {
            let base = policy_text(&[OWNER], port);
            let list: Vec<String> = urls.iter().map(|url| format!("\"{url}\"")).collect();
            format!("{{\"auditWebhooks\": [{}], {}", list.join(", "), &base[1..])
        };
        let policy_path = dir.join("policy.hujson");
        let siem = "http://siem:9000/hook";
        std::fs::write(&policy_path, hooks(&[siem], 22)).unwrap();
        coord.set_policy_file(&policy_path).unwrap();
        assert_eq!(coord.audit_webhook_urls().unwrap(), [siem]);
        let now = SystemTime::now();
        let made = apitoken::create(
            &coord,
            &CreateAsk {
                scopes: all_scopes().iter().map(|s| s.to_string()).collect(),
                ttl_secs: 60,
            },
            OWNER,
            now,
        )
        .unwrap();
        let before = sha(&policy_path);
        for urls in [
            vec![],
            vec![siem, "http://other:9000/hook"],
            vec!["http://other:9000/hook"],
        ] {
            let ask = call_with("admin-policy-set", &hooks(&urls, 22), &made.secret);
            let reply = dispatch_token(&coord, &ask, &made.secret, now);
            assert_eq!(reply.status, Some(403), "{urls:?}");
        }
        assert_eq!(sha(&policy_path), before);
        assert_eq!(coord.audit_webhook_urls().unwrap(), [siem]);
        assert_eq!(deny_count(&coord, &made.id, "webhooks"), 3);
        // The same webhooks in a new policy is allowed.
        let ask = call_with("admin-policy-set", &hooks(&[siem], 2222), &made.secret);
        let reply = dispatch_token(&coord, &ask, &made.secret, now);
        assert_eq!(reply.status, Some(200));
        assert_ne!(sha(&policy_path), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// W25-3b: no token changes the owners, the node lock signers, or the token rules.
    #[test]
    fn a_token_cannot_escalate_past_its_scope() {
        let dir = std::env::temp_dir().join(format!("orblx-server-escal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let coord = Coordinator::open(&dir, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let policy_path = dir.join("policy.hujson");
        std::fs::write(&policy_path, policy_text(&[OWNER], 22)).unwrap();
        coord.set_policy_file(&policy_path).unwrap();
        let now = SystemTime::now();
        let owner_id = orblx_identity::SpiffeId::parse(OWNER).unwrap();
        let a_id = orblx_identity::SpiffeId::parse(NODE_A).unwrap();
        // A policy:write token and a token with every scope get the same refusals.
        for scopes in [
            vec!["policy:write".to_string()],
            all_scopes().iter().map(|s| s.to_string()).collect(),
        ] {
            let made = apitoken::create(
                &coord,
                &CreateAsk {
                    scopes,
                    ttl_secs: 60,
                },
                OWNER,
                now,
            )
            .unwrap();
            let before = sha(&policy_path);
            let tokens_before = sha(&dir.join(apitoken::API_TOKEN_FILE));
            for owners in [vec![OWNER, NODE_A], vec![], vec![NODE_A]] {
                let ask = call_with("admin-policy-set", &policy_text(&owners, 22), &made.secret);
                let reply = dispatch_token(&coord, &ask, &made.secret, now);
                assert_eq!(reply.status, Some(403), "{owners:?}");
                assert!(!reply.ok);
                assert!(reply.detail.is_none());
            }
            assert_eq!(sha(&policy_path), before);
            assert!(coord.caller_is_owner(&owner_id).unwrap());
            assert!(!coord.caller_is_owner(&a_id).unwrap());
            assert_eq!(deny_count(&coord, &made.id, "owners"), 3);
            // The same owners in a new policy is allowed.
            let ask = call_with(
                "admin-policy-set",
                &policy_text(&[OWNER], 2222),
                &made.secret,
            );
            let reply = dispatch_token(&coord, &ask, &made.secret, now);
            assert_eq!(reply.status, Some(200));
            assert_ne!(sha(&policy_path), before);
            assert!(coord.caller_is_owner(&owner_id).unwrap());
            std::fs::write(&policy_path, policy_text(&[OWNER], 22)).unwrap();
            // Token rules: owner SVID only, for every token.
            for (op, name) in [
                (
                    "admin-token-create",
                    r#"{"scopes":["policy:write"],"ttl_secs":60}"#.to_string(),
                ),
                ("admin-token-list", String::new()),
                ("admin-token-revoke", made.id.clone()),
            ] {
                let reply = dispatch_token(
                    &coord,
                    &call_with(op, &name, &made.secret),
                    &made.secret,
                    now,
                );
                assert_eq!(reply.status, Some(403), "{op}");
            }
            assert_eq!(sha(&dir.join(apitoken::API_TOKEN_FILE)), tokens_before);
        }
        // Node lock signers: lock:write only. A policy:write token gets 403.
        let made = apitoken::create(
            &coord,
            &CreateAsk {
                scopes: vec!["policy:write".to_string()],
                ttl_secs: 60,
            },
            OWNER,
            now,
        )
        .unwrap();
        let lock_before = sha(&dir.join(crate::nodelock::COORD_LOCK_FILE));
        let key = "a".repeat(64);
        for (op, name) in [
            ("admin-lock-init", format!(r#"{{"keys":["{key}"]}}"#)),
            ("admin-lock-update", "{}".to_string()),
            ("admin-lock-sign", "{}".to_string()),
        ] {
            let reply = dispatch_token(
                &coord,
                &call_with(op, &name, &made.secret),
                &made.secret,
                now,
            );
            assert_eq!(reply.status, Some(403), "{op}");
        }
        assert_eq!(
            sha(&dir.join(crate::nodelock::COORD_LOCK_FILE)),
            lock_before
        );
        assert_eq!(deny_count(&coord, &made.id, "scope"), 3);
        // Only the owner SVID path can change the owners.
        let lock = crate::admin::policy_write_lock().unwrap();
        let ask = call_with("admin-policy-set", &policy_text(&[OWNER, NODE_A], 22), "");
        run_admin(&coord, &ask, Caller::Owner(OWNER), Some(&lock), now).unwrap();
        drop(lock);
        assert!(coord.caller_is_owner(&a_id).unwrap());
        let audit = coord.config_audit_text().unwrap();
        let _ = orblx_audit::verify_config_jsonl(&audit).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn replace_count(coord: &Coordinator) -> usize {
        coord
            .config_audit_text()
            .unwrap()
            .lines()
            .filter(|line| line.contains("\"policy-replace\""))
            .count()
    }

    /// W25-9: a stale policy-set gets 409 and does not write. The same text does not write.
    #[test]
    fn policy_set_with_an_expected_sha_refuses_a_stale_write() {
        let dir = std::env::temp_dir().join(format!("orblx-server-expect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let coord = Coordinator::open(&dir, "coord", OidcConfig::TokenOnly).unwrap();
        coord.enable_config_audit().unwrap();
        let policy_path = dir.join("policy.hujson");
        std::fs::write(&policy_path, policy_text(&[OWNER], 22)).unwrap();
        coord.set_policy_file(&policy_path).unwrap();
        let now = SystemTime::now();
        let made = apitoken::create(
            &coord,
            &CreateAsk {
                scopes: vec!["policy:write".to_string()],
                ttl_secs: 60,
            },
            OWNER,
            now,
        )
        .unwrap();
        let live = sha(&policy_path);
        let next = policy_text(&[OWNER], 2222);
        let with_expect = |text: &str, expect: &str| {
            let mut ask = call_with("admin-policy-set", text, &made.secret);
            ask.expect_sha256 = Some(expect.to_string());
            dispatch_token(&coord, &ask, &made.secret, now)
        };
        // A stale sha: 409, and the file does not change.
        let replaces = replace_count(&coord);
        let reply = with_expect(&next, &"0".repeat(64));
        assert_eq!(reply.status, Some(409));
        assert!(!reply.ok);
        assert!(reply.error.unwrap().contains("live policy changed"));
        assert_eq!(sha(&policy_path), live);
        assert_eq!(replace_count(&coord), replaces);
        // The live sha: 200, and the file changes.
        let reply = with_expect(&next, &live);
        assert_eq!(reply.status, Some(200));
        assert!(reply.detail.unwrap().contains("\"changed\":true"));
        let applied = sha(&policy_path);
        assert_ne!(applied, live);
        assert_eq!(replace_count(&coord), replaces + 1);
        // The same text again: 200, "changed": false, and no new policy record.
        let reply = with_expect(&next, &applied);
        assert_eq!(reply.status, Some(200));
        assert!(reply.detail.unwrap().contains("\"changed\":false"));
        assert_eq!(sha(&policy_path), applied);
        assert_eq!(replace_count(&coord), replaces + 1);
        // The sha that the first diff saw is now stale.
        let reply = with_expect(&policy_text(&[OWNER], 23), &live);
        assert_eq!(reply.status, Some(409));
        assert_eq!(sha(&policy_path), applied);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
