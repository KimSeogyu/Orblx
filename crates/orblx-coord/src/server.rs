use std::net::SocketAddr;
use std::time::SystemTime;

use orblx_identity::{DenySet, GoogleJwks, TrustBundle, WorkloadKind};
use rustls::pki_types::CertificateDer;

use crate::error::CoordError;
use crate::http_util::fetch_google_jwks;
use crate::netmap::encode_hex;
use crate::proto::{self, Request, Response};
use crate::state::Coordinator;
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
    let material = coord.tls_material()?;
    let endpoint = tlsutil::server_endpoint(&material, listen)?;
    let addr = endpoint.local_addr().map_err(CoordError::io)?;
    let coord = coord.clone();
    let handle = tokio::spawn(async move {
        let _ = accept_loop(endpoint, coord).await;
    });
    Ok((addr, handle))
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

async fn accept_loop(endpoint: quinn::Endpoint, coord: Coordinator) -> Result<(), CoordError> {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let coord = coord.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = handle_connection(&coord, connection).await {
                        println!("coord request failed: {}", err.public_text());
                    }
                }
                Err(_) => println!("coord handshake failed"),
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    coord: &Coordinator,
    connection: quinn::Connection,
) -> Result<(), CoordError> {
    let (mut send, mut recv) = connection.accept_bi().await.map_err(|_| {
        println!("coord rejected: the stream did not open");
        CoordError::Protocol("The request is not valid.".to_string())
    })?;
    let request = proto::read_json::<Request>(&mut recv).await?;
    let response = match dispatch(coord, &connection, request).await {
        Ok(response) => response,
        Err(err) => {
            println!("coord rejected: {}", err.public_text());
            Response {
                ok: false,
                error: Some(err.public_text()),
                certificate_pem: None,
                private_key_pem: None,
                trust_bundle_pem: None,
                netmap_pub_hex: None,
                netmap: None,
                endpoints: None,
            }
        }
    };
    proto::write_json(&mut send, &response).await?;
    let _ = send.finish();
    drop(send);
    drop(recv);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), connection.closed()).await;
    Ok(())
}

async fn dispatch(
    coord: &Coordinator,
    connection: &quinn::Connection,
    request: Request,
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
            let peer = peer_node(connection, &coord.tls_material()?.trust_pem)?;
            let peer = peer.ok_or(CoordError::Peer)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let result = coord.renew_node(&request.name, now)?;
            println!("renewed {}", result.name);
            Ok(leaf_response(result))
        }
        "netmap" => {
            let peer = peer_node(connection, &coord.tls_material()?.trust_pem)?;
            let peer = peer.ok_or(CoordError::Peer)?;
            if peer != request.name {
                return Err(CoordError::Peer);
            }
            let view = coord.netmap_for(&request.name)?;
            println!("netmap {}", request.name);
            Ok(Response {
                ok: true,
                error: None,
                certificate_pem: None,
                private_key_pem: None,
                trust_bundle_pem: None,
                netmap_pub_hex: Some(encode_hex(&view.netmap_public)),
                netmap: Some(view.signed_netmap),
                endpoints: Some(view.endpoints),
            })
        }
        _ => Err(CoordError::Protocol(
            "The request is not valid.".to_string(),
        )),
    }
}

fn leaf_response(result: crate::state::EnrollResult) -> Response {
    Response {
        ok: true,
        error: None,
        certificate_pem: Some(result.certificate_pem),
        private_key_pem: Some(result.private_key_pem),
        trust_bundle_pem: Some(result.trust_bundle_pem),
        netmap_pub_hex: Some(encode_hex(&result.netmap_public)),
        netmap: Some(result.signed_netmap),
        endpoints: Some(result.endpoints),
    }
}

fn peer_node(
    connection: &quinn::Connection,
    trust_pem: &str,
) -> Result<Option<String>, CoordError> {
    let Some(identity) = connection.peer_identity() else {
        return Ok(None);
    };
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| CoordError::Peer)?;
    let Some(leaf) = chain.first() else {
        return Ok(None);
    };
    let trust = TrustBundle::from_pem(trust_pem)?;
    let id = trust.authenticate_leaf(leaf.as_ref(), SystemTime::now(), &DenySet::empty())?;
    if id.kind() != WorkloadKind::Node {
        return Err(CoordError::Peer);
    }
    Ok(Some(id.name().to_string()))
}
