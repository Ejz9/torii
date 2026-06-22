use crate::{error::Error, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, HeaderValue, Request},
    response::IntoResponse,
};
use hyper::{HeaderMap, StatusCode, header};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tracing::error;

pub async fn handle_any(
    State(state): State<Arc<AppState>>,
    ip: ConnectInfo<std::net::SocketAddr>,
    mut req: Request<Body>,
) -> Result<impl IntoResponse, Error> {
    let source_ip = ip.ip().to_string();
    let upgrade_intent = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();
    let (mut parts, body) = req.into_parts();
    let host_string = parts
        .headers
        .get("HOST")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown_host");
    let mut is_websocket = false;
    let upgrade_header = parts
        .headers
        .get("Upgrade")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let connection_header = parts
        .headers
        .get("Connection")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if upgrade_header == "websocket" && connection_header.contains("upgrade") {
        is_websocket = true;
    };
    let path = parts.uri.path();
    let Some(matched_route) = state.dynamic_config.load().find_route(host_string, path) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let upstream_base = matched_route.route.upstream.to_string();
    let upstream_clean = upstream_base.trim_end_matches('/');

    let new_uri = format!("{}/{}", upstream_clean, matched_route.catch_all);
    let tls_no_verify = matched_route.route.tls_insecure_skip_verify;
    parts.uri = new_uri.parse()?;
    inject_headers(&mut parts.headers, source_ip, is_websocket);
    let req = Request::from_parts(parts, body);

    let pool = if tls_no_verify {
        &state.insecure_connection_pool
    } else {
        &state.connection_pool
    };

    match pool.request(req).await {
        Ok(mut res) => {
            if res.status() == StatusCode::SWITCHING_PROTOCOLS {
                if let Some(client_intent) = upgrade_intent {
                    let server_intent = hyper::upgrade::on(&mut res);
                    tokio::spawn(async move {
                        if let (Ok(client_stream), Ok(server_stream)) =
                            tokio::join!(client_intent, server_intent)
                        {
                            let mut client_io = TokioIo::new(client_stream);
                            let mut server_io = TokioIo::new(server_stream);
                            let _ =
                                tokio::io::copy_bidirectional(&mut client_io, &mut server_io).await;
                        }
                    });
                }
            }
            Ok(res.map(|body| Body::new(body)).into_response())
        }
        Err(e) => {
            error!("URI: {}, Error: {}", new_uri, e);
            Err(Error::UpstreamTimeout)
        }
    }
}

fn inject_headers(request_headers: &mut HeaderMap, source_ip: String, is_websocket: bool) {
    let header_source = HeaderValue::from_str(&source_ip).unwrap();
    request_headers.remove("x-forwarded-user");
    request_headers.remove(header::AUTHORIZATION);
    request_headers.remove("x-forwarded-email");
    request_headers.remove("x-forwarded-groups");
    request_headers.remove("x-forwarded-for");
    request_headers.remove("x-forwarded-host");
    request_headers.remove("x-forwarded-proto");
    request_headers.remove("x-real-ip");

    if !is_websocket {
        request_headers.remove("Connection");
        request_headers.remove("Upgrade");
    }
    request_headers.remove("Keep-Alive");
    request_headers.remove("Proxy-Authenticate");
    request_headers.remove("Proxy-Authorization");
    request_headers.remove("Te");
    request_headers.remove("Trailers");
    request_headers.remove("Transfer-Encoding");

    request_headers.insert(HeaderName::from_static("x-forwarded-for"), header_source);
}
