use crate::{error::Error, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, HeaderValue, Request},
    response::IntoResponse,
};
use hyper::{HeaderMap, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tracing::{debug, error};

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
        .or_else(|| parts.uri.authority().map(|auth| auth.host()))
        .unwrap_or("unknown_host")
        .to_string();
    let path = parts.uri.path();
    let Some(matched_route) = state.dynamic_config.load().find_route(&host_string, path) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    let upstream_base = matched_route.route.upstream.to_string();
    let upstream_clean = upstream_base.trim_end_matches('/');
    let upstream_uri = upstream_base.parse::<hyper::Uri>()?;
    let upstream_host_header = upstream_uri
        .authority()
        .map(|a| a.as_str())
        .unwrap_or("localhost")
        .to_string();

    let safe_path = if matched_route.catch_all.starts_with("/") {
        matched_route.catch_all.clone()
    } else {
        format!("/{}", matched_route.catch_all)
    };

    let query = parts.uri.query().unwrap_or("");
    let query_suffix = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", query)
    };

    let new_uri = format!("{}{}{}", upstream_clean, safe_path, query_suffix);
    let tls_no_verify = matched_route.route.tls_insecure_skip_verify;
    parts.uri = new_uri.parse()?;
    parts.version = hyper::Version::HTTP_11;
    inject_headers(
        &mut parts.headers,
        source_ip,
        &upstream_host_header,
        &host_string,
    );
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
                            if let Err(e) =
                                tokio::io::copy_bidirectional(&mut client_io, &mut server_io).await
                            {
                                debug!("WebSocket stream closed or interrupted: {}", e)
                            }
                        }
                    });
                } else {
                    debug!("Failed to upgrade. Client or server rejected the handshake.")
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

fn inject_headers(
    request_headers: &mut HeaderMap,
    source_ip: String,
    upstream_host: &str,
    original_host: &str,
) {
    request_headers.remove("x-forwarded-user");
    request_headers.remove("x-forwarded-email");
    request_headers.remove("x-forwarded-groups");
    request_headers.remove("x-forwarded-for");
    request_headers.remove("x-real-ip");
    request_headers.remove(hyper::header::SERVER);

    request_headers.remove("Proxy-Authenticate");
    request_headers.remove("Proxy-Authorization");
    request_headers.remove("Te");
    request_headers.remove("Trailers");
    request_headers.remove("Transfer-Encoding");

    request_headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&source_ip).unwrap(),
    );
    request_headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    request_headers.insert(
        hyper::header::HOST,
        HeaderValue::from_str(upstream_host).unwrap(),
    );
    request_headers.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_str(original_host).unwrap(),
    );
    request_headers.insert(hyper::header::SERVER, HeaderValue::from_static("Torii"));
    request_headers.insert(
        hyper::header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    request_headers.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    request_headers.insert(
        hyper::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
}
