use crate::{cli::config::RouteMatch, error::Error, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, HeaderValue, Request},
    response::IntoResponse,
};
use hyper::{HeaderMap, StatusCode};
use hyper_util::rt::TokioIo;
use std::{io::Write, net::IpAddr, sync::Arc};
use tracing::debug;

pub async fn handle_any(
    State(state): State<Arc<AppState>>,
    ip: ConnectInfo<std::net::SocketAddr>,
    mut req: Request<Body>,
) -> Result<impl IntoResponse, Error> {
    let source_ip = &ip.ip();
    let upgrade_intent = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();
    let (mut parts, body) = req.into_parts();
    let host_header = parts.headers.get(hyper::header::HOST).cloned().or_else(|| {
        parts
            .uri
            .authority()
            .and_then(|auth| HeaderValue::from_str(auth.host()).ok())
    });
    let host_str = host_header
        .as_ref()
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unkown_host");
    let Some(matched_route) = parts.extensions.remove::<RouteMatch>().or_else(|| {
        state
            .dynamic_config
            .load()
            .find_route(host_str, parts.uri.path())
    }) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    if matched_route.catch_all.as_ref() == "/" && parts.uri.query().is_none() {
        parts.uri = matched_route.route.upstream.clone()
    } else {
        let pq = match parts.uri.query() {
            Some(q) if !q.is_empty() => {
                let mut s = String::with_capacity(matched_route.catch_all.len() + 1 + q.len());
                s.push_str(&matched_route.catch_all);
                s.push('?');
                s.push_str(q);
                axum::http::uri::PathAndQuery::try_from(s)?
            }
            _ => {
                if matched_route.catch_all.as_ref() == "/" {
                    axum::http::uri::PathAndQuery::from_static("/")
                } else {
                    axum::http::uri::PathAndQuery::try_from(matched_route.catch_all.as_ref())?
                }
            }
        };
        let mut uri_parts = axum::http::uri::Parts::default();
        uri_parts.scheme = matched_route.route.upstream_scheme.clone();
        uri_parts.authority = matched_route.route.upstream_authority.clone();
        uri_parts.path_and_query = Some(pq);
        parts.uri = axum::http::Uri::from_parts(uri_parts)?;
    }

    let tls_no_verify = matched_route.route.tls_insecure_skip_verify;
    parts.version = hyper::Version::HTTP_11;
    let _ = inject_headers(
        &mut parts.headers,
        source_ip,
        &matched_route.route.upstream_host_header,
        host_header,
    );
    let req = Request::from_parts(parts, body);

    let permit = matched_route
        .route
        .upstream_limiter
        .acquire()
        .await
        .map_err(|_| Error::UpstreamTimeout)?;
    let pool = if tls_no_verify {
        &state.insecure_connection_pool
    } else {
        &state.connection_pool
    };

    match pool.request(req).await {
        Ok(mut res) => {
            drop(permit);
            let headers = res.headers_mut();
            headers.remove(hyper::header::UPGRADE);
            headers.insert(
                hyper::header::CONNECTION,
                HeaderValue::from_static("keep-alive"),
            );
            headers.insert(
                HeaderName::from_static("keep-alive"),
                HeaderValue::from_static("timeout=65"),
            );
            headers.insert(hyper::header::SERVER, HeaderValue::from_static("Torii"));
            headers.insert(
                hyper::header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );
            headers.insert(
                hyper::header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                hyper::header::X_FRAME_OPTIONS,
                HeaderValue::from_static("SAMEORIGIN"),
            );
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
            drop(permit);
            debug!("Upstream Error: {e}");
            Err(Error::UpstreamTimeout)
        }
    }
}

const STRIP_HEADERS: [HeaderName; 13] = [
    HeaderName::from_static("x-forwarded-user"),
    HeaderName::from_static("x-forwarded-email"),
    HeaderName::from_static("x-forwarded-groups"),
    HeaderName::from_static("x-real-ip"),
    hyper::header::SERVER,
    hyper::header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-authenticate"),
    HeaderName::from_static("proxy-authorization"),
    HeaderName::from_static("te"),
    HeaderName::from_static("trailers"),
    hyper::header::TRANSFER_ENCODING,
    hyper::header::UPGRADE,
];

fn inject_headers(
    request_headers: &mut HeaderMap,
    source_ip: &IpAddr,
    upstream_host: &HeaderValue,
    original_host: Option<HeaderValue>,
) -> Result<(), Error> {
    for header in &STRIP_HEADERS {
        request_headers.remove(header);
    }
    request_headers.insert(
        hyper::header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );
    let mut ip_buf = [0u8; 46];
    let len = {
        let mut cursor = std::io::Cursor::new(&mut ip_buf[..]);
        write!(cursor, "{}", source_ip)?;
        cursor.position() as usize
    };
    let ip_header_val = HeaderValue::from_bytes(&ip_buf[..len])?;
    request_headers.insert(HeaderName::from_static("x-forwarded-for"), ip_header_val);
    request_headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    request_headers.insert(hyper::header::HOST, upstream_host.clone());
    if let Some(host_val) = original_host {
        request_headers.insert(HeaderName::from_static("x-forwarded-host"), host_val);
    }
    Ok(())
}
