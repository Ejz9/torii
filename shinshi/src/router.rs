use crate::{error::Error, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, HeaderValue, Request},
    response::IntoResponse,
};
use hyper::{HeaderMap, StatusCode};
use hyper_util::rt::TokioIo;
use keidai::{ActiveRoute, ShinshiConfig};
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use tracing::debug;

/// Request and response pipeline based on RFC 9110, RFC 9113, and RFC 6455
pub async fn handle_any(
    State(state): State<Arc<AppState>>,
    ip: ConnectInfo<std::net::SocketAddr>,
    mut req: Request<Body>,
) -> Result<impl IntoResponse, Error> {
    let source_ip = &ip.ip();
    let client_version = req.version();
    let upgrade_intent = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();
    let (mut parts, body) = req.into_parts();
    let host_str = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| parts.uri.host())
        .unwrap_or("unkown_host");
    let domain = host_str.split(':').next().unwrap_or(host_str);
    let routes = state.routes.load();
    let Some(route) = routes.get(domain) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let mut uri_parts = parts.uri.into_parts();
    uri_parts.scheme = route.upstream_scheme.clone();
    uri_parts.authority = route.upstream_authority.clone();
    parts.uri = axum::http::Uri::from_parts(uri_parts)?;

    let tls_no_verify = route.tls_insecure_skip_verify;
    parts.version = hyper::Version::HTTP_11;
    let _ = inject_headers(&mut parts.headers, source_ip, &route.upstream_host_header);
    let req = Request::from_parts(parts, body);

    let permit = route
        .upstream_limiter
        .acquire()
        .await
        .map_err(|_| anyhow::anyhow!("Upstream limiter closed"))?;
    let pool = if tls_no_verify {
        &state.insecure_connection_pool
    } else {
        &state.connection_pool
    };

    match pool.request(req).await {
        Ok(mut res) => {
            drop(permit);
            let is_upgrade = res.status() == StatusCode::SWITCHING_PROTOCOLS;
            let headers = res.headers_mut();
            headers.reserve(6);
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
            if is_upgrade {
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
            } else {
                headers.remove(hyper::header::UPGRADE);
                headers.remove(hyper::header::TRANSFER_ENCODING);
                headers.remove(HeaderName::from_static("proxy-connection"));
                headers.remove(hyper::header::CONNECTION);
                headers.remove(HeaderName::from_static("keep-alive"));
                if client_version < hyper::Version::HTTP_2 {
                    headers.insert(
                        hyper::header::CONNECTION,
                        HeaderValue::from_static("keep-alive"),
                    );
                    headers.insert(
                        HeaderName::from_static("keep-alive"),
                        HeaderValue::from_static("timeout=65"),
                    );
                }
            }
            Ok(res.map(|body| Body::new(body)).into_response())
        }
        Err(e) => {
            drop(permit);
            debug!("Upstream Error: {e}");
            Ok(StatusCode::BAD_GATEWAY.into_response())
        }
    }
}

fn inject_headers(
    request_headers: &mut HeaderMap,
    source_ip: &IpAddr,
    upstream_host: &HeaderValue,
) -> Result<(), Error> {
    let connection_tokens = request_headers
        .get(hyper::header::CONNECTION)
        .and_then(|h| h.to_str().ok());
    let mut to_remove: [Option<hyper::header::HeaderName>; 16] = Default::default();
    let mut remove_count = 0;
    for name in request_headers.keys() {
        let is_conn_token = connection_tokens.is_some_and(|tokens| {
            tokens
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case(name.as_str()))
        });
        if is_forbidden_header(name.as_str()) || is_conn_token {
            if remove_count >= 16 {
                return Err(anyhow::anyhow!("Too many hop-by-hop headers").into());
            }
            to_remove[remove_count] = Some(name.clone());
            remove_count += 1;
        }
    }
    for i in 0..remove_count {
        if let Some(ref name) = to_remove[i] {
            request_headers.remove(name);
        }
    }
    request_headers.insert(
        hyper::header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );
    let ip_header_val = match source_ip {
        IpAddr::V4(ipv4) => {
            let mut buf = [0u8; 15];
            let len = format_ipv4_ascii(ipv4, &mut buf);
            HeaderValue::from_bytes(&buf[..len])?
        }
        IpAddr::V6(ipv6) => HeaderValue::from_str(&ipv6.to_string())?,
    };
    request_headers.insert(HeaderName::from_static("x-forwarded-for"), ip_header_val);
    request_headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    if let Some(host_val) = request_headers.remove(hyper::header::HOST) {
        request_headers.insert(HeaderName::from_static("x-forwarded-host"), host_val);
    }
    request_headers.insert(hyper::header::HOST, upstream_host.clone());
    Ok(())
}

fn is_forbidden_header(name: &str) -> bool {
    name.starts_with("x-forwarded-")
        || matches!(
            name,
            "x-real-ip"
                | "server"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
        )
}

fn format_ipv4_ascii(ipv4: &std::net::Ipv4Addr, buf: &mut [u8; 15]) -> usize {
    let octets = ipv4.octets();
    let mut pos = 0;
    for (idx, &octet) in octets.iter().enumerate() {
        if idx > 0 {
            buf[pos] = b'.';
            pos += 1;
        }
        if octet >= 100 {
            buf[pos] = b'0' + (octet / 100);
            buf[pos + 1] = b'0' + ((octet / 10) % 10);
            buf[pos + 2] = b'0' + (octet % 10);
            pos += 3;
        } else if octet >= 10 {
            buf[pos] = b'0' + (octet / 10);
            buf[pos + 1] = b'0' + (octet % 10);
            pos += 2;
        } else {
            buf[pos] = b'0' + octet;
            pos += 1;
        }
    }
    pos
}

pub fn build_active_routes(config: &ShinshiConfig) -> HashMap<String, Arc<ActiveRoute>> {
    let mut map = HashMap::new();
    for (route, cfg) in &config.routes {
        if let Ok(active) = ActiveRoute::try_from(cfg.clone()) {
            let active_arc = Arc::new(active);
            map.insert(route.to_string(), Arc::clone(&active_arc));
            for alias in &cfg.aliases {
                map.insert(alias.to_string(), Arc::clone(&active_arc));
            }
        }
    }
    map
}
