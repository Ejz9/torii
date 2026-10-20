use crate::{cli::config::RouteMatch, error::Error, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, HeaderValue, Request},
    response::IntoResponse,
};
use hyper::{HeaderMap, StatusCode};
use hyper_util::rt::TokioIo;
use std::{net::IpAddr, sync::Arc};
use tracing::debug;

/// Request and response pipeline based on RFC 9110, RFC 9113, and RFC 6455
pub async fn handle_any(
    State(state): State<Arc<AppState>>,
    ip: ConnectInfo<std::net::SocketAddr>,
    mut req: Request<Body>,
) -> Result<impl IntoResponse, Error> {
    let source_ip = &ip.ip();
    let upgrade_intent = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();
    let (mut parts, body) = req.into_parts();
    let host_str = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| parts.uri.host())
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
            headers.insert(
                hyper::header::ALT_SVC,
                HeaderValue::from_static("h3=\":443\"; ma=86400"),
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
                headers.insert(
                    hyper::header::CONNECTION,
                    HeaderValue::from_static("keep-alive"),
                );
                headers.insert(
                    HeaderName::from_static("keep-alive"),
                    HeaderValue::from_static("timeout=65"),
                );
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
                return Err(Error::Http(
                    StatusCode::BAD_REQUEST,
                    "Too many hop-by-hop headers",
                ));
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
