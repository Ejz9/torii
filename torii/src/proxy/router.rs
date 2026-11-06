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
    let client_version = req.version();
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
    inject_headers(
        &mut parts.headers,
        source_ip,
        &matched_route.route.upstream_host_header,
        upgrade_intent.is_some(),
    )?;
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
            Err(Error::UpstreamTimeout)
        }
    }
}

fn inject_headers(
    request_headers: &mut HeaderMap,
    source_ip: &IpAddr,
    upstream_host: &HeaderValue,
    is_upgrade: bool,
) -> Result<(), Error> {
    for header in &STRIP_HEADERS {
        if is_upgrade && *header == hyper::header::UPGRADE {
            continue;
        }
        request_headers.remove(header);
    }

    let mut tokens_to_remove: [Option<HeaderName>; 16] = Default::default();
    let mut token_count = 0;

    for conn_val in request_headers.get_all(hyper::header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            if !conn_str.eq_ignore_ascii_case("keep-alive")
                && !conn_str.eq_ignore_ascii_case("close")
            {
                for token in conn_str.split(',') {
                    let trimmed = token.trim();
                    if !trimmed.is_empty() {
                        if is_upgrade && trimmed.eq_ignore_ascii_case("upgrade") {
                            continue;
                        }
                        if token_count >= 16 {
                            return Err(Error::Http(
                                StatusCode::BAD_REQUEST,
                                "Too many hop-by-hop headers",
                            ));
                        }
                        if let Ok(name) = hyper::header::HeaderName::from_bytes(trimmed.as_bytes())
                        {
                            if matches!(
                                name,
                                hyper::header::CONTENT_LENGTH
                                    | hyper::header::HOST
                                    | hyper::header::TE
                            ) {
                                continue;
                            }
                            tokens_to_remove[token_count] = Some(name);
                            token_count += 1;
                        }
                    }
                }
            }
        }
    }
    request_headers.remove(hyper::header::CONNECTION);
    for name in &tokens_to_remove[..token_count] {
        if let Some(header_name) = name {
            request_headers.remove(header_name);
        }
    }
    if is_upgrade {
        request_headers.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
    } else {
        request_headers.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
    }

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

const STRIP_HEADERS: [hyper::header::HeaderName; 19] = [
    hyper::header::TRANSFER_ENCODING,
    hyper::header::UPGRADE,
    hyper::header::TE,
    hyper::header::TRAILER,
    hyper::header::SERVER,
    hyper::header::HeaderName::from_static("trailers"),
    hyper::header::HeaderName::from_static("keep-alive"),
    hyper::header::HeaderName::from_static("proxy-connection"),
    hyper::header::HeaderName::from_static("proxy-authenticate"),
    hyper::header::HeaderName::from_static("proxy-authorization"),
    hyper::header::HeaderName::from_static("forwarded"),
    hyper::header::HeaderName::from_static("x-real-ip"),
    hyper::header::HeaderName::from_static("x-forwarded-for"),
    hyper::header::HeaderName::from_static("x-forwarded-host"),
    hyper::header::HeaderName::from_static("x-forwarded-proto"),
    hyper::header::HeaderName::from_static("x-forwarded-port"),
    hyper::header::HeaderName::from_static("x-forwarded-user"),
    hyper::header::HeaderName::from_static("x-forwarded-email"),
    hyper::header::HeaderName::from_static("x-forwarded-groups"),
];

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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{CONNECTION, HOST, HeaderMap, HeaderValue, TRANSFER_ENCODING, UPGRADE};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_inject_headers_standard_request() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("client.example.com"));
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert(
            hyper::header::USER_AGENT,
            HeaderValue::from_static("curl/8.0"),
        );

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let upstream_host = HeaderValue::from_static("backend.internal:80");

        let _ = inject_headers(&mut headers, &ip, &upstream_host, false);

        assert_eq!(headers.get(HOST).unwrap(), "backend.internal:80");
        assert_eq!(headers.get(CONNECTION).unwrap(), "keep-alive");
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "192.168.1.50");
        assert_eq!(headers.get(hyper::header::USER_AGENT).unwrap(), "curl/8.0");
    }

    #[test]
    fn test_strip_inherent_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        headers.insert(
            HeaderName::from_static("proxy-connection"),
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert(
            HeaderName::from_static("x-real-ip"),
            HeaderValue::from_static("1.2.3.4"),
        );
        headers.insert(
            HeaderName::from_static("x-forward-user"),
            HeaderValue::from_static("admin"),
        );

        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 1, 30));
        let upstream_host = HeaderValue::from_static("backend:80");

        let _ = inject_headers(&mut headers, &ip, &upstream_host, false);

        assert!(headers.get(TRANSFER_ENCODING).is_none());
        assert!(headers.get("proxy-connection").is_none());
        assert!(headers.get("x-real-ip").is_none());
        assert!(headers.get("x-forwarded-user").is_none());
        assert_eq!(headers.get(HOST).unwrap(), "backend:80");
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "10.99.1.30");
    }

    #[test]
    fn test_dynamic_connection_token_stripping() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("X-Custom-Secret, X-Internal-Flag"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-secret"),
            HeaderValue::from_static("supersecret"),
        );
        headers.insert(
            HeaderName::from_static("x-internal-flag"),
            HeaderValue::from_static("true"),
        );
        headers.insert(
            hyper::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token123"),
        );

        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0));
        let upstream_host = HeaderValue::from_static("backend:80");

        let _ = inject_headers(&mut headers, &ip, &upstream_host, false);

        assert!(headers.get("x-custom-secret").is_none());
        assert!(headers.get("x-internal-flag").is_none());
        assert_eq!(
            headers.get(hyper::header::AUTHORIZATION).unwrap(),
            "Bearer token123"
        );
        assert_eq!(headers.get(CONNECTION).unwrap(), "keep-alive");
        assert_eq!(headers.get(HOST).unwrap(), "backend:80");
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "10.1.0.0");
    }

    #[test]
    fn test_hop_by_hop_token_limit_dos_protection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_static(
                "a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z",
            ),
        );

        let ip = IpAddr::V6(Ipv6Addr::new(10, 11, 12, 13, 14, 15, 3, 8));
        let upstream_host = HeaderValue::from_static("backend:5000");

        let result = inject_headers(&mut headers, &ip, &upstream_host, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Http(status, msg) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(msg, "Too many hop-by-hop headers");
            }
            other => panic!("Expected Error::Http 400, got {:?}", other),
        }
    }

    #[test]
    fn test_hop_by_hop_token_bypass() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r"),
        );
        headers.append(CONNECTION, HeaderValue::from_static("keep-alive"));

        let ip = IpAddr::V6(Ipv6Addr::new(10, 11, 12, 13, 14, 15, 3, 8));
        let upstream_host = HeaderValue::from_static("backend:443");
        let result = inject_headers(&mut headers, &ip, &upstream_host, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Http(status, msg) => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(msg, "Too many hop-by-hop headers");
            }
            other => panic!("Expected Error::Http 400, got {:?}", other),
        }
    }

    #[test]
    fn test_websocket_upgrade_preservation() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            HeaderName::from_static("sec-websocket-key"),
            HeaderValue::from_static("dGhlIHNhbXBsZQ=="),
        );

        let ip = IpAddr::V6(Ipv6Addr::new(15, 15, 15, 15, 15, 15, 15, 15));
        let upstream_host = HeaderValue::from_static("upstream:80");

        let _ = inject_headers(&mut headers, &ip, &upstream_host, true);

        assert_eq!(headers.get(UPGRADE).unwrap(), "websocket");
        assert_eq!(headers.get(CONNECTION).unwrap(), "Upgrade");
        assert!(headers.get("sec-websocket-key").is_some());
        assert_eq!(headers.get(HOST).unwrap(), "upstream:80");
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "f:f:f:f:f:f:f:f");
    }

    #[test]
    fn test_format_ipv4_ascii_edge_cases() {
        let test_cases = [
            (Ipv4Addr::new(0, 0, 0, 0), "0.0.0.0"),
            (Ipv4Addr::new(127, 0, 0, 1), "127.0.0.1"),
            (Ipv4Addr::new(192, 168, 1, 254), "192.168.1.254"),
            (Ipv4Addr::new(255, 255, 255, 255), "255.255.255.255"),
            (Ipv4Addr::new(10, 99, 1, 30), "10.99.1.30"),
        ];

        for (ip, expected_str) in test_cases {
            let mut buf = [0u8; 15];
            let len = format_ipv4_ascii(&ip, &mut buf);
            let result_str = std::str::from_utf8(&buf[..len]).unwrap();
            assert_eq!(result_str, expected_str)
        }
    }
}
