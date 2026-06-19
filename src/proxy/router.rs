use crate::{error::Error, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, HeaderValue, Request},
    response::IntoResponse,
};
use hyper::{HeaderMap, StatusCode, header};
use std::sync::Arc;
use tracing::error;

pub async fn handle_any(
    State(state): State<Arc<AppState>>,
    ip: ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
) -> Result<impl IntoResponse, Error> {
    let source_ip = ip.ip().to_string();
    let (mut parts, body) = req.into_parts();
    let config = state.dynamic_config.load();
    let Ok(matched_route) = config.routes.at(parts.uri.path()) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    
    let new_uri = format!(
        "{}{}",
        matched_route.value.upstream,
        matched_route.params.get("catch_all").unwrap_or("")
    );
    let tls_no_verify = matched_route.value.tls_insecure_skip_verify;
    parts.uri = new_uri.parse()?;
    inject_headers(&mut parts.headers, source_ip);
    let req = Request::from_parts(parts, body);



    let pool = if tls_no_verify {
        &state.insecure_connection_pool
    } else {
        &state.connection_pool
    };

    match pool.request(req).await {
        Ok(res) => {
            Ok(res.map(|body| Body::new(body)).into_response())
        }
        Err(e) => {
            error!("URI: {}, Error: {}", new_uri, e);
            Err(Error::UpstreamTimeout)
        }
    }
}

fn inject_headers(request_headers: &mut HeaderMap, source_ip: String) {
    let header_source = HeaderValue::from_str(&source_ip).unwrap();
    request_headers.remove("x-forwarded-user");
    request_headers.remove(header::AUTHORIZATION);
    request_headers.remove("x-forwarded-email");
    request_headers.remove("x-forwarded-groups");
    request_headers.remove("x-forwarded-for");
    request_headers.remove("x-forwarded-host");
    request_headers.remove("x-forwarded-proto");
    request_headers.remove("x-real-ip");

    request_headers.remove("Connection");
    request_headers.remove("Keep-Alive");
    request_headers.remove("Proxy-Authenticate");
    request_headers.remove("Proxy-Authorization");
    request_headers.remove("Te");
    request_headers.remove("Trailers");
    request_headers.remove("Transfer-Encoding");
    request_headers.remove("Upgrade");

    request_headers.insert(HeaderName::from_static("x-forwarded-for"), header_source);
}
