use crate::error::Error::{self, Http};
use crate::state::AppState;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::http::header;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use biscuit_auth::macros::authorizer;
use biscuit_auth::{Authorizer, Biscuit};
use keidai::ConnectionEvent;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::time::Instant;
use url::form_urlencoded;

fn inject_headers(
    request_headers: &mut HeaderMap,
    authorizer: &mut Authorizer,
) -> Result<(), Error> {
    if let Ok(users) = authorizer.query_all::<_, (String,), _>("data($u) <- user($u)") {
        if let Some((user,)) = users.into_iter().next() {
            if let Ok(val) = HeaderValue::from_str(&user) {
                request_headers.insert(HeaderName::from_static("x-forwarded-user"), val);
            }
        }
    }
    Ok(())
}

//#[instrument(skip(state, headers), err)]
pub async fn enforce_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, Error> {
    let bounce = |uri: &axum::http::Uri, is_background_asset: bool, sec_fetch_mode: &str| {
        if is_background_asset || sec_fetch_mode == "cors" {
            return Ok(StatusCode::UNAUTHORIZED.into_response());
        }
        let raw_path = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(uri.path());
        let return_param = form_urlencoded::byte_serialize(raw_path.as_bytes()).collect::<String>();
        let login_url = format!("/auth/login?return_to={}", return_param);
        Ok(Redirect::temporary(&login_url).into_response())
    };
    if req.method().as_str() == "CONNECT" {
        return Err(Error::Http(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
        ));
    }
    let sec_fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if sec_fetch_site == "cross-site"
        && matches!(req.method().as_str(), "POST" | "PUT" | "DELETE" | "PATCH")
    {
        return Err(Http(StatusCode::FORBIDDEN, "Forbidden"));
    }
    let sec_fetch_dest = headers
        .get("sec-fetch-dest")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sec_fetch_mode = headers
        .get("sec-fetch-mode")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let mut is_background_asset = false;
    if matches!(
        sec_fetch_dest,
        "style" | "script" | "image" | "font" | "manifest"
    ) {
        is_background_asset = true;
    }

    let path = req.uri().path();
    let Some(host) = headers
        .get("HOST")
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().authority().map(|auth| auth.host()))
    else {
        return Err(Http(StatusCode::BAD_REQUEST, "Bad Request"));
    };
    let Some(matched_route) = state.dynamic_config.load().find_route(host, path) else {
        return bounce(req.uri(), is_background_asset, &sec_fetch_mode);
    };
    req.extensions_mut().insert(matched_route.clone());

    if !matched_route.route.public_bypass {
        if let (Some(_), Some(_)) = (&state.endpoints, &state.config.oidc_provider) {
            if is_background_asset
                && matched_route
                    .route
                    .allowed_asset_paths
                    .iter()
                    .any(|path| matched_route.catch_all.starts_with(path))
            {
                return Ok(next.run(req).await.into_response());
            }

            let Some(cookie) = headers.get(header::COOKIE) else {
                return bounce(req.uri(), is_background_asset, &sec_fetch_mode);
            };
            let cookie = &cookie.to_str().unwrap_or("");
            let torii_session = cookie.split(';').find_map(|pair| {
                let pair: &str = pair.trim();
                if pair.starts_with("torii_session=") {
                    Some(&pair["torii_session=".len()..])
                } else {
                    None
                }
            });
            let Some(session) = torii_session else {
                return bounce(req.uri(), is_background_asset, &sec_fetch_mode);
            };

            let Ok(biscuit_token) = Biscuit::from_base64(session, state.root_keypair.public())
            else {
                return bounce(req.uri(), is_background_asset, &sec_fetch_mode);
            };

            let mut builder = authorizer!(
                r#"
                time({now});
                "#,
                now = SystemTime::now()
            );
            if matched_route.route.allowed_groups.is_empty() {
                builder = builder.code("allow if true;")?;
            } else {
                for group in &matched_route.route.allowed_groups {
                    builder = builder.code(format!("allow if group(\"{group}\");"))?;
                }
            }
            let mut authorizer = builder.build(&biscuit_token)?;
            match authorizer.authorize() {
                Ok(_) => {}
                Err(biscuit_auth::error::Token::FailedLogic(
                    biscuit_auth::error::Logic::NoMatchingPolicy { checks },
                )) if checks.is_empty() => {
                    return Err(Http(StatusCode::FORBIDDEN, "Forbidden"));
                }
                Err(_) => return bounce(req.uri(), is_background_asset, &sec_fetch_mode),
            }
            inject_headers(req.headers_mut(), &mut authorizer)?;
        }
    }
    // CHECK FOR TORII SESSION COOKIE
    return Ok(next.run(req).await.into_response());
}

pub async fn temizuya(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let mut event = ConnectionEvent::new(0, 0, req.uri().path(), addr.ip(), req.method().as_str());
    let response = next.run(req).await;
    event.latency_ms = start.elapsed().as_millis() as u32;
    event.status_code = response.status().as_u16();
    let _ = state.event_tx.try_send(event);
    response
}
