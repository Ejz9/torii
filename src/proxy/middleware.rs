use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::oidc::TokenResponse;
use crate::auth::oidc::{ActiveSession, validate_token};
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect};
use tracing::instrument;
use url::form_urlencoded;

fn inject_headers(request_headers: &mut HeaderMap, session: &ActiveSession) {
    let header_name = HeaderValue::from_str(&session.claims.name).unwrap();
    request_headers.insert(HeaderName::from_static("x-forwarded-user"), header_name);
}

#[instrument(skip(state, headers), err)]
pub async fn enforce_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let original_uri = req.uri().to_string();
    let bounce = |is_background_asset: bool, sec_fetch_mode: &str| {
        if is_background_asset || sec_fetch_mode == "cors" {
            return Ok(StatusCode::UNAUTHORIZED.into_response());
        }
        let return_param =
            form_urlencoded::byte_serialize(original_uri.as_bytes()).collect::<String>();
        let login_url = format!("/auth/login?return_to={}", return_param);
        Ok(Redirect::temporary(&login_url).into_response())
    };
    if req.method().as_str() == "CONNECT" {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    let sec_fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if sec_fetch_site == "cross-site"
        && matches!(req.method().as_str(), "POST" | "PUT" | "DELETE" | "PATCH")
    {
        return Err(StatusCode::FORBIDDEN);
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
    let Some(host) = headers.get("HOST").and_then(|h| h.to_str().ok()) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(matched_route) = state.dynamic_config.load().find_route(host, path) else {
        return bounce(is_background_asset, &sec_fetch_mode);
    };
    if matched_route.route.public_bypass {
        return Ok(next.run(req).await.into_response());
    }
    // TODO PUBLIC PATH BYPASS
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
        return bounce(is_background_asset, &sec_fetch_mode);
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
    let Some(id) = torii_session else {
        return bounce(is_background_asset, &sec_fetch_mode);
    };
    let Some(session) = state.session_cache.get(id).await else {
        return bounce(is_background_asset, &sec_fetch_mode);
    };

    if !matched_route.route.allowed_groups.is_empty() {
        if let Some(groups) = &session.claims.groups {
            let has_access = matched_route
                .route
                .allowed_groups
                .iter()
                .any(|group| groups.contains(group));
            if !has_access {
                return Err(StatusCode::FORBIDDEN);
            }
        } else {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let request_headers = req.headers_mut();
    if session.claims.exp
        > SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    {
        inject_headers(request_headers, &session);
        return Ok(next.run(req).await.into_response());
    }
    let Some(token) = session.user_token.refresh_token else {
        return bounce(is_background_asset, &sec_fetch_mode);
    };

    let session_refresh = async {
        let res = reqwest::Client::new()
            .post(&state.endpoints.token_endpoint)
            .form(&[
                ("client_id", state.config.oidc_client_id.as_str()),
                ("client_secret", state.config.oidc_client_secret.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", token.as_str()),
                ("redirect_uri", state.config.oidc_callback_uri.as_str()),
            ])
            .send()
            .await
            .ok()?;
        if !res.status().is_success() {
            return None;
        }
        let response = res.json::<TokenResponse>().await.ok()?;
        let valid_claims = validate_token(state.clone(), &response.id_token)
            .await
            .ok()?;
        Some(ActiveSession {
            user_token: response,
            claims: valid_claims,
        })
    }
    .await;

    let Some(session) = session_refresh else {
        state.session_cache.remove(id).await;
        return bounce(is_background_asset, &sec_fetch_mode);
    };

    inject_headers(request_headers, &session);
    state.session_cache.insert(id.to_string(), session).await;
    return Ok(next.run(req).await.into_response());
}
