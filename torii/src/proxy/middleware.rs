use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::oidc::TokenResponse;
use crate::auth::oidc::{ActiveSession, validate_token};
use crate::error::Error::{self, Http};
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect};
use url::form_urlencoded;

fn inject_headers(request_headers: &mut HeaderMap, session: &ActiveSession) -> Result<(), Error> {
    let header_name = HeaderValue::from_str(&session.claims.name)?;
    request_headers.insert(HeaderName::from_static("x-forwarded-user"), header_name);
    Ok(())
}

//#[instrument(skip(state, headers), err)]
pub async fn enforce_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, Error> {
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
        return bounce(is_background_asset, &sec_fetch_mode);
    };

    if !matched_route.route.public_bypass {
        if let (Some(endpoints), Some(oidc_provider)) =
            (&state.endpoints, &state.config.oidc_provider)
        {
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
                        return Err(Http(StatusCode::FORBIDDEN, "Forbidden"));
                    }
                } else {
                    return Err(Http(StatusCode::FORBIDDEN, "Forbidden"));
                }
            }

            let request_headers = req.headers_mut();
            if session.claims.exp > SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() {
                inject_headers(request_headers, &session)?;
                return Ok(next.run(req).await.into_response());
            }
            let Some(token) = session.user_token.refresh_token else {
                return bounce(is_background_asset, &sec_fetch_mode);
            };
            let session_refresh = async {
                let res = reqwest::Client::new()
                    .post(endpoints.token_endpoint.as_str())
                    .form(&[
                        ("client_id", oidc_provider.oidc_client_id.as_str()),
                        ("client_secret", oidc_provider.oidc_client_secret.as_str()),
                        ("grant_type", "refresh_token"),
                        ("refresh_token", token.as_str()),
                        ("redirect_uri", oidc_provider.oidc_callback_uri.as_str()),
                    ])
                    .send()
                    .await
                    .ok()?;
                if !res.status().is_success() {
                    return None;
                }
                let response = res.json::<TokenResponse>().await.ok()?;
                let valid_claims = validate_token(
                    &state.limiter_cache,
                    endpoints,
                    &state.jwks_cache,
                    oidc_provider,
                    &response.id_token,
                )
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

            inject_headers(request_headers, &session)?;
            state.session_cache.insert(id.to_string(), session).await;
        }
    }
    // CHECK FOR TORII SESSION COOKIE
    return Ok(next.run(req).await.into_response());
}
