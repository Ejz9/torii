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
    let header_name = HeaderValue::from_str(&session.claims.preferred_name).unwrap();
    let header_token =
        HeaderValue::from_str(&format!("Bearer {}", session.user_token.access_token)).unwrap();
    request_headers.remove("x-forwarded-user");
    request_headers.remove(header::AUTHORIZATION);
    request_headers.remove("x-forwarded-email");
    request_headers.remove("x-forwarded-groups");
    request_headers.remove("x-forwarded-for");
    request_headers.remove("x-forwarded-host");
    request_headers.remove("x-forwarded-proto");
    request_headers.remove("x-real-ip");

    request_headers.insert(header::AUTHORIZATION, header_token);
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
    let bounce = || {
        let return_param =
            form_urlencoded::byte_serialize(original_uri.as_bytes()).collect::<String>();
        let login_url = format!("auth/login?return_to={}", return_param);
        Ok(Redirect::temporary(&login_url).into_response())
    };
    let Some(cookie) = headers.get(header::COOKIE) else {
        return bounce();
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
        return bounce();
    };
    let Some(session) = state.session_cache.get(id).await else {
        return bounce();
    };
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
        return bounce();
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
        return bounce();
    };

    inject_headers(request_headers, &session);
    state.session_cache.insert(id.to_string(), session).await;
    return Ok(next.run(req).await.into_response());
}
