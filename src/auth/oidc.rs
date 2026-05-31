use std::sync::Arc;

use crate::error::Error;
use crate::state::AppState;
use axum::extract::{State, Query};
use axum::response::{IntoResponse, Redirect};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub end_session_endpoint: String,
}

impl Endpoints {
    pub async fn discover_endpoints(issuer_url: &str) -> Result<Self, Error> {
        let oidc_configuration_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let response = reqwest::get(oidc_configuration_url)
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }
}

pub async fn auth_redirect(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let code = Uuid::new_v4().to_string();
    let uri = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&scope=openid%20profile%20email&state={}",
        state.endpoints.authorization_endpoint,
        state.config.oidc_client_id,
        url::form_urlencoded::byte_serialize(state.config.oidc_callback_uri.as_bytes())
            .collect::<String>(),
        &code
    );
    state.csrf_cache.insert(code, ()).await;
    Redirect::temporary(&uri)
}

#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    code: String,
    state: String
}

pub async fn auth_callback(State(state): State<Arc<AppState>>,Query(query): Query<AuthCallbackQuery>) -> impl IntoResponse {
    
}
