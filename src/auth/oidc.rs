use std::sync::Arc;

use crate::error::Error;
use crate::state::AppState;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, response};
use axum::http::StatusCode;
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect};
use moka::ops::compute::Op;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub end_session_endpoint: String,
    pub jwks_uri: String
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

pub async fn enforce_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(cookie) = headers.get(header::COOKIE) {
        let cookie = &cookie.to_str().unwrap_or("");
        let torii_session = cookie.split(';').find_map(|pair| {
            let pair: &str = pair.trim();
            if pair.starts_with("torii_session=") {
                Some(&pair["torii_session=".len()..])
            } else {
                None
            }
        });
        if let Some(id) = torii_session {
            if state.session_cache.contains_key(id) {
                return Ok(next.run(req).await.into_response());
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
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
    state: String,
}

#[derive(Deserialize, Clone)]
pub struct TokenResponse {
    access_token: String,
    id_token: String,
    token_type: String,
    expires_in: u64,
}

pub async fn auth_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthCallbackQuery>,
) -> Result<impl IntoResponse, Error> {
    if let Some(_) = state.csrf_cache.remove(&query.state).await {
        let response = reqwest::Client::new()
            .post(&state.endpoints.token_endpoint)
            .form(&[
                ("client_id", state.config.oidc_client_id.as_str()),
                ("client_secret", state.config.oidc_client_secret.as_str()),
                ("code", query.code.as_str()),
                ("grant_type", "authorization_code"),
                ("redirect_uri", state.config.oidc_callback_uri.as_str()),
            ])
            .send()
            .await?
            .json::<TokenResponse>()
            .await?;
        let session_id = Uuid::new_v4().to_string();
        let cookie = format!(
            "torii_session={}; HttpOnly; Path=/; SameSite=Lax",
            session_id
        ); //TODO Add "Secure" when in prod not local testing
        state.session_cache.insert(session_id, response).await;
        Ok((
            [(header::SET_COOKIE, cookie)],
            Redirect::temporary("http://127.0.0.1:8080/SUCCESS"),
        )
            .into_response()) //TODO: Process the intended route the user wants to go
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

pub async fn validate_token() {

}

#[derive(Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Jwk {
    Rsa(RsaKey),
    Ec(EcKey)
}

#[derive(Deserialize)]
pub struct RsaKey {
    alg: String,
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: String,
    e: String
}

#[derive(Deserialize)]
pub struct EcKey {
    alg: String,
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    crv: String,
    x: String,
    y: String
}

pub async fn fetch_jwks(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, Error> {
    let response = reqwest::get(state.endpoints.jwks_uri.to_string()).json()::<Jwks>.await?;
    for key in response.keys {
        match key {
            Jwk::Rsa(rsa_data) => {

            }
            Jwk::Ec(ec_data) => {

            }
        }
    }
    

}

pub async fn exchange_tunnel_key(headers: HeaderMap) -> () {
    todo!("Gen and exchange tunnel_key")
}
