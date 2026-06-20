use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::error::Error;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::{IntoResponse, Redirect};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tracing::{info, instrument, warn};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub end_session_endpoint: String,
    pub jwks_uri: String,
    pub grant_types_supported: Option<Vec<String>>,
}

impl Endpoints {
    #[instrument(name = "oidc_discovery")]
    pub async fn discover_endpoints(issuer_url: &str) -> Result<Self, Error> {
        info!("Fetching OIDC endpoints...");
        let oidc_configuration_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let response = reqwest::get(oidc_configuration_url)
            .await?
            .error_for_status()?;
        info!("OIDC endpoints located!");
        let endpoints: Endpoints = response.json().await?;
        match &endpoints.grant_types_supported {
            None => {
                warn!(
                    "OIDC provider did not advertise supported grant types. Spec defaults applied. Background session invalidation via refresh tokens is assumed DISABLED."
                )
            }
            Some(grants) if !grants.contains(&"refresh_token".to_string()) => {
                warn!(
                    "OIDC provider explicitly excluded 'refresh_token' from supported grants. Background session invalidation is DISABLED. Expired sessions will force a hard redirect."
                )
            }
            Some(_) => {
                info!(
                    "Refresh token grant supported by upstream provider. Background session invalidation is ACTIVE."
                )
            }
        }
        Ok(endpoints)
    }
}

#[derive(Deserialize)]
pub struct LoginQuery {
    return_to: Option<String>,
}

pub async fn auth_redirect(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    let code = Uuid::new_v4().to_string();
    let uri = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&scope=openid%20profile%20email%20offline_access&state={}",
        state.endpoints.authorization_endpoint,
        state.config.oidc_client_id,
        url::form_urlencoded::byte_serialize(state.config.oidc_callback_uri.as_bytes())
            .collect::<String>(),
        &code
    );
    let target_url = query.return_to.unwrap_or_else(|| "/".to_string());
    state.csrf_cache.insert(code, target_url).await;
    Redirect::temporary(&uri)
}

#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[derive(Deserialize, Clone)]
pub struct ActiveSession {
    pub user_token: TokenResponse,
    pub claims: Claims,
}

static TTL_WARNED: AtomicBool = AtomicBool::new(false);

#[instrument(skip_all, err)]
pub async fn auth_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthCallbackQuery>,
) -> Result<impl IntoResponse, Error> {
    if let Some(return_url) = state.csrf_cache.remove(&query.state).await {
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
        let valid_claims = validate_token(state.clone(), &response.id_token).await?;
        if response.expires_in > 1800 {
            if !TTL_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    "Token TTL is {} seconds. Consider shortening this upstream for better security.",
                    &response.expires_in
                );
            }
        }
        let session = ActiveSession {
            user_token: response,
            claims: valid_claims,
        };
        let session_id = Uuid::new_v4().to_string();
        let cookie = format!(
            "torii_session={}; HttpOnly; Path=/; SameSite=Lax",
            session_id
        ); //TODO Add "Secure" when in prod not local testing
        state.session_cache.insert(session_id, session).await;
        Ok((
            [(header::SET_COOKIE, cookie)],
            Redirect::temporary(&return_url),
        )
            .into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

#[derive(Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub preferred_name: Option<String>,
    pub name: String,
}

#[instrument(skip(state, token), err)]
pub async fn validate_token(state: Arc<AppState>, token: &str) -> Result<Claims, Error> {
    let header = decode_header(&token)?;
    let kid = header.kid.ok_or(Error::InvalidKeyId)?;
    let mut key_wrapper = state.jwks_cache.get(&kid).await;
    if key_wrapper.is_none() {
        if !state.limiter_cache.contains_key("jwks_limiter") {
            state
                .limiter_cache
                .insert("jwks_limiter".to_string(), ())
                .await;
            fetch_jwks(state.clone()).await?;
        }
        key_wrapper = state.jwks_cache.get(&kid).await;
    }
    let key = key_wrapper.ok_or(Error::InvalidKeyId)?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[state.config.oidc_client_id.clone()]);
    Ok(decode::<Claims>(&token, &key, &validation)?.claims)
}

#[derive(Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Jwk {
    Rsa(RsaKey),
    Ec(EcKey),
}

#[derive(Deserialize)]
pub struct RsaKey {
    alg: String,
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: String,
    e: String,
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
    y: String,
}

#[instrument(skip(state), name = "jwks_refresh")]
pub async fn fetch_jwks(state: Arc<AppState>) -> Result<(), Error> {
    let response = reqwest::get(state.endpoints.jwks_uri.to_string())
        .await?
        .json::<Jwks>()
        .await?;
    let mut keys_added = 0;
    for key in response.keys {
        match key {
            Jwk::Rsa(rsa_data) => {
                if let Some(use_val) = &rsa_data.key_use {
                    if use_val != "sig" {
                        continue;
                    }
                }
                state
                    .jwks_cache
                    .insert(
                        rsa_data.kid,
                        DecodingKey::from_rsa_components(&rsa_data.n, &rsa_data.e).unwrap(),
                    )
                    .await;
            }
            Jwk::Ec(ec_data) => {
                if let Some(use_val) = &ec_data.key_use {
                    if use_val != "sig" {
                        continue;
                    }
                }
                state
                    .jwks_cache
                    .insert(
                        ec_data.kid,
                        DecodingKey::from_ec_components(&ec_data.x, &ec_data.y).unwrap(),
                    )
                    .await;
            }
        }
        keys_added += 1;
    }
    info!("Successfully fetched and cached {} key(s)", keys_added);
    Ok(())
}

pub async fn exchange_tunnel_key(headers: HeaderMap) -> () {
    todo!("Gen and exchange tunnel_key")
}
