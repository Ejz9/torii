mod auth;
mod config;
mod error;
mod proxy;
mod state;
use axum::routing::any;

use crate::auth::oidc::{
    TokenResponse, auth_callback, auth_redirect, enforce_auth, exchange_tunnel_key,
};
use crate::proxy::router::handle_any;
use crate::state::AppState;
use crate::{auth::oidc::Endpoints, config::Config};
use axum::{Router, middleware, serve};
use dotenvy;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let config = Config::new().expect("FATAL: Missing environment variables");
    let endpoints = Endpoints::discover_endpoints(&config.oidc_issuer_url)
        .await
        .expect("FATAL: Failed to fetch OIDC Discovery document");
    let csrf_cache: Cache<String, ()> = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(300))
        .build();
    let session_cache: Cache<String, TokenResponse> = Cache::builder().max_capacity(10_000).build();
    let jwks_cache: 
    let state = Arc::new(AppState {
        config,
        endpoints,
        csrf_cache,
        session_cache,
    });
    let addr = (state.config.host, state.config.port);
    let public_routes = Router::new()
        .route("/auth/login", any(auth_redirect))
        .route("/auth/callback", any(auth_callback));
    let private_routes = Router::new()
        .route("/api/tunnel-key", any(exchange_tunnel_key))
        .route("/{*path}", any(handle_any))
        .route_layer(middleware::from_fn_with_state(state.clone(), enforce_auth));
    let app = Router::new()
        .merge(public_routes)
        .merge(private_routes)
        .with_state(state);
    let listener = TcpListener::bind(addr)
        .await
        .expect("FATAL: Failed to bind to port or port is already in use");
    serve(listener, app).await.expect("FATAL: Failed to serve");
}
