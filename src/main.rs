mod auth;
mod config;
mod error;
mod proxy;
mod state;
use axum::routing::any;
use jsonwebtoken::DecodingKey;
use tracing::{Level, error, info};
use tracing_subscriber::FmtSubscriber;

use crate::auth::oidc::{
    ActiveSession, auth_callback, auth_redirect, exchange_tunnel_key, fetch_jwks,
};
use crate::proxy::middleware::enforce_auth;
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
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    /* Clean panics for deployment
    std::panic::set_hook(Box::new(|panic_info| {
        let payload = panic_info.payload().downcast_ref::<&str>().unwrap_or(&"unknown panic");
        let location = panic_info.location().unwrap();

        error!(
            "Thread panicked at {}:{}: {}",
            location.file(),
            location.line(),
            payload
        )
    }));
    */
    info!("Attempting to load environment...");
    dotenvy::dotenv().ok();
    let config = match Config::new() {
        Ok(c) => c,
        Err(e) => {
            error!("FATAL: {}", e);
            std::process::exit(1);
        }
    };
    info!("Environment loaded successfully!");
    let endpoints = Endpoints::discover_endpoints(&config.oidc_issuer_url)
        .await
        .expect("FATAL: Failed to fetch OIDC Discovery document");
    info!("Preparing resources...");
    let csrf_cache: Cache<String, String> = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(300))
        .build();
    let session_cache: Cache<String, ActiveSession> = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_hours(168))
        .build();
    let jwks_cache: Cache<String, DecodingKey> = Cache::new(20);
    let limiter_cache: Cache<String, ()> = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(15))
        .build();
    let state = Arc::new(AppState {
        config,
        endpoints,
        csrf_cache,
        session_cache,
        jwks_cache,
        limiter_cache,
    });
    fetch_jwks(state.clone())
        .await
        .expect("FATAL: Failed to fetch JWKS from OIDC provider");
    let addr = format!("{}:{}", state.config.host, state.config.port);
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
    let listener = TcpListener::bind(&addr)
        .await
        .expect("FATAL: Failed to bind to port or port is already in use");
    info!("Listening on {}...", addr);
    serve(listener, app).await.expect("FATAL: Failed to serve");
}
