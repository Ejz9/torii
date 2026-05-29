mod config;
mod auth;
mod error;
mod proxy;
mod state;
use axum::routing::any;

use crate::{auth::oidc::Endpoints, config::Config};
use crate::proxy::router::handle_any;
use crate::state::AppState;
use axum::{Router, serve};
use dotenvy;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let config = Config::new().expect("FATAL: Missing environment variables");
    let endpoints = Endpoints::discover_endpoints(&config.oidc_issuer_url).await.expect("FATAL: Failed to fetch OIDC Discovery document");
    let state = Arc::new(AppState {
        config,
        endpoints,
    });
    let addr = (state.config.host, state.config.port);
    let app = Router::new()
        .route("/{*path}", any(handle_any))
        .with_state(state);
    let listener = TcpListener::bind(addr)
        .await
        .expect("FATAL: Failed to bind to port or port is already in use");
    serve(listener, app).await.expect("FATAL: Failed to serve");
}
