use crate::state::AppState;
use axum::{body::Body, extract::State, http::Request, response::IntoResponse};
use std::sync::Arc;
use tracing::info;

pub async fn handle_any(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> impl IntoResponse {
    info!("Intercepted request for: {}", req.uri());
    "GATEWAY INTERCEPT SUCCESSFUL"
}
