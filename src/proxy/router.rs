use std::sync::Arc;
use axum::{extract::State, response::IntoResponse, http::Request, body::Body};
use crate::state::AppState;

pub async fn handle_any(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> impl IntoResponse {
    println!("Intercepted request for: {}", req.uri());
    "GATEWAY INTERCEPT SUCCESSFUL"
}
