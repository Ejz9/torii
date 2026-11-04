use axum::{http::StatusCode, response::IntoResponse};
use tracing::error;

pub struct Error(pub anyhow::Error);

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        error!("Handler error: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    }
}

impl<E> From<E> for Error
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
