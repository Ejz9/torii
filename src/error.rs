use axum::http::StatusCode;
use axum::response::IntoResponse;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Upstream Timeout")]
    UpstreamTimeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error("Missing required environment variable(s): {0}")]
    Env(String),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    ParseIpv4Addr(#[from] std::net::AddrParseError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            Error::UpstreamTimeout => (StatusCode::GATEWAY_TIMEOUT, "Upstream timeout"),
            Error::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
            Error::Reqwest(_) => (StatusCode::BAD_GATEWAY, "Upstream error"),
            Error::Serde(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Serde error"),
            Error::Axum(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Axum error"),
            Error::Env(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Environment error"),
            Error::ParseInt(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Parse int error"),
            Error::ParseIpv4Addr(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Parse ipv4 addr error"),
            Error::Uuid(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Uuid error"),
            Error::Url(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Url error"),
        };
        (status, error_message).into_response()
    }
}
