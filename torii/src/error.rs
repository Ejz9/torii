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
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid or missing Key ID in token header")]
    InvalidKeyId,
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    ConfigError(#[from] matchit::InsertError),
    #[error(transparent)]
    RouteNotFound(#[from] matchit::MatchError),
    #[error(transparent)]
    InvalidUri(#[from] axum::http::uri::InvalidUri),
    #[error("Invalid internet domain. Should contain at minimum base.tld")]
    InvalidDomain,
    #[error(transparent)]
    InvalidPem(#[from] x509_parser::error::PEMError),
    #[error(transparent)]
    InvalidX509(#[from] x509_parser::error::X509Error),
    #[error(transparent)]
    Acme(#[from] instant_acme::Error),
    #[error("ACME validation failed for domain: {domain} with status: {status:?}")]
    AcmeOrderFailed {
        domain: String,
        status: instant_acme::OrderStatus,
    },
    #[error(transparent)]
    RustlsPem(#[from] rustls::pki_types::pem::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error("Configuration Error {0}")]
    InvalidCustomSetup(String),
    #[error(transparent)]
    InvalidHeader(#[from] hyper::header::InvalidHeaderValue),
    #[error(transparent)]
    WebPki(#[from] rustls::server::VerifierBuilderError),
    #[error(transparent)]
    ServerName(#[from] rustls::pki_types::InvalidDnsNameError),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::UpstreamTimeout => {
                (StatusCode::GATEWAY_TIMEOUT, "Upstream timeout").into_response()
            }
            Error::Io(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
            Error::Reqwest(_) => (StatusCode::BAD_GATEWAY, "Upstream error").into_response(),
            Error::Serde(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Serde error").into_response(),
            Error::Axum(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Axum error").into_response(),
            Error::Env(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Environment error").into_response()
            }
            Error::ParseInt(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Parse int error").into_response()
            }
            Error::ParseIpv4Addr(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Parse ipv4 addr error").into_response()
            }
            Error::Uuid(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Uuid error").into_response(),
            Error::Url(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Url error").into_response(),
            Error::Jwt(_) => (
                StatusCode::UNAUTHORIZED,
                "Invalid token signature or format",
            )
                .into_response(),
            Error::InvalidKeyId => {
                (StatusCode::UNAUTHORIZED, "Unknown signing key").into_response()
            }
            Error::Toml(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Toml error").into_response(),
            Error::ConfigError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Config error").into_response()
            }
            Error::RouteNotFound(_) => {
                (StatusCode::NOT_FOUND, "Requested URL not found").into_response()
            }
            Error::InvalidUri(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Invalid URL").into_response()
            }
            Error::InvalidDomain => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Invalid domain").into_response()
            }
            Error::InvalidPem(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Invalid PEM").into_response()
            }
            Error::InvalidX509(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid X.509 certificate",
            )
                .into_response(),
            Error::Acme(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Acme error").into_response(),
            Error::AcmeOrderFailed { domain, status } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Acme validation failed for domain: {domain} with status: {status:?}"),
            )
                .into_response(),
            Error::RustlsPem(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Cryptography Error").into_response()
            }
            Error::Rustls(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Cryptography Error").into_response()
            }
            Error::InvalidCustomSetup(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Invalid custom path").into_response()
            }
            Error::InvalidHeader(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Invalid header").into_response()
            }
            Error::WebPki(_) => (StatusCode::INTERNAL_SERVER_ERROR, "WebPki Error").into_response(),
            Error::ServerName(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Server Name Error").into_response()
            }
        }
    }
}
