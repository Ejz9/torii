use crate::error::Error;
use std::env::var;
use std::net::Ipv4Addr;
#[derive(Debug)]
pub struct Config {
    pub port: u16,
    pub host: Ipv4Addr,
    pub timeout_seconds: u64,
    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_callback_uri: String,
    pub acme_provider: String,
    pub acme_token: String,
    pub cert_path: String
}

impl Config {
    pub fn new() -> Result<Self, Error> {
        let port = var("PORT").unwrap_or_else(|_| "443".to_string()).parse()?;
        let host = var("HOST")
            .unwrap_or_else(|_| "0.0.0.0".to_string())
            .parse()?;
        let timeout_seconds = var("TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()?;
        let oidc_issuer_url = var("OIDC_ISSUER_URL")
            .map_err(|_| Error::Env("OIDC_ISSUER_URL is required".to_string()))?;
        let oidc_client_id =
            var("OIDC_CLIENT_ID").map_err(|_| Error::Env("OIDC_CLIENT_ID".to_string()))?;
        let oidc_client_secret =
            var("OIDC_CLIENT_SECRET").map_err(|_| Error::Env("OIDC_CLIENT_SECRET".to_string()))?;
        let oidc_callback_uri =
            var("OIDC_CALLBACK_URI").map_err(|_| Error::Env("OIDC_CALLBACK_URI".to_string()))?;
        let acme_provider= var("ACME_PROVIDER").map_err(|_| Error::Env("ACME_PROVIDER".to_string()))?;
        let acme_token = var("ACME_TOKEN").map_err(|_| Error::Env("ACME_TOKEN".to_string()))?; 
        let cert_path = var("CERT_PATH").unwrap_or_else(|_| "/var/lib/torii/certs/".to_string());
        Ok(Config {
            port,
            host,
            timeout_seconds,
            oidc_issuer_url,
            oidc_client_id,
            oidc_client_secret,
            oidc_callback_uri,
            acme_provider,
            acme_token,
            cert_path
        })
    }
}
