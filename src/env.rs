use crate::acme::dns::ProviderKind;
use crate::acme::providers::cloudflare::CloudflareProvider;
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
    pub acme_directory_url: String,
    pub acme_provider: ProviderKind,
    pub acme_email: Option<String>,
    pub cert_path: String,
    pub custom_ca_path: Option<String>,
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
        let acme_provider_string =
            var("ACME_PROVIDER").map_err(|_| Error::Env("ACME_PROVIDER".to_string()))?;
        let acme_email = var("ACME_EMAIL").ok();
        let acme_zone_id =
            var("ACME_ZONE_ID").map_err(|_| Error::Env("ACME_ZONE_ID".to_string()))?;
        let acme_token = var("ACME_TOKEN").map_err(|_| Error::Env("ACME_TOKEN".to_string()))?;
        let cert_path = var("CERT_PATH").unwrap_or_else(|_| "/var/lib/torii/certs/".to_string());
        let custom_ca_path = var("CUSTOM_CA_PATH").ok();
        let acme_directory_url = var("ACME_DIRECTORY_URL").unwrap_or_else(|_| instant_acme::LetsEncrypt::Production.url().to_owned());
        let acme_provider = match acme_provider_string.to_lowercase().as_str() {
            "cloudflare" => ProviderKind::Cloudflare(CloudflareProvider {
                zone_id: acme_zone_id,
                api_token: acme_token,
            }),
            _ => {
                return Err(Error::Env(format!(
                    "Invalid ACME provider: {}",
                    acme_provider_string
                )));
            }
        };
        Ok(Config {
            port,
            host,
            timeout_seconds,
            oidc_issuer_url,
            oidc_client_id,
            oidc_client_secret,
            oidc_callback_uri,
            acme_directory_url,
            acme_provider,
            acme_email,
            cert_path,
            custom_ca_path,
        })
    }
}
