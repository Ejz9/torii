use crate::acme::providers::ProviderKind;
use crate::acme::providers::cloudflare::CloudflareProvider;
use crate::auth::oidc::OidcProvider;
use crate::ebpf::mihari::MihariProviderKind;
use crate::ebpf::mihari::crowdsec::CrowdSecProvider;
use crate::error::Error;
use std::env::var;
use std::net::Ipv4Addr;
#[derive(Debug)]
pub struct Config {
    pub interface: Option<String>,
    pub port: u16,
    pub host: Ipv4Addr,
    pub oidc_provider: Option<OidcProvider>,
    pub acme_directory_url: String,
    pub acme_provider: Option<ProviderKind>,
    pub acme_email: Option<String>,
    pub cert_path: String,
    pub custom_ca_path: Option<String>,
    pub ddns: bool,
    pub mihari_interval: u64,
    pub mihari_provider: Option<MihariProviderKind>,
    pub kekkai_path: String,
    pub hashira_shm_capacity: u32,
    pub ebpf_metrics: bool,
}

impl Config {
    pub fn new() -> Result<Self, Error> {
        let interface = var("INTERFACE").ok();
        let port = var("PORT").unwrap_or_else(|_| "443".to_string()).parse()?;
        let host = var("HOST")
            .unwrap_or_else(|_| "0.0.0.0".to_string())
            .parse()?;
        let oidc_issuer_url = var("OIDC_ISSUER_URL").ok();
        let oidc_client_id = var("OIDC_CLIENT_ID").ok();
        let oidc_client_secret = var("OIDC_CLIENT_SECRET").ok();
        let oidc_callback_uri = var("OIDC_CALLBACK_URI").ok();
        let oidc_provider = match (oidc_issuer_url, oidc_client_id, oidc_client_secret, oidc_callback_uri) {
            (Some(oidc_issuer_url), Some(oidc_client_id), Some(oidc_client_secret), Some(oidc_callback_uri)) => Some(OidcProvider { oidc_issuer_url, oidc_client_id, oidc_client_secret, oidc_callback_uri }),
            (None, None, None, None) => None,
            _ => return Err(Error::Env("Incomplete OIDC config. OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_CALLBACK_URI must be set to enable OIDC".to_string()))
        };
        let acme_provider = match var("ACME_PROVIDER").ok() {
            Some(acme_provider_string) => {
                let acme_zone_id =
                    var("ACME_ZONE_ID").map_err(|_| Error::Env("ACME_ZONE_ID".to_string()))?;
                let acme_token =
                    var("ACME_TOKEN").map_err(|_| Error::Env("ACME_TOKEN".to_string()))?;
                match acme_provider_string.to_lowercase().as_str() {
                    "cloudflare" => Some(ProviderKind::Cloudflare(CloudflareProvider {
                        zone_id: acme_zone_id,
                        api_token: acme_token,
                    })),
                    _ => {
                        return Err(Error::Env(format!(
                            "Invalid ACME provider: {}",
                            acme_provider_string
                        )));
                    }
                }
            }
            None => None,
        };
        let acme_email = var("ACME_EMAIL").ok();
        let cert_path = var("CERT_PATH").unwrap_or_else(|_| "/var/lib/torii/certs/".to_string());
        let custom_ca_path = var("CUSTOM_CA_PATH").ok();
        let acme_directory_url = var("ACME_DIRECTORY_URL")
            .unwrap_or_else(|_| instant_acme::LetsEncrypt::Production.url().to_owned());
        let ddns = var("DDNS")
            .map(|v| v.parse::<bool>().unwrap_or(true))
            .unwrap_or(false);
        let mihari_interval = var("MIHARI_INTERVAL")
            .unwrap_or_else(|_| "86400".to_string())
            .parse::<u64>()?;
        let mihari_provider_string = var("MIHARI_PROVIDER").ok();
        let mihari_provider = match mihari_provider_string {
            Some(provider) if provider.to_lowercase() == "crowdsec" => {
                let mihari_provider_url = var("MIHARI_PROVIDER_URL")
                    .map_err(|_| Error::Env("MIHARI_PROVIDER_URL".to_string()))?;
                let mihari_provider_token = var("MIHARI_PROVIDER_TOKEN")
                    .map_err(|_| Error::Env("MIHARI_PROVIDER_TOKEN".to_string()))?;
                Some(MihariProviderKind::CrowdSec(CrowdSecProvider {
                    api_url: mihari_provider_url,
                    api_key: mihari_provider_token,
                }))
            }
            Some(unkown) => return Err(Error::Env(format!("Invalid MIHARI provider: {}", unkown))),
            None => None,
        };
        let kekkai_path =
            var("KEKKAI_PATH").unwrap_or_else(|_| "/var/lib/torii/kekkai/".to_string());
        if let Err(e) = std::fs::create_dir_all(&kekkai_path) {
            return Err(Error::Env(format!("Failed to create KEKKAI_PATH: {e}")));
        }
        let hashira_shm_capacity = var("HASHIRA_SHM_CAPACITY")
            .unwrap_or_else(|_| "100000".to_string())
            .parse::<u32>()?;
        let ebpf_metrics = var("EBPF_METRICS")
            .map(|v| v.parse::<bool>().unwrap_or(true))
            .unwrap_or(false);
        Ok(Config {
            interface,
            port,
            host,
            oidc_provider,
            acme_directory_url,
            acme_provider,
            acme_email,
            cert_path,
            custom_ca_path,
            ddns,
            mihari_interval,
            mihari_provider,
            kekkai_path,
            hashira_shm_capacity,
            ebpf_metrics,
        })
    }
}
