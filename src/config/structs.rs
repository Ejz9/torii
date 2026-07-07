use std::{
    collections::{HashMap, HashSet},
    fs,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http;
use rustls::{client::WebPkiServerVerifier, sign::CertifiedKey};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    acme::dns::{parse_certificate, verify_certificate_signature},
    error::Error,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ToriiConfig {
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    routes: HashMap<String, RouteConfig>,
}

impl Default for ToriiConfig {
    fn default() -> Self {
        Self {
            security: SecurityConfig::default(),
            routes: HashMap::new(),
        }
    }
}

pub struct ActiveState {
    pub security: SecurityConfig,
    pub routes: matchit::Router<ActiveRoute>,
}

pub struct RouteMatch {
    pub route: ActiveRoute,
    pub catch_all: String,
}

impl ActiveState {
    pub fn build(
        config: ToriiConfig,
        verifier: &Arc<WebPkiServerVerifier>,
    ) -> Result<
        (
            Self,
            HashSet<String>,
            HashSet<String>,
            HashMap<String, Arc<CertifiedKey>>,
        ),
        Error,
    > {
        let mut individual_certs = HashSet::new();
        let mut wildcard_certs = HashSet::new();
        let mut valid_certificates: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        let mut router = matchit::Router::new();
        for (route, value) in config.routes.into_iter() {
            let clean_route = route.trim_end_matches('/');
            let domain = clean_route.parse::<DomainTier>()?;
            if value.tls_cert_path.is_none() && value.tls_key_path.is_none() {
                match domain {
                    DomainTier::Root | DomainTier::Nested => {
                        individual_certs.insert(clean_route.to_string());
                    }
                    DomainTier::Subdomain => {
                        if value.individual_cert
                            || !config.security.default_certificate_mode_wildcard
                        {
                            individual_certs.insert(clean_route.to_string());
                        } else {
                            if let Some((_, root)) = clean_route.split_once(".") {
                                if !root.is_empty() {
                                    wildcard_certs.insert(root.to_string());
                                }
                            }
                        }
                    }
                }
            } else {
                let certificate =
                    match validate_and_parse_custom_certificates(&value, clean_route, verifier) {
                        Ok(certificate) => certificate,
                        Err(e) => {
                            error!("Failed to parse certificate for route: {}: {}", route, e);
                            continue;
                        }
                    };
                valid_certificates.insert(clean_route.to_string(), certificate);
            }
            let exact_pattern = format!("/{}", clean_route);
            router.insert(exact_pattern, value.clone().try_into()?)?;

            let catch_all_pattern = format!("/{}/{{*catch_all}}", clean_route);
            router.insert(catch_all_pattern, value.try_into()?)?;
        }

        Ok((
            ActiveState {
                security: config.security,
                routes: router,
            },
            individual_certs,
            wildcard_certs,
            valid_certificates,
        ))
    }

    pub fn find_route(&self, host: &str, mut path: &str) -> Option<RouteMatch> {
        if path == "/" {
            path = "";
        }
        let route = format!("/{}{}", host, path);
        let Ok(matched_route) = self.routes.at(&route) else {
            return None;
        };
        let catch_all = matched_route
            .params
            .get("catch_all")
            .unwrap_or("")
            .to_string();
        Some(RouteMatch {
            route: matched_route.value.clone(),
            catch_all,
        })
    }
}

fn validate_and_parse_custom_certificates(
    config: &RouteConfig,
    domain: &str,
    verifier: &WebPkiServerVerifier,
) -> Result<Arc<CertifiedKey>, Error> {
    let Some(cert_path) = &config.tls_cert_path else {
        error!("No certificate path provided for route: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "No certificate path provided for route {}",
            domain
        )));
    };
    let Some(key_path) = &config.tls_key_path else {
        error!("No key path provided for route: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "No key path provided for route {}",
            domain
        )));
    };
    let cert_bytes = fs::read(cert_path)?;
    let key_bytes = fs::read(key_path)?;
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&cert_bytes) else {
        error!("Failed to parse pem file for domain: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "Failed to parse pem file for domain: {}",
            domain
        )));
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&pem.contents) else {
        error!("Failed to parse cert from pem file for domain: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "Failed to parse cert from pem file for domain: {}",
            domain
        )));
    };
    let not_after = cert.tbs_certificate.validity.not_after;
    if (not_after.timestamp() as u64)
        < SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
        || (not_after.timestamp() as u64)
            < SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + Duration::from_hours(24 * 30).as_secs()
    {
        error!(
            "Certificate for {} is expired or expires in less than 30 days",
            domain
        );
        return Err(Error::InvalidCustomSetup(format!(
            "Certificate for {} is expired or expires in less than 30 days",
            domain
        )));
    }
    verify_certificate_signature(verifier, domain, &cert_bytes)?;
    Ok(parse_certificate(key_bytes, cert_bytes)?)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "default_certificate_mode_wildcard")]
    default_certificate_mode_wildcard: bool,
    #[serde(default = "default_ebpf_strike_threshold")]
    ebpf_strike_threshold: u64,
    #[serde(default = "default_ebpf_lockout_duration_secs")]
    ebpf_lockout_duration_secs: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_certificate_mode_wildcard: false,
            ebpf_strike_threshold: 10,
            ebpf_lockout_duration_secs: 3600,
        }
    }
}

fn default_certificate_mode_wildcard() -> bool {
    false
}
fn default_ebpf_strike_threshold() -> u64 {
    10
}
fn default_ebpf_lockout_duration_secs() -> u64 {
    3600
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RouteConfig {
    upstream: String,
    #[serde(default)]
    public_bypass: bool,
    #[serde(default)]
    tls_insecure_skip_verify: bool,
    #[serde(default)]
    individual_cert: bool,
    #[serde(default)]
    tls_cert_path: Option<String>,
    #[serde(default)]
    tls_key_path: Option<String>,
    #[serde(default)]
    allowed_asset_paths: Vec<String>,
    #[serde(default)]
    allowed_groups: Vec<String>,
}

#[derive(Clone)]
pub struct ActiveRoute {
    pub upstream: http::Uri,
    pub public_bypass: bool,
    pub tls_insecure_skip_verify: bool,
    pub allowed_asset_paths: Vec<String>,
    pub allowed_groups: Vec<String>,
}

impl TryFrom<RouteConfig> for ActiveRoute {
    type Error = Error;
    fn try_from(config: RouteConfig) -> Result<Self, Self::Error> {
        Ok(ActiveRoute {
            upstream: config.upstream.parse()?,
            public_bypass: config.public_bypass,
            tls_insecure_skip_verify: config.tls_insecure_skip_verify,
            allowed_asset_paths: config.allowed_asset_paths,
            allowed_groups: config.allowed_groups,
        })
    }
}

pub enum DomainTier {
    Root,
    Subdomain,
    Nested,
}

impl FromStr for DomainTier {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(".").count();
        match s.split(".").count() {
            0 => Err(Error::InvalidDomain),
            1 => Err(Error::InvalidDomain),
            2 => Ok(DomainTier::Root),
            3 => Ok(DomainTier::Subdomain),
            _ => Ok(DomainTier::Nested),
        }
    }
}
