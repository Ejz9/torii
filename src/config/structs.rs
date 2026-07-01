use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use axum::http;
use serde::{Deserialize, Serialize};

use crate::error::Error;

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
    pub fn build(config: ToriiConfig) -> Result<(Self, HashSet<String>, HashSet<String>), Error> {
        let mut individual_certs = HashSet::new();
        let mut wildcard_certs = HashSet::new();
        let mut router = matchit::Router::new();
        for (route, value) in config.routes.into_iter() {
            let clean_route = route.trim_end_matches('/');
            let domain = clean_route.parse::<DomainTier>()?;
            if value.tls_cert_path.is_none() && value.tls_key_path.is_none() {
                match domain {
                    DomainTier::Root | DomainTier:: Nested => {
                        individual_certs.insert(clean_route.to_string());
                    }
                    DomainTier::Subdomain => {
                        if value.individual_cert || !config.security.default_certificate_mode_wildcard {
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
            }
            // TODO add logic for self-signed certificates
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
