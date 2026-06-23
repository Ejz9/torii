use std::{collections::HashMap, str::FromStr};

use axum::http::{self, uri};
use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Serialize, Deserialize, Clone)]
pub struct ToriiConfig {
    security: SecurityConfig,
    routes: HashMap<String, RouteConfig>,
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
    pub fn build(config: ToriiConfig) -> Result<Self, Error> {
        let mut individual_certs = vec![];
        let mut wildcard_certs = vec![];
        let mut router = matchit::Router::new();
        for (route, value) in config.routes.into_iter() {
            let clean_route = route.trim_end_matches('/');
            let domain = clean_route.parse::<DomainTier>()?;
            if value.tls_cert_path.is_none() && value.tls_key_path.is_none() {
                match domain {
                    DomainTier::Root => individual_certs.push(clean_route.to_string()),
                    DomainTier::Nested => individual_certs.push(clean_route.to_string()),
                    DomainTier::Subdomain => {
                        if value.individual_cert {
                            individual_certs.push(clean_route.to_string());
                        } else {
                            //FIX
                            let root = clean_route.split_once(".").to_string();
                            wildcard_certs.push(root)
                        }
                    }
                }
            }
            let exact_pattern = format!("/{}", clean_route);
            router.insert(exact_pattern, value.clone().try_into()?)?;

            let catch_all_pattern = format!("/{}/{{*catch_all}}", clean_route);
            router.insert(catch_all_pattern, value.try_into()?)?;
        }
        Ok(ActiveState {
            security: config.security,
            routes: router,
        })
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
    default_certificate_mode: String,
    ebpf_strike_threshold: u64,
    ebpf_lockout_duration_secs: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RouteConfig {
    upstream: String,
    public_bypass: bool,
    tls_insecure_skip_verify: bool,
    individual_cert: bool,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    allowed_asset_paths: Vec<String>,
    allowed_groups: Vec<String>,
}

#[derive(Clone)]
pub struct ActiveRoute {
    pub upstream: http::Uri,
    pub public_bypass: bool,
    pub tls_insecure_skip_verify: bool,
    pub individual_cert: bool,
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
            individual_cert: config.individual_cert,
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
