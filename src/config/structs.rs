use std::collections::HashMap;

use axum::http;
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

impl ActiveState {
    pub fn build(config: ToriiConfig) -> Result<Self, Error> {
        let mut router = matchit::Router::new();
        for (route, value) in config.routes.into_iter() {
            let clean_route = route.trim_end_matches('/');
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
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecurityConfig {
    ebpf_strike_threshold: u64,
    ebpf_lockout_duration_secs: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RouteConfig {
    upstream: String,
    public_bypass: bool,
    tls_insecure_skip_verify: bool,
}

pub struct ActiveRoute {
    pub upstream: http::Uri,
    pub public_bypass: bool,
    pub tls_insecure_skip_verify: bool,
}

impl TryFrom<RouteConfig> for ActiveRoute {
    type Error = Error;
    fn try_from(config: RouteConfig) -> Result<Self, Self::Error> {
        Ok(ActiveRoute {
            upstream: config.upstream.parse()?,
            public_bypass: config.public_bypass,
            tls_insecure_skip_verify: config.tls_insecure_skip_verify,
        })
    }
}
