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
            if route.ends_with('/') {
                router.insert(
                    format!("{}*catch_all", route),
                    value.try_into()?,
                )?;
            } else {
                router.insert(
                    format!("{}/*catch_all", route),
                    value.try_into()?,
                )?;
            }
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
