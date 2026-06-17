use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Serialize, Deserialize, Clone)]
pub struct ToriiConfig {
    security: SecurityConfig,
    routes: HashMap<String, RouteConfig>,
}

pub struct ActiveState {
    security: SecurityConfig,
    routes: matchit::Router<RouteConfig>
}

impl ActiveState {
    pub fn build(config: ToriiConfig) -> Result<Self, Error> {
        let mut router = matchit::Router::new();
        for (route, value) in config.routes.into_iter() {
            if route.ends_with('/') {
                router.insert(format!("{}*catch_all", route), value);
            } else {
                router.insert(format!("{}/*catch_all", route), value);
            }
        }
        Ok(ActiveState { security: config.security, routes: router})
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
}
