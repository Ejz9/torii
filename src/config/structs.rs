use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct ToriiConfig {
    security: SecurityConfig,
    routes: HashMap<String, RouteConfig>,
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
