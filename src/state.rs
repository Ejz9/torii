use std::fs::read_to_string;
use std::time::Duration;

use crate::auth::oidc::{ActiveSession, Endpoints};
use crate::config::structs::ToriiConfig;
use crate::env::Config;
use crate::error::Error;
use arc_swap::ArcSwap;
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use toml::from_str;
use tracing::info;
pub struct AppState {
    pub config: Config,
    pub endpoints: Endpoints,
    pub csrf_cache: Cache<String, String>,
    pub session_cache: Cache<String, ActiveSession>,
    pub jwks_cache: Cache<String, DecodingKey>,
    pub limiter_cache: Cache<String, ()>,
    pub dynamic_config: ArcSwap<ToriiConfig>,
}

impl AppState {
    pub async fn new(config: Config, config_path: String) -> Result<Self, Error> {
        let endpoints = Endpoints::discover_endpoints(&config.oidc_issuer_url)
            .await
            .expect("FATAL: Failed to fetch OIDC Discovery document");
        info!("Preparing resources...");
        let csrf_cache: Cache<String, String> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(300))
            .build();
        let session_cache: Cache<String, ActiveSession> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_hours(168))
            .build();
        let jwks_cache: Cache<String, DecodingKey> = Cache::new(20);
        let limiter_cache: Cache<String, ()> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(15))
            .build();
        let configuration_file = read_to_string(config_path)?;
        let configuration = from_str(&configuration_file)?;
        let dynamic_config = ArcSwap::from_pointee(configuration);
        Ok(Self {
            config,
            endpoints,
            csrf_cache,
            session_cache,
            jwks_cache,
            limiter_cache,
            dynamic_config,
        })
    }
}
