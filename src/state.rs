use crate::config::Config;
use crate::auth::oidc::Endpoints;
use moka::future::Cache;
pub struct AppState {
    pub config: Config,
    pub endpoints: Endpoints,
    pub csrf_cache: Cache<String, ()>
}