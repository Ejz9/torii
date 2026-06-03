use crate::auth::oidc::{Endpoints, TokenResponse};
use crate::config::Config;
use moka::future::Cache;
pub struct AppState {
    pub config: Config,
    pub endpoints: Endpoints,
    pub csrf_cache: Cache<String, ()>,
    pub session_cache: Cache<String, TokenResponse>,
}
