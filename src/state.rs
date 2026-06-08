use crate::auth::oidc::{ActiveSession, Endpoints};
use crate::config::Config;
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
pub struct AppState {
    pub config: Config,
    pub endpoints: Endpoints,
    pub csrf_cache: Cache<String, String>,
    pub session_cache: Cache<String, ActiveSession>,
    pub jwks_cache: Cache<String, DecodingKey>,
    pub limiter_cache: Cache<String, ()>
}
