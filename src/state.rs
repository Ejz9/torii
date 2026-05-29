use crate::config::Config;
use crate::auth::oidc::Endpoints;
pub struct AppState {
    pub config: Config,
    pub endpoints: Endpoints,

}