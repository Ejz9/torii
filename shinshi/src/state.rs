use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use axum::body::Body;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use keidai::{
    ActiveRoute, ConnectionEvent, ShinshiConfig, TunnelEndpoint, create_connection_pools,
};
use rustls::sign::CertifiedKey;

use crate::router::build_active_routes;

pub struct AppState {
    pub dynamic_config: Arc<ArcSwap<ShinshiConfig>>,
    pub gateway_host: TunnelEndpoint,
    pub routes: Arc<ArcSwap<HashMap<String, Arc<ActiveRoute>>>>,
    pub connection_pool: Client<HttpsConnector<HttpConnector>, Body>,
    pub insecure_connection_pool: Client<HttpsConnector<HttpConnector>, Body>,
    pub certificates: Arc<ArcSwap<HashMap<String, Arc<CertifiedKey>>>>,
    pub event_tx: flume::Sender<ConnectionEvent>,
}

impl AppState {
    pub async fn new(
        config: ShinshiConfig,
        gateway_host: TunnelEndpoint,
        certs: HashMap<String, Arc<CertifiedKey>>,
        event_tx: flume::Sender<ConnectionEvent>,
    ) -> anyhow::Result<Self> {
        let dynamic_config = Arc::new(ArcSwap::from_pointee(config.clone()));
        let certificates = Arc::new(ArcSwap::from_pointee(certs));
        let routes = Arc::new(ArcSwap::from_pointee(build_active_routes(&config)));
        let (connection_pool, insecure_connection_pool) = create_connection_pools(None)?;
        Ok(Self {
            dynamic_config,
            gateway_host,
            routes,
            connection_pool,
            insecure_connection_pool,
            certificates,
            event_tx,
        })
    }
}
