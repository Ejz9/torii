use std::fs::read_to_string;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::oidc::{ActiveSession, Endpoints};
use crate::config::structs::ActiveState;
use crate::env::Config;
use crate::error::Error;
use arc_swap::ArcSwap;
use axum::body::Body;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use toml::from_str;
use tracing::info;
pub struct AppState {
    pub config: Config,
    pub endpoints: Endpoints,
    pub csrf_cache: Cache<String, String>,
    pub session_cache: Cache<String, ActiveSession>,
    pub jwks_cache: Cache<String, DecodingKey>,
    pub limiter_cache: Cache<String, ()>,
    pub dynamic_config: ArcSwap<ActiveState>,
    pub connection_pool: Client<HttpsConnector<HttpConnector>, Body>,
    pub insecure_connection_pool: Client<HttpsConnector<HttpConnector>, Body>,
}

const DEFAULT_CONFIG_STRING: &str = r#"
# Torii Gateway Configuration

[security]
# The number of malicious requests before the kernel drops the IP at the NIC
ebpf_strike_threshold = 10
# How long (in seconds) the offending IP remains locked out
ebpf_lockout_duration_secs = 3600

[routes]
# Routes are defined by their subdomain and path
# Set public_bypass to 'true' to skip OIDC authentication
# Example:
# [routes."ztree.dev"]
# upstream = "http://192.168.0.1:3000"
# public_bypass = false

"#;

impl AppState {
    pub async fn new(config: Config, config_path: String) -> Result<Self, Error> {
        let endpoints = Endpoints::discover_endpoints(&config.oidc_issuer_url)
            .await
            .expect("FATAL: Failed to fetch OIDC Discovery document");
        if !std::path::Path::new(&config_path).exists() {
            std::fs::write(&config_path, DEFAULT_CONFIG_STRING);
        }
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
        let configuration_parsed = from_str(&configuration_file)?;
        let configuration = ActiveState::build(configuration_parsed)?;
        let dynamic_config = ArcSwap::from_pointee(configuration);
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("no native root CA certificates found")
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let tls_no_verify = NoCertificateVerification {};
        let insecure_tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(tls_no_verify))
            .with_no_client_auth();
        let insecure_connector = HttpsConnectorBuilder::new()
            .with_tls_config(insecure_tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let connection_pool = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(10))
            .pool_max_idle_per_host(50)
            .build(connector);
        let insecure_connection_pool = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(10))
            .pool_max_idle_per_host(50)
            .build(insecure_connector);
        Ok(Self {
            config,
            endpoints,
            csrf_cache,
            session_cache,
            jwks_cache,
            limiter_cache,
            dynamic_config,
            connection_pool,
            insecure_connection_pool,
        })
    }
}

#[derive(Debug)]
pub struct NoCertificateVerification {}

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
