mod acme;
mod auth;
mod config;
mod env;
mod error;
mod proxy;
mod state;
use axum::routing::any;
use clap::Parser;
use rustls::ServerConfig;
use rustls::sign::CertifiedKey;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use toml::from_str;
use tracing::{Level, error, info};
use tracing_subscriber::FmtSubscriber;

use crate::acme::ddns;
use crate::acme::dns;
use crate::auth::oidc::{auth_callback, exchange_tunnel_key, fetch_jwks};
use crate::config::cli::{Cli, Commands};
use crate::config::socket;
use crate::config::structs::ToriiConfig;
use crate::env::Config;
use crate::proxy::router::handle_any;
use crate::proxy::server::{CertificateResolver, serve};
use crate::state::AppState;
use crate::{auth::oidc::auth_redirect, proxy::middleware::enforce_auth};
use axum::{Router, middleware};
use dotenvy;
use std::collections::{HashMap, HashSet};
use std::fs::read_to_string;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    /* Clean panics for deployment
    std::panic::set_hook(Box::new(|panic_info| {
        let payload = panic_info.payload().downcast_ref::<&str>().unwrap_or(&"unknown panic");
        let location = panic_info.location().unwrap();

        error!(
            "Thread panicked at {}:{}: {}",
            location.file(),
            location.line(),
            payload
        )
    }));
    */
    let cli = Cli::parse();
    info!("Attempting to load environment...");
    dotenvy::dotenv().ok();
    let config = match Config::new() {
        Ok(c) => c,
        Err(e) => {
            error!("FATAL: {}", e);
            std::process::exit(1);
        }
    };
    info!("Environment loaded successfully!");
    match cli.command {
        Commands::Start => {
            let (tx, rx) = mpsc::channel::<(
                HashSet<String>,
                HashSet<String>,
                HashMap<String, Arc<CertifiedKey>>,
            )>(20);
            let state = Arc::new(
                AppState::new(config, cli.config, tx)
                    .await
                    .expect("Failed to build state"),
            );
            tokio::spawn(socket::start_config_listener(state.clone()));
            tokio::spawn(dns::start_acme_worker(state.clone(), rx));
            if state.config.ddns {
                tokio::spawn(ddns::start_ddns_worker(state.clone()));
            }
            fetch_jwks(state.clone())
                .await
                .expect("FATAL: Failed to fetch JWKS from OIDC provider");
            let addr = format!("{}:{}", state.config.host, state.config.port);
            let public_routes = Router::new()
                .route("/auth/login", any(auth_redirect))
                .route("/auth/callback", any(auth_callback));
            let private_routes = Router::new()
                .route("/api/tunnel-key", any(exchange_tunnel_key))
                .route("/", any(handle_any))
                .route("/{*path}", any(handle_any))
                .route_layer(middleware::from_fn_with_state(state.clone(), enforce_auth));
            let app = Router::new()
                .merge(public_routes)
                .merge(private_routes)
                .with_state(state.clone());
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CertificateResolver::new(Arc::clone(
                    &state.certificates,
                ))));
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind(&addr)
                .await
                .expect("FATAL: Failed to bind to port or port is already in use");
            info!("Listening on {}...", addr);

            serve(listener, app, acceptor).await
        }
        Commands::Reload => {
            let file_string = match read_to_string(cli.config) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("FATAL: Failed to read config file: {}", e);
                    std::process::exit(1);
                }
            };
            let config: ToriiConfig = match from_str(&file_string) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("FATAL: Invalid configuration: {}", e);
                    std::process::exit(1);
                }
            };
            let config_bytes = match postcard::to_allocvec(&config) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FATAL: Failed to serialize config: {}", e);
                    std::process::exit(1);
                }
            };
            // TODO: look into cross-platform solution
            let mut stream = match UnixStream::connect("/tmp/torii.sock").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("FATAL: Failed to connect to socket: {}", e);
                    std::process::exit(1);
                }
            };
            let Ok(_) = stream.write_all(&config_bytes).await else {
                eprintln!("FATAL: Failed to write to socket");
                std::process::exit(1);
            };
            let response = match stream.read_u8().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("FATAL: Daemon closed connection without confirming: {}", e);
                    std::process::exit(1);
                }
            };
            if response == 1 {
                println!("Configruation reloaded!");
                std::process::exit(0);
            } else {
                eprintln!("FATAL: Daemon rejected the configuration payload.");
                std::process::exit(1);
            }
        }
    }
}
