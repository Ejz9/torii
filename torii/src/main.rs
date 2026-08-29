mod acme;
mod auth;
mod cli;
mod ebpf;
mod env;
mod error;
mod proxy;
mod state;
use anyhow::Context;
use axum::routing::any;
use clap::Parser;
use moka::sync::Cache;
use rustls::ServerConfig;
use rustls::sign::CertifiedKey;
use tokio::fs::read_to_string;
use tokio::select;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use toml::from_str;
use tracing::{Level, error, info};
use tracing_subscriber::FmtSubscriber;

use crate::acme::ddns;
use crate::acme::dns;
use crate::auth::oidc::{auth_callback, exchange_tunnel_key, fetch_jwks};
use crate::cli::cli::{Cli, Commands};
use crate::cli::config::ToriiConfig;
use crate::cli::socket;
use crate::cli::socket::SocketMessage;
use crate::cli::socket::send_socket_message;
use crate::cli::socket::validate_ips;
use crate::ebpf::hashira::EbpfEntry;
use crate::ebpf::kekkai_manager;
use crate::ebpf::ofuda::OfudaEntry;
use crate::env::Config;
use crate::proxy::router::handle_any;
use crate::proxy::server::{CertificateResolver, serve};
use crate::state::AppState;
use crate::{auth::oidc::auth_redirect, proxy::middleware::enforce_auth};
use axum::{Router, middleware};
use dotenvy;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

// Need to drop mpsc of workers that don't start or fail(fail = std exit?).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");
    tracing_log::LogTracer::init().expect("Failed to initialize log tracer");
    let cli = Cli::parse();
    match cli.command {
        Commands::Start => {
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
            let root_token = CancellationToken::new();
            let worker_token = root_token.child_token();
            let network_token = root_token.child_token();
            let mut worker_set: JoinSet<anyhow::Result<()>> = JoinSet::new();
            let (ofuda_tx, ofuda_rx) = mpsc::channel::<OfudaEntry>(1024);
            let (acme_tx, acme_rx) = mpsc::channel::<(
                HashSet<String>,
                HashSet<String>,
                HashMap<String, Arc<CertifiedKey>>,
            )>(20);
            let mihari_notify = Arc::new(Notify::new());
            let (hashira_tx, mut hashira_rx) = tokio::sync::mpsc::channel::<EbpfEntry>(100_000);
            let l4_rate_limiter: Cache<IpAddr, u32> = Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(1))
                .build();
            let state = Arc::new(
                AppState::new(config, cli.config, acme_tx.clone())
                    .await
                    .context("FATAL: Daemon failed to build state")?,
            );
            let Some(interface) = state.config.interface.clone() else {
                error!("Interface not defined in .env");
                std::process::exit(1);
            };
            worker_set.spawn(kekkai_manager::run(
                state.clone(),
                ofuda_rx,
                Arc::clone(&mihari_notify),
                hashira_tx.clone(),
                hashira_rx,
                interface,
                worker_token.clone(),
            ));
            worker_set.spawn(socket::config_listener(
                Arc::clone(&state.dynamic_config),
                Arc::clone(&state.cert_verifier),
                acme_tx,
                state.config.acme_provider.is_some(),
                ofuda_tx,
                mihari_notify,
                state.config.kekkai_path.clone(),
                worker_token.clone(),
            ));
            if let Some(acme_provider) = state.config.acme_provider.clone() {
                worker_set.spawn(dns::acme_worker(
                    state.clone(),
                    acme_provider.clone(),
                    acme_rx,
                    worker_token.clone(),
                ));
                if state.config.ddns {
                    worker_set.spawn(ddns::run(
                        state.clone(),
                        acme_provider,
                        worker_token.clone(),
                    ));
                }
            } else {
                drop(acme_rx);
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

            serve(listener, app, acceptor, l4_rate_limiter, hashira_tx).await
        }
        Commands::Reload => {
            let file_string = read_to_string(cli.config)
                .await
                .context("FATAL: Failed to read config file")?;
            let config: ToriiConfig =
                from_str(&file_string).context("FATAL: Invalid configuration")?;
            send_socket_message(SocketMessage::ReloadConfig(config))
                .await
                .context("FATAL: Daemon rejected the configuration payload")?;
            println!("Configruation reloaded!");
        }
        Commands::Bans(bans_args) => {
            if let Some(filter) = bans_args.list {
                send_socket_message(SocketMessage::ListBans(filter))
                    .await
                    .context("FATAL: Daemon failed to retrieve ban list")?;
            } else {
                let invalid_add_entries = validate_ips(&bans_args.add);
                let invalid_remove_entries = validate_ips(&bans_args.remove);
                if invalid_add_entries || invalid_remove_entries {
                    std::process::exit(1);
                }
                send_socket_message(SocketMessage::UpdateBans(bans_args))
                    .await
                    .context("FATAL: Daemon rejected ban modifications")?;
                println!("Bans Processed");
            }
        }
        Commands::ReloadThreats => {
            send_socket_message(SocketMessage::ReloadMihari)
                .await
                .context("FATAL: Daemon failed to communicate with mihari worker thread")?;
            println!("Mhiari threat worker refreshed");
        }
    }
    std::process::exit(0);
}
