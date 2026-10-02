mod acme;
mod auth;
mod cli;
mod ebpf;
mod env;
mod error;
mod proxy;
mod state;
mod tunnel;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Context;
use axum::routing::any;
use clap::Parser;
use keidai::ConnectionEvent;
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs::Ticketer;
use rustls::server::ServerSessionMemoryCache;
use rustls::sign::CertifiedKey;
use tokio::fs::read_to_string;
use tokio::net::TcpSocket;
use tokio::select;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use toml::from_str;
use tracing::{Level, error, info};
use tracing_subscriber::FmtSubscriber;

use crate::acme::ddns;
use crate::acme::dns;
use crate::auth::biscuit::generate_or_load_keypair;
use crate::auth::oidc::{auth_callback, fetch_jwks};
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
use crate::proxy::middleware::temizuya;
use crate::proxy::router::handle_any;
use crate::proxy::server::{CertificateResolver, serve};
use crate::state::AppState;
use crate::{auth::oidc::auth_redirect, proxy::middleware::enforce_auth};
use axum::{Router, middleware};
use dotenvy;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    tracing_log::LogTracer::init()?;
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
            let root_keypair = generate_or_load_keypair(&config.biscuit_path)
                .context("FATAL: Failed to initialize Biscuit root key")?;
            info!("Environment loaded successfully!");
            let root_token = CancellationToken::new();
            let worker_token = root_token.child_token();
            let network_token = root_token.child_token();
            let mut worker_set: JoinSet<anyhow::Result<()>> = JoinSet::new();
            let (ofuda_tx, ofuda_rx) = mpsc::channel::<OfudaEntry>(32);
            let (acme_tx, acme_rx) = if config.acme_provider.is_some() {
                let (tx, rx) = mpsc::channel::<(
                    HashSet<String>,
                    HashSet<String>,
                    HashMap<String, Arc<CertifiedKey>>,
                )>(32);
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
            let mihari_notify = if config.mihari_provider.is_some() {
                Some(Arc::new(Notify::new()))
            } else {
                None
            };
            let (hashira_tx, hashira_rx) = tokio::sync::mpsc::channel::<EbpfEntry>(10_000);
            let (event_tx, event_rx) = flume::bounded::<ConnectionEvent>(10_000);
            let state = Arc::new(
                AppState::new(
                    config,
                    cli.config,
                    acme_tx.clone(),
                    event_tx.clone(),
                    root_keypair,
                )
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
                mihari_notify.clone(),
                hashira_tx.clone(),
                hashira_rx,
                event_rx,
                interface,
                worker_token.clone(),
            ));
            worker_set.spawn(socket::listener(
                Arc::clone(&state.dynamic_config),
                Arc::clone(&state.cert_verifier),
                acme_tx,
                ofuda_tx,
                mihari_notify.clone(),
                state.config.kekkai_path.clone(),
                worker_token.clone(),
            ));
            if let (Some(acme_provider), Some(acme_rx)) =
                (state.config.acme_provider.clone(), acme_rx)
            {
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
            }
            if let Some(endpoints) = &state.endpoints {
                fetch_jwks(&endpoints, &state.jwks_cache).await?;
            }
            let addr = format!("{}:{}", state.config.host, state.config.port);
            let private_routes = Router::new()
                .route("/", any(handle_any))
                .route("/{*path}", any(handle_any))
                .route_layer(middleware::from_fn_with_state(state.clone(), enforce_auth));
            let mut app = Router::new().merge(private_routes);
            if state.config.oidc_provider.is_some() {
                let auth_routes = Router::new()
                    .route("/auth/login", any(auth_redirect))
                    .route("/auth/callback", any(auth_callback));
                app = app.merge(auth_routes)
            };
            let app = app
                .layer(middleware::from_fn_with_state(state.clone(), temizuya))
                .with_state(state.clone());
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CertificateResolver::new(Arc::clone(
                    &state.certificates,
                ))));
            config.ticketer = Ticketer::new()?;
            config.session_storage = ServerSessionMemoryCache::new(20_000);
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let socket_addr: SocketAddr = addr.parse()?;
            let nr_cpus = std::thread::available_parallelism()?.get();
            let mut servers = Vec::new();
            for _ in 0..nr_cpus {
                let socket_addr = socket_addr;
                let app = app.clone();
                let acceptor = acceptor.clone();
                let event_tx = event_tx.clone();
                let network_token = network_token.clone();
                let socket = match socket_addr {
                    SocketAddr::V4(_) => TcpSocket::new_v4()?,
                    SocketAddr::V6(_) => TcpSocket::new_v6()?,
                };
                socket.set_reuseaddr(true)?;
                socket.set_reuseport(true)?;
                let timeout_secs: libc::c_int = 5;
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_TCP,
                        libc::TCP_DEFER_ACCEPT,
                        &timeout_secs as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&timeout_secs) as libc::socklen_t,
                    );
                }
                socket.bind(socket_addr)?;
                let listener = socket.listen(10240)?;
                servers.push(tokio::spawn(serve(
                    listener,
                    app.clone(),
                    acceptor.clone(),
                    event_tx.clone(),
                    network_token.clone(),
                )));
            }
            info!("Listening on {} across {} listeners...", addr, nr_cpus);

            // Add hashira use in the main server worker or for specialized / auth endpoints.
            // Otherwise leave add to eBPF but should be good to move on to sidecar and http/3
            // can also setup internal JWT for use instead of UUID. Sidecars check this to trust traffic came from torii
            select! {
                _ = tokio::signal::ctrl_c() => {}
                Some(result) = worker_set.join_next() => {
                    match result {
                        Ok(Ok(())) => {
                            error!("FATAL: A critical worker thread exited unexpectedly without throwing an error");
                        }
                        Ok(Err(e)) => {
                            error!("FATAL: A worker thread crashed: {e:#}");
                        }
                        Err(e) => {
                            if e.is_panic() {
                                error!("FATAL: A worker thread encountered a panic");
                            } else {
                                error!("FATAL: A worker thread failed to execute: {e}");
                            }
                        }
                    }
                }
            }
            info!("Shutdown signal recieved...");
            network_token.cancel();
            for server in servers {
                let _ = server.await;
            }
            info!("Network listener stopped");
            worker_token.cancel();
            while let Some(res) = worker_set.join_next().await {
                if let Err(e) = res {
                    error!("Worker error during shutdown {e}");
                }
            }
            info!("Torii completed shutdown");
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
