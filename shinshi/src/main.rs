mod cli;
mod connect;
mod dns;
mod error;
mod middleware;
mod miko;
mod router;
mod server;
mod state;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use axum::Router;
use clap::Parser;
use keidai::{ConnectionEvent, ControlMessage, recv_control};
use rustls::{crypto::aws_lc_rs::Ticketer, server::ServerSessionMemoryCache};
use tokio::{
    task::JoinSet,
    time::{Instant, sleep},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::{
    cli::{Cli, Commands},
    connect::{connect_gateway, handshake_gateway},
    dns::refresh_certificates,
    middleware::{enforce_auth, temizuya},
    router::{build_active_routes, handle_any},
    server::CertificateResolver,
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .finish(),
    )?;
    let cli = Cli::parse();
    match cli.command {
        Commands::Start(args) => {
            let init = args.load_token()?;
            info!(
                "Shinshi starting '{} for gateway at {}",
                init.id, init.server
            );
            let conn = connect_gateway(&init).await?;
            let mut failure_tracker: HashMap<String, (u8, Instant)> = HashMap::new();
            let (
                mut send_stream,
                mut recv_stream,
                config,
                certificates,
                event_stream,
                mut sleep_duration,
            ) = handshake_gateway(&conn, &init, &mut failure_tracker, &args.cert_dir).await?;
            let (event_tx, event_rx) = flume::bounded::<ConnectionEvent>(10_000);
            let state = Arc::new(
                AppState::new(config, init.server, certificates, event_tx.clone())
                    .await
                    .context("FATAL: Shinshi failed to build state")?,
            );
            let root_token = CancellationToken::new();
            let worker_token = root_token.child_token();
            let network_token = root_token.child_token();
            let mut worker_set: JoinSet<anyhow::Result<()>> = JoinSet::new();
            worker_set.spawn(miko::kagura(event_stream, event_rx, worker_token));
            let routes = Router::new()
                .fallback(handle_any)
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    enforce_auth,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    temizuya,
                ))
                .with_state(state.clone());
            let mut tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CertificateResolver::new(Arc::clone(
                    &state.certificates,
                ))));
            tls_config.ticketer = Ticketer::new()?;
            tls_config.session_storage = ServerSessionMemoryCache::new(20_000);
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(tls_config));
            let nr_cpus = std::thread::available_parallelism()?.get();
            worker_set.spawn(server::serve(
                conn,
                routes,
                acceptor,
                event_tx,
                network_token.clone(),
                (nr_cpus * 128).clamp(256, 1024),
            ));
            loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c() => {
                        info!("Shutdown signal recieved...");
                        break;
                    }
                    msg = recv_control(&mut recv_stream) => {
                        match msg {
                            Ok(ControlMessage::SyncConfig(new_config)) => {
                                info!("Updating config from gateway...");
                                let active_routes = build_active_routes(&new_config);
                                state.routes.store(Arc::new(active_routes));
                                state.dynamic_config.store(Arc::new(new_config));
                                failure_tracker.clear();
                                let (new_certs, next_sleep) = refresh_certificates(&mut send_stream, &mut recv_stream, &state.dynamic_config.load().routes, &mut failure_tracker, &args.cert_dir).await?;
                                sleep_duration = next_sleep;
                                state.certificates.store(Arc::new(new_certs));
                            }
                            _ => {
                                warn!("Gateway terminated control stream. Attempting reconnect..."); // or shutting down?
                                break;
                            }
                        }
                    }
                    _ = sleep(sleep_duration) => {
                        let (new_certs, next_sleep) = refresh_certificates(&mut send_stream, &mut recv_stream, &state.dynamic_config.load().routes, &mut failure_tracker, &args.cert_dir).await?;
                        sleep_duration = next_sleep;
                        state.certificates.store(Arc::new(new_certs));
                    }
                }
            }
            network_token.cancel();
            info!("Shinshi completed shutdown");
        }
    }
    Ok(())
}
