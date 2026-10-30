use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use clap::Parser;
use keidai::{ConnectionEvent, ControlMessage, recv_control};
use tokio::{task::JoinSet, time::{Instant, sleep}};
use tokio_util::sync::CancellationToken;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::{
    cli::{Cli, Commands},
    connect::{connect_gateway, handshake_gateway},
    dns::refresh_certificates,
    state::AppState,
};

mod cli;
mod connect;
mod dns;
mod error;
mod state;

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
                mut event_stream,
                sleep_duration,
            ) = handshake_gateway(&conn, &init, &mut failure_tracker, &args.cert_dir).await?;
            let (event_tx, event_rx) = flume::bounded::<ConnectionEvent>(10_000);
            let state = Arc::new(
                AppState::new(config, certificates, event_tx)
                    .await
                    .context("FATAL: Shinshi failed to build state")?,
            );
            let root_token = CancellationToken::new();
            let worker_token = root_token.child_token();
            let network_token = root_token.child_token();
            let mut worker_set: JoinSet<anyhow::Result<()>> = JoinSet::new();
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
                                state.dynamic_config.store(Arc::new(new_config));
                                failure_tracker.clear();
                                let (new_certs, sleep_duration) = refresh_certificates(&mut send_stream, &mut recv_stream, &state.dynamic_config.load().routes, &mut failure_tracker, &args.cert_dir).await?;
                                state.certificates.store(Arc::new(new_certs));
                            }
                            _ => {
                                warn!("Gateway terminated control stream. Attempting reconnect..."); // or shutting down?
                                break;
                            }
                        }
                    }
                    _ = sleep(sleep_duration) => {
                        let (new_certs, sleep_duration) = refresh_certificates(&mut send_stream, &mut recv_stream, &state.dynamic_config.load().routes, &mut failure_tracker, &args.cert_dir).await?;
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
