use biscuit_auth::macros::biscuit;
use keidai::SidecarInit;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    cli::{
        cli::{BansArgs, IpFilter, TunnelArgs},
        config::{ActiveState, ToriiConfig},
    },
    ebpf::{
        kekkai_manager::IpPrefix,
        ofuda::{OfudaEntry, get_ofuda_list},
    },
    error::Error,
    state::AppState,
};

pub async fn listener(
    state: Arc<AppState>,
    config_reload_tx: tokio::sync::broadcast::Sender<()>,
    acme_tx: Option<
        tokio::sync::mpsc::Sender<(
            HashSet<String>,
            HashSet<String>,
            HashMap<String, Arc<CertifiedKey>>,
        )>,
    >,
    ofuda_tx: tokio::sync::mpsc::Sender<OfudaEntry>,
    mihari_notify: Option<Arc<tokio::sync::Notify>>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    std::fs::remove_file("/tmp/torii.sock").ok();
    let Ok(listener) = UnixListener::bind("/tmp/torii.sock") else {
        error!("FATAL: Failed to create config socket, does it already exist?");
        std::process::exit(1)
    };
    loop {
        let mut stream = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => {
                info!("Config socket recieved shutdown signal. Halting listener.");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((s, _addr)) => s,
                    Err(e) => {
                        error!("FATAL: Failed to recieve config bytes: {}", e);
                        continue;
                    }
                }
            }
        };
        let Ok(size) = stream.read_u32().await else {
            let _ = stream.write_u8(0).await;
            continue;
        };
        let mut buffer = vec![0u8; size as usize];
        let Ok(bytes) = stream.read(&mut buffer).await else {
            let _ = stream.write_u8(0).await;
            continue;
        };
        let Some(data) = postcard::from_bytes(&buffer[..bytes]).ok() else {
            let _ = stream.write_u8(0).await;
            continue;
        };
        let _ = stream.write_u8(1).await;
        match data {
            SocketMessage::ReloadConfig(data) => {
                match ActiveState::build(data, &state.cert_verifier) {
                    Ok((config, individual_certs, wildcard_certs, custom_certs)) => {
                        state.dynamic_config.store(Arc::new(config));
                        let _ = config_reload_tx.send(());
                        if let Some(acme_tx) = &acme_tx {
                            let _ = acme_tx
                                .send((individual_certs, wildcard_certs, custom_certs))
                                .await;
                        } else {
                            send_message(
                                &mut stream,
                                SocketResponse::FatalError("ACME provider disabled".to_string()),
                            )
                            .await
                        }
                        send_message(&mut stream, SocketResponse::Success).await
                    }
                    Err(e) => {
                        send_message(&mut stream, SocketResponse::FatalError(e.to_string())).await
                    }
                }
            }
            SocketMessage::UpdateBans(bans_args) => {
                let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), Vec<String>>>();
                let entry: OfudaEntry = (bans_args, tx).into();
                if let Err(e) = ofuda_tx.send(entry).await {
                    error!("Failed to send entry to ofuda: {e}")
                }
                match rx.await {
                    Ok(Ok(())) => send_message(&mut stream, SocketResponse::Success).await,
                    Ok(Err(err_vec)) => {
                        send_message(&mut stream, SocketResponse::PartialSuccess(err_vec)).await
                    }
                    Err(_) => {
                        send_message(
                            &mut stream,
                            SocketResponse::FatalError(
                                "Ofuda worker crashed or dropped request".to_string(),
                            ),
                        )
                        .await
                    }
                }
            }
            SocketMessage::ListBans(filter) => {
                match get_ofuda_list(&filter, &state.config.kekkai_path).await {
                    Ok(bans) => send_message(&mut stream, SocketResponse::ListBans(bans)).await,
                    Err(e) => {
                        send_message(&mut stream, SocketResponse::FatalError(e.to_string())).await
                    }
                }
            }
            SocketMessage::ReloadMihari => {
                if let Some(mihari_notify) = &mihari_notify {
                    mihari_notify.notify_one();
                    send_message(&mut stream, SocketResponse::Success).await;
                }
            }
            SocketMessage::TunnelInit(args) => {
                let active = state.dynamic_config.load();
                let sidecar_id = args.name.unwrap_or_else(|| {
                    uuid::Uuid::new_v4()
                        .to_string()
                        .parse()
                        .expect("UUID is a valid ShinshiName")
                });
                if active.sidecars.contains_key(&sidecar_id) {
                    send_message(
                        &mut stream,
                        SocketResponse::FatalError(format!("'{sidecar_id}' already exists")),
                    )
                    .await;
                    continue;
                }
                let mut errors = Vec::new();
                for route in &args.routes {
                    if let Some(sidecar) = active.sidecar_routes.get(route) {
                        errors.push(format!("'{route}' is already registered to {sidecar}",));
                    }
                    if active.routes.at(&format!("/{route}")).is_ok() {
                        errors.push(format!(
                            "'{route}' is already configured as a gateway route"
                        ));
                    }
                }

                if !errors.is_empty() {
                    send_message(
                        &mut stream,
                        SocketResponse::FatalError(format!(
                            "Route collisions detected:\n - {}",
                            errors.join("\n -")
                        )),
                    )
                    .await;
                    continue;
                }

                let builder = biscuit!(
                    r#"
                    sidecar({id});
                    "#,
                    id = sidecar_id.to_string()
                );
                let Some(server) = args.server.or_else(|| state.config.sando_endpoint.clone())
                else {
                    send_message(&mut stream, SocketResponse::FatalError("Server endpoint required: specify with --server <host:port> or set SANDO_ENDPOINT in .env".to_string())).await;
                    continue;
                };
                let token = builder.build(&state.root_keypair)?.to_base64()?;
                let init = SidecarInit {
                    id: sidecar_id,
                    token,
                    fingerprint: state.tunnel_fingerprint.clone(),
                    server: server,
                };
                let command = format!("shinshi start --token {}", init.to_token()?);
                send_message(&mut stream, SocketResponse::TunnelCommand(command)).await
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub enum SocketMessage {
    ReloadConfig(ToriiConfig),
    UpdateBans(BansArgs),
    ListBans(IpFilter),
    ReloadMihari,
    TunnelInit(TunnelArgs),
}

#[derive(Serialize, Deserialize)]
pub enum SocketResponse {
    Success,
    PartialSuccess(Vec<String>),
    FatalError(String),
    ListBans(Vec<IpPrefix>),
    TunnelCommand(String),
}

pub async fn send_socket_message(message: SocketMessage) -> Result<(), Error> {
    let bytes = postcard::to_allocvec(&message)
        .map_err(|e| Error::InvalidCustomSetup(format!("FATAL: Failed to serialize: {e}")))?;
    let mut stream = UnixStream::connect("/tmp/torii.sock").await.map_err(|e| {
        Error::InvalidCustomSetup(format!(
            "FATAL: Failed to connect to socket is daemon running? {e}"
        ))
    })?;
    stream.write_u32(bytes.len() as u32).await.map_err(|e| {
        Error::InvalidCustomSetup(format!("FATAL: Failed to write bytes length {e}"))
    })?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| Error::InvalidCustomSetup(format!("FATAL: Failed to write bytes {e}")))?;
    let accepted = stream.read_u8().await.map_err(|e| {
        Error::InvalidCustomSetup(format!(
            "FATAL: Daemon closed connection without confirming {e}"
        ))
    })?;
    if accepted == 0 {
        return Err(Error::InvalidCustomSetup(
            "FATAL: Daemon rejected the bytes.".to_string(),
        ));
    }
    let response_len = stream.read_u32().await.map_err(|e| {
        Error::InvalidCustomSetup(format!("FATAL: Failed to read response length {e}"))
    })?;
    let mut response_buf = vec![0u8; response_len as usize];
    stream
        .read_exact(&mut response_buf)
        .await
        .map_err(|e| Error::InvalidCustomSetup(format!("FATAL: Failed to read response {e}")))?;
    let response: SocketResponse = postcard::from_bytes(&response_buf)
        .map_err(|e| Error::InvalidCustomSetup(format!("FATAL: Failed to deserialize {e}")))?;
    match response {
        SocketResponse::Success => Ok(()),
        SocketResponse::PartialSuccess(errors) => Err(Error::InvalidCustomSetup(format!(
            "Partial success: The following issues occurred:\n - {}",
            errors.join("\n - ")
        ))),
        SocketResponse::ListBans(bans) => {
            if bans.is_empty() {
                println!("There are no active bans");
            } else {
                println!("Active Bans:");
                for ban in &bans {
                    println!("- {ban}");
                }
            }
            Ok(())
        }
        SocketResponse::TunnelCommand(command) => Ok(println!(
            "Sidecar init generated successfully!\nRun on your backend host:\n\n {command}"
        )),
        SocketResponse::FatalError(err) => {
            Err(Error::InvalidCustomSetup(format!("Daemon Error: {err}")))
        }
    }
}

async fn send_message(stream: &mut UnixStream, message: SocketResponse) {
    if let Ok(bytes) = postcard::to_allocvec(&message) {
        let _ = stream.write_u32(bytes.len() as u32).await;
        let _ = stream.write_all(&bytes).await;
    }
}
