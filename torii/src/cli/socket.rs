use arc_swap::ArcSwap;
use rustls::{client::WebPkiServerVerifier, sign::CertifiedKey};
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
        cli::{BansArgs, IpFilter},
        config::{ActiveState, ToriiConfig},
    },
    ebpf::{
        kekkai_manager::IpPrefix,
        ofuda::{OfudaEntry, get_ofuda_list},
    },
    error::Error,
};

pub async fn config_listener(
    mut dynamic_config: Arc<ArcSwap<ActiveState>>,
    cert_verifier: Arc<WebPkiServerVerifier>,
    acme_tx: tokio::sync::mpsc::Sender<(
        HashSet<String>,
        HashSet<String>,
        HashMap<String, Arc<CertifiedKey>>,
    )>,
    ofuda_tx: tokio::sync::mpsc::Sender<OfudaEntry>,
    mihari_tx: tokio::sync::mpsc::Sender<Option<String>>,
    kekkai_path: String,
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
            SocketMessage::ReloadConfig(data) => match ActiveState::build(data, &cert_verifier) {
                Ok((config, individual_certs, wildcard_certs, custom_certs)) => {
                    dynamic_config.store(Arc::new(config));
                    if let Err(e) = acme_tx
                        .send((individual_certs, wildcard_certs, custom_certs))
                        .await
                    {
                        error!("FATAL: ACME worker thread is dead: {}", e);
                        send_message(&mut stream, SocketResponse::FatalError(e.to_string())).await
                    }
                    send_message(&mut stream, SocketResponse::Success).await
                }
                Err(e) => {
                    send_message(&mut stream, SocketResponse::FatalError(e.to_string())).await
                }
            },
            SocketMessage::UpdateBans(bans_args) => {
                let invalid_add_entries = validate_ips(&bans_args.add);
                let invalid_remove_entries = validate_ips(&bans_args.remove);
                if invalid_add_entries || invalid_remove_entries {
                    error!("Invalid addresses present");
                    continue;
                }
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
            SocketMessage::ListBans(filter) => match get_ofuda_list(&filter, &kekkai_path).await {
                Ok(bans) => {
                    let strings: Vec<String> = bans.iter().map(|ip| ip.to_string()).collect();
                    send_message(&mut stream, SocketResponse::ListBans(strings)).await
                }
                Err(e) => {
                    send_message(&mut stream, SocketResponse::FatalError(e.to_string())).await
                }
            },
            SocketMessage::CommandMihari { action } => {
                if action.eq_ignore_ascii_case("stop") {
                    if let Err(e) = mihari_tx.send(None).await {
                        error!("Failed to send shutdown signal to mihari: {e}");
                        send_message(&mut stream, SocketResponse::FatalError(e.to_string())).await
                    }
                } else {
                    if let Err(e) = mihari_tx.send(Some(action)).await {
                        error!("Failed to send action to mihari: {e}");
                        send_message(&mut stream, SocketResponse::FatalError(e.to_string())).await
                    }
                }
                send_message(&mut stream, SocketResponse::Success).await;
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
    CommandMihari { action: String },
}

#[derive(Serialize, Deserialize)]
pub enum SocketResponse {
    Success,
    PartialSuccess(Vec<String>),
    FatalError(String),
    ListBans(Vec<String>),
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
                Ok(println!("There are no active bans"))
            } else {
                Ok(println!("Active Bans:\n - {}", bans.join("\n - ")))
            }
        }
        SocketResponse::FatalError(err) => {
            Err(Error::InvalidCustomSetup(format!("Daemon Error: {err}")))
        }
    }
}

pub fn validate_ips(list: &Vec<String>) -> bool {
    let mut error = false;
    for ip in list {
        if ip.parse::<IpPrefix>().is_err() {
            eprintln!("FATAL: Invalid IP Address {ip}");
            if !error {
                error = true;
            }
        }
    }
    error
}

async fn send_message(stream: &mut UnixStream, message: SocketResponse) {
    if let Ok(bytes) = postcard::to_allocvec(&message) {
        let _ = stream.write_u32(bytes.len() as u32).await;
        let _ = stream.write_all(&bytes).await;
    }
}
