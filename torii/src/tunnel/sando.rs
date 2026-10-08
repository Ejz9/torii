use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use aws_lc_rs::digest;
use biscuit_auth::{Biscuit, macros::authorizer};
use keidai::{ConnectionEvent, ControlMessage, SidecarConfig, recv_control, send_control};
use log::warn;
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
use zerocopy::IntoBytes;

use crate::{error::Error, state::AppState};

pub fn load_or_generate_tunnel_cert(
    sando_path: &str,
) -> Result<(rustls::ServerConfig, [u8; 32]), Error> {
    let cert_path = format!("{sando_path}tunnel_cert.der");
    let key_path = format!("{sando_path}tunnel_key.der");

    let (cert_bytes, key_bytes) = match (fs::read(&cert_path), fs::read(&key_path)) {
        (Ok(cert_bytes), Ok(key_bytes)) => (cert_bytes, key_bytes),
        _ => {
            info!("Generating new Sando tunnel certificate...");
            let cert_key = generate_simple_self_signed(vec![
                "torii-tunnel".to_string(),
                "localhost".to_string(),
            ])?;
            let cert_bytes = cert_key.cert.der().to_vec();
            let key_bytes = cert_key.signing_key.serialize_der();
            fs::write(&cert_path, &cert_bytes)?;
            fs::write(&key_path, &key_bytes)?;
            (cert_bytes, key_bytes)
        }
    };
    let digest = digest::digest(&digest::SHA256, &cert_bytes);
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(digest.as_ref());
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_bytes)],
            PrivateKeyDer::Pkcs8(key_bytes.into()),
        )?;
    server_config.alpn_protocols = vec![b"torii-tunnel".to_vec()];
    Ok((server_config, fingerprint))
}

pub async fn listener(
    cancellation_token: CancellationToken,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let (rustls_config, fingerprint_) = load_or_generate_tunnel_cert(&state.config.sando_path)?;
    let quic_crypto = QuicServerConfig::try_from(rustls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport_config =
        Arc::get_mut(&mut server_config.transport).expect("transport config should be unique");
    transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
    let addr = SocketAddr::new(IpAddr::V4(state.config.host), state.config.quic_event_port);
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("Listening for QUIC tunnels on {addr}...");
    loop {
        let incoming = select! {
            biased;
            _ = cancellation_token.cancelled() => break,
            conn = endpoint.accept() => {
                match conn {
                    Some(incoming) => incoming,
                    None => break,
                }
            }
        };
        let child_token = cancellation_token.child_token();
        let sidecar_state = state.clone();
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            info!("Sidecar connected from {}", connection.remote_address());
            if let Err(e) = handle_sidecar(connection, sidecar_state, child_token).await {
                error!("Sidecar session error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_sidecar(
    connection: quinn::Connection,
    state: Arc<AppState>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;

    let msg = recv_control(&mut recv_stream).await?;
    let token = match msg {
        ControlMessage::Auth { token } => Biscuit::from(&token, state.root_keypair.public())?,
        _ => {
            let _ = state.event_tx.try_send(ConnectionEvent::new(
                0,
                400,
                "",
                connection.remote_address().ip(),
                "",
            ));
            anyhow::bail!("Expected Auth as first message")
        }
    };
    let mut authorizer = authorizer!(
        r#"
        allow if sidecar($id);
        "#
    )
    .build(&token)?;
    if let Err(e) = authorizer.authorize() {
        debug!("Invalid credentials for sidecar connection");
        let _ = state.event_tx.try_send(ConnectionEvent::new(
            0,
            403,
            "",
            connection.remote_address().ip(),
            "QUIC",
        ));
        connection.close(403_u32.into(), b"unauthorized");
        anyhow::bail!("Expected a valid token: {e}")
    }

    let ids: Vec<(String,)> = authorizer.query_all("data($id) <- sidecar($id)")?;
    let (id,) = ids
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Token missing sidecar fact"))?;

    let active = state.dynamic_config.load();
    let Some(sidecar_cfg) = active.sidecars.get(&id) else {
        warn!("Sidecar '{id}' authenticated, but has no routes configured");
        connection.close(404_u32.into(), b"no routes configured");
        anyhow::bail!("No configuration found for sidecar '{id}'");
    };

    let msg = ControlMessage::SyncConfig(SidecarConfig {
        routes: sidecar_cfg.routes.clone(),
        forbidden_paths: active.security.forbidden_paths.clone(),
    });
    let _ = send_control(&mut send_stream, &msg).await?;

    let Ok(Ok(ControlMessage::Ready)) =
        tokio::time::timeout(Duration::from_secs(10), recv_control(&mut recv_stream)).await
    else {
        anyhow::bail!("Expected Ready message from sidecar '{id}'")
    };

    let mut map = (**state.sidecars.load()).clone();
    map.insert(id.clone(), connection.clone());
    state.sidecars.store(Arc::new(map));
    debug!("Sidecar {id} added to routing table");

    let mut event_stream = connection.accept_uni().await?;
    let mut reload_rx = state.config_reload_tx.subscribe();

    loop {
        let mut event = ConnectionEvent::new(0, 0, "", IpAddr::V4(Ipv4Addr::UNSPECIFIED), "");
        select! {
            biased;
            _ = cancellation_token.cancelled() => {
                connection.close(0_u32.into(), b"gateway shutdown");
                break;
            }
            Ok(()) = reload_rx.recv() => {
                let dynamic_config = state.dynamic_config.load();
                if let Some(config) = dynamic_config.sidecars.get(&id) {
                    let msg = ControlMessage::SyncConfig(SidecarConfig {
                        routes: config.routes.clone(),
                        forbidden_paths: active.security.forbidden_paths.clone(),
                    });
                    if let Err(e) = send_control(&mut send_stream, &msg).await {
                        error!("Failed to send reloaded config to sidecar '{id}': {e}");
                        break;
                    }
                }
            }
            res = event_stream.read_exact(event.as_mut_bytes()) => {
                match res {
                    Ok(()) => {
                        let _ = state.event_tx.try_send(event);
                    }
                    Err(_) => break,
                }
            }
        }
    }

    debug!("Sidecar {id} disconnected, unregistering...");
    let mut map = (**state.sidecars.load()).clone();
    map.remove(&id);
    state.sidecars.store(Arc::new(map));

    Ok(())
}
