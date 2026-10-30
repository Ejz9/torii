use std::{collections::HashMap, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use keidai::{ControlMessage, SidecarConfig, SidecarInit, recv_control, send_control};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::sign::CertifiedKey;
use tokio::{net::lookup_host, time::Instant};

use crate::{dns::refresh_certificates, state::NoCertificateVerification};

pub async fn connect_gateway(init: &SidecarInit) -> anyhow::Result<quinn::Connection> {
    let verifier = Arc::new(NoCertificateVerification {
        fingerprint: Some(init.fingerprint),
    });
    let mut rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"torii-tunnel".to_vec()];
    let quinn_crypto = QuicClientConfig::try_from(rustls_config)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([0; 16], 0)))
        .or_else(|_| quinn::Endpoint::client(SocketAddr::from(([0; 4], 0))))?;
    endpoint.set_default_client_config(client_config);
    let addr = lookup_host((init.server.host.as_str(), init.server.port))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve gateway host '{}'", init.server.host))?;
    Ok(endpoint.connect(addr, "torii-tunnel")?.await?)
}

pub async fn handshake_gateway(
    conn: &quinn::Connection,
    init: &SidecarInit,
    failure_tracker: &mut HashMap<String, (u8, Instant)>,
    cert_dir: &Path,
) -> anyhow::Result<(
    quinn::SendStream,
    quinn::RecvStream,
    SidecarConfig,
    HashMap<String, Arc<CertifiedKey>>,
    quinn::SendStream,
    Duration,
)> {
    let (mut send_stream, mut recv_stream) = conn.open_bi().await?;
    send_control(
        &mut send_stream,
        &ControlMessage::Auth {
            token: init.token.clone(),
        },
    )
    .await?;
    let msg = recv_control(&mut recv_stream).await?;
    let config = match msg {
        ControlMessage::SyncConfig(cfg) => cfg,
        _ => anyhow::bail!("Expected SyncConfig from gateway"),
    };
    let (certificates, sleep_duration) = refresh_certificates(
        &mut send_stream,
        &mut recv_stream,
        &config.routes,
        failure_tracker,
        &cert_dir,
    )
    .await?;
    send_control(&mut send_stream, &ControlMessage::Ready).await?;
    let event_stream = conn.open_uni().await?;
    Ok((
        send_stream,
        recv_stream,
        config,
        certificates,
        event_stream,
        sleep_duration,
    ))
}
