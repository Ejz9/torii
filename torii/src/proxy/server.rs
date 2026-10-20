use arc_swap::ArcSwap;
use axum::{Router, http, response::IntoResponse};
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use keidai::{ConnectionEvent, ShinshiName};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::{debug, error};

use crate::{cli::config::ActiveState, proxy::sni::extract_sni};

#[derive(Debug)]
pub struct CertificateResolver {
    certificates: Arc<ArcSwap<HashMap<String, Arc<CertifiedKey>>>>,
}

impl CertificateResolver {
    pub fn new(certificates: Arc<ArcSwap<HashMap<String, Arc<CertifiedKey>>>>) -> Self {
        Self { certificates }
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let domain = client_hello.server_name()?;
        let certificates = self.certificates.load();
        if let Some(cert) = certificates.get(domain) {
            return Some(cert.clone());
        }
        if let Some((_, root)) = domain.split_once('.') {
            for (key, cert) in certificates.iter() {
                if let Some(suffix) = key.strip_prefix("*.") {
                    if suffix == root {
                        return Some(cert.clone());
                    }
                }
            }
        }
        None
    }
}

// TCP HTTP connection server based on RFC 9112 and RFC 9113
pub async fn serve(
    listener: TcpListener,
    routes: Router,
    acceptor: TlsAcceptor,
    event_tx: flume::Sender<ConnectionEvent>,
    cancel_token: CancellationToken,
    handshake_limit: usize,
    dynamic_config: Arc<ArcSwap<ActiveState>>,
    sidecars: Arc<ArcSwap<HashMap<ShinshiName, quinn::Connection>>>,
) -> anyhow::Result<()> {
    let handshake_limiter = Arc::new(tokio::sync::Semaphore::new(handshake_limit));
    loop {
        let permit = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            res = handshake_limiter.clone().acquire_owned() => {
                let Ok(p) = res else { break };
                p
            }
        };
        let (tcp_stream, remote_addr) = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            res = listener.accept() => {
                match res {
                    Ok(conn) => conn,
                    Err(_) => {
                        drop(permit);
                        continue;
                    }
                }
            }
        };
        let _ = tcp_stream.set_nodelay(true);
        let tls_acceptor = acceptor.clone();
        let app = routes.clone();
        let tx = event_tx.clone();
        let config = Arc::clone(&dynamic_config);
        let tunnels = Arc::clone(&sidecars);

        tokio::spawn(async move {
            let mut peek_buf = [0u8; 1024];
            let ch_bytes =
                match tokio::time::timeout(Duration::from_secs(5), tcp_stream.peek(&mut peek_buf))
                    .await
                {
                    Ok(Ok(ch_bytes)) => ch_bytes,
                    _ => {
                        drop(permit);
                        let _ = tx.try_send(ConnectionEvent::new(
                            5000,
                            408,
                            "",
                            remote_addr.ip(),
                            "TCP",
                        ));
                        return;
                    }
                };
            if let Some(domain) = extract_sni(&peek_buf[..ch_bytes]) {
                let active = config.load();
                if let Some(sidecar_id) = active.sidecar_routes.get(domain) {
                    drop(permit);
                    let sidecar_conn = tunnels.load().get(sidecar_id).cloned();
                    if let Some(conn) = sidecar_conn {
                        let Ok(Ok((mut quic_send, mut quic_recv))) =
                            tokio::time::timeout(Duration::from_secs(3), conn.open_bi()).await
                        else {
                            let _ = tx.try_send(ConnectionEvent::new(
                                0,
                                502,
                                "",
                                remote_addr.ip(),
                                "QUIC",
                            ));
                            return;
                        };
                        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
                        let _ = tokio::join!(
                            tokio::io::copy(&mut tcp_read, &mut quic_send),
                            tokio::io::copy(&mut quic_recv, &mut tcp_write)
                        );
                        return;
                    } else {
                        debug!("Sidecar '{sidecar_id}' for '{domain}' is offline");
                        let _ = tx.try_send(ConnectionEvent::new(
                            5000,
                            503,
                            "",
                            remote_addr.ip(),
                            "TCP",
                        ));
                        return;
                    }
                }
            }
            let stream =
                match tokio::time::timeout(Duration::from_secs(5), tls_acceptor.accept(tcp_stream))
                    .await
                {
                    Ok(Ok(stream)) => {
                        drop(permit);
                        stream
                    }
                    Ok(Err(_)) => {
                        drop(permit);
                        let _ =
                            tx.try_send(ConnectionEvent::new(0, 400, "", remote_addr.ip(), "TLS"));
                        return;
                    }
                    _ => {
                        drop(permit);
                        let _ = tx.try_send(ConnectionEvent::new(
                            5000,
                            408,
                            "",
                            remote_addr.ip(),
                            "TLS",
                        ));
                        return;
                    }
                };
            let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(move |mut req| {
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(remote_addr));
                app.clone().call(req)
            });

            if is_h2 {
                let mut h2 = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                h2.timer(TokioTimer::new())
                    .keep_alive_interval(Some(Duration::from_secs(65)))
                    .max_concurrent_streams(1000)
                    //.max_frame_size(Some(64 * 1024))
                    .adaptive_window(true)
                    .max_send_buf_size(16 * 1024);
                if let Err(e) = h2.serve_connection(io, service).await {
                    handle_connection_error(Box::new(e));
                }
            } else {
                let mut http1 = hyper::server::conn::http1::Builder::new();
                http1
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(5))
                    .keep_alive(true);
                if let Err(e) = http1.serve_connection(io, service).with_upgrades().await {
                    if e.is_timeout() {
                        let _ = tx.try_send(ConnectionEvent::new(
                            5000,
                            408,
                            "",
                            remote_addr.ip(),
                            "HTTP",
                        ));
                    }
                    handle_connection_error(Box::new(e));
                }
            }
        });
    }
    Ok(())
}

// UDP HTTP connection server based on RFC 9000 and RFC 9114
pub async fn serve_h3(
    endpoint: quinn::Endpoint,
    routes: Router,
    event_tx: flume::Sender<ConnectionEvent>,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    // a handshake_limiter may be useful (needs testing) but quic has built in protections (anti-amplification, retries)
    loop {
        let incoming = tokio::select! {
            biased;
            _ = cancellation_token.cancelled() => break,
            conn = endpoint.accept() => {
                match conn {
                    Some(incoming) => incoming,
                    None => break,
                }
            }
        };
        let app = routes.clone();
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            let remote_addr = connection.remote_address();
            let h3_quin_conn = h3_quinn::Connection::new(connection);
            let Ok(mut h3_conn) = h3::server::Connection::new(h3_quin_conn).await else {
                return;
            };
            while let Ok(Some(resolver)) = h3_conn.accept().await {
                let mut app = app.clone();
                tokio::spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let (mut parts, ()) = req.into_parts();
                    parts
                        .extensions
                        .insert(axum::extract::ConnectInfo(remote_addr));
                    let request = axum::http::Request::from_parts(parts, axum::body::Body::empty());
                    let response = match app.call(request).await {
                        Ok(res) => res,
                        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    };
                    let (parts, mut body) = response.into_parts();
                    if let Err(e) = stream
                        .send_response(http::Response::from_parts(parts, ()))
                        .await
                    {
                        handle_connection_error(Box::new(e));
                        return;
                    }
                    while let Some(Ok(frame)) = body.frame().await {
                        if let Some(chunk) = frame.data_ref() {
                            if let Err(e) = stream.send_data(chunk.clone()).await {
                                handle_connection_error(Box::new(e));
                                break;
                            }
                        }
                    }
                    if let Err(e) = stream.finish().await {
                        handle_connection_error(Box::new(e));
                    }
                });
            }
        });
    }
    Ok(())
}

fn handle_connection_error(e: Box<dyn std::error::Error + Send + Sync>) {
    let is_client_disconnect = if let Some(error) = e.downcast_ref::<hyper::Error>() {
        error.is_incomplete_message() || error.is_canceled()
    } else {
        false
    };
    let is_io_disconnect = e
        .source()
        .unwrap_or(e.as_ref())
        .downcast_ref::<std::io::Error>()
        .map(|io_error| {
            matches!(
                io_error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
            )
        })
        .unwrap_or(false);
    let is_h3_disconnect = if let Some(error) = e.downcast_ref::<h3::error::StreamError>() {
        matches!(error, h3::error::StreamError::RemoteTerminate { .. }) || error.is_h3_no_error()
    } else {
        false
    };
    if is_client_disconnect || is_io_disconnect || is_h3_disconnect {
        debug!("Client disconnected early: {}", e);
    } else {
        error!("Failed to serve connection: {}", e)
    }
}
