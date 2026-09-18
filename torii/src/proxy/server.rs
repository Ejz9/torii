use arc_swap::ArcSwap;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use keidai::ConnectionEvent;
use moka::sync::Cache;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc::Sender};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::{debug, error, info};

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

pub async fn serve(
    listener: TcpListener,
    routes: Router,
    acceptor: TlsAcceptor,
    event_tx: Sender<ConnectionEvent>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let handshake_limiter = Arc::new(tokio::sync::Semaphore::new(256));
    loop {
        let (tcp_stream, remote_addr) = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => {
                info!("Server recieved shutdown signal. Halting listener.");
                break;
            }
            res = listener.accept() => {
                let Ok(conn) = res else {
                    continue;
                };
                conn
            }
        };
        let _ = tcp_stream.set_nodelay(true);
        let tls_acceptor = acceptor.clone();
        let app = routes.clone();
        let limiter = Arc::clone(&handshake_limiter);
        let tx = event_tx.clone();

        tokio::spawn(async move {
            let Ok(permit) = limiter.acquire_owned().await else {
                return;
            };
            let stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => {
                    drop(permit);
                    stream
                }
                Err(e) => {
                    drop(permit);
                    debug!("TLS Handshake failed: {}", e);
                    let _ = tx.try_send(ConnectionEvent::new(0, 400, "", remote_addr.ip(), "TLS"));
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
                let mut h2 = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                h2.http2()
                    .timer(TokioTimer::new())
                    .keep_alive_interval(Some(Duration::from_secs(65)))
                    .max_concurrent_streams(1000);
                if let Err(e) = h2.serve_connection_with_upgrades(io, service).await {
                    handle_connection_error(e);
                }
            } else {
                let mut http1 = hyper::server::conn::http1::Builder::new();
                http1
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(5))
                    .pipeline_flush(true)
                    .keep_alive(true);
                if let Err(e) = http1.serve_connection(io, service).with_upgrades().await {
                    handle_connection_error(Box::new(e));
                }
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

    if is_client_disconnect || is_io_disconnect {
        debug!("Client disconnected early: {}", e);
    } else {
        error!("Failed to serve connection: {}", e)
    }
}
