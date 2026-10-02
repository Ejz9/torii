use arc_swap::ArcSwap;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use keidai::ConnectionEvent;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tracing::{debug, error};

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
    let handshake_limiter = Arc::new(tokio::sync::Semaphore::new(64));
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

        tokio::task::spawn(async move {
            let stream =
                match tokio::time::timeout(Duration::from_secs(5), tls_acceptor.accept(tcp_stream))
                    .await
                {
                    Ok(Ok(stream)) => {
                        drop(permit);
                        stream
                    }
                    _ => {
                        drop(permit);
                        let _ =
                            tx.try_send(ConnectionEvent::new(0, 400, "", remote_addr.ip(), "TLS"));
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
