use std::{collections::HashMap, net::IpAddr, pin::Pin, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use keidai::ConnectionEvent;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
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
    conn: quinn::Connection,
    routes: Router,
    acceptor: TlsAcceptor,
    event_tx: flume::Sender<ConnectionEvent>,
    cancel_token: CancellationToken,
    handshake_limit: usize,
) -> anyhow::Result<()> {
    let handshake_limiter = Arc::new(tokio::sync::Semaphore::new(handshake_limit));
    let connection = conn.clone();
    loop {
        let permit = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            res = handshake_limiter.clone().acquire_owned() => {
                let Ok(p) = res else {break};
                p
            }
        };
        let (send_stream, mut recv_stream) = tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            res = connection.accept_bi() => {
                match res {
                    Ok(streams) => streams,
                    Err(_) => {
                        drop(permit);
                        break;
                    }
                }
            }
        };
        let tls_acceptor = acceptor.clone();
        let app = routes.clone();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let mut ip_bytes = [0u8; 16];
            if recv_stream.read_exact(&mut ip_bytes).await.is_err() {
                drop(permit);
                return;
            }
            let Ok(port) = recv_stream.read_u16().await else {
                drop(permit);
                return;
            };
            let v6 = std::net::Ipv6Addr::from(ip_bytes);
            let client_ip = v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6));
            let client_addr = std::net::SocketAddr::new(client_ip, port);
            let bistream = BiStream {
                send: send_stream,
                recv: recv_stream,
            };
            let stream =
                match tokio::time::timeout(Duration::from_secs(5), tls_acceptor.accept(bistream))
                    .await
                {
                    Ok(Ok(stream)) => {
                        drop(permit);
                        stream
                    }
                    Ok(Err(_)) => {
                        drop(permit);
                        let _ =
                            tx.try_send(ConnectionEvent::new(0, 400, "", client_addr.ip(), "TLS"));
                        return;
                    }
                    _ => {
                        drop(permit);
                        let _ = tx.try_send(ConnectionEvent::new(
                            5000,
                            408,
                            "",
                            client_addr.ip(),
                            "TLS",
                        ));
                        return;
                    }
                };
            let is_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |mut req| {
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(client_addr));
                app.clone().call(req)
            });
            if is_h2 {
                let mut h2 = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                h2.timer(TokioTimer::new())
                    .keep_alive_interval(Some(Duration::from_secs(65)))
                    .max_concurrent_streams(1000)
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
                            client_addr.ip(),
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

pub struct BiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl AsyncRead for BiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
