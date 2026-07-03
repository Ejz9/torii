use arc_swap::ArcSwap;
use axum::Router;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{collections::HashMap, error::Error, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
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
            let wildcard = format!("*.{}", root);
            if let Some(cert) = certificates.get(&wildcard) {
                return Some(cert.clone());
            }
        }
        None
    }
}

pub async fn serve(listner: TcpListener, routes: Router, acceptor: TlsAcceptor) {
    loop {
        let Ok((tcp_stream, remote_addr)) = listner.accept().await else {
            continue;
        };
        let tls_acceptor = acceptor.clone();
        let app = routes.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |mut req| {
                        req.extensions_mut()
                            .insert(axum::extract::ConnectInfo(remote_addr));
                        app.clone().call(req)
                    });

                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        let is_client_disconnect = e.is_incomplete_message() || e.is_canceled();
                        let is_io_disconnect = e
                            .source()
                            .and_then(|s| s.downcast_ref::<std::io::Error>())
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
                }
                Err(e) => error!("TLS Handshake failed: {}", e),
            }
        });
    }
}
