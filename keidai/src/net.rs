use std::{sync::Arc, time::Duration};

use anyhow::Context;
use axum::body::Body;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use rustls::{
    ClientConfig,
    client::danger::{HandshakeSignatureValid, ServerCertVerified},
};

pub fn format_ipv4_ascii(ipv4: &std::net::Ipv4Addr, buf: &mut [u8; 15]) -> usize {
    let octets = ipv4.octets();
    let mut pos = 0;
    for (idx, &octet) in octets.iter().enumerate() {
        if idx > 0 {
            buf[pos] = b'.';
            pos += 1;
        }
        if octet >= 100 {
            buf[pos] = b'0' + (octet / 100);
            buf[pos + 1] = b'0' + ((octet / 10) % 10);
            buf[pos + 2] = b'0' + (octet % 10);
            pos += 3;
        } else if octet >= 10 {
            buf[pos] = b'0' + (octet / 10);
            buf[pos + 1] = b'0' + (octet % 10);
            pos += 2;
        } else {
            buf[pos] = b'0' + octet;
            pos += 1;
        }
    }
    pos
}

pub fn create_connection_pools(
    fingerprint: Option<[u8; 32]>,
) -> anyhow::Result<(
    Client<HttpsConnector<HttpConnector>, Body>,
    Client<HttpsConnector<HttpConnector>, Body>,
)> {
    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    http.set_keepalive(Some(Duration::from_secs(60)));
    let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .context("Failed to load native CA root certificates. Verify system CA certificates are installed.")?
            .https_or_http()
            .enable_http1()
            .wrap_connector(http.clone());
    let tls_no_verify = NoCertificateVerification { fingerprint };
    let insecure_tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(tls_no_verify))
        .with_no_client_auth();
    let insecure_connector = HttpsConnectorBuilder::new()
        .with_tls_config(insecure_tls_config)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    let connection_pool = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(60))
        .pool_max_idle_per_host(usize::MAX)
        .build(connector);
    let insecure_connection_pool = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(60))
        .pool_max_idle_per_host(usize::MAX)
        .build(insecure_connector);
    Ok((connection_pool, insecure_connection_pool))
}

#[derive(Debug)]
pub struct NoCertificateVerification {
    pub fingerprint: Option<[u8; 32]>,
}

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(fingerprint) = self.fingerprint {
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
            if digest.as_ref() == fingerprint {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        } else {
            Ok(ServerCertVerified::assertion())
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.fingerprint.is_some() {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        } else {
            Ok(HandshakeSignatureValid::assertion())
        }
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.fingerprint.is_some() {
            rustls::crypto::verify_tls13_signature(
                msg,
                cert,
                dss,
                &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        } else {
            Ok(HandshakeSignatureValid::assertion())
        }
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
