use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use keidai::{ControlMessage, Route, RouteConfig, parse_certificate, recv_control, send_control};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::sign::CertifiedKey;
use tokio::{fs, time::Instant};
use tracing::error;

pub async fn refresh_certificates(
    send_stream: &mut quinn::SendStream,
    recv_stream: &mut quinn::RecvStream,
    routes: &HashMap<Route, RouteConfig>,
    failure_tracker: &mut HashMap<String, (u8, Instant)>,
    cert_dir: &Path,
) -> anyhow::Result<(HashMap<String, Arc<CertifiedKey>>, Duration)> {
    let mut valid_certificates = HashMap::new();
    let mut sleep_duration = Duration::from_hours(60 * 24);
    let mut encountered_error = false;
    for (route, route_config) in routes {
        let domain = route.to_string();
        let (cert_path, key_path, is_custom) =
            match (&route_config.tls_cert_path, &route_config.tls_key_path) {
                (Some(c), Some(k)) => (PathBuf::from(c), PathBuf::from(k), true),
                _ => (
                    cert_dir.join(format!("{domain}.crt")),
                    cert_dir.join(format!("{domain}.key")),
                    false,
                ),
            };

        if let Some((cert, not_after)) = async {
            let cert_bytes = fs::read(&cert_path).await.ok()?;
            let key_bytes = fs::read(&key_path).await.ok()?;
            let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_bytes).ok()?;
            let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
            let not_after = cert.tbs_certificate.validity.not_after.timestamp() as u64;
            let key = parse_certificate(key_bytes, cert_bytes).ok()?;
            Some((key, not_after))
        }
        .await
        {
            let thirty_days = Duration::from_hours(24 * 30).as_secs();
            if not_after > SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + thirty_days {
                sleep_duration = sleep_duration.min(Duration::from_secs(
                    not_after
                        - (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + thirty_days),
                ));
                valid_certificates.insert(domain, cert);
                continue;
            }
        }
        if is_custom {
            error!(
                "Custom certificate for '{domain}' at {:?} is missing or expired",
                cert_path
            );
            continue;
        }
        if let Some(&(retries, timestamp)) = failure_tracker.get(&domain) {
            if retries >= 4 && timestamp.elapsed() < Duration::from_hours(24) {
                error!("Skipping CSR for {domain} for 24hrs to avoid rate limits");
                encountered_error = true;
                continue;
            }
        }
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let params = CertificateParams::new(vec![domain.clone()])?;
        let csr_der = params.serialize_request(&key_pair)?.der().to_vec();
        let private_key_pem = key_pair.serialize_pem();
        send_control(
            send_stream,
            &keidai::ControlMessage::CertRequest {
                domain: domain.clone(),
                csr: csr_der,
            },
        )
        .await?;
        match recv_control(recv_stream).await? {
            ControlMessage::CertResponse { domain, cert_chain } => {
                if let Some(parent) = cert_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                fs::write(&key_path, &private_key_pem).await?;
                fs::write(&cert_path, &cert_chain).await?;
                let cert =
                    parse_certificate(private_key_pem.into_bytes(), cert_chain.into_bytes())?;
                valid_certificates.insert(domain.clone(), cert);
                failure_tracker.remove(&domain);
            }
            ControlMessage::CertError { domain, error } => {
                error!("Gateway failed to sign certificate for '{domain}': {error}");
                let entry = failure_tracker.entry(domain).or_insert((0, Instant::now()));
                entry.0 += 1;
                entry.1 = Instant::now();
                encountered_error = true;
            }
            _ => anyhow::bail!("Unexpected response during cert exchange"),
        }
    }
    if encountered_error {
        sleep_duration = Duration::from_mins(30);
    }
    Ok((valid_certificates, sleep_duration))
}
