use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{PrivateKeyDer, ServerName, UnixTime};
use rustls::{pki_types::CertificateDer, sign::CertifiedKey};
use std::collections::HashMap;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use tokio::{fs, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::acme::providers::ProviderKind;
use crate::{error::Error, state::AppState};

pub async fn acme_worker(
    state: Arc<AppState>,
    acme_provider: ProviderKind,
    mut rx: tokio::sync::mpsc::Receiver<(
        HashSet<String>,
        HashSet<String>,
        HashMap<String, Arc<CertifiedKey>>,
    )>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let mut current_individual_certs = HashSet::new();
    let mut current_wildcard_certs = HashSet::new();
    let mut current_custom_certificates = HashSet::new();
    let mut sleep_duration = Duration::from_hours(60 * 24);
    let mut failure_tracker = HashMap::new();
    fs::create_dir_all(&state.config.cert_path).await?;
    loop {
        tokio::select! {
            biased;
            _ = cancel_token.cancelled() => {
                info!("ACME recieved shutdown signal. Halting refresh.");
                break;
            }
            Some((new_individual_certs, new_wildcard_certs, custom_certs)) = rx.recv() => {
                current_individual_certs = new_individual_certs;
                current_wildcard_certs = new_wildcard_certs;

                current_custom_certificates = custom_certs.keys().cloned().collect();

                let mut active_map = (**state.certificates.load()).clone();
                active_map.extend(custom_certs);
                state.certificates.store(Arc::new(active_map));

                sleep_duration = refresh_certificates(&state, &acme_provider, current_individual_certs.clone(), current_wildcard_certs.clone(), &current_custom_certificates, &mut failure_tracker).await;
            }
            _ = sleep(sleep_duration) => { sleep_duration = refresh_certificates(&state, &acme_provider, current_individual_certs.clone(), current_wildcard_certs.clone(), &current_custom_certificates, &mut failure_tracker).await; }
        }
    }
    Ok(())
}

async fn refresh_certificates(
    state: &AppState,
    acme_provider: &ProviderKind,
    individual_certs: HashSet<String>,
    wildcard_certs: HashSet<String>,
    custom_certs: &HashSet<String>,
    failure_tracker: &mut HashMap<String, (u8, Instant)>,
) -> Duration {
    let mut valid_certificates: HashMap<String, Arc<CertifiedKey>> =
        (**state.certificates.load()).clone();
    let (sleep_duration, needs_refresh) = validate_certificate_files(
        state,
        &individual_certs,
        &wildcard_certs,
        &mut valid_certificates,
        &custom_certs,
    )
    .await;

    let account = match get_or_create_account(&state).await {
        Ok(account) => account,
        Err(e) => {
            error!("Failed to get or create account: {e}");
            if !valid_certificates.is_empty() {
                state.certificates.store(Arc::new(valid_certificates));
            }
            return Duration::from_mins(5);
        }
    };

    let mut encountered_error = false;
    for domain in needs_refresh {
        if let Some(&(retries, timestamp)) = failure_tracker.get(&domain) {
            if retries >= 4 && timestamp.elapsed() < Duration::from_hours(24) {
                error!("Skipping {domain} for 24hrs to avoid rate limits");
                encountered_error = true;
                continue;
            }
        }
        let certificate = match process_domain(
            &state,
            acme_provider,
            domain.to_string(),
            &wildcard_certs,
            &account,
        )
        .await
        {
            Ok(cert) => {
                failure_tracker.remove(&domain);
                cert
            }
            Err(e) => {
                error!("Failed to process domain {domain}: {e}");
                let entry = failure_tracker
                    .entry(domain.clone())
                    .or_insert((0, Instant::now()));
                entry.0 += 1;
                entry.1 = Instant::now();
                encountered_error = true;
                continue;
            }
        };

        let key = if wildcard_certs.contains(&domain) {
            format!("*.{domain}")
        } else {
            domain
        };

        valid_certificates.insert(key, certificate);
    }

    if !valid_certificates.is_empty() {
        state.certificates.store(Arc::new(valid_certificates));
    }
    if encountered_error {
        return Duration::from_mins(30);
    }
    info!(
        "Certifiates refreshed! ACME worker sleeping for: {} days",
        sleep_duration.as_secs() / 86400
    );
    sleep_duration
}

async fn validate_certificate_files(
    state: &AppState,
    individual_certs: &HashSet<String>,
    wildcard_certs: &HashSet<String>,
    valid_certificates: &mut HashMap<String, Arc<CertifiedKey>>,
    custom_certs: &HashSet<String>,
) -> (Duration, Vec<String>) {
    let mut needs_refresh: Vec<String> = Vec::new();
    let mut sleep_duration = Duration::from_hours(60 * 24);
    let base_path = Path::new(&state.config.cert_path);
    let individual_path = base_path.join("individual");
    let wildcard_path = base_path.join("wildcard");
    if let Err(e) = cleanup(
        &individual_path,
        &individual_certs,
        valid_certificates,
        custom_certs,
    )
    .await
    {
        error!("Failed to clean individual certs: {}", e)
    }
    if let Err(e) = cleanup(
        &wildcard_path,
        &wildcard_certs,
        valid_certificates,
        custom_certs,
    )
    .await
    {
        error!("Failed to clean wildcard certs: {}", e)
    }
    if let Err(e) = create_missing(
        &state,
        &individual_path,
        individual_certs,
        valid_certificates,
        &mut needs_refresh,
        &mut sleep_duration,
        wildcard_certs,
    )
    .await
    {
        error!("Failed to create missing individual certs: {}", e)
    }
    if let Err(e) = create_missing(
        &state,
        &wildcard_path,
        wildcard_certs,
        valid_certificates,
        &mut needs_refresh,
        &mut sleep_duration,
        wildcard_certs,
    )
    .await
    {
        error!("Failed to create missing wildcard certs: {}", e)
    }
    (sleep_duration, needs_refresh)
}

async fn cleanup(
    dir: &PathBuf,
    certs: &HashSet<String>,
    valid_certs: &mut HashMap<String, Arc<CertifiedKey>>,
    custom_domains: &HashSet<String>,
) -> Result<(), Error> {
    if !fs::try_exists(dir).await? {
        return Ok(());
    }
    let mut entries = fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let entry = entry;
        let domain = entry.file_name().into_string().unwrap_or_default();
        if !certs.contains(&domain) {
            fs::remove_dir_all(entry.path()).await?;
        }
        if valid_certs.contains_key(&domain) && !custom_domains.contains(&domain) {
            valid_certs.remove_entry(&domain);
        }
    }
    Ok(())
}

async fn create_missing(
    state: &AppState,
    dir: &PathBuf,
    certs: &HashSet<String>,
    valid_certs: &mut HashMap<String, Arc<CertifiedKey>>,
    needs_refresh: &mut Vec<String>,
    sleep_duration: &mut Duration,
    wildcard_certs: &HashSet<String>,
) -> Result<(), Error> {
    for domain in certs {
        let path = dir.join(domain);
        let cert_path = path.join("fullchain.pem");
        let key_path = path.join("privkey.pem");
        if let Err(e) = fs::create_dir_all(&path).await {
            return Err(Error::Io(e));
        }
        let Ok(cert_bytes) = fs::read(&cert_path).await else {
            error!("Failed to read cert file for domain: {domain}");
            needs_refresh.push(domain.clone());
            continue;
        };
        let Ok(key_bytes) = fs::read(key_path).await else {
            needs_refresh.push(domain.clone());
            error!("Failed to read key file for domain: {domain}");
            continue;
        };
        let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&cert_bytes) else {
            error!("Failed to parse pem file for domain: {domain}");
            needs_refresh.push(domain.clone());
            continue;
        };
        let Ok((_, cert)) = x509_parser::parse_x509_certificate(&pem.contents) else {
            error!("Failed to parse cert from pem file for domain: {domain}");
            needs_refresh.push(domain.clone());
            continue;
        };
        let not_after = cert.tbs_certificate.validity.not_after.timestamp() as u64;
        if not_after < SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            || not_after
                < SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                    + Duration::from_hours(24 * 30).as_secs()
        {
            needs_refresh.push(domain.clone());
            continue;
        }
        if not_after - SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            < sleep_duration.as_secs()
        {
            *sleep_duration = Duration::from_secs(
                not_after - SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            );
        }
        if let Err(e) = verify_certificate_signature(&state.cert_verifier, domain, &cert_bytes) {
            error!("Failed to verify certificate signature for domain: {domain}: {e}",);
            needs_refresh.push(domain.clone());
            continue;
        }
        let Ok(certificate) = parse_certificate(key_bytes, cert_bytes) else {
            error!("Failed to parse certificate for domain: {domain}");
            continue;
        };
        let key = if wildcard_certs.contains(domain) {
            format!("*.{}", domain)
        } else {
            domain.to_string()
        };
        valid_certs.insert(key, certificate);
    }
    Ok(())
}

async fn get_or_create_account(state: &AppState) -> Result<Account, Error> {
    let account_file = Path::new(&state.config.cert_path).join("acme_account.json");

    let account = match fs::try_exists(&account_file).await.unwrap_or(false) {
        true => {
            let json = fs::read_to_string(account_file).await?;
            let credentials = serde_json::from_str(&json)?;
            let builder = Account::builder()?;
            let account = builder.from_credentials(credentials).await?;
            account
        }
        false => {
            let mut contact_list = Vec::new();
            if let Some(email) = &state.config.acme_email {
                contact_list.push(format!("mailto:{}", email));
            }
            let contact_refs: Vec<&str> = contact_list.iter().map(|s| s.as_str()).collect();
            let builder = Account::builder()?;
            let (account, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    state.config.acme_directory_url.clone(), // staging if testing
                    None,
                )
                .await?;

            let json = serde_json::to_string(&credentials)?;
            fs::write(account_file, json).await?;
            account
        }
    };
    Ok(account)
}

async fn process_domain(
    state: &AppState,
    acme_provider: &ProviderKind,
    domain: String,
    wildcard_certs: &HashSet<String>,
    account: &Account,
) -> Result<Arc<CertifiedKey>, Error> {
    let (save_path, identifiers) = if wildcard_certs.contains(&domain) {
        (
            PathBuf::new()
                .join(&state.config.cert_path)
                .join("wildcard")
                .join(&domain),
            vec![
                Identifier::Dns(domain.to_string()),
                Identifier::Dns(format!("*.{}", domain.to_string())),
            ],
        )
    } else {
        (
            PathBuf::new()
                .join(&state.config.cert_path)
                .join("individual")
                .join(&domain),
            vec![Identifier::Dns(domain.to_string())],
        )
    };

    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let mut authorizations = order.authorizations();
    let mut cleanup_records = Vec::new();
    while let Some(Ok(mut authz)) = authorizations.next().await {
        if authz.status == AuthorizationStatus::Valid {
            continue;
        }
        let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) else {
            error!("No DNS-01 challenge found for: {}", domain);
            continue;
        };
        let challenge_domain = challenge.identifier().to_string();
        let clean_domain = challenge_domain.trim_start_matches("*.");
        let txt_record_name = format!("_acme-challenge.{}", clean_domain);
        let challenge_token = challenge.key_authorization();
        let txt_value = challenge_token.dns_value();

        let record_id = acme_provider
            .create_txt_record(&txt_record_name, &txt_value)
            .await?;
        cleanup_records.push((txt_record_name, record_id));
        sleep(Duration::from_secs(30)).await;
        challenge.set_ready().await?;
    }
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    for (_, record_id) in cleanup_records {
        if let Err(e) = acme_provider.delete_txt_record(&record_id).await {
            error!("Failed to delete TXT record: {}", e);
        }
    }
    if status != OrderStatus::Ready {
        return Err(Error::AcmeOrderFailed { domain, status });
    }
    let private_key_pem = order.finalize().await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    fs::create_dir_all(&save_path).await?;
    fs::write(save_path.join("privkey.pem"), &private_key_pem).await?;
    fs::write(save_path.join("fullchain.pem"), &cert_chain_pem).await?;
    let certificate = parse_certificate(private_key_pem.into_bytes(), cert_chain_pem.into_bytes())?;
    Ok(certificate)
}

pub fn parse_certificate(
    private_key_bytes: Vec<u8>,
    cert_chain_bytes: Vec<u8>,
) -> Result<Arc<CertifiedKey>, Error> {
    let key = PrivateKeyDer::from_pem_slice(&private_key_bytes)?;
    let chain: Vec<CertificateDer> =
        CertificateDer::pem_slice_iter(&cert_chain_bytes).collect::<Result<Vec<_>, _>>()?;
    let signing_key = crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
}

pub fn verify_certificate_signature(
    verifier: &WebPkiServerVerifier,
    domain: &str,
    cert_bytes: &[u8],
) -> Result<(), Error> {
    let server_name = ServerName::try_from(domain)?;
    let chain: Vec<CertificateDer> =
        CertificateDer::pem_slice_iter(&cert_bytes).collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        error!("No certificates found for domain: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "No certificates found for domain: {}",
            domain
        )));
    }
    verifier.verify_server_cert(&chain[0], &chain[1..], &server_name, &[], UnixTime::now())?;
    Ok(())
}
