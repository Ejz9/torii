use std::{cmp, sync::Arc, time::Duration};

use tokio::time::sleep;
use tracing::error;

use crate::state::AppState;

pub async fn start_ddns_worker(state: Arc<AppState>) {
    let mut last_known_ip: Option<std::net::IpAddr> = None;
    let mut cached_record_id: Option<String> = None;
    let mut failed_attempts = 0;
    loop {
        let ddns_domain = &state.dynamic_config.load().ddns_domain;
        let Some(domain) = ddns_domain else {
            error!("DDNS domain not set");
            sleep(Duration::from_mins(5)).await;
            continue;
        };
        let Ok(response) = reqwest::get("https://1.1.1.1/cdn-cgi/trace").await else {
            error!("Failed to fetch IP address from cloudflare");
            failed_attempts += 1;
            sleep(Duration::from_secs(cmp::min(failed_attempts * 30, 900))).await;
            continue;
        };
        let Ok(payload) = response.text().await else {
            error!("Failed to parse response from cloudflare");
            failed_attempts += 1;
            sleep(Duration::from_secs(cmp::min(failed_attempts * 30, 900))).await;
            continue;
        };
        let Some(response_ip) = payload
            .lines()
            .find(|line| line.starts_with("ip="))
            .and_then(|line| line.split("=").nth(1))
            .and_then(|ip_str| ip_str.parse::<std::net::IpAddr>().ok())
        else {
            error!("Failed to parse IP address from cloudflare response");
            failed_attempts += 1;
            sleep(Duration::from_secs(cmp::min(failed_attempts * 30, 900))).await;
            continue;
        };

        if Some(response_ip) != last_known_ip {
            match state
                .config
                .acme_provider
                .sync_ip(
                    domain,
                    &response_ip.to_string(),
                    cached_record_id.as_deref(),
                )
                .await
            {
                Ok(returned_id) => {
                    cached_record_id = Some(returned_id);
                    last_known_ip = Some(response_ip);
                    failed_attempts = 0;
                }
                Err(e) => {
                    error!("Failed to sync DDNS IP: {}", e);
                    failed_attempts += 1;
                    sleep(Duration::from_secs(cmp::min(failed_attempts * 30, 900))).await;
                    continue;
                }
            }
        }
        sleep(Duration::from_mins(5)).await;
    }
}
