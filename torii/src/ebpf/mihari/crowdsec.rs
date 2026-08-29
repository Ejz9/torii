use serde::Deserialize;

use crate::{
    ebpf::{
        kekkai_manager::{Ipv4Prefix, Ipv6Prefix},
        mihari::MihariProvider,
    },
    error::Error,
};

#[derive(Clone, Debug)]
pub struct CrowdSecProvider {
    pub api_url: String,
    pub api_key: String,
}

#[derive(Deserialize)]
struct CrowdsecEntry {
    value: String,
}

impl MihariProvider for CrowdSecProvider {
    async fn fetch_lists(&self) -> Result<(Vec<Ipv4Prefix>, Vec<Ipv6Prefix>), Error> {
        let response = reqwest::Client::new()
            .get(&self.api_url)
            .header("X-API-KEY", &self.api_key)
            .send()
            .await?
            .error_for_status()?;
        let body = response.text().await?;
        let mut v4_entries = Vec::new();
        let mut v6_entries = Vec::new();

        if let Ok(entries) = serde_json::from_str::<Vec<CrowdsecEntry>>(&body) {
            for entry in entries {
                if let Ok(addr) = entry.value.parse::<Ipv4Prefix>() {
                    v4_entries.push(addr);
                }
                if let Ok(addr) = entry.value.parse::<Ipv6Prefix>() {
                    v6_entries.push(addr);
                }
            }
        } else {
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(addr) = line.parse::<Ipv4Prefix>() {
                    v4_entries.push(addr);
                }
                if let Ok(addr) = line.parse::<Ipv6Prefix>() {
                    v6_entries.push(addr);
                }
            }
        }
        Ok((v4_entries, v6_entries))
    }
}
