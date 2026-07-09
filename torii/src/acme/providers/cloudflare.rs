use serde_json::json;

use crate::{
    acme::providers::{DdnsProvider, DnsProvider},
    error::Error,
};

#[derive(Debug)]
pub struct CloudflareProvider {
    pub zone_id: String,
    pub api_token: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareRecord {
    name: String,
    ttl: u32,
    r#type: String,
    comment: String,
    content: String,
    private_routing: bool,
    proxied: bool,
}

#[derive(serde::Deserialize)]
pub struct CloudflareResponse {
    result: CloudflareRecordResponse,
}

#[derive(serde::Deserialize)]
pub struct CloudflareRecordResponse {
    id: String,
}

#[derive(serde::Deserialize)]
pub struct CloudflareListResponse {
    result: Vec<CloudflareRecordResponse>,
}

impl DnsProvider for CloudflareProvider {
    async fn create_txt_record(&self, domain: &str, content: &str) -> Result<String, Error> {
        let url = format!("{}/dns_records", self.zone_url());
        let record = CloudflareRecord {
            name: domain.to_string(),
            ttl: 120,
            r#type: "TXT".to_string(),
            comment: "Torii Automated Certs".to_string(),
            content: format!("\"{content}\""),
            private_routing: false,
            proxied: false,
        };
        let response = reqwest::Client::new()
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&record)
            .send()
            .await?
            .error_for_status()?;
        let response: CloudflareResponse = response.json().await?;
        Ok(response.result.id)
    }
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), Error> {
        let _ = reqwest::Client::new()
            .delete(self.record_url(record_id))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

impl DdnsProvider for CloudflareProvider {
    async fn sync_ip(
        &self,
        domain: &str,
        ip: &str,
        cached_id: Option<&str>,
    ) -> Result<String, Error> {
        if let Some(record_id) = cached_id {
            self.update_a_record(&record_id, ip).await?;
            return Ok(record_id.to_string());
        };
        match self.fetch_a_record(domain).await? {
            Some(record_id) => {
                self.update_a_record(&record_id, ip).await?;
                Ok(record_id)
            }
            None => {
                let new_id = self.create_a_record(domain, ip).await?;
                Ok(new_id)
            }
        }
    }
}

impl CloudflareProvider {
    fn zone_url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/zones/{}",
            self.zone_id
        )
    }
    fn record_url(&self, record_id: &str) -> String {
        format!("{}/dns_records/{}", self.zone_url(), record_id)
    }
    async fn fetch_a_record(&self, domain: &str) -> Result<Option<String>, crate::error::Error> {
        let url = format!("{}/dns_records?type=A&name={}", self.zone_url(), domain);
        let response = reqwest::Client::new()
            .get(url)
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?;
        let response: CloudflareListResponse = response.json().await?;
        Ok(response.result.into_iter().next().map(|r| r.id))
    }
    async fn create_a_record(&self, domain: &str, ip: &str) -> Result<String, crate::error::Error> {
        let url = format!("{}/dns_records", self.zone_url());
        let record = CloudflareRecord {
            name: domain.to_string(),
            ttl: 120,
            r#type: "A".to_string(),
            comment: "Torii DDNS".to_string(),
            content: ip.to_string(),
            private_routing: false,
            proxied: false,
        };
        let response = reqwest::Client::new()
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&record)
            .send()
            .await?
            .error_for_status()?;
        let response: CloudflareResponse = response.json().await?;
        Ok(response.result.id)
    }
    async fn update_a_record(
        &self,
        record_id: &str,
        ip: &str,
    ) -> Result<String, crate::error::Error> {
        let contents = json!({ "content" : ip });
        let response = reqwest::Client::new()
            .patch(self.record_url(record_id))
            .bearer_auth(&self.api_token)
            .json(&contents)
            .send()
            .await?
            .error_for_status()?;
        let response: CloudflareResponse = response.json().await?;
        Ok(response.result.id)
    }
}
