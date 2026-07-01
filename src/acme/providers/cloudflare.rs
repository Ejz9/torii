use crate::{acme::providers::DnsProvider, error::Error};

#[derive(Debug)]
pub struct CloudflareProvider {
    pub zone_id: String,
    pub api_token: String,
}

#[derive(Debug, serde::Serialize)]
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

#[derive(Debug, serde::Deserialize)]
pub struct CloudflareResponse {
    result: CloudflareRecordResponse,
}

#[derive(Debug, serde::Deserialize)]
pub struct CloudflareRecordResponse {
    id: String,
}

impl DnsProvider for CloudflareProvider {
    async fn create_txt_record(&self, domain: &str, token: &str) -> Result<String, Error> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );
        let record = CloudflareRecord {
            name: domain.to_string(),
            ttl: 120,
            r#type: "TXT".to_string(),
            comment: "Torii Automated Certs".to_string(),
            content: format!("\"{token}\""),
            private_routing: false,
            proxied: false,
        };
        let response = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&record)
            .send()
            .await?
            .error_for_status()?;
        let response: CloudflareResponse = response.json().await?;
        Ok(response.result.id)
    }
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), Error> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.zone_id, record_id
        );
        let _ = reqwest::Client::new()
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
