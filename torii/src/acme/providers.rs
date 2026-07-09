use crate::{acme::providers::cloudflare::CloudflareProvider, error::Error};

pub mod cloudflare;

pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(
        &self,
        domain: &str,
        content: &str,
    ) -> Result<String, crate::error::Error>;
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), crate::error::Error>;
}

pub trait DdnsProvider: Send + Sync {
    async fn sync_ip(
        &self,
        domain: &str,
        ip: &str,
        cached_id: Option<&str>,
    ) -> Result<String, crate::error::Error>;
}

#[derive(Debug)]
pub enum ProviderKind {
    Cloudflare(CloudflareProvider),
}

impl ProviderKind {
    pub async fn create_txt_record(&self, domain: &str, content: &str) -> Result<String, Error> {
        match self {
            ProviderKind::Cloudflare(provider) => provider.create_txt_record(domain, content).await,
        }
    }
    pub async fn delete_txt_record(&self, token: &str) -> Result<(), Error> {
        match self {
            ProviderKind::Cloudflare(provider) => provider.delete_txt_record(token).await,
        }
    }
    pub async fn sync_ip(
        &self,
        domain: &str,
        ip: &str,
        cached_id: Option<&str>,
    ) -> Result<String, Error> {
        match self {
            ProviderKind::Cloudflare(provider) => provider.sync_ip(domain, ip, cached_id).await,
        }
    }
}
