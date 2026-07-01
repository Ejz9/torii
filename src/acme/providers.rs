pub mod cloudflare;

pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(
        &self,
        domain: &str,
        token: &str,
    ) -> Result<String, crate::error::Error>;
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), crate::error::Error>;
}
