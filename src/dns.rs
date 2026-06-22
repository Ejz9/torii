use std::sync::Arc;

use crate::{error::Error, state::AppState};

pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(&self, domain: &str, token: &str) -> Result<(), Error>;
    async fn delete_txt_record(&self, domain: &str, token: &str) -> Result<(), Error>;
}

pub async fn start_acme_worker(state: Arc<AppState>) {
    
}

pub struct CloudflareProvider {
    api_token: String
}

impl DnsProvider for CloudflareProvider {
    async fn create_txt_record(&self, domain: &str, token: &str) -> Result<(), Error> {
        todo!()
    }
    async fn delete_txt_record(&self, domain: &str, token: &str) -> Result<(), Error> {
        todo!()
    }
}