use std::{path::Path, sync::Arc};

use crate::{error::Error, state::AppState};

pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(&self, domain: &str, token: &str) -> Result<(), Error>;
    async fn delete_txt_record(&self, domain: &str, token: &str) -> Result<(), Error>;
}

pub async fn start_acme_worker(state: Arc<AppState>) {
    let path = Path::new(&state.config.cert_path);
    if !path.exists() {
        std::fs::create_dir_all(&state.config.cert_path);
        loop {

        }
    }
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