use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use rustls::{
    crypto, pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject}, server::{ClientHello, ResolvesServerCert}, sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BiscuitPublicKey(pub [u8; 32]);

impl From<biscuit_auth::PublicKey> for BiscuitPublicKey {
    fn from(k: biscuit_auth::PublicKey) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&k.to_bytes());
        Self(bytes)
    }
}

impl TryFrom<BiscuitPublicKey> for biscuit_auth::PublicKey {
    type Error = anyhow::Error;

    fn try_from(k: BiscuitPublicKey) -> Result<Self, Self::Error> {
        Ok(biscuit_auth::PublicKey::from_bytes(
            &k.0,
            biscuit_auth::builder::Algorithm::Ed25519,
        )?)
    }
}

pub fn parse_certificate(
    private_key_bytes: Vec<u8>,
    cert_chain_bytes: Vec<u8>,
) -> anyhow::Result<Arc<CertifiedKey>> {
    let key = PrivateKeyDer::from_pem_slice(&private_key_bytes)?;
    let chain: Vec<CertificateDer> =
        CertificateDer::pem_slice_iter(&cert_chain_bytes).collect::<Result<Vec<_>, _>>()?;
    let signing_key = crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
}

#[derive(Debug)]
pub struct CertificateResolver {
    certificates: Arc<ArcSwap<HashMap<String, Arc<CertifiedKey>>>>,
}

impl CertificateResolver {
    pub fn new(certificates: Arc<ArcSwap<HashMap<String, Arc<CertifiedKey>>>>) -> Self {
        Self { certificates }
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let domain = client_hello.server_name()?;
        let certificates = self.certificates.load();
        if let Some(cert) = certificates.get(domain) {
            return Some(cert.clone());
        }
        if let Some((_, root)) = domain.split_once('.') {
            for (key, cert) in certificates.iter() {
                if let Some(suffix) = key.strip_prefix("*.")
                    && suffix == root
                {
                    return Some(cert.clone());
                }
            }
        }
        None
    }
}