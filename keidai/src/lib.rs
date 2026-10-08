use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct ConnectionEvent {
    pub latency_ms: u32,
    pub status_code: u16,
    pub path_len: u16,
    pub ip: [u8; 16],
    pub method: [u8; 8],
    pub method_len: u8,
    pub path: [u8; 255],
}

impl ConnectionEvent {
    pub fn path_str(&self) -> &str {
        std::str::from_utf8(&self.path[..self.path_len as usize]).unwrap_or("<invalid-utf8>")
    }

    pub fn method_str(&self) -> &str {
        std::str::from_utf8(&self.method[..self.method_len as usize]).unwrap_or("")
    }

    pub fn ip_addr(&self) -> IpAddr {
        let v6 = Ipv6Addr::from(self.ip);
        if let Some(v4) = v6.to_ipv4_mapped() {
            IpAddr::V4(v4)
        } else {
            IpAddr::V6(v6)
        }
    }

    pub fn new(
        latency_ms: u32,
        status_code: u16,
        path: &str,
        ip: std::net::IpAddr,
        method: &str,
    ) -> Self {
        let ip_bytes = match ip {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(v6) => v6.octets(),
        };
        let mut method_bytes = [0u8; 8];
        let method_len = method.len().min(8);
        method_bytes[..method_len].copy_from_slice(&method.as_bytes()[..method_len]);

        let mut path_bytes = [0u8; 255];
        let path_len = path.len().min(255);
        path_bytes[..path_len].copy_from_slice(&path.as_bytes()[..path_len]);
        ConnectionEvent {
            latency_ms,
            status_code,
            path_len: path_len as u16,
            ip: ip_bytes,
            method: method_bytes,
            method_len: method_len as u8,
            path: path_bytes,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ControlMessage {
    Auth { token: Vec<u8> },
    SyncConfig(SidecarConfig),
    RequestCert { domain: String, csr: Vec<u8> },
    CertResponse { domain: String, cert_chain: String },
    CertError { domain: String, reason: String },
    Ready,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RouteConfig {
    pub upstream: String,
    #[serde(default = "default_max_connections")]
    pub max_concurrent_connections: usize,
    #[serde(default)]
    pub public_bypass: bool,
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
    #[serde(default)]
    pub individual_cert: bool,
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    #[serde(default)]
    pub tls_key_path: Option<String>,
    #[serde(default)]
    pub allowed_asset_paths: Vec<String>,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
}

fn default_max_connections() -> usize {
    256
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SidecarConfig {
    #[serde(default)]
    pub routes: HashMap<String, RouteConfig>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
}

pub async fn send_control(
    stream: &mut quinn::SendStream,
    msg: &ControlMessage,
) -> anyhow::Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub async fn recv_control(stream: &mut quinn::RecvStream) -> anyhow::Result<ControlMessage> {
    let len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}
