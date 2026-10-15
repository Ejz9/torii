use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv6Addr},
    ops::Deref,
    str::FromStr,
};

use anyhow::bail;
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
    CertRequest { domain: String, csr: Vec<u8> },
    CertResponse { domain: String, cert_chain: String },
    CertError { domain: String, error: String },
    Ready,
}

/// Route validator based on RFC 1035, RFC 1123 and RFC 2181
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct Route(String);

impl FromStr for Route {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('*') {
            bail!("Route must not contain '*'");
        }
        let s = s.trim_end_matches('/');
        if s.contains('/') {
            bail!("Route must not contain additional '/'");
        }
        if s.len() >= 253 {
            bail!("Route must not be longer than 253 characters")
        }
        if s.split('.').count() < 2 {
            bail!("Domain must contain at least two labels (e.g example.com)")
        }
        let labels = s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
        if !labels {
            bail!("Domain contains invalid labels")
        }
        Ok(Self(s.to_string()))
    }
}

impl Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Route {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for Route {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for Route {
    fn borrow(&self) -> &str {
        &self.0
    }
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
    pub allowed_asset_paths: Vec<CleanPath>,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<Route>,
}

fn default_max_connections() -> usize {
    256
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SidecarConfig {
    #[serde(default)]
    pub routes: HashMap<Route, RouteConfig>,
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(from = "String", into = "String")]
pub struct CleanPath(String);

impl From<String> for CleanPath {
    fn from(value: String) -> Self {
        if value.starts_with('/') {
            Self(value)
        } else {
            Self(format!("/{value}"))
        }
    }
}

impl From<CleanPath> for String {
    fn from(value: CleanPath) -> Self {
        value.0
    }
}

impl AsRef<str> for CleanPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(serde::Serialize, serde::Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct ShinshiName(String);

impl FromStr for ShinshiName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 64 {
            bail!("Sidecar name must be between 1 to 64 characters");
        }
        if !s.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            bail!("Sidecar name must start with an alphanumeric character");
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            bail!("Sidecar name must conly contain alphanumeric characters, '_', and '-'");
        }
        Ok(Self(s.to_string()))
    }
}

impl Display for ShinshiName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Borrow<str> for ShinshiName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl ShinshiName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
pub struct SidecarInit {
    pub id: ShinshiName,
    pub token: String,
    pub fingerprint: String,
    pub server: TunnelEndpoint,
}

impl SidecarInit {
    pub fn to_token(&self) -> anyhow::Result<String> {
        let bytes = postcard::to_allocvec(self)?;
        Ok(hex::encode(bytes))
    }

    pub fn from_token(s: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(s)?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TunnelEndpoint {
    pub host: String,
    pub port: u16,
}

impl FromStr for TunnelEndpoint {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host_str, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("Endpoint must be in format host:port"))?;
        let port = port_str.parse::<u16>()?;
        let host = host_str.trim_end_matches(['[', ']']).to_string();
        Ok(Self { host, port })
    }
}

impl Display for TunnelEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}
