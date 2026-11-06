use std::{borrow::Borrow, collections::HashMap, fmt::Display, str::FromStr};

use anyhow::bail;
use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{BiscuitPublicKey, Route, RouteConfig};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfig {
    #[serde(default)]
    pub routes: HashMap<Route, RouteConfig>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShinshiConfig {
    pub routes: HashMap<Route, RouteConfig>,
    pub forbidden_paths: Vec<String>,
    pub root_public_key: Option<BiscuitPublicKey>,
}

impl ShinshiConfig {
    pub fn new(config: SidecarConfig, root_public_key: Option<BiscuitPublicKey>) -> Self {
        Self {
            routes: config.routes,
            forbidden_paths: config.forbidden_paths,
            root_public_key,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Eq, PartialEq, Hash, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Clone)]
pub struct SidecarInit {
    pub id: ShinshiName,
    pub token: Vec<u8>,
    pub fingerprint: [u8; 32],
    pub server: TunnelEndpoint,
}

impl SidecarInit {
    pub fn to_token(&self) -> anyhow::Result<String> {
        let bytes = postcard::to_allocvec(self)?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn from_token(s: &str) -> anyhow::Result<Self> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(s)?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

impl FromStr for SidecarInit {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_token(s)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shinshi_name_validation() {
        assert!("auth_service".parse::<ShinshiName>().is_ok());
        assert!("backend-1".parse::<ShinshiName>().is_ok());
        assert!("edge01".parse::<ShinshiName>().is_ok());
        assert!("a".parse::<ShinshiName>().is_ok());
        assert!("".parse::<ShinshiName>().is_err());
        assert!("-bad".parse::<ShinshiName>().is_err());
        assert!("bad name!".parse::<ShinshiName>().is_err());
    }
}
