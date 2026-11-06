use std::{borrow::Borrow, fmt::Display, ops::Deref, str::FromStr, sync::Arc};

use anyhow::bail;
use serde::{Deserialize, Serialize};

/// Route validator based on RFC 1035, RFC 1123 and RFC 2181
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Hash, Debug)]
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

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Clone)]
pub struct ActiveRoute {
    pub upstream: http::Uri,
    pub upstream_limiter: Arc<tokio::sync::Semaphore>,
    pub upstream_scheme: Option<http::uri::Scheme>,
    pub upstream_authority: Option<http::uri::Authority>,
    pub upstream_host_header: http::HeaderValue,
    pub public_bypass: bool,
    pub tls_insecure_skip_verify: bool,
    pub allowed_asset_paths: Vec<CleanPath>,
    pub allowed_groups_datalog_policy: String,
}

impl TryFrom<RouteConfig> for ActiveRoute {
    type Error = anyhow::Error;
    fn try_from(config: RouteConfig) -> Result<Self, Self::Error> {
        let upstream: http::Uri = config.upstream.parse()?;
        let upstream_scheme = upstream.scheme().cloned();
        let upstream_authority = upstream.authority().cloned();
        let upstream_host_str = upstream
            .authority()
            .map(|a| a.as_str())
            .unwrap_or("localhost");
        let upstream_host_header = http::HeaderValue::from_str(upstream_host_str)?;
        let upstream_limiter = Arc::new(tokio::sync::Semaphore::new(
            config.max_concurrent_connections,
        ));
        let allowed_groups_datalog_policy = if config.allowed_groups.is_empty() {
            "allow if true;".to_string()
        } else {
            config
                .allowed_groups
                .iter()
                .map(|g| format!("allow if group(\"{g}\");"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        Ok(ActiveRoute {
            upstream,
            upstream_limiter,
            upstream_scheme,
            upstream_authority,
            upstream_host_header,
            public_bypass: config.public_bypass,
            tls_insecure_skip_verify: config.tls_insecure_skip_verify,
            allowed_asset_paths: config.allowed_asset_paths,
            allowed_groups_datalog_policy,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_validation() {
        assert!("example.com".parse::<Route>().is_ok());
        assert!("api.sub.example.com".parse::<Route>().is_ok());
        assert!("service-1.internal.net".parse::<Route>().is_ok());
        assert!("*.example.com".parse::<Route>().is_err());
        assert!("example.com/api".parse::<Route>().is_err());
        assert!("localhost".parse::<Route>().is_err());
        assert!("-bad.com".parse::<Route>().is_err());
        assert!("".parse::<Route>().is_err());
    }
}
