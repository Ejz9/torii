use std::{
    collections::{HashMap, HashSet},
    fs,
    ops::Deref,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aho_corasick::AhoCorasick;
use axum::http;
use keidai::{CleanPath, Route, RouteConfig, ShinshiName, SidecarConfig};
use rustls::{client::WebPkiServerVerifier, sign::CertifiedKey};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    acme::dns::{parse_certificate, verify_certificate_signature},
    error::Error,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ToriiConfig {
    #[serde(default)]
    ddns_domain: Option<Route>,
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    routes: HashMap<Route, RouteConfig>,
    #[serde(default)]
    sidecars: HashMap<ShinshiName, SidecarConfig>,
}

impl Default for ToriiConfig {
    fn default() -> Self {
        Self {
            ddns_domain: None,
            security: SecurityConfig::default(),
            routes: HashMap::new(),
            sidecars: HashMap::new(),
        }
    }
}

pub struct ActiveState {
    pub ddns_domain: Option<Route>,
    pub security: SecurityConfig,
    pub routes: matchit::Router<Arc<ActiveRoute>>,
    pub sidecar_routes: HashMap<Route, ShinshiName>,
    pub sidecars: HashMap<ShinshiName, SidecarConfig>,
}

#[derive(Clone)]
pub struct RouteMatch {
    pub route: Arc<ActiveRoute>,
    pub catch_all: SmallPath,
}

impl ActiveState {
    pub fn build(
        mut config: ToriiConfig,
        verifier: &Arc<WebPkiServerVerifier>,
    ) -> Result<
        (
            Self,
            HashSet<String>,
            HashSet<String>,
            HashMap<String, Arc<CertifiedKey>>,
        ),
        Error,
    > {
        let path_bytes: Vec<&[u8]> = config
            .security
            .forbidden_paths
            .iter()
            .map(|s| s.as_bytes())
            .collect();
        if !config.security.forbidden_paths.is_empty() {
            let Ok(matcher) = AhoCorasick::new(path_bytes) else {
                error!("Failed to create path matcher");
                return Err(Error::InvalidCustomSetup(
                    "Invalid forbidden_paths pattern".to_string(),
                ));
            };
            config.security.path_matcher = Some(Arc::new(matcher));
        }
        let mut individual_certs = HashSet::new();
        let mut wildcard_certs = HashSet::new();
        let mut valid_certificates: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        let mut router = matchit::Router::new();
        let gateway_routes: HashSet<Route> = config.routes.keys().cloned().collect();
        for (route, value) in config.routes.into_iter() {
            let domain = route.parse::<DomainTier>()?;
            if value.tls_cert_path.is_none() && value.tls_key_path.is_none() {
                match domain {
                    DomainTier::Root | DomainTier::Nested => {
                        individual_certs.insert(route.to_string());
                    }
                    DomainTier::Subdomain => {
                        if value.individual_cert
                            || !config.security.default_certificate_mode_wildcard
                        {
                            individual_certs.insert(route.to_string());
                        } else {
                            if let Some((_, root)) = route.split_once(".") {
                                if !root.is_empty() {
                                    wildcard_certs.insert(root.to_string());
                                }
                            }
                        }
                    }
                }
            } else {
                let certificate =
                    match validate_and_parse_custom_certificates(&value, &route, verifier) {
                        Ok(certificate) => certificate,
                        Err(e) => {
                            error!("Failed to parse certificate for route: {}: {}", route, e);
                            continue;
                        }
                    };
                valid_certificates.insert(route.to_string(), certificate);
            }
            let aliases = value.aliases.clone();
            let individual_cert = value.individual_cert;
            let active_route = Arc::new(value.try_into()?);
            let exact_pattern = format!("/{route}");
            router.insert(exact_pattern, Arc::clone(&active_route))?;

            let catch_all_pattern = format!("/{route}/{{*catch_all}}");
            router.insert(catch_all_pattern, Arc::clone(&active_route))?;

            if !aliases.is_empty() {
                for alias in aliases {
                    if individual_cert || !config.security.default_certificate_mode_wildcard {
                        individual_certs.insert(alias.to_string());
                    } else {
                        if let Some((_, root)) = alias.split_once(".") {
                            if !root.is_empty() {
                                wildcard_certs.insert(root.to_string());
                            }
                        }
                    }
                    router.insert(format!("/{alias}"), Arc::clone(&active_route))?;
                    router.insert(
                        format!("/{alias}/{{*catch_all}}"),
                        Arc::clone(&active_route),
                    )?;
                }
            }
        }

        let mut sidecar_routes = HashMap::new();
        for (sidecar_id, sidecar_cfg) in &config.sidecars {
            for route in sidecar_cfg.routes.keys() {
                if gateway_routes.contains(route) {
                    return Err(Error::InvalidCustomSetup(format!(
                        "Route collision: '{route}' is configured as both a gateway and sidecar route"
                    )));
                }
                if let Some(existing_sidecar) =
                    sidecar_routes.insert(route.clone(), sidecar_id.clone())
                {
                    return Err(Error::InvalidCustomSetup(format!(
                        "Route collision: '{route}' is claimed by '{existing_sidecar}' and '{sidecar_id}'"
                    )));
                }
            }
        }

        Ok((
            ActiveState {
                ddns_domain: config.ddns_domain,
                security: config.security,
                routes: router,
                sidecar_routes,
                sidecars: config.sidecars,
            },
            individual_certs,
            wildcard_certs,
            valid_certificates,
        ))
    }

    pub fn find_route(&self, host: &str, mut path: &str) -> Option<RouteMatch> {
        if path == "/" {
            path = "";
        }
        let mut buf = [0u8; 512];
        buf[0] = b'/';
        let h_bytes = host.as_bytes();
        let p_bytes = path.as_bytes();
        let total_len = 1 + h_bytes.len() + p_bytes.len();
        if total_len > buf.len() {
            return None;
        }
        buf[1..1 + h_bytes.len()].copy_from_slice(h_bytes);
        buf[1 + h_bytes.len()..total_len].copy_from_slice(p_bytes);
        let route = std::str::from_utf8(&buf[..total_len]).ok()?;
        let matched_route = self.routes.at(route).ok()?;
        let catch_all = match matched_route.params.get("catch_all") {
            Some(ca) if ca.starts_with('/') => SmallPath::from_str(ca),
            Some(ca) => {
                let mut s = String::with_capacity(ca.len() + 1);
                s.push('/');
                s.push_str(ca);
                SmallPath::from_str(&s)
            }
            None => SmallPath::Static("/"),
        };
        Some(RouteMatch {
            route: matched_route.value.clone(),
            catch_all,
        })
    }
}

fn validate_and_parse_custom_certificates(
    config: &RouteConfig,
    domain: &str,
    verifier: &WebPkiServerVerifier,
) -> Result<Arc<CertifiedKey>, Error> {
    let Some(cert_path) = &config.tls_cert_path else {
        error!("No certificate path provided for route: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "No certificate path provided for route {}",
            domain
        )));
    };
    let Some(key_path) = &config.tls_key_path else {
        error!("No key path provided for route: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "No key path provided for route {}",
            domain
        )));
    };
    let cert_bytes = fs::read(cert_path)?;
    let key_bytes = fs::read(key_path)?;
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&cert_bytes) else {
        error!("Failed to parse pem file for domain: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "Failed to parse pem file for domain: {}",
            domain
        )));
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&pem.contents) else {
        error!("Failed to parse cert from pem file for domain: {}", domain);
        return Err(Error::InvalidCustomSetup(format!(
            "Failed to parse cert from pem file for domain: {}",
            domain
        )));
    };
    let not_after = cert.tbs_certificate.validity.not_after;
    if (not_after.timestamp() as u64) < SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
        || (not_after.timestamp() as u64)
            < SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                + Duration::from_hours(24 * 30).as_secs()
    {
        error!(
            "Certificate for {} is expired or expires in less than 30 days",
            domain
        );
        return Err(Error::InvalidCustomSetup(format!(
            "Certificate for {} is expired or expires in less than 30 days",
            domain
        )));
    }
    verify_certificate_signature(verifier, domain, &cert_bytes)?;
    Ok(parse_certificate(key_bytes, cert_bytes)?)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecurityConfig {
    #[serde(default = "default_certificate_mode_wildcard")]
    default_certificate_mode_wildcard: bool,
    #[serde(default = "forbidden_paths")]
    pub forbidden_paths: Vec<String>,
    #[serde(default = "ebpf_strike_threshold")]
    pub ebpf_strike_threshold: u64,
    #[serde(default = "ebpf_velocity_threshhold")]
    pub ebpf_velocity_threshhold: u64,
    #[serde(default = "ebpf_lockout_duration_secs")]
    pub ebpf_lockout_duration_secs: u64,
    #[serde(skip)]
    pub path_matcher: Option<Arc<AhoCorasick>>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_certificate_mode_wildcard: false,
            forbidden_paths: vec![],
            ebpf_strike_threshold: 10,
            ebpf_velocity_threshhold: 150,
            ebpf_lockout_duration_secs: 3600,
            path_matcher: None,
        }
    }
}

fn default_certificate_mode_wildcard() -> bool {
    false
}
fn forbidden_paths() -> Vec<String> {
    vec![]
}
fn ebpf_strike_threshold() -> u64 {
    10
}
fn ebpf_velocity_threshhold() -> u64 {
    150
}
fn ebpf_lockout_duration_secs() -> u64 {
    3600
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
    type Error = Error;
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

pub enum DomainTier {
    Root,
    Subdomain,
    Nested,
}

impl FromStr for DomainTier {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(".").count();
        match s.split(".").count() {
            0 | 1 => Err(Error::InvalidDomain),
            2 => Ok(DomainTier::Root),
            3 => Ok(DomainTier::Subdomain),
            _ => Ok(DomainTier::Nested),
        }
    }
}

#[derive(Clone)]
pub enum SmallPath {
    Static(&'static str),
    Inline { buf: [u8; 30], len: u8 },
    Heap(String),
}

impl SmallPath {
    #[inline]
    pub fn from_str(s: &str) -> Self {
        if s == "/" {
            return SmallPath::Static("/");
        }
        let bytes = s.as_bytes();
        if bytes.len() <= 30 {
            let mut buf = [0u8; 30];
            buf[..bytes.len()].copy_from_slice(bytes);
            SmallPath::Inline {
                buf,
                len: bytes.len() as u8,
            }
        } else {
            SmallPath::Heap(s.to_string())
        }
    }
}

impl Deref for SmallPath {
    type Target = str;
    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            SmallPath::Static(s) => s,
            SmallPath::Inline { buf, len } => {
                std::str::from_utf8(&buf[..*len as usize]).unwrap_or("")
            }
            SmallPath::Heap(s) => s.as_str(),
        }
    }
}

impl AsRef<str> for SmallPath {
    #[inline]
    fn as_ref(&self) -> &str {
        self.deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_minimal_config() {
        let toml_str = r#"
            [security]
            default_certificate_mode_wildcard = false
            ebpf_strike_threshold = 10
        "#;
        let res: Result<ToriiConfig, _> = toml::from_str(toml_str);
        assert!(res.is_ok(), "Expected valid TOML to parse successfully");
    }

    #[test]
    fn test_deny_unkown_fields_at_root() {
        let toml_str = r#"
            unknown_root_key = "should_fail"
        "#;
        let res: Result<ToriiConfig, _> = toml::from_str(toml_str);
        assert!(res.is_err(), "Expected unknown field to trigger an error");
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("unknown field `unknown_root_key`"));
    }

    #[test]
    fn test_sidecar_config_parsing() {
        let toml_str = r#"
            [sidecars.my_sidecar]
            forbidden_paths = ["admin", "private"]

            [sidecars.my_sidecar.routes."app.example.com"]
            upstream = "http://127.0.0.1:8080"
            public_bypass = true
        "#;
        let res: Result<ToriiConfig, _> = toml::from_str(toml_str);
        assert!(
            res.is_ok(),
            "Failed to parse valid sidecar config: {:?}",
            res.err()
        );
        let config = res.unwrap();
        let sidecar_name = "my_sidecar".parse::<ShinshiName>().unwrap();
        assert!(config.sidecars.contains_key(&sidecar_name));
        let sidecar = &config.sidecars[&sidecar_name];
        assert_eq!(sidecar.forbidden_paths, vec!["admin", "private"]);
    }
}
