//! Configuration types for the SPIFFE authentication agent.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// SPIFFE agent configuration received via on_configure().
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SpiffeAgentConfig {
    /// SPIRE Workload API configuration.
    #[serde(default)]
    pub spire: SpireConfig,

    /// TLS termination settings.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Identity output headers.
    #[serde(default)]
    pub headers: HeadersConfig,

    /// Allowlist configuration.
    #[serde(default)]
    pub allowlist: AllowlistConfig,

    /// Failure behavior configuration.
    #[serde(default)]
    pub failure: FailureConfig,

    /// Audit logging configuration.
    #[serde(default)]
    pub audit: AuditConfig,
}

/// SPIRE Workload API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SpireConfig {
    /// Socket path to SPIRE agent.
    #[serde(default = "default_spire_socket")]
    pub socket: PathBuf,

    /// Trust bundle refresh interval in seconds.
    #[serde(default = "default_bundle_refresh_interval")]
    pub bundle_refresh_interval: u64,

    /// SVID rotation margin - refresh this many seconds before expiry.
    #[serde(default = "default_svid_rotation_margin")]
    pub svid_rotation_margin: u64,

    /// Timeout for Workload API calls in milliseconds.
    #[serde(default = "default_api_timeout_ms")]
    pub api_timeout_ms: u64,
}

impl Default for SpireConfig {
    fn default() -> Self {
        Self {
            socket: default_spire_socket(),
            bundle_refresh_interval: default_bundle_refresh_interval(),
            svid_rotation_margin: default_svid_rotation_margin(),
            api_timeout_ms: default_api_timeout_ms(),
        }
    }
}

fn default_spire_socket() -> PathBuf {
    PathBuf::from("/run/spire/sockets/agent.sock")
}

fn default_bundle_refresh_interval() -> u64 {
    300 // 5 minutes
}

fn default_svid_rotation_margin() -> u64 {
    60 // 1 minute
}

fn default_api_timeout_ms() -> u64 {
    5000 // 5 seconds
}

/// TLS termination settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsConfig {
    /// Header containing client certificate (URL-encoded PEM or base64 DER).
    #[serde(default = "default_client_cert_header")]
    pub client_cert_header: String,

    /// Require mTLS for all requests.
    #[serde(default)]
    pub require_mtls: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            client_cert_header: default_client_cert_header(),
            require_mtls: false,
        }
    }
}

fn default_client_cert_header() -> String {
    "X-Forwarded-Client-Cert".to_string()
}

/// Identity output headers configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HeadersConfig {
    /// Header for SPIFFE ID.
    #[serde(default = "default_spiffe_id_header")]
    pub spiffe_id: String,

    /// Header for trust domain.
    #[serde(default = "default_trust_domain_header")]
    pub trust_domain: String,

    /// Header for workload ID (path portion of SPIFFE ID).
    #[serde(default = "default_workload_id_header")]
    pub workload_id: String,

    /// Header for authentication method.
    #[serde(default = "default_auth_method_header")]
    pub auth_method: String,

    /// Header for authentication timestamp.
    #[serde(default = "default_auth_timestamp_header")]
    pub auth_timestamp: String,
}

impl Default for HeadersConfig {
    fn default() -> Self {
        Self {
            spiffe_id: default_spiffe_id_header(),
            trust_domain: default_trust_domain_header(),
            workload_id: default_workload_id_header(),
            auth_method: default_auth_method_header(),
            auth_timestamp: default_auth_timestamp_header(),
        }
    }
}

fn default_spiffe_id_header() -> String {
    "X-SPIFFE-Id".to_string()
}

fn default_trust_domain_header() -> String {
    "X-SPIFFE-Trust-Domain".to_string()
}

fn default_workload_id_header() -> String {
    "X-SPIFFE-Workload-Id".to_string()
}

fn default_auth_method_header() -> String {
    "X-Auth-Method".to_string()
}

fn default_auth_timestamp_header() -> String {
    "X-Auth-Timestamp".to_string()
}

/// Allowlist configuration for SPIFFE IDs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct AllowlistConfig {
    /// Exact SPIFFE ID matches.
    #[serde(default)]
    pub exact: Vec<String>,

    /// Prefix matches (workloads under a path).
    #[serde(default)]
    pub prefix: Vec<String>,

    /// Trust domain restrictions.
    #[serde(default)]
    pub trust_domains: Vec<String>,

    /// Regex patterns for complex matching.
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl AllowlistConfig {
    /// Returns true if the allowlist is empty (allows all).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.prefix.is_empty()
            && self.trust_domains.is_empty()
            && self.patterns.is_empty()
    }
}

/// Failure behavior configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FailureConfig {
    /// What to do when SPIRE is unavailable.
    /// Options: "fail_closed", "fail_open", "cache"
    #[serde(default = "default_spire_unavailable")]
    pub spire_unavailable: FailureMode,

    /// Cache TTL in seconds when SPIRE is down (only used with "cache" mode).
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,

    /// What to do when certificate validation fails.
    #[serde(default = "default_validation_failure")]
    pub validation_failure: ValidationFailureAction,
}

impl Default for FailureConfig {
    fn default() -> Self {
        Self {
            spire_unavailable: default_spire_unavailable(),
            cache_ttl: default_cache_ttl(),
            validation_failure: default_validation_failure(),
        }
    }
}

fn default_spire_unavailable() -> FailureMode {
    FailureMode::FailClosed
}

fn default_cache_ttl() -> u64 {
    3600 // 1 hour
}

fn default_validation_failure() -> ValidationFailureAction {
    ValidationFailureAction::Reject
}

/// Failure mode when SPIRE is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    /// Reject requests if identity cannot be verified (security-first).
    #[default]
    FailClosed,
    /// Allow requests if SPIRE unavailable (availability-first).
    FailOpen,
    /// Use cached SVIDs when SPIRE is down.
    Cache,
}

/// Action to take when certificate validation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFailureAction {
    /// Reject the request with 401/403.
    #[default]
    Reject,
    /// Log and allow (for testing/migration).
    LogAndAllow,
}

/// Audit logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuditConfig {
    /// Log successful authentications.
    #[serde(default = "default_true")]
    pub log_success: bool,

    /// Log failed authentications.
    #[serde(default = "default_true")]
    pub log_failures: bool,

    /// Include SPIFFE ID in all logs.
    #[serde(default = "default_true")]
    pub include_spiffe_id: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_success: true,
            log_failures: true,
            include_spiffe_id: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SpiffeAgentConfig::default();
        assert_eq!(
            config.spire.socket,
            PathBuf::from("/run/spire/sockets/agent.sock")
        );
        assert_eq!(config.spire.bundle_refresh_interval, 300);
        assert_eq!(
            config.tls.client_cert_header,
            "X-Forwarded-Client-Cert"
        );
        assert!(!config.tls.require_mtls);
        assert_eq!(config.failure.spire_unavailable, FailureMode::FailClosed);
    }

    #[test]
    fn test_parse_config() {
        let json = r#"{
            "spire": {
                "socket": "/custom/path/agent.sock",
                "bundle-refresh-interval": 600
            },
            "tls": {
                "require-mtls": true
            },
            "allowlist": {
                "exact": ["spiffe://example.org/frontend"],
                "trust-domains": ["example.org"]
            },
            "failure": {
                "spire-unavailable": "fail_open"
            }
        }"#;

        let config: SpiffeAgentConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.spire.socket,
            PathBuf::from("/custom/path/agent.sock")
        );
        assert_eq!(config.spire.bundle_refresh_interval, 600);
        assert!(config.tls.require_mtls);
        assert_eq!(
            config.allowlist.exact,
            vec!["spiffe://example.org/frontend"]
        );
        assert_eq!(
            config.allowlist.trust_domains,
            vec!["example.org"]
        );
        assert_eq!(config.failure.spire_unavailable, FailureMode::FailOpen);
    }

    #[test]
    fn test_allowlist_is_empty() {
        let config = AllowlistConfig::default();
        assert!(config.is_empty());

        let config_with_exact = AllowlistConfig {
            exact: vec!["spiffe://example.org/app".to_string()],
            ..Default::default()
        };
        assert!(!config_with_exact.is_empty());
    }
}
