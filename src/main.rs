//! Sentinel SPIFFE Authentication Agent
//!
//! This agent provides SPIFFE/SPIRE-based workload identity authentication
//! for the Sentinel reverse proxy. It validates incoming client certificates
//! containing SPIFFE SVIDs and enforces allowlist policies.
//!
//! # Features
//!
//! - X.509 SVID validation from client certificates
//! - SPIFFE ID extraction and propagation via headers
//! - Flexible allowlist matching (exact, prefix, regex, trust domain)
//! - Configurable failure modes (fail-open, fail-closed, cache)
//! - Integration with SPIRE Workload API for trust bundle management
//!
//! # Usage
//!
//! ```bash
//! sentinel-spiffe-agent --socket /var/run/sentinel/spiffe.sock
//! ```

mod allowlist;
mod config;
mod spiffe;

use anyhow::{anyhow, Result};
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, ConfigureEvent, HeaderOp,
    RequestHeadersEvent,
};

use allowlist::{AllowlistMatch, MatchType, SpiffeIdAllowlist};
use config::{FailureMode, SpiffeAgentConfig, ValidationFailureAction};
use spiffe::{validate_certificate, TrustBundleCache, ValidationResult, WorkloadApiClient};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-spiffe-agent")]
#[command(about = "SPIFFE/SPIRE workload identity agent for Sentinel reverse proxy")]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/sentinel-spiffe.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// Path to SPIRE agent socket
    #[arg(
        long,
        default_value = "/run/spire/sockets/agent.sock",
        env = "SPIRE_AGENT_SOCKET"
    )]
    spire_socket: PathBuf,

    /// Enable verbose logging
    #[arg(short, long, env = "SPIFFE_VERBOSE")]
    verbose: bool,
}

/// SPIFFE authentication agent.
pub struct SpiffeAgent {
    /// Agent configuration.
    config: RwLock<SpiffeAgentConfig>,
    /// SPIFFE ID allowlist.
    allowlist: RwLock<SpiffeIdAllowlist>,
    /// SPIRE Workload API client.
    workload_client: Arc<WorkloadApiClient>,
    /// Trust bundle cache.
    bundle_cache: Arc<TrustBundleCache>,
}

impl SpiffeAgent {
    /// Create a new SPIFFE agent.
    pub fn new(config: SpiffeAgentConfig) -> Result<Self> {
        // Create allowlist from config
        let allowlist = SpiffeIdAllowlist::new(&config.allowlist)
            .map_err(|e| anyhow!("Failed to create allowlist: {}", e))?;

        // Create workload API client
        let workload_client = Arc::new(WorkloadApiClient::new(
            config.spire.socket.clone(),
            config.spire.bundle_refresh_interval,
            config.spire.api_timeout_ms,
        ));

        let bundle_cache = workload_client.bundle_cache();

        Ok(Self {
            config: RwLock::new(config),
            allowlist: RwLock::new(allowlist),
            workload_client,
            bundle_cache,
        })
    }

    /// Reconfigure the agent with new settings.
    pub async fn reconfigure(&self, new_config: SpiffeAgentConfig) -> Result<()> {
        // Create new allowlist
        let new_allowlist = SpiffeIdAllowlist::new(&new_config.allowlist)
            .map_err(|e| anyhow!("Failed to create allowlist: {}", e))?;

        // Update allowlist
        *self.allowlist.write().await = new_allowlist;

        // Update config
        *self.config.write().await = new_config;

        info!("SPIFFE agent reconfigured");
        Ok(())
    }

    /// Get a header value from the headers map (case-insensitive).
    fn get_header<'a>(
        headers: &'a HashMap<String, Vec<String>>,
        name: &str,
    ) -> Option<&'a str> {
        let name_lower = name.to_lowercase();
        headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .and_then(|(_, v)| v.first())
            .map(|s| s.as_str())
    }

    /// Build an unauthorized response.
    fn build_unauthorized_response(&self, reason: &str, status: u16) -> AgentResponse {
        warn!(reason = %reason, "SPIFFE authentication failed");

        AgentResponse::block(status, Some("Unauthorized".to_string()))
            .add_response_header(HeaderOp::Set {
                name: "WWW-Authenticate".to_string(),
                value: "SPIFFE".to_string(),
            })
            .with_audit(AuditMetadata {
                tags: vec!["spiffe".to_string(), "auth_failed".to_string()],
                reason_codes: vec!["SPIFFE_AUTH_FAILED".to_string()],
                custom: HashMap::from([("reason".to_string(), serde_json::json!(reason))]),
                ..Default::default()
            })
    }

    /// Build a success response with identity headers.
    fn build_identity_response(
        &self,
        validation: &ValidationResult,
        allowlist_match: &AllowlistMatch,
        config: &SpiffeAgentConfig,
    ) -> AgentResponse {
        let spiffe_id = validation.spiffe_id.as_ref().unwrap();
        let trust_domain = validation.trust_domain.as_ref().unwrap();

        let mut response = AgentResponse::default_allow()
            .add_request_header(HeaderOp::Set {
                name: config.headers.spiffe_id.clone(),
                value: spiffe_id.clone(),
            })
            .add_request_header(HeaderOp::Set {
                name: config.headers.trust_domain.clone(),
                value: trust_domain.clone(),
            })
            .add_request_header(HeaderOp::Set {
                name: config.headers.auth_method.clone(),
                value: "spiffe".to_string(),
            })
            .add_request_header(HeaderOp::Set {
                name: config.headers.auth_timestamp.clone(),
                value: chrono::Utc::now().timestamp().to_string(),
            });

        // Add workload ID if present
        if let Some(ref workload_path) = validation.workload_path {
            response = response.add_request_header(HeaderOp::Set {
                name: config.headers.workload_id.clone(),
                value: workload_path.clone(),
            });
        }

        // Build audit metadata
        let mut custom = HashMap::new();
        custom.insert(
            "spiffe_id".to_string(),
            serde_json::json!(spiffe_id),
        );
        custom.insert(
            "trust_domain".to_string(),
            serde_json::json!(trust_domain),
        );
        if let Some(ref match_type) = allowlist_match.match_type {
            custom.insert(
                "match_type".to_string(),
                serde_json::json!(match_type.to_string()),
            );
        }
        if let Some(ref pattern) = allowlist_match.pattern {
            custom.insert(
                "match_pattern".to_string(),
                serde_json::json!(pattern),
            );
        }
        if let Some(ref cert_info) = validation.cert_info {
            custom.insert(
                "cert_serial".to_string(),
                serde_json::json!(cert_info.serial_number),
            );
        }

        response.with_audit(AuditMetadata {
            tags: vec!["spiffe".to_string(), "authenticated".to_string()],
            confidence: Some(1.0),
            reason_codes: vec!["SPIFFE_VALID".to_string()],
            custom,
            ..Default::default()
        })
    }

    /// Handle fail-open scenario.
    fn build_fail_open_response(&self, reason: &str) -> AgentResponse {
        warn!(reason = %reason, "SPIFFE authentication failed, fail-open enabled");

        AgentResponse::default_allow().with_audit(AuditMetadata {
            tags: vec!["spiffe".to_string(), "fail_open".to_string()],
            reason_codes: vec!["SPIFFE_FAIL_OPEN".to_string()],
            custom: HashMap::from([("reason".to_string(), serde_json::json!(reason))]),
            ..Default::default()
        })
    }
}

#[async_trait::async_trait]
impl AgentHandler for SpiffeAgent {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        let json_config: SpiffeAgentConfig = match serde_json::from_value(event.config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse SPIFFE config: {}, using defaults", e);
                return AgentResponse::default_allow();
            }
        };

        if let Err(e) = self.reconfigure(json_config).await {
            warn!("Failed to reconfigure SPIFFE agent: {}", e);
            return AgentResponse::block(500, Some(format!("Configuration error: {}", e)));
        }

        // Try to connect to SPIRE agent
        if let Err(e) = self.workload_client.connect().await {
            warn!("Failed to connect to SPIRE agent: {}", e);
            // Don't fail - we can still validate certs without trust bundles
        }

        info!("SPIFFE agent configured via on_configure");
        AgentResponse::default_allow()
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let config = self.config.read().await;

        // Get client certificate from header
        let cert_header = match Self::get_header(&event.headers, &config.tls.client_cert_header) {
            Some(cert) => cert,
            None => {
                if config.tls.require_mtls {
                    debug!("No client certificate, mTLS required");
                    return match config.failure.spire_unavailable {
                        FailureMode::FailOpen => {
                            self.build_fail_open_response("No client certificate")
                        }
                        _ => self.build_unauthorized_response("No client certificate", 401),
                    };
                }
                // mTLS not required, allow through
                return AgentResponse::default_allow();
            }
        };

        // Get trust bundles from cache (if available)
        let trust_bundles = if self.workload_client.is_connected().await {
            Some(self.bundle_cache.get_all().await)
        } else {
            None
        };

        // Validate the certificate
        let validation = match validate_certificate(cert_header, trust_bundles.as_ref()) {
            Ok(result) => result,
            Err(e) => {
                let error_msg = e.to_string();
                debug!(error = %error_msg, "Certificate validation failed");

                return match config.failure.validation_failure {
                    ValidationFailureAction::Reject => {
                        match config.failure.spire_unavailable {
                            FailureMode::FailOpen => {
                                self.build_fail_open_response(&error_msg)
                            }
                            _ => self.build_unauthorized_response(&error_msg, 401),
                        }
                    }
                    ValidationFailureAction::LogAndAllow => {
                        warn!(error = %error_msg, "Certificate validation failed, log-and-allow enabled");
                        AgentResponse::default_allow().with_audit(AuditMetadata {
                            tags: vec![
                                "spiffe".to_string(),
                                "validation_failed".to_string(),
                                "log_and_allow".to_string(),
                            ],
                            reason_codes: vec!["SPIFFE_VALIDATION_FAILED".to_string()],
                            custom: HashMap::from([(
                                "error".to_string(),
                                serde_json::json!(error_msg),
                            )]),
                            ..Default::default()
                        })
                    }
                };
            }
        };

        // Check if validation succeeded
        if !validation.valid {
            let error_msg = validation.error.as_deref().unwrap_or("Unknown error");
            return match config.failure.spire_unavailable {
                FailureMode::FailOpen => self.build_fail_open_response(error_msg),
                _ => self.build_unauthorized_response(error_msg, 401),
            };
        }

        // Get the SPIFFE ID
        let spiffe_id = match &validation.spiffe_id {
            Some(id) => id,
            None => {
                return match config.failure.spire_unavailable {
                    FailureMode::FailOpen => self.build_fail_open_response("No SPIFFE ID"),
                    _ => self.build_unauthorized_response("No SPIFFE ID in certificate", 401),
                };
            }
        };

        // Check allowlist
        let allowlist = self.allowlist.read().await;
        let allowlist_match = allowlist.is_allowed(spiffe_id);

        if !allowlist_match.allowed {
            info!(
                spiffe_id = %spiffe_id,
                "SPIFFE ID not in allowlist"
            );
            return self.build_unauthorized_response(
                &format!("SPIFFE ID {} not allowed", spiffe_id),
                403,
            );
        }

        // Log successful authentication
        if config.audit.log_success {
            info!(
                spiffe_id = %spiffe_id,
                trust_domain = validation.trust_domain.as_deref().unwrap_or("unknown"),
                match_type = ?allowlist_match.match_type,
                "SPIFFE authentication successful"
            );
        }

        // Build success response
        self.build_identity_response(&validation, &allowlist_match, &config)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},sentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Sentinel SPIFFE Agent");

    // Build default configuration from args
    let mut config = SpiffeAgentConfig::default();
    config.spire.socket = args.spire_socket;

    info!(
        spire_socket = %config.spire.socket.display(),
        require_mtls = config.tls.require_mtls,
        failure_mode = ?config.failure.spire_unavailable,
        "Configuration loaded"
    );

    // Create agent
    let agent = SpiffeAgent::new(config)?;

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new("sentinel-spiffe-agent", args.socket, Box::new(agent));

    server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::AllowlistConfig;

    fn test_config() -> SpiffeAgentConfig {
        SpiffeAgentConfig {
            allowlist: AllowlistConfig {
                exact: vec!["spiffe://example.org/frontend".to_string()],
                trust_domains: vec!["example.org".to_string()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_agent_creation() {
        let config = test_config();
        let agent = SpiffeAgent::new(config);
        assert!(agent.is_ok());
    }

    #[tokio::test]
    async fn test_get_header_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert(
            "X-Forwarded-Client-Cert".to_string(),
            vec!["cert-data".to_string()],
        );

        assert_eq!(
            SpiffeAgent::get_header(&headers, "x-forwarded-client-cert"),
            Some("cert-data")
        );
        assert_eq!(
            SpiffeAgent::get_header(&headers, "X-FORWARDED-CLIENT-CERT"),
            Some("cert-data")
        );
        assert_eq!(SpiffeAgent::get_header(&headers, "nonexistent"), None);
    }

    #[tokio::test]
    async fn test_reconfigure() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        // Reconfigure with new allowlist
        let new_config = SpiffeAgentConfig {
            allowlist: AllowlistConfig {
                exact: vec!["spiffe://other.org/backend".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        let result = agent.reconfigure(new_config).await;
        assert!(result.is_ok());

        // Verify new allowlist is active
        let allowlist = agent.allowlist.read().await;
        assert!(allowlist.is_allowed("spiffe://other.org/backend").allowed);
        assert!(!allowlist.is_allowed("spiffe://example.org/frontend").allowed);
    }
}
