//! Zentinel SPIFFE Authentication Agent
//!
//! This agent provides SPIFFE/SPIRE-based workload identity authentication
//! for the Zentinel reverse proxy. It validates incoming client certificates
//! containing SPIFFE SVIDs and enforces allowlist policies.
//!
//! # Features
//!
//! - X.509 SVID validation from client certificates
//! - SPIFFE ID extraction and propagation via headers
//! - Flexible allowlist matching (exact, prefix, regex, trust domain)
//! - Configurable failure modes (fail-open, fail-closed, cache)
//! - Integration with SPIRE Workload API for trust bundle management
//! - Protocol v2 support with health reporting and metrics
//!
//! # Usage
//!
//! ```bash
//! # UDS mode (default)
//! zentinel-spiffe-agent --socket /var/run/zentinel/spiffe.sock
//!
//! # gRPC mode
//! zentinel-spiffe-agent --grpc-address 127.0.0.1:50051
//! ```

mod allowlist;
mod config;
mod spiffe;

use anyhow::{anyhow, Result};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, GrpcAgentServerV2,
    HealthConfig, HealthStatus, MetricsReport, ShutdownReason, UdsAgentServerV2,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestHeadersEvent,
};

use allowlist::{AllowlistMatch, SpiffeIdAllowlist};
use config::{FailureMode, SpiffeAgentConfig, ValidationFailureAction};
use spiffe::{validate_certificate, TrustBundleCache, ValidationResult, WorkloadApiClient};

/// Get current time in milliseconds since Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-spiffe-agent")]
#[command(about = "SPIFFE/SPIRE workload identity agent for Zentinel reverse proxy")]
struct Args {
    /// Path to Unix socket (UDS mode)
    #[arg(
        long,
        default_value = "/tmp/zentinel-spiffe.sock",
        env = "AGENT_SOCKET"
    )]
    socket: PathBuf,

    /// gRPC address to listen on (gRPC mode). If specified, UDS mode is disabled.
    #[arg(long, env = "AGENT_GRPC_ADDRESS")]
    grpc_address: Option<SocketAddr>,

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
    /// Configuration version for tracking updates.
    config_version: RwLock<Option<String>>,
    /// SPIFFE ID allowlist.
    allowlist: RwLock<SpiffeIdAllowlist>,
    /// SPIRE Workload API client.
    workload_client: Arc<WorkloadApiClient>,
    /// Trust bundle cache.
    bundle_cache: Arc<TrustBundleCache>,
    /// Requests processed counter.
    requests_processed: AtomicU64,
    /// Requests allowed counter.
    requests_allowed: AtomicU64,
    /// Requests blocked counter.
    requests_blocked: AtomicU64,
    /// Whether the agent is draining.
    draining: RwLock<bool>,
}

impl SpiffeAgent {
    /// Create a new SPIFFE agent.
    pub fn new(config: SpiffeAgentConfig) -> Result<Self> {
        config.validate().map_err(|e| anyhow!(e))?;

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
            config_version: RwLock::new(None),
            allowlist: RwLock::new(allowlist),
            workload_client,
            bundle_cache,
            requests_processed: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            draining: RwLock::new(false),
        })
    }

    /// Reconfigure the agent with new settings.
    pub async fn reconfigure(&self, new_config: SpiffeAgentConfig) -> Result<()> {
        new_config.validate().map_err(|e| anyhow!(e))?;

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
    fn get_header<'a>(headers: &'a HashMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
        let name_lower = name.to_lowercase();
        headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .and_then(|(_, v)| v.first())
            .map(|s| s.as_str())
    }

    /// Remove every identity header this agent emits from the upstream
    /// request, so a client cannot supply them itself. Applied to every
    /// response that lets the request through, before any identity is set.
    fn strip_identity_headers(
        mut response: AgentResponse,
        config: &SpiffeAgentConfig,
    ) -> AgentResponse {
        for name in config.identity_header_names() {
            response = response.add_request_header(HeaderOp::Remove { name });
        }
        response
    }

    /// Allow the request without an identity (identity headers stripped).
    fn build_anonymous_allow(config: &SpiffeAgentConfig) -> AgentResponse {
        Self::strip_identity_headers(AgentResponse::default_allow(), config)
    }

    /// Build an unauthorized response.
    fn build_unauthorized_response(&self, reason: &str, status: u16) -> AgentResponse {
        warn!(reason = %reason, "SPIFFE authentication failed");

        // Increment blocked counter
        self.requests_blocked.fetch_add(1, Ordering::Relaxed);

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
        // Increment allowed counter
        self.requests_allowed.fetch_add(1, Ordering::Relaxed);

        let spiffe_id = validation.spiffe_id.as_ref().unwrap();
        let trust_domain = validation.trust_domain.as_ref().unwrap();

        let mut response = Self::build_anonymous_allow(config)
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
        custom.insert("spiffe_id".to_string(), serde_json::json!(spiffe_id));
        custom.insert("trust_domain".to_string(), serde_json::json!(trust_domain));
        if let Some(ref match_type) = allowlist_match.match_type {
            custom.insert(
                "match_type".to_string(),
                serde_json::json!(match_type.to_string()),
            );
        }
        if let Some(ref pattern) = allowlist_match.pattern {
            custom.insert("match_pattern".to_string(), serde_json::json!(pattern));
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
    fn build_fail_open_response(&self, reason: &str, config: &SpiffeAgentConfig) -> AgentResponse {
        warn!(reason = %reason, "SPIFFE authentication failed, fail-open enabled");

        Self::build_anonymous_allow(config).with_audit(AuditMetadata {
            tags: vec!["spiffe".to_string(), "fail_open".to_string()],
            reason_codes: vec!["SPIFFE_FAIL_OPEN".to_string()],
            custom: HashMap::from([("reason".to_string(), serde_json::json!(reason))]),
            ..Default::default()
        })
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for SpiffeAgent {
    /// Get agent capabilities for v2 protocol.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            protocol_version: 2,
            agent_id: "zentinel-spiffe-agent".to_string(),
            name: "Zentinel SPIFFE Authentication Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_events: vec![EventType::RequestHeaders, EventType::Configure],
            features: AgentFeatures {
                streaming_body: false,
                websocket: false,
                guardrails: false,
                config_push: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                flow_control: false,
                health_reporting: true,
            },
            limits: AgentLimits {
                max_body_size: 0, // We don't process bodies
                max_concurrency: 100,
                preferred_chunk_size: 0,
                max_memory: None,
                max_processing_time_ms: Some(1000),
            },
            health: HealthConfig {
                report_interval_ms: 10_000,
                include_load_metrics: true,
                include_resource_metrics: false,
            },
        }
    }

    /// Handle configuration update from proxy (v2 signature).
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        let json_config: SpiffeAgentConfig = match serde_json::from_value(config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse SPIFFE config: {}, using defaults", e);
                return false;
            }
        };

        if let Err(e) = self.reconfigure(json_config).await {
            warn!("Failed to reconfigure SPIFFE agent: {}", e);
            return false;
        }

        // Store the config version
        *self.config_version.write().await = version.clone();

        // Try to connect to SPIRE agent
        if let Err(e) = self.workload_client.connect().await {
            warn!("Failed to connect to SPIRE agent: {}", e);
            // Don't fail - we can still validate certs without trust bundles
        }

        info!(
            config_version = ?version,
            "SPIFFE agent configured via on_configure"
        );
        true
    }

    /// Get current health status.
    fn health_status(&self) -> HealthStatus {
        let is_draining = *self.draining.blocking_read();

        if is_draining {
            return HealthStatus {
                agent_id: "zentinel-spiffe-agent".to_string(),
                state: zentinel_agent_protocol::v2::HealthState::Draining { eta_ms: None },
                message: Some("Agent is draining".to_string()),
                load: None,
                resources: None,
                valid_until_ms: None,
                timestamp_ms: now_ms(),
            };
        }

        // Check SPIRE connectivity
        let spire_connected = self.workload_client.socket_exists();

        if !spire_connected {
            return HealthStatus::degraded(
                "zentinel-spiffe-agent",
                vec!["spire_integration".to_string()],
                1.5, // Increase timeout slightly when SPIRE is unavailable
            );
        }

        HealthStatus::healthy("zentinel-spiffe-agent")
    }

    /// Get current metrics report.
    fn metrics_report(&self) -> Option<MetricsReport> {
        use zentinel_agent_protocol::v2::{CounterMetric, GaugeMetric};

        let processed = self.requests_processed.load(Ordering::Relaxed);
        let allowed = self.requests_allowed.load(Ordering::Relaxed);
        let blocked = self.requests_blocked.load(Ordering::Relaxed);

        let mut report = MetricsReport::new("zentinel-spiffe-agent", 10_000);

        report
            .counters
            .push(CounterMetric::new("spiffe_agent_requests_total", processed));
        report.counters.push(CounterMetric::new(
            "spiffe_agent_requests_allowed_total",
            allowed,
        ));
        report.counters.push(CounterMetric::new(
            "spiffe_agent_requests_blocked_total",
            blocked,
        ));

        // Add gauge for current state
        report.gauges.push(GaugeMetric::new(
            "spiffe_agent_spire_connected",
            if self.workload_client.socket_exists() {
                1.0
            } else {
                0.0
            },
        ));

        Some(report)
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "SPIFFE agent received shutdown request"
        );
        // Set draining flag
        *self.draining.write().await = true;
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "SPIFFE agent received drain request"
        );
        // Set draining flag
        *self.draining.write().await = true;
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Increment request counter
        self.requests_processed.fetch_add(1, Ordering::Relaxed);
        let config = self.config.read().await;

        // Zentinel does not tell agents which peer certificate it verified, and
        // it never sets the client-certificate header itself, so that header is
        // client-controlled unless a trusted front proxy sets it. Without the
        // explicit opt-in there is no verifiable identity source at all.
        if !config.tls.trust_forwarded_client_cert {
            if config.tls.require_mtls {
                debug!("No verifiable client identity source, mTLS required");
                return self.build_unauthorized_response(
                    "No verifiable client identity (the client certificate header is not trusted)",
                    401,
                );
            }
            return Self::build_anonymous_allow(&config);
        }

        // Get client certificate from header
        let cert_header = match Self::get_header(&event.headers, &config.tls.client_cert_header) {
            Some(cert) => cert,
            None => {
                if config.tls.require_mtls {
                    debug!("No client certificate, mTLS required");
                    return self.build_unauthorized_response("No client certificate", 401);
                }
                // mTLS not required, allow through without an identity
                return Self::build_anonymous_allow(&config);
            }
        };

        // A forwarded certificate is only identity if it chains to the SPIRE
        // trust bundle. Always verify: an empty or missing bundle rejects the
        // certificate instead of skipping verification.
        let trust_bundles = self.bundle_cache.get_all().await;

        // Validate the certificate
        let validation = match validate_certificate(cert_header, Some(&trust_bundles)) {
            Ok(result) => result,
            Err(e) => {
                let error_msg = e.to_string();
                debug!(error = %error_msg, "Certificate validation failed");

                return match config.failure.validation_failure {
                    ValidationFailureAction::Reject => match config.failure.spire_unavailable {
                        FailureMode::FailOpen => self.build_fail_open_response(&error_msg, &config),
                        _ => self.build_unauthorized_response(&error_msg, 401),
                    },
                    ValidationFailureAction::LogAndAllow => {
                        warn!(error = %error_msg, "Certificate validation failed, log-and-allow enabled");
                        Self::build_anonymous_allow(&config).with_audit(AuditMetadata {
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
                FailureMode::FailOpen => self.build_fail_open_response(error_msg, &config),
                _ => self.build_unauthorized_response(error_msg, 401),
            };
        }

        // Get the SPIFFE ID
        let spiffe_id = match &validation.spiffe_id {
            Some(id) => id,
            None => {
                return match config.failure.spire_unavailable {
                    FailureMode::FailOpen => self.build_fail_open_response("No SPIFFE ID", &config),
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
            return self
                .build_unauthorized_response(&format!("SPIFFE ID {} not allowed", spiffe_id), 403);
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
            "{}={},zentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        protocol_version = 2,
        "Starting Zentinel SPIFFE Agent"
    );

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

    // Start server based on transport mode
    if let Some(grpc_addr) = args.grpc_address {
        // gRPC mode
        info!(
            address = %grpc_addr,
            "Starting gRPC agent server (v2 protocol)"
        );
        let server = GrpcAgentServerV2::new("zentinel-spiffe-agent", Box::new(agent));
        server
            .run(grpc_addr)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    } else {
        // UDS mode (default)
        info!(socket = ?args.socket, "Starting UDS agent server");
        let server = UdsAgentServerV2::new("zentinel-spiffe-agent", args.socket, Box::new(agent));
        server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;
    }

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
                prefix: vec![],
                patterns: vec![],
            },
            spire: config::SpireConfig::default(),
            tls: config::TlsConfig::default(),
            headers: config::HeadersConfig::default(),
            failure: config::FailureConfig::default(),
            audit: config::AuditConfig::default(),
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
                prefix: vec![],
                trust_domains: vec![],
                patterns: vec![],
            },
            spire: config::SpireConfig::default(),
            tls: config::TlsConfig::default(),
            headers: config::HeadersConfig::default(),
            failure: config::FailureConfig::default(),
            audit: config::AuditConfig::default(),
        };

        let result = agent.reconfigure(new_config).await;
        assert!(result.is_ok());

        // Verify new allowlist is active
        let allowlist = agent.allowlist.read().await;
        assert!(allowlist.is_allowed("spiffe://other.org/backend").allowed);
        assert!(
            !allowlist
                .is_allowed("spiffe://example.org/frontend")
                .allowed
        );
    }

    #[test]
    fn test_v2_capabilities() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        let caps = agent.capabilities();
        assert_eq!(caps.protocol_version, 2);
        assert_eq!(caps.agent_id, "zentinel-spiffe-agent");
        assert!(caps.features.config_push);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
        assert!(!caps.features.streaming_body);
        assert!(!caps.features.websocket);
    }

    #[test]
    fn test_v2_health_status() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        let health = agent.health_status();
        assert_eq!(health.agent_id, "zentinel-spiffe-agent");
        // Should be degraded since SPIRE socket doesn't exist in tests
        assert!(matches!(
            health.state,
            zentinel_agent_protocol::v2::HealthState::Degraded { .. }
        ));
    }

    #[test]
    fn test_v2_metrics_report() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        let metrics = agent.metrics_report();
        assert!(metrics.is_some());

        let report = metrics.unwrap();
        assert_eq!(report.agent_id, "zentinel-spiffe-agent");
        assert!(!report.counters.is_empty());
        assert!(!report.gauges.is_empty());
    }

    #[tokio::test]
    async fn test_v2_on_configure() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        let new_config = serde_json::json!({
            "allowlist": {
                "exact": ["spiffe://new.org/app"],
                "prefix": [],
                "trust-domains": [],
                "patterns": []
            }
        });

        let result =
            AgentHandlerV2::on_configure(&agent, new_config, Some("v1.0.0".to_string())).await;
        assert!(result);

        // Verify config version was stored
        let version = agent.config_version.read().await;
        assert_eq!(version.as_deref(), Some("v1.0.0"));
    }

    #[tokio::test]
    async fn test_v2_on_shutdown() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        // Initially not draining
        assert!(!*agent.draining.read().await);

        // Trigger shutdown
        agent.on_shutdown(ShutdownReason::Graceful, 30000).await;

        // Should now be draining
        assert!(*agent.draining.read().await);
    }

    #[tokio::test]
    async fn test_v2_on_drain() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        // Initially not draining
        assert!(!*agent.draining.read().await);

        // Trigger drain
        agent.on_drain(60000, DrainReason::Maintenance).await;

        // Should now be draining
        assert!(*agent.draining.read().await);
    }

    #[test]
    fn test_request_counters() {
        let config = test_config();
        let agent = SpiffeAgent::new(config).unwrap();

        // Initial counters should be zero
        assert_eq!(agent.requests_processed.load(Ordering::Relaxed), 0);
        assert_eq!(agent.requests_allowed.load(Ordering::Relaxed), 0);
        assert_eq!(agent.requests_blocked.load(Ordering::Relaxed), 0);

        // Simulate incrementing
        agent.requests_processed.fetch_add(10, Ordering::Relaxed);
        agent.requests_allowed.fetch_add(8, Ordering::Relaxed);
        agent.requests_blocked.fetch_add(2, Ordering::Relaxed);

        assert_eq!(agent.requests_processed.load(Ordering::Relaxed), 10);
        assert_eq!(agent.requests_allowed.load(Ordering::Relaxed), 8);
        assert_eq!(agent.requests_blocked.load(Ordering::Relaxed), 2);
    }

    /// Self-signed certificate with URI SAN `spiffe://example.org/frontend`
    /// (an ID that `test_config()` allows), base64 DER, valid until 2126.
    /// Anyone can mint one; it must never become an identity.
    const SELF_SIGNED_SPIFFE_CERT_B64: &str = "MIIBvzCCAWWgAwIBAgIUD+hnRt1zck5cEDDmykWIb+i2/eUwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUc2VsZi1zaWduZWQtYXR0YWNrZXIwIBcNMjYxMDIxMTg0MDQ2WhgPMjEyNjA5MjcxODQwNDZaMB8xHTAbBgNVBAMMFHNlbGYtc2lnbmVkLWF0dGFja2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb8rMIb8Jz7LZtZ+XzhoP4f3uM0MD6nUQOfhfinc6MpRGU3s063JA4Goi7ct5fD2HimaEks3yiLYfMp5NS2FSiaN9MHswHQYDVR0OBBYEFNKaHS0U5jd4VbflUz9bP0Yd5c++MB8GA1UdIwQYMBaAFNKaHS0U5jd4VbflUz9bP0Yd5c++MA8GA1UdEwEB/wQFMAMBAf8wKAYDVR0RBCEwH4Ydc3BpZmZlOi8vZXhhbXBsZS5vcmcvZnJvbnRlbmQwCgYIKoZIzj0EAwIDSAAwRQIgb7E2ZXjbTbnARidrI7Fj/GL4CX2+YsSGaV+O9QiLSqECIQDiuPbLyvaz1BMYS/LX75REdoxW2iIK2YUmeqs2GiHZtg==";

    fn request(headers: &[(&str, &str)]) -> RequestHeadersEvent {
        RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "c".to_string(),
                request_id: "r".to_string(),
                client_ip: "203.0.113.7".to_string(),
                client_port: 40000,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2026-10-21T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                .collect(),
        }
    }

    /// Headers a client tries to smuggle in, plus a forged certificate.
    fn spoofed_request() -> RequestHeadersEvent {
        request(&[
            ("X-Forwarded-Client-Cert", SELF_SIGNED_SPIFFE_CERT_B64),
            ("x-spiffe-id", "spiffe://example.org/admin"),
            ("X-SPIFFE-Trust-Domain", "example.org"),
            ("X-SPIFFE-Workload-Id", "/admin"),
            ("X-Auth-Method", "spiffe"),
            ("X-Auth-Timestamp", "1"),
        ])
    }

    fn status(response: &AgentResponse) -> Option<u16> {
        match &response.decision {
            zentinel_agent_protocol::Decision::Block { status, .. } => Some(*status),
            _ => None,
        }
    }

    fn removed(response: &AgentResponse) -> Vec<String> {
        response
            .request_headers
            .iter()
            .filter_map(|op| match op {
                HeaderOp::Remove { name } => Some(name.to_lowercase()),
                _ => None,
            })
            .collect()
    }

    fn set(response: &AgentResponse) -> Vec<String> {
        response
            .request_headers
            .iter()
            .filter_map(|op| match op {
                HeaderOp::Set { name, .. } | HeaderOp::Add { name, .. } => {
                    Some(name.to_lowercase())
                }
                _ => None,
            })
            .collect()
    }

    fn assert_identity_headers_stripped(response: &AgentResponse, config: &SpiffeAgentConfig) {
        let removed = removed(response);
        for name in [
            "x-spiffe-id",
            "x-spiffe-trust-domain",
            "x-spiffe-workload-id",
            "x-auth-method",
            "x-auth-timestamp",
        ] {
            assert!(removed.contains(&name.to_string()), "{name} not stripped");
        }
        for name in config.identity_header_names() {
            assert!(
                removed.contains(&name.to_lowercase()),
                "{name} not stripped"
            );
        }
        assert!(set(response).is_empty(), "no identity may be set");
    }

    #[tokio::test]
    async fn test_rule_a_identity_headers_stripped_when_allowing_without_mtls() {
        // require-mtls off (default): request passes, but anonymously.
        let mut config = test_config();
        config.headers.spiffe_id = "X-Custom-Spiffe".to_string();
        let agent = SpiffeAgent::new(config.clone()).unwrap();
        let mut event = spoofed_request();
        event
            .headers
            .insert("X-Custom-Spiffe".to_string(), vec!["forged".to_string()]);

        let response = agent.on_request_headers(event).await;
        assert_eq!(status(&response), None);
        assert_identity_headers_stripped(&response, &config);
        assert!(removed(&response).contains(&"x-custom-spiffe".to_string()));
        assert_eq!(agent.requests_allowed.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_rule_a_identity_headers_stripped_on_fail_open() {
        // Even the opt-in path's fail-open / log-and-allow branches must strip.
        let config = test_config();
        let agent = SpiffeAgent::new(config.clone()).unwrap();
        {
            let mut cfg = agent.config.write().await;
            cfg.tls.trust_forwarded_client_cert = true; // bypasses validate()
            cfg.failure.spire_unavailable = FailureMode::FailOpen;
        }
        let response = agent.on_request_headers(spoofed_request()).await;
        assert_eq!(status(&response), None);
        assert_identity_headers_stripped(&response, &config);

        {
            let mut cfg = agent.config.write().await;
            cfg.failure.spire_unavailable = FailureMode::FailClosed;
            cfg.failure.validation_failure = ValidationFailureAction::LogAndAllow;
        }
        let response = agent.on_request_headers(spoofed_request()).await;
        assert_eq!(status(&response), None);
        assert_identity_headers_stripped(&response, &config);
    }

    #[test]
    fn test_fixture_is_a_forgery_unverified_parsing_accepts() {
        // Guards the tests below: without a trust bundle the certificate is
        // accepted as `spiffe://example.org/frontend` (what the agent did with
        // every forwarded certificate before), and with an empty bundle it is
        // rejected.
        let unverified = validate_certificate(SELF_SIGNED_SPIFFE_CERT_B64, None).unwrap();
        assert!(unverified.valid);
        assert_eq!(
            unverified.spiffe_id.as_deref(),
            Some("spiffe://example.org/frontend")
        );
        assert!(validate_certificate(SELF_SIGNED_SPIFFE_CERT_B64, Some(&HashMap::new())).is_err());
    }

    #[tokio::test]
    async fn test_rule_b_forwarded_cert_ignored_by_default() {
        // A forged certificate in X-Forwarded-Client-Cert must not become an
        // identity: no X-SPIFFE-Id is set, and with require-mtls it is denied.
        let mut config = test_config();
        config.tls.require_mtls = true;
        let agent = SpiffeAgent::new(config).unwrap();
        let response = agent.on_request_headers(spoofed_request()).await;
        assert_eq!(status(&response), Some(401));
        assert!(set(&response).is_empty());
        assert_eq!(agent.requests_allowed.load(Ordering::Relaxed), 0);
        assert_eq!(agent.requests_blocked.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_rule_b_opt_in_rejected_by_new_reconfigure_and_on_configure() {
        let mut opt_in = test_config();
        opt_in.tls.trust_forwarded_client_cert = true;
        let err = SpiffeAgent::new(opt_in.clone()).err().unwrap().to_string();
        assert!(err.contains("zentinel-agent-spiffe#5"), "{err}");

        let agent = SpiffeAgent::new(test_config()).unwrap();
        assert!(agent.reconfigure(opt_in).await.is_err());

        let accepted = AgentHandlerV2::on_configure(
            &agent,
            serde_json::json!({
                "tls": { "require-mtls": true, "trust-forwarded-client-cert": true },
                "allowlist": { "exact": ["spiffe://example.org/frontend"] }
            }),
            Some("v2".to_string()),
        )
        .await;
        assert!(!accepted, "opt-in config must be refused");
        let cfg = agent.config.read().await;
        assert!(!cfg.tls.trust_forwarded_client_cert);
        drop(cfg);
        assert!(agent.config_version.read().await.is_none());
    }

    #[tokio::test]
    async fn test_rule_b_opt_in_still_requires_trust_bundle_verification() {
        // Defence in depth: if the opt-in flag were ever set, a certificate
        // that does not chain to the trust bundle (here: the bundle cache is
        // empty, as it is whenever SPIRE has not delivered one) is rejected.
        let agent = SpiffeAgent::new(test_config()).unwrap();
        agent.config.write().await.tls.trust_forwarded_client_cert = true;
        let response = agent.on_request_headers(spoofed_request()).await;
        assert_eq!(status(&response), Some(401));
        assert!(set(&response).is_empty());
        assert_eq!(agent.requests_allowed.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_rule_c_require_mtls_without_identity_source_denies() {
        // No verifiable identity source + require-mtls: deny, whatever the
        // failure modes say, with and without a client certificate header.
        for (spire_unavailable, validation_failure) in [
            (FailureMode::FailClosed, ValidationFailureAction::Reject),
            (FailureMode::FailOpen, ValidationFailureAction::LogAndAllow),
            (FailureMode::Cache, ValidationFailureAction::Reject),
        ] {
            let mut config = test_config();
            config.tls.require_mtls = true;
            config.failure.spire_unavailable = spire_unavailable;
            config.failure.validation_failure = validation_failure;
            let agent = SpiffeAgent::new(config).unwrap();

            for event in [request(&[]), spoofed_request()] {
                let response = agent.on_request_headers(event).await;
                assert_eq!(status(&response), Some(401), "{spire_unavailable:?}");
                assert!(set(&response).is_empty());
            }
            assert_eq!(agent.requests_allowed.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn test_rule_c_require_mtls_opt_in_missing_cert_denies_even_fail_open() {
        let agent = SpiffeAgent::new(test_config()).unwrap();
        {
            let mut cfg = agent.config.write().await;
            cfg.tls.trust_forwarded_client_cert = true;
            cfg.tls.require_mtls = true;
            cfg.failure.spire_unavailable = FailureMode::FailOpen;
        }
        let response = agent.on_request_headers(request(&[])).await;
        assert_eq!(status(&response), Some(401));
    }
}
