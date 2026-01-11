//! SPIRE Workload API client.
//!
//! Connects to the SPIRE agent via Unix domain socket to fetch
//! X.509 SVIDs and trust bundles.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

/// Errors that can occur when interacting with the SPIRE Workload API.
#[derive(Debug, Error)]
pub enum WorkloadApiError {
    #[error("failed to connect to SPIRE agent: {0}")]
    ConnectionFailed(String),

    #[error("SPIRE agent returned error: {0}")]
    AgentError(String),

    #[error("timeout waiting for SPIRE agent response")]
    Timeout,

    #[error("no X.509 SVID available")]
    NoSvid,

    #[error("no trust bundle available for domain: {0}")]
    NoBundleForDomain(String),

    #[error("socket path does not exist: {0}")]
    SocketNotFound(String),
}

/// Trust bundle for a trust domain.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    /// Trust domain name.
    pub trust_domain: String,
    /// DER-encoded CA certificates.
    pub ca_certs: Vec<Vec<u8>>,
    /// When the bundle was last refreshed.
    pub refreshed_at: Instant,
}

/// Cache for trust bundles.
#[derive(Debug)]
pub struct TrustBundleCache {
    /// Bundles keyed by trust domain.
    bundles: RwLock<HashMap<String, TrustBundle>>,
    /// Cache TTL in seconds.
    ttl_secs: u64,
}

impl TrustBundleCache {
    /// Create a new trust bundle cache.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            bundles: RwLock::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Get a trust bundle for a domain.
    pub async fn get(&self, trust_domain: &str) -> Option<TrustBundle> {
        let bundles = self.bundles.read().await;
        bundles.get(trust_domain).cloned()
    }

    /// Get all trust bundles as a map of trust domain to CA certs.
    pub async fn get_all(&self) -> HashMap<String, Vec<Vec<u8>>> {
        let bundles = self.bundles.read().await;
        bundles
            .iter()
            .map(|(k, v)| (k.clone(), v.ca_certs.clone()))
            .collect()
    }

    /// Update the cache with new bundles.
    pub async fn update(&self, new_bundles: HashMap<String, Vec<Vec<u8>>>) {
        let mut bundles = self.bundles.write().await;
        let now = Instant::now();

        for (domain, ca_certs) in new_bundles {
            bundles.insert(
                domain.clone(),
                TrustBundle {
                    trust_domain: domain,
                    ca_certs,
                    refreshed_at: now,
                },
            );
        }

        debug!(
            bundle_count = bundles.len(),
            "Updated trust bundle cache"
        );
    }

    /// Check if the cache needs refresh.
    pub async fn needs_refresh(&self) -> bool {
        let bundles = self.bundles.read().await;
        if bundles.is_empty() {
            return true;
        }

        let now = Instant::now();
        let ttl = Duration::from_secs(self.ttl_secs);

        bundles
            .values()
            .any(|b| now.duration_since(b.refreshed_at) > ttl)
    }

    /// Clear the cache.
    pub async fn clear(&self) {
        let mut bundles = self.bundles.write().await;
        bundles.clear();
    }
}

/// SPIRE Workload API client.
///
/// Connects to the SPIRE agent to fetch X.509 SVIDs and trust bundles.
pub struct WorkloadApiClient {
    /// SPIRE agent socket path.
    socket_path: PathBuf,
    /// Trust bundle cache.
    bundle_cache: Arc<TrustBundleCache>,
    /// Whether the client is connected.
    connected: RwLock<bool>,
    /// API call timeout in milliseconds.
    timeout_ms: u64,
}

impl WorkloadApiClient {
    /// Create a new Workload API client.
    pub fn new(socket_path: PathBuf, bundle_refresh_secs: u64, timeout_ms: u64) -> Self {
        info!(
            socket_path = %socket_path.display(),
            bundle_refresh_secs = bundle_refresh_secs,
            "Creating SPIRE Workload API client"
        );

        Self {
            socket_path,
            bundle_cache: Arc::new(TrustBundleCache::new(bundle_refresh_secs)),
            connected: RwLock::new(false),
            timeout_ms,
        }
    }

    /// Get the bundle cache.
    pub fn bundle_cache(&self) -> Arc<TrustBundleCache> {
        Arc::clone(&self.bundle_cache)
    }

    /// Check if the socket exists.
    pub fn socket_exists(&self) -> bool {
        self.socket_path.exists()
    }

    /// Connect to the SPIRE agent.
    ///
    /// This is a placeholder that will be replaced with actual gRPC connection
    /// when full SPIRE integration is implemented.
    pub async fn connect(&self) -> Result<(), WorkloadApiError> {
        if !self.socket_path.exists() {
            warn!(
                socket_path = %self.socket_path.display(),
                "SPIRE agent socket does not exist"
            );
            return Err(WorkloadApiError::SocketNotFound(
                self.socket_path.display().to_string(),
            ));
        }

        // TODO: Implement actual gRPC connection over Unix socket
        // For now, we mark as connected if the socket exists
        *self.connected.write().await = true;

        info!(
            socket_path = %self.socket_path.display(),
            "Connected to SPIRE agent"
        );

        Ok(())
    }

    /// Check if connected to SPIRE agent.
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Fetch trust bundles from SPIRE agent.
    ///
    /// This is a placeholder that will be replaced with actual SPIRE API calls
    /// when full integration is implemented.
    pub async fn fetch_trust_bundles(&self) -> Result<HashMap<String, Vec<Vec<u8>>>, WorkloadApiError>
    {
        if !self.is_connected().await {
            return Err(WorkloadApiError::ConnectionFailed(
                "Not connected to SPIRE agent".to_string(),
            ));
        }

        // TODO: Implement actual FetchX509Bundles gRPC call
        // For now, return cached bundles or empty
        trace!("Fetching trust bundles from SPIRE agent");

        if self.bundle_cache.needs_refresh().await {
            debug!("Trust bundle cache needs refresh");
            // In production, this would call SPIRE API
            // For now, we just return what's in cache
        }

        Ok(self.bundle_cache.get_all().await)
    }

    /// Refresh trust bundles in the background.
    pub async fn refresh_bundles(&self) -> Result<(), WorkloadApiError> {
        trace!("Refreshing trust bundles");

        let bundles = self.fetch_trust_bundles().await?;
        self.bundle_cache.update(bundles).await;

        Ok(())
    }

    /// Start background trust bundle refresh task.
    pub fn start_bundle_refresh_task(
        self: Arc<Self>,
        refresh_interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        let client = self;

        tokio::spawn(async move {
            let interval = Duration::from_secs(refresh_interval_secs);

            loop {
                tokio::time::sleep(interval).await;

                if let Err(e) = client.refresh_bundles().await {
                    error!(error = %e, "Failed to refresh trust bundles");
                }
            }
        })
    }

    /// Validate bundles are available for a trust domain.
    pub async fn has_bundle_for(&self, trust_domain: &str) -> bool {
        self.bundle_cache.get(trust_domain).await.is_some()
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }
}

/// Builder for WorkloadApiClient.
pub struct WorkloadApiClientBuilder {
    socket_path: PathBuf,
    bundle_refresh_secs: u64,
    timeout_ms: u64,
}

impl WorkloadApiClientBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from("/run/spire/sockets/agent.sock"),
            bundle_refresh_secs: 300,
            timeout_ms: 5000,
        }
    }

    /// Set the socket path.
    pub fn socket_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.socket_path = path.into();
        self
    }

    /// Set the bundle refresh interval.
    pub fn bundle_refresh_secs(mut self, secs: u64) -> Self {
        self.bundle_refresh_secs = secs;
        self
    }

    /// Set the API timeout.
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Build the client.
    pub fn build(self) -> WorkloadApiClient {
        WorkloadApiClient::new(self.socket_path, self.bundle_refresh_secs, self.timeout_ms)
    }
}

impl Default for WorkloadApiClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trust_bundle_cache() {
        let cache = TrustBundleCache::new(300);

        // Initially empty
        assert!(cache.needs_refresh().await);
        assert!(cache.get("example.org").await.is_none());

        // Add a bundle
        let mut bundles = HashMap::new();
        bundles.insert("example.org".to_string(), vec![vec![1, 2, 3]]);
        cache.update(bundles).await;

        // Now has bundle
        assert!(!cache.needs_refresh().await);
        let bundle = cache.get("example.org").await.unwrap();
        assert_eq!(bundle.trust_domain, "example.org");
        assert_eq!(bundle.ca_certs, vec![vec![1, 2, 3]]);
    }

    #[tokio::test]
    async fn test_client_builder() {
        let client = WorkloadApiClientBuilder::new()
            .socket_path("/custom/path/agent.sock")
            .bundle_refresh_secs(600)
            .timeout_ms(10000)
            .build();

        assert_eq!(
            client.socket_path(),
            &PathBuf::from("/custom/path/agent.sock")
        );
    }

    #[tokio::test]
    async fn test_client_socket_not_found() {
        let client = WorkloadApiClient::new(
            PathBuf::from("/nonexistent/socket.sock"),
            300,
            5000,
        );

        let result = client.connect().await;
        assert!(matches!(result, Err(WorkloadApiError::SocketNotFound(_))));
    }
}
