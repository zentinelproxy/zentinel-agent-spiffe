//! SPIRE Workload API client.
//!
//! Connects to the SPIRE agent via Unix domain socket to fetch
//! X.509 SVIDs and trust bundles.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tracing::{debug, error, info, trace, warn};

// Include the generated protobuf code
pub mod proto {
    tonic::include_proto!("spiffe.workload");
}

/// Errors that can occur when interacting with the SPIRE Workload API.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
#[derive(Debug)]
pub struct TrustBundleCache {
    /// Bundles keyed by trust domain.
    bundles: RwLock<HashMap<String, TrustBundle>>,
    /// Cache TTL in seconds.
    ttl_secs: u64,
}

#[allow(dead_code)]
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

        debug!(bundle_count = bundles.len(), "Updated trust bundle cache");
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

/// Parse concatenated DER-encoded X.509 certificates into individual certificates.
///
/// SPIRE returns trust bundles as a single blob containing multiple DER certificates
/// concatenated together. This function splits them into individual certs.
#[allow(dead_code)]
fn parse_der_certificates(data: &[u8]) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // DER sequence starts with 0x30 (SEQUENCE tag)
        if data[offset] != 0x30 {
            break;
        }

        // Parse the length
        let (len, header_len) = match data.get(offset + 1) {
            Some(&b) if b < 0x80 => {
                // Short form: length is directly encoded
                (b as usize, 2)
            }
            Some(&0x81) => {
                // Long form: 1 byte length
                match data.get(offset + 2) {
                    Some(&len_byte) => (len_byte as usize, 3),
                    None => break,
                }
            }
            Some(&0x82) => {
                // Long form: 2 byte length
                match (data.get(offset + 2), data.get(offset + 3)) {
                    (Some(&hi), Some(&lo)) => (((hi as usize) << 8) | (lo as usize), 4),
                    _ => break,
                }
            }
            _ => break,
        };

        let total_len = header_len + len;
        if offset + total_len > data.len() {
            break;
        }

        certs.push(data[offset..offset + total_len].to_vec());
        offset += total_len;
    }

    certs
}

/// SPIRE Workload API client.
///
/// Connects to the SPIRE agent to fetch X.509 SVIDs and trust bundles.
pub struct WorkloadApiClient {
    /// SPIRE agent socket path.
    socket_path: PathBuf,
    /// Trust bundle cache.
    bundle_cache: Arc<TrustBundleCache>,
    /// gRPC client (when connected).
    grpc_client:
        RwLock<Option<proto::spiffe_workload_api_client::SpiffeWorkloadApiClient<Channel>>>,
    /// API call timeout in milliseconds.
    timeout_ms: u64,
}

#[allow(dead_code)]
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
            grpc_client: RwLock::new(None),
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

    /// Connect to the SPIRE agent via Unix domain socket.
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

        let socket_path = self.socket_path.clone();
        let timeout = Duration::from_millis(self.timeout_ms);

        // Create a channel that connects over Unix socket
        // The URI doesn't matter for Unix sockets, but tonic requires one
        let channel = Endpoint::try_from("http://[::]:50051")
            .map_err(|e| WorkloadApiError::ConnectionFailed(e.to_string()))?
            .connect_timeout(timeout)
            .timeout(timeout)
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = socket_path.clone();
                async move {
                    UnixStream::connect(path)
                        .await
                        .map(hyper_util::rt::TokioIo::new)
                }
            }))
            .await
            .map_err(|e| WorkloadApiError::ConnectionFailed(e.to_string()))?;

        // Create the gRPC client
        let client = proto::spiffe_workload_api_client::SpiffeWorkloadApiClient::new(channel);
        *self.grpc_client.write().await = Some(client);

        info!(
            socket_path = %self.socket_path.display(),
            "Connected to SPIRE agent"
        );

        Ok(())
    }

    /// Check if connected to SPIRE agent.
    pub async fn is_connected(&self) -> bool {
        self.grpc_client.read().await.is_some()
    }

    /// Fetch trust bundles from SPIRE agent via the FetchX509Bundles gRPC call.
    pub async fn fetch_trust_bundles(
        &self,
    ) -> Result<HashMap<String, Vec<Vec<u8>>>, WorkloadApiError> {
        let mut client = {
            let guard = self.grpc_client.read().await;
            match guard.as_ref() {
                Some(c) => c.clone(),
                None => {
                    return Err(WorkloadApiError::ConnectionFailed(
                        "Not connected to SPIRE agent".to_string(),
                    ));
                }
            }
        };

        trace!("Fetching trust bundles from SPIRE agent");

        // Call the FetchX509Bundles RPC (streaming response)
        let request = tonic::Request::new(proto::X509BundlesRequest {});
        let mut stream = client
            .fetch_x509_bundles(request)
            .await
            .map_err(|e| WorkloadApiError::AgentError(e.message().to_string()))?
            .into_inner();

        // Get the first response from the stream
        // The SPIRE Workload API streams updates, but we just need the initial bundles
        let response = stream
            .message()
            .await
            .map_err(|e| WorkloadApiError::AgentError(e.message().to_string()))?
            .ok_or_else(|| {
                WorkloadApiError::AgentError("Empty response from SPIRE agent".to_string())
            })?;

        // Parse the bundles - each bundle is a concatenation of DER-encoded certificates
        let mut bundles = HashMap::new();
        for (trust_domain, bundle_bytes) in response.bundles {
            // Parse concatenated DER certificates into individual certs
            let certs = parse_der_certificates(&bundle_bytes);
            debug!(
                trust_domain = %trust_domain,
                cert_count = certs.len(),
                "Received trust bundle"
            );
            bundles.insert(trust_domain, certs);
        }

        // Update the cache
        self.bundle_cache.update(bundles.clone()).await;

        Ok(bundles)
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
#[allow(dead_code)]
pub struct WorkloadApiClientBuilder {
    socket_path: PathBuf,
    bundle_refresh_secs: u64,
    timeout_ms: u64,
}

#[allow(dead_code)]
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
        let client = WorkloadApiClient::new(PathBuf::from("/nonexistent/socket.sock"), 300, 5000);

        let result = client.connect().await;
        assert!(matches!(result, Err(WorkloadApiError::SocketNotFound(_))));
    }

    #[test]
    fn test_parse_der_certificates_single() {
        // A minimal DER sequence: 0x30 (SEQUENCE) + 0x03 (length 3) + 3 bytes content
        let cert = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let certs = parse_der_certificates(&cert);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert);
    }

    #[test]
    fn test_parse_der_certificates_multiple() {
        // Two concatenated DER sequences
        let cert1 = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let cert2 = vec![0x30, 0x04, 0x04, 0x05, 0x06, 0x07];
        let mut combined = cert1.clone();
        combined.extend(&cert2);

        let certs = parse_der_certificates(&combined);
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], cert1);
        assert_eq!(certs[1], cert2);
    }

    #[test]
    fn test_parse_der_certificates_long_form() {
        // DER sequence with 2-byte length encoding (0x82)
        // 0x30 0x82 0x01 0x00 means SEQUENCE with length 256
        let mut cert = vec![0x30, 0x82, 0x01, 0x00];
        cert.extend(vec![0x00; 256]); // 256 bytes of content

        let certs = parse_der_certificates(&cert);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].len(), 260); // 4 byte header + 256 bytes content
    }

    #[test]
    fn test_parse_der_certificates_empty() {
        let certs = parse_der_certificates(&[]);
        assert!(certs.is_empty());
    }
}
