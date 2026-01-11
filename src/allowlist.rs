//! SPIFFE ID allowlist matching.
//!
//! Provides multiple matching strategies for validating SPIFFE IDs:
//! - Exact match
//! - Prefix match
//! - Trust domain match
//! - Regex pattern match

use regex::Regex;
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, trace};

use crate::config::AllowlistConfig;

/// Errors that can occur during allowlist operations.
#[derive(Debug, Error)]
pub enum AllowlistError {
    #[error("invalid regex pattern '{pattern}': {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// SPIFFE ID allowlist for validating workload identities.
#[derive(Debug)]
pub struct SpiffeIdAllowlist {
    /// Exact match set.
    exact: HashSet<String>,
    /// Prefix patterns.
    prefixes: Vec<String>,
    /// Allowed trust domains.
    trust_domains: HashSet<String>,
    /// Compiled regex patterns.
    patterns: Vec<CompiledPattern>,
    /// Whether the allowlist allows all (empty config).
    allow_all: bool,
}

#[derive(Debug)]
struct CompiledPattern {
    regex: Regex,
    original: String,
}

impl SpiffeIdAllowlist {
    /// Create a new allowlist from configuration.
    pub fn new(config: &AllowlistConfig) -> Result<Self, AllowlistError> {
        // If the allowlist is empty, allow all
        let allow_all = config.is_empty();

        // Build exact match set
        let exact: HashSet<String> = config.exact.iter().cloned().collect();

        // Build prefix list
        let prefixes = config.prefix.clone();

        // Build trust domain set
        let trust_domains: HashSet<String> = config.trust_domains.iter().cloned().collect();

        // Compile regex patterns
        let mut patterns = Vec::with_capacity(config.patterns.len());
        for pattern in &config.patterns {
            let regex = Regex::new(pattern).map_err(|e| AllowlistError::InvalidPattern {
                pattern: pattern.clone(),
                source: e,
            })?;
            patterns.push(CompiledPattern {
                regex,
                original: pattern.clone(),
            });
        }

        debug!(
            exact_count = exact.len(),
            prefix_count = prefixes.len(),
            trust_domain_count = trust_domains.len(),
            pattern_count = patterns.len(),
            allow_all = allow_all,
            "Created SPIFFE ID allowlist"
        );

        Ok(Self {
            exact,
            prefixes,
            trust_domains,
            patterns,
            allow_all,
        })
    }

    /// Check if a SPIFFE ID is allowed.
    ///
    /// Returns a match result indicating whether the ID is allowed and how it matched.
    pub fn is_allowed(&self, spiffe_id: &str) -> AllowlistMatch {
        // If allowlist is empty, allow all
        if self.allow_all {
            trace!(spiffe_id = %spiffe_id, "Allowlist is empty, allowing all");
            return AllowlistMatch {
                allowed: true,
                match_type: Some(MatchType::AllowAll),
                pattern: None,
            };
        }

        // Check exact match first (fastest)
        if self.exact.contains(spiffe_id) {
            trace!(spiffe_id = %spiffe_id, "Exact match found");
            return AllowlistMatch {
                allowed: true,
                match_type: Some(MatchType::Exact),
                pattern: Some(spiffe_id.to_string()),
            };
        }

        // Check prefix match
        for prefix in &self.prefixes {
            if spiffe_id.starts_with(prefix) {
                trace!(spiffe_id = %spiffe_id, prefix = %prefix, "Prefix match found");
                return AllowlistMatch {
                    allowed: true,
                    match_type: Some(MatchType::Prefix),
                    pattern: Some(prefix.clone()),
                };
            }
        }

        // Check trust domain match
        if let Some(trust_domain) = extract_trust_domain(spiffe_id) {
            if self.trust_domains.contains(trust_domain) {
                trace!(
                    spiffe_id = %spiffe_id,
                    trust_domain = %trust_domain,
                    "Trust domain match found"
                );
                return AllowlistMatch {
                    allowed: true,
                    match_type: Some(MatchType::TrustDomain),
                    pattern: Some(trust_domain.to_string()),
                };
            }
        }

        // Check regex patterns (slowest)
        for pattern in &self.patterns {
            if pattern.regex.is_match(spiffe_id) {
                trace!(
                    spiffe_id = %spiffe_id,
                    pattern = %pattern.original,
                    "Regex pattern match found"
                );
                return AllowlistMatch {
                    allowed: true,
                    match_type: Some(MatchType::Regex),
                    pattern: Some(pattern.original.clone()),
                };
            }
        }

        // No match found
        debug!(spiffe_id = %spiffe_id, "No allowlist match found");
        AllowlistMatch {
            allowed: false,
            match_type: None,
            pattern: None,
        }
    }
}

/// Result of an allowlist check.
#[derive(Debug, Clone)]
pub struct AllowlistMatch {
    /// Whether the SPIFFE ID is allowed.
    pub allowed: bool,
    /// The type of match (if allowed).
    pub match_type: Option<MatchType>,
    /// The pattern that matched (if allowed).
    pub pattern: Option<String>,
}

/// Type of allowlist match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// Matched because allowlist is empty (allow all).
    AllowAll,
    /// Exact string match.
    Exact,
    /// Prefix match.
    Prefix,
    /// Trust domain match.
    TrustDomain,
    /// Regex pattern match.
    Regex,
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchType::AllowAll => write!(f, "allow_all"),
            MatchType::Exact => write!(f, "exact"),
            MatchType::Prefix => write!(f, "prefix"),
            MatchType::TrustDomain => write!(f, "trust_domain"),
            MatchType::Regex => write!(f, "regex"),
        }
    }
}

/// Extract the trust domain from a SPIFFE ID.
///
/// SPIFFE ID format: spiffe://trust-domain/workload-path
///
/// Returns None if the SPIFFE ID is not valid.
pub fn extract_trust_domain(spiffe_id: &str) -> Option<&str> {
    // Must start with spiffe://
    let remainder = spiffe_id.strip_prefix("spiffe://")?;

    // Trust domain is everything before the first /
    match remainder.find('/') {
        Some(pos) => Some(&remainder[..pos]),
        None => Some(remainder), // No path, just trust domain
    }
}

/// Extract the workload path from a SPIFFE ID.
///
/// SPIFFE ID format: spiffe://trust-domain/workload-path
///
/// Returns None if there is no workload path or the SPIFFE ID is invalid.
pub fn extract_workload_path(spiffe_id: &str) -> Option<&str> {
    // Must start with spiffe://
    let remainder = spiffe_id.strip_prefix("spiffe://")?;

    // Workload path is everything after the first /
    remainder.find('/').map(|pos| &remainder[pos..])
}

/// Parse a SPIFFE ID into its components.
pub fn parse_spiffe_id(spiffe_id: &str) -> Option<SpiffeIdComponents<'_>> {
    let remainder = spiffe_id.strip_prefix("spiffe://")?;

    let (trust_domain, workload_path) = match remainder.find('/') {
        Some(pos) => (&remainder[..pos], Some(&remainder[pos..])),
        None => (remainder, None),
    };

    Some(SpiffeIdComponents {
        full_id: spiffe_id,
        trust_domain,
        workload_path,
    })
}

/// Components of a parsed SPIFFE ID.
#[derive(Debug, Clone)]
pub struct SpiffeIdComponents<'a> {
    /// The full SPIFFE ID.
    pub full_id: &'a str,
    /// The trust domain.
    pub trust_domain: &'a str,
    /// The workload path (if present).
    pub workload_path: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_trust_domain() {
        assert_eq!(
            extract_trust_domain("spiffe://example.org/frontend"),
            Some("example.org")
        );
        assert_eq!(
            extract_trust_domain("spiffe://cluster.local/ns/default/sa/myapp"),
            Some("cluster.local")
        );
        assert_eq!(
            extract_trust_domain("spiffe://example.org"),
            Some("example.org")
        );
        assert_eq!(extract_trust_domain("http://example.org"), None);
        assert_eq!(extract_trust_domain("invalid"), None);
    }

    #[test]
    fn test_extract_workload_path() {
        assert_eq!(
            extract_workload_path("spiffe://example.org/frontend"),
            Some("/frontend")
        );
        assert_eq!(
            extract_workload_path("spiffe://cluster.local/ns/default/sa/myapp"),
            Some("/ns/default/sa/myapp")
        );
        assert_eq!(extract_workload_path("spiffe://example.org"), None);
    }

    #[test]
    fn test_parse_spiffe_id() {
        let components = parse_spiffe_id("spiffe://example.org/frontend").unwrap();
        assert_eq!(components.trust_domain, "example.org");
        assert_eq!(components.workload_path, Some("/frontend"));

        let components = parse_spiffe_id("spiffe://example.org").unwrap();
        assert_eq!(components.trust_domain, "example.org");
        assert_eq!(components.workload_path, None);
    }

    #[test]
    fn test_allowlist_exact_match() {
        let config = AllowlistConfig {
            exact: vec!["spiffe://example.org/frontend".to_string()],
            ..Default::default()
        };

        let allowlist = SpiffeIdAllowlist::new(&config).unwrap();

        let result = allowlist.is_allowed("spiffe://example.org/frontend");
        assert!(result.allowed);
        assert_eq!(result.match_type, Some(MatchType::Exact));

        let result = allowlist.is_allowed("spiffe://example.org/backend");
        assert!(!result.allowed);
    }

    #[test]
    fn test_allowlist_prefix_match() {
        let config = AllowlistConfig {
            prefix: vec!["spiffe://example.org/services/".to_string()],
            ..Default::default()
        };

        let allowlist = SpiffeIdAllowlist::new(&config).unwrap();

        let result = allowlist.is_allowed("spiffe://example.org/services/api");
        assert!(result.allowed);
        assert_eq!(result.match_type, Some(MatchType::Prefix));

        let result = allowlist.is_allowed("spiffe://example.org/frontend");
        assert!(!result.allowed);
    }

    #[test]
    fn test_allowlist_trust_domain_match() {
        let config = AllowlistConfig {
            trust_domains: vec!["example.org".to_string()],
            ..Default::default()
        };

        let allowlist = SpiffeIdAllowlist::new(&config).unwrap();

        let result = allowlist.is_allowed("spiffe://example.org/any/path");
        assert!(result.allowed);
        assert_eq!(result.match_type, Some(MatchType::TrustDomain));

        let result = allowlist.is_allowed("spiffe://other.org/any/path");
        assert!(!result.allowed);
    }

    #[test]
    fn test_allowlist_regex_match() {
        let config = AllowlistConfig {
            patterns: vec![r"spiffe://example\.org/team-[a-z]+/.*".to_string()],
            ..Default::default()
        };

        let allowlist = SpiffeIdAllowlist::new(&config).unwrap();

        let result = allowlist.is_allowed("spiffe://example.org/team-alpha/service");
        assert!(result.allowed);
        assert_eq!(result.match_type, Some(MatchType::Regex));

        let result = allowlist.is_allowed("spiffe://example.org/team-123/service");
        assert!(!result.allowed);
    }

    #[test]
    fn test_allowlist_empty_allows_all() {
        let config = AllowlistConfig::default();
        let allowlist = SpiffeIdAllowlist::new(&config).unwrap();

        let result = allowlist.is_allowed("spiffe://any.domain/any/path");
        assert!(result.allowed);
        assert_eq!(result.match_type, Some(MatchType::AllowAll));
    }

    #[test]
    fn test_invalid_regex_pattern() {
        let config = AllowlistConfig {
            patterns: vec!["[invalid".to_string()],
            ..Default::default()
        };

        let result = SpiffeIdAllowlist::new(&config);
        assert!(result.is_err());
    }
}
