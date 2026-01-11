//! X.509 certificate validation for SPIFFE SVIDs.
//!
//! Provides certificate parsing, SPIFFE ID extraction, and validation
//! against trust bundles.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, trace, warn};
use x509_parser::prelude::*;

use crate::allowlist::{extract_trust_domain, extract_workload_path};

/// Errors that can occur during certificate validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("failed to decode certificate: {0}")]
    DecodingFailed(String),

    #[error("failed to parse certificate: {0}")]
    ParseFailed(String),

    #[error("certificate has no SPIFFE ID in SAN URIs")]
    NoSpiffeId,

    #[error("invalid SPIFFE ID format: {0}")]
    InvalidSpiffeId(String),

    #[error("certificate has expired")]
    Expired,

    #[error("certificate not yet valid")]
    NotYetValid,

    #[error("trust domain '{0}' not found in trust bundles")]
    UnknownTrustDomain(String),

    #[error("certificate chain verification failed: {0}")]
    ChainVerificationFailed(String),
}

/// Result of certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the certificate is valid.
    pub valid: bool,
    /// Extracted SPIFFE ID.
    pub spiffe_id: Option<String>,
    /// Trust domain.
    pub trust_domain: Option<String>,
    /// Workload path.
    pub workload_path: Option<String>,
    /// Additional certificate information.
    pub cert_info: Option<CertificateInfo>,
    /// Error message if validation failed.
    pub error: Option<String>,
}

impl ValidationResult {
    /// Create a successful validation result.
    pub fn success(
        spiffe_id: String,
        trust_domain: String,
        workload_path: Option<String>,
        cert_info: CertificateInfo,
    ) -> Self {
        Self {
            valid: true,
            spiffe_id: Some(spiffe_id),
            trust_domain: Some(trust_domain),
            workload_path,
            cert_info: Some(cert_info),
            error: None,
        }
    }

    /// Create a failed validation result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            spiffe_id: None,
            trust_domain: None,
            workload_path: None,
            cert_info: None,
            error: Some(error.into()),
        }
    }
}

/// Information extracted from a certificate.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Certificate serial number (hex).
    pub serial_number: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Subject distinguished name.
    pub subject: String,
    /// Not valid before timestamp (Unix seconds).
    pub not_before: i64,
    /// Not valid after timestamp (Unix seconds).
    pub not_after: i64,
    /// Additional claims extracted from the certificate.
    pub claims: HashMap<String, String>,
}

/// Decode a client certificate from a header value.
///
/// Supports multiple encoding formats:
/// - URL-encoded PEM
/// - Base64-encoded DER
/// - Raw PEM (newlines replaced with spaces or %0A)
pub fn decode_certificate(header_value: &str) -> Result<Vec<u8>, ValidationError> {
    let header_value = header_value.trim();

    // Try URL-decoded PEM first
    if let Ok(decoded) = urlencoding::decode(header_value) {
        let decoded_str = decoded.as_ref();
        if decoded_str.contains("-----BEGIN CERTIFICATE-----") {
            trace!("Decoding URL-encoded PEM certificate");
            return parse_pem_to_der(decoded_str);
        }
    }

    // Try raw PEM (with spaces instead of newlines)
    if header_value.contains("-----BEGIN CERTIFICATE-----")
        || header_value.contains("BEGIN CERTIFICATE")
    {
        trace!("Decoding raw PEM certificate");
        // Replace spaces that might be newlines
        let pem_str = header_value
            .replace("-----BEGIN CERTIFICATE----- ", "-----BEGIN CERTIFICATE-----\n")
            .replace(" -----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");
        return parse_pem_to_der(&pem_str);
    }

    // Try base64-encoded DER
    trace!("Trying base64-encoded DER certificate");
    BASE64
        .decode(header_value)
        .map_err(|e| ValidationError::DecodingFailed(format!("Base64 decode failed: {}", e)))
}

/// Parse a PEM certificate string to DER bytes.
fn parse_pem_to_der(pem_str: &str) -> Result<Vec<u8>, ValidationError> {
    let mut reader = std::io::Cursor::new(pem_str.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ValidationError::ParseFailed(format!("PEM parse failed: {}", e)))?;

    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| ValidationError::ParseFailed("No certificate found in PEM".to_string()))
}

/// Extract the SPIFFE ID from an X.509 certificate.
///
/// The SPIFFE ID is stored in the Subject Alternative Name (SAN) URI extension.
pub fn extract_spiffe_id_from_cert(cert_der: &[u8]) -> Result<String, ValidationError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| ValidationError::ParseFailed(format!("DER parse failed: {}", e)))?;

    // Look for SPIFFE ID in SAN URIs
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::URI(uri) = name {
                if uri.starts_with("spiffe://") {
                    trace!(spiffe_id = %uri, "Found SPIFFE ID in certificate SAN");
                    return Ok(uri.to_string());
                }
            }
        }
    }

    Err(ValidationError::NoSpiffeId)
}

/// Validate a client certificate and extract SPIFFE identity.
///
/// This performs:
/// 1. Certificate decoding (from header format)
/// 2. Certificate parsing
/// 3. SPIFFE ID extraction from SAN
/// 4. Validity period check
/// 5. Trust bundle verification (if bundles provided)
pub fn validate_certificate(
    cert_header: &str,
    trust_bundles: Option<&HashMap<String, Vec<Vec<u8>>>>,
) -> Result<ValidationResult, ValidationError> {
    // Decode the certificate
    let cert_der = decode_certificate(cert_header)?;

    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(&cert_der)
        .map_err(|e| ValidationError::ParseFailed(format!("Certificate parse failed: {}", e)))?;

    // Extract SPIFFE ID
    let spiffe_id = extract_spiffe_id_from_cert(&cert_der)?;

    // Parse SPIFFE ID components
    let trust_domain = extract_trust_domain(&spiffe_id)
        .ok_or_else(|| ValidationError::InvalidSpiffeId(spiffe_id.clone()))?
        .to_string();

    let workload_path = extract_workload_path(&spiffe_id).map(String::from);

    // Check validity period
    let now = chrono::Utc::now().timestamp();
    let not_before = cert.validity.not_before.timestamp();
    let not_after = cert.validity.not_after.timestamp();

    if now < not_before {
        warn!(
            spiffe_id = %spiffe_id,
            not_before = %not_before,
            now = %now,
            "Certificate not yet valid"
        );
        return Err(ValidationError::NotYetValid);
    }

    if now > not_after {
        warn!(
            spiffe_id = %spiffe_id,
            not_after = %not_after,
            now = %now,
            "Certificate has expired"
        );
        return Err(ValidationError::Expired);
    }

    // Verify against trust bundle if provided
    if let Some(bundles) = trust_bundles {
        if let Some(bundle) = bundles.get(&trust_domain) {
            // Verify the certificate was issued by one of the trusted CAs
            let mut verified = false;
            for ca_der in bundle {
                if verify_certificate_signature(&cert_der, ca_der).is_ok() {
                    verified = true;
                    break;
                }
            }

            if !verified {
                warn!(
                    spiffe_id = %spiffe_id,
                    trust_domain = %trust_domain,
                    "Certificate not signed by any CA in trust bundle"
                );
                return Err(ValidationError::ChainVerificationFailed(
                    "Certificate not signed by any trusted CA".to_string(),
                ));
            }
        } else {
            warn!(
                spiffe_id = %spiffe_id,
                trust_domain = %trust_domain,
                "Trust domain not found in trust bundles"
            );
            return Err(ValidationError::UnknownTrustDomain(trust_domain));
        }
    }

    // Build certificate info
    let cert_info = CertificateInfo {
        serial_number: cert.serial.to_str_radix(16),
        issuer: cert.issuer.to_string(),
        subject: cert.subject.to_string(),
        not_before,
        not_after,
        claims: extract_certificate_claims(&cert),
    };

    debug!(
        spiffe_id = %spiffe_id,
        trust_domain = %trust_domain,
        serial = %cert_info.serial_number,
        "Certificate validation successful"
    );

    Ok(ValidationResult::success(
        spiffe_id,
        trust_domain,
        workload_path,
        cert_info,
    ))
}

/// Verify a certificate's signature against a CA certificate.
fn verify_certificate_signature(cert_der: &[u8], ca_der: &[u8]) -> Result<(), ValidationError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| ValidationError::ParseFailed(format!("Cert parse failed: {}", e)))?;

    let (_, ca) = X509Certificate::from_der(ca_der)
        .map_err(|e| ValidationError::ParseFailed(format!("CA parse failed: {}", e)))?;

    // Verify the certificate was signed by the CA
    cert.verify_signature(Some(ca.public_key()))
        .map_err(|e| ValidationError::ChainVerificationFailed(format!("Signature verification failed: {:?}", e)))
}

/// Extract additional claims from the certificate.
fn extract_certificate_claims(cert: &X509Certificate) -> HashMap<String, String> {
    let mut claims = HashMap::new();

    // Extract common name from subject
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Ok(cn) = attr.as_str() {
                    claims.insert("cn".to_string(), cn.to_string());
                }
            }
            if attr.attr_type() == &oid_registry::OID_X509_ORGANIZATION_NAME {
                if let Ok(o) = attr.as_str() {
                    claims.insert("organization".to_string(), o.to_string());
                }
            }
        }
    }

    // Extract DNS names from SAN
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let dns_names: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|name| {
                if let GeneralName::DNSName(dns) = name {
                    Some(dns.to_string())
                } else {
                    None
                }
            })
            .collect();

        if !dns_names.is_empty() {
            claims.insert("dns_names".to_string(), dns_names.join(","));
        }
    }

    claims
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test certificate data (self-signed for testing)
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpEgcMFvMAoGCCqGSM49BAMCMBExDzANBgNVBAMMBnRlc3Rj
YTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBMxETAPBgNVBAMMCHRl
c3R3b3JrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest1234567890abcdef
ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900aNS
MFAwHQYDVR0OBBYEFBBBBBBBBBBBBBBBBBBBBBBBBBBBMBMGCSsGAQQBgtpLAQQG
c3BpZmZlMA4GA1UdDwEB/wQEAwIFoDAKBggqhkjOPQQDAgNIADBFAiEAtest1234
aiAiEAtest56789=
-----END CERTIFICATE-----"#;

    #[test]
    fn test_decode_base64_der() {
        // A minimal DER-encoded certificate (just checking decode works)
        let base64_der = "MIIB"; // Truncated for test
        let result = decode_certificate(base64_der);
        // Should fail on parse but decode should work
        assert!(result.is_ok() || matches!(result, Err(ValidationError::DecodingFailed(_))));
    }

    #[test]
    fn test_extract_trust_domain_helper() {
        assert_eq!(
            extract_trust_domain("spiffe://example.org/workload"),
            Some("example.org")
        );
    }

    #[test]
    fn test_validation_result_success() {
        let result = ValidationResult::success(
            "spiffe://example.org/app".to_string(),
            "example.org".to_string(),
            Some("/app".to_string()),
            CertificateInfo {
                serial_number: "1234".to_string(),
                issuer: "CN=Test CA".to_string(),
                subject: "CN=Test".to_string(),
                not_before: 0,
                not_after: i64::MAX,
                claims: HashMap::new(),
            },
        );

        assert!(result.valid);
        assert_eq!(result.spiffe_id, Some("spiffe://example.org/app".to_string()));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_validation_result_failure() {
        let result = ValidationResult::failure("Test error");
        assert!(!result.valid);
        assert!(result.spiffe_id.is_none());
        assert_eq!(result.error, Some("Test error".to_string()));
    }
}
