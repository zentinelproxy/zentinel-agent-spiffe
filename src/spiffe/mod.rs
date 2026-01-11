//! SPIFFE/SPIRE integration modules.
//!
//! This module provides:
//! - Certificate parsing and SPIFFE ID extraction
//! - SVID validation against trust bundles
//! - SPIRE Workload API client

mod validation;
mod workload_api;

pub use validation::{
    extract_spiffe_id_from_cert, validate_certificate, CertificateInfo, ValidationError,
    ValidationResult,
};
pub use workload_api::{TrustBundle, TrustBundleCache, WorkloadApiClient, WorkloadApiError};
