//! SPIFFE/SPIRE integration modules.
//!
//! This module provides:
//! - Certificate parsing and SPIFFE ID extraction
//! - SVID validation against trust bundles
//! - SPIRE Workload API client

mod validation;
mod workload_api;

pub use validation::{validate_certificate, ValidationResult};
pub use workload_api::{TrustBundleCache, WorkloadApiClient};
