//! Scan result persistence.
//!
//! Provides JSON-based storage for scan results with query capabilities.

mod json_store;

pub use json_store::{ScanRecord, ScanStore};
