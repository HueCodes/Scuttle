//! Unique identifiers for scan results.
//!
//! `ScanId` provides type-safe, unique identifiers for persisted scan results,
//! preventing accidental misuse of string identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// A unique identifier for a scan result.
///
/// Uses UUID v4 internally for globally unique identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScanId(Uuid);

impl ScanId {
    /// Generate a new random scan ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a ScanId from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// Get the raw bytes of this ID.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// Get a short representation (first 8 characters).
    pub fn short(&self) -> String {
        self.0.to_string()[..8].to_string()
    }
}

impl Default for ScanId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ScanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ScanId {
    type Err = ScanIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Support both full UUIDs and short forms
        if s.len() == 8 {
            // Short form - this is a prefix search, but for parsing we need full UUID
            return Err(ScanIdError::ShortFormNotSupported);
        }

        let uuid = Uuid::parse_str(s).map_err(|_| ScanIdError::InvalidFormat(s.to_string()))?;
        Ok(Self(uuid))
    }
}

/// Error type for ScanId parsing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ScanIdError {
    #[error("invalid scan ID format: {0}")]
    InvalidFormat(String),
    #[error("short form IDs require database lookup")]
    ShortFormNotSupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_id_generation() {
        let id1 = ScanId::new();
        let id2 = ScanId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_scan_id_display() {
        let id = ScanId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 36); // UUID format with hyphens
    }

    #[test]
    fn test_scan_id_short() {
        let id = ScanId::new();
        let short = id.short();
        assert_eq!(short.len(), 8);
    }

    #[test]
    fn test_scan_id_roundtrip() {
        let id = ScanId::new();
        let s = id.to_string();
        let parsed: ScanId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }
}
