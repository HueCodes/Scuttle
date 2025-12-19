//! JSON-based scan result storage.
//!
//! Stores each scan as a separate JSON file for simplicity and durability.
//! Supports listing, querying, and exporting scan results.

use crate::config::Paths;
use crate::error::{StorageError, StorageResult};
use crate::scanner::traits::{PortResult, ScanType};
use crate::types::ScanId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A persisted scan record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    /// Unique identifier for this scan.
    pub id: ScanId,
    /// When the scan was started.
    pub started_at: DateTime<Utc>,
    /// When the scan completed.
    pub completed_at: DateTime<Utc>,
    /// Target specification (hostname, IP, or CIDR).
    pub target: String,
    /// Resolved IP address.
    pub ip_address: String,
    /// Type of scan performed.
    pub scan_type: String,
    /// Number of ports scanned.
    pub ports_scanned: usize,
    /// Number of open ports found.
    pub open_ports: usize,
    /// Number of closed ports found.
    pub closed_ports: usize,
    /// Number of filtered ports found.
    pub filtered_ports: usize,
    /// Total scan duration in milliseconds.
    pub duration_ms: u64,
    /// Individual port results.
    pub results: Vec<PortResult>,
}

impl ScanRecord {
    /// Create a new scan record.
    pub fn new(target: impl Into<String>, ip: impl Into<String>, scan_type: ScanType) -> Self {
        Self {
            id: ScanId::new(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            target: target.into(),
            ip_address: ip.into(),
            scan_type: scan_type.to_string(),
            ports_scanned: 0,
            open_ports: 0,
            closed_ports: 0,
            filtered_ports: 0,
            duration_ms: 0,
            results: Vec::new(),
        }
    }

    /// Finalize the scan record with results.
    pub fn finalize(mut self, results: Vec<PortResult>, duration_ms: u64) -> Self {
        self.completed_at = Utc::now();
        self.duration_ms = duration_ms;
        self.ports_scanned = results.len();

        for result in &results {
            match result.status {
                crate::scanner::traits::PortStatus::Open
                | crate::scanner::traits::PortStatus::OpenFiltered => {
                    self.open_ports += 1;
                }
                crate::scanner::traits::PortStatus::Closed => {
                    self.closed_ports += 1;
                }
                crate::scanner::traits::PortStatus::Filtered => {
                    self.filtered_ports += 1;
                }
            }
        }

        self.results = results;
        self
    }

    /// Get a short summary of the scan.
    pub fn summary(&self) -> String {
        format!(
            "{} ({}) - {} open, {} closed, {} filtered [{:.2}s]",
            self.target,
            self.ip_address,
            self.open_ports,
            self.closed_ports,
            self.filtered_ports,
            self.duration_ms as f64 / 1000.0
        )
    }
}

/// JSON file-based scan storage.
pub struct ScanStore {
    scans_dir: PathBuf,
}

impl ScanStore {
    /// Create a new scan store.
    pub fn new() -> StorageResult<Self> {
        let paths = Paths::get();
        let scans_dir = paths.scans_dir();

        fs::create_dir_all(&scans_dir)
            .map_err(|e| StorageError::DirectoryError(e.to_string()))?;

        Ok(Self { scans_dir })
    }

    /// Save a scan record.
    pub fn save(&self, record: &ScanRecord) -> StorageResult<()> {
        let file = self.scan_file(&record.id);
        let content = serde_json::to_string_pretty(record)?;

        fs::write(&file, content).map_err(|e| StorageError::SaveFailed(e.to_string()))
    }

    /// Load a scan record by ID.
    pub fn load(&self, id: &ScanId) -> StorageResult<ScanRecord> {
        let file = self.scan_file(id);

        if !file.exists() {
            return Err(StorageError::ScanNotFound(id.to_string()));
        }

        let content =
            fs::read_to_string(&file).map_err(|e| StorageError::LoadFailed(e.to_string()))?;

        serde_json::from_str(&content).map_err(|e| StorageError::LoadFailed(e.to_string()))
    }

    /// Find a scan by short ID prefix.
    pub fn find_by_prefix(&self, prefix: &str) -> StorageResult<ScanRecord> {
        let matches: Vec<_> = self
            .list_ids()?
            .into_iter()
            .filter(|id| id.to_string().starts_with(prefix))
            .collect();

        match matches.len() {
            0 => Err(StorageError::ScanNotFound(prefix.to_string())),
            1 => self.load(&matches[0]),
            _ => Err(StorageError::LoadFailed(format!(
                "ambiguous prefix '{}': {} matches",
                prefix,
                matches.len()
            ))),
        }
    }

    /// List all scan IDs.
    pub fn list_ids(&self) -> StorageResult<Vec<ScanId>> {
        let mut ids = Vec::new();

        for entry in
            fs::read_dir(&self.scans_dir).map_err(|e| StorageError::DirectoryError(e.to_string()))?
        {
            let entry = entry.map_err(|e| StorageError::DirectoryError(e.to_string()))?;
            let path = entry.path();

            if path.extension().map_or(false, |ext| ext == "json") {
                if let Some(stem) = path.file_stem() {
                    if let Ok(id) = stem.to_string_lossy().parse::<ScanId>() {
                        ids.push(id);
                    }
                }
            }
        }

        Ok(ids)
    }

    /// List all scan records (metadata only, results truncated).
    pub fn list(&self) -> StorageResult<Vec<ScanRecord>> {
        let ids = self.list_ids()?;
        let mut records = Vec::new();

        for id in ids {
            if let Ok(record) = self.load(&id) {
                records.push(record);
            }
        }

        // Sort by date, most recent first
        records.sort_by(|a, b| b.started_at.cmp(&a.started_at));

        Ok(records)
    }

    /// List recent scans (last n).
    pub fn list_recent(&self, count: usize) -> StorageResult<Vec<ScanRecord>> {
        let mut records = self.list()?;
        records.truncate(count);
        Ok(records)
    }

    /// Delete a scan record.
    pub fn delete(&self, id: &ScanId) -> StorageResult<()> {
        let file = self.scan_file(id);

        if !file.exists() {
            return Err(StorageError::ScanNotFound(id.to_string()));
        }

        fs::remove_file(&file).map_err(|e| StorageError::SaveFailed(e.to_string()))
    }

    /// Delete scans older than a given duration.
    pub fn cleanup(&self, max_age: chrono::Duration) -> StorageResult<usize> {
        let cutoff = Utc::now() - max_age;
        let mut deleted = 0;

        for record in self.list()? {
            if record.started_at < cutoff {
                self.delete(&record.id)?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Get the file path for a scan.
    fn scan_file(&self, id: &ScanId) -> PathBuf {
        self.scans_dir.join(format!("{}.json", id))
    }

    /// Get storage statistics.
    pub fn stats(&self) -> StorageResult<StorageStats> {
        let records = self.list()?;
        let total_size: u64 = self
            .list_ids()?
            .iter()
            .filter_map(|id| fs::metadata(self.scan_file(id)).ok())
            .map(|m| m.len())
            .sum();

        Ok(StorageStats {
            scan_count: records.len(),
            total_size_bytes: total_size,
            oldest_scan: records.last().map(|r| r.started_at),
            newest_scan: records.first().map(|r| r.started_at),
        })
    }
}

impl Default for ScanStore {
    fn default() -> Self {
        Self::new().expect("Failed to initialize scan store")
    }
}

/// Storage statistics.
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Number of stored scans.
    pub scan_count: usize,
    /// Total size in bytes.
    pub total_size_bytes: u64,
    /// Oldest scan timestamp.
    pub oldest_scan: Option<DateTime<Utc>>,
    /// Newest scan timestamp.
    pub newest_scan: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::traits::PortStatus;
    use crate::types::Port;

    #[test]
    fn test_scan_record_creation() {
        let record = ScanRecord::new("192.168.1.1", "192.168.1.1", ScanType::Connect);
        assert_eq!(record.target, "192.168.1.1");
        assert_eq!(record.open_ports, 0);
    }

    #[test]
    fn test_scan_record_finalize() {
        let record = ScanRecord::new("example.com", "93.184.216.34", ScanType::Connect);
        let results = vec![
            PortResult::new(Port::new(80).unwrap(), PortStatus::Open, "http"),
            PortResult::new(Port::new(443).unwrap(), PortStatus::Open, "https"),
            PortResult::new(Port::new(22).unwrap(), PortStatus::Closed, "ssh"),
        ];

        let finalized = record.finalize(results, 1500);
        assert_eq!(finalized.ports_scanned, 3);
        assert_eq!(finalized.open_ports, 2);
        assert_eq!(finalized.closed_ports, 1);
    }

    #[test]
    fn test_scan_record_serialization() {
        let record = ScanRecord::new("test", "127.0.0.1", ScanType::Connect);
        let json = serde_json::to_string(&record).unwrap();
        let parsed: ScanRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target, record.target);
    }
}
