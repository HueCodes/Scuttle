//! Scanner module - coordinates different scanning techniques.
//!
//! This module provides a unified interface for TCP, SYN, and UDP scanning,
//! managing concurrent scanning tasks using the tokio runtime.

pub mod rate_limiter;
pub mod syn;
pub mod tcp;
pub mod traits;
pub mod udp;

pub use rate_limiter::RateLimiter;
pub use syn::SynScanner;
pub use tcp::TcpConnectScanner;
pub use traits::{PortResult, PortStatus, ScanConfig, ScanType, Scanner};
pub use udp::UdpScanner;

use crate::error::ScanResult;
use crate::storage::ScanRecord;
use crate::types::Port;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Configuration for a complete scan job.
#[derive(Debug, Clone)]
pub struct ScanJobConfig {
    /// Ports to scan.
    pub ports: Vec<Port>,
    /// Maximum concurrent connections.
    pub concurrency: usize,
    /// Show verbose output with progress bar.
    pub verbose: bool,
    /// Include closed ports in results.
    pub show_closed: bool,
    /// Rate limit in packets per second (0 = unlimited).
    pub rate_limit: u32,
}

impl Default for ScanJobConfig {
    fn default() -> Self {
        Self {
            ports: Vec::new(),
            concurrency: 500,
            verbose: false,
            show_closed: false,
            rate_limit: 0,
        }
    }
}

impl ScanJobConfig {
    /// Create a new job config with the given ports.
    pub fn new(ports: Vec<Port>) -> Self {
        Self {
            ports,
            ..Default::default()
        }
    }

    /// Set concurrency level.
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Enable verbose mode.
    pub fn with_verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Show closed ports.
    pub fn with_closed(mut self) -> Self {
        self.show_closed = true;
        self
    }

    /// Set rate limit.
    pub fn with_rate_limit(mut self, rate: u32) -> Self {
        self.rate_limit = rate;
        self
    }
}

/// Execute a complete port scan using the provided scanner.
pub async fn run_scan(
    scanner: Arc<dyn Scanner>,
    config: ScanJobConfig,
) -> ScanResult<ScanRecord> {
    let start_time = Instant::now();
    let total_ports = config.ports.len();
    let scan_type = scanner.scan_type();
    let target = scanner.target();

    // Set up progress bar
    let progress = if config.verbose {
        let pb = ProgressBar::new(total_ports as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );
        pb.set_message("Starting scan...");
        Some(pb)
    } else {
        None
    };

    // Create semaphore for bounded concurrency
    let semaphore = Arc::new(Semaphore::new(config.concurrency));

    // Create rate limiter if needed
    let rate_limiter = if config.rate_limit > 0 {
        Some(Arc::new(RateLimiter::new(config.rate_limit)))
    } else {
        None
    };

    // Execute concurrent scans
    let results: Vec<PortResult> = stream::iter(config.ports.clone())
        .map(|port| {
            let sem = Arc::clone(&semaphore);
            let scanner = Arc::clone(&scanner);
            let limiter = rate_limiter.clone();
            let progress = progress.clone();

            async move {
                // Acquire semaphore permit for concurrency control
                let _permit = sem.acquire().await.unwrap();

                // Apply rate limiting if configured
                if let Some(ref limiter) = limiter {
                    limiter.wait().await;
                }

                let result = scanner.scan_port(port).await;

                // Update progress bar
                if let Some(ref pb) = progress {
                    pb.inc(1);
                    if result.status == PortStatus::Open {
                        pb.set_message(format!("Found: {}/tcp open", port));
                    }
                }

                result
            }
        })
        .buffer_unordered(config.concurrency.min(1000))
        .collect()
        .await;

    if let Some(pb) = progress {
        pb.finish_with_message(format!(
            "Scan complete - {} open ports found",
            results.iter().filter(|r| r.is_open()).count()
        ));
    }

    // Filter and sort results
    let mut filtered_results: Vec<PortResult> = if config.show_closed {
        results
    } else {
        results
            .into_iter()
            .filter(|r| r.status != PortStatus::Closed)
            .collect()
    };
    filtered_results.sort_by_key(|r| r.port);

    let duration = start_time.elapsed();

    // Create scan record
    let record = ScanRecord::new(target.to_string(), target.to_string(), scan_type)
        .finalize(filtered_results, duration.as_millis() as u64);

    Ok(record)
}

/// Create a scanner based on scan type and configuration.
pub fn create_scanner(
    scan_type: ScanType,
    config: ScanConfig,
) -> ScanResult<Arc<dyn Scanner>> {
    match scan_type {
        ScanType::Connect => Ok(Arc::new(TcpConnectScanner::new(
            config.target,
            config.timeout,
            config.grab_banners,
        ))),
        ScanType::Syn => {
            let scanner = SynScanner::new(
                config.target,
                config.interface.as_deref(),
                config.timeout,
            )?;
            Ok(Arc::new(scanner))
        }
        ScanType::Udp => Ok(Arc::new(UdpScanner::new(config.target, config.timeout))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_job_config() {
        let config = ScanJobConfig::new(vec![Port::new(80).unwrap(), Port::new(443).unwrap()])
            .with_concurrency(100)
            .with_verbose()
            .with_rate_limit(1000);

        assert_eq!(config.ports.len(), 2);
        assert_eq!(config.concurrency, 100);
        assert!(config.verbose);
        assert_eq!(config.rate_limit, 1000);
    }

    #[test]
    fn test_create_scanner() {
        use std::net::{IpAddr, Ipv4Addr};
        use std::time::Duration;

        let config = ScanConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .with_timeout(Duration::from_secs(1));

        let scanner = create_scanner(ScanType::Connect, config);
        assert!(scanner.is_ok());
    }
}
