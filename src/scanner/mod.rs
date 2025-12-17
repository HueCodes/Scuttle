//! Scanner module - coordinates different scanning techniques.
//!
//! This module provides a unified interface for TCP, SYN, and UDP scanning,
//! managing concurrent scanning tasks using the tokio runtime.

pub mod syn;
pub mod tcp;
pub mod udp;

use crate::cli::ScanType;
use crate::error::ScanResult;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub use syn::SynScanner;
pub use tcp::TcpConnectScanner;
pub use udp::UdpScanner;

/// Status of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    /// Port is open (service listening)
    Open,
    /// Port is closed (no service, RST received)
    Closed,
    /// Port is filtered (no response, possibly by firewall)
    Filtered,
    /// Port is either open or filtered (UDP-specific)
    #[serde(rename = "open|filtered")]
    OpenFiltered,
}

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortStatus::Open => write!(f, "open"),
            PortStatus::Closed => write!(f, "closed"),
            PortStatus::Filtered => write!(f, "filtered"),
            PortStatus::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

/// Result of scanning a single port.
#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub status: PortStatus,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// Complete scan results.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResults {
    pub target: String,
    pub ip_address: String,
    pub scan_type: String,
    pub ports_scanned: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub duration_ms: u64,
    pub results: Vec<PortResult>,
}

/// Configuration for a scan.
pub struct ScanConfig {
    pub target: IpAddr,
    pub target_hostname: String,
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
    pub concurrency: usize,
    pub timeout: Duration,
    pub grab_banners: bool,
    pub show_closed: bool,
    pub verbose: bool,
    pub interface: Option<String>,
}

/// Execute a complete port scan.
pub async fn run_scan(config: ScanConfig) -> ScanResult<ScanResults> {
    let start_time = Instant::now();
    let total_ports = config.ports.len();

    // Set up progress bar
    let progress = if config.verbose {
        let pb = ProgressBar::new(total_ports as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Create semaphore for bounded concurrency
    let semaphore = Arc::new(Semaphore::new(config.concurrency));

    let results: Vec<PortResult> = match config.scan_type {
        ScanType::Connect => {
            let scanner = Arc::new(TcpConnectScanner::new(
                config.target,
                config.timeout,
                config.grab_banners,
            ));

            scan_with_scanner(
                config.ports,
                semaphore,
                progress.as_ref(),
                move |port| {
                    let scanner = Arc::clone(&scanner);
                    async move { scanner.scan_port(port).await }
                },
            )
            .await
        }
        ScanType::Syn => {
            let scanner = Arc::new(
                SynScanner::new(config.target, config.interface.as_deref(), config.timeout)
                    .map_err(|e| {
                        eprintln!("\nSYN scan error: {}", e);
                        eprintln!("Hint: SYN scanning requires root/sudo privileges.");
                        eprintln!("Try: sudo scuttle {} -s syn", config.target_hostname);
                        e
                    })?,
            );

            scan_with_scanner(
                config.ports,
                semaphore,
                progress.as_ref(),
                move |port| {
                    let scanner = Arc::clone(&scanner);
                    async move { scanner.scan_port(port).await }
                },
            )
            .await
        }
        ScanType::Udp => {
            let scanner = Arc::new(UdpScanner::new(config.target, config.timeout));

            scan_with_scanner(
                config.ports,
                semaphore,
                progress.as_ref(),
                move |port| {
                    let scanner = Arc::clone(&scanner);
                    async move { scanner.scan_port(port).await }
                },
            )
            .await
        }
    };

    if let Some(pb) = progress {
        pb.finish_with_message("Scan complete");
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

    // Count statistics
    let open_count = filtered_results
        .iter()
        .filter(|r| r.status == PortStatus::Open || r.status == PortStatus::OpenFiltered)
        .count();
    let closed_count = filtered_results
        .iter()
        .filter(|r| r.status == PortStatus::Closed)
        .count();
    let filtered_count = filtered_results
        .iter()
        .filter(|r| r.status == PortStatus::Filtered)
        .count();

    let duration = start_time.elapsed();

    Ok(ScanResults {
        target: config.target_hostname,
        ip_address: config.target.to_string(),
        scan_type: config.scan_type.to_string(),
        ports_scanned: total_ports,
        open_ports: open_count,
        closed_ports: closed_count,
        filtered_ports: filtered_count,
        duration_ms: duration.as_millis() as u64,
        results: filtered_results,
    })
}

/// Generic scan executor with bounded concurrency.
async fn scan_with_scanner<F, Fut>(
    ports: Vec<u16>,
    semaphore: Arc<Semaphore>,
    progress: Option<&ProgressBar>,
    scanner_fn: F,
) -> Vec<PortResult>
where
    F: Fn(u16) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = PortResult> + Send,
{
    stream::iter(ports)
        .map(|port| {
            let sem = Arc::clone(&semaphore);
            let scanner = scanner_fn.clone();
            let progress = progress.cloned();

            async move {
                // Acquire semaphore permit
                let _permit = sem.acquire().await.unwrap();

                let result = scanner(port).await;

                // Update progress
                if let Some(ref pb) = progress {
                    pb.inc(1);
                    if result.status == PortStatus::Open {
                        pb.set_message(format!("Found open port: {}", port));
                    }
                }

                result
            }
        })
        .buffer_unordered(1000) // Allow high buffering, semaphore controls actual concurrency
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_status_display() {
        assert_eq!(PortStatus::Open.to_string(), "open");
        assert_eq!(PortStatus::Closed.to_string(), "closed");
        assert_eq!(PortStatus::Filtered.to_string(), "filtered");
    }
}
