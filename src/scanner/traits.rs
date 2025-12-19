//! Scanner trait abstraction.
//!
//! Defines a common interface for all scanner implementations,
//! enabling polymorphism and easier testing.

use crate::types::Port;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// Status of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    /// Port is open (service listening).
    Open,
    /// Port is closed (no service, RST received).
    Closed,
    /// Port is filtered (no response, possibly by firewall).
    Filtered,
    /// Port is either open or filtered (UDP-specific ambiguity).
    #[serde(rename = "open|filtered")]
    OpenFiltered,
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
            Self::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

/// Result of scanning a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// The port number that was scanned.
    pub port: Port,
    /// Status determined by the scan.
    pub status: PortStatus,
    /// Detected or inferred service name.
    pub service: String,
    /// Banner captured from the service (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Response time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,
}

impl PortResult {
    /// Create a new port result.
    pub fn new(port: Port, status: PortStatus, service: impl Into<String>) -> Self {
        Self {
            port,
            status,
            service: service.into(),
            banner: None,
            response_time_ms: None,
        }
    }

    /// Set the banner.
    pub fn with_banner(mut self, banner: Option<String>) -> Self {
        self.banner = banner;
        self
    }

    /// Set the response time.
    pub fn with_response_time(mut self, time_ms: u64) -> Self {
        self.response_time_ms = Some(time_ms);
        self
    }

    /// Check if the port is open.
    pub fn is_open(&self) -> bool {
        matches!(self.status, PortStatus::Open | PortStatus::OpenFiltered)
    }
}

/// Available scan types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    /// TCP connect scan (default, no special privileges required).
    Connect,
    /// SYN stealth scan (requires root/admin privileges).
    Syn,
    /// UDP scan (requires root/admin privileges for ICMP detection).
    Udp,
}

impl Default for ScanType {
    fn default() -> Self {
        Self::Connect
    }
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => write!(f, "TCP Connect"),
            Self::Syn => write!(f, "SYN Stealth"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

impl std::str::FromStr for ScanType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "connect" | "tcp" => Ok(Self::Connect),
            "syn" | "stealth" => Ok(Self::Syn),
            "udp" => Ok(Self::Udp),
            _ => Err(format!("unknown scan type: {}", s)),
        }
    }
}

/// Configuration for a scan operation.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Target IP address.
    pub target: IpAddr,
    /// Original target specification (hostname if resolved).
    pub target_hostname: String,
    /// Connection/response timeout.
    pub timeout: Duration,
    /// Whether to attempt banner grabbing.
    pub grab_banners: bool,
    /// Network interface to use (for raw socket scans).
    pub interface: Option<String>,
}

impl ScanConfig {
    /// Create a new scan configuration.
    pub fn new(target: IpAddr) -> Self {
        Self {
            target,
            target_hostname: target.to_string(),
            timeout: Duration::from_secs(3),
            grab_banners: false,
            interface: None,
        }
    }

    /// Set the target hostname.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.target_hostname = hostname.into();
        self
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable banner grabbing.
    pub fn with_banners(mut self) -> Self {
        self.grab_banners = true;
        self
    }

    /// Set the network interface.
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }
}

/// Trait for port scanner implementations.
///
/// This trait abstracts the scanning mechanism, allowing for different
/// implementations (TCP connect, SYN, UDP) to be used interchangeably.
///
/// # Example
///
/// ```ignore
/// use scuttle::scanner::{Scanner, ScanConfig, PortResult};
///
/// async fn scan_port<S: Scanner>(scanner: &S, port: Port) -> PortResult {
///     scanner.scan_port(port).await
/// }
/// ```
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Get the scan type this scanner implements.
    fn scan_type(&self) -> ScanType;

    /// Check if this scanner requires elevated privileges.
    fn requires_privileges(&self) -> bool;

    /// Scan a single port.
    async fn scan_port(&self, port: Port) -> PortResult;

    /// Scan multiple ports concurrently.
    ///
    /// Default implementation scans each port individually.
    /// Implementations may override for batch optimizations.
    async fn scan_ports(&self, ports: &[Port]) -> Vec<PortResult> {
        let mut results = Vec::with_capacity(ports.len());
        for &port in ports {
            results.push(self.scan_port(port).await);
        }
        results
    }

    /// Get the target IP address.
    fn target(&self) -> IpAddr;

    /// Get the configured timeout.
    fn timeout(&self) -> Duration;
}

/// A boxed scanner for dynamic dispatch.
pub type BoxedScanner = Box<dyn Scanner>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_status_display() {
        assert_eq!(PortStatus::Open.to_string(), "open");
        assert_eq!(PortStatus::Closed.to_string(), "closed");
        assert_eq!(PortStatus::Filtered.to_string(), "filtered");
        assert_eq!(PortStatus::OpenFiltered.to_string(), "open|filtered");
    }

    #[test]
    fn test_scan_type_from_str() {
        assert_eq!("connect".parse::<ScanType>().unwrap(), ScanType::Connect);
        assert_eq!("syn".parse::<ScanType>().unwrap(), ScanType::Syn);
        assert_eq!("udp".parse::<ScanType>().unwrap(), ScanType::Udp);
    }

    #[test]
    fn test_port_result() {
        let port = Port::new(80).unwrap();
        let result = PortResult::new(port, PortStatus::Open, "http")
            .with_banner(Some("Apache/2.4".to_string()))
            .with_response_time(15);

        assert!(result.is_open());
        assert_eq!(result.banner, Some("Apache/2.4".to_string()));
        assert_eq!(result.response_time_ms, Some(15));
    }
}
