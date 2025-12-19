//! TCP Connect Scanner implementation.
//!
//! Performs standard TCP connect scans using the operating system's
//! socket API. This is the most reliable scanning method but also
//! the most detectable as it completes the full TCP handshake.

use crate::banner::grab_banner_from_stream;
use crate::error::{ScanError, ScanResult};
use crate::scanner::traits::{PortResult, PortStatus, ScanType, Scanner};
use crate::services::get_service_description;
use crate::types::Port;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TCP Connect Scanner.
///
/// Uses standard socket connect() calls to determine port status.
/// Does not require elevated privileges.
///
/// # Performance Characteristics
///
/// - **Reliability**: High - uses OS-level connection establishment
/// - **Stealth**: Low - completes full TCP handshake, easily logged
/// - **Speed**: Good - fully async with configurable concurrency
/// - **Privileges**: None required
pub struct TcpConnectScanner {
    target: IpAddr,
    timeout: Duration,
    grab_banners: bool,
}

impl TcpConnectScanner {
    /// Create a new TCP connect scanner.
    ///
    /// # Arguments
    /// * `target` - Target IP address to scan
    /// * `timeout` - Connection timeout per port
    /// * `grab_banners` - Whether to attempt banner grabbing on open ports
    pub fn new(target: IpAddr, timeout: Duration, grab_banners: bool) -> Self {
        Self {
            target,
            timeout,
            grab_banners,
        }
    }

    /// Attempt to connect to the target address.
    async fn attempt_connect(&self, addr: SocketAddr) -> ScanResult<TcpStream> {
        match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("refused") {
                    Err(ScanError::ConnectionRefused)
                } else if error_str.contains("unreachable") {
                    if error_str.contains("host") {
                        Err(ScanError::HostUnreachable)
                    } else {
                        Err(ScanError::NetworkUnreachable(e.to_string()))
                    }
                } else {
                    Err(ScanError::ConnectionFailed {
                        target: self.target.to_string(),
                        port: addr.port(),
                        reason: e.to_string(),
                    })
                }
            }
            Err(_) => Err(ScanError::Timeout),
        }
    }
}

#[async_trait]
impl Scanner for TcpConnectScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Connect
    }

    fn requires_privileges(&self) -> bool {
        false
    }

    fn target(&self) -> IpAddr {
        self.target
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn scan_port(&self, port: Port) -> PortResult {
        let port_num = port.as_u16();
        let addr = SocketAddr::new(self.target, port_num);
        let service = get_service_description(port_num).to_string();
        let start = Instant::now();

        match self.attempt_connect(addr).await {
            Ok(stream) => {
                let response_time = start.elapsed().as_millis() as u64;
                let banner = if self.grab_banners {
                    grab_banner_from_stream(stream, port_num).await
                } else {
                    drop(stream);
                    None
                };

                PortResult::new(port, PortStatus::Open, service)
                    .with_banner(banner)
                    .with_response_time(response_time)
            }
            Err(e) => {
                let status = match e {
                    ScanError::ConnectionRefused => PortStatus::Closed,
                    ScanError::Timeout => PortStatus::Filtered,
                    ScanError::HostUnreachable | ScanError::NetworkUnreachable(_) => {
                        PortStatus::Filtered
                    }
                    _ => PortStatus::Closed,
                };

                PortResult::new(port, status, service)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_scanner_creation() {
        let scanner = TcpConnectScanner::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_secs(1),
            false,
        );
        assert_eq!(scanner.target, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(!scanner.requires_privileges());
        assert_eq!(scanner.scan_type(), ScanType::Connect);
    }

    #[tokio::test]
    async fn test_scan_closed_port() {
        let scanner = TcpConnectScanner::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(100),
            false,
        );

        // Port 1 is almost certainly closed
        let port = Port::new(1).unwrap();
        let result = scanner.scan_port(port).await;

        // Should be closed or filtered (depending on firewall)
        assert!(matches!(
            result.status,
            PortStatus::Closed | PortStatus::Filtered
        ));
    }
}
