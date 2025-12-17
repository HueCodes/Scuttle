//! TCP Connect Scanner implementation.
//!
//! Performs standard TCP connect scans using the operating system's
//! socket API. This is the most reliable scanning method but also
//! the most detectable as it completes the full TCP handshake.

use crate::banner::grab_banner_from_stream;
use crate::error::{ScanError, ScanResult};
use crate::scanner::{PortResult, PortStatus};
use crate::services::get_service_description;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TCP Connect Scanner.
///
/// Uses standard socket connect() calls to determine port status.
/// Does not require elevated privileges.
pub struct TcpConnectScanner {
    target: IpAddr,
    timeout: Duration,
    grab_banners: bool,
}

impl TcpConnectScanner {
    /// Create a new TCP connect scanner.
    pub fn new(target: IpAddr, timeout: Duration, grab_banners: bool) -> Self {
        Self {
            target,
            timeout,
            grab_banners,
        }
    }

    /// Scan a single port.
    pub async fn scan_port(&self, port: u16) -> PortResult {
        let addr = SocketAddr::new(self.target, port);
        let service = get_service_description(port).to_string();

        match self.attempt_connect(addr).await {
            Ok(stream) => {
                let banner = if self.grab_banners {
                    grab_banner_from_stream(stream, port).await
                } else {
                    drop(stream);
                    None
                };

                PortResult {
                    port,
                    status: PortStatus::Open,
                    service,
                    banner,
                }
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

                PortResult {
                    port,
                    status,
                    service,
                    banner: None,
                }
            }
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
                    Err(ScanError::ConnectionFailed(e.to_string()))
                }
            }
            Err(_) => Err(ScanError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = TcpConnectScanner::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_secs(1),
            false,
        );
        assert_eq!(scanner.target, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
