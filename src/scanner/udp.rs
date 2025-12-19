//! UDP Scanner implementation.
//!
//! Performs UDP port scanning by sending UDP packets and analyzing
//! responses (or lack thereof). UDP scanning is inherently less reliable
//! than TCP scanning due to the connectionless nature of UDP.
//!
//! # Detection Methods
//!
//! 1. **ICMP Port Unreachable**: If received, port is definitely closed
//! 2. **UDP Response**: If any data is received, port is open
//! 3. **No Response**: Port is either open or filtered (ambiguous)
//!
//! # Privileges
//!
//! Root/sudo privileges are required to receive ICMP messages.

use crate::error::{ScanError, ScanResult};
use crate::scanner::traits::{PortResult, PortStatus, ScanType, Scanner};
use crate::services::get_service_description;
use crate::types::Port;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Known UDP service probes for better detection.
struct UdpProbe {
    port: u16,
    payload: &'static [u8],
}

/// Common UDP service probes.
const UDP_PROBES: &[UdpProbe] = &[
    // DNS query for version.bind
    UdpProbe {
        port: 53,
        payload: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    },
    // SNMP get-request
    UdpProbe {
        port: 161,
        payload: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04",
    },
    // NTP version request
    UdpProbe {
        port: 123,
        payload: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00",
    },
    // TFTP read request
    UdpProbe {
        port: 69,
        payload: b"\x00\x01test\x00netascii\x00",
    },
    // NetBIOS name query
    UdpProbe {
        port: 137,
        payload: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    },
];

/// Default probe for unknown ports.
const DEFAULT_PROBE: &[u8] = b"\x00";

/// UDP Scanner for detecting open UDP ports.
///
/// # Performance Characteristics
///
/// - **Reliability**: Low - UDP is connectionless
/// - **Stealth**: Medium - may be logged by firewalls
/// - **Speed**: Slow - requires waiting for timeouts
/// - **Privileges**: Root for ICMP detection
pub struct UdpScanner {
    target: IpAddr,
    timeout: Duration,
    retries: u32,
}

impl UdpScanner {
    /// Create a new UDP scanner.
    ///
    /// # Arguments
    /// * `target` - Target IP address
    /// * `timeout` - How long to wait for responses
    pub fn new(target: IpAddr, timeout: Duration) -> Self {
        Self {
            target,
            timeout,
            retries: 2, // UDP is unreliable, retry a few times
        }
    }

    /// Send probe and wait for response.
    async fn probe_port(&self, port: u16) -> ScanResult<PortStatus> {
        let addr = SocketAddr::new(self.target, port);

        // Bind to random local port
        let local_addr: SocketAddr = if self.target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| ScanError::ConnectionFailed {
                target: self.target.to_string(),
                port,
                reason: e.to_string(),
            })?;

        socket.connect(addr).await.map_err(|e| ScanError::ConnectionFailed {
            target: self.target.to_string(),
            port,
            reason: e.to_string(),
        })?;

        let probe = get_probe_for_port(port);

        for attempt in 0..self.retries {
            // Send probe
            socket.send(probe).await.map_err(|e| ScanError::ConnectionFailed {
                target: self.target.to_string(),
                port,
                reason: e.to_string(),
            })?;

            // Wait for response
            let mut buf = [0u8; 1024];
            match timeout(self.timeout, socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    // Got a response - port is open
                    return Ok(PortStatus::Open);
                }
                Ok(Err(e)) => {
                    let err_str = e.to_string().to_lowercase();
                    if err_str.contains("refused") || err_str.contains("unreachable") {
                        // ICMP error - port is closed
                        return Ok(PortStatus::Closed);
                    }
                }
                Err(_) => {
                    // Timeout - might be open or filtered
                    // Continue to next retry
                }
                _ => {}
            }

            // Brief delay between retries
            if attempt < self.retries - 1 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        // No response after retries - open|filtered
        Ok(PortStatus::OpenFiltered)
    }
}

#[async_trait]
impl Scanner for UdpScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Udp
    }

    fn requires_privileges(&self) -> bool {
        true // For ICMP detection
    }

    fn target(&self) -> IpAddr {
        self.target
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn scan_port(&self, port: Port) -> PortResult {
        let port_num = port.as_u16();
        let service = get_service_description(port_num).to_string();

        let status = match self.probe_port(port_num).await {
            Ok(status) => status,
            Err(_) => PortStatus::Filtered,
        };

        PortResult::new(port, status, service)
    }
}

/// Get the appropriate probe payload for a port.
fn get_probe_for_port(port: u16) -> &'static [u8] {
    UDP_PROBES
        .iter()
        .find(|p| p.port == port)
        .map(|p| p.payload)
        .unwrap_or(DEFAULT_PROBE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_probe_selection() {
        assert_eq!(get_probe_for_port(53).len(), 12); // DNS probe
        assert_eq!(get_probe_for_port(12345), DEFAULT_PROBE); // Unknown port
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = UdpScanner::new(IpAddr::V4(Ipv4Addr::LOCALHOST), Duration::from_secs(1));
        assert_eq!(scanner.target, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(scanner.requires_privileges());
        assert_eq!(scanner.scan_type(), ScanType::Udp);
    }
}
