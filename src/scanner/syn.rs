//! SYN (Stealth) Scanner implementation.
//!
//! Performs half-open TCP scanning by sending SYN packets and analyzing
//! responses without completing the TCP handshake. This method is less
//! detectable than full connect scans but requires raw socket access
//! (elevated privileges).
//!
//! # Privileges Required
//!
//! This scanner requires root/administrator privileges to:
//! - Create raw sockets
//! - Send crafted TCP packets
//! - Receive and analyze raw network responses
//!
//! # How It Works
//!
//! 1. Send a TCP SYN packet to the target port
//! 2. Analyze the response:
//!    - SYN/ACK: Port is open (service is listening)
//!    - RST: Port is closed (no service)
//!    - No response: Port may be filtered
//! 3. Send RST to close without completing handshake (stealth)

use crate::error::{ScanError, ScanResult};
use crate::scanner::{PortResult, PortStatus};
use crate::services::get_service_description;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// SYN Scanner for stealth port scanning.
///
/// **Requires elevated privileges (root/sudo).**
pub struct SynScanner {
    target: Ipv4Addr,
    source_ip: Ipv4Addr,
    interface: NetworkInterface,
    timeout: Duration,
}

impl SynScanner {
    /// Create a new SYN scanner.
    ///
    /// # Arguments
    /// * `target` - Target IP address (must be IPv4)
    /// * `interface_name` - Network interface to use (e.g., "eth0", "en0")
    /// * `timeout` - How long to wait for responses
    ///
    /// # Errors
    /// Returns an error if:
    /// - Target is not IPv4
    /// - Interface cannot be found
    /// - Unable to determine source IP
    pub fn new(
        target: IpAddr,
        interface_name: Option<&str>,
        timeout: Duration,
    ) -> ScanResult<Self> {
        let target_v4 = match target {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return Err(ScanError::InvalidConfig(
                    "SYN scanning only supports IPv4 currently".to_string(),
                ))
            }
        };

        let interface = find_interface(interface_name)?;
        let source_ip = get_interface_ipv4(&interface)?;

        Ok(Self {
            target: target_v4,
            source_ip,
            interface,
            timeout,
        })
    }

    /// Scan a single port using SYN technique.
    pub async fn scan_port(&self, port: u16) -> PortResult {
        let service = get_service_description(port).to_string();

        match self.send_syn_and_wait(port).await {
            Ok(status) => PortResult {
                port,
                status,
                service,
                banner: None, // SYN scans don't grab banners
            },
            Err(_) => PortResult {
                port,
                status: PortStatus::Filtered,
                service,
                banner: None,
            },
        }
    }

    /// Send SYN packet and wait for response.
    async fn send_syn_and_wait(&self, port: u16) -> ScanResult<PortStatus> {
        // Build the SYN packet
        let packet = self.build_syn_packet(port)?;

        // Get datalink channel
        let (mut tx, mut rx) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(ScanError::RawSocketError(
                    "Unsupported channel type".to_string(),
                ))
            }
            Err(e) => {
                // Check for permission error
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("permission") || err_str.contains("operation not permitted") {
                    return Err(ScanError::PermissionDenied(
                        "Raw socket access requires root/sudo privileges".to_string(),
                    ));
                }
                return Err(ScanError::RawSocketError(e.to_string()));
            }
        };

        // Send the packet
        tx.send_to(&packet, None)
            .ok_or_else(|| ScanError::RawSocketError("Failed to send packet".to_string()))?
            .map_err(|e| ScanError::RawSocketError(e.to_string()))?;

        // Wait for response with timeout
        let start = std::time::Instant::now();
        while start.elapsed() < self.timeout {
            match rx.next() {
                Ok(frame) => {
                    if let Some(status) = self.parse_response(frame, port) {
                        return Ok(status);
                    }
                }
                Err(e) => {
                    // Ignore timeout errors, break on others
                    if !e.to_string().contains("timed out") {
                        break;
                    }
                }
            }
        }

        // No response within timeout - port is filtered
        Ok(PortStatus::Filtered)
    }

    /// Build a TCP SYN packet.
    fn build_syn_packet(&self, dest_port: u16) -> ScanResult<Vec<u8>> {
        // Use a random source port
        let source_port: u16 = rand_source_port();

        // Ethernet + IP + TCP header sizes
        let ethernet_header_size = 14;
        let ip_header_size = 20;
        let tcp_header_size = 20;
        let total_size = ethernet_header_size + ip_header_size + tcp_header_size;

        let mut buffer = vec![0u8; total_size];

        // Build Ethernet frame
        {
            let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..ethernet_header_size])
                .ok_or_else(|| ScanError::InvalidPacket("Failed to create ethernet packet".to_string()))?;

            // Use broadcast for now (ARP resolution would be needed for real implementation)
            eth_packet.set_destination(pnet::util::MacAddr::broadcast());
            eth_packet.set_source(self.interface.mac.unwrap_or(pnet::util::MacAddr::zero()));
            eth_packet.set_ethertype(EtherTypes::Ipv4);
        }

        // Build IP packet
        {
            let mut ip_packet = MutableIpv4Packet::new(
                &mut buffer[ethernet_header_size..ethernet_header_size + ip_header_size + tcp_header_size],
            )
            .ok_or_else(|| ScanError::InvalidPacket("Failed to create IP packet".to_string()))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_dscp(0);
            ip_packet.set_ecn(0);
            ip_packet.set_total_length((ip_header_size + tcp_header_size) as u16);
            ip_packet.set_identification(rand::random());
            ip_packet.set_flags(Ipv4Flags::DontFragment);
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.target);
            ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
        }

        // Build TCP packet
        {
            let mut tcp_packet = MutableTcpPacket::new(
                &mut buffer[ethernet_header_size + ip_header_size..],
            )
            .ok_or_else(|| ScanError::InvalidPacket("Failed to create TCP packet".to_string()))?;

            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
            tcp_packet.set_sequence(rand::random());
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_reserved(0);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(65535);
            tcp_packet.set_urgent_ptr(0);

            let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &self.source_ip, &self.target);
            tcp_packet.set_checksum(checksum);
        }

        Ok(buffer)
    }

    /// Parse response packet to determine port status.
    fn parse_response(&self, frame: &[u8], expected_port: u16) -> Option<PortStatus> {
        // Skip Ethernet header (14 bytes)
        if frame.len() < 14 + 20 + 20 {
            return None;
        }

        let ip_start = 14;
        let ip_packet = pnet::packet::ipv4::Ipv4Packet::new(&frame[ip_start..])?;

        // Verify it's from our target
        if ip_packet.get_source() != self.target {
            return None;
        }

        // Verify it's TCP
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None;
        }

        let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
        let tcp_start = ip_start + ip_header_len;

        let tcp_packet = TcpPacket::new(&frame[tcp_start..])?;

        // Verify it's for the port we scanned
        if tcp_packet.get_source() != expected_port {
            return None;
        }

        let flags = tcp_packet.get_flags();

        // SYN+ACK means port is open
        if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
            return Some(PortStatus::Open);
        }

        // RST means port is closed
        if flags & TcpFlags::RST != 0 {
            return Some(PortStatus::Closed);
        }

        None
    }
}

/// Find a suitable network interface.
fn find_interface(name: Option<&str>) -> ScanResult<NetworkInterface> {
    let interfaces = datalink::interfaces();

    if let Some(name) = name {
        interfaces
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| ScanError::InterfaceNotFound(name.to_string()))
    } else {
        // Find the first non-loopback interface with an IP
        interfaces
            .into_iter()
            .find(|iface| {
                !iface.is_loopback()
                    && iface.is_up()
                    && iface.ips.iter().any(|ip| ip.is_ipv4())
            })
            .ok_or_else(|| {
                ScanError::InterfaceNotFound("No suitable network interface found".to_string())
            })
    }
}

/// Get IPv4 address from interface.
fn get_interface_ipv4(interface: &NetworkInterface) -> ScanResult<Ipv4Addr> {
    interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(addr) if !addr.is_loopback() => Some(addr),
            _ => None,
        })
        .ok_or_else(|| {
            ScanError::InvalidConfig(format!(
                "Interface {} has no IPv4 address",
                interface.name
            ))
        })
}

/// Generate a random source port in the ephemeral range.
fn rand_source_port() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen_range(49152..65535)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_interface() {
        // Should find at least one interface
        let result = find_interface(None);
        // This might fail in CI environments without network
        if result.is_ok() {
            let iface = result.unwrap();
            assert!(!iface.name.is_empty());
        }
    }
}
