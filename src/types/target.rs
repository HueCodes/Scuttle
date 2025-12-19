//! Target specification types with CIDR and hostname support.
//!
//! Provides flexible target parsing supporting:
//! - Single IP addresses (IPv4 and IPv6)
//! - CIDR notation (192.168.1.0/24)
//! - Hostnames (example.com)
//! - Multiple targets

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// A single scan target that has been resolved to an IP address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanTarget {
    /// The original input (hostname or IP string).
    pub original: String,
    /// The resolved IP address.
    pub ip: IpAddr,
}

impl ScanTarget {
    /// Create a new scan target.
    pub fn new(original: impl Into<String>, ip: IpAddr) -> Self {
        Self {
            original: original.into(),
            ip,
        }
    }

    /// Check if this target is IPv6.
    pub fn is_ipv6(&self) -> bool {
        self.ip.is_ipv6()
    }

    /// Check if this target is IPv4.
    pub fn is_ipv4(&self) -> bool {
        self.ip.is_ipv4()
    }
}

impl fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.original == self.ip.to_string() {
            write!(f, "{}", self.ip)
        } else {
            write!(f, "{} ({})", self.original, self.ip)
        }
    }
}

/// Error type for target parsing and resolution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TargetError {
    #[error("invalid target format: {0}")]
    InvalidFormat(String),
    #[error("failed to resolve hostname '{0}': {1}")]
    DnsResolutionFailed(String, String),
    #[error("no IP addresses found for hostname '{0}'")]
    NoAddressesFound(String),
    #[error("invalid CIDR notation: {0}")]
    InvalidCidr(String),
    #[error("CIDR range too large: {0} addresses (max: {1})")]
    CidrTooLarge(u128, u128),
}

/// A target specification that may contain multiple targets.
///
/// Supports:
/// - Single IP: "192.168.1.1"
/// - CIDR: "192.168.1.0/24"
/// - Hostname: "example.com"
/// - IPv6: "::1", "2001:db8::/32"
#[derive(Debug, Clone)]
pub enum TargetSpec {
    /// A single IP address.
    Single(IpAddr),
    /// A CIDR network range.
    Cidr(IpNetwork),
    /// A hostname to be resolved.
    Hostname(String),
}

impl TargetSpec {
    /// Maximum number of hosts allowed in a CIDR range.
    pub const MAX_CIDR_HOSTS: u128 = 65536; // /16 for IPv4

    /// Parse a target specification from a string.
    pub fn parse(s: &str) -> Result<Self, TargetError> {
        let s = s.trim();

        // Try parsing as IP address first
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Single(ip));
        }

        // Try parsing as CIDR
        if s.contains('/') {
            let network: IpNetwork = s
                .parse()
                .map_err(|_| TargetError::InvalidCidr(s.to_string()))?;

            let host_count = match network {
                IpNetwork::V4(net) => net.size() as u128,
                IpNetwork::V6(net) => {
                    let prefix = net.prefix() as u32;
                    if prefix >= 128 { 1 } else { 1u128 << (128 - prefix) }
                }
            };
            if host_count > Self::MAX_CIDR_HOSTS {
                return Err(TargetError::CidrTooLarge(host_count, Self::MAX_CIDR_HOSTS));
            }

            return Ok(Self::Cidr(network));
        }

        // Assume it's a hostname
        if is_valid_hostname(s) {
            return Ok(Self::Hostname(s.to_string()));
        }

        Err(TargetError::InvalidFormat(s.to_string()))
    }

    /// Resolve this target specification to a list of scan targets.
    ///
    /// For CIDR ranges, this expands to all host addresses.
    /// For hostnames, this performs DNS resolution.
    pub async fn resolve(&self) -> Result<Vec<ScanTarget>, TargetError> {
        match self {
            Self::Single(ip) => Ok(vec![ScanTarget::new(ip.to_string(), *ip)]),

            Self::Cidr(network) => {
                let original = network.to_string();
                let targets: Vec<ScanTarget> = network
                    .iter()
                    .filter(|ip| {
                        // Filter out network and broadcast addresses for IPv4
                        if let (IpNetwork::V4(net), IpAddr::V4(addr)) = (network, ip) {
                            if net.prefix() < 31 {
                                let network_addr = net.network();
                                let broadcast = net.broadcast();
                                return *addr != network_addr && *addr != broadcast;
                            }
                        }
                        true
                    })
                    .map(|ip| ScanTarget::new(original.clone(), ip))
                    .collect();
                Ok(targets)
            }

            Self::Hostname(hostname) => {
                let resolver = TokioAsyncResolver::tokio(
                    ResolverConfig::default(),
                    ResolverOpts::default(),
                );

                let response = resolver.lookup_ip(hostname.as_str()).await.map_err(|e| {
                    TargetError::DnsResolutionFailed(hostname.clone(), e.to_string())
                })?;

                let ips: Vec<IpAddr> = response.iter().collect();
                if ips.is_empty() {
                    return Err(TargetError::NoAddressesFound(hostname.clone()));
                }

                // Return only the first IP (most common use case)
                // Users can specify --all-ips flag if they want all resolved IPs
                Ok(vec![ScanTarget::new(hostname.clone(), ips[0])])
            }
        }
    }

    /// Get an estimate of how many hosts this target represents.
    pub fn estimated_host_count(&self) -> u128 {
        match self {
            Self::Single(_) => 1,
            Self::Cidr(network) => match network {
                IpNetwork::V4(net) => net.size() as u128,
                IpNetwork::V6(net) => {
                    let prefix = net.prefix() as u32;
                    if prefix >= 128 { 1 } else { 1u128 << (128 - prefix) }
                }
            },
            Self::Hostname(_) => 1, // Assume single host until resolved
        }
    }
}

impl FromStr for TargetSpec {
    type Err = TargetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for TargetSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(ip) => write!(f, "{}", ip),
            Self::Cidr(network) => write!(f, "{}", network),
            Self::Hostname(hostname) => write!(f, "{}", hostname),
        }
    }
}

/// Check if a string is a valid hostname.
fn is_valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }

    // Must contain at least one dot for a proper hostname (but allow single-label for local)
    // Each label must be 1-63 characters
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        // Must start and end with alphanumeric
        if !label.chars().next().map_or(false, |c| c.is_alphanumeric()) {
            return false;
        }
        if !label.chars().last().map_or(false, |c| c.is_alphanumeric()) {
            return false;
        }
        // Can only contain alphanumeric and hyphens
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let spec = TargetSpec::parse("192.168.1.1").unwrap();
        assert!(matches!(spec, TargetSpec::Single(IpAddr::V4(_))));
    }

    #[test]
    fn test_parse_ipv6() {
        let spec = TargetSpec::parse("::1").unwrap();
        assert!(matches!(spec, TargetSpec::Single(IpAddr::V6(_))));
    }

    #[test]
    fn test_parse_cidr_v4() {
        let spec = TargetSpec::parse("192.168.1.0/24").unwrap();
        if let TargetSpec::Cidr(network) = spec {
            assert_eq!(network.prefix(), 24);
        } else {
            panic!("Expected CIDR");
        }
    }

    #[test]
    fn test_parse_hostname() {
        let spec = TargetSpec::parse("example.com").unwrap();
        assert!(matches!(spec, TargetSpec::Hostname(_)));
    }

    #[test]
    fn test_cidr_too_large() {
        // /8 would be 16M hosts - too large
        let result = TargetSpec::parse("10.0.0.0/8");
        assert!(matches!(result, Err(TargetError::CidrTooLarge(_, _))));
    }

    #[test]
    fn test_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("sub.example.com"));
        assert!(is_valid_hostname("my-server"));
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-invalid.com"));
    }
}
