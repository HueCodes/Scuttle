//! Command-line interface definitions for Scuttle.
//!
//! Uses `clap` derive macros for declarative argument parsing.

use clap::{Parser, ValueEnum};
use std::net::IpAddr;

/// A high-performance network port scanner written in Rust.
#[derive(Parser, Debug)]
#[command(name = "scuttle")]
#[command(author = "HueCodes <huecodes@proton.me>")]
#[command(version = "0.1.0")]
#[command(about = "A fast, versatile port scanner", long_about = None)]
pub struct Args {
    /// Target IP address or hostname to scan
    #[arg(value_name = "TARGET")]
    pub target: String,

    /// Ports to scan (e.g., "80", "80,443", "1-1000", "22,80,443,8000-9000")
    #[arg(short, long, default_value = "1-1000")]
    pub ports: String,

    /// Scan type to use
    #[arg(short = 's', long = "scan-type", value_enum, default_value = "connect")]
    pub scan_type: ScanType,

    /// Maximum number of concurrent scanning tasks
    #[arg(short = 'c', long, default_value = "500")]
    pub concurrency: usize,

    /// Output format for results
    #[arg(short, long, value_enum, default_value = "plain")]
    pub output: OutputFormat,

    /// Connection timeout in milliseconds
    #[arg(short = 't', long, default_value = "3000")]
    pub timeout: u64,

    /// Enable banner grabbing (TCP only)
    #[arg(short = 'b', long)]
    pub banner: bool,

    /// Show closed ports in output
    #[arg(long)]
    pub show_closed: bool,

    /// Verbose output (show scanning progress)
    #[arg(short, long)]
    pub verbose: bool,

    /// Network interface to use (required for SYN scan)
    #[arg(short = 'i', long)]
    pub interface: Option<String>,
}

/// Available scan types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanType {
    /// TCP connect scan (default, no special privileges required)
    Connect,
    /// SYN stealth scan (requires root/admin privileges)
    Syn,
    /// UDP scan (requires root/admin privileges for ICMP detection)
    Udp,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Connect => write!(f, "TCP Connect"),
            ScanType::Syn => write!(f, "SYN Stealth"),
            ScanType::Udp => write!(f, "UDP"),
        }
    }
}

/// Output format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable plain text
    Plain,
    /// JSON structured output
    Json,
    /// CSV format for data analysis
    Csv,
}

/// Parse port specification string into a vector of port numbers.
///
/// Supports:
/// - Single ports: "80"
/// - Comma-separated: "80,443,8080"
/// - Ranges: "1-1000"
/// - Mixed: "22,80,443,8000-9000"
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }
            let start: u16 = bounds[0]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port number: {}", bounds[0]))?;
            let end: u16 = bounds[1]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port number: {}", bounds[1]))?;
            if start > end {
                return Err(format!("Invalid port range: {} > {}", start, end));
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port number: {}", part))?;
            ports.push(port);
        }
    }

    // Remove duplicates and sort
    ports.sort_unstable();
    ports.dedup();

    if ports.is_empty() {
        return Err("No valid ports specified".to_string());
    }

    Ok(ports)
}

/// Resolve a hostname or IP address string to an IpAddr.
pub async fn resolve_target(target: &str) -> Result<IpAddr, String> {
    // First, try parsing as IP address
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Otherwise, perform DNS resolution
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let response = resolver
        .lookup_ip(target)
        .await
        .map_err(|e| format!("Failed to resolve hostname '{}': {}", target, e))?;

    response
        .iter()
        .next()
        .ok_or_else(|| format!("No IP addresses found for hostname '{}'", target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn test_parse_comma_separated() {
        assert_eq!(parse_ports("80,443,8080").unwrap(), vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_range() {
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_mixed() {
        assert_eq!(
            parse_ports("22,80,100-102").unwrap(),
            vec![22, 80, 100, 101, 102]
        );
    }

    #[test]
    fn test_parse_deduplication() {
        assert_eq!(parse_ports("80,80,443").unwrap(), vec![80, 443]);
    }

    #[test]
    fn test_parse_invalid_range() {
        assert!(parse_ports("100-50").is_err());
    }

    #[test]
    fn test_parse_invalid_port() {
        assert!(parse_ports("abc").is_err());
    }
}
