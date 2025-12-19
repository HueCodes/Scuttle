//! Port types with validation and parsing.
//!
//! The `Port` newtype ensures values are always valid port numbers (1-65535).
//! `PortRange` and `PortSpec` handle complex port specifications.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A validated network port number (1-65535).
///
/// Using a newtype prevents accidental misuse of raw u16 values
/// and ensures port numbers are always valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Port(u16);

impl Port {
    /// Minimum valid port number.
    pub const MIN: u16 = 1;
    /// Maximum valid port number.
    pub const MAX: u16 = 65535;

    /// Create a new Port from a u16, returning None if invalid.
    #[inline]
    pub const fn new(port: u16) -> Option<Self> {
        if port >= Self::MIN && port <= Self::MAX {
            Some(Self(port))
        } else {
            None
        }
    }

    /// Create a Port without validation. Use only when the value is known valid.
    ///
    /// # Safety
    /// The caller must ensure `port` is in the valid range (1-65535).
    #[inline]
    pub const fn new_unchecked(port: u16) -> Self {
        Self(port)
    }

    /// Get the raw port number.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Check if this is a privileged port (< 1024).
    #[inline]
    pub const fn is_privileged(self) -> bool {
        self.0 < 1024
    }

    /// Check if this is an ephemeral port (49152-65535).
    #[inline]
    pub const fn is_ephemeral(self) -> bool {
        self.0 >= 49152
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u16> for Port {
    type Error = PortError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(PortError::OutOfRange(value))
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> Self {
        port.0
    }
}

/// Error type for port parsing and validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PortError {
    #[error("port {0} is out of valid range (1-65535)")]
    OutOfRange(u16),
    #[error("invalid port number: {0}")]
    InvalidFormat(String),
    #[error("invalid port range: start ({0}) > end ({1})")]
    InvalidRange(u16, u16),
    #[error("empty port specification")]
    Empty,
}

/// A range of ports (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    start: Port,
    end: Port,
}

impl PortRange {
    /// Create a new port range.
    pub fn new(start: Port, end: Port) -> Result<Self, PortError> {
        if start.0 > end.0 {
            Err(PortError::InvalidRange(start.0, end.0))
        } else {
            Ok(Self { start, end })
        }
    }

    /// Create a range containing a single port.
    pub const fn single(port: Port) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Get the number of ports in this range.
    pub const fn len(&self) -> usize {
        (self.end.0 - self.start.0 + 1) as usize
    }

    /// Check if the range is empty (never true for valid ranges).
    pub const fn is_empty(&self) -> bool {
        false // A valid PortRange always has at least one port
    }

    /// Iterate over all ports in this range.
    pub fn iter(&self) -> impl Iterator<Item = Port> {
        let start = self.start.0;
        let end = self.end.0;
        (start..=end).map(Port::new_unchecked)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// A complete port specification that can contain multiple ranges.
///
/// Supports formats like:
/// - Single port: "80"
/// - Comma-separated: "80,443,8080"
/// - Range: "1-1000"
/// - Mixed: "22,80,443,8000-9000"
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortSpec {
    ranges: Vec<PortRange>,
}

impl PortSpec {
    /// Create an empty port specification.
    pub const fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a port range to the specification.
    pub fn add_range(&mut self, range: PortRange) {
        self.ranges.push(range);
    }

    /// Add a single port to the specification.
    pub fn add_port(&mut self, port: Port) {
        self.ranges.push(PortRange::single(port));
    }

    /// Get all ports as a sorted, deduplicated vector.
    pub fn to_ports(&self) -> Vec<Port> {
        let mut ports: Vec<Port> = self.ranges.iter().flat_map(|r| r.iter()).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Get the total number of unique ports.
    pub fn count(&self) -> usize {
        self.to_ports().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Common scan profiles.
    pub fn top_100() -> Self {
        // Top 100 most common ports
        let ports = [
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
            139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
            554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
            1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
            5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
            6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
            49153, 49154, 49155, 49156, 49157,
        ];
        let mut spec = Self::new();
        for &p in &ports {
            if let Some(port) = Port::new(p) {
                spec.add_port(port);
            }
        }
        spec
    }

    /// Full port range (1-65535).
    pub fn full() -> Self {
        let mut spec = Self::new();
        if let (Some(start), Some(end)) = (Port::new(1), Port::new(65535)) {
            if let Ok(range) = PortRange::new(start, end) {
                spec.add_range(range);
            }
        }
        spec
    }
}

impl FromStr for PortSpec {
    type Err = PortError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(PortError::Empty);
        }

        let mut spec = Self::new();

        for part in s.split(',') {
            let part = part.trim();
            if part.contains('-') {
                let bounds: Vec<&str> = part.split('-').collect();
                if bounds.len() != 2 {
                    return Err(PortError::InvalidFormat(part.to_string()));
                }

                let start: u16 = bounds[0]
                    .trim()
                    .parse()
                    .map_err(|_| PortError::InvalidFormat(bounds[0].to_string()))?;
                let end: u16 = bounds[1]
                    .trim()
                    .parse()
                    .map_err(|_| PortError::InvalidFormat(bounds[1].to_string()))?;

                let start_port = Port::new(start).ok_or(PortError::OutOfRange(start))?;
                let end_port = Port::new(end).ok_or(PortError::OutOfRange(end))?;
                let range = PortRange::new(start_port, end_port)?;
                spec.add_range(range);
            } else {
                let port: u16 = part
                    .parse()
                    .map_err(|_| PortError::InvalidFormat(part.to_string()))?;
                let port = Port::new(port).ok_or(PortError::OutOfRange(port))?;
                spec.add_port(port);
            }
        }

        if spec.is_empty() {
            return Err(PortError::Empty);
        }

        Ok(spec)
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.ranges.iter().map(|r| r.to_string()).collect();
        write!(f, "{}", parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_validation() {
        assert!(Port::new(0).is_none());
        assert!(Port::new(1).is_some());
        assert!(Port::new(80).is_some());
        assert!(Port::new(65535).is_some());
    }

    #[test]
    fn test_port_properties() {
        let port80 = Port::new(80).unwrap();
        assert!(port80.is_privileged());
        assert!(!port80.is_ephemeral());

        let port50000 = Port::new(50000).unwrap();
        assert!(!port50000.is_privileged());
        assert!(port50000.is_ephemeral());
    }

    #[test]
    fn test_port_range() {
        let start = Port::new(1).unwrap();
        let end = Port::new(100).unwrap();
        let range = PortRange::new(start, end).unwrap();
        assert_eq!(range.len(), 100);
    }

    #[test]
    fn test_port_spec_parsing() {
        let spec: PortSpec = "80".parse().unwrap();
        assert_eq!(spec.count(), 1);

        let spec: PortSpec = "80,443".parse().unwrap();
        assert_eq!(spec.count(), 2);

        let spec: PortSpec = "1-100".parse().unwrap();
        assert_eq!(spec.count(), 100);

        let spec: PortSpec = "22,80,443,8000-8010".parse().unwrap();
        assert_eq!(spec.count(), 14);
    }

    #[test]
    fn test_port_spec_dedup() {
        let spec: PortSpec = "80,80,443,80".parse().unwrap();
        assert_eq!(spec.count(), 2);
    }
}
