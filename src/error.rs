//! Error types for Scuttle.
//!
//! Uses `thiserror` for ergonomic error definitions.

use thiserror::Error;

/// Main error type for scanning operations.
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection timed out")]
    Timeout,

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Network unreachable: {0}")]
    NetworkUnreachable(String),

    #[error("Host unreachable")]
    HostUnreachable,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Raw socket error: {0}")]
    RawSocketError(String),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[allow(dead_code)]
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Result type alias for scan operations.
pub type ScanResult<T> = Result<T, ScanError>;
