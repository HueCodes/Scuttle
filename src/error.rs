//! Comprehensive error types for Scuttle.
//!
//! Uses `thiserror` for ergonomic error definitions with proper
//! error chaining and context.

use crate::types::{PortError, ScanIdError, TargetError};
use std::path::PathBuf;
use thiserror::Error;

/// Main error type for scanning operations.
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("connection failed to {target}:{port}: {reason}")]
    ConnectionFailed {
        target: String,
        port: u16,
        reason: String,
    },

    #[error("connection timed out")]
    Timeout,

    #[error("connection refused")]
    ConnectionRefused,

    #[error("network unreachable: {0}")]
    NetworkUnreachable(String),

    #[error("host unreachable")]
    HostUnreachable,

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("raw socket error: {0}")]
    RawSocketError(String),

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("scan cancelled")]
    Cancelled,
}

/// Error type for configuration operations.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {reason}")]
    ReadFailed { path: PathBuf, reason: String },

    #[error("failed to write config file '{path}': {reason}")]
    WriteFailed { path: PathBuf, reason: String },

    #[error("invalid config format: {0}")]
    InvalidFormat(String),

    #[error("config directory not found")]
    DirectoryNotFound,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Error type for storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("scan not found: {0}")]
    ScanNotFound(String),

    #[error("failed to save scan: {0}")]
    SaveFailed(String),

    #[error("failed to load scan: {0}")]
    LoadFailed(String),

    #[error("storage directory not accessible: {0}")]
    DirectoryError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid scan ID: {0}")]
    InvalidScanId(#[from] ScanIdError),
}

/// Error type for profile operations.
#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("profile not found: {0}")]
    NotFound(String),

    #[error("profile already exists: {0}")]
    AlreadyExists(String),

    #[error("invalid profile name: {0}")]
    InvalidName(String),

    #[error("failed to save profile: {0}")]
    SaveFailed(String),

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("port error: {0}")]
    Port(#[from] PortError),
}

/// Error type for CLI operations.
#[derive(Error, Debug)]
pub enum CliError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("target error: {0}")]
    Target(#[from] TargetError),

    #[error("port error: {0}")]
    Port(#[from] PortError),

    #[error("scan error: {0}")]
    Scan(#[from] ScanError),

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("profile error: {0}")]
    Profile(#[from] ProfileError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid scan ID: {0}")]
    ScanId(#[from] ScanIdError),

    #[error("{0}")]
    Other(String),
}

/// Result type alias for scan operations.
pub type ScanResult<T> = Result<T, ScanError>;

/// Result type alias for config operations.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// Result type alias for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Result type alias for profile operations.
pub type ProfileResult<T> = Result<T, ProfileError>;

/// Result type alias for CLI operations.
pub type CliResult<T> = Result<T, CliError>;
