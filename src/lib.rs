//! # Scuttle - A High-Performance Network Port Scanner
//!
//! Scuttle is a fast, versatile port scanner written in Rust, designed for
//! network security professionals and system administrators.
//!
//! ## Features
//!
//! - **Multiple Scan Types**: TCP Connect, SYN Stealth, and UDP scanning
//! - **High Performance**: Async I/O with configurable concurrency and rate limiting
//! - **Flexible Targeting**: Single IPs, hostnames, and CIDR ranges
//! - **Scan Profiles**: Save and reuse scan configurations
//! - **Result Persistence**: Automatic saving and export of scan results
//! - **Banner Grabbing**: Service identification on open ports
//! - **Multiple Output Formats**: Plain text, JSON, and CSV
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use scuttle::scanner::{TcpConnectScanner, Scanner, ScanType};
//! use scuttle::types::Port;
//! use std::net::IpAddr;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() {
//!     let target: IpAddr = "192.168.1.1".parse().unwrap();
//!     let scanner = TcpConnectScanner::new(target, Duration::from_secs(3), false);
//!
//!     let port = Port::new(80).unwrap();
//!     let result = scanner.scan_port(port).await;
//!
//!     println!("Port {} is {}", result.port, result.status);
//! }
//! ```
//!
//! ## Architecture
//!
//! The library is organized into several modules:
//!
//! - [`types`] - Core type definitions with newtype patterns for type safety
//! - [`scanner`] - Scanner implementations and the `Scanner` trait
//! - [`config`] - Configuration management and scan profiles
//! - [`storage`] - Scan result persistence
//! - [`error`] - Comprehensive error types
//! - [`output`] - Output formatting utilities

pub mod banner;
pub mod cli;
pub mod config;
pub mod error;
pub mod output;
pub mod scanner;
pub mod services;
pub mod storage;
pub mod types;

// Re-export commonly used types
pub use error::{CliError, ScanError};
pub use scanner::{PortResult, PortStatus, ScanType, Scanner};
pub use types::{Port, PortSpec, ScanId, ScanTarget, TargetSpec};
