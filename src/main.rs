//! Scuttle - A high-performance network port scanner written in Rust.
//!
//! # Features
//!
//! - **TCP Connect Scan**: Standard socket-based scanning (no special privileges)
//! - **SYN Stealth Scan**: Half-open scanning using raw sockets (requires root)
//! - **UDP Scan**: Detect open UDP ports (requires root for ICMP detection)
//! - **High Concurrency**: Async I/O with configurable task limits
//! - **Service Detection**: Identify services by well-known ports
//! - **Banner Grabbing**: Retrieve service banners on TCP connections
//! - **Multiple Output Formats**: Plain text, JSON, or CSV
//!
//! # Usage
//!
//! ```bash
//! # Basic TCP connect scan
//! scuttle 192.168.1.1
//!
//! # Scan specific ports
//! scuttle 192.168.1.1 -p 80,443,8080
//!
//! # SYN stealth scan (requires sudo)
//! sudo scuttle 192.168.1.1 -s syn
//!
//! # UDP scan
//! sudo scuttle 192.168.1.1 -s udp -p 53,123,161
//!
//! # With banner grabbing and JSON output
//! scuttle 192.168.1.1 -b -o json
//! ```

mod banner;
mod cli;
mod error;
mod output;
mod scanner;
mod services;

use clap::Parser;
use cli::{parse_ports, resolve_target, Args, ScanType};
use output::{print_error, print_results, print_scan_header, print_warning};
use scanner::{run_scan, ScanConfig};
use std::process::ExitCode;
use std::time::Duration;

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    // Parse command-line arguments
    let args = Args::parse();

    // Run the scanner
    if let Err(e) = run(args).await {
        print_error(&e.to_string());
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

async fn run(args: Args) -> anyhow::Result<()> {
    // Parse ports
    let ports = parse_ports(&args.ports).map_err(|e| anyhow::anyhow!(e))?;

    if ports.is_empty() {
        return Err(anyhow::anyhow!("No valid ports specified"));
    }

    // Resolve target
    let target_ip = resolve_target(&args.target)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    // Check for privileged scan types
    if matches!(args.scan_type, ScanType::Syn | ScanType::Udp) {
        if !is_root() {
            print_warning(&format!(
                "{} scan requires root/sudo privileges for raw socket access.",
                args.scan_type
            ));
            print_warning("Results may be incomplete or scanning may fail.");
        }
    }

    // Print scan header (unless JSON/CSV output for clean parsing)
    if args.output == cli::OutputFormat::Plain {
        print_scan_header(
            &args.target,
            &target_ip.to_string(),
            &args.scan_type.to_string(),
            ports.len(),
        );
    }

    // Build scan configuration
    let config = ScanConfig {
        target: target_ip,
        target_hostname: args.target,
        ports,
        scan_type: args.scan_type,
        concurrency: args.concurrency,
        timeout: Duration::from_millis(args.timeout),
        grab_banners: args.banner,
        show_closed: args.show_closed,
        verbose: args.verbose,
        interface: args.interface,
    };

    // Execute scan
    let results = run_scan(config).await?;

    // Output results
    print_results(&results, args.output)?;

    Ok(())
}

/// Check if running with root/admin privileges.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // On Windows, check for admin privileges
        // This is a simplified check
        false
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_root_returns_bool() {
        // Just verify it doesn't panic
        let _ = is_root();
    }
}
