//! Scan subcommand implementation.
//!
//! Handles the `scuttle scan <target>` command for port scanning.

use crate::cli::OutputFormat;
use crate::config::ProfileManager;
use crate::error::CliResult;
use crate::output;
use crate::scanner::{
    create_scanner, run_scan, ScanConfig, ScanJobConfig, ScanType,
};
use crate::storage::ScanStore;
use crate::types::{Port, PortSpec, ScanTarget, TargetSpec};
use clap::Parser;
use std::time::Duration;

/// Scan a target for open ports.
#[derive(Parser, Debug)]
pub struct ScanCommand {
    /// Target to scan (IP, hostname, or CIDR notation)
    ///
    /// Examples:
    ///   192.168.1.1        Single IP address
    ///   example.com        Hostname
    ///   192.168.1.0/24     CIDR range
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

    /// Network interface to use (for SYN scan)
    #[arg(short = 'i', long)]
    pub interface: Option<String>,

    /// Rate limit in packets per second (0 = unlimited)
    #[arg(short = 'r', long = "rate", default_value = "0")]
    pub rate_limit: u32,

    /// Use a saved scan profile
    #[arg(long = "profile", short = 'P')]
    pub profile: Option<String>,

    /// Don't save scan results
    #[arg(long)]
    pub no_save: bool,
}

impl ScanCommand {
    /// Execute the scan command.
    pub async fn execute(&self, verbose: bool, quiet: bool) -> CliResult<()> {
        // Apply profile if specified
        let (ports_str, scan_type, concurrency, timeout_ms, banner, rate_limit) =
            if let Some(profile_name) = &self.profile {
                let manager = ProfileManager::new()?;
                let profile = manager
                    .get(profile_name)
                    .ok_or_else(|| crate::error::CliError::Other(format!(
                        "profile '{}' not found",
                        profile_name
                    )))?;

                (
                    profile.ports.clone(),
                    profile.scan_type.parse().unwrap_or(ScanType::Connect),
                    profile.concurrency,
                    profile.timeout_ms,
                    profile.banner,
                    profile.rate_limit,
                )
            } else {
                (
                    self.ports.clone(),
                    self.scan_type,
                    self.concurrency,
                    self.timeout,
                    self.banner,
                    self.rate_limit,
                )
            };

        // Parse ports
        let port_spec: PortSpec = ports_str.parse()?;
        let ports = port_spec.to_ports();

        if ports.is_empty() {
            return Err(crate::error::CliError::Other("No valid ports specified".to_string()));
        }

        // Parse and resolve target
        let target_spec = TargetSpec::parse(&self.target)?;
        let targets = target_spec.resolve().await?;

        if targets.is_empty() {
            return Err(crate::error::CliError::Other(
                "No valid targets resolved".to_string(),
            ));
        }

        // Check for privileged scan types
        if matches!(scan_type, ScanType::Syn | ScanType::Udp) {
            if !is_root() {
                output::print_warning(&format!(
                    "{} scan requires root/sudo privileges for raw socket access.",
                    scan_type
                ));
                output::print_warning("Results may be incomplete or scanning may fail.");
            }
        }

        // Scan each resolved target
        for scan_target in targets {
            self.scan_target(
                &scan_target,
                &ports,
                scan_type,
                concurrency,
                timeout_ms,
                banner,
                rate_limit,
                verbose,
                quiet,
            )
            .await?;
        }

        Ok(())
    }

    async fn scan_target(
        &self,
        target: &ScanTarget,
        ports: &[Port],
        scan_type: ScanType,
        concurrency: usize,
        timeout_ms: u64,
        banner: bool,
        rate_limit: u32,
        verbose: bool,
        quiet: bool,
    ) -> CliResult<()> {
        // Print scan header (unless JSON/CSV output for clean parsing)
        if !quiet && self.output == OutputFormat::Plain {
            output::print_scan_header(
                &target.original,
                &target.ip.to_string(),
                &scan_type.to_string(),
                ports.len(),
            );
        }

        // Build scan configuration
        let scan_config = ScanConfig::new(target.ip)
            .with_hostname(&target.original)
            .with_timeout(Duration::from_millis(timeout_ms));

        let scan_config = if banner {
            scan_config.with_banners()
        } else {
            scan_config
        };

        let scan_config = if let Some(ref iface) = self.interface {
            scan_config.with_interface(iface)
        } else {
            scan_config
        };

        // Create scanner
        let scanner = create_scanner(scan_type, scan_config)?;

        // Build job configuration
        let job_config = ScanJobConfig::new(ports.to_vec())
            .with_concurrency(concurrency)
            .with_rate_limit(rate_limit);

        let job_config = if verbose {
            job_config.with_verbose()
        } else {
            job_config
        };

        let job_config = if self.show_closed {
            job_config.with_closed()
        } else {
            job_config
        };

        // Execute scan
        let record = run_scan(scanner, job_config).await?;

        // Save results unless disabled
        if !self.no_save {
            let store = ScanStore::new()?;
            store.save(&record)?;

            if !quiet && self.output == OutputFormat::Plain {
                output::print_info(&format!("Scan saved as {}", record.id.short()));
            }
        }

        // Output results
        output::print_results(&record, self.output)?;

        Ok(())
    }
}

/// Check if running with root/admin privileges.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        false
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}
