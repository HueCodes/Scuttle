//! Export subcommand implementation.
//!
//! Handles the `scuttle export <scan-id>` command for exporting scan results.

use crate::cli::OutputFormat;
use crate::error::CliResult;
use crate::output;
use crate::storage::ScanStore;
use crate::types::ScanId;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

/// Export scan results.
#[derive(Parser, Debug)]
pub struct ExportCommand {
    /// Scan ID or prefix to export
    ///
    /// Can be a full UUID or the first few characters (short ID).
    #[arg(value_name = "SCAN_ID")]
    pub scan_id: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    pub format: OutputFormat,

    /// Output file path (prints to stdout if not specified)
    #[arg(short = 'o', long = "output")]
    pub output_file: Option<PathBuf>,

    /// Include closed ports in export
    #[arg(long)]
    pub include_closed: bool,

    /// Export only open ports
    #[arg(long)]
    pub open_only: bool,
}

impl ExportCommand {
    /// Execute the export command.
    pub fn execute(&self, _verbose: bool, quiet: bool) -> CliResult<()> {
        let store = ScanStore::new()?;

        // Find the scan by ID or prefix
        let record = if self.scan_id.len() < 36 {
            // Short ID - find by prefix
            store.find_by_prefix(&self.scan_id)?
        } else {
            // Full ID
            let id: ScanId = self.scan_id.parse()?;
            store.load(&id)?
        };

        // Filter results if requested
        let mut record = record;
        if self.open_only {
            record.results.retain(|r| r.is_open());
        } else if !self.include_closed {
            record.results.retain(|r| {
                !matches!(r.status, crate::scanner::PortStatus::Closed)
            });
        }

        // Generate output
        let content = match self.format {
            OutputFormat::Json => serde_json::to_string_pretty(&record)
                .map_err(|e| crate::error::CliError::Other(e.to_string()))?,
            OutputFormat::Csv => generate_csv(&record)?,
            OutputFormat::Plain => generate_plain(&record),
        };

        // Write to file or stdout
        if let Some(ref path) = self.output_file {
            fs::write(path, &content)
                .map_err(|e| crate::error::CliError::Other(format!("failed to write file: {}", e)))?;

            if !quiet {
                output::print_success(&format!(
                    "Exported scan {} to {}",
                    record.id.short(),
                    path.display()
                ));
            }
        } else {
            println!("{}", content);
        }

        Ok(())
    }
}

/// Generate CSV output.
fn generate_csv(record: &crate::storage::ScanRecord) -> CliResult<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);

    // Write header
    wtr.write_record(["port", "status", "service", "banner", "response_time_ms"])
        .map_err(|e| crate::error::CliError::Other(e.to_string()))?;

    // Write results
    for result in &record.results {
        wtr.write_record([
            &result.port.to_string(),
            &result.status.to_string(),
            &result.service,
            result.banner.as_deref().unwrap_or(""),
            &result.response_time_ms.map_or(String::new(), |t| t.to_string()),
        ])
        .map_err(|e| crate::error::CliError::Other(e.to_string()))?;
    }

    String::from_utf8(wtr.into_inner().map_err(|e| crate::error::CliError::Other(e.to_string()))?)
        .map_err(|e| crate::error::CliError::Other(e.to_string()))
}

/// Generate plain text output.
fn generate_plain(record: &crate::storage::ScanRecord) -> String {
    let mut output = String::new();

    output.push_str(&format!("Scan Report: {}\n", record.id));
    output.push_str(&format!("{}\n\n", "=".repeat(60)));

    output.push_str(&format!("Target:       {}\n", record.target));
    output.push_str(&format!("IP Address:   {}\n", record.ip_address));
    output.push_str(&format!("Scan Type:    {}\n", record.scan_type));
    output.push_str(&format!("Started:      {}\n", record.started_at));
    output.push_str(&format!("Completed:    {}\n", record.completed_at));
    output.push_str(&format!("Duration:     {} ms\n\n", record.duration_ms));

    output.push_str(&format!(
        "Summary: {} ports scanned, {} open, {} closed, {} filtered\n\n",
        record.ports_scanned, record.open_ports, record.closed_ports, record.filtered_ports
    ));

    if !record.results.is_empty() {
        output.push_str("Results:\n");
        output.push_str(&format!("{}\n", "-".repeat(60)));
        output.push_str(&format!(
            "{:>6}  {:^12}  {:<15}  {}\n",
            "PORT", "STATUS", "SERVICE", "BANNER"
        ));
        output.push_str(&format!("{}\n", "-".repeat(60)));

        for result in &record.results {
            let banner = result.banner.as_deref().unwrap_or("");
            let banner_display = if banner.len() > 30 {
                format!("{}...", &banner[..30])
            } else {
                banner.to_string()
            };

            output.push_str(&format!(
                "{:>6}  {:^12}  {:<15}  {}\n",
                result.port, result.status, result.service, banner_display
            ));
        }
    }

    output
}
