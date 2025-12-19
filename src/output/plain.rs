//! Plain text output formatting.
//!
//! Produces human-readable output with colors and formatting.

use crate::cli::OutputFormat;
use crate::scanner::PortStatus;
use crate::storage::ScanRecord;
use console::{style, Style};
use std::io::{self, Write};

/// Format and print scan results.
pub fn print_results(record: &ScanRecord, format: OutputFormat) -> io::Result<()> {
    match format {
        OutputFormat::Plain => print_plain(record),
        OutputFormat::Json => super::json_format::print_json(record),
        OutputFormat::Csv => super::csv_format::print_csv(record),
    }
}

/// Print results in human-readable plain text format.
pub fn print_plain(record: &ScanRecord) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Header
    writeln!(out)?;
    writeln!(
        out,
        "{}",
        style("═══════════════════════════════════════════════════════════════")
            .cyan()
    )?;
    writeln!(
        out,
        "                    {} Scan Results",
        style("Scuttle").cyan().bold()
    )?;
    writeln!(
        out,
        "{}",
        style("═══════════════════════════════════════════════════════════════")
            .cyan()
    )?;
    writeln!(out)?;

    // Scan info
    writeln!(out, "  {} {}", style("Target:").bold(), record.target)?;
    writeln!(
        out,
        "  {} {}",
        style("IP Address:").bold(),
        record.ip_address
    )?;
    writeln!(
        out,
        "  {} {}",
        style("Scan Type:").bold(),
        record.scan_type
    )?;
    writeln!(
        out,
        "  {} {}",
        style("Scan ID:").bold(),
        style(record.id.short()).dim()
    )?;
    writeln!(out)?;

    // Statistics
    writeln!(
        out,
        "  {} {} ports scanned in {:.2}s",
        style("Statistics:").bold(),
        record.ports_scanned,
        record.duration_ms as f64 / 1000.0
    )?;
    writeln!(
        out,
        "               {} open, {} closed, {} filtered",
        style(record.open_ports).green().bold(),
        style(record.closed_ports).red(),
        style(record.filtered_ports).yellow()
    )?;
    writeln!(out)?;

    // Port table
    if record.results.is_empty() {
        writeln!(out, "  {}", style("No ports to display.").dim())?;
    } else {
        // Table header
        writeln!(
            out,
            "  {}",
            style("───────────────────────────────────────────────────────────────")
                .dim()
        )?;
        writeln!(
            out,
            "  {:>6}  {:^14}  {:<15}  {}",
            style("PORT").bold(),
            style("STATE").bold(),
            style("SERVICE").bold(),
            style("BANNER").bold()
        )?;
        writeln!(
            out,
            "  {}",
            style("───────────────────────────────────────────────────────────────")
                .dim()
        )?;

        // Port results
        for result in &record.results {
            let status_style = match result.status {
                PortStatus::Open | PortStatus::OpenFiltered => Style::new().green().bold(),
                PortStatus::Closed => Style::new().red(),
                PortStatus::Filtered => Style::new().yellow(),
            };

            let banner_display = result
                .banner
                .as_ref()
                .map(|b| truncate_string(b, 35))
                .unwrap_or_default();

            writeln!(
                out,
                "  {:>6}  {:^14}  {:<15}  {}",
                result.port,
                status_style.apply_to(&result.status.to_string()),
                result.service,
                style(banner_display).dim()
            )?;
        }

        writeln!(
            out,
            "  {}",
            style("───────────────────────────────────────────────────────────────")
                .dim()
        )?;
    }

    writeln!(out)?;
    writeln!(
        out,
        "{}",
        style("═══════════════════════════════════════════════════════════════")
            .cyan()
    )?;
    writeln!(out)?;

    Ok(())
}

/// Print a scan header before scanning begins.
pub fn print_scan_header(target: &str, ip: &str, scan_type: &str, ports: usize) {
    println!();
    println!(
        "{} {} v{}",
        style("Starting").cyan(),
        style("Scuttle").cyan().bold(),
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "{} Scan type: {}",
        style("•").dim(),
        style(scan_type).yellow()
    );
    println!(
        "{} Target: {} ({})",
        style("•").dim(),
        style(target).white().bold(),
        ip
    );
    println!(
        "{} Scanning {} ports...",
        style("•").dim(),
        style(ports).white().bold()
    );
    println!();
}

/// Print an error message.
pub fn print_error(msg: &str) {
    eprintln!("{} {}", style("Error:").red().bold(), msg);
}

/// Print a warning message.
pub fn print_warning(msg: &str) {
    eprintln!("{} {}", style("Warning:").yellow().bold(), msg);
}

/// Print a success message.
pub fn print_success(msg: &str) {
    println!("{} {}", style("✓").green().bold(), msg);
}

/// Print an info message.
pub fn print_info(msg: &str) {
    println!("{} {}", style("ℹ").blue().bold(), msg);
}

/// Truncate a string to a maximum length, adding ellipsis if truncated.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
    }
}
