//! Output formatting module.
//!
//! Provides formatters for plain text, JSON, and CSV output of scan results.

use crate::cli::OutputFormat;
use crate::scanner::{PortStatus, ScanResults};
use console::{style, Style};
use std::io::{self, Write};

/// Format and print scan results according to the specified format.
pub fn print_results(results: &ScanResults, format: OutputFormat) -> io::Result<()> {
    match format {
        OutputFormat::Plain => print_plain(results),
        OutputFormat::Json => print_json(results),
        OutputFormat::Csv => print_csv(results),
    }
}

/// Print results in human-readable plain text format.
fn print_plain(results: &ScanResults) -> io::Result<()> {
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
    writeln!(
        out,
        "  {} {}",
        style("Target:").bold(),
        results.target
    )?;
    writeln!(
        out,
        "  {} {}",
        style("IP Address:").bold(),
        results.ip_address
    )?;
    writeln!(
        out,
        "  {} {}",
        style("Scan Type:").bold(),
        results.scan_type
    )?;
    writeln!(out)?;

    // Statistics
    writeln!(
        out,
        "  {} {} ports scanned in {:.2}s",
        style("Statistics:").bold(),
        results.ports_scanned,
        results.duration_ms as f64 / 1000.0
    )?;
    writeln!(
        out,
        "               {} open, {} closed, {} filtered",
        style(results.open_ports).green().bold(),
        style(results.closed_ports).red(),
        style(results.filtered_ports).yellow()
    )?;
    writeln!(out)?;

    // Port table
    if results.results.is_empty() {
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
        for result in &results.results {
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

/// Print results in JSON format.
fn print_json(results: &ScanResults) -> io::Result<()> {
    let json = serde_json::to_string_pretty(results)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    println!("{}", json);
    Ok(())
}

/// Print results in CSV format.
fn print_csv(results: &ScanResults) -> io::Result<()> {
    let stdout = io::stdout();
    let mut wtr = csv::Writer::from_writer(stdout.lock());

    // Write header
    wtr.write_record(["port", "status", "service", "banner"])?;

    // Write results
    for result in &results.results {
        wtr.write_record([
            &result.port.to_string(),
            &result.status.to_string(),
            &result.service,
            result.banner.as_deref().unwrap_or(""),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

/// Truncate a string to a maximum length, adding ellipsis if truncated.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Print a scan header before scanning begins.
pub fn print_scan_header(target: &str, ip: &str, scan_type: &str, ports: usize) {
    println!();
    println!(
        "{} {} v0.1.0",
        style("Starting").cyan(),
        style("Scuttle").cyan().bold()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
    }
}
