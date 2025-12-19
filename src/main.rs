//! Scuttle - A high-performance network port scanner written in Rust.
//!
//! # Usage
//!
//! ```bash
//! # Scan with the new subcommand interface
//! scuttle scan 192.168.1.1
//! scuttle scan 192.168.1.1 -p 80,443,8080
//! scuttle scan 192.168.1.0/24 -p 22,80
//!
//! # Use a scan profile
//! scuttle scan target.com --profile quick
//!
//! # Manage profiles
//! scuttle profiles list
//! scuttle profiles create my-scan -p 1-1000 -s connect
//!
//! # Export scan results
//! scuttle export abc123 -f json -o results.json
//!
//! # View scan history
//! scuttle history -n 20
//!
//! # Legacy mode (backwards compatible)
//! scuttle 192.168.1.1 -p 80,443
//! ```

use clap::Parser;
use scuttle::cli::{Cli, Commands, HistoryCommand};
use scuttle::output;
use scuttle::storage::ScanStore;
use std::process::ExitCode;

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
    let cli = Cli::parse();

    // Run the appropriate command
    if let Err(e) = run(cli).await {
        output::print_error(&e.to_string());
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let verbose = cli.verbose;
    let quiet = cli.quiet;

    match cli.command {
        Some(Commands::Scan(cmd)) => {
            cmd.execute(verbose, quiet).await?;
        }
        Some(Commands::Profiles(cmd)) => {
            cmd.execute(verbose, quiet)?;
        }
        Some(Commands::Export(cmd)) => {
            cmd.execute(verbose, quiet)?;
        }
        Some(Commands::History(cmd)) => {
            execute_history(cmd, verbose, quiet)?;
        }
        None => {
            // Legacy mode: if target is provided without subcommand
            if let Some(target) = cli.legacy_target {
                // Create a default scan command
                let scan_cmd = scuttle::cli::ScanCommand {
                    target,
                    ports: "1-1000".to_string(),
                    scan_type: scuttle::scanner::ScanType::Connect,
                    concurrency: 500,
                    output: scuttle::cli::OutputFormat::Plain,
                    timeout: 3000,
                    banner: false,
                    show_closed: false,
                    interface: None,
                    rate_limit: 0,
                    profile: None,
                    no_save: false,
                };
                scan_cmd.execute(verbose, quiet).await?;
            } else {
                // No command and no target - show help
                println!("Scuttle v{}", env!("CARGO_PKG_VERSION"));
                println!();
                println!("Usage: scuttle <COMMAND>");
                println!();
                println!("Commands:");
                println!("  scan      Scan a target for open ports");
                println!("  profiles  Manage scan profiles");
                println!("  export    Export scan results");
                println!("  history   View scan history");
                println!();
                println!("Run 'scuttle --help' for more information.");
            }
        }
    }

    Ok(())
}

/// Execute the history command.
fn execute_history(cmd: HistoryCommand, _verbose: bool, quiet: bool) -> anyhow::Result<()> {
    let store = ScanStore::new()?;

    if cmd.clear {
        // Clear all history
        if !quiet {
            println!("This will delete all saved scans. Continue? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
        }

        for id in store.list_ids()? {
            store.delete(&id)?;
        }

        if !quiet {
            output::print_success("Scan history cleared");
        }
        return Ok(());
    }

    if let Some(days) = cmd.prune {
        let duration = chrono::Duration::days(days as i64);
        let deleted = store.cleanup(duration)?;
        if !quiet {
            output::print_success(&format!("Deleted {} scans older than {} days", deleted, days));
        }
        return Ok(());
    }

    // List recent scans
    let records = store.list_recent(cmd.count)?;

    if records.is_empty() {
        if !quiet {
            println!("No scans in history.");
        }
        return Ok(());
    }

    println!("\n{:<10} {:<20} {:<20} {:>6} {:>6} {:>8}",
        "ID", "TARGET", "DATE", "OPEN", "PORTS", "TIME");
    println!("{}", "-".repeat(80));

    for record in &records {
        let date = record.started_at.format("%Y-%m-%d %H:%M");
        let duration = format!("{:.1}s", record.duration_ms as f64 / 1000.0);

        println!(
            "{:<10} {:<20} {:<20} {:>6} {:>6} {:>8}",
            record.id.short(),
            truncate(&record.target, 18),
            date,
            record.open_ports,
            record.ports_scanned,
            duration
        );

        if cmd.detailed {
            println!("           IP: {}, Type: {}", record.ip_address, record.scan_type);
            if record.open_ports > 0 {
                let open_ports: Vec<String> = record
                    .results
                    .iter()
                    .filter(|r| r.is_open())
                    .take(10)
                    .map(|r| format!("{}/{}", r.port, r.service))
                    .collect();
                println!("           Open: {}", open_ports.join(", "));
            }
            println!();
        }
    }

    println!();

    Ok(())
}

/// Truncate a string to a maximum length.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
