//! CLI subcommand definitions and handlers.
//!
//! Implements a git-like subcommand architecture:
//! - `scuttle scan <target>` - Scan a target
//! - `scuttle profiles list|create|delete` - Manage scan profiles
//! - `scuttle export <scan-id>` - Export scan results
//! - `scuttle history` - View scan history

mod export;
mod profiles;
mod scan;

pub use export::ExportCommand;
pub use profiles::ProfilesCommand;
pub use scan::ScanCommand;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Scuttle - A high-performance network port scanner.
///
/// Scuttle supports multiple scanning techniques including TCP connect,
/// SYN stealth, and UDP scanning. It can scan single hosts, CIDR ranges,
/// and supports saved scan profiles.
#[derive(Parser, Debug)]
#[command(name = "scuttle")]
#[command(author = "HueCodes <huecodes@proton.me>")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "A fast, versatile port scanner", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Path to custom configuration file
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Directory for output files
    #[arg(long, global = true, value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    // Legacy mode: if no subcommand, treat first arg as target
    /// Target to scan (legacy mode, use 'scuttle scan' instead)
    #[arg(value_name = "TARGET", hide = true)]
    pub legacy_target: Option<String>,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a target for open ports
    #[command(alias = "s")]
    Scan(ScanCommand),

    /// Manage scan profiles
    #[command(alias = "p")]
    Profiles(ProfilesCommand),

    /// Export scan results
    #[command(alias = "e")]
    Export(ExportCommand),

    /// View scan history
    #[command(alias = "h")]
    History(HistoryCommand),
}

/// View and manage scan history.
#[derive(Parser, Debug)]
pub struct HistoryCommand {
    /// Number of recent scans to show
    #[arg(short = 'n', long, default_value = "10")]
    pub count: usize,

    /// Show detailed information for each scan
    #[arg(short, long)]
    pub detailed: bool,

    /// Clear all scan history
    #[arg(long)]
    pub clear: bool,

    /// Delete scans older than N days
    #[arg(long, value_name = "DAYS")]
    pub prune: Option<u32>,
}

/// Output format for results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable plain text
    Plain,
    /// JSON structured output
    Json,
    /// CSV format for data analysis
    Csv,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Plain
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::Json => write!(f, "json"),
            Self::Csv => write!(f, "csv"),
        }
    }
}
