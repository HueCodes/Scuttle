//! Output formatting module.
//!
//! Provides formatters for plain text, JSON, and CSV output of scan results.

mod csv_format;
mod json_format;
mod plain;

pub use csv_format::print_csv;
pub use json_format::print_json;
pub use plain::{
    print_error, print_info, print_results, print_scan_header, print_success, print_warning,
};

use crate::cli::OutputFormat;
use crate::storage::ScanRecord;
use std::io;

/// Format and print scan results according to the specified format.
pub fn format_results(record: &ScanRecord, format: OutputFormat) -> io::Result<()> {
    match format {
        OutputFormat::Plain => plain::print_plain(record),
        OutputFormat::Json => json_format::print_json(record),
        OutputFormat::Csv => csv_format::print_csv(record),
    }
}
