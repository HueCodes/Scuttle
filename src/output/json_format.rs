//! JSON output formatting.

use crate::storage::ScanRecord;
use std::io;

/// Print results in JSON format.
pub fn print_json(record: &ScanRecord) -> io::Result<()> {
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    println!("{}", json);
    Ok(())
}
