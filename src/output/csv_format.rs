//! CSV output formatting.

use crate::storage::ScanRecord;
use std::io;

/// Print results in CSV format.
pub fn print_csv(record: &ScanRecord) -> io::Result<()> {
    let stdout = io::stdout();
    let mut wtr = csv::Writer::from_writer(stdout.lock());

    // Write header
    wtr.write_record(["port", "status", "service", "banner", "response_time_ms"])?;

    // Write results
    for result in &record.results {
        wtr.write_record([
            &result.port.to_string(),
            &result.status.to_string(),
            &result.service,
            result.banner.as_deref().unwrap_or(""),
            &result.response_time_ms.map_or(String::new(), |t| t.to_string()),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}
