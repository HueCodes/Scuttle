//! Core type definitions using newtype patterns for type safety.
//!
//! These types prevent common logic errors by making invalid states unrepresentable
//! at compile time.

mod port;
mod scan_id;
mod target;

pub use port::{Port, PortError, PortRange, PortSpec};
pub use scan_id::{ScanId, ScanIdError};
pub use target::{ScanTarget, TargetError, TargetSpec};
