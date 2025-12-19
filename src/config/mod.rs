//! Configuration management for Scuttle.
//!
//! Provides XDG-compliant configuration storage and management,
//! including scan profiles and application settings.

mod profiles;
mod settings;

pub use profiles::{Profile, ProfileManager};
pub use settings::{AppSettings, Paths};
