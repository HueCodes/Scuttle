//! Application settings and paths.
//!
//! Manages XDG-compliant paths for configuration, data, and cache.

use crate::error::{ConfigError, ConfigResult};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Global paths singleton.
static PATHS: OnceLock<Paths> = OnceLock::new();

/// Application directory paths following XDG Base Directory Specification.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Configuration directory (~/.config/scuttle)
    pub config_dir: PathBuf,
    /// Data directory (~/.local/share/scuttle)
    pub data_dir: PathBuf,
    /// Cache directory (~/.cache/scuttle)
    pub cache_dir: PathBuf,
}

impl Paths {
    /// Get the global paths instance.
    pub fn get() -> &'static Paths {
        PATHS.get_or_init(|| Self::new().expect("Failed to initialize paths"))
    }

    /// Initialize paths using XDG directories.
    fn new() -> ConfigResult<Self> {
        let project = ProjectDirs::from("com", "scuttle", "scuttle")
            .ok_or(ConfigError::DirectoryNotFound)?;

        let paths = Self {
            config_dir: project.config_dir().to_path_buf(),
            data_dir: project.data_dir().to_path_buf(),
            cache_dir: project.cache_dir().to_path_buf(),
        };

        // Ensure directories exist
        fs::create_dir_all(&paths.config_dir)?;
        fs::create_dir_all(&paths.data_dir)?;
        fs::create_dir_all(&paths.cache_dir)?;

        Ok(paths)
    }

    /// Get the path to the settings file.
    pub fn settings_file(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }

    /// Get the path to the profiles directory.
    pub fn profiles_dir(&self) -> PathBuf {
        self.config_dir.join("profiles")
    }

    /// Get the path to the scans storage directory.
    pub fn scans_dir(&self) -> PathBuf {
        self.data_dir.join("scans")
    }
}

/// Application-wide settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    /// Default concurrency level.
    pub default_concurrency: usize,
    /// Default timeout in milliseconds.
    pub default_timeout_ms: u64,
    /// Default scan type.
    pub default_scan_type: String,
    /// Enable verbose output by default.
    pub verbose: bool,
    /// Default output format.
    pub default_output_format: String,
    /// Maximum rate (packets per second), 0 for unlimited.
    pub default_rate_limit: u32,
    /// Auto-save scan results.
    pub auto_save_scans: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            default_concurrency: 500,
            default_timeout_ms: 3000,
            default_scan_type: "connect".to_string(),
            verbose: false,
            default_output_format: "plain".to_string(),
            default_rate_limit: 0,
            auto_save_scans: true,
        }
    }
}

impl AppSettings {
    /// Load settings from the default location.
    pub fn load() -> ConfigResult<Self> {
        let paths = Paths::get();
        let file = paths.settings_file();

        if !file.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&file).map_err(|e| ConfigError::ReadFailed {
            path: file.clone(),
            reason: e.to_string(),
        })?;

        serde_json::from_str(&content).map_err(|e| ConfigError::InvalidFormat(e.to_string()))
    }

    /// Load settings from a specific file.
    pub fn load_from(path: &PathBuf) -> ConfigResult<Self> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::ReadFailed {
            path: path.clone(),
            reason: e.to_string(),
        })?;

        serde_json::from_str(&content).map_err(|e| ConfigError::InvalidFormat(e.to_string()))
    }

    /// Save settings to the default location.
    pub fn save(&self) -> ConfigResult<()> {
        let paths = Paths::get();
        let file = paths.settings_file();

        let content = serde_json::to_string_pretty(self)?;
        fs::write(&file, content).map_err(|e| ConfigError::WriteFailed {
            path: file,
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = AppSettings::default();
        assert_eq!(settings.default_concurrency, 500);
        assert_eq!(settings.default_timeout_ms, 3000);
    }

    #[test]
    fn test_settings_serialization() {
        let settings = AppSettings::default();
        let json = serde_json::to_string(&settings).unwrap();
        let parsed: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.default_concurrency, settings.default_concurrency);
    }
}
