//! Scan profile management.
//!
//! Profiles allow users to save and reuse scan configurations.

use crate::error::{ConfigError, ProfileError, ProfileResult};
use crate::types::PortSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use super::settings::Paths;

/// A saved scan profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Profile name (used as identifier).
    pub name: String,
    /// Description of this profile.
    #[serde(default)]
    pub description: String,
    /// Port specification string.
    pub ports: String,
    /// Scan type (connect, syn, udp).
    #[serde(default = "default_scan_type")]
    pub scan_type: String,
    /// Concurrency level.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Enable banner grabbing.
    #[serde(default)]
    pub banner: bool,
    /// Rate limit (packets per second, 0 for unlimited).
    #[serde(default)]
    pub rate_limit: u32,
}

fn default_scan_type() -> String {
    "connect".to_string()
}

fn default_concurrency() -> usize {
    500
}

fn default_timeout() -> u64 {
    3000
}

impl Profile {
    /// Create a new profile with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            ports: "1-1000".to_string(),
            scan_type: default_scan_type(),
            concurrency: default_concurrency(),
            timeout_ms: default_timeout(),
            banner: false,
            rate_limit: 0,
        }
    }

    /// Parse the port specification.
    pub fn port_spec(&self) -> Result<PortSpec, crate::types::PortError> {
        self.ports.parse()
    }

    /// Validate the profile configuration.
    pub fn validate(&self) -> ProfileResult<()> {
        if self.name.is_empty() {
            return Err(ProfileError::InvalidName("name cannot be empty".to_string()));
        }

        if !self.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(ProfileError::InvalidName(
                "name can only contain alphanumeric characters, hyphens, and underscores".to_string(),
            ));
        }

        // Validate ports parse correctly
        self.port_spec()?;

        // Validate scan type
        if !["connect", "syn", "udp"].contains(&self.scan_type.as_str()) {
            return Err(ProfileError::InvalidName(format!(
                "invalid scan type: {}",
                self.scan_type
            )));
        }

        Ok(())
    }
}

/// Built-in profile presets.
impl Profile {
    /// Quick scan profile (top 100 ports).
    pub fn quick() -> Self {
        Self {
            name: "quick".to_string(),
            description: "Quick scan of top 100 ports".to_string(),
            ports: "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080".to_string(),
            scan_type: "connect".to_string(),
            concurrency: 1000,
            timeout_ms: 2000,
            banner: false,
            rate_limit: 0,
        }
    }

    /// Full scan profile (all ports).
    pub fn full() -> Self {
        Self {
            name: "full".to_string(),
            description: "Complete scan of all 65535 ports".to_string(),
            ports: "1-65535".to_string(),
            scan_type: "connect".to_string(),
            concurrency: 500,
            timeout_ms: 3000,
            banner: false,
            rate_limit: 0,
        }
    }

    /// Web services scan profile.
    pub fn web() -> Self {
        Self {
            name: "web".to_string(),
            description: "Common web service ports".to_string(),
            ports: "80,443,8000,8080,8443,8888,9000,9090,3000,5000".to_string(),
            scan_type: "connect".to_string(),
            concurrency: 100,
            timeout_ms: 5000,
            banner: true,
            rate_limit: 0,
        }
    }

    /// Database scan profile.
    pub fn database() -> Self {
        Self {
            name: "database".to_string(),
            description: "Common database ports".to_string(),
            ports: "1433,1521,3306,5432,6379,9042,27017,5984,11211".to_string(),
            scan_type: "connect".to_string(),
            concurrency: 50,
            timeout_ms: 5000,
            banner: true,
            rate_limit: 0,
        }
    }

    /// Stealth scan profile.
    pub fn stealth() -> Self {
        Self {
            name: "stealth".to_string(),
            description: "Low-profile SYN scan".to_string(),
            ports: "1-1000".to_string(),
            scan_type: "syn".to_string(),
            concurrency: 100,
            timeout_ms: 5000,
            banner: false,
            rate_limit: 100,
        }
    }

    /// Get all built-in profiles.
    pub fn builtins() -> Vec<Profile> {
        vec![
            Self::quick(),
            Self::full(),
            Self::web(),
            Self::database(),
            Self::stealth(),
        ]
    }
}

/// Manages profile storage and retrieval.
pub struct ProfileManager {
    profiles_dir: PathBuf,
    cache: HashMap<String, Profile>,
}

impl ProfileManager {
    /// Create a new profile manager.
    pub fn new() -> ProfileResult<Self> {
        let paths = Paths::get();
        let profiles_dir = paths.profiles_dir();

        fs::create_dir_all(&profiles_dir).map_err(|e| {
            ProfileError::Config(ConfigError::WriteFailed {
                path: profiles_dir.clone(),
                reason: e.to_string(),
            })
        })?;

        let mut manager = Self {
            profiles_dir,
            cache: HashMap::new(),
        };

        // Load all profiles into cache
        manager.load_all()?;

        Ok(manager)
    }

    /// Get a profile by name.
    pub fn get(&self, name: &str) -> Option<&Profile> {
        // Check built-ins first
        for builtin in Profile::builtins() {
            if builtin.name == name {
                // Return from cache if loaded, otherwise the builtin
                return self.cache.get(name).or(Some(&builtin).map(|_| {
                    // This is a workaround - we can't return a reference to a temporary
                    // In practice, builtins should be in the cache after load_all
                    self.cache.get(name)
                })?);
            }
        }

        self.cache.get(name)
    }

    /// List all available profiles.
    pub fn list(&self) -> Vec<&Profile> {
        self.cache.values().collect()
    }

    /// Create a new profile.
    pub fn create(&mut self, profile: Profile) -> ProfileResult<()> {
        profile.validate()?;

        if self.cache.contains_key(&profile.name) {
            return Err(ProfileError::AlreadyExists(profile.name.clone()));
        }

        self.save_profile(&profile)?;
        self.cache.insert(profile.name.clone(), profile);

        Ok(())
    }

    /// Delete a profile.
    pub fn delete(&mut self, name: &str) -> ProfileResult<()> {
        // Can't delete built-in profiles
        if Profile::builtins().iter().any(|p| p.name == name) {
            return Err(ProfileError::InvalidName(
                "cannot delete built-in profile".to_string(),
            ));
        }

        if !self.cache.contains_key(name) {
            return Err(ProfileError::NotFound(name.to_string()));
        }

        let file = self.profile_file(name);
        if file.exists() {
            fs::remove_file(&file).map_err(|e| ProfileError::SaveFailed(e.to_string()))?;
        }

        self.cache.remove(name);

        Ok(())
    }

    /// Load all profiles from disk.
    fn load_all(&mut self) -> ProfileResult<()> {
        // Add built-in profiles to cache
        for profile in Profile::builtins() {
            self.cache.insert(profile.name.clone(), profile);
        }

        // Load user profiles (will override built-ins with same name)
        if self.profiles_dir.exists() {
            for entry in fs::read_dir(&self.profiles_dir)
                .map_err(|e| ProfileError::SaveFailed(e.to_string()))?
            {
                let entry = entry.map_err(|e| ProfileError::SaveFailed(e.to_string()))?;
                let path = entry.path();

                if path.extension().map_or(false, |ext| ext == "json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(profile) = serde_json::from_str::<Profile>(&content) {
                            self.cache.insert(profile.name.clone(), profile);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Save a profile to disk.
    fn save_profile(&self, profile: &Profile) -> ProfileResult<()> {
        let file = self.profile_file(&profile.name);
        let content = serde_json::to_string_pretty(profile)
            .map_err(|e| ProfileError::SaveFailed(e.to_string()))?;

        fs::write(&file, content).map_err(|e| ProfileError::SaveFailed(e.to_string()))
    }

    /// Get the file path for a profile.
    fn profile_file(&self, name: &str) -> PathBuf {
        self.profiles_dir.join(format!("{}.json", name))
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new().expect("Failed to initialize profile manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_validation() {
        let mut profile = Profile::new("test");
        assert!(profile.validate().is_ok());

        profile.name = "".to_string();
        assert!(profile.validate().is_err());

        profile.name = "test!@#".to_string();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn test_builtin_profiles() {
        let builtins = Profile::builtins();
        assert!(!builtins.is_empty());

        for profile in builtins {
            assert!(profile.validate().is_ok());
        }
    }

    #[test]
    fn test_profile_serialization() {
        let profile = Profile::quick();
        let json = serde_json::to_string(&profile).unwrap();
        let parsed: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, profile.name);
    }
}
