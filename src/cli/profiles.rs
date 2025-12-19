//! Profiles subcommand implementation.
//!
//! Handles the `scuttle profiles` command for managing scan profiles.

use crate::config::{Profile, ProfileManager};
use crate::error::CliResult;
use crate::output;
use clap::{Parser, Subcommand};

/// Manage scan profiles.
#[derive(Parser, Debug)]
pub struct ProfilesCommand {
    #[command(subcommand)]
    pub action: ProfilesAction,
}

/// Profile management actions.
#[derive(Subcommand, Debug)]
pub enum ProfilesAction {
    /// List all available profiles
    List,

    /// Show details of a specific profile
    Show {
        /// Profile name
        name: String,
    },

    /// Create a new profile
    Create {
        /// Profile name
        name: String,

        /// Ports to scan
        #[arg(short, long, default_value = "1-1000")]
        ports: String,

        /// Scan type (connect, syn, udp)
        #[arg(short = 's', long, default_value = "connect")]
        scan_type: String,

        /// Concurrency level
        #[arg(short, long, default_value = "500")]
        concurrency: usize,

        /// Timeout in milliseconds
        #[arg(short, long, default_value = "3000")]
        timeout: u64,

        /// Enable banner grabbing
        #[arg(short, long)]
        banner: bool,

        /// Rate limit (packets per second)
        #[arg(short, long, default_value = "0")]
        rate_limit: u32,

        /// Profile description
        #[arg(short = 'd', long)]
        description: Option<String>,
    },

    /// Delete a profile
    Delete {
        /// Profile name
        name: String,

        /// Skip confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

impl ProfilesCommand {
    /// Execute the profiles command.
    pub fn execute(&self, _verbose: bool, quiet: bool) -> CliResult<()> {
        match &self.action {
            ProfilesAction::List => self.list_profiles(quiet),
            ProfilesAction::Show { name } => self.show_profile(name, quiet),
            ProfilesAction::Create {
                name,
                ports,
                scan_type,
                concurrency,
                timeout,
                banner,
                rate_limit,
                description,
            } => self.create_profile(
                name,
                ports,
                scan_type,
                *concurrency,
                *timeout,
                *banner,
                *rate_limit,
                description.as_deref(),
                quiet,
            ),
            ProfilesAction::Delete { name, yes } => self.delete_profile(name, *yes, quiet),
        }
    }

    fn list_profiles(&self, quiet: bool) -> CliResult<()> {
        let manager = ProfileManager::new()?;
        let profiles = manager.list();

        if profiles.is_empty() {
            if !quiet {
                println!("No profiles found.");
            }
            return Ok(());
        }

        if !quiet {
            println!("\n{:<15} {:<12} {:<20} {}", "NAME", "SCAN TYPE", "PORTS", "DESCRIPTION");
            println!("{}", "-".repeat(70));
        }

        for profile in profiles {
            let ports_display = if profile.ports.len() > 18 {
                format!("{}...", &profile.ports[..18])
            } else {
                profile.ports.clone()
            };

            let desc = if profile.description.len() > 30 {
                format!("{}...", &profile.description[..30])
            } else {
                profile.description.clone()
            };

            println!(
                "{:<15} {:<12} {:<20} {}",
                profile.name, profile.scan_type, ports_display, desc
            );
        }

        if !quiet {
            println!();
        }

        Ok(())
    }

    fn show_profile(&self, name: &str, _quiet: bool) -> CliResult<()> {
        let manager = ProfileManager::new()?;
        let profile = manager
            .get(name)
            .ok_or_else(|| crate::error::CliError::Other(format!("profile '{}' not found", name)))?;

        println!("\nProfile: {}", profile.name);
        println!("{}", "=".repeat(40));
        println!("Description:  {}", profile.description);
        println!("Ports:        {}", profile.ports);
        println!("Scan Type:    {}", profile.scan_type);
        println!("Concurrency:  {}", profile.concurrency);
        println!("Timeout:      {} ms", profile.timeout_ms);
        println!("Banner Grab:  {}", if profile.banner { "yes" } else { "no" });
        println!(
            "Rate Limit:   {}",
            if profile.rate_limit == 0 {
                "unlimited".to_string()
            } else {
                format!("{} pps", profile.rate_limit)
            }
        );
        println!();

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn create_profile(
        &self,
        name: &str,
        ports: &str,
        scan_type: &str,
        concurrency: usize,
        timeout: u64,
        banner: bool,
        rate_limit: u32,
        description: Option<&str>,
        quiet: bool,
    ) -> CliResult<()> {
        let mut manager = ProfileManager::new()?;

        let profile = Profile {
            name: name.to_string(),
            description: description.unwrap_or("").to_string(),
            ports: ports.to_string(),
            scan_type: scan_type.to_string(),
            concurrency,
            timeout_ms: timeout,
            banner,
            rate_limit,
        };

        manager.create(profile)?;

        if !quiet {
            output::print_success(&format!("Profile '{}' created successfully", name));
        }

        Ok(())
    }

    fn delete_profile(&self, name: &str, yes: bool, quiet: bool) -> CliResult<()> {
        let mut manager = ProfileManager::new()?;

        // Verify profile exists
        if manager.get(name).is_none() {
            return Err(crate::error::CliError::Other(format!(
                "profile '{}' not found",
                name
            )));
        }

        // Confirm deletion
        if !yes {
            println!("Delete profile '{}'? [y/N] ", name);
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
        }

        manager.delete(name)?;

        if !quiet {
            output::print_success(&format!("Profile '{}' deleted", name));
        }

        Ok(())
    }
}
