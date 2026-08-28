//! Config commands

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tabled::{settings::Style, Table};

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set configuration value
    Set {
        #[arg(short, long)]
        key: String,

        #[arg(short, long)]
        value: String,
    },

    /// Get configuration value
    Get {
        #[arg(short, long)]
        key: String,
    },

    /// Reset configuration to defaults
    Reset {
        #[arg(long)]
        force: bool,
    },

    /// Show configuration file path
    Path,

    /// List configuration profiles
    #[command(name = "list-profiles")]
    ListProfiles,

    /// Use a configuration profile
    Use {
        #[arg(short, long)]
        profile: String,
    },

    /// Create a new profile
    CreateProfile {
        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        base: Option<String>,
    },

    /// Delete a profile
    DeleteProfile {
        #[arg(short, long)]
        name: String,

        #[arg(long)]
        force: bool,
    },

    /// Show current profile
    CurrentProfile,

    /// Edit configuration in $EDITOR
    Edit,
}

impl ConfigCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            ConfigCommands::Show => {
                let config = ctx.config.clone();
                print_output(&config, &ctx.output_format)?;
            }

            ConfigCommands::Set { key, value } => {
                ctx.config.set(&key, &value)?;
                ctx.config.save()?;
                println!("Configuration updated: {} = {}", key, value);
            }

            ConfigCommands::Get { key } => {
                if let Some(value) = ctx.config.get(&key) {
                    println!("{} = {}", key, value);
                } else {
                    println!("Key not found: {}", key);
                }
            }

            ConfigCommands::Reset { force } => {
                if !force {
                    print!("Are you sure you want to reset configuration to defaults? (y/N): ");
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                ctx.config.reset()?;
                ctx.config.save()?;
                println!("Configuration reset to defaults!");
            }

            ConfigCommands::Path => {
                if let Some(path) = ctx.config.path() {
                    println!("{}", path.display());
                } else {
                    println!("No configuration file found (using defaults)");
                }
            }

            ConfigCommands::ListProfiles => {
                let profiles = ctx.config.list_profiles()?;
                if profiles.is_empty() {
                    println!("No profiles found. Create one with 'openre config create-profile'.");
                } else {
                    let current = ctx.config.current_profile()?;
                    for profile in profiles {
                        let marker = if current.as_ref() == Some(&profile) { " * " } else { "   " };
                        println!("{} {}", marker, profile);
                    }
                    println!("\n* indicates current profile");
                }
            }

            ConfigCommands::Use { profile } => {
                ctx.config.use_profile(&profile)?;
                ctx.config.save()?;
                println!("Switched to profile: {}", profile);
            }

            ConfigCommands::CreateProfile { name, base } => {
                ctx.config.create_profile(&name, base.as_deref())?;
                ctx.config.save()?;
                println!("Profile '{}' created successfully!", name);
            }

            ConfigCommands::DeleteProfile { name, force } => {
                if !force {
                    print!("Are you sure you want to delete profile '{}'? (y/N): ", name);
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                ctx.config.delete_profile(&name)?;
                ctx.config.save()?;
                println!("Profile '{}' deleted!", name);
            }

            ConfigCommands::CurrentProfile => {
                if let Some(current) = ctx.config.current_profile()? {
                    println!("Current profile: {}", current);
                } else {
                    println!("No profile selected (using defaults)");
                }
            }

            ConfigCommands::Edit => {
                let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
                if let Some(path) = ctx.config.path() {
                    let status = std::process::Command::new(&editor)
                        .arg(&path)
                        .status()?;
                    if status.success() {
                        println!("Configuration edited. Reloading...");
                        ctx.config.reload()?;
                    } else {
                        println!("Editor exited with error.");
                    }
                } else {
                    println!("No configuration file found. Create one first with 'openre config set'.");
                }
            }
        }

        Ok(())
    }
}
