//! Config commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};
use std::path::PathBuf;

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
}

impl ConfigCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
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
        }
        
        Ok(())
    }
}