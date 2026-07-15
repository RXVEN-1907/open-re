//! Server commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Start the API server
    Start {
        #[arg(short, long, default_value = "8080")]
        port: u16,
        
        #[arg(short, long, default_value = "0.0.0.0")]
        host: String,
        
        #[arg(long)]
        workers: Option<usize>,
    },
    
    /// Check server health
    Health,
    
    /// Get server info
    Info,
    
    /// Get server metrics
    Metrics,
}

impl ServerCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ServerCommands::Start { port, host, workers } => {
                println!("Starting server on {}:{}...", host, port);
                println!("Note: This command would start the server in the background.");
                println!("For production, use the Docker image or systemd service.");
                
                // In a real implementation, this would start the server
                // For now, just show the command that would be run
                println!("\nTo start the server, run:");
                println!("  cargo run --bin openre-api -- --port {} --host {}", port, host);
                if let Some(workers) = workers {
                    println!("  With {} workers", workers);
                }
            }
            
            ServerCommands::Health => {
                let response = ctx.get("/health").await?;
                let health: serde_json::Value = response.json().await?;
                print_output(&health, &ctx.output_format)?;
            }
            
            ServerCommands::Info => {
                let response = ctx.get("/ready").await?;
                let info: serde_json::Value = response.json().await?;
                print_output(&info, &ctx.output_format)?;
            }
            
            ServerCommands::Metrics => {
                let response = ctx.get("/metrics").await?;
                let text = response.text().await?;
                println!("{}", text);
            }
        }
        
        Ok(())
    }
}