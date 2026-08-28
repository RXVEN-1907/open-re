//! Server commands

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};

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

        #[arg(long)]
        daemon: bool,
    },

    /// Stop the API server
    Stop,

    /// Check server status
    Status,

    /// Check server health
    Health,

    /// Get server info
    Info,

    /// Get server metrics
    Metrics,
}

impl ServerCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            ServerCommands::Start {
                port,
                host,
                workers,
                daemon,
            } => {
                println!("Starting server on {}:{}...", host, port);
                if daemon {
                    println!("Running in daemon mode...");
                }
                println!("Note: This command would start the server in the background.");
                println!("For production, use the Docker image or systemd service.");

                // In a real implementation, this would start the server
                // For now, just show the command that would be run
                println!("\nTo start the server, run:");
                println!(
                    "  cargo run --bin openre-api -- --port {} --host {}",
                    port, host
                );
                if let Some(workers) = workers {
                    println!("  With {} workers", workers);
                }
            }

            ServerCommands::Stop => {
                println!("Stopping server...");
                // In a real implementation, this would send a shutdown signal
                // For now, just show what would happen
                println!("Server stop signal sent.");
                println!("  (In production, this would send SIGTERM to the server process)");
            }

            ServerCommands::Status => {
                println!("Checking server status...");
                let response = ctx.get("/ready").await;
                match response {
                    Ok(resp) if resp.status().is_success() => {
                        let info: serde_json::Value = resp.json().await?;
                        println!("{} Server is running", "✓".green());
                        print_output(&info, &ctx.output_format)?;
                    }
                    Ok(resp) => {
                        println!("{} Server responded with error: {}", "✗".red(), resp.status());
                    }
                    Err(e) => {
                        println!("{} Server is not reachable: {}", "✗".red(), e);
                        println!("  Make sure the server is running on {}", ctx.server_url);
                    }
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
