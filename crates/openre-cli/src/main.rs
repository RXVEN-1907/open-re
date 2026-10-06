#![allow(clippy::too_many_lines)]
#![allow(clippy::module_inception)]
#![allow(clippy::ptr_arg)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod analysis_stubs;
mod ai_stubs;
mod intelligence_stubs;
mod output;
mod error;
mod context;

use crate::commands::hunt::HuntArgs;

/// OpenRe - Unified Reverse Engineering & Offensive Security CLI Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Activate debug mode
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Subcommands
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Instant security assessment with AI-powered PoC generation and viral sharing
    Hunt(HuntArgs),  // New hunt command
}

#[tokio::main]
async fn main() -> Result<(), crate::error::CliError> {
    // Initialize tracing subscriber
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "openre=info".into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let args = Args::parse();

    if args.debug {
        tracing::subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_max_level(tracing::Level::TRACE)
                .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
                .finish()
        )
        .expect("Unable to set global default subscriber");
    }

    match args.command {
        Commands::Hunt(command) => {
            commands::hunt::execute(command).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        Args::command().debug_assert();
    }
}
