#![allow(clippy::too_many_lines)]
#![allow(clippy::module_inception)]
#![allow(clippy::ptr_arg)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
use commands::{
    ai::AiCommands,
    analyze::AnalyzeCommands,
    config::ConfigCommands,
    exploit::ExploitCommands,
    remediate::RemediateCommands,
    report::ReportCommands,
    schedule::ScheduleCommands,
    hunt::HuntSubcommands,  // New import for hunt command
};

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
    /// AI-powered analysis and remediation suggestions
    Ai(AiCommands),
    /// Analyze files, binaries, and network traffic
    Analyze(AnalyzeCommands),
    /// Configure OpenRe settings
    Config(ConfigCommands),
    /// Generate exploit code and proof-of-concepts
    Exploit(ExploitCommands),
    /// Remediate vulnerabilities with AI-generated fixes
    Remediate(RemediateCommands),
    /// Generate reports in various formats
    Report(ReportCommands),
    /// Schedule recurring scans and monitoring
    Schedule(ScheduleCommands),
    /// Instant security assessment with AI-powered PoC generation and viral sharing
    Hunt(HuntSubcommands),  // New hunt command
}

#[tokio::main]
async fn main() {
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
        Commands::Ai(command) => {
            commands::ai::execute(command).await?;
        }
        Commands::Analyze(command) => {
            commands::analyze::execute(command).await?;
        }
        Commands::Config(command) => {
            commands::config::execute(command).await?;
        }
        Commands::Exploit(command) => {
            commands::exploit::execute(command).await?;
        }
        Commands::Remediate(command) => {
            commands::remediate::execute(command).await?;
        }
        Commands::Report(command) => {
            commands::report::execute(command).await?;
        }
        Commands::Schedule(command) => {
            commands::schedule::execute(command).await?;
        }
        Commands::Hunt(command) => {
            commands::hunt::execute(command).await?;
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
