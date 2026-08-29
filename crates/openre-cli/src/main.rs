//! CLI for open-re

pub mod commands;
mod config;
mod context;
mod error;
mod output;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use colored::Colorize;
use commands::{
    ai::AiCommands, analyst::AnalystCommands, auth::AuthCommands,
    config::ConfigCommands, file::FileCommands, finding::FindingCommands, function::FunctionCommands,
    plugin::PluginCommands, project::ProjectCommands, report::ReportCommands, scan::ScanCommands,
    server::ServerCommands,
    // analysis::AnalysisCommands, // Temporarily disabled due to compilation errors
};
pub use config::CliConfig;
pub use context::Context;
pub use error::CliError;
pub use output::{print_output, print_smart_banner, show_startup_animation, OutputFormat};

use std::path::PathBuf;

/// Check if global help is requested (before any subcommand)
fn is_global_help_requested(args: &[String]) -> bool {
    // Skip the binary name (args[0])
    for arg in &args[1..] {
        // Stop at first non-flag (subcommand)
        if !arg.starts_with('-') {
            break;
        }
        if arg == "--help" || arg == "-h" {
            return true;
        }
    }
    false
}

/// Check if global version is requested (before any subcommand)
fn is_global_version_requested(args: &[String]) -> bool {
    // Skip the binary name (args[0])
    for arg in &args[1..] {
        // Stop at first non-flag (subcommand)
        if !arg.starts_with('-') {
            break;
        }
        if arg == "--version" || arg == "-V" {
            return true;
        }
    }
    false
}

/// Check if banner is explicitly disabled in raw args
fn is_banner_disabled(args: &[String]) -> bool {
    args.iter().any(|a| a == "--no-banner")
}

/// Disable colors for this process (using local control)
fn disable_colors() {
    // Use a local override instead of global
    let _ = colored::control::set_override(false);
}

#[derive(Parser)]
#[command(
    name = "openre",
    version,
    about = "open-re: Open-source reverse engineering platform",
    long_about = "A modern, extensible reverse engineering platform with AI-powered analysis",
    disable_help_subcommand = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Output format
    #[arg(short, long, global = true, default_value = "table")]
    format: OutputFormat,

    /// API server URL
    #[arg(long, global = true, default_value = "http://localhost:8080")]
    server: String,

    /// API key for authentication
    #[arg(long, global = true, env = "OPENRE_API_KEY")]
    api_key: Option<String>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Generate shell completions
    #[arg(long, global = true, value_name = "SHELL")]
    completion: Option<Shell>,

    /// Hide ASCII banner on startup (enabled by default)
    #[arg(long, global = true)]
    no_banner: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Authentication commands
    #[command(subcommand)]
    Auth(AuthCommands),

    /// Project management
    #[command(subcommand)]
    Project(ProjectCommands),

    /// File management
    #[command(subcommand)]
    File(FileCommands),

    // /// Binary analysis (temporarily disabled)
    //     #[command(subcommand)]
    //     Analysis(AnalysisCommands),

    /// Function analysis
    #[command(subcommand)]
    Function(FunctionCommands),

    /// AI-powered analysis
    #[command(subcommand)]
    Ai(AiCommands),

    /// AI Security Analyst
    #[command(subcommand)]
    Analyst(AnalystCommands),

    /// Plugin management
    #[command(subcommand)]
    Plugin(PluginCommands),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Server management
    #[command(subcommand)]
    Server(ServerCommands),

    /// Scan management
    #[command(subcommand)]
    Scan(ScanCommands),

    /// Finding management
    #[command(subcommand)]
    Finding(FindingCommands),

    /// Report generation
    #[command(subcommand)]
    Report(ReportCommands),

    /// Show version information
    Version,

    /// Show help information
    Help {
        /// Command to show help for (supports nested subcommands like "auth login")
        #[arg(value_name = "COMMAND", num_args = 1..)]
        command: Vec<String>,
    },
}

/// Print version information
fn print_version_info() {
    println!("{} {}", "Version:".bold(), env!("CARGO_PKG_VERSION").bright_white());
    println!("{} {}", "Component:".bold(), "openre-cli (unified CLI)".bright_white());
    println!(
        "{} {}",
        "Repository:".bold(),
        "https://github.com/RXVEN-1907/open-re".bright_blue().underline()
    );
    println!("{} {}", "Platform:".bold(), "open-re v0.2.0-dev".bright_white());
    println!();
    println!("{}", "Part of the open-re platform:".dimmed());
    println!("  • openre-scan — Standalone security scanner");
    println!("  • openre-cli — Unified CLI for all platform operations (this tool)");
    println!("  • openre-api — REST/gRPC API server");
    println!("  • openre-analysis — Binary analysis pipeline");
    println!("  • openre-plugins — WASM plugin system");
    println!("  • openre-security-ai — AI-powered vulnerability analysis");
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    // Capture raw args before clap parses them
    let raw_args: Vec<String> = std::env::args().collect();

    // Check for global help/version requests early to show banner
    let show_help = is_global_help_requested(&raw_args);
    let show_version = is_global_version_requested(&raw_args);
    let no_banner = is_banner_disabled(&raw_args);
    let show_banner = !no_banner;

    // Show banner early for global help/version if requested
    if (show_help || show_version) && show_banner {
        print_smart_banner();
    }

    // Parse CLI
    let cli = Cli::parse();

    // Disable colors if requested
    if cli.no_color {
        disable_colors();
    }

    // Handle completion generation
    if let Some(shell) = cli.completion {
        generate(shell, &mut Cli::command(), "openre", &mut std::io::stdout());
        return Ok(());
    }

    // Handle Version command (subcommand)
    if matches!(cli.command, Commands::Version) {
        if show_banner {
            // Banner already shown if --version was in raw args
            // But if user ran `openre version` without --version flag, show banner now
            if !show_version {
                print_smart_banner();
            }
        }
        // Show animation for subcommand
        if show_banner {
            show_startup_animation().await;
        }
        print_version_info();
        return Ok(());
    }

    // Handle Help command (subcommand)
    if matches!(cli.command, Commands::Help { .. }) {
        if show_banner {
            // Banner already shown if --help was in raw args
            // But if user ran `openre help` without --help flag, show banner now
            if !show_help {
                print_smart_banner();
            }
        }
        // Show animation for subcommand
        if show_banner {
            show_startup_animation().await;
        }

        // Print help for specific command or general help
        if let Commands::Help { command } = cli.command {
            if !command.is_empty() {
                // Try to print help for subcommand (including nested)
                let mut cmd = Cli::command();
                let mut current_cmd = cmd;
                for (i, part) in command.iter().enumerate() {
                    if let Some(subcmd) = current_cmd.find_subcommand_mut(part) {
                        if i == command.len() - 1 {
                            subcmd.print_help().unwrap();
                            println!();
                        } else {
                            current_cmd = subcmd.clone();
                        }
                    } else {
                        eprintln!("Unknown command: {}", command.join(" "));
                        return Err(CliError::InvalidInput(format!("Unknown command: {}", command.join(" "))));
                    }
                }
            } else {
                // Print general help
                Cli::command().print_help().unwrap();
                println!();
            }
        }
        return Ok(());
    }

    // For regular commands, show banner by default (unless --no-banner)
    if show_banner {
        print_smart_banner();
    }

    // Load configuration
    let config = CliConfig::load(cli.config.as_deref())?;

    // Create HTTP client
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // Create context
    let ctx = Context {
        config,
        client,
        server_url: cli.server,
        api_key: cli.api_key,
        output_format: cli.format,
        verbose: cli.verbose,
    };

    // Execute command
    match cli.command {
        Commands::Auth(cmd) => cmd.execute(ctx).await,
        Commands::Project(cmd) => cmd.execute(ctx).await,
        Commands::File(cmd) => cmd.execute(ctx).await,
        // Commands::Analysis(cmd) => cmd.execute(ctx).await, // Temporarily disabled
        Commands::Function(cmd) => cmd.execute(ctx).await,
        Commands::Ai(cmd) => cmd.execute(ctx).await,
        Commands::Analyst(cmd) => cmd.execute(ctx).await,
        Commands::Plugin(cmd) => cmd.execute(ctx).await,
        Commands::Config(cmd) => cmd.execute(ctx).await,
        Commands::Server(cmd) => cmd.execute(ctx).await,
        Commands::Scan(cmd) => cmd.execute(ctx).await,
        Commands::Finding(cmd) => cmd.execute(ctx).await,
        Commands::Report(cmd) => cmd.execute(ctx).await,
        Commands::Version => unreachable!(), // Handled above
        Commands::Help { .. } => unreachable!(), // Handled above
    }
}
