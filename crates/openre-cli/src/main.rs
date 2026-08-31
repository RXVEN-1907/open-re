//! CLI for open-re

pub mod commands;
mod config;
mod context;
mod error;
mod output;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use commands::{
    ai::AiCommands, analyst::AnalystCommands, auth::AuthCommands,
    config::ConfigCommands, file::FileCommands, finding::FindingCommands, function::FunctionCommands,
    plugin::PluginCommands, project::ProjectCommands, report::ReportCommands, scan::ScanCommands,
    server::ServerCommands, worker::WorkerCommands,
    // analysis::AnalysisCommands, // Temporarily disabled due to compilation errors
};
pub use config::CliConfig;
pub use context::Context;
pub use error::CliError;
pub use output::{print_output, OutputFormat};

use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "openre",
    version,
    about = "open-re: Open-source reverse engineering platform",
    long_about = "A modern, extensible reverse engineering platform with AI-powered analysis"
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

    /// Worker management
    #[command(subcommand)]
    Worker(WorkerCommands),
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Handle completion generation
    if let Some(shell) = cli.completion {
        generate(shell, &mut Cli::command(), "openre", &mut std::io::stdout());
        return Ok(());
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
        Commands::Worker(cmd) => cmd.execute(ctx).await,
    }
}
