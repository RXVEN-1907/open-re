//! CLI for open-re

pub mod commands;
mod config;
mod context;
mod error;
mod output;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use commands::{
    agent::AgentCommand, ai::AiCommands, analysis::AnalysisCommands, analyst::AnalystCommands,
    attack_paths::AttackPathsCommand, auth::AuthCommands, compare::CompareCommand,
    config::ConfigCommands, file::FileCommands, finding::FindingCommands,
    function::FunctionCommands, investigate::InvestigateCommand, job::JobCommands,
    knowledge::KnowledgeCommand, map::MapCommand, plugin::PluginCommands, prioritize::PrioritizeCommand,
    project::ProjectCommands, recheck::RecheckCommand, relationships::RelationshipsCommand,
    report::ReportCommands, scan::ScanCommands, server::ServerCommands, tui::TuiCommands,
    verify::VerifyCommand,
};
pub use config::CliConfig;
pub use context::offline::OfflineStore;
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

    /// Run in offline mode (local operations without API server)
    #[arg(long, global = true)]
    offline: bool,

    /// Local database path for offline mode
    #[arg(long, global = true, value_name = "PATH")]
    local_db: Option<PathBuf>,

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

    /// Binary analysis
    #[command(subcommand)]
    Analysis(AnalysisCommands),

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

    /// Application Map
    Map(MapCommand),

    /// Finding Relationships
    Relationships(RelationshipsCommand),

    /// Attack Paths
    AttackPaths(AttackPathsCommand),

    /// Finding Verification
    Verify(VerifyCommand),

    /// Scan Comparison
    Compare(CompareCommand),

    /// Finding Recheck
    Recheck(RecheckCommand),

    /// Finding Prioritization
    Prioritize(PrioritizeCommand),

    /// Security Knowledge
    Knowledge(KnowledgeCommand),

    /// Investigation Workflow
    Investigate(InvestigateCommand),

    /// Agent Management
    Agent(AgentCommand),

    /// Job management
    #[command(subcommand)]
    Job(JobCommands),

    /// Full-screen interactive TUI
    #[command(subcommand)]
    Tui(TuiCommands),
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
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build()?;

    // Create context with offline support
    let mut ctx = Context::new(
        config,
        client,
        cli.server,
        cli.api_key,
        cli.format,
        cli.verbose,
        cli.offline,
        cli.local_db,
    )?;

    // Execute command
    match cli.command {
        Commands::Auth(cmd) => cmd.execute(ctx).await,
        Commands::Project(cmd) => cmd.execute(ctx).await,
        Commands::File(cmd) => cmd.execute(ctx).await,
        Commands::Analysis(cmd) => cmd.execute(ctx).await,
        Commands::Function(cmd) => cmd.execute(ctx).await,
        Commands::Ai(cmd) => cmd.execute(ctx).await,
        Commands::Analyst(cmd) => cmd.execute(ctx).await,
        Commands::Plugin(cmd) => cmd.execute(ctx).await,
        Commands::Config(cmd) => cmd.execute(ctx).await,
        Commands::Server(cmd) => cmd.execute(ctx).await,
        Commands::Scan(cmd) => cmd.execute(ctx).await,
        Commands::Finding(cmd) => cmd.execute(ctx).await,
        Commands::Report(cmd) => cmd.execute(ctx).await,
        Commands::Map(cmd) => cmd.execute(ctx).await,
        Commands::Relationships(cmd) => cmd.execute(ctx).await,
        Commands::AttackPaths(cmd) => cmd.execute(ctx).await,
        Commands::Verify(cmd) => cmd.execute(ctx).await,
        Commands::Compare(cmd) => cmd.execute(ctx).await,
        Commands::Recheck(cmd) => cmd.execute(ctx).await,
        Commands::Prioritize(cmd) => cmd.execute(ctx).await,
        Commands::Knowledge(cmd) => cmd.execute(ctx).await,
        Commands::Investigate(cmd) => cmd.execute(ctx).await,
        Commands::Agent(cmd) => cmd.execute(ctx).await,
        Commands::Job(cmd) => cmd.execute(&mut ctx).await,
        Commands::Tui(cmd) => cmd.execute(ctx).await,
    }
}
