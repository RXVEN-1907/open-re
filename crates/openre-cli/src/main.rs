//! openre - Unified Reverse Engineering & Offensive Security CLI
//!
//! A single binary for binary analysis, web scanning, AI-powered vulnerability discovery,
//! PoC generation, and actionable remediation guidance.

use clap::{Parser, Subcommand, ValueEnum, CommandFactory};
use clap_complete::{generate, Shell};
use colored::Colorize;
use openre_config::Config;
use std::path::PathBuf;

mod commands;
mod config;
mod context;
mod error;
mod output;
mod ai_stubs;
mod analysis_stubs;
mod intelligence_stubs;

use commands::{
    ai::AiCommands, analyze::AnalyzeCommands, config::ConfigCommands, exploit::ExploitCommands,
    remediate::RemediateCommands, scan::ScanCommands,
};
pub use config::CliConfig;
pub use context::Context;
pub use error::CliError;
pub use output::{print_output, OutputFormat};

#[derive(Parser, Debug)]
#[command(
    name = "openre",
    version,
    about = "openre - Reverse engineering & offensive security platform",
    long_about = "Unified CLI for binary analysis, web scanning, AI-powered vulnerability discovery,\nPoC exploit generation, and actionable remediation guidance.\n\nAll features work locally. Cloud AI is optional. No database or server required.",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Output format
    #[arg(short, long, global = true, default_value = "table", value_enum)]
    format: OutputFormat,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Run in offline mode (no network requests except explicit targets)
    #[arg(long, global = true)]
    offline: bool,

    /// Generate shell completions
    #[arg(long, global = true, value_name = "SHELL")]
    completion: Option<Shell>,

    /// AI provider to use
    #[arg(long, global = true, value_enum, default_value = "auto")]
    ai_provider: AiProviderArg,

    /// AI model (for local providers)
    #[arg(long, global = true)]
    ai_model: Option<String>,

    /// Disable AI features entirely
    #[arg(long, global = true)]
    no_ai: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum AiProviderArg {
    Auto,
    Local,
    Ollama,
    LlamaCpp,
    Onnx,
    OpenAI,
    Anthropic,
    Vllm,
}

impl From<AiProviderArg> for crate::ai_stubs::AiProvider {
    fn from(p: AiProviderArg) -> Self {
        match p {
            AiProviderArg::Auto => crate::ai_stubs::AiProvider::Local, // Default to local
            AiProviderArg::Local => crate::ai_stubs::AiProvider::Local,
            AiProviderArg::Ollama => crate::ai_stubs::AiProvider::Ollama,
            AiProviderArg::LlamaCpp => crate::ai_stubs::AiProvider::LlamaCpp,
            AiProviderArg::Onnx => crate::ai_stubs::AiProvider::Onnx,
            AiProviderArg::OpenAI => crate::ai_stubs::AiProvider::OpenAI,
            AiProviderArg::Anthropic => crate::ai_stubs::AiProvider::Anthropic,
            AiProviderArg::Vllm => crate::ai_stubs::AiProvider::Vllm,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan web applications and APIs for vulnerabilities
    #[command(subcommand)]
    Scan(ScanCommands),

    /// Analyze binaries (ELF, PE, Mach-O, WASM)
    #[command(subcommand)]
    Analyze(AnalyzeCommands),

    /// AI-powered vulnerability analysis and exploitation
    #[command(subcommand)]
    Ai(AiCommands),

    /// Generate proof-of-concept exploits for findings
    #[command(subcommand)]
    Exploit(ExploitCommands),

    /// Get actionable remediation guidance
    #[command(subcommand)]
    Remediate(RemediateCommands),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Show version and build info
    Version,
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Handle completion generation
    if let Some(shell) = cli.completion {
        generate(shell, &mut Cli::command(), "openre", &mut std::io::stdout());
        return Ok(());
    }

    // Initialize tracing
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Load configuration
    let config = CliConfig::load(cli.config.as_deref())?;

    // Create context
    let ai_provider: crate::ai_stubs::AiProvider = cli.ai_provider.into();
    let ctx = Context::new(config, cli.format, cli.verbose, cli.offline, ai_provider, cli.ai_model, cli.no_ai)?;

    // Execute command
    let result = match cli.command {
        Commands::Scan(cmd) => cmd.execute(ctx).await,
        Commands::Analyze(cmd) => cmd.execute(ctx).await,
        Commands::Ai(cmd) => cmd.execute(ctx).await,
        Commands::Exploit(cmd) => cmd.execute(ctx).await,
        Commands::Remediate(cmd) => cmd.execute(ctx).await,
        Commands::Config(cmd) => cmd.execute(ctx).await,
        Commands::Version => {
            print_version();
            Ok(())
        }
    };

    if let Err(e) = &result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }

    result
}

fn print_version() {
    println!(
        "{} {}",
        "openre".bold().cyan(),
        env!("CARGO_PKG_VERSION").bold()
    );
    println!("{}", "Unified reverse engineering & offensive security platform".dimmed());
    println!();
    println!("{}", "Features:".bold());
    println!("  • Binary analysis (ELF, PE, Mach-O, WASM)");
    println!("  • Web/API vulnerability scanning");
    println!("  • AI-powered analysis (local: Ollama, llama.cpp, ONNX | cloud: OpenAI, Anthropic)");
    println!("  • PoC exploit generation");
    println!("  • Actionable remediation guidance");
    println!("  • SARIF/JSON/Table output for CI/CD");
    println!();
    println!("{}", "No database, no server, no Docker required. Just works.".green());
    println!("{}", "https://github.com/RXVEN-1907/open-re".dimmed());
}