#![allow(clippy::too_many_lines)]
#![allow(clippy::module_inception)]
#![allow(clippy::ptr_arg)]

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

mod commands;
mod context;
mod error;
mod output;

pub use crate::context::Context;
pub use crate::error::{CliError, Result};
pub use crate::output::{print_output, OutputFormat};

use crate::commands::ai::AiCommands;
use crate::commands::analyze::AnalyzeCommands;
use crate::commands::config::ConfigCommands;
use crate::commands::exploit::ExploitCommands;
use crate::commands::hunt::HuntArgs;
use crate::commands::queue::QueueCommands;
use crate::commands::remediate::RemediateCommands;
use crate::commands::report::ReportCommands;
use crate::commands::scan::ScanCommands;
use crate::commands::schedule::ScheduleCommands;

/// OpenRe - Unified Reverse Engineering & Offensive Security CLI Tool
#[derive(Parser, Debug)]
#[command(name = "openre", author, version, about, long_about = None)]
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
    Hunt(HuntArgs),
    /// Web vulnerability scanning
    Scan {
        #[command(subcommand)]
        command: ScanCommands,
    },
    /// Binary analysis and disassembly
    Analyze {
        #[command(subcommand)]
        command: AnalyzeCommands,
    },
    /// AI-assisted analysis
    Ai {
        #[command(subcommand)]
        command: AiCommands,
    },
    /// PoC exploit generation
    Exploit {
        #[command(subcommand)]
        command: ExploitCommands,
    },
    /// Remediation guidance
    Remediate {
        #[command(subcommand)]
        command: RemediateCommands,
    },
    /// Report template management
    Report {
        #[command(subcommand)]
        command: ReportCommands,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Job queue management
    Queue {
        #[command(subcommand)]
        command: QueueCommands,
    },
    /// Scheduled scan management
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommands,
    },
    /// Generate shell completions
    Completions(CompletionsArgs),
}

#[derive(clap::Args, Debug)]
struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    shell: Shell,
}

fn print_completions(shell: Shell) {
    let mut buf = Vec::new();
    let mut cmd = Args::command();
    cmd.build();
    clap_complete::generate(shell, &mut cmd, "openre", &mut buf);
    // Ignore write errors so a closed pipe (e.g. `| head`) does not panic.
    use std::io::Write as _;
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(&buf);
    let _ = stdout.flush();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "openre=info".into());

    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();

    if args.debug {
        tracing::subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_max_level(tracing::Level::TRACE)
                .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
                .finish(),
        )
        .expect("Unable to set global default subscriber");
    }

    // Completions must work without a readable user config.
    if let Commands::Completions(completions) = args.command {
        print_completions(completions.shell);
        return Ok(());
    }

    let ctx = Context::new()?;

    match args.command {
        Commands::Hunt(command) => commands::hunt::execute(command).await,
        Commands::Scan { command } => command.execute(ctx).await,
        Commands::Analyze { command } => command.execute(ctx).await,
        Commands::Ai { command } => command.execute(ctx).await,
        Commands::Exploit { command } => command.execute(ctx).await,
        Commands::Remediate { command } => command.execute(ctx).await,
        Commands::Report { command } => command.execute(ctx).await,
        Commands::Config { command } => command.execute(ctx).await,
        Commands::Queue { command } => command.execute(ctx).await,
        Commands::Schedule { command } => command.execute(ctx).await,
        Commands::Completions(_) => unreachable!("handled before context construction"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Args::command().debug_assert();
    }

    #[test]
    fn completions_smoke() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell] {
            let mut buf = std::io::Cursor::new(Vec::new());
            let mut cmd = Args::command();
            cmd.build();
            clap_complete::generate(shell, &mut cmd, "openre", &mut buf);
            assert!(!buf.into_inner().is_empty(), "no completions for {:?}", shell);
        }
    }
}
