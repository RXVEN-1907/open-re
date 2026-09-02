//! openre-tui - Full-screen interactive TUI for open-re platform

use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_tui::{run_tui, App};
use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::{fmt, EnvFilter};

const ASCII_BANNER: &str = r#"
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚══╝     ╚══════╝╚═╝  ╚═══╝         ╚═════╝ ╚══════╝
"#;

#[derive(Parser, Debug)]
#[command(name = "openre-tui")]
#[command(about = "Full-screen interactive TUI for open-re platform")]
#[command(
    long_about = "openre-tui: Full-screen terminal user interface for the open-re platform\n\nPanels: Projects, Jobs, Scans, Reverse Engineering, Findings, Workflows, AI, Plugins, Logs, Reports\n\nPart of the open-re platform: https://github.com/RXVEN-1907/open-re"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Theme to use
    #[arg(long, global = true, value_enum, default_value = "dark")]
    theme: ThemeArg,

    /// Disable mouse support
    #[arg(long)]
    no_mouse: bool,

    /// Start in specific panel
    #[arg(long, value_enum)]
    panel: Option<PanelArg>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ThemeArg {
    Dark,
    Light,
    HighContrast,
    SolarizedDark,
    SolarizedLight,
    Dracula,
    Nord,
    Gruvbox,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum PanelArg {
    Projects,
    Jobs,
    Scans,
    ReverseEngineering,
    Findings,
    Workflows,
    AI,
    Plugins,
    Logs,
    Reports,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the TUI (default)
    Run,

    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let filter = EnvFilter::new(level.to_string());
    fmt().with_env_filter(filter).compact().init();

    // Print banner
    println!("{}", ASCII_BANNER.bright_cyan().bold());
    println!("{}", "openre-tui - Full-screen Interactive TUI".bright_white());
    println!("{}", "Part of the open-re platform".dimmed());
    println!();

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => {
            println!("{}", "Starting TUI...".bright_cyan());
            run_tui().await?;
        }
        Commands::Version => {
            println!("{} {}", "Version:".bold(), env!("CARGO_PKG_VERSION").bright_white());
            println!("{} {}", "Component:".bold(), "openre-tui".bright_white());
            println!(
                "{} {}",
                "Repository:".bold(),
                "https://github.com/RXVEN-1907/open-re".bright_blue().underline()
            );
        }
    }

    Ok(())
}
