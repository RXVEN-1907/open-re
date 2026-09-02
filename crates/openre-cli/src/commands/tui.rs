//! TUI command for launching the full-screen terminal UI

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

/// TUI command
#[derive(Subcommand, Debug)]
pub enum TuiCommands {
    /// Launch the full-screen interactive TUI (default)
    Run(TuiRunArgs),

    /// Show TUI version information
    Version,
}

/// Arguments for running the TUI
#[derive(Args, Debug)]
pub struct TuiRunArgs {
    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Theme to use
    #[arg(long, value_enum, default_value = "dark")]
    pub theme: ThemeArg,

    /// Disable mouse support
    #[arg(long)]
    pub no_mouse: bool,

    /// Start in specific panel
    #[arg(long, value_enum)]
    pub panel: Option<PanelArg>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ThemeArg {
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
pub enum PanelArg {
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

impl TuiCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            TuiCommands::Run(args) => {
                println!("{}", "🚀 Launching openre-tui...".bright_cyan().bold());
                println!("{}", "Press F1 for help, Ctrl+Q to quit".dimmed());
                println!();

                // Set up environment for TUI
                if let Some(theme) = std::env::var("OPENRE_TUI_THEME").ok() {
                    // Theme already set via env
                } else {
                    std::env::set_var("OPENRE_TUI_THEME", format!("{:?}", args.theme));
                }

                if args.no_mouse {
                    std::env::set_var("OPENRE_TUI_NO_MOUSE", "1");
                }

                if let Some(ref panel) = args.panel {
                    std::env::set_var("OPENRE_TUI_START_PANEL", format!("{:?}", panel));
                }

                // Forward the config path
                if let Some(config) = args.config {
                    std::env::set_var("OPENRE_CONFIG", config.display().to_string());
                }

                // Set verbose logging
                if args.verbose {
                    std::env::set_var("RUST_LOG", "debug");
                }

                // Run the TUI
                // We need to call the openre_tui::run_tui function
                // Since openre-tui is a separate binary, we'll exec it
                use std::process::Command;

                let mut cmd = Command::new("openre-tui");
                cmd.arg("run");

                if args.verbose {
                    cmd.arg("--verbose");
                }

                if args.no_mouse {
                    cmd.arg("--no-mouse");
                }

                match format!("{:?}", args.theme).to_lowercase().as_str() {
                    "light" => cmd.arg("--theme").arg("light"),
                    "highcontrast" => cmd.arg("--theme").arg("high-contrast"),
                    "solarizeddark" => cmd.arg("--theme").arg("solarized-dark"),
                    "solarizedlight" => cmd.arg("--theme").arg("solarized-light"),
                    "dracula" => cmd.arg("--theme").arg("dracula"),
                    "nord" => cmd.arg("--theme").arg("nord"),
                    "gruvbox" => cmd.arg("--theme").arg("gruvbox"),
                    _ => &mut cmd,
                };

                if let Some(panel) = args.panel {
                    cmd.arg("--panel").arg(format!("{:?}", panel).to_lowercase());
                }

                // Execute and wait
                let status = cmd.status()?;
                if !status.success() {
                    return Err(CliError::Other(format!(
                        "TUI exited with status: {:?}",
                        status.code()
                    )));
                }

                Ok(())
            }
            TuiCommands::Version => {
                println!("{}", "openre-tui".bright_cyan().bold());
                println!("Version: {}", env!("CARGO_PKG_VERSION"));
                println!("Part of: open-re platform");
                println!("Repository: https://github.com/RXVEN-1907/open-re");
                Ok(())
            }
        }
    }
}
