//! openre-scan - Lightweight Standalone Security Scanner
//!
//! A minimal, fast security assessment tool for web applications and APIs.

use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_config::{Config, ScannerConfig};
use openre_scan::{run_scan, OutputFormat, ScanConfig, ScanProfile};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use tracing::Level;
use tracing_subscriber::{fmt, EnvFilter};

// ASCII Art Banner from README
const ASCII_BANNER: &str = r#"
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝
"#;

const ASCII_BANNER_SMALL: &str = r#"
███████╗██████╗ ██████╗  ██████╗ ███████╗███████╗
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝
█████╗  ██████╔╝██████╔╝██║   ██║███████╗█████╗
██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║╚════██║██╔══╝
███████╗██║  ██║██║     ╚██████╔╝███████║███████╗
╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝
"#;

/// Print the ASCII art banner
fn print_banner() {
    println!("{}", ASCII_BANNER.bright_cyan().bold());
    println!("{}", "Open-source Reverse Engineering & Offensive Security Platform".bright_white());
    println!(
        "{}",
        "Modern security tools + LLMs for automated binary, web, API & app analysis".dimmed()
    );
    println!(
        "{}",
        "Discover vulnerabilities • Generate PoC exploits • Actionable remediation".dimmed()
    );
    println!();
}

/// Print a compact banner for smaller terminals
fn print_compact_banner() {
    println!("{}", ASCII_BANNER_SMALL.bright_cyan().bold());
    println!("{}", "open-re: Security Scanner & Reverse Engineering Platform".bright_white());
    println!();
}

/// Detect terminal width and print appropriate banner
fn print_smart_banner() {
    let width = terminal_width().unwrap_or(80);
    if width >= 100 {
        print_banner();
    } else {
        print_compact_banner();
    }
}

/// Get terminal width
fn terminal_width() -> Option<usize> {
    // Try crossterm first
    #[cfg(feature = "tui")]
    {
        use crossterm::terminal::size;
        if let Ok((w, _)) = size() {
            return Some(w as usize);
        }
    }
    // Fallback to env var
    std::env::var("COLUMNS").ok().and_then(|s| s.parse().ok())
}

/// Animated spinner for startup
#[allow(dead_code)]
async fn show_startup_animation() {
    let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let message = "Initializing openre-scan...";

    for _ in 0..2 {
        for frame in frames {
            print!("\r{} {} ", frame.bright_cyan(), message.bright_white());
            io::stdout().flush().ok();
            sleep(Duration::from_millis(80)).await;
        }
    }
    println!("\r{} {}", "✓".green(), "Ready!".green().bold());
    println!();
}

#[derive(Parser, Debug)]
#[command(name = "openre-scan")]
#[command(about = "Lightweight Security Scanner")]
#[command(
    long_about = "openre-scan: Lightweight standalone security scanner for web applications and APIs\n\nA minimal, fast security assessment tool with 18+ security checks across three scan profiles.\nPart of the open-re platform: https://github.com/RXVEN-1907/open-re"
)]
#[command(version)]
#[command(
    after_help = "Examples:\n  openre-scan scan https://example.com --profile quick\n  openre-scan scan https://example.com --profile standard --format json\n  openre-scan scan https://example.com --profile full --output results.sarif\n  openre-scan tui\n\nFor more information, visit: https://github.com/RXVEN-1907/open-re"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, global = true, default_value = "table", value_enum)]
    format: OutputFormat,

    /// Configuration file path (default: ~/.config/openre/config.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Request timeout in seconds (overrides config file)
    #[arg(long, global = true)]
    timeout: Option<u64>,

    /// Maximum redirects (overrides config file)
    #[arg(long, global = true)]
    max_redirects: Option<usize>,

    /// User agent (overrides config file)
    #[arg(long, global = true)]
    user_agent: Option<String>,

    /// Follow redirects (overrides config file)
    #[arg(long, global = true)]
    follow_redirects: Option<bool>,

    /// Show ASCII banner on startup
    #[arg(long, global = true, default_value = "true")]
    banner: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Scan profile (overrides config file)
    #[arg(long, global = true)]
    profile: Option<ScanProfile>,

    /// Maximum scan duration in seconds (overrides config file)
    #[arg(long, global = true)]
    max_duration: Option<u64>,

    /// Rate limit requests per second (overrides config file)
    #[arg(long, global = true)]
    rate_limit: Option<f64>,

    /// Number of concurrent checks (overrides config file)
    #[arg(long, global = true)]
    concurrent: Option<usize>,

    /// Disable TLS verification (overrides config file)
    #[arg(long, global = true)]
    no_tls_verify: bool,

    /// Proxy URL (overrides config file)
    #[arg(long, global = true)]
    proxy: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a target
    Scan {
        /// Target to scan (URL)
        target: String,

        /// Scan profile
        #[arg(short, long, value_enum)]
        profile: Option<ScanProfile>,

        /// Output format
        #[arg(short, long, value_enum)]
        format: Option<OutputFormat>,

        /// Checks to run (comma-separated)
        #[arg(long, value_delimiter = ',')]
        checks: Option<Vec<String>>,

        /// Checks to exclude (comma-separated)
        #[arg(long, value_delimiter = ',')]
        exclude: Option<Vec<String>>,

        /// Maximum scan duration in seconds
        #[arg(long)]
        max_duration: Option<u64>,

        /// Save scan results to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable progress bar
        #[arg(long)]
        no_progress: bool,

        /// Follow redirects
        #[arg(long)]
        follow_redirects: Option<bool>,

        /// Custom headers (key=value)
        #[arg(long, value_delimiter = ',', value_parser = parse_header)]
        header: Option<Vec<(String, String)>>,
    },

    /// Show version information
    Version,

    /// Launch interactive TUI (experimental)
    #[cfg(feature = "tui")]
    Tui,
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid header format: {}", s));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load unified configuration
    let mut config = if let Some(config_path) = &cli.config {
        // Load from specified config file
        let content = std::fs::read_to_string(config_path)?;
        toml::from_str::<Config>(&content)?
    } else {
        // Load from default locations with precedence
        Config::load()?
    };

    // Apply CLI overrides to scanner config
    apply_cli_overrides(&mut config.scanner, &cli);

    // Disable colors if requested
    if cli.no_color {
        colored::control::set_override(false);
    }

    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let filter = EnvFilter::new(level.to_string());
    fmt().with_env_filter(filter).compact().init();

    // Show banner unless explicitly disabled or running version command
    let show_banner = cli.banner && !matches!(cli.command, Commands::Version);
    if show_banner {
        print_smart_banner();
        // Small delay for visual effect
        sleep(Duration::from_millis(100)).await;
    }

    match cli.command {
        Commands::Scan {
            target,
            profile,
            format,
            checks,
            exclude,
            max_duration,
            output,
            no_progress,
            follow_redirects,
            header,
        } => {
            // Determine output format with precedence: command > global flag > config default
            let output_format = format.or(Some(cli.format));

            run_scan(
                ScanConfig {
                    target_str: target,
                    profile: profile.or(cli.profile),
                    format: output_format,
                    checks,
                    exclude,
                    max_duration: max_duration.or(cli.max_duration),
                    output,
                    no_progress,
                    follow_redirects: follow_redirects.or(cli.follow_redirects),
                    headers: header,
                    timeout: cli.timeout,
                    max_redirects: cli.max_redirects,
                    user_agent: cli.user_agent,
                },
                &config.scanner,
            )
            .await?;
        }
        Commands::Version => {
            openre_scan::show_version();
        }
        #[cfg(feature = "tui")]
        Commands::Tui => {
            if show_banner {
                println!("{}", "Launching TUI...".bright_cyan());
            }
            openre_scan::tui::run_tui().await?;
        }
    }

    Ok(())
}

/// Apply CLI overrides to scanner configuration
fn apply_cli_overrides(scanner_config: &mut ScannerConfig, cli: &Cli) {
    if let Some(timeout) = cli.timeout {
        scanner_config.timeout_secs = timeout;
    }
    if let Some(max_redirects) = cli.max_redirects {
        scanner_config.max_redirects = max_redirects;
    }
    if let Some(user_agent) = &cli.user_agent {
        scanner_config.user_agent = user_agent.clone();
    }
    if let Some(follow_redirects) = cli.follow_redirects {
        scanner_config.follow_redirects = follow_redirects;
    }
    if let Some(max_duration) = cli.max_duration {
        scanner_config.max_duration_secs = max_duration;
    }
    if let Some(rate_limit) = cli.rate_limit {
        scanner_config.rate_limit_rps = rate_limit;
    }
    if let Some(concurrent) = cli.concurrent {
        scanner_config.concurrent_checks = concurrent;
    }
    if cli.no_tls_verify {
        scanner_config.tls_verify = false;
    }
    if let Some(proxy) = &cli.proxy {
        scanner_config.proxy = Some(proxy.clone());
    }
}
