//! openre-scan - Lightweight Standalone Security Scanner
//!
//! A minimal, fast security assessment tool for web applications and APIs.

use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_config::{Config, ScannerConfig};
use openre_core::history::{HistoryStorage, ScanConfigSummary, ScanSummary};
use openre_core::ids::ScanId;
use openre_core::result::Severity;
use openre_scan::{run_scan, runner::run_scan_internal, OutputFormat, ScanConfig, ScanProfile};
use openre_storage::history::SqliteHistoryStorage;
use std::collections::HashSet;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::{sleep, Duration as TokioDuration};
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
use tokio::time::{interval, sleep};
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
        /// Enable continuous monitoring mode
        #[arg(long)]
        continuous: bool,

        /// Interval between scans in minutes (default: 60)
        #[arg(long, default_value_t = 60)]
        interval: u64,
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

    // Handle commands
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
            continuous,
            interval,
        } => {
            // Handle scan command
            let scan_args = ScanConfig {
                target_str: target,
                profile,
                format,
                checks,
                exclude,
                max_duration,
                output,
                no_progress,
                follow_redirects,
                headers: header,
                timeout: None,
                max_redirects: None,
                user_agent: None,
            };
            handle_scan(config, scan_args, continuous, interval).await?;
        }
        Commands::Version => {
            openre_scan::show_version();
        }
        Commands::Tui => {
            #[cfg(feature = "tui")]
            {
                // Launch TUI
                // We'll need to implement this or return an error if not implemented
                Err(anyhow::anyhow!("TUI feature not implemented"))?;
            }
            #[cfg(not(feature = "tui"))]
            {
                return Err(anyhow::anyhow!("TUI feature not enabled"))?;
            }
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

/// Map a finding severity to a terminal color for highlighting
fn severity_color(severity: &Severity) -> colored::Color {
    match severity {
        Severity::Critical => colored::Color::Red,
        Severity::High => colored::Color::BrightRed,
        Severity::Medium => colored::Color::Yellow,
        Severity::Low => colored::Color::BrightCyan,
        Severity::Info => colored::Color::Cyan,
    }
}

/// Handle the scan command with continuous monitoring support
async fn handle_scan(
    config: Config,
    scan_args: ScanConfig,
    continuous: bool,
    interval: u64,
) -> anyhow::Result<()> {
    if continuous {
        // Continuous monitoring mode
        println!(
            "{} {}",
            "🔄 Starting continuous monitoring mode".bright_green().bold(),
            format!("(interval: {} minutes)", interval).dimmed()
        );

        // Get history storage for baseline comparison
        let history = SqliteHistoryStorage::new(&config.storage.local_path.join("history.db"))?;
        history.ensure_schema().await?;

        let mut baseline_scan_id: Option<ScanId> = None;
        let mut first_scan = true;

        // Continuous monitoring loop
        loop {
            println!(
                "\n{} {}",
                "🔍 Starting scan at".bright_white().bold(),
                chrono::Utc::now().to_rfc3339()
            );

            // Apply scan arguments to config
            // (scanner-level overrides were already applied via `apply_cli_overrides`;
            // the remaining scan arguments live in `scan_args`)

            // Run the scan
            let result = run_scan_internal(
                scan_args.target_str.clone(),
                scan_args.resolve_profile(&config.scanner),
                scan_args.resolve_format(),
                config.scanner.timeout_secs,
                config.scanner.max_redirects,
                config.scanner.user_agent.clone(),
            )
            .await;

            match result {
                Ok(findings) => {
                    if first_scan {
                        // First scan - establish baseline
                        println!(
                            "{} {}",
                            "📊 Baseline scan completed".bright_green().bold(),
                            format!("({} findings)", findings.len()).dimmed()
                        );

                        // Save baseline scan summary and findings to history
                        let scan_id = ScanId::new();
                        let target_id = openre_core::ids::TargetId::from_uuid(uuid::Uuid::new_v4());

                        let summary = ScanSummary {
                            scan_id,
                            project_id: None,
                            target_id,
                            name: format!("Baseline scan of {}", scan_args.target_str),
                            description: Some(
                                "Baseline scan for continuous monitoring".to_string(),
                            ),
                            status: "completed".to_string(),
                            config: ScanConfigSummary {
                                name: format!("Baseline scan of {}", scan_args.target_str),
                                target_url: scan_args.target_str.clone(),
                                plugins: vec![],
                                rate_limit: None,
                                timeout_seconds: Some(config.scanner.timeout_secs as u32),
                                auth_configured: false,
                                custom_headers_count: scan_args
                                    .headers
                                    .as_ref()
                                    .map_or(0, |h| h.len()),
                            },
                            progress: openre_core::history::ScanProgressSummary {
                                total_endpoints: 0,
                                endpoints_scanned: 0,
                                endpoints_failed: 0,
                                percentage: 0.0,
                                completed_checks: vec![],
                            },
                            finding_stats: openre_core::result::FindingStats {
                                total: findings.len(),
                                by_severity: std::collections::HashMap::new(),
                                by_confidence: std::collections::HashMap::new(),
                                by_category: std::collections::HashMap::new(),
                                by_plugin: std::collections::HashMap::new(),
                                verified: 0,
                                false_positives: 0,
                                avg_risk_score: 0.0,
                                max_risk_score: 0,
                                by_owasp_category: std::collections::HashMap::new(),
                                by_cwe: std::collections::HashMap::new(),
                                avg_advanced_risk_score: 0.0,
                                max_advanced_risk_score: 0,
                                by_remediation_priority: std::collections::HashMap::new(),
                                exploit_available_count: 0,
                                exploited_in_wild_count: 0,
                            },
                            risk_metrics: openre_core::history::RiskMetricsSummary {
                                overall_risk_score: 0,
                                risk_level: openre_core::reporting::RiskLevel::Low,
                                critical_count: 0,
                                high_count: 0,
                                medium_count: 0,
                                low_count: 0,
                                info_count: 0,
                                avg_risk_score: 0.0,
                                max_risk_score: 0,
                            },
                            plugin_executions: vec![],
                            created_at: chrono::Utc::now(),
                            started_at: Some(chrono::Utc::now()),
                            completed_at: Some(chrono::Utc::now()),
                            duration_seconds: Some(0),
                            tags: vec![],
                        };

                        history.save_scan_summary(&summary).await?;
                        history.save_deduplicated_findings(&scan_id, &findings).await?;

                        baseline_scan_id = Some(scan_id);
                        first_scan = false;
                    } else {
                        // Subsequent scan - compare with baseline
                        if let Some(baseline_id) = baseline_scan_id {
                            let baseline_findings =
                                history.get_deduplicated_findings(&baseline_id).await?;

                            // Convert findings to sets for comparison (using ID as key)
                            let current_findings_set: HashSet<_> =
                                findings.iter().map(|f| f.id).collect();
                            let baseline_findings_set: HashSet<_> =
                                baseline_findings.iter().map(|f| f.id).collect();

                            let new_findings: Vec<_> = findings
                                .iter()
                                .filter(|f| !baseline_findings_set.contains(&f.id))
                                .cloned()
                                .collect();

                            let fixed_findings: Vec<_> = baseline_findings
                                .iter()
                                .filter(|f| !current_findings_set.contains(&f.id))
                                .cloned()
                                .collect();

                            let unchanged_count = baseline_findings
                                .iter()
                                .filter(|f| current_findings_set.contains(&f.id))
                                .count();

                            // Output results
                            println!(
                                "\n{} {}",
                                "📊 Comparison scan completed".bright_white().bold(),
                                format!("({} findings)", findings.len()).dimmed()
                            );
                            println!(
                                "{} {}",
                                "📈 Baseline findings:".bright_blue().bold(),
                                baseline_findings.len()
                            );
                            println!(
                                "{} {}",
                                "🆕 New findings:".bright_green().bold(),
                                new_findings.len()
                            );
                            println!(
                                "{} {}",
                                "✅ Fixed findings:".bright_yellow().bold(),
                                fixed_findings.len()
                            );
                            println!(
                                "{} {}",
                                "➖ Unchanged findings:".bright_blue().bold(),
                                unchanged_count
                            );

                            if !new_findings.is_empty() {
                                println!(
                                    "\n{} {}",
                                    "⚠️  ALERT: New vulnerabilities detected!".bright_red().bold(),
                                    format!("({} new findings)", new_findings.len()).dimmed()
                                );
                                for finding in &new_findings {
                                    println!(
                                        "  {} {} [{}]",
                                        "🆕".bright_green(),
                                        finding.title.bright_white(),
                                        format!("({})", finding.severity)
                                            .color(severity_color(&finding.severity))
                                    );
                                }
                            }

                            if !fixed_findings.is_empty() {
                                println!(
                                    "\n{} {}",
                                    "✅ FIXED: Vulnerabilities resolved".bright_green().bold(),
                                    format!("({} findings)", fixed_findings.len()).dimmed()
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "❌ Scan failed:".bright_red().bold(), e);
                }
            }

            // Wait for the specified interval
            println!(
                "\n{} {}",
                "😴 Waiting for next scan".bright_white().dimmed(),
                format!("({} minutes)", interval).dimmed()
            );
            sleep(TokioDuration::from_secs(interval * 60)).await;
        }
    } else {
        // Regular (non-continuous) scan mode
        run_scan(scan_args, &config.scanner).await?;
    }

    Ok(())
}
