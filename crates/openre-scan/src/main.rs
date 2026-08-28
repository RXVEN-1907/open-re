//! openre-scan - Lightweight Standalone Security Scanner
//!
//! A minimal, fast security assessment tool for web applications and APIs.

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use openre_core::ids::ScanId;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use tokio::time::sleep;

// Re-export core types for public API
pub use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, FindingFilter,
    FindingSort, RemediationEffort, RemediationGuidance, RemediationPriority, Severity,
};
use regex::Regex;
use reqwest::Client;
use select::document::Document;
use select::predicate::Name;
use std::collections::HashMap;
use std::path::PathBuf;
use tabled::{Table, Tabled};
use tracing::Level;
use tracing_subscriber::{fmt, EnvFilter};
use url::Url;

// ASCII Art Banner from README
const ASCII_BANNER: &str = r#"
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚══╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝
"#;

const ASCII_BANNER_SMALL: &str = r#"
███████╗██████╗ ██████╗  ██████╗ ███████╗███████╗
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝
█████╗  ██████╔╝██████╔╝██║   ██║███████╗█████╗
██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║╚════██║██╔══╝
███████╗██║  ██║██║     ╚██████╔╝███████║███████╗
╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝
"#;

// TUI module (experimental)
#[cfg(feature = "tui")]
pub mod tui;

/// Print the ASCII art banner
fn print_banner() {
    println!("{}", ASCII_BANNER.bright_cyan().bold());
    println!("{}", "Open-source Reverse Engineering & Offensive Security Platform".bright_white());
    println!("{}", "Modern security tools + LLMs for automated binary, web, API & app analysis".dimmed());
    println!("{}", "Discover vulnerabilities • Generate PoC exploits • Actionable remediation".dimmed());
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
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Animated spinner for startup
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
#[command(long_about = "openre-scan: Lightweight standalone security scanner for web applications and APIs\n\nA minimal, fast security assessment tool with 18+ security checks across three scan profiles.\nPart of the open-re platform: https://github.com/RXVEN-1907/open-re")]
#[command(version)]
#[command(after_help = "Examples:\n  openre-scan scan https://example.com --profile quick\n  openre-scan scan https://example.com --profile standard --format json\n  openre-scan scan https://example.com --profile full --output results.sarif\n  openre-scan tui\n\nFor more information, visit: https://github.com/RXVEN-1907/open-re")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, global = true, default_value = "table", value_enum)]
    format: OutputFormat,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Request timeout in seconds
    #[arg(long, global = true, default_value = "10")]
    timeout: u64,

    /// Maximum redirects
    #[arg(long, global = true, default_value = "10")]
    max_redirects: usize,

    /// User agent
    #[arg(long, global = true, default_value = "openre-scan/0.1.0")]
    user_agent: String,

    /// Show ASCII banner on startup
    #[arg(long, global = true, default_value = "true")]
    banner: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a target
    Scan {
        /// Target to scan (URL)
        target: String,

        /// Scan profile
        #[arg(short, long, default_value = "standard", value_enum)]
        profile: ScanProfile,

        /// Output format
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,

        /// Checks to run (comma-separated)
        #[arg(long, value_delimiter = ',')]
        checks: Option<Vec<String>>,

        /// Checks to exclude (comma-separated)
        #[arg(long, value_delimiter = ',')]
        exclude: Option<Vec<String>>,

        /// Maximum scan duration in seconds
        #[arg(long, default_value = "300")]
        max_duration: u64,

        /// Save scan results to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Disable progress bar
        #[arg(long)]
        no_progress: bool,

        /// Follow redirects
        #[arg(long)]
        follow_redirects: bool,

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

#[derive(Debug, Clone, ValueEnum)]
pub enum ScanProfile {
    Quick,
    Standard,
    Full,
}

fn parse_header(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid header format: {}", s));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[tokio::main]
#[allow(dead_code)]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Disable colors if requested
    if cli.no_color {
        colored::control::set_override(false);
    }

    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
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
            run_scan(ScanConfig {
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
                timeout: cli.timeout,
                max_redirects: cli.max_redirects,
                user_agent: cli.user_agent,
            })
            .await?;
        }
        Commands::Version => {
            show_version();
        }
        #[cfg(feature = "tui")]
        Commands::Tui => {
            if show_banner {
                println!("{}", "Launching TUI...".bright_cyan());
            }
            tui::run_tui().await?;
        }
    }

    Ok(())
}

// Internal scan function for TUI
pub async fn run_scan_internal(
    target_str: String,
    profile: ScanProfile,
    _format: OutputFormat,
    timeout: u64,
    max_redirects: usize,
    user_agent: String,
) -> anyhow::Result<Vec<crate::Finding>> {
    let target_url = if target_str.starts_with("http://") || target_str.starts_with("https://") {
        target_str.parse::<Url>()?
    } else {
        format!("https://{}", target_str).parse::<Url>()?
    };

    let client = build_client(timeout, max_redirects, false, user_agent, None)?;

    let all_checks = get_all_checks(&profile);
    let checks_to_run: Vec<Check> = all_checks
        .into_iter()
        .filter(|c| c.name() != "sensitive-files")
        .collect();

    let mut all_findings = Vec::new();

    for check in checks_to_run {
        match check.run(&client, &target_url).await {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => eprintln!("Check {} failed: {}", check.name(), e),
        }
    }

    Ok(all_findings)
}

#[derive(Debug)]
#[allow(dead_code)]
struct ScanConfig {
    target_str: String,
    profile: ScanProfile,
    format: OutputFormat,
    checks: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    #[allow(dead_code)]
    max_duration: u64,
    output: Option<PathBuf>,
    no_progress: bool,
    follow_redirects: bool,
    headers: Option<Vec<(String, String)>>,
    timeout: u64,
    max_redirects: usize,
    user_agent: String,
}

#[allow(dead_code)]
async fn run_scan(config: ScanConfig) -> anyhow::Result<()> {
    // Use MultiProgress for better progress display
    let multi_progress = MultiProgress::new();

    let target_url =
        if config.target_str.starts_with("http://") || config.target_str.starts_with("https://") {
            config.target_str.parse::<Url>()?
        } else {
            format!("https://{}", config.target_str).parse::<Url>()?
        };

    let client = build_client(
        config.timeout,
        config.max_redirects,
        config.follow_redirects,
        config.user_agent,
        config.headers,
    )?;

    let all_checks = get_all_checks(&config.profile);
    let checks_to_run: Vec<Check> = all_checks
        .into_iter()
        .filter(|c| {
            let should_run = config
                .checks
                .as_ref()
                .map(|cs| cs.iter().any(|s| s == c.name()))
                .unwrap_or(true);
            let should_exclude = config
                .exclude
                .as_ref()
                .map(|es| es.iter().any(|s| s == c.name()))
                .unwrap_or(false);
            should_run && !should_exclude
        })
        .collect();

    let checks_count = checks_to_run.len();

    // Print scan header with better formatting
    let line_top = format!("{}", "┌".dimmed()) + &"─".repeat(78) + &format!("{}", "┐".dimmed());
    let line_mid = format!("{}", "├".dimmed()) + &"─".repeat(78) + &format!("{}", "┤".dimmed());
    let line_bot = format!("{}", "└".dimmed()) + &"─".repeat(78) + &format!("{}", "┘".dimmed());

    println!("{}", line_top);
    println!("{} {:<76} {}", "│".dimmed(), "🔍 openre-scan — Security Scan".bold().bright_cyan(), "│".dimmed());
    println!("{}", line_mid);
    println!("{} {:<20} {:<56} {}", "│".dimmed(), "Target:".bold(), config.target_str.bright_white(), "│".dimmed());
    println!("{} {:<20} {:<56} {}", "│".dimmed(), "Profile:".bold(), format!("{:?} ({} checks)", config.profile, checks_count).bright_white(), "│".dimmed());
    println!("{}", line_bot);
    println!();

    // Show checks being run
    println!("{}", "📋 Checks to run:".bold().bright_blue());
    for (i, check) in checks_to_run.iter().enumerate() {
        let check_info = get_check_description(check);
        println!("  {}. {} {}",
            format!("{:2}", i + 1).dimmed(),
            check.name().bright_cyan(),
            check_info.dimmed()
        );
    }
    println!();

    // Progress bar with better styling
    let progress_bar = if !config.no_progress {
        let pb = multi_progress.add(ProgressBar::new(checks_count as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} {msg:<40} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let start_time = Instant::now();
    let mut all_findings = Vec::new();
    let scan_id = ScanId::new();

    for (_i, check) in checks_to_run.iter().enumerate() {
        if let Some(pb) = &progress_bar {
            pb.set_message(format!("Running {}", check.name()));
        }

        match check.run(&client, &target_url).await {
            Ok(findings) => {
                if !findings.is_empty() {
                    for finding in &findings {
                        let _severity_icon = match finding.severity {
                            Severity::Critical => "🔴".to_string(),
                            Severity::High => "🟠".to_string(),
                            Severity::Medium => "🟡".to_string(),
                            Severity::Low => "🟢".to_string(),
                            Severity::Info => "🔵".to_string(),
                        };
                        println!("  {} {} {} [{}]",
                            "✓".green(),
                            finding.title.bright_white(),
                            format!("({})", finding.severity).color(severity_color(&finding.severity)),
                            check.name().dimmed()
                        );
                    }
                }
                all_findings.extend(findings);
            }
            Err(e) => {
                if let Some(pb) = &progress_bar {
                    pb.suspend(|| {
                        eprintln!("{} {} failed: {}", "✗".red().bold(), check.name().bright_yellow(), e);
                    });
                } else {
                    eprintln!("{} {} failed: {}", "✗".red().bold(), check.name().bright_yellow(), e);
                }
            }
        }

        if let Some(pb) = &progress_bar {
            pb.inc(1);
        }
    }

    let duration = start_time.elapsed();

    if let Some(pb) = progress_bar {
        pb.finish_with_message("✓ Scan complete!");
    }

    println!();
    let line_top = format!("{}", "┌".dimmed()) + &"─".repeat(78) + &format!("{}", "┐".dimmed());
    let line_mid = format!("{}", "├".dimmed()) + &"─".repeat(78) + &format!("{}", "┤".dimmed());
    let line_bot = format!("{}", "└".dimmed()) + &"─".repeat(78) + &format!("{}", "┘".dimmed());

    println!("{}", line_top);
    println!("{} {:<76} {}", "│".dimmed(), "📋 Scan Results".bold().bright_green(), "│".dimmed());
    println!("{}", line_mid);
    println!("{} {:<20} {:<56} {}", "│".dimmed(), "Scan ID:".bold(), scan_id.to_string().bright_white(), "│".dimmed());
    println!("{} {:<20} {:<56} {}", "│".dimmed(), "Duration:".bold(), format!("{:.2}s", duration.as_secs_f32()).bright_white(), "│".dimmed());
    println!("{} {:<20} {:<56} {}", "│".dimmed(), "Checks Run:".bold(), checks_count.to_string().bright_white(), "│".dimmed());
    println!("{} {:<20} {:<56} {}", "│".dimmed(), "Findings:".bold(), all_findings.len().to_string().bright_white(), "│".dimmed());
    println!("{}", line_bot);
    println!();

    // Print severity summary
    if !all_findings.is_empty() {
        print_severity_summary(&all_findings);
        println!();
    }

    display_results(
        &all_findings,
        &config.format,
        config.output,
        &target_url,
        duration,
        checks_count,
    )
    .await?;

    Ok(())
}

/// Get color for severity
fn severity_color(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "red",
        Severity::High => "red",
        Severity::Medium => "yellow",
        Severity::Low => "green",
        Severity::Info => "blue",
    }
}

/// Get description for a check
fn get_check_description(check: &Check) -> &'static str {
    match check {
        Check::HttpHeaders => "HTTP header analysis",
        Check::TlsCertificate => "TLS certificate validation",
        Check::CookieSecurity => "Cookie security flags",
        Check::SecurityHeaders => "Security headers (HSTS, CSP, etc.)",
        Check::ContentSecurityPolicy => "CSP directive analysis",
        Check::CorsConfiguration => "CORS misconfiguration",
        Check::InformationDisclosure => "Debug info & version disclosure",
        Check::TechnologyFingerprint => "Tech stack detection",
        Check::RobotsTxt => "robots.txt enumeration",
        Check::SitemapXml => "sitemap.xml discovery",
        Check::DirectoryListing => "Directory listing detection",
        Check::SensitiveFiles => "Sensitive file exposure (20+ paths)",
        Check::FormAnalysis => "Form security (GET passwords, CSRF)",
        Check::LinkAnalysis => "Mixed content & external links",
        Check::ScriptAnalysis => "Inline/external script analysis",
        Check::MetaTags => "Security-relevant meta tags",
        Check::HttpMethods => "Dangerous HTTP methods (TRACE, PUT, etc.)",
        Check::SslTlsConfiguration => "SSL/TLS deep configuration",
    }
}

/// Print severity summary
fn print_severity_summary(findings: &[Finding]) {
    let mut counts = std::collections::HashMap::new();
    for f in findings {
        *counts.entry(f.severity).or_insert(0) += 1;
    }

    println!("{}", "📊 Findings by Severity:".bold().bright_blue());
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        if let Some(count) = counts.get(&sev) {
            let (icon, color) = match sev {
                Severity::Critical => ("🔴", "red"),
                Severity::High => ("🟠", "red"),
                Severity::Medium => ("🟡", "yellow"),
                Severity::Low => ("🟢", "green"),
                Severity::Info => ("🔵", "blue"),
            };
            println!("  {} {:<10} {}", icon, format!("{:?}:", sev).color(color), count);
        }
    }
}

pub fn build_client(
    timeout: u64,
    max_redirects: usize,
    follow_redirects: bool,
    user_agent: String,
    headers: Option<Vec<(String, String)>>,
) -> anyhow::Result<Client> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(max_redirects)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent(user_agent)
        .gzip(true)
        .brotli(true)
        .deflate(true);

    if let Some(h) = headers {
        let mut header_map = reqwest::header::HeaderMap::new();
        for (k, v) in h {
            let header_name = reqwest::header::HeaderName::from_bytes(k.as_bytes())?;
            let header_value = reqwest::header::HeaderValue::from_str(&v)?;
            header_map.insert(header_name, header_value);
        }
        builder = builder.default_headers(header_map);
    }

    Ok(builder.build()?)
}

#[derive(Debug, Clone)]
pub enum Check {
    HttpHeaders,
    TlsCertificate,
    CookieSecurity,
    SecurityHeaders,
    ContentSecurityPolicy,
    CorsConfiguration,
    InformationDisclosure,
    TechnologyFingerprint,
    RobotsTxt,
    SitemapXml,
    DirectoryListing,
    SensitiveFiles,
    FormAnalysis,
    LinkAnalysis,
    ScriptAnalysis,
    MetaTags,
    HttpMethods,
    SslTlsConfiguration,
}

impl Check {
    fn name(&self) -> &'static str {
        match self {
            Check::HttpHeaders => "http-headers",
            Check::TlsCertificate => "tls-certificate",
            Check::CookieSecurity => "cookie-security",
            Check::SecurityHeaders => "security-headers",
            Check::ContentSecurityPolicy => "csp",
            Check::CorsConfiguration => "cors",
            Check::InformationDisclosure => "info-disclosure",
            Check::TechnologyFingerprint => "tech-fingerprint",
            Check::RobotsTxt => "robots-txt",
            Check::SitemapXml => "sitemap",
            Check::DirectoryListing => "dir-listing",
            Check::SensitiveFiles => "sensitive-files",
            Check::FormAnalysis => "forms",
            Check::LinkAnalysis => "links",
            Check::ScriptAnalysis => "scripts",
            Check::MetaTags => "meta-tags",
            Check::HttpMethods => "http-methods",
            Check::SslTlsConfiguration => "ssl-config",
        }
    }

    pub async fn run(&self, client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
        match self {
            Check::HttpHeaders => check_http_headers(client, target).await,
            Check::TlsCertificate => check_tls_certificate(client, target).await,
            Check::CookieSecurity => check_cookie_security(client, target).await,
            Check::SecurityHeaders => check_security_headers(client, target).await,
            Check::ContentSecurityPolicy => check_csp(client, target).await,
            Check::CorsConfiguration => check_cors(client, target).await,
            Check::InformationDisclosure => check_information_disclosure(client, target).await,
            Check::TechnologyFingerprint => check_technology_fingerprint(client, target).await,
            Check::RobotsTxt => check_robots_txt(client, target).await,
            Check::SitemapXml => check_sitemap(client, target).await,
            Check::DirectoryListing => check_directory_listing(client, target).await,
            Check::SensitiveFiles => check_sensitive_files(client, target).await,
            Check::FormAnalysis => check_forms(client, target).await,
            Check::LinkAnalysis => check_links(client, target).await,
            Check::ScriptAnalysis => check_scripts(client, target).await,
            Check::MetaTags => check_meta_tags(client, target).await,
            Check::HttpMethods => check_http_methods(client, target).await,
            Check::SslTlsConfiguration => check_ssl_config(client, target).await,
        }
    }
}

pub fn get_all_checks(profile: &ScanProfile) -> Vec<Check> {
    match profile {
        ScanProfile::Quick => vec![
            Check::HttpHeaders,
            Check::SecurityHeaders,
            Check::CookieSecurity,
            Check::TlsCertificate,
            Check::InformationDisclosure,
            Check::TechnologyFingerprint,
        ],
        ScanProfile::Standard => vec![
            Check::HttpHeaders,
            Check::TlsCertificate,
            Check::CookieSecurity,
            Check::SecurityHeaders,
            Check::ContentSecurityPolicy,
            Check::CorsConfiguration,
            Check::InformationDisclosure,
            Check::TechnologyFingerprint,
            Check::RobotsTxt,
            Check::SitemapXml,
            Check::DirectoryListing,
            Check::SensitiveFiles,
            Check::FormAnalysis,
            Check::LinkAnalysis,
            Check::ScriptAnalysis,
            Check::MetaTags,
        ],
        ScanProfile::Full => vec![
            Check::HttpHeaders,
            Check::TlsCertificate,
            Check::CookieSecurity,
            Check::SecurityHeaders,
            Check::ContentSecurityPolicy,
            Check::CorsConfiguration,
            Check::InformationDisclosure,
            Check::TechnologyFingerprint,
            Check::RobotsTxt,
            Check::SitemapXml,
            Check::DirectoryListing,
            Check::SensitiveFiles,
            Check::FormAnalysis,
            Check::LinkAnalysis,
            Check::ScriptAnalysis,
            Check::MetaTags,
            Check::HttpMethods,
            Check::SslTlsConfiguration,
        ],
    }
}

// Check implementations
async fn check_http_headers(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    if let Some(server) = headers.get("server") {
        let finding = Finding::new(FindingConfig {
            title: "Server Header Disclosure".to_string(),
            description: format!(
                "Server header reveals: {}",
                server.to_str().unwrap_or("unknown")
            ),
            severity: Severity::Info,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "http-headers".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(
            EvidenceType::HttpResponse,
            "Server header present".to_string(),
        )
        .with_data(serde_json::json!({"header": "server", "value": server.to_str().unwrap_or("")}))
        .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    if let Some(powered) = headers.get("x-powered-by") {
        let finding = Finding::new(FindingConfig {
            title: "X-Powered-By Header Disclosure".to_string(),
            description: format!(
                "X-Powered-By header reveals: {}",
                powered.to_str().unwrap_or("unknown")
            ),
            severity: Severity::Low,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "http-headers".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(
            EvidenceType::HttpResponse,
            "X-Powered-By header present".to_string(),
        )
        .with_data(
            serde_json::json!({"header": "x-powered-by", "value": powered.to_str().unwrap_or("")}),
        )
        .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}

async fn check_security_headers(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    let security_headers = [
        (
            "x-frame-options",
            "X-Frame-Options",
            Severity::Medium,
            "Clickjacking protection",
        ),
        (
            "x-content-type-options",
            "X-Content-Type-Options",
            Severity::Medium,
            "MIME type sniffing protection",
        ),
        (
            "strict-transport-security",
            "Strict-Transport-Security",
            Severity::High,
            "HSTS enforcement",
        ),
        (
            "content-security-policy",
            "Content-Security-Policy",
            Severity::High,
            "Content Security Policy",
        ),
        (
            "referrer-policy",
            "Referrer-Policy",
            Severity::Medium,
            "Referrer policy",
        ),
        (
            "permissions-policy",
            "Permissions-Policy",
            Severity::Low,
            "Feature policy",
        ),
        (
            "cross-origin-opener-policy",
            "Cross-Origin-Opener-Policy",
            Severity::Low,
            "COOP",
        ),
        (
            "cross-origin-resource-policy",
            "Cross-Origin-Resource-Policy",
            Severity::Low,
            "CORP",
        ),
    ];

    for (header_name, display_name, severity, description) in security_headers {
        if headers.get(header_name).is_none() {
            let finding = Finding::new(FindingConfig {
                title: format!("Missing {} Header", display_name),
                description: format!("{} header is missing. {}", display_name, description),
                severity,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "security-headers".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                format!("Missing {} header", display_name),
            )
            .with_data(serde_json::json!({"missing_header": header_name}))
            .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                format!("Add {} header", display_name),
                vec![format!(
                    "Add the {} header to your HTTP responses",
                    display_name
                )],
                RemediationEffort::Low,
                RemediationPriority::High,
            );
            findings.push(
                finding
                    .with_evidence(evidence)
                    .with_remediation(remediation),
            );
        }
    }

    Ok(findings)
}

async fn check_cookie_security(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;

    for cookie_header in response.headers().get_all("set-cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            let cookie = cookie_str;

            if !cookie.to_lowercase().contains("secure") && target.scheme() == "https" {
                let finding = Finding::new(FindingConfig {
                    title: "Cookie Missing Secure Flag".to_string(),
                    description: format!("Cookie set without Secure flag on HTTPS: {}", cookie),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "cookie-security".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    "Cookie without Secure flag".to_string(),
                )
                .with_data(serde_json::json!({"cookie": cookie}))
                .with_location(target.to_string());
                let remediation = RemediationGuidance::new(
                    "Add Secure flag to cookies".to_string(),
                    vec!["Set the Secure attribute on all cookies served over HTTPS".to_string()],
                    RemediationEffort::Low,
                    RemediationPriority::High,
                );
                findings.push(
                    finding
                        .with_evidence(evidence)
                        .with_remediation(remediation),
                );
            }

            if !cookie.to_lowercase().contains("httponly") {
                let finding = Finding::new(FindingConfig {
                    title: "Cookie Missing HttpOnly Flag".to_string(),
                    description: format!("Cookie set without HttpOnly flag: {}", cookie),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "cookie-security".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    "Cookie without HttpOnly flag".to_string(),
                )
                .with_data(serde_json::json!({"cookie": cookie}))
                .with_location(target.to_string());
                let remediation = RemediationGuidance::new(
                    "Add HttpOnly flag to cookies".to_string(),
                    vec!["Set the HttpOnly attribute on session cookies".to_string()],
                    RemediationEffort::Low,
                    RemediationPriority::High,
                );
                findings.push(
                    finding
                        .with_evidence(evidence)
                        .with_remediation(remediation),
                );
            }

            if !cookie.to_lowercase().contains("samesite") {
                let finding = Finding::new(FindingConfig {
                    title: "Cookie Missing SameSite Attribute".to_string(),
                    description: format!("Cookie set without SameSite attribute: {}", cookie),
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "cookie-security".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    "Cookie without SameSite".to_string(),
                )
                .with_data(serde_json::json!({"cookie": cookie}))
                .with_location(target.to_string());
                findings.push(finding.with_evidence(evidence));
            }
        }
    }

    Ok(findings)
}

async fn check_tls_certificate(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if target.scheme() != "https" {
        let finding = Finding::new(FindingConfig {
            title: "Not Using HTTPS".to_string(),
            description: "Target is not using HTTPS encryption".to_string(),
            severity: Severity::High,
            confidence: Confidence::VeryHigh,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "tls-certificate".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let remediation = RemediationGuidance::new(
            "Enable HTTPS".to_string(),
            vec![
                "Obtain and install a valid TLS certificate".to_string(),
                "Configure HTTPS on your web server".to_string(),
                "Redirect all HTTP traffic to HTTPS".to_string(),
            ],
            RemediationEffort::Medium,
            RemediationPriority::Immediate,
        );
        findings.push(finding.with_remediation(remediation));
        return Ok(findings);
    }

    match client.get(target.as_str()).send().await {
        Ok(_) => {
            let finding = Finding::new(FindingConfig {
                title: "HTTPS Enabled".to_string(),
                description: "Target is accessible via HTTPS".to_string(),
                severity: Severity::Info,
                confidence: Confidence::High,
                category: Category::Configuration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "tls-certificate".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            findings.push(finding);
        }
        Err(e) => {
            let finding = Finding::new(FindingConfig {
                title: "HTTPS Connection Failed".to_string(),
                description: format!("Failed to connect via HTTPS: {}", e),
                severity: Severity::High,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "tls-certificate".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            findings.push(finding);
        }
    }

    Ok(findings)
}

async fn check_csp(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    if let Some(csp) = headers.get("content-security-policy") {
        let csp_str = csp.to_str().unwrap_or("");

        if csp_str.contains("unsafe-inline") {
            let finding = Finding::new(FindingConfig {
                title: "CSP Allows unsafe-inline".to_string(),
                description: "Content-Security-Policy contains 'unsafe-inline' directive"
                    .to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "csp".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "CSP with unsafe-inline".to_string(),
            )
            .with_data(serde_json::json!({"csp": csp_str}))
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }

        if csp_str.contains("unsafe-eval") {
            let finding = Finding::new(FindingConfig {
                title: "CSP Allows unsafe-eval".to_string(),
                description: "Content-Security-Policy contains 'unsafe-eval' directive".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "csp".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "CSP with unsafe-eval".to_string(),
            )
            .with_data(serde_json::json!({"csp": csp_str}))
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }

        if csp_str.contains("'*'") || csp_str.contains("\"*\"") {
            let finding = Finding::new(FindingConfig {
                title: "CSP Uses Wildcard".to_string(),
                description:
                    "Content-Security-Policy uses wildcard (*) which may be overly permissive"
                        .to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "csp".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "CSP with wildcard".to_string())
                    .with_data(serde_json::json!({"csp": csp_str}))
                    .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    } else {
        let finding = Finding::new(FindingConfig {
            title: "Missing Content-Security-Policy".to_string(),
            description: "No Content-Security-Policy header found".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "csp".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let remediation = RemediationGuidance::new(
            "Implement Content-Security-Policy".to_string(),
            vec![
                "Add a Content-Security-Policy header to restrict resource loading".to_string(),
                "Start with a restrictive policy and adjust as needed".to_string(),
                "Use nonce or hash-based approach for inline scripts".to_string(),
            ],
            RemediationEffort::Medium,
            RemediationPriority::High,
        );
        findings.push(finding.with_remediation(remediation));
    }

    Ok(findings)
}

async fn check_cors(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    if let Some(acao) = headers.get("access-control-allow-origin") {
        let acao_str = acao.to_str().unwrap_or("");
        if acao_str == "*" {
            let finding = Finding::new(FindingConfig {
                title: "CORS Allows All Origins".to_string(),
                description: "Access-Control-Allow-Origin is set to * (wildcard)".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "cors".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "CORS wildcard origin".to_string(),
            )
            .with_data(serde_json::json!({"acao": acao_str}))
            .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                "Restrict CORS origins".to_string(),
                vec![
                    "Set Access-Control-Allow-Origin to specific trusted origins".to_string(),
                    "Avoid using wildcard (*) for origins that handle sensitive data".to_string(),
                ],
                RemediationEffort::Low,
                RemediationPriority::Medium,
            );
            findings.push(
                finding
                    .with_evidence(evidence)
                    .with_remediation(remediation),
            );
        }
    }

    if let Some(acac) = headers.get("access-control-allow-credentials") {
        if acac.to_str().unwrap_or("").to_lowercase() == "true" {
            if let Some(acao) = headers.get("access-control-allow-origin") {
                if acao.to_str().unwrap_or("") == "*" {
                    let finding = Finding::new(FindingConfig {
                        title: "CORS Credentials with Wildcard Origin".to_string(),
                        description:
                            "Access-Control-Allow-Credentials is true with wildcard origin"
                                .to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: Category::SecurityMisconfiguration,
                        target: target.to_string(),
                        target_type: "web".to_string(),
                        plugin_source: "cors".to_string(),
                        plugin_version: "1.0".to_string(),
                        scan_id: scan_id(),
                    });
                    findings.push(finding);
                }
            }
        }
    }

    Ok(findings)
}

async fn check_information_disclosure(
    client: &Client,
    target: &Url,
) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    let debug_headers = [
        "x-debug-token",
        "x-drupal-cache",
        "x-varnish",
        "via",
        "x-cache",
    ];
    for header in debug_headers {
        if headers.contains_key(header) {
            let finding = Finding::new(FindingConfig {
                title: format!("Debug Header Exposed: {}", header),
                description: format!("Debug header {} is present in response", header),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "info-disclosure".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                format!("Debug header {} found", header),
            ).with_data(serde_json::json!({"header": header, "value": headers.get(header).unwrap().to_str().unwrap_or("")}))
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or("");
        if server_str.contains('/') {
            let finding = Finding::new(FindingConfig {
                title: "Server Version Disclosure".to_string(),
                description: format!("Server header reveals version: {}", server_str),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "info-disclosure".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "Server version disclosed".to_string(),
            )
            .with_data(serde_json::json!({"server": server_str}))
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    Ok(findings)
}

async fn check_technology_fingerprint(
    client: &Client,
    target: &Url,
) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();

    let tech_signatures = [
        ("x-powered-by", "PHP", r"PHP/"),
        ("x-powered-by", "ASP.NET", r"ASP\.NET"),
        ("server", "Apache", r"Apache/"),
        ("server", "nginx", r"nginx/"),
        ("server", "IIS", r"Microsoft-IIS/"),
        ("x-generator", "WordPress", r"WordPress"),
        ("x-drupal-cache", "Drupal", r""),
        ("x-drupal-dynamic-cache", "Drupal", r""),
    ];

    for (header_name, tech_name, pattern) in tech_signatures {
        if let Some(header) = headers.get(header_name) {
            let header_str = header.to_str().unwrap_or("");
            if pattern.is_empty() || Regex::new(pattern).unwrap().is_match(header_str) {
                let finding = Finding::new(FindingConfig {
                    title: format!("Technology Detected: {}", tech_name),
                    description: format!("{} detected via {} header", tech_name, header_name),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "tech-fingerprint".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    format!("{} detected", tech_name),
                ).with_data(serde_json::json!({"technology": tech_name, "header": header_name, "value": header_str}))
                .with_location(target.to_string());
                findings.push(finding.with_evidence(evidence));
            }
        }
    }

    let body_signatures = [
        ("WordPress", r"wp-content|wp-includes"),
        ("Drupal", r"drupal\.js|Drupal\.settings"),
        ("Joomla", r"joomla|Joomla"),
        ("React", r"react\.js|ReactDOM"),
        ("Vue", r"vue\.js|Vue\.js"),
        ("Angular", r"angular\.js|ng-app"),
        ("jQuery", r"jquery"),
        ("Bootstrap", r"bootstrap"),
    ];

    for (tech_name, pattern) in body_signatures {
        if Regex::new(pattern).unwrap().is_match(&body) {
            let finding = Finding::new(FindingConfig {
                title: format!("Technology Detected: {}", tech_name),
                description: format!("{} detected in page content", tech_name),
                severity: Severity::Info,
                confidence: Confidence::Medium,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "tech-fingerprint".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                format!("{} detected in body", tech_name),
            )
            .with_data(serde_json::json!({"technology": tech_name, "source": "body"}))
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    Ok(findings)
}

async fn check_robots_txt(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut robots_url = target.clone();
    robots_url.set_path("/robots.txt");

    match client.get(robots_url.as_str()).send().await {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await.unwrap_or_default();
            let finding = Finding::new(FindingConfig {
                title: "robots.txt Found".to_string(),
                description: "robots.txt file is accessible".to_string(),
                severity: Severity::Info,
                confidence: Confidence::High,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "robots-txt".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "robots.txt accessible".to_string(),
            )
            .with_data(serde_json::json!({"content": body.chars().take(500).collect::<String>()}))
            .with_location(robots_url.to_string());
            findings.push(finding.with_evidence(evidence));

            for line in body.lines() {
                if line.to_lowercase().starts_with("disallow:") && !line.contains("disallow: /") {
                    let path = line.split(':').nth(1).unwrap_or("").trim();
                    if !path.is_empty() && path != "/" {
                        let finding = Finding::new(FindingConfig {
                            title: "Interesting robots.txt Entry".to_string(),
                            description: format!("robots.txt disallows: {}", path),
                            severity: Severity::Info,
                            confidence: Confidence::Low,
                            category: Category::InformationDisclosure,
                            target: target.to_string(),
                            target_type: "web".to_string(),
                            plugin_source: "robots-txt".to_string(),
                            plugin_version: "1.0".to_string(),
                            scan_id: scan_id(),
                        });
                        let evidence = Evidence::new(
                            EvidenceType::HttpResponse,
                            format!("Disallowed path: {}", path),
                        )
                        .with_location(robots_url.to_string());
                        findings.push(finding.with_evidence(evidence));
                    }
                }
            }
        }
        Ok(_) => {
            // Non-success status, ignore
        }
        Err(_) => {
            // Request failed, ignore
        }
    }

    Ok(findings)
}

async fn check_sitemap(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut sitemap_url = target.clone();
    sitemap_url.set_path("/sitemap.xml");

    match client.get(sitemap_url.as_str()).send().await {
        Ok(response) if response.status().is_success() => {
            let finding = Finding::new(FindingConfig {
                title: "sitemap.xml Found".to_string(),
                description: "sitemap.xml file is accessible".to_string(),
                severity: Severity::Info,
                confidence: Confidence::High,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "sitemap".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "sitemap.xml accessible".to_string(),
            )
            .with_location(sitemap_url.to_string());
            findings.push(finding.with_evidence(evidence));
        }
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(findings)
}

async fn check_directory_listing(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let listing_indicators = [
        "Index of /",
        "Directory listing for",
        "<title>Index of",
        "Parent Directory",
        "[DIR]",
        "Name</a>",
        "Last modified</a>",
    ];

    for indicator in listing_indicators {
        if body.contains(indicator) {
            let finding = Finding::new(FindingConfig {
                title: "Directory Listing Enabled".to_string(),
                description: format!(
                    "Directory listing appears to be enabled: found '{}'",
                    indicator
                ),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "dir-listing".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "Directory listing detected".to_string(),
            )
            .with_data(serde_json::json!({"indicator": indicator}))
            .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                "Disable directory listing".to_string(),
                vec![
                    "Configure web server to disable directory indexing".to_string(),
                    "Add default index file (index.html, index.php, etc.)".to_string(),
                ],
                RemediationEffort::Low,
                RemediationPriority::High,
            );
            findings.push(
                finding
                    .with_evidence(evidence)
                    .with_remediation(remediation),
            );
            break;
        }
    }

    Ok(findings)
}

async fn check_sensitive_files(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let sensitive_paths = [
        ".git/",
        ".env",
        "config.php",
        "wp-config.php",
        "settings.py",
        "config.yaml",
        "docker-compose.yml",
        "Dockerfile",
        "README.md",
        "CHANGELOG.md",
        "package.json",
        "composer.json",
        "requirements.txt",
        "pom.xml",
        "build.gradle",
        ".htaccess",
        "web.config",
        "robots.txt",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        ".well-known/security.txt",
    ];

    for path in sensitive_paths {
        let mut test_url = target.clone();
        test_url.set_path(&format!("/{}", path));

        match client.head(test_url.as_str()).send().await {
            Ok(response) if response.status().is_success() => {
                let finding = Finding::new(FindingConfig {
                    title: format!("Sensitive File Exposed: {}", path),
                    description: format!("Sensitive file accessible: {}", test_url),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "sensitive-files".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    format!("Sensitive file found: {}", path),
                ).with_data(serde_json::json!({"file": path, "url": test_url.to_string(), "status": response.status().as_u16()}))
                .with_location(test_url.to_string());
                findings.push(finding.with_evidence(evidence));
            }
            Ok(_) => {}
            Err(_) => {}
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Ok(findings)
}

async fn check_forms(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let forms = document.find(Name("form")).collect::<Vec<_>>();

    for form in forms {
        let action = form.attr("action").unwrap_or("");
        let method = form.attr("method").unwrap_or("GET").to_uppercase();

        let password_inputs = form
            .find(Name("input"))
            .filter(|n| n.attr("type") == Some("password"))
            .count();

        if password_inputs > 0 && method == "GET" {
            let finding = Finding::new(FindingConfig {
                title: "Password Field in GET Form".to_string(),
                description:
                    "Form with password field uses GET method, exposing credentials in URL"
                        .to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "forms".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "Password field in GET form".to_string(),
            )
            .with_data(serde_json::json!({"action": action, "method": method}))
            .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                "Use POST for forms with password fields".to_string(),
                vec![
                    "Change form method to POST".to_string(),
                    "Ensure HTTPS is used for all forms handling credentials".to_string(),
                ],
                RemediationEffort::Low,
                RemediationPriority::Immediate,
            );
            findings.push(
                finding
                    .with_evidence(evidence)
                    .with_remediation(remediation),
            );
        }

        let autocomplete = form.attr("autocomplete");
        if autocomplete == Some("on") && password_inputs > 0 {
            let finding = Finding::new(FindingConfig {
                title: "Autocomplete Enabled on Password Form".to_string(),
                description: "Form with password field has autocomplete enabled".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "forms".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "Autocomplete on password form".to_string(),
            )
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }

        let has_csrf = form.find(Name("input")).any(|n| {
            let name = n.attr("name").unwrap_or("");
            name.to_lowercase().contains("csrf")
                || name.to_lowercase().contains("token")
                || name.to_lowercase().contains("_token")
        });

        if !has_csrf && method == "POST" && password_inputs > 0 {
            let finding = Finding::new(FindingConfig {
                title: "Missing CSRF Protection on Login Form".to_string(),
                description: "POST form with password field lacks apparent CSRF token".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "forms".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "Possible missing CSRF token".to_string(),
            )
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    Ok(findings)
}

async fn check_links(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let links = document
        .find(Name("a"))
        .filter_map(|n| n.attr("href"))
        .collect::<Vec<_>>();

    let mut _external_links = 0;
    let mut http_links = 0;
    let mut mailto_links = 0;

    for link in &links {
        if link.starts_with("http://") {
            http_links += 1;
        } else if link.starts_with("https://") {
            if !link.contains(target.host_str().unwrap_or("")) {
                _external_links += 1;
            }
        } else if link.starts_with("mailto:") {
            mailto_links += 1;
        }
    }

    if http_links > 0 {
        let finding = Finding::new(FindingConfig {
            title: "Mixed Content: HTTP Links on HTTPS Page".to_string(),
            description: format!("Found {} HTTP links on HTTPS page", http_links),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "links".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(EvidenceType::HttpResponse, "HTTP links found".to_string())
            .with_data(serde_json::json!({"http_links": http_links}))
            .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    if mailto_links > 0 {
        let finding = Finding::new(FindingConfig {
            title: "Email Addresses Exposed in mailto Links".to_string(),
            description: format!("Found {} mailto: links", mailto_links),
            severity: Severity::Low,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "links".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(EvidenceType::HttpResponse, "mailto links found".to_string())
            .with_data(serde_json::json!({"mailto_links": mailto_links}))
            .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}

async fn check_scripts(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let scripts = document
        .find(Name("script"))
        .filter_map(|n| n.attr("src"))
        .collect::<Vec<_>>();

    for script in scripts {
        if script.starts_with("http://") {
            let finding = Finding::new(FindingConfig {
                title: "Mixed Content: HTTP Script on HTTPS Page".to_string(),
                description: format!("External script loaded over HTTP: {}", script),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "scripts".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "HTTP script source".to_string())
                    .with_data(serde_json::json!({"script": script}))
                    .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    let inline_scripts = document
        .find(Name("script"))
        .filter(|n| n.attr("src").is_none())
        .count();
    if inline_scripts > 0 {
        let finding = Finding::new(FindingConfig {
            title: "Inline Scripts Detected".to_string(),
            description: format!(
                "Found {} inline script(s) which may violate CSP",
                inline_scripts
            ),
            severity: Severity::Info,
            confidence: Confidence::Medium,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "scripts".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(
            EvidenceType::HttpResponse,
            "Inline scripts found".to_string(),
        )
        .with_data(serde_json::json!({"count": inline_scripts}))
        .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}

async fn check_meta_tags(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let metas = document.find(Name("meta")).collect::<Vec<_>>();

    for meta in metas {
        if let Some(name) = meta.attr("name") {
            if name.to_lowercase() == "generator" {
                if let Some(content) = meta.attr("content") {
                    let finding = Finding::new(FindingConfig {
                        title: "Generator Meta Tag Disclosure".to_string(),
                        description: format!("Generator meta tag reveals: {}", content),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: Category::InformationDisclosure,
                        target: target.to_string(),
                        target_type: "web".to_string(),
                        plugin_source: "meta-tags".to_string(),
                        plugin_version: "1.0".to_string(),
                        scan_id: scan_id(),
                    });
                    let evidence =
                        Evidence::new(EvidenceType::HttpResponse, "Generator meta tag".to_string())
                            .with_data(serde_json::json!({"content": content}))
                            .with_location(target.to_string());
                    findings.push(finding.with_evidence(evidence));
                }
            }
        }

        if let Some(http_equiv) = meta.attr("http-equiv") {
            if http_equiv.to_lowercase() == "refresh" {
                if let Some(content) = meta.attr("content") {
                    let finding = Finding::new(FindingConfig {
                        title: "Meta Refresh Redirect".to_string(),
                        description: format!("Meta refresh redirect found: {}", content),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: Category::SecurityMisconfiguration,
                        target: target.to_string(),
                        target_type: "web".to_string(),
                        plugin_source: "meta-tags".to_string(),
                        plugin_version: "1.0".to_string(),
                        scan_id: scan_id(),
                    });
                    let evidence =
                        Evidence::new(EvidenceType::HttpResponse, "Meta refresh".to_string())
                            .with_data(serde_json::json!({"content": content}))
                            .with_location(target.to_string());
                    findings.push(finding.with_evidence(evidence));
                }
            }
        }
    }

    Ok(findings)
}

async fn check_http_methods(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let methods = ["TRACE", "TRACK", "PUT", "DELETE", "PATCH", "OPTIONS"];

    for method in methods {
        let req = client.request(method.parse().unwrap(), target.as_str());
        if let Ok(response) = req.send().await {
            if response.status().is_success() || response.status().as_u16() == 204 {
                let severity = match method {
                    "TRACE" | "TRACK" => Severity::Medium,
                    "PUT" | "DELETE" => Severity::High,
                    _ => Severity::Low,
                };

                let finding = Finding::new(FindingConfig {
                    title: format!("HTTP {} Method Enabled", method),
                    description: format!("Server accepts {} requests", method),
                    severity,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "http-methods".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    format!("{} method allowed", method),
                )
                .with_data(
                    serde_json::json!({"method": method, "status": response.status().as_u16()}),
                )
                .with_location(target.to_string());
                findings.push(finding.with_evidence(evidence));
            }
        }
    }

    Ok(findings)
}

async fn check_ssl_config(_client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if target.scheme() == "https" {
        let finding = Finding::new(FindingConfig {
            title: "SSL/TLS Configuration Check".to_string(),
            description: "SSL/TLS configuration analysis requires specialized tools (e.g., testssl.sh, sslyze)".to_string(),
            severity: Severity::Info,
            confidence: Confidence::Low,
            category: Category::Configuration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "ssl-config".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(
            EvidenceType::HttpResponse,
            "SSL/TLS check placeholder".to_string(),
        ).with_data(serde_json::json!({"note": "Use testssl.sh or sslyze for comprehensive SSL/TLS testing"}))
        .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}

#[allow(dead_code)]
async fn display_results(
    findings: &[Finding],
    format: &OutputFormat,
    output: Option<PathBuf>,
    target: &Url,
    duration: Duration,
    checks_run: usize,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Table => print_table_results(findings, target, duration, checks_run),
        OutputFormat::Json => {
            print_json_results(findings, target, duration, checks_run, output).await?
        }
        OutputFormat::Sarif => {
            print_sarif_results(findings, target, duration, checks_run, output).await?
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn print_table_results(
    findings: &[Finding],
    _target: &Url,
    _duration: Duration,
    _checks_run: usize,
) {
    #[derive(Tabled)]
    struct FindingRow {
        #[tabled(rename = "Severity")]
        severity: String,
        #[tabled(rename = "Confidence")]
        confidence: String,
        #[tabled(rename = "Category")]
        category: String,
        #[tabled(rename = "Title")]
        title: String,
        #[tabled(rename = "Check")]
        check: String,
    }

    let rows: Vec<FindingRow> = findings
        .iter()
        .map(|f| FindingRow {
            severity: format_severity(&f.severity),
            confidence: format!("{:?}", f.confidence),
            category: format!("{:?}", f.category),
            title: if f.title.len() > 60 {
                format!("{}...", &f.title[..57])
            } else {
                f.title.clone()
            },
            check: f.plugin_source.clone(),
        })
        .collect();

    if rows.is_empty() {
        println!("\n{} No findings detected.", "✓".green());
        return;
    }

    let table = Table::new(rows).to_string();
    println!("{}", table);

    let mut severity_counts = std::collections::HashMap::new();
    for f in findings {
        *severity_counts.entry(f.severity).or_insert(0) += 1;
    }

    println!("\n{}", "📊 Summary by Severity".bold());
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        if let Some(count) = severity_counts.get(&sev) {
            let color = match sev {
                Severity::Critical => "red",
                Severity::High => "red",
                Severity::Medium => "yellow",
                Severity::Low => "green",
                Severity::Info => "blue",
            };
            println!("  {}: {}", format!("{:?}", sev).color(color), count);
        }
    }
}

#[allow(dead_code)]
fn format_severity(sev: &Severity) -> String {
    match sev {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".red().to_string(),
        Severity::Medium => "MEDIUM".yellow().to_string(),
        Severity::Low => "LOW".green().to_string(),
        Severity::Info => "INFO".blue().to_string(),
    }
}

#[allow(dead_code)]
async fn print_json_results(
    findings: &[Finding],
    target: &Url,
    duration: Duration,
    checks_run: usize,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    use serde_json::json;

    let result = json!({
        "scan_id": scan_id().to_string(),
        "target": target.to_string(),
        "duration_seconds": duration.as_secs_f32(),
        "checks_run": checks_run,
        "findings_count": findings.len(),
        "findings": findings,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let json_str = serde_json::to_string_pretty(&result)?;

    if let Some(path) = output {
        tokio::fs::write(path, json_str).await?;
        println!("Results written to file");
    } else {
        println!("{}", json_str);
    }

    Ok(())
}

#[allow(dead_code)]
async fn print_sarif_results(
    findings: &[Finding],
    target: &Url,
    _duration: Duration,
    _checks_run: usize,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    use serde_json::json;

    let mut results = Vec::new();
    for f in findings {
        let mut result = json!({
            "ruleId": f.plugin_source,
            "level": match f.severity {
                Severity::Critical => "error",
                Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
                Severity::Info => "note",
            },
            "message": { "text": f.title },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": target.to_string() },
                    "region": { "startLine": 1 }
                }
            }],
            "properties": {
                "severity": format!("{:?}", f.severity),
                "confidence": format!("{:?}", f.confidence),
                "category": format!("{:?}", f.category),
                "description": f.description,
            }
        });

        if let Some(cwe) = f.cwe_ids.first() {
            result["properties"]["cwe"] = json!(cwe);
        }

        results.push(result);
    }

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "openre-scan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/RXVEN-1907/open-re",
                    "rules": []
                }
            },
            "results": results,
            "invocations": [{
                "toolExecutionSuccessful": true,
                "startTimeUtc": chrono::Utc::now().to_rfc3339(),
                "endTimeUtc": chrono::Utc::now().to_rfc3339(),
            }]
        }]
    });

    let json_str = serde_json::to_string_pretty(&sarif)?;

    if let Some(path) = output {
        tokio::fs::write(path, json_str).await?;
        println!("SARIF results written to file");
    } else {
        println!("{}", json_str);
    }

    Ok(())
}

#[allow(dead_code)]
fn show_version() {
    print_banner();
    println!("{} {}", "Version:".bold(), env!("CARGO_PKG_VERSION").bright_white());
    println!("{} {}", "Component:".bold(), "openre-scan (standalone scanner)".bright_white());
    println!("{} {}", "Repository:".bold(), "https://github.com/RXVEN-1907/open-re".bright_blue().underline());
    println!("{} {}", "Platform:".bold(), "open-re v0.2.0-dev".bright_white());
    println!();
    println!("{}", "Part of the open-re platform:".dimmed());
    println!("  • openre-scan — Standalone security scanner (this tool)");
    println!("  • openre-cli — Unified CLI for all platform operations");
    println!("  • openre-api — REST/gRPC API server");
    println!("  • openre-analysis — Binary analysis pipeline");
    println!("  • openre-plugins — WASM plugin system");
    println!("  • openre-security-ai — AI-powered vulnerability analysis");
}

fn scan_id() -> ScanId {
    ScanId::new()
}

// Extensions for Finding and Evidence
#[allow(dead_code)]
trait FindingExt {
    fn with_evidence(self, evidence: Evidence) -> Self;
    fn with_remediation(self, remediation: RemediationGuidance) -> Self;
}

impl FindingExt for Finding {
    fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    fn with_remediation(mut self, remediation: RemediationGuidance) -> Self {
        self.remediation = Some(remediation);
        self
    }
}

#[allow(dead_code)]
trait EvidenceExt {
    fn new(evidence_type: EvidenceType, description: String) -> Self;
    fn with_data(self, data: serde_json::Value) -> Self;
    fn with_location(self, location: String) -> Self;
}

impl EvidenceExt for Evidence {
    fn new(evidence_type: EvidenceType, description: String) -> Self {
        Self {
            evidence_type,
            description,
            data: None,
            location: None,
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: None,
            timestamp: chrono::Utc::now(),
        }
    }

    fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }
}

trait RemediationGuidanceExt {
    fn new(
        summary: String,
        steps: Vec<String>,
        effort: RemediationEffort,
        priority: RemediationPriority,
    ) -> Self;
}

impl RemediationGuidanceExt for RemediationGuidance {
    fn new(
        summary: String,
        steps: Vec<String>,
        effort: RemediationEffort,
        priority: RemediationPriority,
    ) -> Self {
        Self {
            summary,
            steps,
            code_examples: Vec::new(),
            references: Vec::new(),
            effort,
            priority,
        }
    }
}
