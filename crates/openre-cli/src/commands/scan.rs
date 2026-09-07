//! Web vulnerability scanning commands

use colored::Colorize;
use clap::{Args, Subcommand, ValueEnum};
use openre_scan::{ScanProfile, ScanTarget, Scanner, ScanResult};
use openre_core::result::Severity;
use crate::{Context, CliError, print_output, OutputFormat};
use std::path::PathBuf;
use std::str::FromStr;
use tabled::{Table, settings::Style};

#[derive(Subcommand, Debug)]
pub enum ScanCommands {
    /// Quick scan (essential checks only, ~2-3s)
    Quick(ScanArgs),
    /// Standard scan (recommended, ~10-15s)
    Standard(ScanArgs),
    /// Full scan (all checks, ~30-60s)
    Full(ScanArgs),
    /// Custom scan with specific checks
    Custom(CustomScanArgs),
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Target URL or domain
    target: String,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Custom headers (can be repeated, format: "Key: Value")
    #[arg(long, value_name = "HEADER")]
    header: Vec<String>,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Follow redirects
    #[arg(long, default_value = "true")]
    follow_redirects: bool,

    /// Maximum redirect depth
    #[arg(long, default_value = "10")]
    max_redirects: usize,

    /// User agent string
    #[arg(long)]
    user_agent: Option<String>,

    /// Proxy URL (e.g., http://127.0.0.1:8080)
    #[arg(long)]
    proxy: Option<String>,

    /// Rate limit (requests per second)
    #[arg(long)]
    rate_limit: Option<f64>,

    /// Exclude specific checks
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Include only specific checks
    #[arg(long, value_delimiter = ',')]
    checks: Vec<String>,
}

#[derive(Args, Debug)]
struct CustomScanArgs {
    /// Target URL or domain
    target: String,

    /// Scan profile
    #[arg(long, value_enum, default_value = "standard")]
    profile: ScanProfileArg,

    /// Checks to run (comma-separated)
    #[arg(long, value_delimiter = ',')]
    checks: Vec<String>,

    /// Checks to exclude (comma-separated)
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Custom headers
    #[arg(long, value_name = "HEADER")]
    header: Vec<String>,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,
}

#[derive(Debug, Clone, ValueEnum)]
enum ScanProfileArg {
    Quick,
    Standard,
    Full,
}

impl ScanCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ScanCommands::Quick(args) => run_scan(ctx, ScanProfile::Quick, args).await,
            ScanCommands::Standard(args) => run_scan(ctx, ScanProfile::Standard, args).await,
            ScanCommands::Full(args) => run_scan(ctx, ScanProfile::Full, args).await,
            ScanCommands::Custom(args) => run_custom_scan(ctx, args).await,
        }
    }
}

async fn run_scan(ctx: Context, profile: ScanProfile, args: ScanArgs) -> Result<(), CliError> {
    let mut target = ScanTarget::new(&args.target).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    target = target
        .with_timeout(args.timeout)
        .with_max_redirects(args.max_redirects);

    // Parse headers
    let mut headers = Vec::new();
    for h in args.header {
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if !headers.is_empty() {
        target = target.with_headers(headers);
    }

    if let Some(ua) = args.user_agent {
        target = target.with_user_agent(ua);
    }
    if let Some(proxy) = args.proxy {
        target = target.with_proxy(proxy);
    }
    if let Some(rate) = args.rate_limit {
        target = target.with_rate_limit(rate);
    }

    let spinner = ctx.spinner(format!("Scanning {} with {} profile...", args.target, profile));

    let mut scanner = Scanner::new(profile)?;
    let mut result = scanner.scan(target).await?;

    // Update result with checks_run (scanner doesn't track this yet)
    // result.checks_run = ...; // Would need to be computed

    spinner.finish_and_clear();

    output_results(ctx, &result, args.output).await
}

async fn run_custom_scan(ctx: Context, args: CustomScanArgs) -> Result<(), CliError> {
    let profile = match args.profile {
        ScanProfileArg::Quick => ScanProfile::Quick,
        ScanProfileArg::Standard => ScanProfile::Standard,
        ScanProfileArg::Full => ScanProfile::Full,
    };

    let mut target = ScanTarget::new(&args.target).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    target = target.with_timeout(args.timeout);

    // Parse headers
    let mut headers = Vec::new();
    for h in args.header {
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if !headers.is_empty() {
        target = target.with_headers(headers);
    }

    let spinner = ctx.spinner(format!("Scanning {} with custom profile...", args.target));

    let mut scanner = Scanner::new(profile)?;
    let result = scanner.scan(target).await?;

    spinner.finish_and_clear();

    output_results(ctx, &result, args.output).await
}

async fn output_results(ctx: Context, result: &ScanResult, output_path: Option<PathBuf>) -> Result<(), CliError> {
    // Print summary to console
    print_scan_summary(result);

    // Write to file if requested
    if let Some(path) = output_path {
        let format = if path.extension().and_then(|s| s.to_str()) == Some("sarif") {
            OutputFormat::Sarif
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            OutputFormat::Json
        } else {
            ctx.format
        };

        print_output(result, format, Some(&path))?;
        println!("\n{} Results saved to {}", "✓".green().bold(), path.display());
    }

    Ok(())
}

fn print_scan_summary(result: &ScanResult) {
    println!("\n{}", "═".repeat(60).dimmed());
    println!("{} {}", "📋 Scan Results".bold().cyan(), format!("({})", result.scan_id).dimmed());
    println!("{}", "═".repeat(60).dimmed());
    println!("  {} {}", "Target:".bold(), result.target);
    println!("  {} {}", "Profile:".bold(), result.profile);
    println!("  {} {:.2}s", "Duration:".bold(), result.duration_ms as f64 / 1000.0);
    println!("  {} {}", "Checks Run:".bold(), result.checks_run);
    println!("  {} {}", "Findings:".bold(), result.findings.len());

    if !result.findings.is_empty() {
        println!("\n{}", "Findings by Severity:".bold());
        let mut counts = std::collections::HashMap::new();
        for f in &result.findings {
            *counts.entry(f.severity).or_insert(0) += 1;
        }
        for (sev, count) in [("critical", "🔴"), ("high", "🟠"), ("medium", "🟡"), ("low", "🔵"), ("info", "⚪")] {
            if let Some(c) = counts.get(&Severity::from_str(sev).unwrap_or(Severity::Info)) {
                println!("  {} {}: {}", sev.to_uppercase().bold(), " ".repeat(8 - sev.len()), c);
            }
        }
    }

    // Show top findings
    if !result.findings.is_empty() {
        println!("\n{}", "Top Findings:".bold());
        let mut table = Table::new(
            result.findings.iter().take(10).map(|f| ScanFindingRow {
                severity: format!("{:?}", f.severity),
                title: f.title.clone(),
                check: f.plugin_source.clone(),
            }).collect::<Vec<_>>()
        );
        table.with(Style::modern());
        println!("{}", table);
    }
}

#[derive(tabled::Tabled)]
struct ScanFindingRow {
    #[tabled(rename = "SEV")]
    severity: String,
    #[tabled(rename = "TITLE")]
    title: String,
    #[tabled(rename = "CHECK")]
    check: String,
}