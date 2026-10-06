//! Web vulnerability scanning commands

use crate::output::{print_output, OutputFormat};
use crate::error::CliError;
use crate::context::Context;
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::error::OpenreResult;
use openre_core::history::{HistoryStorage, ScanProgressSummary, ScanSummary};
use openre_core::ids::{FindingId, ProjectId, ScanId};
use openre_core::result::Finding;
use openre_core::result::Severity;
use openre_scan::checks::get_all_checks;
use openre_scan::client::{build_client, build_client_with_config};
use openre_scan::config::ScanConfig;
use openre_scan::output::display_results;
use openre_scan::{ScanProfile, ScanResult, ScanTarget, Scanner};
use openre_storage::history::SqliteHistoryStorage;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tabled::{Table, Tabled, Style};
use tokio::time::{sleep, Duration};

fn get_history_storage(ctx: &Context) -> SqliteHistoryStorage {
    let db_path = ctx.config.storage.local_path.join("history.db");
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create history directory");
    }
    SqliteHistoryStorage::new(&db_path).expect("Failed to create history storage")
}

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
    /// Pause a running scan
    Pause(PauseScanArgs),
    /// Resume a paused scan
    Resume(ResumeScanArgs),
    /// Export scan data
    #[command(subcommand)]
    Export(ExportCommands),
    /// Import scan data
    #[command(subcommand)]
    Import(ImportCommands),
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

#[derive(Debug, Clone, ValueEnum)]
enum ExportFormat {
    Json,
    Csv,
}

/// Export commands
#[derive(Subcommand, Debug)]
enum ExportCommands {
    /// Export findings for a specific scan
    Findings(ExportFindingsArgs),
    /// Export scan summaries with optional filters
    Scans(ExportScansArgs),
    /// Export projects
    Projects(ExportProjectsArgs),
}

/// Import commands
#[derive(Subcommand, Debug)]
enum ImportCommands {
    /// Import findings from a file
    Findings(ImportFindingsArgs),
    /// Import scan summaries from a file
    Scans(ImportScansArgs),
    /// Import projects from a file
    Projects(ImportProjectsArgs),
}

/// Arguments for exporting findings
#[derive(Args, Debug)]
struct ExportFindingsArgs {
    /// Scan ID to export findings for
    scan_id: String,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    format: ExportFormat,

    /// Output file path (if not specified, prints to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Arguments for exporting scan summaries
#[derive(Args, Debug)]
struct ExportScansArgs {
    /// Filter by project ID (optional)
    #[arg(long)]
    project_id: Option<String>,

    /// Filter by status (e.g., completed, running, failed)
    #[arg(long)]
    status: Option<String>,

    /// Filter by date range (ISO 8601 format, e.g., 2024-01-01T00:00:00Z)
    #[arg(long)]
    date_from: Option<String>,

    #[arg(long)]
    date_to: Option<String>,

    /// Filter by tags (comma-separated)
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,

    /// Filter by minimum severity (critical, high, medium, low, info)
    #[arg(long)]
    min_severity: Option<String>,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    format: ExportFormat,

    /// Output file path (if not specified, prints to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Arguments for exporting projects
#[derive(Args, Debug)]
struct ExportProjectsArgs {
    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    format: ExportFormat,

    /// Output file path (if not specified, prints to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Arguments for importing findings
#[derive(Args, Debug)]
struct ImportFindingsArgs {
    /// Input file path
    input: PathBuf,

    /// Scan ID to associate the findings with (if not in the file)
    #[arg(long)]
    scan_id: Option<String>,
}

/// Arguments for importing scan summaries
#[derive(Args, Debug)]
struct ImportScansArgs {
    /// Input file path
    input: PathBuf,
}

/// Arguments for importing projects
#[derive(Args, Debug)]
struct ImportProjectsArgs {
    /// Input file path
    input: PathBuf,
}

#[derive(Args, Debug)]
struct PauseScanArgs {
    /// Scan ID to pause
    scan_id: String,
}

#[derive(Args, Debug)]
struct ResumeScanArgs {
    /// Scan ID to resume
    scan_id: String,
}

impl ScanCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ScanCommands::Quick(args) => run_scan(ctx, ScanProfile::Quick, args).await,
            ScanCommands::Standard(args) => run_scan(ctx, ScanProfile::Standard, args).await,
            ScanCommands::Full(args) => run_scan(ctx, ScanProfile::Full, args).await,
            ScanCommands::Custom(args) => run_custom_scan(ctx, args).await,
            ScanCommands::Pause(args) => pause_scan(ctx, &args.scan_id).await,
            ScanCommands::Resume(args) => resume_scan(ctx, &args.scan_id).await,
            ScanCommands::Export(cmd) => export_command(ctx, cmd).await,
            ScanCommands::Import(cmd) => import_command(ctx, cmd).await,
        }
    }
}

async fn export_command(ctx: Context, cmd: ExportCommands) -> Result<(), CliError> {
    match cmd {
        ExportCommands::Findings(args) => export_findings(ctx, args).await,
        ExportCommands::Scans(args) => export_scans(ctx, args).await,
        ExportCommands::Projects(args) => export_projects(ctx, args).await,
    }
}

async fn import_command(ctx: Context, cmd: ImportCommands) -> Result<(), CliError> {
    match cmd {
        ImportCommands::Findings(args) => import_findings(ctx, args).await,
        ImportCommands::Scans(args) => import_scans(ctx, args).await,
        ImportCommands::Projects(args) => import_projects(ctx, args).await,
    }
}

async fn run_scan(ctx: Context, profile: ScanProfile, args: ScanArgs) -> Result<(), CliError> {
    // Generate a unique scan ID
    let scan_id = ScanId::new();

    // Get history storage
    let history = get_history_storage(&ctx);

    // Create initial scan summary with pending status
    let mut summary = ScanSummary {
        scan_id,
        project_id: None, // We don't have project ID in CLI scan context
        target_id: openre_core::ids::TargetId::from_uuid(uuid::Uuid::new_v4()), // We'll set this properly later
        name: format!("Scan {}", args.target),
        description: Some(format!("Scan of {} with {:?} profile", args.target, profile)),
        status: "pending".to_string(),
        config: openre_core::history::ScanConfigSummary {
            name: format!("Scan {}", args.target),
            target_url: args.target.clone(),
            plugins: vec![], // We don't have plugin info here
            rate_limit: None,
            timeout_seconds: Some(args.timeout as u32),
            auth_configured: false,
            custom_headers_count: args.header.len(),
        },
        progress: ScanProgressSummary {
            total_endpoints: 0, // We don't have endpoint info in CLI scan
            endpoints_scanned: 0,
            endpoints_failed: 0,
            percentage: 0.0,
            completed_checks: Vec::new(),
        },
        finding_stats: openre_core::result::FindingStats {
            total: 0,
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
        plugin_executions: Vec::new(),
        created_at: chrono::Utc::now(),
        started_at: None,
        completed_at: None,
        duration_seconds: None,
        tags: Vec::new(),
    };

    // Save initial summary
    history.save_scan_summary(&summary).await?;

    // Update target ID to be based on the scan ID for consistency
    // In a real implementation, we would have a proper target ID
    // For now, we'll keep it as is

    // Update status to running
    let mut running_summary = summary.clone();
    running_summary.status = "running".to_string();
    running_summary.started_at = Some(chrono::Utc::now());
    history.save_scan_summary(&running_summary).await?;

    // Build scan target
    let mut target =
        ScanTarget::new(&args.target).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    target = target.with_timeout(args.timeout).with_max_redirects(args.max_redirects);

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

    // Get checks to run based on profile
    let all_checks = get_all_checks(&profile);
    let checks_to_run: Vec<openre_scan::checks::Check> = all_checks
        .into_iter()
        .filter(|c| {
            let should_run = args.checks.is_empty() || args.checks.iter().any(|s| s == c.name());
            let should_exclude = args.exclude.iter().any(|s| s == c.name());
            should_run && !should_exclude
        })
        .collect();

    // If no checks specified, run all
    let checks_to_run = if args.checks.is_empty() && args.exclude.is_empty() {
        get_all_checks(&profile)
            .into_iter()
            .filter(|c| c.name() != "sensitive-files") // Match the original behavior
            .collect()
    } else {
        checks_to_run
    };

    // Initialize findings vector
    let mut all_findings = Vec::new();
    let start_time = std::time::Instant::now();
    let spinner = ctx.spinner(format!("Scanning {}", args.target));

    let checks_run_count = checks_to_run.len();

    // Process each check
    for check in checks_to_run {
        // Check for pause/cancelled status before each check
        loop {
            // Load current summary from history
            let current_summary = history.get_scan_summary(&running_summary.scan_id).await?;
            if let Some(summary) = current_summary {
                match summary.status.as_str() {
                    "paused" => {
                        // Wait a bit and check again
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    "cancelled" => {
                        return Err(CliError::ScanCancelled);
                    }
                    "failed" => {
                        return Err(CliError::ScanFailed);
                    }
                    "completed" => {
                        // Already completed, shouldn't happen
                        break;
                    }
                    _ => {
                        // running or pending - proceed
                        break;
                    }
                }
            } else {
                // Summary not found, treat as error
                return Err(CliError::HistoryError(format!(
                    "Scan summary not found for ID: {}",
                    running_summary.scan_id
                )));
            }
        }

        // Run the check
        match check
            .run(
                &build_client(args.timeout, args.max_redirects, false, String::new(), None)?,
                &target.url,
            )
            .await
        {
            Ok(findings) => {
                if !findings.is_empty() {
                    // Print finding immediately (optional)
                    for finding in &findings {
                        println!(
                            "  {} {} [{}]",
                            "✓".green(),
                            finding.title.bright_white(),
                            format!("({})", finding.severity)
                                .color(severity_color(&finding.severity))
                        );
                    }
                    all_findings.extend(findings);
                }
            }
            Err(e) => {
                eprintln!("{} {} failed: {}", "✗".red().bold(), check.name().bright_yellow(), e);
                // Continue with other checks
            }
        }

        // Update progress: mark this check as completed
        let mut updated_summary = history
            .get_scan_summary(&running_summary.scan_id)
            .await?
            .expect("Scan summary should exist");
        updated_summary.progress.completed_checks.push(check.name().to_string());
        // Update finding stats (we'll compute at the end for simplicity)
        // Save the updated summary
        history.save_scan_summary(&updated_summary).await?;
    }

    // Calculate duration
    let duration = start_time.elapsed();

    // Update final summary with completed status
    let mut final_summary =
        history.get_scan_summary(&scan_id).await?.expect("Scan summary should exist");
    final_summary.status = "completed".to_string();
    final_summary.completed_at = Some(chrono::Utc::now());
    final_summary.duration_seconds = Some(duration.as_secs() as u64);
    // Update finding stats
    let mut severity_counts = std::collections::HashMap::new();
    for f in &all_findings {
        *severity_counts.entry(f.severity.clone()).or_insert(0) += 1;
    }
    final_summary.finding_stats = openre_core::result::FindingStats {
        total: all_findings.len(),
        by_severity: severity_counts.clone(),
        by_confidence: std::collections::HashMap::new(), // We don't track confidence in CLI scan
        by_category: std::collections::HashMap::new(),   // We don't track category
        by_plugin: std::collections::HashMap::new(),     // We don't track plugin
        verified: all_findings.iter().filter(|f| f.verified).count(),
        false_positives: 0, // We don't track false positives
        avg_risk_score: if all_findings.is_empty() {
            0.0
        } else {
            all_findings.iter().map(|f| f.risk_score.unwrap_or(0) as f32).sum::<f32>()
                / all_findings.len() as f32
        },
        max_risk_score: if all_findings.is_empty() {
            0
        } else {
            all_findings.iter().map(|f| f.risk_score.unwrap_or(0)).max().unwrap_or(0)
        },
        by_owasp_category: std::collections::HashMap::new(),
        by_cwe: std::collections::HashMap::new(),
        avg_advanced_risk_score: 0.0,
        max_advanced_risk_score: 0,
        by_remediation_priority: std::collections::HashMap::new(),
        exploit_available_count: 0,
        exploited_in_wild_count: 0,
    };
    // Update risk metrics based on findings
    final_summary.risk_metrics = openre_core::history::RiskMetricsSummary {
        overall_risk_score: if all_findings.is_empty() {
            0
        } else {
            (all_findings.iter().map(|f| f.risk_score.unwrap_or(0) as u8).sum::<u8>()
                / all_findings.len() as u8) as u8
        },
        risk_level: if all_findings.is_empty() {
            openre_core::reporting::RiskLevel::Low
        } else {
            let avg_score =
                (all_findings.iter().map(|f| f.risk_score.unwrap_or(0) as u8).sum::<u8>() as f32
                    / all_findings.len() as f32)
                    .round() as u8;
            match avg_score {
                0..=25 => openre_core::reporting::RiskLevel::Low,
                26..=50 => openre_core::reporting::RiskLevel::Medium,
                51..=75 => openre_core::reporting::RiskLevel::High,
                _ => openre_core::reporting::RiskLevel::Critical,
            }
        },
        critical_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Critical)
            .count(),
        high_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::High)
            .count(),
        medium_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Medium)
            .count(),
        low_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Low)
            .count(),
        info_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Info)
            .count(),
        avg_risk_score: final_summary.finding_stats.avg_risk_score,
        max_risk_score: final_summary.finding_stats.max_risk_score as u8,
    };
    history.save_scan_summary(&final_summary).await?;

    // Build scan result
    let mut severity_counts_hashmap = std::collections::HashMap::new();
    for f in &all_findings {
        *severity_counts_hashmap.entry(f.severity.to_string()).or_insert(0) += 1;
    }
    let result = ScanResult {
        scan_id: scan_id.as_uuid(),
        target: args.target,
        profile,
        duration_ms: duration.as_millis() as u64,
        checks_run: checks_run_count,
        findings: all_findings,
        severity_counts: severity_counts_hashmap,
    };

    spinner.finish_and_clear();

    output_results(ctx, &result, args.output).await
}

async fn run_custom_scan(ctx: Context, args: CustomScanArgs) -> Result<(), CliError> {
    // Generate a unique scan ID
    let scan_id = ScanId::new();

    // Get history storage
    let history = get_history_storage(&ctx);

    // Determine profile
    let profile = match args.profile {
        ScanProfileArg::Quick => ScanProfile::Quick,
        ScanProfileArg::Standard => ScanProfile::Standard,
        ScanProfileArg::Full => ScanProfile::Full,
    };

    // Create initial scan summary with pending status
    let mut summary = ScanSummary {
        scan_id,
        project_id: None, // We don't have project ID in CLI scan context
        target_id: openre_core::ids::TargetId::from_uuid(uuid::Uuid::new_v4()), // We'll set this properly later
        name: format!("Custom Scan {}", args.target),
        description: Some(format!("Custom scan of {} with {:?} profile", args.target, profile)),
        status: "pending".to_string(),
        config: openre_core::history::ScanConfigSummary {
            name: format!("Custom Scan {}", args.target),
            target_url: args.target.clone(),
            plugins: vec![], // We don't have plugin info here
            rate_limit: None,
            timeout_seconds: Some(args.timeout as u32),
            auth_configured: false,
            custom_headers_count: args.header.len(),
        },
        progress: ScanProgressSummary {
            total_endpoints: 0, // We don't have endpoint info in CLI scan
            endpoints_scanned: 0,
            endpoints_failed: 0,
            percentage: 0.0,
            completed_checks: Vec::new(),
        },
        finding_stats: openre_core::result::FindingStats {
            total: 0,
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
        plugin_executions: Vec::new(),
        created_at: chrono::Utc::now(),
        started_at: None,
        completed_at: None,
        duration_seconds: None,
        tags: Vec::new(),
    };

    // Save initial summary
    history.save_scan_summary(&summary).await?;

    // Update target ID to be based on the scan ID for consistency
    // In a real implementation, we would have a proper target ID
    // For now, we'll keep it as is

    // Update status to running
    let mut running_summary = summary.clone();
    running_summary.status = "running".to_string();
    running_summary.started_at = Some(chrono::Utc::now());
    history.save_scan_summary(&running_summary).await?;

    // Build scan target
    let mut target =
        ScanTarget::new(&args.target).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
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

    // Get checks to run based on args
    let all_checks = get_all_checks(&profile);
    let checks_to_run: Vec<openre_scan::checks::Check> = all_checks
        .into_iter()
        .filter(|c| {
            let should_run = args.checks.is_empty() || args.checks.iter().any(|s| s == c.name());
            let should_exclude = args.exclude.iter().any(|s| s == c.name());
            should_run && !should_exclude
        })
        .collect();

    // If no checks specified, run all (excluding sensitive-files to match original behavior)
    let checks_to_run = if args.checks.is_empty() && args.exclude.is_empty() {
        get_all_checks(&profile).into_iter().filter(|c| c.name() != "sensitive-files").collect()
    } else {
        checks_to_run
    };

    // Initialize findings vector
    let mut all_findings = Vec::new();
    let start_time = std::time::Instant::now();
    let spinner = ctx.spinner(format!("Scanning {}", args.target));

    let checks_run_count = checks_to_run.len();

    // Process each check
    for check in checks_to_run {
        // Check for pause/cancelled status before each check
        loop {
            // Load current summary from history
            let current_summary = history.get_scan_summary(&running_summary.scan_id).await?;
            if let Some(summary) = current_summary {
                match summary.status.as_str() {
                    "paused" => {
                        // Wait a bit and check again
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    "cancelled" => {
                        return Err(CliError::ScanCancelled);
                    }
                    "failed" => {
                        return Err(CliError::ScanFailed);
                    }
                    "completed" => {
                        // Already completed, shouldn't happen
                        break;
                    }
                    _ => {
                        // running or pending - proceed
                        break;
                    }
                }
            } else {
                // Summary not found, treat as error
                return Err(CliError::HistoryError(format!(
                    "Scan summary not found for ID: {}",
                    running_summary.scan_id
                )));
            }
        }

        // Run the check
        match check
            .run(&build_client(args.timeout, 0, false, String::new(), None)?, &target.url)
            .await
        {
            Ok(findings) => {
                if !findings.is_empty() {
                    // Print finding immediately (optional)
                    for finding in &findings {
                        println!(
                            "  {} {} [{}]",
                            "✓".green(),
                            finding.title.bright_white(),
                            format!("({})", finding.severity)
                                .color(severity_color(&finding.severity))
                        );
                    }
                    all_findings.extend(findings);
                }
            }
            Err(e) => {
                eprintln!("{} {} failed: {}", "✗".red().bold(), check.name().bright_yellow(), e);
                // Continue with other checks
            }
        }

        // Update progress: mark this check as completed
        let mut updated_summary = history
            .get_scan_summary(&running_summary.scan_id)
            .await?
            .expect("Scan summary should exist");
        updated_summary.progress.completed_checks.push(check.name().to_string());
        // Update finding stats (we'll compute at the end for simplicity)
        // Save the updated summary
        history.save_scan_summary(&updated_summary).await?;
    }

    // Calculate duration
    let duration = start_time.elapsed();

    // Update final summary with completed status
    let mut final_summary =
        history.get_scan_summary(&scan_id).await?.expect("Scan summary should exist");
    final_summary.status = "completed".to_string();
    final_summary.completed_at = Some(chrono::Utc::now());
    final_summary.duration_seconds = Some(duration.as_secs() as u64);
    // Update finding stats
    let mut severity_counts = std::collections::HashMap::new();
    for f in &all_findings {
        *severity_counts.entry(f.severity.clone()).or_insert(0) += 1;
    }
    final_summary.finding_stats = openre_core::result::FindingStats {
        total: all_findings.len(),
        by_severity: severity_counts.clone(),
        by_confidence: std::collections::HashMap::new(), // We don't track confidence in CLI scan
        by_category: std::collections::HashMap::new(),   // We don't track category
        by_plugin: std::collections::HashMap::new(),     // We don't track plugin
        verified: all_findings.iter().filter(|f| f.verified).count(),
        false_positives: 0, // We don't track false positives
        avg_risk_score: if all_findings.is_empty() {
            0.0
        } else {
            all_findings.iter().map(|f| f.risk_score.unwrap_or(0) as f32).sum::<f32>()
                / all_findings.len() as f32
        },
        max_risk_score: if all_findings.is_empty() {
            0
        } else {
            all_findings.iter().map(|f| f.risk_score.unwrap_or(0)).max().unwrap_or(0)
        },
        by_owasp_category: std::collections::HashMap::new(),
        by_cwe: std::collections::HashMap::new(),
        avg_advanced_risk_score: 0.0,
        max_advanced_risk_score: 0,
        by_remediation_priority: std::collections::HashMap::new(),
        exploit_available_count: 0,
        exploited_in_wild_count: 0,
    };
    // Update risk metrics based on findings
    final_summary.risk_metrics = openre_core::history::RiskMetricsSummary {
        overall_risk_score: if all_findings.is_empty() {
            0
        } else {
            (all_findings.iter().map(|f| f.risk_score.unwrap_or(0) as u8).sum::<u8>()
                / all_findings.len() as u8) as u8
        },
        risk_level: if all_findings.is_empty() {
            openre_core::reporting::RiskLevel::Low
        } else {
            let avg_score =
                (all_findings.iter().map(|f| f.risk_score.unwrap_or(0) as u8).sum::<u8>() as f32
                    / all_findings.len() as f32)
                    .round() as u8;
            match avg_score {
                0..=25 => openre_core::reporting::RiskLevel::Low,
                26..=50 => openre_core::reporting::RiskLevel::Medium,
                51..=75 => openre_core::reporting::RiskLevel::High,
                _ => openre_core::reporting::RiskLevel::Critical,
            }
        },
        critical_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Critical)
            .count(),
        high_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::High)
            .count(),
        medium_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Medium)
            .count(),
        low_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Low)
            .count(),
        info_count: all_findings
            .iter()
            .filter(|f| f.severity == openre_core::result::Severity::Info)
            .count(),
        avg_risk_score: final_summary.finding_stats.avg_risk_score,
        max_risk_score: final_summary.finding_stats.max_risk_score as u8,
    };
    history.save_scan_summary(&final_summary).await?;

    // Build scan result
    let mut severity_counts_hashmap = std::collections::HashMap::new();
    for f in &all_findings {
        *severity_counts_hashmap.entry(f.severity.to_string()).or_insert(0) += 1;
    }
    let result = ScanResult {
        scan_id: scan_id.as_uuid(),
        target: args.target,
        profile,
        duration_ms: duration.as_millis() as u64,
        checks_run: checks_run_count,
        findings: all_findings,
        severity_counts: severity_counts_hashmap,
    };

    spinner.finish_and_clear();

    output_results(ctx, &result, args.output).await
}

async fn output_results(
    ctx: Context,
    result: &ScanResult,
    output_path: Option<PathBuf>,
) -> Result<(), CliError> {
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
        for (sev, count) in
            [("critical", "🔴"), ("high", "🟠"), ("medium", "🟡"), ("low", "🔵"), ("info", "⚪")]
        {
            if let Some(c) = counts.get(&Severity::from_str(sev).unwrap_or(Severity::Info)) {
                println!("  {} {}: {}", sev.to_uppercase().bold(), " ".repeat(8 - sev.len()), c);
            }
        }
    }

    // Show top findings
    if !result.findings.is_empty() {
        println!("\n{}", "Top Findings:".bold());
        let mut table = Table::new(
            result
                .findings
                .iter()
                .take(10)
                .map(|f| ScanFindingRow {
                    severity: format!("{:?}", f.severity),
                    title: f.title.clone(),
                    check: f.plugin_source.clone(),
                })
                .collect::<Vec<_>>(),
        );
        table.with(Style::modern());
        println!("{}", table);
    }
}

// Export functions
async fn export_findings(ctx: Context, args: ExportFindingsArgs) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);
    let scan_id = ScanId::from_uuid(
        uuid::Uuid::parse_str(&args.scan_id)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid scan ID: {}", e)))?,
    );

    // Get scan summary to verify it exists
    let scan_summary_opt = history
        .get_scan_summary(&scan_id)
        .await
        .map_err(|e| CliError::HistoryError(e.to_string()))?;

    let scan_summary = scan_summary_opt
        .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", args.scan_id)))?;

    // Get deduplicated findings for the scan
    let findings = history
        .get_deduplicated_findings(&scan_id)
        .await
        .map_err(|e| CliError::HistoryError(e.to_string()))?;

    // Serialize findings based on format
    let output = match args.format {
        ExportFormat::Json => serde_json::to_string_pretty(&findings)
            .map_err(|e| CliError::InvalidArgs(format!("Failed to serialize JSON: {}", e)))?,
        ExportFormat::Csv => {
            // Convert findings to CSV
            let mut csv = String::new();
            // Header
            csv.push_str("id,title,description,severity,confidence,plugin_source,location\n");
            for f in &findings {
                csv.push_str(&format!(
                    "\"{}\",\"{}\",\"{}\",{:?},{:?},\"{}\",\"{}\"\n",
                    f.id,
                    f.title.replace('"', "\"\""),
                    f.description.replace('"', "\"\""),
                    f.severity,
                    f.confidence,
                    f.plugin_source,
                    f.evidence.first().and_then(|e| e.location.clone()).unwrap_or_default()
                ));
            }
            csv
        }
    };

    // Output to file or stdout
    if let Some(path) = args.output {
        std::fs::write(&path, output)
            .map_err(|e| CliError::Other(format!("Failed to write file: {}", e)))?;
        println!("\n{} Findings exported to {}", "✓".green().bold(), path.display());
    } else {
        println!("{}", output);
    }

    Ok(())
}

async fn export_scans(ctx: Context, args: ExportScansArgs) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);

    // Parse optional filters
    let project_id = args
        .project_id
        .as_deref()
        .map(|s| ProjectId::from_uuid(uuid::Uuid::parse_str(s).unwrap_or_default()));

    let status = args.status.clone();

    let date_from = args
        .date_from
        .as_deref()
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| CliError::InvalidArgs(format!("Invalid date_from: {}", e)))
                .map(|dt| dt.with_timezone(&chrono::Utc))
        })
        .transpose()?;

    let date_to = args
        .date_to
        .as_deref()
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| CliError::InvalidArgs(format!("Invalid date_to: {}", e)))
                .map(|dt| dt.with_timezone(&chrono::Utc))
        })
        .transpose()?;

    let tags = args.tags.clone();

    let min_severity = args.min_severity.as_deref().map(|s| {
        Severity::from_str(s).unwrap_or_else(|_| {
            eprintln!("{} Warning: Invalid severity '{}', ignoring filter", "⚠".yellow(), s);
            Severity::Info
        })
    });

    // Get scan summaries with filters
    let mut summaries = history
        .list_scan_summaries(project_id.clone(), 1000, 0)
        .await
        .map_err(|e| CliError::HistoryError(e.to_string()))?;

    // Apply filters in memory (since we don't have complex querying in the history trait yet)
    summaries.retain(|summary| {
        // Status filter
        if let Some(ref status_filter) = status {
            if summary.status != *status_filter {
                return false;
            }
        }

        // Date range filter
        if let Some(from) = date_from {
            if summary.created_at < from {
                return false;
            }
        }
        if let Some(to) = date_to {
            if summary.created_at > to {
                return false;
            }
        }

        // Tags filter
        if !tags.is_empty() {
            let summary_tags: HashSet<String> = summary.tags.iter().cloned().collect();
            if !tags.iter().all(|tag| summary_tags.contains(tag)) {
                return false;
            }
        }

        // Minimum severity filter
        if let Some(min_sev) = min_severity {
            // Check if any finding meets or exceeds the minimum severity
            let meets_min =
                summary.finding_stats.by_severity.iter().any(|(sev, count)| {
                    *count > 0 && severity_meets_min(sev, &min_sev.to_string())
                });
            if !meets_min {
                return false;
            }
        }

        true
    });

    // Serialize based on format
    let output = match args.format {
        ExportFormat::Json => serde_json::to_string_pretty(&summaries)
            .map_err(|e| CliError::InvalidArgs(format!("Failed to serialize JSON: {}", e)))?,
        ExportFormat::Csv => {
            // Convert scan summaries to CSV
            let mut csv = String::new();
            // Header
            csv.push_str("id,project_id,target_id,name,description,status,created_at,started_at,completed_at,duration_seconds,finding_count\n");
            for summary in &summaries {
                csv.push_str(&format!(
                    "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",{},{}\n",
                    summary.scan_id,
                    summary.project_id.map(|p| p.to_string()).unwrap_or_default(),
                    summary.target_id,
                    summary.name.replace('"', "\"\""),
                    summary.description.as_deref().unwrap_or("").replace('"', "\"\""),
                    summary.status,
                    summary.created_at.to_rfc3339(),
                    summary.started_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
                    summary.completed_at.map(|dt| dt.to_rfc3339()).unwrap_or_default(),
                    summary.duration_seconds.unwrap_or(0),
                    summary.finding_stats.total
                ));
            }
            csv
        }
    };

    // Output to file or stdout
    if let Some(path) = args.output {
        std::fs::write(&path, output)
            .map_err(|e| CliError::Other(format!("Failed to write file: {}", e)))?;
        println!("\n{} Scan summaries exported to {}", "✓".green().bold(), path.display());
    } else {
        println!("{}", output);
    }

    Ok(())
}

async fn export_projects(ctx: Context, args: ExportProjectsArgs) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);
    // For now, we'll export unique project IDs from scan summaries
    // In a full implementation, we might have a dedicated project storage
    let summaries = history
        .list_scan_summaries(None, 10000, 0)
        .await
        .map_err(|e| CliError::HistoryError(e.to_string()))?;

    // Extract unique project IDs
    let mut projects = HashMap::new();
    for summary in &summaries {
        if let Some(project_id) = &summary.project_id {
            projects.entry(project_id.clone()).or_insert_with(|| {
                ProjectInfo {
                    id: project_id.clone(),
                    name: format!("Project {}", project_id), // Placeholder
                    scan_count: 0,
                    last_scan: summary.created_at,
                }
            });
        }
    }

    // Update scan counts and last scan dates
    for summary in &summaries {
        if let Some(project_id) = &summary.project_id {
            if let Some(info) = projects.get_mut(project_id) {
                info.scan_count += 1;
                if summary.created_at > info.last_scan {
                    info.last_scan = summary.created_at;
                }
            }
        }
    }

    let project_list: Vec<ProjectInfo> = projects.into_values().collect();

    // Serialize based on format
    let output = match args.format {
        ExportFormat::Json => serde_json::to_string_pretty(&project_list)
            .map_err(|e| CliError::InvalidArgs(format!("Failed to serialize JSON: {}", e)))?,
        ExportFormat::Csv => {
            // Convert projects to CSV
            let mut csv = String::new();
            // Header
            csv.push_str("id,name,scan_count,last_scan\n");
            for project in &project_list {
                csv.push_str(&format!(
                    "\"{}\",\"{}\",{},\"{}\"\n",
                    project.id,
                    project.name.replace('"', "\"\""),
                    project.scan_count,
                    project.last_scan.to_rfc3339()
                ));
            }
            csv
        }
    };

    // Output to file or stdout
    if let Some(path) = args.output {
        std::fs::write(&path, output)
            .map_err(|e| CliError::Other(format!("Failed to write file: {}", e)))?;
        println!("\n{} Projects exported to {}", "✓".green().bold(), path.display());
    } else {
        println!("{}", output);
    }

    Ok(())
}

// Import functions
async fn import_findings(ctx: Context, args: ImportFindingsArgs) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);
    // Read the input file
    let data = std::fs::read_to_string(&args.input)
        .map_err(|e| CliError::Other(format!("Failed to read file: {}", e)))?;

    // Deserialize findings (try JSON first, then CSV if needed)
    let findings: Vec<Finding> = match args.input.extension().and_then(|s| s.to_str()).unwrap_or("")
    {
        "json" => serde_json::from_str(&data)
            .map_err(|e| CliError::InvalidArgs(format!("Failed to parse JSON: {}", e)))?,
        "csv" => {
            // Parse CSV findings manually
            let mut findings = Vec::new();
            let mut lines = data.lines();
            // Skip header
            let _header = lines.next();
            for line in lines {
                if line.trim().is_empty() {
                    continue;
                }
                // Simple CSV parsing - assumes no commas in quoted fields for simplicity
                let parts: Vec<String> =
                    line.splitn(7, ',').map(|s| s.trim().to_string()).collect();
                if parts.len() >= 7 {
                    let id = parts[0].trim_matches('"').to_string();
                    let title = parts[1].trim_matches('"').to_string();
                    let description = parts[2].trim_matches('"').to_string();
                    let severity = parts[3].to_string();
                    let confidence = parts[4].to_string();
                    let plugin_source = parts[5].trim_matches('"').to_string();
                    let location = if parts[6].is_empty() || parts[6] == "\"\"" {
                        None
                    } else {
                        Some(parts[6].trim_matches('"').to_string())
                    };

                    let record = CsvFindingRecord {
                        id,
                        title,
                        description,
                        severity,
                        confidence,
                        plugin_source,
                        location,
                    };
                    findings.push(record.into());
                }
            }
            findings
        }
        _ => {
            // Try JSON by default
            serde_json::from_str(&data)
                .map_err(|e| CliError::InvalidArgs(format!("Failed to parse JSON: {}", e)))?
        }
    };

    // Determine scan ID
    let scan_id = if let Some(scan_id_str) = args.scan_id {
        ScanId::from_uuid(
            uuid::Uuid::parse_str(&scan_id_str)
                .map_err(|e| CliError::InvalidArgs(format!("Invalid scan ID: {}", e)))?,
        )
    } else {
        // If no scan ID provided, we need to create a new scan summary or use an existing one?
        // For simplicity, we'll require a scan ID for import findings
        return Err(CliError::InvalidArgs(
            "Scan ID is required for importing findings (use --scan-id)".to_string(),
        ));
    };

    // Verify scan exists
    let scan_summary_opt = history
        .get_scan_summary(&scan_id)
        .await
        .map_err(|e| CliError::HistoryError(e.to_string()))?;

    if scan_summary_opt.is_none() {
        return Err(CliError::NotFound(format!("Scan not found: {}", scan_id)));
    }

    // Save findings as deduplicated findings for the scan
    history
        .save_deduplicated_findings(&scan_id, &findings)
        .await
        .map_err(|e| CliError::HistoryError(e.to_string()))?;

    // Update the scan summary with new finding stats
    // We'll need to update the finding_stats in the scan summary
    // For now, we'll just note that the findings have been imported
    println!("\n{} Imported {} findings for scan {}", "✓".green().bold(), findings.len(), scan_id);

    Ok(())
}

async fn import_scans(ctx: Context, args: ImportScansArgs) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);
    // Read the input file
    let data = std::fs::read_to_string(&args.input)
        .map_err(|e| CliError::Other(format!("Failed to read file: {}", e)))?;

    // Deserialize scan summaries (try JSON first, then CSV if needed)
    let summaries: Vec<ScanSummary> =
        match args.input.extension().and_then(|s| s.to_str()).unwrap_or("") {
            "json" => serde_json::from_str(&data)
                .map_err(|e| CliError::InvalidArgs(format!("Failed to parse JSON: {}", e)))?,
            "csv" => {
                // Parse CSV scan summaries manually
                let mut summaries = Vec::new();
                let mut lines = data.lines();
                // Skip header
                let _header = lines.next();
                for line in lines {
                    if line.trim().is_empty() {
                        continue;
                    }
                    // Simple CSV parsing - assumes no commas in quoted fields for simplicity
                    let parts: Vec<String> =
                        line.splitn(11, ',').map(|s| s.trim().to_string()).collect();
                    if parts.len() >= 11 {
                        let id = parts[0].trim_matches('"').to_string();
                        let project_id = if parts[1].is_empty() || parts[1] == "\"\"" {
                            None
                        } else {
                            Some(parts[1].trim_matches('"').to_string())
                        };
                        let target_id = parts[2].trim_matches('"').to_string();
                        let name = parts[3].trim_matches('"').to_string();
                        let description = if parts[4].is_empty() || parts[4] == "\"\"" {
                            None
                        } else {
                            Some(parts[4].trim_matches('"').to_string())
                        };
                        let status = parts[5].to_string();
                        let created_at = parts[6].to_string();
                        let started_at = if parts[7].is_empty() || parts[7] == "\"\"" {
                            None
                        } else {
                            Some(parts[7].to_string())
                        };
                        let completed_at = if parts[8].is_empty() || parts[8] == "\"\"" {
                            None
                        } else {
                            Some(parts[8].to_string())
                        };
                        let duration_seconds = if parts[9].is_empty() || parts[9] == "0" {
                            None
                        } else {
                            parts[9].parse().ok()
                        };
                        let finding_count = parts[10].parse().unwrap_or(0);

                        let record = CsvScanSummaryRecord {
                            id,
                            project_id,
                            target_id,
                            name,
                            description,
                            status,
                            created_at,
                            started_at,
                            completed_at,
                            duration_seconds,
                            finding_count,
                        };
                        summaries.push(record.into());
                    }
                }
                summaries
            }
            _ => {
                // Try JSON by default
                serde_json::from_str(&data)
                    .map_err(|e| CliError::InvalidArgs(format!("Failed to parse JSON: {}", e)))?
            }
        };

    // Import each scan summary
    for summary in &summaries {
        history
            .save_scan_summary(&summary)
            .await
            .map_err(|e| CliError::HistoryError(e.to_string()))?;
    }

    println!("\n{} Imported {} scan summaries", "✓".green().bold(), summaries.len());

    Ok(())
}

async fn import_projects(ctx: Context, args: ImportProjectsArgs) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);
    // For now, projects are derived from scan summaries, so importing projects
    // would mean importing scan summaries that contain those projects.
    // We'll delegate to import_scans for now.
    import_scans(ctx, ImportScansArgs { input: args.input }).await
}

// Helper structs for CSV export/import
#[derive(serde::Deserialize)]
struct CsvFindingRecord {
    id: String,
    title: String,
    description: String,
    severity: String,
    confidence: String,
    plugin_source: String,
    location: Option<String>,
}

impl From<CsvFindingRecord> for Finding {
    fn from(record: CsvFindingRecord) -> Self {
        Finding {
            id: openre_core::ids::FindingId::from_uuid(
                uuid::Uuid::parse_str(&record.id).unwrap_or_default(),
            ),
            title: record.title,
            description: record.description,
            severity: Severity::from_str(&record.severity).unwrap_or(Severity::Info),
            confidence: openre_core::result::Confidence::from_str(&record.confidence)
                .unwrap_or(openre_core::result::Confidence::Low),
            category: openre_core::result::Category::Configuration,
            target: String::new(),
            target_type: String::new(),
            evidence: record
                .location
                .map(|location| {
                    vec![openre_core::result::Evidence::new(
                        openre_core::result::EvidenceType::HttpRequest,
                        location,
                    )]
                })
                .unwrap_or_default(),
            references: Vec::new(),
            plugin_source: record.plugin_source,
            plugin_version: String::new(),
            timestamp: chrono::Utc::now(),
            scan_id: openre_core::ids::ScanId::from_uuid(uuid::Uuid::new_v4()),
            metadata: std::collections::HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: None,
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some(uuid::Uuid::new_v4().to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }
}

#[derive(serde::Deserialize)]
struct CsvScanSummaryRecord {
    id: String,
    project_id: Option<String>,
    target_id: String,
    name: String,
    description: Option<String>,
    status: String,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    duration_seconds: Option<u64>,
    finding_count: usize,
}

impl From<CsvScanSummaryRecord> for ScanSummary {
    fn from(record: CsvScanSummaryRecord) -> Self {
        ScanSummary {
            scan_id: ScanId::from_uuid(uuid::Uuid::parse_str(&record.id).unwrap_or_default()),
            project_id: record
                .project_id
                .map(|s| ProjectId::from_uuid(uuid::Uuid::parse_str(&s).unwrap_or_default())),
            target_id: openre_core::ids::TargetId::from_uuid(
                uuid::Uuid::parse_str(&record.target_id).unwrap_or_default(),
            ),
            name: record.name.clone(),
            description: record.description,
            status: record.status,
            config: openre_core::history::ScanConfigSummary {
                name: record.name,
                target_url: "".to_string(),
                plugins: Vec::new(),
                rate_limit: None,
                timeout_seconds: None,
                auth_configured: false,
                custom_headers_count: 0,
            },
            progress: ScanProgressSummary {
                total_endpoints: 0,
                endpoints_scanned: 0,
                endpoints_failed: 0,
                percentage: 0.0,
                completed_checks: Vec::new(),
            },
            finding_stats: openre_core::result::FindingStats {
                total: record.finding_count,
                by_severity: HashMap::new(),
                by_confidence: HashMap::new(),
                by_category: HashMap::new(),
                by_plugin: HashMap::new(),
                verified: 0,
                false_positives: 0,
                avg_risk_score: 0.0,
                max_risk_score: 0,
                by_owasp_category: HashMap::new(),
                by_cwe: HashMap::new(),
                avg_advanced_risk_score: 0.0,
                max_advanced_risk_score: 0,
                by_remediation_priority: HashMap::new(),
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
            plugin_executions: Vec::new(),
            created_at: chrono::DateTime::parse_from_rfc3339(&record.created_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            started_at: record.started_at.as_deref().map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now())
            }),
            completed_at: record.completed_at.as_deref().map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now())
            }),
            duration_seconds: record.duration_seconds,
            tags: Vec::new(),
        }
    }
}

// Helper struct for project export
#[derive(serde::Serialize)]
struct ProjectInfo {
    id: ProjectId,
    name: String,
    scan_count: usize,
    last_scan: chrono::DateTime<chrono::Utc>,
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

fn severity_color(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "red",
        Severity::High => "red",
        Severity::Medium => "yellow",
        Severity::Low => "green",
        Severity::Info => "blue",
    }
}

fn severity_meets_min(sev: &Severity, min_sev: &str) -> bool {
    let sev_str = sev.to_string().to_lowercase();
    let min_sev_lower = min_sev.to_lowercase();

    // Define severity levels in order of increasing severity
    let levels = vec!["info", "low", "medium", "high", "critical"];

    let sev_index = levels.iter().position(|&l| l == sev_str.as_str()).unwrap_or(0);
    let min_index = levels.iter().position(|&l| l == min_sev_lower.as_str()).unwrap_or(0);

    sev_index >= min_index
}

async fn pause_scan(ctx: Context, scan_id: &str) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);
    let scan_id_uuid = ScanId::from_uuid(
        uuid::Uuid::parse_str(scan_id)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid scan ID: {}", e)))?,
    );

    let mut summary = history
        .get_scan_summary(&scan_id_uuid)
        .await?
        .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", scan_id)))?;

    if summary.status != "running" {
        return Err(CliError::InvalidArgs(format!(
            "Cannot pause scan with status: {}",
            summary.status
        )));
    }

    summary.status = "paused".to_string();
    history.save_scan_summary(&summary).await?;

    println!("Scan {} paused", scan_id);
    Ok(())
}

async fn resume_scan(ctx: Context, scan_id: &str) -> Result<(), CliError> {
    let history = get_history_storage(&ctx);
    let scan_id_uuid = ScanId::from_uuid(
        uuid::Uuid::parse_str(scan_id)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid scan ID: {}", e)))?,
    );

    let mut summary = history
        .get_scan_summary(&scan_id_uuid)
        .await?
        .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", scan_id)))?;

    if summary.status != "paused" {
        return Err(CliError::InvalidArgs(format!(
            "Cannot resume scan with status: {}",
            summary.status
        )));
    }

    summary.status = "running".to_string();
    history.save_scan_summary(&summary).await?;

    println!("Scan {} resumed", scan_id);
    Ok(())
}
