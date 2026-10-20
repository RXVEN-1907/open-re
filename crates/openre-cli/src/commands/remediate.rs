//! Remediation guidance commands

use crate::context::Context;
use crate::error::CliError;
use crate::output::{print_output, OutputFormat};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::evidence::VerificationStatus;
use openre_core::result::{Finding, RemediationEffort, RemediationPriority, Severity};
use openre_intelligence::{KnowledgeBase, VerificationEngine};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tabled::{Style, Table, Tabled};

#[derive(Subcommand, Debug)]
pub enum RemediateCommands {
    /// Get remediation plan for a finding
    Plan(PlanArgs),
    /// Get quick fix for a finding
    QuickFix(QuickFixArgs),
    /// Generate remediation report for multiple findings
    Report(ReportArgs),
    /// Check if a finding has been remediated
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
pub(crate) struct PlanArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Target environment
    #[arg(long, value_enum, default_value = "production")]
    environment: EnvironmentArg,

    /// Compliance framework
    #[arg(long, value_enum)]
    compliance: Option<ComplianceArg>,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct QuickFixArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Language/framework
    #[arg(long, value_enum)]
    language: Option<LanguageArg>,
}

#[derive(Args, Debug)]
pub(crate) struct ReportArgs {
    /// Directory with findings (JSON files)
    path: PathBuf,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Group by
    #[arg(long, value_enum, default_value = "severity")]
    group_by: GroupByArg,
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Target to verify against
    #[arg(long)]
    target: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EnvironmentArg {
    Development,
    Staging,
    Production,
    CiCd,
}

impl EnvironmentArg {
    fn as_str(self) -> &'static str {
        match self {
            EnvironmentArg::Development => "development",
            EnvironmentArg::Staging => "staging",
            EnvironmentArg::Production => "production",
            EnvironmentArg::CiCd => "ci/cd",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ComplianceArg {
    Owasp,
    PciDss,
    Hipaa,
    Gdpr,
    Soc2,
    Iso27001,
    Nist,
}

impl ComplianceArg {
    fn as_str(self) -> &'static str {
        match self {
            ComplianceArg::Owasp => "OWASP Top 10",
            ComplianceArg::PciDss => "PCI DSS",
            ComplianceArg::Hipaa => "HIPAA",
            ComplianceArg::Gdpr => "GDPR",
            ComplianceArg::Soc2 => "SOC 2",
            ComplianceArg::Iso27001 => "ISO 27001",
            ComplianceArg::Nist => "NIST CSF",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LanguageArg {
    Python,
    Javascript,
    Typescript,
    Go,
    Java,
    Csharp,
    Php,
    Ruby,
    Rust,
}

impl LanguageArg {
    fn as_str(self) -> &'static str {
        match self {
            LanguageArg::Python => "python",
            LanguageArg::Javascript => "javascript",
            LanguageArg::Typescript => "typescript",
            LanguageArg::Go => "go",
            LanguageArg::Java => "java",
            LanguageArg::Csharp => "csharp",
            LanguageArg::Php => "php",
            LanguageArg::Ruby => "ruby",
            LanguageArg::Rust => "rust",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GroupByArg {
    Severity,
    Category,
    Component,
    Compliance,
}

impl RemediateCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            RemediateCommands::Plan(args) => run_plan(ctx, args).await,
            RemediateCommands::QuickFix(args) => run_quick_fix(ctx, args).await,
            RemediateCommands::Report(args) => run_report(ctx, args).await,
            RemediateCommands::Verify(args) => run_verify(ctx, args).await,
        }
    }
}

/// Priority derived from severity when the finding carries no explicit priority.
fn priority_from_severity(severity: Severity) -> RemediationPriority {
    match severity {
        Severity::Critical => RemediationPriority::Immediate,
        Severity::High => RemediationPriority::High,
        Severity::Medium => RemediationPriority::Medium,
        Severity::Low | Severity::Info => RemediationPriority::Low,
    }
}

fn effort_label(effort: Option<RemediationEffort>) -> String {
    match effort {
        Some(RemediationEffort::Trivial) => "trivial".to_string(),
        Some(RemediationEffort::Low) => "low".to_string(),
        Some(RemediationEffort::Medium) => "medium".to_string(),
        Some(RemediationEffort::High) => "high".to_string(),
        Some(RemediationEffort::VeryHigh) => "very high".to_string(),
        None => "unestimated".to_string(),
    }
}

async fn run_plan(ctx: Context, args: PlanArgs) -> Result<(), CliError> {
    let mut finding = load_finding(&args.finding)?;

    let spinner = ctx.spinner("Generating remediation plan...");
    // Knowledge base enrichment adds CWE/CAPEC references and OWASP mapping.
    let kb = KnowledgeBase::new();
    let _kb_entry = kb.enrich_single_finding(&mut finding)?;
    spinner.finish_and_clear();

    let guidance = finding.remediation.clone();
    let priority = guidance
        .as_ref()
        .map(|g| g.priority)
        .unwrap_or_else(|| priority_from_severity(finding.severity));

    let plan = RemediationPlan {
        title: finding.title.clone(),
        severity: format!("{:?}", finding.severity),
        priority: format!("{:?}", priority),
        environment: args.environment.as_str().to_string(),
        compliance: args.compliance.map(|c| c.as_str().to_string()),
        summary: guidance.as_ref().map(|g| g.summary.clone()).unwrap_or_else(|| {
            format!("Remediate {:?} finding on {}", finding.category, finding.target)
        }),
        steps: guidance.as_ref().map(|g| g.steps.clone()).unwrap_or_else(|| {
            vec![
                format!("Reproduce the finding on {} using the recorded evidence", finding.target),
                format!(
                    "Apply the fix for {:?} (CWE: {})",
                    finding.category,
                    if finding.cwe_ids.is_empty() {
                        "unmapped".to_string()
                    } else {
                        finding.cwe_ids.join(", ")
                    }
                ),
                format!("Re-scan {} and confirm the finding no longer fires", finding.target),
            ]
        }),
        code_examples: guidance
            .as_ref()
            .map(|g| {
                g.code_examples
                    .iter()
                    .map(|c| {
                        format!(
                            "Language: {}\nVulnerable:\n{}\nFixed:\n{}\n{}",
                            c.language, c.vulnerable, c.fixed, c.explanation
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        effort: guidance
            .as_ref()
            .map(|g| effort_label(Some(g.effort)))
            .unwrap_or_else(|| effort_label(None)),
        references: finding.references.iter().map(|r| format!("{}: {}", r.title, r.url)).collect(),
    };

    println!("\n{}", "Remediation Plan".bold().cyan());
    println!("{}", "═".repeat(50).dimmed());
    println!("{} (severity {}, priority {})", plan.title.bold(), plan.severity, plan.priority);
    println!("Environment: {}", plan.environment);
    if let Some(compliance) = &plan.compliance {
        println!("Compliance lens: {}", compliance);
    }
    println!("Estimated effort: {}", plan.effort);
    println!();
    println!("{}", plan.summary);
    println!();

    if !plan.steps.is_empty() {
        println!("{}", "Steps:".bold());
        for (i, step) in plan.steps.iter().enumerate() {
            let priority_icon = match priority {
                RemediationPriority::Immediate => "🔴",
                RemediationPriority::High => "🟠",
                RemediationPriority::Medium => "🟡",
                RemediationPriority::Low | RemediationPriority::Deferred => "🔵",
            };
            println!("  {}. {} {}", i + 1, priority_icon, step);
        }
        println!();
    }

    if !plan.code_examples.is_empty() {
        println!("{}", "Examples:".bold());
        for example in &plan.code_examples {
            println!("{}", "─".repeat(40).dimmed());
            for line in example.lines() {
                println!("  {}", line);
            }
        }
        println!();
    }

    if !plan.references.is_empty() {
        println!("{}", "References:".bold());
        for r in &plan.references {
            println!("  • {}", r);
        }
    }

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&plan)?;
        std::fs::write(&path, json)?;
        println!("\n{} Saved to {}", "✓".green().bold(), path.display());
    }
    Ok(())
}

async fn run_quick_fix(ctx: Context, args: QuickFixArgs) -> Result<(), CliError> {
    let finding = load_finding(&args.finding)?;

    let spinner = ctx.spinner("Generating quick fix...");
    let kb = KnowledgeBase::new();
    let mut enriched = finding.clone();
    let _ = kb.enrich_single_finding(&mut enriched);
    spinner.finish_and_clear();

    let guidance = finding.remediation.clone();
    let fix = QuickFix {
        description: guidance.as_ref().map(|g| g.summary.clone()).unwrap_or_else(|| {
            format!("Apply the {:?} fix on {}", finding.category, finding.target)
        }),
        code: guidance
            .as_ref()
            .and_then(|g| {
                g.code_examples
                    .iter()
                    .find(|c| match &args.language {
                        Some(lang) => c.language.eq_ignore_ascii_case(lang.as_str()),
                        None => true,
                    })
                    .map(|c| c.fixed.clone())
            })
            .or_else(|| {
                // Fall back to the vulnerable/fixed pair of the first example.
                finding
                    .remediation
                    .as_ref()
                    .and_then(|g| g.code_examples.first().map(|c| c.fixed.clone()))
            }),
        commands: None,
    };

    println!("\n{}", "Quick Fix".bold().green());
    println!("{}", "═".repeat(50).dimmed());
    println!("{}", fix.description);
    println!();

    if let Some(code) = fix.code {
        println!("{}", "Code:".bold());
        println!("{}", code);
    } else {
        println!(
            "{} No code example attached to this finding. Run `openre remediate plan` for the full plan.",
            "ℹ".blue()
        );
    }

    if let Some(commands) = fix.commands {
        println!("\n{}", "Commands:".bold());
        for cmd in commands {
            println!("  $ {}", cmd);
        }
    }
    Ok(())
}

async fn run_report(ctx: Context, args: ReportArgs) -> Result<(), CliError> {
    let mut findings = load_findings_from_path(&args.path)?;

    let kb = KnowledgeBase::new();
    let _ = kb.enrich_findings(&mut findings);

    let spinner =
        ctx.spinner(format!("Generating remediation report for {} findings...", findings.len()));
    let report = build_report(&findings, args.group_by);
    spinner.finish_and_clear();

    println!("\n{}", "Remediation Report".bold().cyan());
    println!("{}", "═".repeat(50).dimmed());
    println!("Total Findings: {}", report.total);
    println!("Estimated Effort: {}", report.total_effort);
    println!("Critical Path: {}", report.critical_path.join(" → "));
    println!();

    if ctx.format == OutputFormat::Table {
        for group in &report.groups {
            println!("\n{} ({})", group.name.bold(), group.count);
            let mut table = Table::new(
                group
                    .items
                    .iter()
                    .map(|i| RemediationItemRow {
                        finding: i.finding_title.clone(),
                        priority: i.priority.clone(),
                        effort: i.effort.clone(),
                        summary: i.summary.clone(),
                    })
                    .collect::<Vec<_>>(),
            );
            table.with(Style::modern());
            println!("{}", table);
        }
    } else {
        print_output(&report, ctx.format, args.output.as_deref())?;
        return Ok(());
    }

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&path, json)?;
        println!("\n{} Saved to {}", "✓".green().bold(), path.display());
    }
    Ok(())
}

async fn run_verify(ctx: Context, args: VerifyArgs) -> Result<(), CliError> {
    let mut finding = load_finding(&args.finding)?;

    let Some(target) = args.target.or_else(|| {
        if finding.target.is_empty() {
            None
        } else {
            Some(finding.target.clone())
        }
    }) else {
        println!("{} Target required for verification. Use --target <url>", "ℹ".blue());
        return Ok(());
    };
    finding.target = target;

    let engine = VerificationEngine::new();
    let spinner = ctx.spinner("Verifying remediation...");
    let result = engine.verify_finding(&finding).await;
    spinner.finish_and_clear();
    let result = result?;

    match result.status {
        VerificationStatus::Confirmed | VerificationStatus::Likely => {
            println!(
                "{} Finding still reproduces on {} — NOT remediated",
                "✗".red().bold(),
                finding.target
            );
        }
        VerificationStatus::NotReproducible => {
            println!("{} Finding no longer reproduces — appears remediated", "✓".green().bold());
        }
        VerificationStatus::Unconfirmed
        | VerificationStatus::Error
        | VerificationStatus::Skipped => {
            println!(
                "{} Could not determine remediation state on {}",
                "⚠".yellow().bold(),
                finding.target
            );
        }
    }
    println!("  Status: {:?} (confidence {:.0}%)", result.status, result.confidence * 100.0);
    if !result.notes.is_empty() {
        println!("  Notes: {}", result.notes);
    }
    Ok(())
}

fn build_report(findings: &[Finding], group_by: GroupByArg) -> RemediationReport {
    let mut groups_map: HashMap<String, Vec<&Finding>> = HashMap::new();
    for finding in findings {
        let key = match group_by {
            GroupByArg::Severity => format!("{:?}", finding.severity),
            GroupByArg::Category => format!("{:?}", finding.category),
            GroupByArg::Component => finding.target.clone(),
            GroupByArg::Compliance => {
                finding.owasp_category.clone().unwrap_or_else(|| "unmapped".to_string())
            }
        };
        groups_map.entry(key).or_default().push(finding);
    }

    let mut groups: Vec<RemediationGroup> = groups_map
        .into_iter()
        .map(|(name, items)| {
            let count = items.len();
            RemediationGroup {
                name,
                count,
                items: items
                    .into_iter()
                    .map(|f| RemediationItem {
                        finding_title: f.title.clone(),
                        priority: format!("{:?}", priority_from_severity(f.severity)),
                        effort: effort_label(f.remediation.as_ref().map(|g| g.effort)),
                        summary: f.remediation.as_ref().map(|g| g.summary.clone()).unwrap_or_else(
                            || f.description.lines().next().unwrap_or("").to_string(),
                        ),
                    })
                    .collect(),
            }
        })
        .collect();
    groups.sort_by_key(|g| std::cmp::Reverse(g.count));

    let estimated = findings.iter().filter(|f| f.remediation.is_some()).count();
    let critical_path: Vec<String> = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .map(|f| f.title.clone())
        .take(10)
        .collect();

    RemediationReport {
        total: findings.len(),
        groups,
        total_effort: format!("{}/{} findings carry an effort estimate", estimated, findings.len()),
        critical_path,
    }
}

fn load_finding(path: &str) -> Result<Finding, CliError> {
    if path.ends_with(".json") {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Err(CliError::InvalidArgs(
            "Finding ID lookup not implemented. Use JSON file for now.".into(),
        ))
    }
}

fn load_findings_from_path(path: &Path) -> Result<Vec<Finding>, CliError> {
    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
        let content = std::fs::read_to_string(path)?;
        Ok(vec![serde_json::from_str(&content)?])
    } else if path.is_dir() {
        let mut findings = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = std::fs::read_to_string(entry.path())?;
                if let Ok(f) = serde_json::from_str::<Finding>(&content) {
                    findings.push(f);
                }
            }
        }
        Ok(findings)
    } else {
        Err(CliError::InvalidArgs("Path must be a JSON file or directory".into()))
    }
}

#[derive(serde::Serialize)]
struct RemediationPlan {
    title: String,
    severity: String,
    priority: String,
    environment: String,
    compliance: Option<String>,
    summary: String,
    steps: Vec<String>,
    code_examples: Vec<String>,
    effort: String,
    references: Vec<String>,
}

#[derive(serde::Serialize)]
struct QuickFix {
    description: String,
    code: Option<String>,
    commands: Option<Vec<String>>,
}

#[derive(serde::Serialize)]
struct RemediationReport {
    total: usize,
    groups: Vec<RemediationGroup>,
    total_effort: String,
    critical_path: Vec<String>,
}

#[derive(serde::Serialize)]
struct RemediationGroup {
    name: String,
    count: usize,
    items: Vec<RemediationItem>,
}

#[derive(serde::Serialize)]
struct RemediationItem {
    finding_title: String,
    priority: String,
    effort: String,
    summary: String,
}

#[derive(tabled::Tabled)]
struct RemediationItemRow {
    #[tabled(rename = "FINDING")]
    finding: String,
    #[tabled(rename = "PRIORITY")]
    priority: String,
    #[tabled(rename = "EFFORT")]
    effort: String,
    #[tabled(rename = "SUMMARY")]
    summary: String,
}
