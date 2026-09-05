//! Remediation guidance commands

use colored::Colorize;
use clap::{Args, Subcommand, ValueEnum};
use crate::intelligence_stubs::{
    Finding, RemediationEngine, RemediationPlan, RemediationReport, RemediationItem,
    Priority, Environment, ComplianceFramework, Language, GroupBy, VerificationResult,
};
use crate::{Context, CliError, print_output, OutputFormat};
use std::path::PathBuf;
use tabled::{Table, settings::Style};

#[derive(Subcommand, Debug)]
pub struct RemediateCommands {
    #[command(subcommand)]
    command: RemediateSubcommand,
}

#[derive(Subcommand, Debug)]
enum RemediateSubcommand {
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
struct PlanArgs {
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
struct QuickFixArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Language/framework
    #[arg(long, value_enum)]
    language: Option<LanguageArg>,
}

#[derive(Args, Debug)]
struct ReportArgs {
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
struct VerifyArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Target to verify against
    #[arg(long)]
    target: Option<String>,
}

#[derive(Debug, Clone, ValueEnum)]
enum EnvironmentArg {
    Development,
    Staging,
    Production,
    CiCd,
}

#[derive(Debug, Clone, ValueEnum)]
enum ComplianceArg {
    Owasp,
    PciDss,
    Hipaa,
    Gdpr,
    Soc2,
    Iso27001,
    Nist,
}

#[derive(Debug, Clone, ValueEnum)]
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

#[derive(Debug, Clone, ValueEnum)]
enum GroupByArg {
    Severity,
    Category,
    Component,
    Compliance,
}

impl RemediateCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self.command {
            RemediateSubcommand::Plan(args) => run_plan(ctx, args).await,
            RemediateSubcommand::QuickFix(args) => run_quick_fix(ctx, args).await,
            RemediateSubcommand::Report(args) => run_report(ctx, args).await,
            RemediateSubcommand::Verify(args) => run_verify(ctx, args).await,
        }
    }
}

async fn run_plan(ctx: Context, args: PlanArgs) -> Result<(), CliError> {
    let finding = load_finding(&args.finding)?;
    let engine = RemediationEngine::new();

    let spinner = ctx.spinner("Generating remediation plan...");
    let plan = engine.generate_plan(
        &finding,
        args.environment.into(),
        args.compliance.map(|c| c.into()),
    ).await?;
    spinner.finish_and_clear();

    println!("\n{}", "Remediation Plan".bold().cyan());
    println!("{}", "═".repeat(50).dimmed());
    println!("{}", plan.summary);
    println!();

    if !plan.steps.is_empty() {
        println!("{}", "Steps:".bold());
        for (i, step) in plan.steps.iter().enumerate() {
            let priority_icon = match step.priority {
                Priority::Critical => "🔴",
                Priority::High => "🟠",
                Priority::Medium => "🟡",
                Priority::Low => "🔵",
            };
            println!("  {}. {} {} {}", i + 1, priority_icon, step.title.bold(), format!("({})", step.effort).dimmed());
            println!("     {}", step.description);
            if let Some(code) = &step.code_example {
                println!("\n     {}:", "Example".bold());
                for line in code.lines() {
                    println!("       {}", line);
                }
            }
            println!();
        }
    }

    if let Some(refs) = &plan.references {
        println!("{}", "References:".bold());
        for r in refs {
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
    let engine = RemediationEngine::new();

    let spinner = ctx.spinner("Generating quick fix...");
    let fix = engine.quick_fix(&finding, args.language.map(|l| l.into())).await?;
    spinner.finish_and_clear();

    println!("\n{}", "Quick Fix".bold().green());
    println!("{}", "═".repeat(50).dimmed());
    println!("{}", fix.description);
    println!();

    if let Some(code) = fix.code {
        println!("{}", "Code:".bold());
        println!("{}", code);
    }

    if let Some(config) = fix.config {
        println!("\n{}", "Config:".bold());
        println!("{}", config);
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
    let findings = load_findings_from_path(&args.path)?;
    let engine = RemediationEngine::new();

    let spinner = ctx.spinner(format!("Generating remediation report for {} findings...", findings.len()));
    let report = engine.generate_report(&findings, args.group_by.into()).await?;
    spinner.finish_and_clear();

    println!("\n{}", "Remediation Report".bold().cyan());
    println!("{}", "═".repeat(50).dimmed());
    println!("Total Findings: {}", findings.len());
    println!("Estimated Effort: {}", report.total_effort);
    println!("Critical Path: {}", report.critical_path.join(" → "));
    println!();

    if ctx.format == OutputFormat::Table {
        for group in &report.groups {
            println!("\n{} ({})", group.name.bold(), group.count);
            let mut table = Table::new(
                group.items.iter().map(|i| RemediationItemRow {
                    finding: i.finding_title.clone(),
                    priority: format!("{:?}", i.priority),
                    effort: i.effort.clone(),
                    summary: i.summary.clone(),
                }).collect::<Vec<_>>()
            );
            table.with(Style::modern());
            println!("{}", table);
        }
    }

    if let Some(path) = args.output {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&path, json)?;
        println!("\n{} Saved to {}", "✓".green().bold(), path.display());
    }
    Ok(())
}

async fn run_verify(ctx: Context, args: VerifyArgs) -> Result<(), CliError> {
    let finding = load_finding(&args.finding)?;
    let engine = RemediationEngine::new();

    if let Some(target) = args.target {
        let spinner = ctx.spinner("Verifying remediation...");
        let result = engine.verify(&finding, &target).await?;
        spinner.finish_and_clear();

        if result.remediated {
            println!("{} Finding appears remediated!", "✓".green().bold());
        } else {
            println!("{} Finding NOT remediated", "✗".red().bold());
        }
        println!("  Evidence: {}", result.evidence);
    } else {
        println!("{} Target required for verification. Use --target <url>", "ℹ".blue());
    }
    Ok(())
}

fn load_finding(path: &str) -> Result<Finding, CliError> {
    if path.ends_with(".json") {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Err(CliError::InvalidArgs("Finding ID lookup not implemented. Use JSON file for now.".into()))
    }
}

fn load_findings_from_path(path: &PathBuf) -> Result<Vec<Finding>, CliError> {
    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
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

impl From<EnvironmentArg> for crate::intelligence_stubs::Environment {
    fn from(e: EnvironmentArg) -> Self {
        match e {
            EnvironmentArg::Development => crate::intelligence_stubs::Environment::Development,
            EnvironmentArg::Staging => crate::intelligence_stubs::Environment::Staging,
            EnvironmentArg::Production => crate::intelligence_stubs::Environment::Production,
            EnvironmentArg::CiCd => crate::intelligence_stubs::Environment::CiCd,
        }
    }
}

impl From<ComplianceArg> for crate::intelligence_stubs::ComplianceFramework {
    fn from(c: ComplianceArg) -> Self {
        match c {
            ComplianceArg::Owasp => crate::intelligence_stubs::ComplianceFramework::Owasp,
            ComplianceArg::PciDss => crate::intelligence_stubs::ComplianceFramework::PciDss,
            ComplianceArg::Hipaa => crate::intelligence_stubs::ComplianceFramework::Hipaa,
            ComplianceArg::Gdpr => crate::intelligence_stubs::ComplianceFramework::Gdpr,
            ComplianceArg::Soc2 => crate::intelligence_stubs::ComplianceFramework::Soc2,
            ComplianceArg::Iso27001 => crate::intelligence_stubs::ComplianceFramework::Iso27001,
            ComplianceArg::Nist => crate::intelligence_stubs::ComplianceFramework::Nist,
        }
    }
}

impl From<LanguageArg> for crate::intelligence_stubs::Language {
    fn from(l: LanguageArg) -> Self {
        match l {
            LanguageArg::Python => crate::intelligence_stubs::Language::Python,
            LanguageArg::Javascript => crate::intelligence_stubs::Language::JavaScript,
            LanguageArg::Typescript => crate::intelligence_stubs::Language::TypeScript,
            LanguageArg::Go => crate::intelligence_stubs::Language::Go,
            LanguageArg::Java => crate::intelligence_stubs::Language::Java,
            LanguageArg::Csharp => crate::intelligence_stubs::Language::CSharp,
            LanguageArg::Php => crate::intelligence_stubs::Language::Php,
            LanguageArg::Ruby => crate::intelligence_stubs::Language::Ruby,
            LanguageArg::Rust => crate::intelligence_stubs::Language::Rust,
        }
    }
}

impl From<GroupByArg> for crate::intelligence_stubs::GroupBy {
    fn from(g: GroupByArg) -> Self {
        match g {
            GroupByArg::Severity => crate::intelligence_stubs::GroupBy::Severity,
            GroupByArg::Category => crate::intelligence_stubs::GroupBy::Category,
            GroupByArg::Component => crate::intelligence_stubs::GroupBy::Component,
            GroupByArg::Compliance => crate::intelligence_stubs::GroupBy::Compliance,
        }
    }
}