//! AI-powered analysis commands

use colored::Colorize;
use clap::{Args, Subcommand, ValueEnum};
use crate::ai_stubs::{AiProvider, AiClient, AnalysisRequest, AnalysisType, ExplainDetail, Audience, FixType, ConnectionTestResult, ProviderInfo};
use crate::intelligence_stubs::{CorrelationEngine, Finding};
use crate::{Context, CliError, print_output, OutputFormat};
use std::path::PathBuf;
use tabled::{Table, settings::Style};

#[derive(Subcommand, Debug)]
pub struct AiCommands {
    #[command(subcommand)]
    command: AiSubcommand,
}

#[derive(Subcommand, Debug)]
enum AiSubcommand {
    /// Chat with AI assistant
    Chat(ChatArgs),
    /// Analyze a finding with AI
    Analyze(AnalyzeArgs),
    /// Explain a vulnerability/finding
    Explain(ExplainArgs),
    /// Generate remediation guidance
    Remediate(RemediateArgs),
    /// Correlate findings across scans
    Correlate(CorrelateArgs),
    /// List available AI providers/models
    Providers,
    /// Test AI connection
    Test(TestArgs),
}

#[derive(Args, Debug)]
struct ChatArgs {
    /// Message to send (if not provided, starts interactive chat)
    message: Option<String>,

    /// System prompt
    #[arg(long)]
    system: Option<String>,

    /// Temperature
    #[arg(long, default_value = "0.7")]
    temperature: f32,

    /// Max tokens
    #[arg(long)]
    max_tokens: Option<u32>,
}

#[derive(Args, Debug)]
struct AnalyzeArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Additional context
    #[arg(long)]
    context: Option<String>,
}

#[derive(Args, Debug)]
struct ExplainArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Detail level
    #[arg(long, value_enum, default_value = "standard")]
    detail: crate::ai_stubs::ExplainDetail,

    /// Target audience
    #[arg(long, value_enum, default_value = "developer")]
    audience: crate::ai_stubs::Audience,
}

#[derive(Debug, Clone, ValueEnum)]
enum ExplainDetailArg {
    Brief,
    Standard,
    Deep,
}

#[derive(Debug, Clone, ValueEnum)]
enum AudienceArg {
    Developer,
    SecurityTeam,
    Management,
    Executive,
}

#[derive(Args, Debug)]
struct RemediateArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Preferred fix type
    #[arg(long, value_enum, default_value = "code")]
    fix_type: crate::ai_stubs::FixType,

    /// Language/framework context
    #[arg(long)]
    language: Option<String>,
}

#[derive(Debug, Clone, ValueEnum)]
enum FixTypeArg {
    Code,
    Config,
    Architecture,
    Process,
}

#[derive(Args, Debug)]
struct CorrelateArgs {
    /// Project directory or scan results directory
    path: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value = "table")]
    format: OutputFormat,

    /// Minimum confidence
    #[arg(long, default_value = "0.5")]
    min_confidence: f32,
}

#[derive(Args, Debug)]
struct TestArgs {
    /// Provider to test
    #[arg(long, value_enum)]
    provider: Option<crate::ai_stubs::AiProvider>,

    /// Model to test
    #[arg(long)]
    model: Option<String>,
}

impl AiCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        if ctx.no_ai {
            return Err(CliError::InvalidArgs("AI features disabled with --no-ai".into()));
        }

        match self.command {
            AiSubcommand::Chat(args) => run_chat(ctx, args).await,
            AiSubcommand::Analyze(args) => run_analyze(ctx, args).await,
            AiSubcommand::Explain(args) => run_explain(ctx, args).await,
            AiSubcommand::Remediate(args) => run_remediate(ctx, args).await,
            AiSubcommand::Correlate(args) => run_correlate(ctx, args).await,
            AiSubcommand::Providers => run_providers(ctx).await,
            AiSubcommand::Test(args) => run_test(ctx, args).await,
        }
    }
}

async fn run_chat(ctx: Context, args: ChatArgs) -> Result<(), CliError> {
    let client = ctx.ai_client()?;

    if let Some(msg) = args.message {
        // Single message mode
        let response = client.chat(&msg, args.system.as_deref(), args.temperature, args.max_tokens).await?;
        println!("{}", response);
    } else {
        // Interactive chat mode
        println!("{}", "openre AI Chat (type 'exit' to quit)".bold().cyan());
        println!("{}", "─".repeat(50).dimmed());

        loop {
            let input = dialoguer::Input::<String>::new()
                .with_prompt("You")
                .allow_empty(false)
                .interact_text()?;

            if input.trim().eq_ignore_ascii_case("exit") {
                break;
            }

            let spinner = ctx.spinner("Thinking...");
            let response = client.chat(&input, args.system.as_deref(), args.temperature, args.max_tokens).await?;
            spinner.finish_and_clear();

            println!("{} {}", "AI".bold().green(), response);
            println!();
        }
    }
    Ok(())
}

async fn run_analyze(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let client = ctx.ai_client()?;
    let finding = load_finding(&args.finding)?;

    let spinner = ctx.spinner("Analyzing with AI...");
    let request = AnalysisRequest {
        finding: finding.clone(),
        analysis_type: crate::ai_stubs::AnalysisType::FullAnalysis,
        context: args.context,
    };
    let result: crate::ai_stubs::AnalysisResult = client.analyze(request).await?;
    spinner.finish_and_clear();

    print_output(&result, ctx.format, None)?;
    Ok(())
}

async fn run_explain(ctx: Context, args: ExplainArgs) -> Result<(), CliError> {
    let client = ctx.ai_client()?;
    let finding = load_finding(&args.finding)?;

    let spinner = ctx.spinner("Generating explanation...");
    let explanation = client.explain(&finding, args.detail.into(), args.audience.into()).await?;
    spinner.finish_and_clear();

    println!("\n{}", explanation);
    Ok(())
}

async fn run_remediate(ctx: Context, args: RemediateArgs) -> Result<(), CliError> {
    let client = ctx.ai_client()?;
    let finding = load_finding(&args.finding)?;

    let spinner = ctx.spinner("Generating remediation guidance...");
    let remediation = client.remediate(&finding, args.fix_type.into(), args.language.as_deref()).await?;
    spinner.finish_and_clear();

    println!("\n{}", remediation);
    Ok(())
}

async fn run_correlate(ctx: Context, args: CorrelateArgs) -> Result<(), CliError> {
    let client = ctx.ai_client()?;
    let engine = CorrelationEngine::new();

    let spinner = ctx.spinner("Correlating findings...");
    let findings = load_findings_from_path(&args.path)?;
    let correlations = engine.correlate(&findings).await?;
    spinner.finish_and_clear();

    if correlations.is_empty() {
        println!("{} No correlations found", "ℹ".blue());
        return Ok(());
    }

    if args.format == OutputFormat::Table {
        let mut table = Table::new(
            correlations.iter().map(|c| CorrelationRow {
                finding_a: c.finding_a.title.clone(),
                finding_b: c.finding_b.title.clone(),
                correlation_type: format!("{:?}", c.correlation_type),
                confidence: format!("{:.0}%", c.confidence * 100.0),
                description: c.description.clone(),
            }).collect::<Vec<_>>()
        );
        table.with(Style::modern());
        println!("{}", table);
    } else {
        print_output(&correlations, args.format, None)?;
    }
    Ok(())
}

async fn run_providers(ctx: Context) -> Result<(), CliError> {
    let client = ctx.ai_client()?;
    let providers = client.list_providers().await?;

    println!("\n{}", "Available AI Providers:".bold().cyan());
    for p in providers {
        let status = if p.available { "✓".green() } else { "✗".red() };
        println!("  {} {} ({})", status, p.name.bold(), p.provider_type);
        for m in &p.models {
            println!("    • {}", m);
        }
    }
    Ok(())
}

async fn run_test(ctx: Context, args: TestArgs) -> Result<(), CliError> {
    let client = ctx.ai_client()?;

    let spinner = ctx.spinner("Testing AI connection...");
    let result = client.test_connection(args.provider, args.model.as_deref()).await?;
    spinner.finish_and_clear();

    if result.success {
        println!("{} Connection successful!", "✓".green().bold());
        println!("  Provider: {}", result.provider);
        println!("  Model: {}", result.model);
        println!("  Latency: {:.0}ms", result.latency_ms);
    } else {
        println!("{} Connection failed: {}", "✗".red().bold(), result.error.unwrap_or_default());
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
struct CorrelationRow {
    #[tabled(rename = "FINDING A")]
    finding_a: String,
    #[tabled(rename = "FINDING B")]
    finding_b: String,
    #[tabled(rename = "TYPE")]
    correlation_type: String,
    #[tabled(rename = "CONFIDENCE")]
    confidence: String,
    #[tabled(rename = "DESCRIPTION")]
    description: String,
}


impl From<ExplainDetailArg> for crate::ai_stubs::ExplainDetail {
    fn from(d: ExplainDetailArg) -> Self {
        match d {
            ExplainDetailArg::Brief => crate::ai_stubs::ExplainDetail::Brief,
            ExplainDetailArg::Standard => crate::ai_stubs::ExplainDetail::Standard,
            ExplainDetailArg::Deep => crate::ai_stubs::ExplainDetail::Deep,
        }
    }
}

impl From<AudienceArg> for crate::ai_stubs::Audience {
    fn from(a: AudienceArg) -> Self {
        match a {
            AudienceArg::Developer => crate::ai_stubs::Audience::Developer,
            AudienceArg::SecurityTeam => crate::ai_stubs::Audience::SecurityTeam,
            AudienceArg::Management => crate::ai_stubs::Audience::Management,
            AudienceArg::Executive => crate::ai_stubs::Audience::Executive,
        }
    }
}

impl From<FixTypeArg> for crate::ai_stubs::FixType {
    fn from(f: FixTypeArg) -> Self {
        match f {
            FixTypeArg::Code => crate::ai_stubs::FixType::Code,
            FixTypeArg::Config => crate::ai_stubs::FixType::Config,
            FixTypeArg::Architecture => crate::ai_stubs::FixType::Architecture,
            FixTypeArg::Process => crate::ai_stubs::FixType::Process,
        }
    }
}

