//! AI-powered analysis commands

use crate::context::Context;
use crate::error::CliError;
use crate::output::{print_output, OutputFormat};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_ai::providers::{CompletionRequest, Message, MessageRole};
use openre_core::result::Finding;
use openre_intelligence::CorrelationEngine;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use tabled::{Style, Table, Tabled};

#[derive(Subcommand, Debug)]
pub enum AiCommands {
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
pub(crate) struct ChatArgs {
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
pub(crate) struct AnalyzeArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Additional context
    #[arg(long)]
    context: Option<String>,

    /// Enable ultrathink mode (maximum thinking budget)
    #[arg(long)]
    ultrathink: bool,
}

#[derive(Args, Debug)]
pub(crate) struct ExplainArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Detail level
    #[arg(long, value_enum, default_value = "standard")]
    detail: DetailArg,

    /// Target audience
    #[arg(long, value_enum, default_value = "developer")]
    audience: AudienceArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DetailArg {
    Brief,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AudienceArg {
    Developer,
    SecurityTeam,
    Management,
    Executive,
}

#[derive(Args, Debug)]
pub(crate) struct RemediateArgs {
    /// Finding ID or JSON file with finding
    finding: String,

    /// Preferred fix type
    #[arg(long, value_enum, default_value = "code")]
    fix_type: FixTypeArg,

    /// Language/framework context
    #[arg(long)]
    language: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FixTypeArg {
    Code,
    Config,
    Architecture,
    Process,
}

#[derive(Args, Debug)]
pub(crate) struct CorrelateArgs {
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
pub(crate) struct TestArgs {
    /// Provider type to test (e.g. openai, anthropic, vllm)
    #[arg(long)]
    provider: Option<String>,

    /// Model to test
    #[arg(long)]
    model: Option<String>,
}

impl AiCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        if ctx.no_ai {
            return Err(CliError::InvalidArgs("AI features disabled with --no-ai".into()));
        }

        match self {
            AiCommands::Chat(args) => run_chat(&ctx, args).await,
            AiCommands::Analyze(args) => run_analyze(&ctx, args).await,
            AiCommands::Explain(args) => run_explain(&ctx, args).await,
            AiCommands::Remediate(args) => run_remediate(&ctx, args).await,
            AiCommands::Correlate(args) => run_correlate(&ctx, args).await,
            AiCommands::Providers => run_providers(&ctx).await,
            AiCommands::Test(args) => run_test(&ctx, args).await,
        }
    }
}

fn completion_request(
    system: Option<&str>,
    user: &str,
    temperature: f32,
    max_tokens: Option<u32>,
) -> CompletionRequest {
    let mut messages = Vec::new();
    if let Some(system) = system {
        messages.push(Message {
            role: MessageRole::System,
            content: Some(system.to_string()),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        });
    }
    messages.push(Message {
        role: MessageRole::User,
        content: Some(user.to_string()),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });
    CompletionRequest {
        messages,
        tools: None,
        tool_choice: None,
        temperature: Some(temperature),
        max_tokens,
        top_p: None,
        stop: None,
        response_format: None,
        stream: false,
        metadata: HashMap::new(),
    }
}

fn response_text(response: &openre_ai::providers::CompletionResponse) -> String {
    response.choices.first().and_then(|c| c.message.content.clone()).unwrap_or_default()
}

async fn run_chat(ctx: &Context, args: ChatArgs) -> Result<(), CliError> {
    let client = ctx.ai_client().await?;

    if let Some(msg) = args.message {
        // Single message mode
        let request =
            completion_request(args.system.as_deref(), &msg, args.temperature, args.max_tokens);
        let response = client.complete(request).await?;
        println!("{}", response_text(&response));
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
            let request = completion_request(
                args.system.as_deref(),
                &input,
                args.temperature,
                args.max_tokens,
            );
            let response = client.complete(request).await;
            spinner.finish_and_clear();
            let response = response?;

            println!("{} {}", "AI".bold().green(), response_text(&response));
            println!();
        }
    }
    Ok(())
}

fn finding_prompt(finding: &Finding, task: &str, extras: &[(String, String)]) -> String {
    let mut prompt = format!(
        "{}\n\nFinding:\n- Title: {}\n- Severity: {:?}\n- Category: {:?}\n- Target: {}\n- Description: {}\n- CWEs: {}\n- CAPECs: {}\n- OWASP: {}\n",
        task,
        finding.title,
        finding.severity,
        finding.category,
        finding.target,
        finding.description,
        if finding.cwe_ids.is_empty() { "-".to_string() } else { finding.cwe_ids.join(", ") },
        if finding.capec_ids.is_empty() { "-".to_string() } else { finding.capec_ids.join(", ") },
        finding.owasp_category.clone().unwrap_or_else(|| "-".to_string()),
    );
    for (label, value) in extras {
        prompt.push_str(&format!("- {}: {}\n", label, value));
    }
    prompt
}

async fn run_analyze(ctx: &Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let client = ctx.ai_client().await?;
    let finding = load_finding(&args.finding)?;

    let mut extras: Vec<(String, String)> = vec![(
        "Analysis depth".to_string(),
        if args.ultrathink { "maximum thinking budget" } else { "standard" }.to_string(),
    )];
    if let Some(context) = &args.context {
        extras.push(("Additional context".to_string(), context.clone()));
    }
    let request = completion_request(
        Some("You are a security analyst. Analyze the finding for exploitability, impact, and false-positive indicators. Be concrete."),
        &finding_prompt(&finding, "Analyze the following security finding.", &extras),
        0.3,
        None,
    );

    let spinner = ctx.spinner("Analyzing with AI...");
    let response = client.complete(request).await;
    spinner.finish_and_clear();
    let response = response?;

    let analysis = AiAnalysis {
        summary: response_text(&response),
        model: response.model.clone(),
        finding_title: finding.title.clone(),
    };
    print_output(&analysis, ctx.format, None)?;
    Ok(())
}

async fn run_explain(ctx: &Context, args: ExplainArgs) -> Result<(), CliError> {
    let client = ctx.ai_client().await?;
    let finding = load_finding(&args.finding)?;

    let extras = vec![
        ("Detail level".to_string(), format!("{:?}", args.detail)),
        ("Audience".to_string(), format!("{:?}", args.audience)),
    ];
    let task = match args.audience {
        AudienceArg::Executive | AudienceArg::Management => {
            "Explain the business risk of the following security finding in plain language."
        }
        _ => "Explain the following security finding technically: root cause, exploitation path, and impact.",
    };
    let request = completion_request(
        Some("You are a security educator. Adapt depth to the requested audience."),
        &finding_prompt(&finding, task, &extras),
        0.5,
        None,
    );

    let spinner = ctx.spinner("Generating explanation...");
    let response = client.complete(request).await;
    spinner.finish_and_clear();
    let response = response?;

    println!("\n{}", response_text(&response));
    Ok(())
}

async fn run_remediate(ctx: &Context, args: RemediateArgs) -> Result<(), CliError> {
    let client = ctx.ai_client().await?;
    let finding = load_finding(&args.finding)?;

    let mut extras = vec![("Fix type".to_string(), format!("{:?}", args.fix_type))];
    if let Some(language) = &args.language {
        extras.push(("Language/framework".to_string(), language.clone()));
    }
    let request = completion_request(
        Some("You are a remediation engineer. Provide actionable, testable fixes with code where applicable."),
        &finding_prompt(&finding, "Provide remediation guidance for the following finding.", &extras),
        0.3,
        None,
    );

    let spinner = ctx.spinner("Generating remediation guidance...");
    let response = client.complete(request).await;
    spinner.finish_and_clear();
    let response = response?;

    println!("\n{}", response_text(&response));
    Ok(())
}

async fn run_correlate(ctx: &Context, args: CorrelateArgs) -> Result<(), CliError> {
    let engine = CorrelationEngine::new();

    let spinner = ctx.spinner("Correlate findings...");
    let findings = load_findings_from_path(&args.path)?;
    let relationships = engine.correlate_findings(&findings).await?;
    spinner.finish_and_clear();

    let titles: HashMap<String, String> =
        findings.iter().map(|f| (f.id.to_string(), f.title.clone())).collect();

    let rows: Vec<CorrelationRow> = relationships
        .iter()
        .filter(|r| r.confidence >= args.min_confidence)
        .map(|r| CorrelationRow {
            source: titles
                .get(&r.source_finding.to_string())
                .cloned()
                .unwrap_or_else(|| r.source_finding.to_string()),
            target: titles
                .get(&r.target_finding.to_string())
                .cloned()
                .unwrap_or_else(|| r.target_finding.to_string()),
            relationship_type: format!("{:?}", r.relationship_type),
            confidence: format!("{:.0}%", r.confidence * 100.0),
            description: r.explanation.clone(),
        })
        .collect();

    if rows.is_empty() {
        println!("{} No correlations found", "ℹ".blue());
        return Ok(());
    }

    if args.format == OutputFormat::Table {
        let mut table = Table::new(rows);
        table.with(Style::modern());
        println!("{}", table);
    } else {
        let correlated: Vec<openre_core::relationships::FindingRelationship> =
            relationships.into_iter().filter(|r| r.confidence >= args.min_confidence).collect();
        print_output(&correlated, args.format, None)?;
    }
    Ok(())
}

async fn run_providers(ctx: &Context) -> Result<(), CliError> {
    let client = ctx.ai_client().await?;
    let health = client.health_check().await;

    println!("\n{}", "Registered AI Providers:".bold().cyan());
    let ids = client.list_provider_ids();
    if ids.is_empty() {
        println!(
            "  {} No providers registered. Set API keys (e.g. OPENAI_API_KEY) or allowed providers in config.",
            "✗".red()
        );
        return Ok(());
    }
    for id in ids {
        let status = match health.get(&id) {
            Some(h) if h.healthy => "✓".green(),
            Some(_) => "✗".red(),
            None => "?".yellow(),
        };
        println!("  {} {}", status, id);
    }
    Ok(())
}

async fn run_test(ctx: &Context, args: TestArgs) -> Result<(), CliError> {
    let client = ctx.ai_client().await?;

    let spinner = ctx.spinner("Testing AI connection...");
    let health = client.health_check().await;
    spinner.finish_and_clear();

    let mut tested = 0;
    let mut ok = 0;
    for (id, status) in &health {
        if let Some(provider) = &args.provider {
            if id.provider_type != *provider {
                continue;
            }
        }
        if let Some(model) = &args.model {
            if id.model_name != *model {
                continue;
            }
        }
        tested += 1;
        if status.healthy {
            ok += 1;
            println!("{} {}/{} reachable", "✓".green().bold(), id.provider_type, id.model_name);
        } else {
            println!(
                "{} {}/{} unreachable: {}",
                "✗".red().bold(),
                id.provider_type,
                id.model_name,
                status.message.clone().unwrap_or_else(|| "unknown error".to_string())
            );
        }
    }

    if tested == 0 {
        println!("{} No registered provider matches the given filters", "⚠".yellow().bold());
    } else if ok == 0 {
        return Err(CliError::Internal("No provider answered successfully".into()));
    }
    Ok(())
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

#[derive(serde::Serialize)]
struct AiAnalysis {
    summary: String,
    model: String,
    finding_title: String,
}

#[derive(tabled::Tabled)]
struct CorrelationRow {
    #[tabled(rename = "SOURCE")]
    source: String,
    #[tabled(rename = "TARGET")]
    target: String,
    #[tabled(rename = "TYPE")]
    relationship_type: String,
    #[tabled(rename = "CONFIDENCE")]
    confidence: String,
    #[tabled(rename = "DESCRIPTION")]
    description: String,
}
