//! Investigation Workflow command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::WorkflowId;
use openre_intelligence::workflow_engine::{InvestigationWorkflowEngine, WorkflowStage};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct InvestigateCommand {
    /// Target to investigate (URL, domain, IP, etc.)
    #[arg(value_name = "TARGET")]
    target: String,

    /// Custom workflow file
    #[arg(short, long)]
    workflow: Option<PathBuf>,

    /// Stage to start from
    #[arg(short, long, value_enum)]
    stage: Option<WorkflowStageArg>,

    /// Resume from workflow ID
    #[arg(long)]
    resume: Option<String>,

    /// Run stages in parallel where possible
    #[arg(long)]
    parallel: bool,

    /// Output directory for results
    #[arg(short, long)]
    output_dir: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    output: InvestigateOutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum WorkflowStageArg {
    Discover,
    Analyze,
    Correlate,
    Verify,
    Prioritize,
    Report,
}

impl From<WorkflowStageArg> for openre_intelligence::workflow_engine::InvestigationStage {
    fn from(s: WorkflowStageArg) -> Self {
        match s {
            WorkflowStageArg::Discover => openre_intelligence::workflow_engine::InvestigationStage::Discover(Default::default()),
            WorkflowStageArg::Analyze => openre_intelligence::workflow_engine::InvestigationStage::Analyze(Default::default()),
            WorkflowStageArg::Correlate => openre_intelligence::workflow_engine::InvestigationStage::Correlate(Default::default()),
            WorkflowStageArg::Verify => openre_intelligence::workflow_engine::InvestigationStage::Verify(Default::default()),
            WorkflowStageArg::Prioritize => openre_intelligence::workflow_engine::InvestigationStage::Prioritize(Default::default()),
            WorkflowStageArg::Report => openre_intelligence::workflow_engine::InvestigationStage::Report(Default::default()),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum InvestigateOutputFormat {
    Json,
    Html,
    Markdown,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvestigationResponse {
    workflow_id: WorkflowId,
    target: String,
    status: String,
    current_stage: Option<WorkflowStage>,
    stages_completed: Vec<WorkflowStage>,
    results: InvestigationResults,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvestigationResults {
    discoveries: Vec<DiscoveryResult>,
    analysis: Vec<AnalysisResult>,
    correlations: Vec<CorrelationResult>,
    verifications: Vec<VerificationResult>,
    prioritized_findings: Vec<PrioritizedFinding>,
    report_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DiscoveryResult {
    url: String,
    method: String,
    status_code: Option<u16>,
    technologies: Vec<String>,
    parameters: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AnalysisResult {
    finding_id: String,
    title: String,
    severity: String,
    category: String,
    confidence: f32,
}

#[derive(Debug, Deserialize, Serialize)]
struct CorrelationResult {
    source_finding: String,
    target_finding: String,
    relationship_type: String,
    confidence: f32,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerificationResult {
    finding_id: String,
    status: String,
    confidence: f32,
}

#[derive(Debug, Deserialize, Serialize)]
struct PrioritizedFinding {
    finding_id: String,
    title: String,
    risk_score: u8,
    risk_level: String,
    rank: usize,
}

impl InvestigateCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        // Build request payload
        let mut payload = serde_json::json!({
            "target": self.target,
            "parallel": self.parallel,
        });

        if let Some(workflow_path) = &self.workflow {
            let workflow_content = tokio::fs::read_to_string(workflow_path).await?;
            payload["workflow"] = serde_json::json!(workflow_content);
        }

        if let Some(stage) = self.stage {
            payload["start_stage"] = serde_json::json!(format!("{:?}", stage));
        }

        if let Some(resume_id) = &self.resume {
            payload["resume_workflow_id"] = serde_json::json!(resume_id);
        }

        if let Some(output_dir) = &self.output_dir {
            payload["output_dir"] = serde_json::json!(output_dir.display().to_string());
        }

        // Start investigation
        let response = ctx.post("/api/investigate", &payload).await?;
        let data: InvestigationResponse = response.json().await?;

        // If not resuming, we might need to poll for completion
        if self.resume.is_none() && data.status == "running" {
            println!("{} Investigation started: {}", "▶".blue(), data.workflow_id);
            println!("Polling for completion...");

            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let status_response =
                    ctx.get(&format!("/api/investigate/{}/status", data.workflow_id)).await?;
                let status_data: InvestigationResponse = status_response.json().await?;

                if let Some(stage) = &status_data.current_stage {
                    print!(
                        "\rCurrent stage: {:?} | Completed: {:?}",
                        stage, status_data.stages_completed
                    );
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                }

                if matches!(status_data.status.as_str(), "completed" | "failed") {
                    println!("\nInvestigation {}!", status_data.status);
                    // Print final results
                    self.print_results(&status_data.results);
                    break;
                }
            }
        } else {
            self.print_results(&data.results);
        }

        // Save output if requested
        if let Some(ref output_dir) = self.output_dir {
            self.save_results(&data, output_dir).await?;
        }

        Ok(())
    }

    fn print_results(&self, results: &InvestigationResults) {
        println!("\n{}", "Investigation Results".bold().underline());

        // Discoveries
        if !results.discoveries.is_empty() {
            println!("\n{}", "Discoveries:".bold());
            let mut builder = tabled::builder::Builder::default();
            builder.push_record(vec![
                "URL".to_string(),
                "Method".to_string(),
                "Status".to_string(),
                "Technologies".to_string(),
                "Parameters".to_string(),
            ]);
            for d in &results.discoveries {
                builder.push_record(vec![
                    d.url.clone(),
                    d.method.clone(),
                    d.status_code.map_or("N/A".to_string(), |s| s.to_string()),
                    d.technologies.join(", "),
                    d.parameters.join(", "),
                ]);
            }
            let table = builder.build().with(Style::modern()).to_string();
            println!("{}", table);
        }

        // Analysis findings
        if !results.analysis.is_empty() {
            println!("\n{}", "Analysis Findings:".bold());
            let mut builder = tabled::builder::Builder::default();
            builder.push_record(vec![
                "Finding ID".to_string(),
                "Title".to_string(),
                "Severity".to_string(),
                "Category".to_string(),
                "Confidence".to_string(),
            ]);
            for a in &results.analysis {
                builder.push_record(vec![
                    a.finding_id.clone(),
                    a.title.clone(),
                    a.severity.clone(),
                    a.category.clone(),
                    format!("{:.2}", a.confidence),
                ]);
            }
            let table = builder.build().with(Style::modern()).to_string();
            println!("{}", table);
        }

        // Correlations
        if !results.correlations.is_empty() {
            println!("\n{}", "Correlations:".bold());
            let mut builder = tabled::builder::Builder::default();
            builder.push_record(vec![
                "Source".to_string(),
                "Target".to_string(),
                "Type".to_string(),
                "Confidence".to_string(),
            ]);
            for c in &results.correlations {
                builder.push_record(vec![
                    c.source_finding.clone(),
                    c.target_finding.clone(),
                    c.relationship_type.clone(),
                    format!("{:.2}", c.confidence),
                ]);
            }
            let table = builder.build().with(Style::modern()).to_string();
            println!("{}", table);
        }

        // Verifications
        if !results.verifications.is_empty() {
            println!("\n{}", "Verifications:".bold());
            let mut builder = tabled::builder::Builder::default();
            builder.push_record(vec![
                "Finding ID".to_string(),
                "Status".to_string(),
                "Confidence".to_string(),
            ]);
            for v in &results.verifications {
                builder.push_record(vec![
                    v.finding_id.clone(),
                    v.status.clone(),
                    format!("{:.2}", v.confidence),
                ]);
            }
            let table = builder.build().with(Style::modern()).to_string();
            println!("{}", table);
        }

        // Prioritized findings
        if !results.prioritized_findings.is_empty() {
            println!("\n{}", "Top Prioritized Findings:".bold());
            let mut builder = tabled::builder::Builder::default();
            builder.push_record(vec![
                "Rank".to_string(),
                "Finding ID".to_string(),
                "Title".to_string(),
                "Risk Score".to_string(),
                "Risk Level".to_string(),
            ]);
            for p in results.prioritized_findings.iter().take(10) {
                let risk_icon = match p.risk_level.as_str() {
                    "Critical" => "🔴",
                    "High" => "🟠",
                    "Medium" => "🟡",
                    "Low" => "🟢",
                    _ => "⚪",
                };
                builder.push_record(vec![
                    p.rank.to_string(),
                    p.finding_id.clone(),
                    p.title.clone(),
                    format!("{} {}", p.risk_score, risk_icon),
                    p.risk_level.clone(),
                ]);
            }
            let table = builder.build().with(Style::modern()).to_string();
            println!("{}", table);
        }

        if let Some(report_path) = &results.report_path {
            println!("\n{} Report saved to: {}", "📄".blue(), report_path);
        }
    }

    async fn save_results(
        &self,
        data: &InvestigationResponse,
        output_dir: &PathBuf,
    ) -> Result<(), CliError> {
        tokio::fs::create_dir_all(output_dir).await?;

        let output = match self.output {
            InvestigateOutputFormat::Json => serde_json::to_string_pretty(data)?,
            InvestigateOutputFormat::Markdown => self.to_markdown(data),
            InvestigateOutputFormat::Html => self.to_html(data),
        };

        let filename = format!(
            "investigation-{}-{}.{}",
            data.workflow_id,
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            match self.output {
                InvestigateOutputFormat::Json => "json",
                InvestigateOutputFormat::Markdown => "md",
                InvestigateOutputFormat::Html => "html",
            }
        );

        let path = output_dir.join(filename);
        tokio::fs::write(&path, output).await?;
        println!("{} Results saved to {}", "✓".green(), path.display());

        Ok(())
    }

    fn to_markdown(&self, data: &InvestigationResponse) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Investigation Report for {}\n\n", data.target));
        md.push_str(&format!("**Workflow ID:** {}\n", data.workflow_id));
        md.push_str(&format!("**Status:** {}\n", data.status));
        md.push_str(&format!("**Started:** {}\n", data.started_at.format("%Y-%m-%d %H:%M:%S")));
        if let Some(completed) = data.completed_at {
            md.push_str(&format!("**Completed:** {}\n", completed.format("%Y-%m-%d %H:%M:%S")));
        }
        md.push_str("\n---\n");

        // Add results sections
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- Discoveries: {}\n", data.results.discoveries.len()));
        md.push_str(&format!("- Findings: {}\n", data.results.analysis.len()));
        md.push_str(&format!("- Correlations: {}\n", data.results.correlations.len()));
        md.push_str(&format!("- Verifications: {}\n", data.results.verifications.len()));
        md.push_str(&format!("- Prioritized: {}\n", data.results.prioritized_findings.len()));

        md
    }

    fn to_html(&self, data: &InvestigationResponse) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Investigation Report for {}</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
        th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; }}
        th {{ background: #f5f5f5; }}
        .critical {{ color: #dc2626; }}
        .high {{ color: #ea580c; }}
        .medium {{ color: #ca8a04; }}
        .low {{ color: #16a34a; }}
    </style>
</head>
<body>
    <h1>Investigation Report for {}</h1>
    <p><strong>Workflow ID:</strong> {}</p>
    <p><strong>Status:</strong> {}</p>
    <p><strong>Started:</strong> {}</p>
</body>
</html>"#,
            data.target, data.target, data.workflow_id, data.status, data.started_at
        )
    }
}

/// Type alias for compatibility with main.rs imports
pub type InvestigateCommands = InvestigateCommand;

