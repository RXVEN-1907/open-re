//! Attack Paths command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::attack_path::{
    AttackNodeType, AttackPath, AttackPathCollection, AttackPathEdge, AttackPathNode, EntryPoint,
    ImpactAssessment, RiskLevel, RiskScore,
};
use openre_core::ids::{AttackPathId, FindingId, NodeId, ScanId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Parser)]
pub struct AttackPathsCommand {
    /// Scan ID to analyze attack paths for
    #[arg(value_name = "SCAN_ID")]
    scan_id: String,

    /// Specific entry point to start from
    #[arg(short, long)]
    entry_point: Option<String>,

    /// Maximum path depth
    #[arg(short, long, default_value = "10")]
    max_depth: usize,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    output: AttackPathOutputFormat,

    /// Minimum risk score to display (0-100)
    #[arg(long, default_value = "0")]
    min_risk: u8,

    /// Show only critical paths
    #[arg(long)]
    critical_only: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AttackPathOutputFormat {
    Json,
    Dot,
    Mermaid,
    Html,
    Table,
}

#[derive(Debug, Deserialize, Serialize)]
struct ScanAttackPathsResponse {
    scan_id: ScanId,
    paths: Vec<AttackPath>,
    metadata: AttackPathCollectionMetadata,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttackPathCollectionMetadata {
    total_paths: usize,
    by_risk_level: HashMap<RiskLevel, usize>,
    by_impact_level: HashMap<openre_core::attack_path::ImpactLevel, usize>,
    average_confidence: f32,
    generated_at: chrono::DateTime<chrono::Utc>,
    target: String,
}

impl AttackPathsCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        let scan_id = ScanId::from_str(&self.scan_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid scan ID: {}", self.scan_id)))?;

        // Fetch attack paths from API
        let mut url = format!("/api/scans/{}/attack-paths", scan_id);
        let mut params = Vec::new();

        if let Some(entry) = &self.entry_point {
            params.push(format!("entry_point={}", entry));
        }
        params.push(format!("max_depth={}", self.max_depth));
        params.push(format!("min_risk={}", self.min_risk));
        if self.critical_only {
            params.push("critical_only=true".to_string());
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = ctx.get(&url).await?;
        let data: ScanAttackPathsResponse = response.json().await?;

        // Filter paths
        let mut paths = data.paths;
        paths.retain(|p| p.overall_risk.score >= self.min_risk);
        if self.critical_only {
            paths.retain(|p| p.overall_risk.level >= RiskLevel::Critical);
        }

        // Sort by risk score descending
        paths.sort_by(|a, b| b.overall_risk.score.cmp(&a.overall_risk.score));

        match self.output {
            AttackPathOutputFormat::Table => self.print_table(&paths, &data.metadata),
            AttackPathOutputFormat::Json => print_output(&paths, &OutputFormat::Json)?,
            AttackPathOutputFormat::Dot => self.print_dot(&paths),
            AttackPathOutputFormat::Mermaid => self.print_mermaid(&paths),
            AttackPathOutputFormat::Html => self.print_html(&paths, &data.metadata),
        }

        Ok(())
    }

    fn print_table(&self, paths: &[AttackPath], metadata: &AttackPathCollectionMetadata) {
        println!(
            "\n{}",
            format!("Attack Paths for Scan (Total: {})", paths.len()).bold().underline()
        );

        if paths.is_empty() {
            println!("No attack paths found matching criteria.");
            return;
        }

        let mut builder = tabled::builder::Builder::default();
        builder.push_record(vec![
            "Path ID".to_string(),
            "Name".to_string(),
            "Risk Score".to_string(),
            "Risk Level".to_string(),
            "Nodes".to_string(),
            "Edges".to_string(),
            "Entry Points".to_string(),
            "Confidence".to_string(),
        ]);

        for path in paths {
            let risk_color = match path.overall_risk.level {
                RiskLevel::Critical => "🔴",
                RiskLevel::High => "🟠",
                RiskLevel::Medium => "🟡",
                RiskLevel::Low => "🟢",
                RiskLevel::VeryLow => "🔵",
                RiskLevel::None => "⚪",
            };

            builder.push_record(vec![
                path.id.to_string(),
                path.name.clone(),
                format!("{} {}", path.overall_risk.score, risk_color),
                format!("{:?}", path.overall_risk.level),
                path.nodes.len().to_string(),
                path.edges.len().to_string(),
                path.entry_points.len().to_string(),
                format!("{:.2}", path.confidence),
            ]);
        }

        let table = builder.build().with(tabled::settings::Style::modern()).to_string();
        println!("{}", table);

        // Print summary
        println!("\n{}", "Summary:".bold());
        println!("  Total paths: {}", metadata.total_paths);
        println!("  Average confidence: {:.2}", metadata.average_confidence);
        println!("  By risk level:");
        for (level, count) in &metadata.by_risk_level {
            println!("    {:?}: {}", level, count);
        }
    }

    fn print_dot(&self, paths: &[AttackPath]) {
        for path in paths {
            println!("{}", path.to_dot());
            println!(); // Separate paths
        }
    }

    fn print_mermaid(&self, paths: &[AttackPath]) {
        for path in paths {
            println!("{}", path.to_mermaid());
            println!(); // Separate paths
        }
    }

    fn print_html(&self, paths: &[AttackPath], metadata: &AttackPathCollectionMetadata) {
        let mut html = String::new();
        html.push_str(&format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Attack Paths - {}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>mermaid.initialize({{startOnLoad:true}});</script>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
        .path {{ margin-bottom: 2rem; padding: 1rem; border: 1px solid #ddd; border-radius: 8px; }}
        .path-header {{ display: flex; gap: 1rem; align-items: center; margin-bottom: 1rem; }}
        .risk-badge {{ padding: 0.25rem 0.75rem; border-radius: 9999px; color: white; font-weight: bold; }}
        .critical {{ background: #dc2626; }}
        .high {{ background: #ea580c; }}
        .medium {{ background: #ca8a04; }}
        .low {{ background: #16a34a; }}
        .verylow {{ background: #2563eb; }}
        .none {{ background: #6b7280; }}
    </style>
</head>
<body>
    <h1>Attack Paths Analysis</h1>
    <p>Target: {}</p>
    <p>Total paths: {} | Avg confidence: {:.2}</p>
"#,
            metadata.target,
            metadata.target,
            metadata.total_paths,
            metadata.average_confidence
        ));

        for path in paths {
            let risk_class = match path.overall_risk.level {
                RiskLevel::Critical => "critical",
                RiskLevel::High => "high",
                RiskLevel::Medium => "medium",
                RiskLevel::Low => "low",
                RiskLevel::VeryLow => "verylow",
                RiskLevel::None => "none",
            };

            html.push_str(&format!(
                r#"
    <div class="path">
        <div class="path-header">
            <h2>{}</h2>
            <span class="risk-badge {}">{:?} ({})</span>
        </div>
        <p><strong>Description:</strong> {}</p>
        <p><strong>Nodes:</strong> {} | <strong>Edges:</strong> {} | <strong>Entry Points:</strong> {} | <strong>Confidence:</strong> {:.2}</p>
        <div class="mermaid">
{}
        </div>
    </div>"#,
                path.name,
                risk_class,
                path.overall_risk.level,
                path.overall_risk.score,
                path.description,
                path.nodes.len(),
                path.edges.len(),
                path.entry_points.len(),
                path.confidence,
                path.to_mermaid()
            ));
        }

        html.push_str(
            r#"
</body>
</html>"#,
        );

        println!("{}", html);
    }
}

/// Type alias for compatibility with main.rs imports
pub type AttackPathsCommands = AttackPathsCommand;

