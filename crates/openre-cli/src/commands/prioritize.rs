//! Finding Prioritization command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::Finding;
use openre_core::risk_knowledge::{calculate_risk_score, RiskFactors, RiskLevel, RiskScore};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct PrioritizeCommand {
    /// Scan ID to prioritize findings for
    #[arg(value_name = "SCAN_ID")]
    scan_id: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: PrioritizeOutputFormat,

    /// Show detailed explanation for each finding
    #[arg(long)]
    explain: bool,

    /// Minimum risk score to include (0-100)
    #[arg(long, default_value = "0")]
    min_score: u8,

    /// Maximum number of findings to show
    #[arg(long, default_value = "50")]
    limit: usize,

    /// Sort by risk score (descending)
    #[arg(long, default_value = "true")]
    sort_by_risk: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PrioritizeOutputFormat {
    Json,
    Table,
}

#[derive(Debug, Deserialize, Serialize)]
struct PrioritizeResponse {
    scan_id: ScanId,
    findings: Vec<PrioritizedFinding>,
    total_findings: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct PrioritizedFinding {
    finding_id: FindingId,
    title: String,
    severity: String,
    category: String,
    risk_score: RiskScore,
    rank: usize,
    risk_factors: Option<RiskFactors>,
}

impl PrioritizeCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        let scan_id = ScanId::from_str(&self.scan_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid scan ID: {}", self.scan_id)))?;

        // Fetch prioritized findings from API
        let mut url = format!("/api/scans/{}/prioritize", scan_id);
        let mut params = Vec::new();

        params.push(format!("min_score={}", self.min_score));
        params.push(format!("limit={}", self.limit));
        params.push(format!("sort_by_risk={}", self.sort_by_risk));
        if self.explain {
            params.push("explain=true".to_string());
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = ctx.get(&url).await?;
        let data: PrioritizeResponse = response.json().await?;

        match self.format {
            PrioritizeOutputFormat::Table => self.print_table(&data.findings),
            PrioritizeOutputFormat::Json => print_output(&data.findings, &OutputFormat::Json)?,
        }

        Ok(())
    }

    fn print_table(&self, findings: &[PrioritizedFinding]) {
        println!(
            "\n{}",
            format!("Prioritized Findings (Top {})", findings.len()).bold().underline()
        );

        if findings.is_empty() {
            println!("No findings matching criteria.");
            return;
        }

        let mut builder = tabled::builder::Builder::default();
        builder.push_record(vec![
            "Rank".to_string(),
            "Finding ID".to_string(),
            "Title".to_string(),
            "Severity".to_string(),
            "Category".to_string(),
            "Risk Score".to_string(),
            "Risk Level".to_string(),
        ]);

        for finding in findings {
            let risk_color = match finding.risk_score.level {
                RiskLevel::Critical => "🔴",
                RiskLevel::High => "🟠",
                RiskLevel::Medium => "🟡",
                RiskLevel::Low => "🟢",
                RiskLevel::VeryLow => "🔵",
                RiskLevel::None => "⚪",
            };

            let title = if finding.title.len() > 50 {
                format!("{}...", &finding.title[..47])
            } else {
                finding.title.clone()
            };

            builder.push_record(vec![
                finding.rank.to_string(),
                finding.finding_id.to_string(),
                title,
                format!("{} {}", finding.severity, risk_color),
                finding.category.clone(),
                finding.risk_score.score.to_string(),
                format!("{:?}", finding.risk_score.level),
            ]);
        }

        let table = builder.build().with(Style::modern()).to_string();
        println!("{}", table);

        // Print explanations if requested
        if self.explain {
            println!("\n{}", "Detailed Explanations:".bold());
            for finding in findings.iter().take(10) {
                println!("\n{} {}", "▶".bold(), finding.title.bold());
                println!("  Finding ID: {}", finding.finding_id);
                println!(
                    "  Risk Score: {} ({:?})",
                    finding.risk_score.score, finding.risk_score.level
                );
                println!("  Confidence: {:.0}%", finding.risk_score.confidence * 100.0);
                println!("  Explanation: {}", finding.risk_score.explanation);

                // Print factor breakdown
                let breakdown = &finding.risk_score.breakdown;
                println!("  Factor Breakdown:");
                self.print_factor("Base Severity", &breakdown.base_severity);
                self.print_factor("Confidence", &breakdown.confidence);
                self.print_factor("Endpoint Context", &breakdown.endpoint_context);
                self.print_factor("Auth Context", &breakdown.auth_context);
                self.print_factor("Sensitivity", &breakdown.sensitivity);
                self.print_factor("Dependencies", &breakdown.dependencies);
                self.print_factor("Reachability", &breakdown.reachability);
                self.print_factor("Exploit Availability", &breakdown.exploit_availability);
                self.print_factor("CVE Matches", &breakdown.cve_matches);
                self.print_factor("CAPEC Matches", &breakdown.capec_matches);
                self.print_factor("MITRE ATT&CK", &breakdown.mitre_attack_matches);
                self.print_factor("Environmental", &breakdown.environmental);
                self.print_factor("Business Context", &breakdown.business);
            }
        }
    }

    fn print_factor(&self, name: &str, factor: &openre_core::risk_knowledge::FactorContribution) {
        if factor.weighted_value > 0.0 {
            println!(
                "    {}: {:.1}/{:.1} (weight: {:.0}%) - {}",
                name,
                factor.weighted_value,
                factor.max_possible * factor.weight,
                factor.weight * 100.0,
                factor.explanation
            );
        }
    }
}

/// Type alias for compatibility with main.rs imports
pub type PrioritizeCommands = PrioritizeCommand;

