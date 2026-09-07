//! Output formatting

use clap::ValueEnum;
use colored::Colorize;
pub use openre_core::ids::ScanId;
pub use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, RemediationEffort,
    RemediationGuidance, RemediationPriority, Severity,
};
use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tabled::{Table, Tabled};
use url::Url;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Table
    }
}

pub fn print_severity_summary(findings: &[Finding]) {
    let mut counts = HashMap::new();
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

pub fn print_table_results(
    findings: &[Finding],
    _target: &Url,
    _duration: Duration,
    _checks_run: usize,
) {
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

    let mut severity_counts = HashMap::new();
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

fn format_severity(sev: &Severity) -> String {
    match sev {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".red().to_string(),
        Severity::Medium => "MEDIUM".yellow().to_string(),
        Severity::Low => "LOW".green().to_string(),
        Severity::Info => "INFO".blue().to_string(),
    }
}

pub async fn print_json_results(
    findings: &[Finding],
    target: &Url,
    duration: Duration,
    checks_run: usize,
    output: Option<PathBuf>,
) -> Result<()> {
    let result = json!({
        "scan_id": ScanId::new().to_string(),
        "target": target.to_string(),
        "duration_seconds": duration.as_secs_f32(),
        "checks_run": checks_run,
        "findings_count": findings.len(),
        "findings": findings,
        "timestamp": Utc::now().to_rfc3339(),
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

pub async fn print_sarif_results(
    findings: &[Finding],
    target: &Url,
    _duration: Duration,
    _checks_run: usize,
    output: Option<PathBuf>,
) -> Result<()> {
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
                "startTimeUtc": Utc::now().to_rfc3339(),
                "endTimeUtc": Utc::now().to_rfc3339(),
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

pub async fn display_results(
    findings: &[Finding],
    format: &OutputFormat,
    output: Option<PathBuf>,
    target: &Url,
    duration: Duration,
    checks_run: usize,
) -> Result<()> {
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