//! Scan Comparison command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Finding, Severity};
use openre_intelligence::types::{
    ScanDiffAnalysis, SeverityChange, SeverityChangeType, TrendAnalysis, TrendDirection,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct CompareCommand {
    /// Baseline (previous) scan ID
    #[arg(value_name = "BASELINE_SCAN")]
    baseline_scan: String,

    /// Current scan ID to compare against
    #[arg(value_name = "CURRENT_SCAN")]
    current_scan: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: CompareOutputFormat,

    /// Show fixed findings
    #[arg(long)]
    show_fixed: bool,

    /// Show new findings
    #[arg(long)]
    show_new: bool,

    /// Show changed findings (severity/confidence)
    #[arg(long)]
    show_changed: bool,

    /// Show remediation status
    #[arg(long)]
    remediation_status: bool,

    /// Minimum severity for significant changes
    #[arg(long, value_enum, default_value = "high")]
    min_severity: SeverityFilter,

    /// Generate HTML report
    #[arg(long)]
    html_report: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum CompareOutputFormat {
    Json,
    Table,
    Html,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityFilter> for Severity {
    fn from(s: SeverityFilter) -> Self {
        match s {
            SeverityFilter::Info => Severity::Info,
            SeverityFilter::Low => Severity::Low,
            SeverityFilter::Medium => Severity::Medium,
            SeverityFilter::High => Severity::High,
            SeverityFilter::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ScanComparisonResponse {
    baseline_scan_id: ScanId,
    current_scan_id: ScanId,
    analysis: ScanDiffAnalysis,
    baseline_findings: Vec<Finding>,
    current_findings: Vec<Finding>,
}

impl CompareCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        let baseline_id = ScanId::from_str(&self.baseline_scan).map_err(|_| {
            CliError::InvalidInput(format!("Invalid baseline scan ID: {}", self.baseline_scan))
        })?;
        let current_id = ScanId::from_str(&self.current_scan).map_err(|_| {
            CliError::InvalidInput(format!("Invalid current scan ID: {}", self.current_scan))
        })?;

        // Fetch comparison from API
        let mut url = format!("/api/scans/{}/compare/{}", baseline_id, current_id);
        let mut params = Vec::new();

        if self.show_fixed {
            params.push("show_fixed=true".to_string());
        }
        if self.show_new {
            params.push("show_new=true".to_string());
        }
        if self.show_changed {
            params.push("show_changed=true".to_string());
        }
        if self.remediation_status {
            params.push("remediation_status=true".to_string());
        }
        params.push(format!("min_severity={:?}", self.min_severity));

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = ctx.get(&url).await?;
        let data: ScanComparisonResponse = response.json().await?;

        if self.html_report || self.format == CompareOutputFormat::Html {
            self.print_html(&data);
        } else {
            match self.format {
                CompareOutputFormat::Table => self.print_table(&data),
                CompareOutputFormat::Json => print_output(&data.analysis, &OutputFormat::Json)?,
                CompareOutputFormat::Html => self.print_html(&data),
            }
        }

        Ok(())
    }

    fn print_table(&self, data: &ScanComparisonResponse) {
        let analysis = &data.analysis;

        println!(
            "\n{}",
            format!("Scan Comparison: {} vs {}", data.baseline_scan_id, data.current_scan_id)
                .bold()
                .underline()
        );

        // Summary
        println!("\n{}", "Summary:".bold());
        println!("  Previous findings: {}", analysis.total_findings_previous);
        println!("  Current findings: {}", analysis.total_findings_current);
        println!("  Net change: {:+} ({:+.1}%)", analysis.net_change, analysis.change_percentage);

        if analysis.is_significant_change {
            println!("  {} SIGNIFICANT CHANGE DETECTED", "⚠".yellow().bold());
        }

        println!("  New findings: {}", analysis.new_findings.len());
        println!("  Resolved findings: {}", analysis.resolved_findings.len());
        println!("  Persistent findings: {}", analysis.persistent_findings.len());
        println!("  Severity changes: {}", analysis.severity_changes.len());

        // Critical new findings
        if !analysis.critical_new_findings.is_empty() {
            println!("\n{}", "Critical New Findings:".red().bold());
            for finding_id in &analysis.critical_new_findings {
                if let Some(finding) = data.current_findings.iter().find(|f| f.id == *finding_id) {
                    println!("  {} - {} ({:?})", "🔴".red(), finding.title, finding.severity);
                    println!("    {}", finding.description);
                }
            }
        }

        // Significant new findings
        if self.show_new && !analysis.significant_new_findings.is_empty() {
            println!("\n{}", "Significant New Findings:".yellow().bold());
            for finding_id in &analysis.significant_new_findings {
                if let Some(finding) = data.current_findings.iter().find(|f| f.id == *finding_id) {
                    println!("  {} - {} ({:?})", "🟠".yellow(), finding.title, finding.severity);
                }
            }
        }

        // Resolved findings
        if self.show_fixed && !analysis.resolved_findings.is_empty() {
            println!("\n{}", "Resolved Findings:".green().bold());
            for finding_id in &analysis.resolved_findings {
                if let Some(finding) = data.baseline_findings.iter().find(|f| f.id == *finding_id) {
                    println!("  {} - {} ({:?})", "✓".green(), finding.title, finding.severity);
                }
            }
        }

        // Severity changes
        if self.show_changed && !analysis.severity_changes.is_empty() {
            println!("\n{}", "Severity Changes:".bold());
            let increased: Vec<_> = analysis
                .severity_changes
                .iter()
                .filter(|sc| matches!(sc.change_type, SeverityChangeType::Increased))
                .collect();
            let decreased: Vec<_> = analysis
                .severity_changes
                .iter()
                .filter(|sc| matches!(sc.change_type, SeverityChangeType::Decreased))
                .collect();

            if !increased.is_empty() {
                println!("  {} Increased:", "↑".red());
                for change in increased {
                    if let Some(finding) =
                        data.current_findings.iter().find(|f| f.id == change.finding_id)
                    {
                        println!(
                            "    {} - {:?} → {:?}",
                            finding.title, change.previous_severity, change.current_severity
                        );
                    }
                }
            }

            if !decreased.is_empty() {
                println!("  {} Decreased:", "↓".green());
                for change in decreased {
                    if let Some(finding) =
                        data.current_findings.iter().find(|f| f.id == change.finding_id)
                    {
                        println!(
                            "    {} - {:?} → {:?}",
                            finding.title, change.previous_severity, change.current_severity
                        );
                    }
                }
            }
        }

        // Trend analysis
        if let Some(trend) = &analysis.trend_analysis {
            println!("\n{}", "Trend Analysis:".bold());
            let trend_icon = match trend.trend_direction {
                TrendDirection::Improving => "📈".green(),
                TrendDirection::Worsening => "📉".red(),
                TrendDirection::Stable => "➡️".blue(),
                TrendDirection::Mixed => "📊".yellow(),
            };
            println!("  Overall trend: {} {:?}", trend_icon, trend.trend_direction);

            if !trend.improving_trends.is_empty() {
                println!("  Improvements:");
                for t in &trend.improving_trends {
                    println!(
                        "    {:?}: {} → {} ({:+})",
                        t.severity, t.previous_count, t.current_count, -t.change
                    );
                }
            }
            if !trend.worsening_trends.is_empty() {
                println!("  Deteriorations:");
                for t in &trend.worsening_trends {
                    println!(
                        "    {:?}: {} → {} ({:+})",
                        t.severity, t.previous_count, t.current_count, t.change
                    );
                }
            }
        }

        // Risk trend
        println!("\n{}", "Risk Trend:".bold());
        let risk_icon = match analysis.risk_trend.trend_direction {
            TrendDirection::Improving => "📈".green(),
            TrendDirection::Worsening => "📉".red(),
            TrendDirection::Stable => "➡️".blue(),
            TrendDirection::Mixed => "📊".yellow(),
        };
        println!("  Direction: {} {:?}", risk_icon, analysis.risk_trend.trend_direction);
        println!("  Overall change: {:+}", analysis.risk_trend.overall_change);
        for factor in &analysis.risk_trend.key_factors {
            println!("  - {}", factor);
        }
    }

    fn print_html(&self, data: &ScanComparisonResponse) {
        let analysis = &data.analysis;

        let mut html = String::new();
        html.push_str(&format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Scan Comparison: {} vs {}</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.6; }}
        .summary {{ background: #f5f5f5; padding: 1rem; border-radius: 8px; margin-bottom: 2rem; }}
        .significant {{ background: #fef3c7; border: 1px solid #f59e0b; }}
        .critical {{ color: #dc2626; font-weight: bold; }}
        .high {{ color: #ea580c; }}
        .medium {{ color: #ca8a04; }}
        .low {{ color: #16a34a; }}
        .resolved {{ color: #16a34a; }}
        .new {{ color: #dc2626; }}
        .changed {{ color: #2563eb; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; }}
        .trend-improving {{ color: #16a34a; }}
        .trend-worsening {{ color: #dc2626; }}
        .trend-stable {{ color: #2563eb; }}
    </style>
</head>
<body>
    <h1>Scan Comparison Report</h1>
    <p><strong>Baseline:</strong> {} | <strong>Current:</strong> {}</p>
"#,
            data.baseline_scan_id,
            data.current_scan_id,
            data.baseline_scan_id,
            data.current_scan_id
        ));

        // Summary
        let significant_class = if analysis.is_significant_change { "significant" } else { "" };
        html.push_str(&format!(
            r#"
    <div class="summary {}">
        <h2>Summary</h2>
        <ul>
            <li>Previous findings: {}</li>
            <li>Current findings: {}</li>
            <li>Net change: {:+} ({:+.1}%)</li>
            <li>New findings: {}</li>
            <li>Resolved findings: {}</li>
            <li>Persistent findings: {}</li>
            <li>Severity changes: {}</li>
        </ul>
    </div>"#,
            significant_class,
            analysis.total_findings_previous,
            analysis.total_findings_current,
            analysis.net_change,
            analysis.change_percentage,
            analysis.new_findings.len(),
            analysis.resolved_findings.len(),
            analysis.persistent_findings.len(),
            analysis.severity_changes.len()
        ));

        // Critical new findings
        if !analysis.critical_new_findings.is_empty() {
            html.push_str("<h2>Critical New Findings</h2><table><tr><th>Finding</th><th>Severity</th><th>Description</th></tr>");
            for finding_id in &analysis.critical_new_findings {
                if let Some(finding) = data.current_findings.iter().find(|f| f.id == *finding_id) {
                    html.push_str(&format!(
                        "<tr><td>{}</td><td class=\"critical\">{:?}</td><td>{}</td></tr>",
                        finding.title, finding.severity, finding.description
                    ));
                }
            }
            html.push_str("</table>");
        }

        // New findings
        if self.show_new && !analysis.significant_new_findings.is_empty() {
            html.push_str("<h2>Significant New Findings</h2><table><tr><th>Finding</th><th>Severity</th></tr>");
            for finding_id in &analysis.significant_new_findings {
                if let Some(finding) = data.current_findings.iter().find(|f| f.id == *finding_id) {
                    html.push_str(&format!(
                        "<tr><td class=\"new\">{}</td><td class=\"high\">{:?}</td></tr>",
                        finding.title, finding.severity
                    ));
                }
            }
            html.push_str("</table>");
        }

        // Resolved findings
        if self.show_fixed && !analysis.resolved_findings.is_empty() {
            html.push_str(
                "<h2>Resolved Findings</h2><table><tr><th>Finding</th><th>Severity</th></tr>",
            );
            for finding_id in &analysis.resolved_findings {
                if let Some(finding) = data.baseline_findings.iter().find(|f| f.id == *finding_id) {
                    html.push_str(&format!(
                        "<tr><td class=\"resolved\">{}</td><td>{:?}</td></tr>",
                        finding.title, finding.severity
                    ));
                }
            }
            html.push_str("</table>");
        }

        // Severity changes
        if self.show_changed && !analysis.severity_changes.is_empty() {
            html.push_str("<h2>Severity Changes</h2><table><tr><th>Finding</th><th>Previous</th><th>Current</th><th>Change</th></tr>");
            for change in &analysis.severity_changes {
                if let Some(finding) =
                    data.current_findings.iter().find(|f| f.id == change.finding_id)
                {
                    let change_class =
                        if matches!(change.change_type, SeverityChangeType::Increased) {
                            "new"
                        } else {
                            "resolved"
                        };
                    html.push_str(&format!(
                        "<tr><td>{}</td><td>{:?}</td><td class=\"{}\">{:?}</td><td class=\"{}\">{:?}</td></tr>",
                        finding.title,
                        change.previous_severity,
                        change_class,
                        change.current_severity,
                        change_class,
                        change.change_type
                    ));
                }
            }
            html.push_str("</table>");
        }

        // Trend
        if let Some(trend) = &analysis.trend_analysis {
            let trend_class = format!("trend-{:?}", trend.trend_direction).to_lowercase();
            html.push_str(&format!(
                "<h2>Trend Analysis</h2><p class=\"{}\">Overall trend: {:?}</p>",
                trend_class, trend.trend_direction
            ));
        }

        html.push_str("</body></html>");
        println!("{}", html);
    }
}

/// Type alias for compatibility with main.rs imports
pub type CompareCommands = CompareCommand;

