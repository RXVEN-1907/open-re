//! Reporting agent implementation

use crate::agents::context::*;
use crate::agents::agent_trait::{AgentContext, SecurityAgent, BaseAgent};
use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use openre_core::ids::AgentId;
use async_trait::async_trait;
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::Finding;
use std::collections::HashMap;

/// Reporting agent for generating reports and summaries
pub struct ReportingAgent {
    base: BaseAgent,
}

impl ReportingAgent {
    /// Create a new reporting agent
    pub fn new() -> Self {
        let base = BaseAgent::new("reporting-agent".to_string(), AgentType::Reporting);
        Self { base }
    }
}

#[async_trait]
impl SecurityAgent for ReportingAgent {
    type Input = ReportingInput;
    type Output = ReportingOutput;

    fn agent_id(&self) -> AgentId {
        self.base.agent_id()
    }

    fn agent_type(&self) -> AgentType {
        self.base.agent_type()
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities()
    }

    fn name(&self) -> &str {
        self.base.name()
    }

    async fn execute(&self, input: Self::Input, _ctx: AgentContext) -> anyhow::Result<AgentResult<Self::Output>> {
        let started_at = std::time::Instant::now();

        let report = match input.format.as_str() {
            "json" => self.generate_json_report(&input),
            "html" => self.generate_html_report(&input),
            "sarif" => self.generate_sarif_report(&input),
            _ => self.generate_text_report(&input),
        };

        let metadata = ReportMetadata {
            generated_at: chrono::Utc::now(),
            scan_id: input.scan_id,
            total_findings: input.findings.len(),
            findings_by_severity: self.count_by_severity(&input.findings),
            report_type: input.report_type.clone(),
        };

        let output = ReportingOutput {
            report,
            format: input.format,
            metadata,
        };

        let duration_ms = started_at.elapsed().as_millis() as u64;
        Ok(AgentResult::success(output, duration_ms))
    }

    fn count_by_severity(&self, findings: &[Finding]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for finding in findings {
            *counts.entry(format!("{:?}", finding.severity)).or_insert(0) += 1;
        }
        counts
    }

    fn generate_json_report(&self, input: &ReportingInput) -> String {
        let report = serde_json::json!({
            "scan_id": input.scan_id,
            "report_type": input.report_type,
            "generated_at": chrono::Utc::now(),
            "findings": input.findings,
            "correlations": input.correlations,
            "attack_paths": input.attack_paths,
            "verification": input.verification,
            "remediation": input.remediation,
        });
        serde_json::to_string_pretty(&report).unwrap_or_default()
    }

    fn generate_html_report(&self, input: &ReportingInput) -> String {
        let mut html = String::new();
        html.push_str("<html><head><title>Security Report</title></head><body>");
        html.push_str(&format!("<h1>Security Scan Report</h1>"));
        html.push_str(&format!("<p>Scan ID: {}</p>", input.scan_id));
        html.push_str(&format!("<p>Generated: {}</p>", chrono::Utc::now()));
        html.push_str(&format!("<p>Total Findings: {}</p>", input.findings.len()));
        html.push_str("<h2>Findings</h2><ul>");
        for finding in &input.findings {
            html.push_str(&format!("<li><strong>{:?}</strong>: {} - {}</li>", finding.severity, finding.title, finding.description));
        }
        html.push_str("</ul></body></html>");
        html
    }

    fn generate_sarif_report(&self, input: &ReportingInput) -> String {
        // Simplified SARIF output
        let sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "openre",
                        "version": "1.0.0"
                    }
                },
                "results": input.findings.iter().map(|f| {
                    serde_json::json!({
                        "ruleId": f.category.to_string(),
                        "message": {"text": f.title.clone()},
                        "level": match f.severity {
                            openre_core::result::Severity::Critical => "error",
                            openre_core::result::Severity::High => "error",
                            openre_core::result::Severity::Medium => "warning",
                            openre_core::result::Severity::Low => "note",
                            openre_core::result::Severity::Info => "note",
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.target.clone()}
                            }
                        }]
                    })
                }).collect::<Vec<_>>()
            }]
        });
        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    }

    fn generate_text_report(&self, input: &ReportingInput) -> String {
        let mut report = String::new();
        report.push_str(&format!("Security Scan Report\n"));
        report.push_str(&format!("====================\n\n"));
        report.push_str(&format!("Scan ID: {}\n", input.scan_id));
        report.push_str(&format!("Generated: {}\n", chrono::Utc::now()));
        report.push_str(&format!("Report Type: {}\n", input.report_type));
        report.push_str(&format!("Total Findings: {}\n\n", input.findings.len()));

        let counts = self.count_by_severity(&input.findings);
        for (severity, count) in counts {
            report.push_str(&format!("  {}: {}\n", severity, count));
        }
        report.push_str("\n");

        for finding in &input.findings {
            report.push_str(&format!("[{:?}] {} - {}\n", finding.severity, finding.title, finding.description));
        }

        report
    }

    async fn health_check(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}