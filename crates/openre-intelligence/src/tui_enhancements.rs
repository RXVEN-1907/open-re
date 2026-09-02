//! TUI Enhancements - Developer experience improvements for the terminal interface

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use colored::*;
use openre_core::ids::FindingId;
use openre_core::result::{Category, Confidence, Finding, Severity};
use std::collections::HashMap;
use std::io::Write as _;
use tracing::debug;

/// Configuration for TUI enhancements
#[derive(Debug, Clone)]
pub struct TuiConfig {
    /// Enable colorized output
    pub enable_colors: bool,

    /// Enable emoji indicators
    pub enable_emojis: bool,

    /// Show detailed finding descriptions
    pub show_detailed_descriptions: bool,

    /// Maximum width for terminal output
    pub max_width: usize,

    /// Enable interactive filtering
    pub enable_filtering: bool,

    /// Show finding confidence indicators
    pub show_confidence_indicators: bool,

    /// Enable progress indicators
    pub enable_progress_indicators: bool,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            enable_colors: true,
            enable_emojis: true,
            show_detailed_descriptions: true,
            max_width: 120,
            enable_filtering: true,
            show_confidence_indicators: true,
            enable_progress_indicators: true,
        }
    }
}

/// TUI enhancement manager for improved developer experience
pub struct TuiEnhancer {
    config: TuiConfig,
}

impl TuiEnhancer {
    /// Create a new TUI enhancer with default configuration
    pub fn new() -> Self {
        Self { config: TuiConfig::default() }
    }

    /// Create a new TUI enhancer with custom configuration
    pub fn with_config(config: TuiConfig) -> Self {
        Self { config }
    }

    /// Format a finding for terminal display
    pub fn format_finding(&self, finding: &Finding, show_related: bool) -> String {
        let mut output = String::new();

        // Severity indicator with color and emoji
        let severity_indicator = self.format_severity_indicator(finding.severity);
        output.push_str(&severity_indicator);

        // Finding title
        let title = if self.config.enable_colors {
            match finding.severity {
                Severity::Critical => format!("{}", finding.title.bold().red()),
                Severity::High => format!("{}", finding.title.bold().yellow()),
                Severity::Medium => format!("{}", finding.title.bold().blue()),
                Severity::Low => format!("{}", finding.title.bold().green()),
                Severity::Info => format!("{}", finding.title.bold().cyan()),
            }
        } else {
            finding.title.clone()
        };

        output.push_str(&format!(" {}\n", title));

        // Finding ID and target
        if self.config.enable_emojis {
            output.push_str(&format!("   🎯 Target: {}\n", finding.target));
            output.push_str(&format!("   🆔 ID: {}\n", finding.id));
        } else {
            output.push_str(&format!("   Target: {}\n", finding.target));
            output.push_str(&format!("   ID: {}\n", finding.id));
        }

        // Category
        if self.config.enable_emojis {
            let category_emoji = match finding.category {
                Category::Injection => "💉",
                Category::BrokenAuthentication => "🔐",
                Category::SensitiveDataExposure => "🛡️",
                Category::Xss => "🎭",
                Category::InsecureDeserialization => "📦",
                Category::SecurityMisconfiguration => "⚙️",
                Category::BrokenAccessControl => "🚪",
                Category::InformationDisclosure => "🔍",
                Category::VulnerableComponents => "🧩",
                _ => "⚠️",
            };
            output.push_str(&format!("   {} Category: {:?}\n", category_emoji, finding.category));
        } else {
            output.push_str(&format!("   Category: {:?}\n", finding.category));
        }

        // Confidence indicator
        if self.config.show_confidence_indicators {
            let confidence_indicator = self.format_confidence_indicator(finding.confidence);
            output.push_str(&format!("   {}\n", confidence_indicator));
        }

        // Risk score if available
        if let Some(risk_score) = finding.risk_score {
            let risk_level = match risk_score {
                0..=20 => "Low",
                21..=40 => "Medium",
                41..=60 => "High",
                61..=80 => "Critical",
                81..=100 => "Extreme",
                _ => "Unknown",
            };

            if self.config.enable_colors {
                let risk_color = match risk_score {
                    0..=20 => "green".to_string(),
                    21..=40 => "blue".to_string(),
                    41..=60 => "yellow".to_string(),
                    61..=80 => "red".to_string(),
                    _ => "white".to_string(),
                };

                output.push_str(&format!(
                    "   ⚠️  Risk Score: {} ({})\n",
                    risk_score.to_string().color(risk_color.as_str()),
                    risk_level.color(risk_color.as_str())
                ));
            } else {
                output.push_str(&format!("   Risk Score: {} ({})\n", risk_score, risk_level));
            }
        }

        // Description (if enabled)
        if self.config.show_detailed_descriptions {
            let description = self.wrap_text(&finding.description, self.config.max_width - 6);
            output.push_str(&format!("   📝 Description:\n      {}\n", description));
        }

        // CWE/CAPEC information if available
        if !finding.cwe_ids.is_empty() || !finding.capec_ids.is_empty() {
            output.push_str("   🔗 References:\n");

            if !finding.cwe_ids.is_empty() {
                let cwe_list = finding.cwe_ids.join(", ");
                output.push_str(&format!("      CWE: {}\n", cwe_list));
            }

            if !finding.capec_ids.is_empty() {
                let capec_list = finding.capec_ids.join(", ");
                output.push_str(&format!("      CAPEC: {}\n", capec_list));
            }
        }

        // Remediation if available
        if let Some(remediation) = &finding.remediation {
            let remediation_text = self.wrap_text(&remediation.summary, self.config.max_width - 6);
            output.push_str(&format!("   💡 Remediation:\n      {}\n", remediation_text));

            if !remediation.steps.is_empty() {
                output.push_str("      Steps:\n");
                for (i, step) in remediation.steps.iter().enumerate() {
                    let step_text = self.wrap_text(step, self.config.max_width - 9);
                    output.push_str(&format!("        {}. {}\n", i + 1, step_text));
                }
            }
        }

        // Related findings (if requested)
        if show_related && !finding.related_findings.is_empty() {
            output.push_str(&format!(
                "   🔗 Related Findings ({}):\n",
                finding.related_findings.len()
            ));
            for related_id in &finding.related_findings {
                output.push_str(&format!("      - {}\n", related_id));
            }
        }

        // Workflow status if available
        if finding.metadata.contains_key("workflow_acknowledged") {
            output.push_str("   ✅ Acknowledged\n");
        }

        if finding.metadata.contains_key("workflow_false_positive") {
            output.push_str("   ❌ Marked as False Positive\n");
        }

        // Root cause information if available
        if finding.metadata.contains_key("root_cause_analysis_performed") {
            output.push_str("   🌱 Root Cause Analysis Performed\n");

            if let Some(root_cause_count) = finding.metadata.get("root_cause_count") {
                output.push_str(&format!("      Related to {} root cause(s)\n", root_cause_count));
            }
        }

        // Separator
        output.push_str(&format!("{}\n", "─".repeat(self.config.max_width.min(80))));

        output
    }

    /// Format severity indicator with color and emoji
    fn format_severity_indicator(&self, severity: Severity) -> String {
        if self.config.enable_emojis && self.config.enable_colors {
            match severity {
                Severity::Critical => format!("{}", "🔴 CRITICAL".red().bold()),
                Severity::High => format!("{}", "🟠 HIGH".yellow().bold()),
                Severity::Medium => format!("{}", "🟡 MEDIUM".blue().bold()),
                Severity::Low => format!("{}", "🟢 LOW".green().bold()),
                Severity::Info => format!("{}", "🔵 INFO".cyan().bold()),
            }
        } else if self.config.enable_emojis {
            match severity {
                Severity::Critical => "🔴 CRITICAL".to_string(),
                Severity::High => "🟠 HIGH".to_string(),
                Severity::Medium => "🟡 MEDIUM".to_string(),
                Severity::Low => "🟢 LOW".to_string(),
                Severity::Info => "🔵 INFO".to_string(),
            }
        } else if self.config.enable_colors {
            match severity {
                Severity::Critical => format!("{}", "CRITICAL".red().bold()),
                Severity::High => format!("{}", "HIGH".yellow().bold()),
                Severity::Medium => format!("{}", "MEDIUM".blue().bold()),
                Severity::Low => format!("{}", "LOW".green().bold()),
                Severity::Info => format!("{}", "INFO".cyan().bold()),
            }
        } else {
            format!("{:?}", severity)
        }
    }

    /// Format confidence indicator
    fn format_confidence_indicator(&self, confidence: Confidence) -> String {
        if self.config.enable_emojis {
            match confidence {
                Confidence::VeryHigh => "🎯 Confidence: Certain".to_string(),
                Confidence::High => "🔥 Confidence: High".to_string(),
                Confidence::Medium => "⚠️  Confidence: Medium".to_string(),
                Confidence::Low => "❓ Confidence: Low".to_string(),
                Confidence::VeryLow => "🤔 Confidence: Unknown".to_string(),
            }
        } else {
            format!("Confidence: {:?}", confidence)
        }
    }

    /// Format a list of findings for display
    pub fn format_findings_list(&self, findings: &[Finding], title: &str) -> String {
        let mut output = String::new();

        // Header
        if self.config.enable_colors {
            output.push_str(&format!("{}\n", title.bold().underline()));
        } else {
            output.push_str(&format!("{}\n", title));
        }

        output.push_str(&format!("Total findings: {}\n\n", findings.len()));

        // Sort findings by severity (critical first)
        let mut sorted_findings = findings.to_vec();
        sorted_findings.sort_by(|a, b| {
            b.severity.cmp(&a.severity) // Reverse order for critical first
        });

        // Format each finding
        for finding in &sorted_findings {
            output.push_str(&self.format_finding(finding, false));
        }

        output
    }

    /// Format a correlation result for display
    pub fn format_correlation_result(&self, correlation: &EnhancedCorrelation) -> String {
        let mut output = String::new();

        if self.config.enable_emojis && self.config.enable_colors {
            output.push_str(&format!("🔗 {} Correlation Chain\n", "🔗".blue().bold()));
        } else if self.config.enable_emojis {
            output.push_str("🔗 Correlation Chain\n");
        } else {
            output.push_str("Correlation Chain\n");
        }

        output.push_str(&format!("   Type: {:?}\n", correlation.correlation_type));
        output.push_str(&format!("   Confidence: {:.2}%\n", correlation.confidence * 100.0));

        let desc_text = self.wrap_text(&correlation.description, self.config.max_width - 6);
        output.push_str(&format!("   Description: {}\n", desc_text));

        output.push_str("   Findings in chain:\n");
        for (i, finding_id) in correlation.finding_ids.iter().enumerate() {
            output.push_str(&format!("     {}. {}\n", i + 1, finding_id));
        }

        output.push_str("   Suggested mitigation approach:\n");
        let mitigation_text =
            self.wrap_text(&correlation.mitigation_approach, self.config.max_width - 9);
        for step in mitigation_text.lines() {
            output.push_str(&format!("     - {}\n", step));
        }

        output.push('\n');
        output
    }

    /// Format a CVE intelligence result for display
    pub fn format_cve_result(&self, cve_info: &CveInfo) -> String {
        let mut output = String::new();

        if self.config.enable_emojis && self.config.enable_colors {
            output.push_str(&format!("🛡️  {} CVE Information\n", "🛡️".red().bold()));
        } else if self.config.enable_emojis {
            output.push_str("🛡️  CVE Information\n");
        } else {
            output.push_str("CVE Information\n");
        }

        output.push_str(&format!("   CVE ID: {}\n", cve_info.cve_id));

        let summary_text = self.wrap_text(&cve_info.description, self.config.max_width - 6);
        output.push_str(&format!("   Summary: {}\n", summary_text));

        if let Some(cvss_score) = cve_info.cvss_score {
            let severity_color = match cvss_score {
                0.0..=3.9 => "green".to_string(),
                4.0..=6.9 => "yellow".to_string(),
                _ => "red".to_string(),
            };

            if self.config.enable_colors {
                output.push_str(&format!(
                    "   CVSS Score: {}\n",
                    cvss_score.to_string().color(severity_color.as_str())
                ));
            } else {
                output.push_str(&format!("   CVSS Score: {}\n", cvss_score));
            }
        }

        if !cve_info.affected_versions.is_empty() {
            output.push_str("   Affected Versions:\n");
            for version in &cve_info.affected_versions {
                output.push_str(&format!("     - {}\n", version));
            }
        }

        let published_text = cve_info.published_date.format("%Y-%m-%d");
        output.push_str(&format!("   Published: {}\n", published_text));

        if !cve_info.references.is_empty() {
            output.push_str("   References:\n");
            for reference in &cve_info.references {
                output.push_str(&format!("     - {}\n", reference));
            }
        }

        output.push('\n');
        output
    }

    /// Format a dependency analysis result for display
    pub fn format_dependency_result(&self, dep_info: &DependencyInfo) -> String {
        let mut output = String::new();

        if self.config.enable_emojis && self.config.enable_colors {
            let emoji = if !dep_info.vulnerabilities.is_empty() { "⚠️" } else { "✅" };
            let color = if !dep_info.vulnerabilities.is_empty() { "red" } else { "green" };
            output.push_str(&format!(
                "{} {} Dependency Information\n",
                emoji,
                emoji.to_string().color(color).bold()
            ));
        } else if self.config.enable_emojis {
            let emoji = if !dep_info.vulnerabilities.is_empty() { "⚠️" } else { "✅" };
            output.push_str(&format!("{} Dependency Information\n", emoji));
        } else {
            output.push_str("Dependency Information\n");
        }

        output.push_str(&format!("   Package: {} ({})\n", dep_info.name, dep_info.version));
        output.push_str(&format!("   Ecosystem: {}\n", dep_info.ecosystem));

        if let Some(latest_version) = &dep_info.latest_version {
            if dep_info.version != *latest_version {
                output.push_str(&format!("   Latest Version: {}\n", latest_version));
                output.push_str("   ⚠️  Outdated Package\n");
            }
        }

        if !dep_info.vulnerabilities.is_empty() {
            output.push_str("   🚨 Vulnerable Package\n");

            if !dep_info.vulnerabilities.is_empty() {
                output.push_str("   Known Vulnerabilities:\n");
                for vuln in &dep_info.vulnerabilities {
                    output.push_str(&format!("     - {}\n", vuln));
                }
            }
        }

        if let Some(recommendation) = &dep_info.upgrade_recommendation {
            let remediation_text =
                self.wrap_text(&recommendation.fixes_description, self.config.max_width - 6);
            output.push_str(&format!("   💡 Remediation: {}\n", remediation_text));
        }

        output.push('\n');
        output
    }

    /// Create a progress indicator for long-running operations
    pub fn create_progress_indicator(&self, operation: &str) -> ProgressIndicator {
        ProgressIndicator::new(operation.to_string(), self.config.enable_colors)
    }

    /// Wrap text to fit within specified width
    fn wrap_text(&self, text: &str, max_width: usize) -> String {
        let mut result = String::new();
        let mut current_line = String::new();

        for word in text.split_whitespace() {
            if current_line.is_empty() {
                current_line.push_str(word);
            } else if current_line.len() + 1 + word.len() <= max_width {
                current_line.push(' ');
                current_line.push_str(word);
            } else {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&current_line);
                current_line = word.to_string();
            }
        }

        if !current_line.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&current_line);
        }

        result
    }

    /// Format a summary dashboard view
    pub fn format_dashboard(
        &self,
        findings: &[Finding],
        correlations: &[EnhancedCorrelation],
    ) -> String {
        let mut output = String::new();

        // Header
        if self.config.enable_colors {
            output.push_str(&format!(
                "{}\n",
                "📊 Security Intelligence Dashboard".bold().underline()
            ));
        } else {
            output.push_str("📊 Security Intelligence Dashboard\n");
        }

        output.push('\n');

        // Summary statistics
        let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium_count = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low_count = findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info_count = findings.iter().filter(|f| f.severity == Severity::Info).count();

        output.push_str("📈 Findings Summary:\n");
        if self.config.enable_colors {
            output.push_str(&format!(
                "   🔴 Critical: {}\n",
                critical_count.to_string().red().bold()
            ));
            output.push_str(&format!("   🟠 High: {}\n", high_count.to_string().yellow().bold()));
            output.push_str(&format!("   🟡 Medium: {}\n", medium_count.to_string().blue().bold()));
            output.push_str(&format!("   🟢 Low: {}\n", low_count.to_string().green().bold()));
            output.push_str(&format!("   🔵 Info: {}\n", info_count.to_string().cyan().bold()));
        } else {
            output.push_str(&format!("   Critical: {}\n", critical_count));
            output.push_str(&format!("   High: {}\n", high_count));
            output.push_str(&format!("   Medium: {}\n", medium_count));
            output.push_str(&format!("   Low: {}\n", low_count));
            output.push_str(&format!("   Info: {}\n", info_count));
        }

        output.push_str(&format!("   📊 Total: {}\n\n", findings.len()));

        // Correlation summary
        output.push_str("🔗 Correlation Summary:\n");
        output.push_str(&format!("   Chain Count: {}\n", correlations.len()));

        let avg_confidence: f64 = if !correlations.is_empty() {
            correlations.iter().map(|c| c.confidence as f64).sum::<f64>()
                / correlations.len() as f64
        } else {
            0.0
        };

        output.push_str(&format!("   Avg Confidence: {:.1}%\n\n", avg_confidence * 100.0));

        // Top categories
        let mut category_counts = HashMap::new();
        for finding in findings {
            *category_counts.entry(&finding.category).or_insert(0) += 1;
        }

        output.push_str("🏷️  Top Categories:\n");
        let mut sorted_categories: Vec<(&Category, usize)> = category_counts.into_iter().collect();
        sorted_categories.sort_by(|a, b| b.1.cmp(&a.1));

        for (category, count) in sorted_categories.iter().take(5) {
            output.push_str(&format!("   {:?}: {}\n", category, count));
        }

        output.push('\n');

        // Workflow status
        let acknowledged_count =
            findings.iter().filter(|f| f.metadata.contains_key("workflow_acknowledged")).count();

        let false_positive_count =
            findings.iter().filter(|f| f.metadata.contains_key("workflow_false_positive")).count();

        output.push_str("✅ Workflow Status:\n");
        output.push_str(&format!("   Acknowledged: {}\n", acknowledged_count));
        output.push_str(&format!("   False Positives: {}\n\n", false_positive_count));

        // Recommendations
        output.push_str("💡 Recommendations:\n");
        if critical_count > 0 {
            output.push_str(&format!(
                "   🔴 Address {} critical findings immediately\n",
                critical_count
            ));
        }
        if !correlations.is_empty() {
            output.push_str("   🔗 Review correlation chains for systemic issues\n");
        }
        if false_positive_count > 0 {
            output.push_str("   ✅ Review false positive markings periodically\n");
        }

        output
    }
}

/// Progress indicator for long-running operations
pub struct ProgressIndicator {
    operation: String,
    start_time: std::time::Instant,
    enable_colors: bool,
}

impl ProgressIndicator {
    pub fn new(operation: String, enable_colors: bool) -> Self {
        Self { operation, start_time: std::time::Instant::now(), enable_colors }
    }

    pub fn update(&self, current: usize, total: usize) {
        let elapsed = self.start_time.elapsed();
        let progress = if total > 0 { (current as f64 / total as f64) * 100.0 } else { 100.0 };

        let elapsed_secs = elapsed.as_secs();
        let minutes = elapsed_secs / 60;
        let seconds = elapsed_secs % 60;

        if self.enable_colors {
            print!(
                "\r{} {:>3.0}% ({}/{}) - {}m {}s",
                self.operation.cyan().bold(),
                progress,
                current,
                total,
                minutes,
                seconds
            );
        } else {
            print!(
                "\r{} {:>3.0}% ({}/{}) - {}m {}s",
                self.operation, progress, current, total, minutes, seconds
            );
        }

        std::io::stdout().flush().unwrap();
    }

    pub fn finish(&self) {
        let elapsed = self.start_time.elapsed();
        let elapsed_secs = elapsed.as_secs();
        let minutes = elapsed_secs / 60;
        let seconds = elapsed_secs % 60;

        if self.enable_colors {
            println!(
                "\n{} {} - Completed in {}m {}s ✅",
                "✓".green().bold(),
                self.operation.green().bold(),
                minutes,
                seconds
            );
        } else {
            println!("\n{} - Completed in {}m {}s", self.operation, minutes, seconds);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{
        AssetCriticality, AttackComplexity, AttackVector, BusinessImpactAssessment, Category,
        Confidence, ExploitabilityAssessment, Finding, ImpactLevel, PrivilegesRequired, Reference,
        ReferenceType, RemediationEffort, RemediationGuidance, RemediationPriority, Scope,
        Severity, UserInteraction,
    };
    use std::collections::HashMap;

    fn create_test_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: "Test finding with detailed description that should be wrapped to multiple lines when displayed in the terminal interface for better readability".to_string(),
            severity,
            confidence: Confidence::High,
            category: Category::Injection,
            target: "https://example.com/test".to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: vec![Reference {
                reference_type: ReferenceType::Cwe,
                title: "CWE-89".to_string(),
                url: "https://cwe.mitre.org/data/definitions/89.html".to_string(),
                description: None,
            }],
            plugin_source: "test-plugin".to_string(),
            plugin_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: HashMap::new(),
            tags: vec!["test".to_string(), "example".to_string()],
            verified: true,
            false_positive: false,
            risk_score: Some(75),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
            cvss_score: Some(9.8),
            cwe_ids: vec!["CWE-89".to_string()],
            capec_ids: vec!["CAPEC-66".to_string()],
            mitre_attack_ids: vec!["T1190".to_string()],
            owasp_category: Some("A03:2021-Injection".to_string()),
            fingerprint: Some("test-fingerprint-12345".to_string()),
            related_findings: vec![FindingId::new(), FindingId::new()],
            remediation: Some(RemediationGuidance {
                summary: "Implement parameterized queries and input validation to prevent SQL injection attacks. Use prepared statements with bound parameters for all database operations.".to_string(),
                steps: vec![
                    "Use parameterized queries instead of string concatenation".to_string(),
                    "Validate and sanitize all user inputs".to_string(),
                    "Implement proper error handling that doesn't expose system information".to_string(),
                ],
                code_examples: Vec::new(),
                references: Vec::new(),
                effort: RemediationEffort::Medium,
                priority: RemediationPriority::High,
            }),
            exploitability: Some(ExploitabilityAssessment {
                score: 8.0,
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Changed,
                exploit_available: true,
                exploited_in_wild: false,
                epss_score: None,
            }),
            business_impact: Some(BusinessImpactAssessment {
                score: 8.5,
                confidentiality: ImpactLevel::High,
                integrity: ImpactLevel::High,
                availability: ImpactLevel::Low,
                asset_criticality: AssetCriticality::Critical,
                regulatory_impact: None,
            }),
        }
    }

    #[test]
    fn test_finding_formatting() {
        let enhancer = TuiEnhancer::new();
        let finding = create_test_finding("SQL Injection Vulnerability", Severity::Critical);

        let formatted = enhancer.format_finding(&finding, true);

        // Check that the output contains key elements
        assert!(formatted.contains("CRITICAL"));
        assert!(formatted.contains("SQL Injection Vulnerability"));
        assert!(formatted.contains("Target: https://example.com/test"));
        assert!(formatted.contains("Category: Injection"));
        assert!(formatted.contains("Risk Score: 75"));
        assert!(formatted.contains("CWE: CWE-89"));
        assert!(formatted.contains("Related Findings"));

        // Check that remediation is included
        assert!(formatted.contains("Remediation:"));
        assert!(formatted.contains("parameterized queries"));

        println!("{}", formatted);
    }

    #[test]
    fn test_findings_list_formatting() {
        let enhancer = TuiEnhancer::new();

        let findings = vec![
            create_test_finding("Critical Issue", Severity::Critical),
            create_test_finding("High Issue", Severity::High),
            create_test_finding("Medium Issue", Severity::Medium),
        ];

        let formatted = enhancer.format_findings_list(&findings, "Test Findings");

        assert!(formatted.contains("Test Findings"));
        assert!(formatted.contains("Total findings: 3"));
        assert!(formatted.contains("Critical Issue"));
        assert!(formatted.contains("High Issue"));
        assert!(formatted.contains("Medium Issue"));

        println!("{}", formatted);
    }

    #[test]
    fn test_correlation_formatting() {
        let enhancer = TuiEnhancer::new();

        let correlation = EnhancedCorrelation {
            finding_ids: vec![FindingId::new(), FindingId::new()],
            correlation_type: crate::CorrelationType::CspXssChain,
            confidence: 0.85,
            description: "Content Security Policy bypass leading to XSS execution".to_string(),
            evidence: vec![
                "Missing Content-Security-Policy header".to_string(),
                "Reflected XSS in search parameter".to_string(),
            ],
            combined_risk: RiskAssessment {
                individual_scores: vec![60, 75],
                combined_score: 85,
                explanation: "Chained CSP bypass and XSS significantly increase impact".to_string(),
            },
            mitigation_approach: "Implement strict CSP headers and sanitize all user inputs"
                .to_string(),
        };

        let formatted = enhancer.format_correlation_result(&correlation);

        assert!(formatted.contains("Correlation Chain"));
        assert!(formatted.contains("CspXssChain"));
        assert!(formatted.contains("Confidence: 85.00%"));
        assert!(formatted.contains("Content Security Policy bypass"));

        println!("{}", formatted);
    }

    #[test]
    fn test_cve_formatting() {
        let enhancer = TuiEnhancer::new();

        let cve_info = CveInfo {
            cve_id: "CVE-2023-12345".to_string(),
            severity: Severity::Critical,
            cvss_score: Some(9.8),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
            description: "Remote code execution vulnerability in test library".to_string(),
            affected_versions: vec![VersionRange {
                start_version: Some("1.0.0".to_string()),
                end_version: Some("1.2.0".to_string()),
                is_vulnerable: true,
            }],
            fixed_versions: vec!["1.2.0".to_string()],
            references: vec![CveReference {
                url: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345".to_string(),
                description: Some("NVD entry for CVE-2023-12345".to_string()),
            }],
            cwe_ids: vec!["CWE-78".to_string()],
            published_date: Utc::now(),
            last_modified_date: Utc::now(),
        };

        let formatted = enhancer.format_cve_result(&cve_info);

        assert!(formatted.contains("CVE Information"));
        assert!(formatted.contains("CVE-2023-12345"));
        assert!(formatted.contains("Remote code execution"));
        assert!(formatted.contains("CVSS Score: 9.8"));
        assert!(formatted.contains("Affected Versions"));

        println!("{}", formatted);
    }

    #[test]
    fn test_dependency_formatting() {
        let enhancer = TuiEnhancer::new();

        let dep_info = DependencyInfo {
            name: "vulnerable-package".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: "npm".to_string(),
            latest_version: Some("2.0.0".to_string()),
            is_outdated: true,
            vulnerabilities: vec![DependencyVulnerability {
                id: "CVE-2023-54321".to_string(),
                severity: Severity::Critical,
                description: "Remote code execution in vulnerable-package".to_string(),
                cvss_score: Some(9.8),
                affected_ranges: vec![VersionRange {
                    start_version: Some("1.0.0".to_string()),
                    end_version: Some("2.0.0".to_string()),
                    is_vulnerable: true,
                }],
                fixed_in: vec!["2.0.0".to_string()],
            }],
            upgrade_recommendation: Some(UpgradeRecommendation {
                target_version: "2.0.0".to_string(),
                risk_level: DependencyUpgradeRisk::Low,
                fixes_description: "Upgrade to version 2.0.0 or later to fix the vulnerability"
                    .to_string(),
            }),
        };

        let formatted = enhancer.format_dependency_result(&dep_info);

        assert!(formatted.contains("Dependency Information"));
        assert!(formatted.contains("vulnerable-package"));
        assert!(formatted.contains("1.0.0"));
        assert!(formatted.contains("npm"));
        assert!(formatted.contains("Vulnerable Package"));
        assert!(formatted.contains("Upgrade to version 2.0.0"));

        println!("{}", formatted);
    }

    #[test]
    fn test_text_wrapping() {
        let enhancer = TuiEnhancer::with_config(TuiConfig { max_width: 40, ..Default::default() });

        let long_text = "This is a very long text that should be wrapped to multiple lines for better readability in the terminal interface.";
        let wrapped = enhancer.wrap_text(long_text, 20);

        // Should contain line breaks
        assert!(wrapped.contains('\n'));

        // Each line should be approximately within the width limit
        for line in wrapped.lines() {
            assert!(line.len() <= 25); // Allow some flexibility
        }

        println!("Original: {}", long_text);
        println!("Wrapped:\n{}", wrapped);
    }

    #[test]
    fn test_dashboard_formatting() {
        let enhancer = TuiEnhancer::new();

        let findings = vec![
            create_test_finding("Critical Issue", Severity::Critical),
            create_test_finding("High Issue", Severity::High),
            create_test_finding("Medium Issue", Severity::Medium),
            create_test_finding("Low Issue", Severity::Low),
            create_test_finding("Info Issue", Severity::Info),
        ];

        let correlations = vec![EnhancedCorrelation {
            finding_ids: vec![FindingId::new(), FindingId::new()],
            correlation_type: crate::CorrelationType::CspXssChain,
            confidence: 0.90,
            description: String::new(),
            evidence: Vec::new(),
            combined_risk: RiskAssessment {
                individual_scores: Vec::new(),
                combined_score: 90,
                explanation: String::new(),
            },
            mitigation_approach: String::new(),
        }];

        let formatted = enhancer.format_dashboard(&findings, &correlations);

        assert!(formatted.contains("Security Intelligence Dashboard"));
        assert!(formatted.contains("Findings Summary"));
        assert!(formatted.contains("Critical: 1"));
        assert!(formatted.contains("Correlation Summary"));
        assert!(formatted.contains("Chain Count: 1"));

        println!("{}", formatted);
    }
}
