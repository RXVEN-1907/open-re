//! Reporting engine for generating security reports in multiple formats

use crate::result::*;
use crate::ids::{ScanId, ProjectId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Report generator
pub struct ReportGenerator {
    /// Configuration
    config: ReportConfig,
}

/// Report configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Include executive summary
    pub include_executive_summary: bool,
    /// Include technical details
    pub include_technical_details: bool,
    /// Include evidence
    pub include_evidence: bool,
    /// Include remediation guidance
    pub include_remediation: bool,
    /// Include reproduction steps
    pub include_reproduction: bool,
    /// Include scan metadata
    pub include_scan_metadata: bool,
    /// Include target metadata
    pub include_target_metadata: bool,
    /// Group findings by
    pub group_by: GroupBy,
    /// Sort findings by
    pub sort_by: FindingSort,
    /// Maximum findings per category
    pub max_findings_per_category: Option<usize>,
    /// Minimum severity to include
    pub min_severity: Option<Severity>,
    /// Custom template
    pub custom_template: Option<String>,
    /// Company/logo info
    pub branding: Option<BrandingInfo>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            include_executive_summary: true,
            include_technical_details: true,
            include_evidence: true,
            include_remediation: true,
            include_reproduction: true,
            include_scan_metadata: true,
            include_target_metadata: true,
            group_by: GroupBy::Severity,
            sort_by: FindingSort::SeverityDesc,
            max_findings_per_category: None,
            min_severity: None,
            custom_template: None,
            branding: None,
        }
    }
}

/// Branding information for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingInfo {
    /// Company name
    pub company_name: String,
    /// Logo URL or base64
    pub logo: Option<String>,
    /// Report title prefix
    pub title_prefix: Option<String>,
    /// Footer text
    pub footer: Option<String>,
    /// Color scheme
    pub color_scheme: Option<ColorScheme>,
}

/// Color scheme for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorScheme {
    /// Primary color
    pub primary: String,
    /// Secondary color
    pub secondary: String,
    /// Critical color
    pub critical: String,
    /// High color
    pub high: String,
    /// Medium color
    pub medium: String,
    /// Low color
    pub low: String,
    /// Info color
    pub info: String,
}

/// How to group findings in report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    /// Group by severity
    Severity,
    /// Group by category
    Category,
    /// Group by target
    Target,
    /// Group by plugin
    Plugin,
    /// Group by OWASP category
    OwaspCategory,
    /// No grouping
    None,
}

/// Report format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// Markdown format
    Markdown,
    /// HTML format
    Html,
    /// JSON format
    Json,
    /// SARIF format
    Sarif,
    /// PDF format (requires external tool)
    Pdf,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report ID
    pub id: String,
    /// Report title
    pub title: String,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Generator version
    pub generator_version: String,
    /// Scan IDs included
    pub scan_ids: Vec<ScanId>,
    /// Project ID
    pub project_id: Option<ProjectId>,
    /// Target information
    pub targets: Vec<TargetInfo>,
    /// Date range
    pub date_range: Option<DateRange>,
    /// Report format
    pub format: ReportFormat,
    /// Configuration used
    pub config: ReportConfig,
}

/// Target information for report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Target identifier
    pub id: String,
    /// Target name
    pub name: String,
    /// Target URL
    pub url: String,
    /// Target type
    pub target_type: String,
    /// Scan count
    pub scan_count: usize,
    /// Finding count
    pub finding_count: usize,
}

/// Date range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    /// Start date
    pub from: DateTime<Utc>,
    /// End date
    pub to: DateTime<Utc>,
}

/// Executive summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    /// Total findings
    pub total_findings: usize,
    /// Findings by severity
    pub by_severity: HashMap<Severity, usize>,
    /// Overall risk score
    pub overall_risk_score: u8,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Critical findings count
    pub critical_count: usize,
    /// High findings count
    pub high_count: usize,
    /// Key findings (top 5)
    pub key_findings: Vec<KeyFinding>,
    /// Scan coverage
    pub scan_coverage: ScanCoverage,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Critical risk
    Critical,
    /// High risk
    High,
    /// Medium risk
    Medium,
    /// Low risk
    Low,
    /// Informational
    Informational,
}

/// Key finding for executive summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFinding {
    /// Finding ID
    pub id: String,
    /// Title
    pub title: String,
    /// Severity
    pub severity: Severity,
    /// Target
    pub target: String,
    /// Category
    pub category: Category,
    /// Risk score
    pub risk_score: u8,
    /// One-line summary
    pub summary: String,
}

/// Scan coverage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCoverage {
    /// Total targets scanned
    pub targets_scanned: usize,
    /// Total endpoints tested
    pub endpoints_tested: usize,
    /// Plugins executed
    pub plugins_executed: usize,
    /// Scan duration
    pub scan_duration_seconds: u64,
    /// Coverage percentage
    pub coverage_percentage: Option<f32>,
}

/// Complete report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report metadata
    pub metadata: ReportMetadata,
    /// Executive summary
    pub executive_summary: Option<ExecutiveSummary>,
    /// Findings grouped by category
    pub findings_by_group: HashMap<String, Vec<Finding>>,
    /// All findings (flat)
    pub all_findings: Vec<Finding>,
    /// Statistics
    pub statistics: FindingStats,
    /// Scan comparison (if applicable)
    pub scan_comparison: Option<ScanComparison>,
    /// Appendices
    pub appendices: Vec<Appendix>,
}

/// Appendix for report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appendix {
    /// Title
    pub title: String,
    /// Content
    pub content: String,
    /// Appendix type
    pub appendix_type: AppendixType,
}

/// Appendix type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppendixType {
    /// Methodology
    Methodology,
    /// Tool versions
    ToolVersions,
    /// Scope
    Scope,
    /// Limitations
    Limitations,
    /// Glossary
    Glossary,
    /// References
    References,
    /// Custom
    Custom,
}

/// Scan comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparison {
    /// Baseline scan ID
    pub baseline_scan_id: ScanId,
    /// Current scan ID
    pub current_scan_id: ScanId,
    /// New findings
    pub new_findings: Vec<Finding>,
    /// Fixed findings
    pub fixed_findings: Vec<Finding>,
    /// Regressed findings (reappeared)
    pub regressed_findings: Vec<Finding>,
    /// Severity changes
    pub severity_changes: Vec<SeverityChange>,
    /// Evidence changes
    pub evidence_changes: Vec<EvidenceChange>,
    /// Summary
    pub summary: ComparisonSummary,
}

/// Severity change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    /// Finding ID (matched by fingerprint)
    pub fingerprint: String,
    /// Previous severity
    pub previous_severity: Severity,
    /// Current severity
    pub current_severity: Severity,
    /// Finding title
    pub title: String,
    /// Target
    pub target: String,
}

/// Evidence change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChange {
    /// Finding ID (matched by fingerprint)
    pub fingerprint: String,
    /// Change type
    pub change_type: EvidenceChangeType,
    /// Description
    pub description: String,
    /// Finding title
    pub title: String,
    /// Target
    pub target: String,
}

/// Evidence change type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceChangeType {
    /// New evidence added
    Added,
    /// Evidence removed
    Removed,
    /// Evidence modified
    Modified,
}

/// Comparison summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    /// Total new findings
    pub new_count: usize,
    /// Total fixed findings
    pub fixed_count: usize,
    /// Total regressed findings
    pub regressed_count: usize,
    /// Severity increased
    pub severity_increased: usize,
    /// Severity decreased
    pub severity_decreased: usize,
    /// Overall risk change
    pub risk_change: i8, // -100 to +100
    /// Comparison timestamp
    pub compared_at: DateTime<Utc>,
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    /// Generate a report from findings
    pub fn generate(&self, findings: &[Finding], scans: &[ScanInfo], targets: &[TargetInfo]) -> Report {
        let metadata = self.build_metadata(findings, scans, targets);
        let executive_summary = if self.config.include_executive_summary {
            Some(self.build_executive_summary(findings, scans))
        } else {
            None
        };
        let findings_by_group = self.group_findings(findings);
        let statistics = self.calculate_statistics(findings);

        Report {
            metadata,
            executive_summary,
            findings_by_group,
            all_findings: findings.to_vec(),
            statistics,
            scan_comparison: None,
            appendices: self.build_appendices(findings, scans),
        }
    }

    /// Generate a comparison report
    pub fn generate_comparison(
        &self,
        baseline_findings: &[Finding],
        current_findings: &[Finding],
        baseline_scan: &ScanInfo,
        current_scan: &ScanInfo,
    ) -> Report {
        let comparison = self.compare_scans(baseline_findings, current_findings, baseline_scan, current_scan);
        
        let metadata = ReportMetadata {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("Scan Comparison: {} vs {}", baseline_scan.name, current_scan.name),
            generated_at: Utc::now(),
            generator_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_ids: vec![baseline_scan.id, current_scan.id],
            project_id: baseline_scan.project_id,
            targets: vec![],
            date_range: Some(DateRange {
                from: baseline_scan.started_at.unwrap_or_else(Utc::now),
                to: current_scan.completed_at.unwrap_or_else(Utc::now),
            }),
            format: ReportFormat::Markdown,
            config: self.config.clone(),
        };

        Report {
            metadata,
            executive_summary: Some(self.build_comparison_executive_summary(&comparison)),
            findings_by_group: HashMap::new(),
            all_findings: current_findings.to_vec(),
            statistics: self.calculate_statistics(current_findings),
            scan_comparison: Some(comparison),
            appendices: vec![],
        }
    }

    /// Build report metadata
    fn build_metadata(&self, findings: &[Finding], scans: &[ScanInfo], targets: &[TargetInfo]) -> ReportMetadata {
        let scan_ids: Vec<ScanId> = scans.iter().map(|s| s.id).collect();
        let project_id = scans.first().and_then(|s| s.project_id);

        let date_range = if !scans.is_empty() {
            let from = scans.iter()
                .filter_map(|s| s.started_at)
                .min()
                .unwrap_or_else(Utc::now);
            let to = scans.iter()
                .filter_map(|s| s.completed_at)
                .max()
                .unwrap_or_else(Utc::now);
            Some(DateRange { from, to })
        } else {
            None
        };

        ReportMetadata {
            id: uuid::Uuid::new_v4().to_string(),
            title: self.config.branding.as_ref()
                .and_then(|b| b.title_prefix.clone())
                .unwrap_or_else(|| "Security Assessment Report".to_string()),
            generated_at: Utc::now(),
            generator_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_ids,
            project_id,
            targets: targets.to_vec(),
            date_range,
            format: ReportFormat::Markdown,
            config: self.config.clone(),
        }
    }

    /// Build executive summary
    fn build_executive_summary(&self, findings: &[Finding], scans: &[ScanInfo]) -> ExecutiveSummary {
        let mut by_severity = HashMap::new();
        let mut total_risk = 0u32;
        let mut risk_count = 0;
        let mut key_findings = Vec::new();

        for finding in findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
            if let Some(score) = finding.risk_score {
                total_risk += score as u32;
                risk_count += 1;
            }
        }

        let critical_count = *by_severity.get(&Severity::Critical).unwrap_or(&0);
        let high_count = *by_severity.get(&Severity::High).unwrap_or(&0);

        // Get top 5 findings by risk score
        let mut sorted_findings = findings.to_vec();
        sorted_findings.sort_by(|a, b| {
            b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0))
                .then_with(|| b.severity.cmp(&a.severity))
        });

        for finding in sorted_findings.iter().take(5) {
            key_findings.push(KeyFinding {
                id: finding.id.to_string(),
                title: finding.title.clone(),
                severity: finding.severity,
                target: finding.target.clone(),
                category: finding.category.clone(),
                risk_score: finding.risk_score.unwrap_or(0),
                summary: finding.summary(),
            });
        }

        let overall_risk_score = if risk_count > 0 { (total_risk.checked_div(risk_count).unwrap_or(0)) as u8 } else { 0 };
        let risk_level = Self::calculate_risk_level(overall_risk_score, critical_count, high_count);

        let scan_coverage = ScanCoverage {
            targets_scanned: scans.iter().map(|s| s.target_id.to_string()).collect::<std::collections::HashSet<_>>().len(),
            endpoints_tested: scans.iter().map(|s| s.progress.endpoints_scanned).sum(),
            plugins_executed: scans.iter().map(|s| s.plugin_executions.len()).sum(),
            scan_duration_seconds: scans.iter()
                .filter_map(|s| s.duration)
                .map(|d| d.as_secs())
                .sum(),
            coverage_percentage: None,
        };

        let recommendations = self.generate_recommendations(findings, &by_severity);

        ExecutiveSummary {
            total_findings: findings.len(),
            by_severity,
            overall_risk_score,
            risk_level,
            critical_count,
            high_count,
            key_findings,
            scan_coverage,
            recommendations,
        }
    }

    /// Build comparison executive summary
    fn build_comparison_executive_summary(&self, comparison: &ScanComparison) -> ExecutiveSummary {
        let mut by_severity = HashMap::new();
        
        for finding in &comparison.new_findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
        }
        for finding in &comparison.regressed_findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
        }

        let critical_count = *by_severity.get(&Severity::Critical).unwrap_or(&0);
        let high_count = *by_severity.get(&Severity::High).unwrap_or(&0);

        ExecutiveSummary {
            total_findings: comparison.new_findings.len() + comparison.regressed_findings.len(),
            by_severity,
            overall_risk_score: 0, // Calculated differently for comparison
            risk_level: RiskLevel::Informational,
            critical_count,
            high_count,
            key_findings: vec![],
            scan_coverage: ScanCoverage {
                targets_scanned: 0,
                endpoints_tested: 0,
                plugins_executed: 0,
                scan_duration_seconds: 0,
                coverage_percentage: None,
            },
            recommendations: vec![
                format!("{} new findings detected", comparison.new_findings.len()),
                format!("{} findings fixed", comparison.fixed_findings.len()),
                format!("{} findings regressed", comparison.regressed_findings.len()),
            ],
        }
    }

    /// Calculate overall risk level
    fn calculate_risk_level(score: u8, critical: usize, high: usize) -> RiskLevel {
        if critical > 0 || score >= 80 {
            RiskLevel::Critical
        } else if high > 0 || score >= 60 {
            RiskLevel::High
        } else if score >= 40 {
            RiskLevel::Medium
        } else if score >= 20 {
            RiskLevel::Low
        } else {
            RiskLevel::Informational
        }
    }

    /// Generate recommendations
    fn generate_recommendations(&self, findings: &[Finding], by_severity: &HashMap<Severity, usize>) -> Vec<String> {
        let mut recommendations = Vec::new();

        if *by_severity.get(&Severity::Critical).unwrap_or(&0) > 0 {
            recommendations.push("Immediately address critical findings - they pose imminent risk".to_string());
        }
        if *by_severity.get(&Severity::High).unwrap_or(&0) > 0 {
            recommendations.push("Prioritize high-severity findings for remediation within 7 days".to_string());
        }
        if *by_severity.get(&Severity::Medium).unwrap_or(&0) > 5 {
            recommendations.push("Address medium-severity findings in next sprint cycle".to_string());
        }

        // Category-specific recommendations
        let categories: std::collections::HashSet<Category> = findings.iter().map(|f| f.category.clone()).collect();
        if categories.contains(&Category::Injection) {
            recommendations.push("Implement input validation and parameterized queries to prevent injection".to_string());
        }
        if categories.contains(&Category::Xss) {
            recommendations.push("Implement Content Security Policy and output encoding for XSS prevention".to_string());
        }
        if categories.contains(&Category::BrokenAuthentication) {
            recommendations.push("Review authentication mechanisms and implement MFA".to_string());
        }
        if categories.contains(&Category::BrokenAccessControl) {
            recommendations.push("Implement proper authorization checks and RBAC".to_string());
        }
        if categories.contains(&Category::SensitiveDataExposure) {
            recommendations.push("Encrypt sensitive data at rest and in transit".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("No critical issues found. Continue regular security assessments.".to_string());
        }

        recommendations
    }

    /// Group findings by configured grouping
    fn group_findings(&self, findings: &[Finding]) -> HashMap<String, Vec<Finding>> {
        let mut groups = HashMap::new();

        for finding in findings {
            // Apply minimum severity filter
            if let Some(min_sev) = self.config.min_severity {
                if finding.severity < min_sev {
                    continue;
                }
            }

            let group_key = match self.config.group_by {
                GroupBy::Severity => finding.severity.to_string(),
                GroupBy::Category => finding.category.to_string(),
                GroupBy::Target => finding.target.clone(),
                GroupBy::Plugin => finding.plugin_source.clone(),
                GroupBy::OwaspCategory => finding.owasp_category.clone().unwrap_or_else(|| "Uncategorized".to_string()),
                GroupBy::None => "All Findings".to_string(),
            };

            groups.entry(group_key).or_insert_with(Vec::new).push(finding.clone());
        }

        // Sort within each group
        for findings in groups.values_mut() {
            self.sort_findings(findings);
            
            // Apply max findings per category limit
            if let Some(max) = self.config.max_findings_per_category {
                if findings.len() > max {
                    findings.truncate(max);
                }
            }
        }

        groups
    }

    /// Sort findings according to config
    fn sort_findings(&self, findings: &mut [Finding]) {
        match self.config.sort_by {
            FindingSort::SeverityDesc => findings.sort_by_key(|b| std::cmp::Reverse(b.severity)),
            FindingSort::SeverityAsc => findings.sort_by_key(|a| a.severity),
            FindingSort::ConfidenceDesc => findings.sort_by_key(|b| std::cmp::Reverse(b.confidence)),
            FindingSort::TimestampDesc => findings.sort_by_key(|b| std::cmp::Reverse(b.timestamp)),
            FindingSort::TimestampAsc => findings.sort_by_key(|a| a.timestamp),
            FindingSort::RiskScoreDesc => findings.sort_by_key(|b| std::cmp::Reverse(b.risk_score.unwrap_or(0))),
            FindingSort::TargetAsc => findings.sort_by_key(|a| a.target.clone()),
        }
    }

    /// Calculate statistics
    fn calculate_statistics(&self, findings: &[Finding]) -> FindingStats {
        let mut by_severity = HashMap::new();
        let mut by_confidence = HashMap::new();
        let mut by_category = HashMap::new();
        let mut by_plugin = HashMap::new();
        let mut by_owasp_category = HashMap::new();
        let mut by_cwe = HashMap::new();
        let mut by_remediation_priority = HashMap::new();
        let mut verified = 0;
        let mut false_positives = 0;
        let mut total_risk_score = 0u32;
        let mut total_advanced_risk_score = 0u32;
        let mut risk_score_count = 0;
        let mut exploit_available_count = 0;
        let mut exploited_in_wild_count = 0;
        let mut max_risk_score = 0u8;
        let mut max_advanced_risk_score = 0u8;

        for finding in findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
            *by_confidence.entry(finding.confidence).or_insert(0) += 1;
            *by_category.entry(finding.category.clone()).or_insert(0) += 1;
            *by_plugin.entry(finding.plugin_source.clone()).or_insert(0) += 1;

            if let Some(owasp) = &finding.owasp_category {
                *by_owasp_category.entry(owasp.clone()).or_insert(0) += 1;
            }

            for cwe in &finding.cwe_ids {
                *by_cwe.entry(cwe.clone()).or_insert(0) += 1;
            }

            if let Some(remediation) = &finding.remediation {
                *by_remediation_priority.entry(remediation.priority).or_insert(0) += 1;
            }

            if finding.verified { verified += 1; }
            if finding.false_positive { false_positives += 1; }

            if let Some(score) = finding.risk_score {
                total_risk_score += score as u32;
                risk_score_count += 1;
                max_risk_score = max_risk_score.max(score);
            }

            let advanced_score = finding.calculate_advanced_risk_score();
            total_advanced_risk_score += advanced_score as u32;
            max_advanced_risk_score = max_advanced_risk_score.max(advanced_score);

            if let Some(exploitability) = &finding.exploitability {
                if exploitability.exploit_available { exploit_available_count += 1; }
                if exploitability.exploited_in_wild { exploited_in_wild_count += 1; }
            }
        }

        FindingStats {
            total: findings.len(),
            by_severity,
            by_confidence,
            by_category,
            by_plugin,
            verified,
            false_positives,
            avg_risk_score: if risk_score_count > 0 { total_risk_score as f32 / risk_score_count as f32 } else { 0.0 },
            max_risk_score,
            by_owasp_category,
            by_cwe,
            avg_advanced_risk_score: if risk_score_count > 0 { total_advanced_risk_score as f32 / risk_score_count as f32 } else { 0.0 },
            max_advanced_risk_score,
            by_remediation_priority,
            exploit_available_count,
            exploited_in_wild_count,
        }
    }

    /// Build appendices
    fn build_appendices(&self, findings: &[Finding], scans: &[ScanInfo]) -> Vec<Appendix> {
        let mut appendices = Vec::new();

        // Methodology
        appendices.push(Appendix {
            title: "Methodology".to_string(),
            content: "This assessment was performed using automated security scanning tools...".to_string(),
            appendix_type: AppendixType::Methodology,
        });

        // Tool versions
        let tool_versions = scans.iter()
            .flat_map(|s| &s.plugin_executions)
            .map(|p| format!("{} v{}", p.plugin_name, p.plugin_version))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n");
        appendices.push(Appendix {
            title: "Tool Versions".to_string(),
            content: tool_versions,
            appendix_type: AppendixType::ToolVersions,
        });

        // Scope
        let targets: Vec<String> = findings.iter()
            .map(|f| f.target.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        appendices.push(Appendix {
            title: "Scope".to_string(),
            content: format!("Targets assessed:\n{}", targets.join("\n")),
            appendix_type: AppendixType::Scope,
        });

        // Glossary
        appendices.push(Appendix {
            title: "Glossary".to_string(),
            content: self.build_glossary(),
            appendix_type: AppendixType::Glossary,
        });

        appendices
    }

    /// Build glossary
    fn build_glossary(&self) -> String {
        r#"
**Severity Levels:**
- **Critical**: Immediate threat, active exploitation likely
- **High**: Significant risk, should be remediated quickly
- **Medium**: Moderate risk, address in normal cycle
- **Low**: Minor risk, address when convenient
- **Info**: Informational, no direct risk

**Confidence Levels:**
- **Very High**: Confirmed vulnerability with proof of concept
- **High**: Strong evidence of vulnerability
- **Medium**: Reasonable evidence
- **Low**: Weak evidence, needs verification
- **Very Low**: Speculative, minimal evidence

**Risk Score:** 0-100 scale combining severity, confidence, exploitability, and business impact.

**OWASP Top 10:** Industry standard classification of web application security risks.

**CWE:** Common Weakness Enumeration - standardized vulnerability classification.

**CVSS:** Common Vulnerability Scoring System - standardized severity scoring.
        "#.to_string()
    }

    /// Compare two scans
    fn compare_scans(
        &self,
        baseline: &[Finding],
        current: &[Finding],
        baseline_scan: &ScanInfo,
        current_scan: &ScanInfo,
    ) -> ScanComparison {
        // Build fingerprint maps
        let baseline_map: HashMap<String, &Finding> = baseline.iter()
            .filter_map(|f| f.fingerprint.as_ref().map(|fp| (fp.clone(), f)))
            .collect();
        let current_map: HashMap<String, &Finding> = current.iter()
            .filter_map(|f| f.fingerprint.as_ref().map(|fp| (fp.clone(), f)))
            .collect();

        let mut new_findings = Vec::new();
        let mut fixed_findings = Vec::new();
        let mut regressed_findings = Vec::new();
        let mut severity_changes = Vec::new();
        let mut evidence_changes = Vec::new();

        // Find new and changed findings
        for (fp, current_finding) in &current_map {
            if let Some(baseline_finding) = baseline_map.get(fp) {
                // Check severity change
                if current_finding.severity != baseline_finding.severity {
                    severity_changes.push(SeverityChange {
                        fingerprint: fp.clone(),
                        previous_severity: baseline_finding.severity,
                        current_severity: current_finding.severity,
                        title: current_finding.title.clone(),
                        target: current_finding.target.clone(),
                    });
                }

                // Check evidence changes
                if current_finding.evidence.len() != baseline_finding.evidence.len() {
                    evidence_changes.push(EvidenceChange {
                        fingerprint: fp.clone(),
                        change_type: if current_finding.evidence.len() > baseline_finding.evidence.len() {
                            EvidenceChangeType::Added
                        } else {
                            EvidenceChangeType::Removed
                        },
                        description: format!("Evidence count changed from {} to {}", 
                            baseline_finding.evidence.len(), current_finding.evidence.len()),
                        title: current_finding.title.clone(),
                        target: current_finding.target.clone(),
                    });
                }

                // Check if regressed (was fixed, now reappeared)
                if baseline_finding.false_positive && !current_finding.false_positive {
                    regressed_findings.push((*current_finding).clone());
                }
            } else {
                // New finding
                new_findings.push((*current_finding).clone());
            }
        }

        // Find fixed findings
        for (fp, baseline_finding) in &baseline_map {
            if !current_map.contains_key(fp) {
                fixed_findings.push((*baseline_finding).clone());
            }
        }

        let summary = ComparisonSummary {
            new_count: new_findings.len(),
            fixed_count: fixed_findings.len(),
            regressed_count: regressed_findings.len(),
            severity_increased: severity_changes.iter().filter(|c| c.current_severity > c.previous_severity).count(),
            severity_decreased: severity_changes.iter().filter(|c| c.current_severity < c.previous_severity).count(),
            risk_change: 0, // Would need more complex calculation
            compared_at: Utc::now(),
        };

        ScanComparison {
            baseline_scan_id: baseline_scan.id,
            current_scan_id: current_scan.id,
            new_findings,
            fixed_findings,
            regressed_findings,
            severity_changes,
            evidence_changes,
            summary,
        }
    }

    /// Render report to string in specified format
    pub fn render(&self, report: &Report, format: ReportFormat) -> String {
        match format {
            ReportFormat::Markdown => self.render_markdown(report),
            ReportFormat::Html => self.render_html(report),
            ReportFormat::Json => self.render_json(report),
            ReportFormat::Sarif => self.render_sarif(report),
            ReportFormat::Pdf => self.render_markdown(report), // PDF would need external tool
        }
    }

    /// Render as Markdown
    fn render_markdown(&self, report: &Report) -> String {
        let mut md = String::new();

        // Title
        md.push_str(&format!("# {}\n\n", report.metadata.title));
        
        // Metadata
        md.push_str("## Report Information\n\n");
        md.push_str(&format!("- **Report ID**: {}\n", report.metadata.id));
        md.push_str(&format!("- **Generated**: {}\n", report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        md.push_str(&format!("- **Generator Version**: {}\n", report.metadata.generator_version));
        md.push_str(&format!("- **Scans**: {}\n", report.metadata.scan_ids.len()));
        if let Some(project_id) = report.metadata.project_id {
            md.push_str(&format!("- **Project**: {}\n", project_id));
        }
        if let Some(range) = &report.metadata.date_range {
            md.push_str(&format!("- **Period**: {} to {}\n", 
                range.from.format("%Y-%m-%d"), range.to.format("%Y-%m-%d")));
        }
        md.push_str("\n");

        // Executive Summary
        if let Some(summary) = &report.executive_summary {
            md.push_str("## Executive Summary\n\n");
            md.push_str(&format!("- **Total Findings**: {}\n", summary.total_findings));
            md.push_str(&format!("- **Overall Risk Score**: {}/100\n", summary.overall_risk_score));
            md.push_str(&format!("- **Risk Level**: {:?}\n", summary.risk_level));
            md.push_str(&format!("- **Critical**: {}\n", summary.critical_count));
            md.push_str(&format!("- **High**: {}\n", summary.high_count));
            md.push_str("\n");

            md.push_str("### Findings by Severity\n\n");
            for (sev, count) in &summary.by_severity {
                md.push_str(&format!("- **{:?}**: {}\n", sev, count));
            }
            md.push_str("\n");

            if !summary.key_findings.is_empty() {
                md.push_str("### Key Findings\n\n");
                for kf in &summary.key_findings {
                    md.push_str(&format!("- **[{} {}]** {} ({})\n", kf.severity, kf.risk_score, kf.title, kf.target));
                }
                md.push_str("\n");
            }

            if !summary.recommendations.is_empty() {
                md.push_str("### Recommendations\n\n");
                for rec in &summary.recommendations {
                    md.push_str(&format!("- {}\n", rec));
                }
                md.push_str("\n");
            }
        }

        // Findings by group
        md.push_str("## Findings\n\n");
        for (group, findings) in &report.findings_by_group {
            md.push_str(&format!("### {}\n\n", group));
            for finding in findings {
                md.push_str(&self.render_finding_markdown(finding));
            }
        }

        // Statistics
        md.push_str("## Statistics\n\n");
        md.push_str(&self.render_statistics_markdown(&report.statistics));

        // Scan comparison
        if let Some(comparison) = &report.scan_comparison {
            md.push_str("## Scan Comparison\n\n");
            md.push_str(&self.render_comparison_markdown(comparison));
        }

        // Appendices
        for appendix in &report.appendices {
            md.push_str(&format!("## Appendix: {}\n\n", appendix.title));
            md.push_str(&format!("{}\n\n", appendix.content));
        }

        md
    }

    /// Render a single finding as Markdown
    fn render_finding_markdown(&self, finding: &Finding) -> String {
        let mut md = String::new();
        
        md.push_str(&format!("#### {} [{}]\n\n", finding.title, finding.severity));
        md.push_str(&format!("**Target**: {}  \n", finding.target));
        md.push_str(&format!("**Category**: {}  \n", finding.category));
        md.push_str(&format!("**Severity**: {}  \n", finding.severity));
        md.push_str(&format!("**Confidence**: {}  \n", finding.confidence));
        md.push_str(&format!("**Risk Score**: {}/100  \n", finding.risk_score.unwrap_or(0)));
        md.push_str(&format!("**Plugin**: {} v{}  \n", finding.plugin_source, finding.plugin_version));
        md.push_str(&format!("**Discovered**: {}  \n", finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        
        if let Some(owasp) = &finding.owasp_category {
            md.push_str(&format!("**OWASP**: {}  \n", owasp));
        }
        
        if !finding.cwe_ids.is_empty() {
            md.push_str(&format!("**CWE**: {}  \n", finding.cwe_ids.join(", ")));
        }
        
        if !finding.cvss_vector.is_none() {
            md.push_str(&format!("**CVSS**: {} ({})  \n", finding.cvss_vector.as_ref().unwrap(), finding.cvss_score.unwrap_or(0.0)));
        }

        md.push_str("\n**Description**:\n\n");
        md.push_str(&format!("{}\n\n", finding.description));

        if self.config.include_evidence && !finding.evidence.is_empty() {
            md.push_str("**Evidence**:\n\n");
            for evidence in &finding.evidence {
                md.push_str(&format!("- **{}**: {}\n", evidence.evidence_type, evidence.description));
                if let Some(loc) = &evidence.location {
                    md.push_str(&format!("  - Location: {}\n", loc));
                }
                if let Some(req) = &evidence.http_request {
                    md.push_str(&format!("  - Request: {} {}\n", req.method, req.url));
                }
                if let Some(resp) = &evidence.http_response {
                    md.push_str(&format!("  - Response: {} ({}) bytes\n", resp.status_code, resp.size_bytes.unwrap_or(0)));
                }
                if let Some(payload) = &evidence.payload {
                    md.push_str(&format!("  - Payload: {} ({})\n", payload.payload, payload.payload_type));
                }
            }
            md.push_str("\n");
        }

        if self.config.include_remediation {
            if let Some(remediation) = &finding.remediation {
                md.push_str("**Remediation**:\n\n");
                md.push_str(&format!("{}\n\n", remediation.summary));
                md.push_str(&format!("**Priority**: {:?}  \n", remediation.priority));
                md.push_str(&format!("**Effort**: {:?}  \n", remediation.effort));
                if !remediation.steps.is_empty() {
                    md.push_str("**Steps**:\n");
                    for (i, step) in remediation.steps.iter().enumerate() {
                        md.push_str(&format!("{}. {}\n", i + 1, step));
                    }
                    md.push_str("\n");
                }
                if !remediation.code_examples.is_empty() {
                    md.push_str("**Code Examples**:\n\n");
                    for example in &remediation.code_examples {
                        md.push_str(&format!("**{}** (Vulnerable):\n```{}\n{}\n```\n\n", example.language, example.language, example.vulnerable));
                        md.push_str(&format!("**{}** (Fixed):\n```{}\n{}\n```\n\n", example.language, example.language, example.fixed));
                        md.push_str(&format!("*{}*\n\n", example.explanation));
                    }
                }
            }
        }

        if self.config.include_reproduction {
            if let Some(evidence) = finding.evidence.first() {
                if let Some(repro) = &evidence.reproduction_steps {
                    md.push_str("**Reproduction Steps**:\n\n");
                    for (i, step) in repro.steps.iter().enumerate() {
                        md.push_str(&format!("{}. {}\n", i + 1, step));
                    }
                    md.push_str(&format!("\n**Expected**: {}\n\n", repro.expected_outcome));
                    md.push_str(&format!("**Actual**: {}\n\n", repro.actual_outcome));
                }
            }
        }

        if !finding.references.is_empty() {
            md.push_str("**References**:\n\n");
            for ref_ in &finding.references {
                md.push_str(&format!("- [{}]({}) - {}\n", ref_.title, ref_.url, ref_.description.as_deref().unwrap_or("")));
            }
            md.push_str("\n");
        }

        md.push_str("---\n\n");
        md
    }

    /// Render statistics as Markdown
    fn render_statistics_markdown(&self, stats: &FindingStats) -> String {
        let mut md = String::new();
        
        md.push_str(&format!("- **Total Findings**: {}\n", stats.total));
        md.push_str(&format!("- **Verified**: {}\n", stats.verified));
        md.push_str(&format!("- **False Positives**: {}\n", stats.false_positives));
        md.push_str(&format!("- **Average Risk Score**: {:.1}\n", stats.avg_risk_score));
        md.push_str(&format!("- **Max Risk Score**: {}\n", stats.max_risk_score));
        md.push_str(&format!("- **Average Advanced Risk Score**: {:.1}\n", stats.avg_advanced_risk_score));
        md.push_str(&format!("- **Max Advanced Risk Score**: {}\n", stats.max_advanced_risk_score));
        md.push_str(&format!("- **Exploit Available**: {}\n", stats.exploit_available_count));
        md.push_str(&format!("- **Exploited in Wild**: {}\n", stats.exploited_in_wild_count));
        md.push_str("\n");

        md.push_str("### By Severity\n\n");
        for (sev, count) in &stats.by_severity {
            md.push_str(&format!("- **{:?}**: {}\n", sev, count));
        }
        md.push_str("\n");

        md.push_str("### By Category\n\n");
        for (cat, count) in &stats.by_category {
            md.push_str(&format!("- **{}**: {}\n", cat, count));
        }
        md.push_str("\n");

        if !stats.by_owasp_category.is_empty() {
            md.push_str("### By OWASP Category\n\n");
            for (owasp, count) in &stats.by_owasp_category {
                md.push_str(&format!("- **{}**: {}\n", owasp, count));
            }
            md.push_str("\n");
        }

        if !stats.by_cwe.is_empty() {
            md.push_str("### Top CWEs\n\n");
            let mut cwes: Vec<_> = stats.by_cwe.iter().collect();
            cwes.sort_by(|a, b| b.1.cmp(a.1));
            for (cwe, count) in cwes.iter().take(10) {
                md.push_str(&format!("- **{}**: {}\n", cwe, count));
            }
            md.push_str("\n");
        }

        md
    }

    /// Render comparison as Markdown
    fn render_comparison_markdown(&self, comparison: &ScanComparison) -> String {
        let mut md = String::new();
        
        md.push_str(&format!("- **Baseline Scan**: {}\n", comparison.baseline_scan_id));
        md.push_str(&format!("- **Current Scan**: {}\n", comparison.current_scan_id));
        md.push_str(&format!("- **Compared**: {}\n", comparison.summary.compared_at.format("%Y-%m-%d %H:%M:%S UTC")));
        md.push_str("\n");

        md.push_str("### Summary\n\n");
        md.push_str(&format!("- **New Findings**: {}\n", comparison.summary.new_count));
        md.push_str(&format!("- **Fixed Findings**: {}\n", comparison.summary.fixed_count));
        md.push_str(&format!("- **Regressed Findings**: {}\n", comparison.summary.regressed_count));
        md.push_str(&format!("- **Severity Increased**: {}\n", comparison.summary.severity_increased));
        md.push_str(&format!("- **Severity Decreased**: {}\n", comparison.summary.severity_decreased));
        md.push_str("\n");

        if !comparison.new_findings.is_empty() {
            md.push_str("### New Findings\n\n");
            for finding in &comparison.new_findings {
                md.push_str(&format!("- **[{} {}]** {} ({})\n", finding.severity, finding.risk_score.unwrap_or(0), finding.title, finding.target));
            }
            md.push_str("\n");
        }

        if !comparison.fixed_findings.is_empty() {
            md.push_str("### Fixed Findings\n\n");
            for finding in &comparison.fixed_findings {
                md.push_str(&format!("- **[{} {}]** {} ({})\n", finding.severity, finding.risk_score.unwrap_or(0), finding.title, finding.target));
            }
            md.push_str("\n");
        }

        if !comparison.regressed_findings.is_empty() {
            md.push_str("### Regressed Findings\n\n");
            for finding in &comparison.regressed_findings {
                md.push_str(&format!("- **[{} {}]** {} ({})\n", finding.severity, finding.risk_score.unwrap_or(0), finding.title, finding.target));
            }
            md.push_str("\n");
        }

        if !comparison.severity_changes.is_empty() {
            md.push_str("### Severity Changes\n\n");
            for change in &comparison.severity_changes {
                md.push_str(&format!("- **{}**: {:?} → {:?} ({})\n", change.title, change.previous_severity, change.current_severity, change.target));
            }
            md.push_str("\n");
        }

        md
    }

    /// Render as HTML
    fn render_html(&self, report: &Report) -> String {
        let markdown = self.render_markdown(report);
        // Simple markdown to HTML conversion (in production, use a proper library)
        let html = markdown
            .replace("# ", "<h1>")
            .replace("\n", "</h1>\n")
            .replace("## ", "<h2>")
            .replace("### ", "<h3>")
            .replace("#### ", "<h4>")
            .replace("**", "<strong>")
            .replace("* ", "<li>")
            .replace("\n", "</li>\n");
        
        format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>{}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h2 {{ color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
        h3 {{ color: #666; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .finding {{ border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin: 20px 0; }}
    </style>
</head>
<body>
{}
</body>
</html>"#, report.metadata.title, html)
    }

    /// Render as JSON
    fn render_json(&self, report: &Report) -> String {
        serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Render as SARIF
    fn render_sarif(&self, report: &Report) -> String {
        let mut sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "open-re",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/open-re/open-re",
                        "rules": []
                    }
                },
                "results": []
            }]
        });

        let mut rule_map = std::collections::HashMap::new();
        let mut rule_index = 0;

        for finding in &report.all_findings {
            let rule_id = format!("{}-{}", finding.category, finding.plugin_source);
            let rule_idx = *rule_map.entry(rule_id.clone()).or_insert_with(|| {
                let idx = rule_index;
                rule_index += 1;
                idx
            });

            // Add rule if new
            if rule_idx == rule_index - 1 {
                let rule = serde_json::json!({
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": { "text": finding.description },
                    "fullDescription": { "text": finding.description },
                    "defaultConfiguration": { "level": Self::severity_to_sarif_level(finding.severity) },
                    "help": { "text": finding.description, "markdown": finding.description },
                    "properties": {
                        "category": finding.category.to_string(),
                        "severity": finding.severity.to_string(),
                        "confidence": finding.confidence.to_string(),
                        "plugin": finding.plugin_source,
                        "riskScore": finding.risk_score.unwrap_or(0)
                    }
                });
                sarif["runs"][0]["tool"]["driver"]["rules"].as_array_mut().unwrap().push(rule);
            }

            // Add result
            let result = serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": Self::severity_to_sarif_level(finding.severity),
                "message": { "text": finding.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.target },
                        "region": { "startLine": 1 }
                    }
                }],
                "properties": {
                    "confidence": finding.confidence.to_string(),
                    "riskScore": finding.risk_score.unwrap_or(0),
                    "cvssVector": finding.cvss_vector,
                    "cvssScore": finding.cvss_score,
                    "cweIds": finding.cwe_ids,
                    "owaspCategory": finding.owasp_category,
                    "pluginSource": finding.plugin_source,
                    "timestamp": finding.timestamp.to_rfc3339()
                }
            });
            sarif["runs"][0]["results"].as_array_mut().unwrap().push(result);
        }

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    }

    /// Convert severity to SARIF level
    fn severity_to_sarif_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::Info => "note",
        }
    }
}

/// Scan information for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    /// Scan ID
    pub id: ScanId,
    /// Scan name
    pub name: String,
    /// Project ID
    pub project_id: Option<ProjectId>,
    /// Target ID
    pub target_id: crate::ids::TargetId,
    /// Scan status
    pub status: String,
    /// Scan progress
    pub progress: ScanProgress,
    /// Plugin executions
    pub plugin_executions: Vec<PluginExecutionInfo>,
    /// Started at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Duration
    pub duration: Option<std::time::Duration>,
}

/// Plugin execution info for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionInfo {
    /// Plugin ID
    pub plugin_id: crate::ids::PluginId,
    /// Plugin name
    pub plugin_name: String,
    /// Plugin version
    pub plugin_version: String,
    /// Status
    pub status: String,
    /// Findings count
    pub findings_count: usize,
    /// Duration
    pub duration: Option<std::time::Duration>,
}

/// Scan progress for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Total endpoints
    pub total_endpoints: usize,
    /// Endpoints scanned
    pub endpoints_scanned: usize,
    /// Current plugin
    pub current_plugin: Option<String>,
    /// Percentage complete
    pub percentage: f32,
    /// Estimated time remaining
    pub eta_seconds: Option<u64>,
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self {
            total_endpoints: 0,
            endpoints_scanned: 0,
            current_plugin: None,
            percentage: 0.0,
            eta_seconds: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ScanId, ProjectId, TargetId};
    use chrono::Utc;

    fn create_test_finding() -> Finding {
        let scan_id = ScanId::new();
        Finding::new(
            "SQL Injection".to_string(),
            "SQL injection in login form".to_string(),
            Severity::High,
            Confidence::High,
            Category::Injection,
            "https://example.com/login".to_string(),
            "rest_api".to_string(),
            "sql-injection-scanner".to_string(),
            "1.0.0".to_string(),
            scan_id,
        )
    }

    fn create_test_scan() -> ScanInfo {
        ScanInfo {
            id: ScanId::new(),
            name: "Test Scan".to_string(),
            project_id: Some(ProjectId::new()),
            target_id: TargetId::new(),
            status: "completed".to_string(),
            progress: ScanProgress::default(),
            plugin_executions: vec![],
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            duration: Some(std::time::Duration::from_secs(60)),
        }
    }

    #[test]
    fn test_report_generation() {
        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config);
        
        let findings = vec![create_test_finding()];
        let scans = vec![create_test_scan()];
        let targets = vec![];
        
        let report = generator.generate(&findings, &scans, &targets);
        
        assert_eq!(report.all_findings.len(), 1);
        assert!(report.executive_summary.is_some());
        assert!(!report.findings_by_group.is_empty());
    }

    #[test]
    fn test_markdown_rendering() {
        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config);
        
        let findings = vec![create_test_finding()];
        let scans = vec![create_test_scan()];
        let targets = vec![];
        
        let report = generator.generate(&findings, &scans, &targets);
        let markdown = generator.render(&report, ReportFormat::Markdown);
        
        assert!(markdown.contains("SQL Injection"));
        assert!(markdown.contains("High"));
        assert!(markdown.contains("example.com"));
    }

    #[test]
    fn test_json_rendering() {
        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config);
        
        let findings = vec![create_test_finding()];
        let scans = vec![create_test_scan()];
        let targets = vec![];
        
        let report = generator.generate(&findings, &scans, &targets);
        let json = generator.render(&report, ReportFormat::Json);
        
        assert!(json.contains("SQL Injection"));
        assert!(json.contains("findings"));
    }

    #[test]
    fn test_sarif_rendering() {
        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config);
        
        let findings = vec![create_test_finding()];
        let scans = vec![create_test_scan()];
        let targets = vec![];
        
        let report = generator.generate(&findings, &scans, &targets);
        let sarif = generator.render(&report, ReportFormat::Sarif);
        
        assert!(sarif.contains("sarif"));
        assert!(sarif.contains("runs"));
        assert!(sarif.contains("results"));
    }

    #[test]
    fn test_comparison_report() {
        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config);
        
        let mut baseline = create_test_finding();
        baseline.fingerprint = Some("fp1".to_string());
        baseline.false_positive = true;
        
        let mut current = create_test_finding();
        current.fingerprint = Some("fp1".to_string());
        current.false_positive = false;
        current.severity = Severity::Critical;
        
        let baseline_scan = create_test_scan();
        let mut current_scan = create_test_scan();
        current_scan.id = ScanId::new();
        
        let report = generator.generate_comparison(&[baseline], &[current], &baseline_scan, &current_scan);
        
        assert!(report.scan_comparison.is_some());
        let comparison = report.scan_comparison.unwrap();
        assert_eq!(comparison.regressed_findings.len(), 1);
        assert_eq!(comparison.severity_changes.len(), 1);
    }
}