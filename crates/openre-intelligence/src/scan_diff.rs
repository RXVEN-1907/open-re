//! Scan Diff Intelligence - Compare scans for changes and identify significant differences

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use chrono::{DateTime, Utc};
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Confidence, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

/// Metadata describing a scan used for diffing
#[derive(Debug, Clone)]
pub struct ScanMetadata {
    pub scan_id: ScanId,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub target: String,
    pub plugins_used: Vec<String>,
    pub configuration: HashMap<String, serde_json::Value>,
    pub tags: Vec<String>,
}

/// Configuration for scan diff analysis
#[derive(Debug, Clone)]
pub struct ScanDiffConfig {
    /// Enable detection of new critical findings
    pub enable_new_critical_detection: bool,

    /// Enable detection of resolved findings
    pub enable_resolved_detection: bool,

    /// Enable trend analysis over multiple scans
    pub enable_trend_analysis: bool,

    /// Minimum severity to consider for significant changes
    pub min_severity_for_significant_change: SeverityLevel,

    /// Time window for considering findings as related (in hours)
    pub time_window_hours: i64,

    /// Threshold for considering a change significant (% of total findings)
    pub significance_threshold_percent: f32,
}

impl Default for ScanDiffConfig {
    fn default() -> Self {
        Self {
            enable_new_critical_detection: true,
            enable_resolved_detection: true,
            enable_trend_analysis: true,
            min_severity_for_significant_change: SeverityLevel::High,
            time_window_hours: 24,
            significance_threshold_percent: 10.0, // 10% change is significant
        }
    }
}

/// Scan diff analyzer for comparing security scans over time
pub struct ScanDiffAnalyzer {
    config: ScanDiffConfig,
}

impl ScanDiffAnalyzer {
    /// Create a new scan diff analyzer with default configuration
    pub fn new() -> Self {
        Self { config: ScanDiffConfig::default() }
    }

    /// Create a new scan diff analyzer with custom configuration
    pub fn with_config(config: ScanDiffConfig) -> Self {
        Self { config }
    }

    /// Compare two scans and analyze the differences
    pub fn compare_scans(
        &self,
        previous_scan: &ScanData,
        current_scan: &ScanData,
    ) -> IntelligenceResult<ScanDiffAnalysis> {
        let previous_findings = &previous_scan.findings;
        let current_findings = &current_scan.findings;

        // Findings are matched across scans by fingerprint when available,
        // falling back to the finding title so re-discovered issues correlate
        // even when ids differ between scanner runs.
        fn identity_key(f: &Finding) -> String {
            f.fingerprint.clone().unwrap_or_else(|| format!("title:{}", f.title))
        }

        let previous_map: HashMap<String, &Finding> =
            previous_findings.iter().map(|f| (identity_key(f), f)).collect();
        let current_map: HashMap<String, &Finding> =
            current_findings.iter().map(|f| (identity_key(f), f)).collect();

        // Identify new findings
        let new_findings: Vec<&Finding> = current_findings
            .iter()
            .filter(|f| !previous_map.contains_key(&identity_key(f)))
            .collect();

        // Identify resolved findings
        let resolved_findings: Vec<&Finding> = previous_findings
            .iter()
            .filter(|f| !current_map.contains_key(&identity_key(f)))
            .collect();

        // Identify persistent findings (in both scans)
        let persistent_findings: Vec<(&Finding, &Finding)> = current_findings
            .iter()
            .filter_map(|current_finding| {
                previous_map
                    .get(&identity_key(current_finding))
                    .map(|prev_finding| (*prev_finding, current_finding))
            })
            .collect();

        // Analyze changes in severity/confidence
        let mut severity_changes = Vec::new();
        let mut confidence_changes = Vec::new();

        for (prev_finding, current_finding) in &persistent_findings {
            if prev_finding.severity != current_finding.severity {
                let change_type = if current_finding.severity > prev_finding.severity {
                    SeverityChangeType::Increased
                } else {
                    SeverityChangeType::Decreased
                };
                let change_magnitude = (current_finding.severity.value() as i8)
                    - (prev_finding.severity.value() as i8);
                severity_changes.push(SeverityChange {
                    finding_id: current_finding.id,
                    fingerprint: current_finding
                        .fingerprint
                        .clone()
                        .unwrap_or_else(|| current_finding.id.to_string()),
                    previous_severity: prev_finding.severity.into(),
                    current_severity: current_finding.severity.into(),
                    change_magnitude,
                    change_type,
                });
            }

            if prev_finding.confidence != current_finding.confidence {
                confidence_changes.push(ConfidenceChange {
                    finding_id: current_finding.id,
                    previous_confidence: prev_finding.confidence.into(),
                    current_confidence: current_finding.confidence.into(),
                    change_type: if current_finding.confidence > prev_finding.confidence {
                        ConfidenceChangeType::Increased
                    } else {
                        ConfidenceChangeType::Decreased
                    },
                });
            }
        }

        // Identify significant new findings based on severity
        let significant_new_findings: Vec<&Finding> = new_findings
            .iter()
            .filter(|f| f.severity >= self.config.min_severity_for_significant_change.into())
            .copied()
            .collect();

        // Identify critical new findings regardless of threshold
        let critical_new_findings: Vec<&Finding> = new_findings
            .iter()
            .filter(|f| f.severity == Severity::Critical.into())
            .copied()
            .collect();

        // Calculate statistics
        let total_previous = previous_findings.len();
        let total_current = current_findings.len();
        let net_change = total_current as i32 - total_previous as i32;
        let change_percent = if total_previous > 0 {
            (net_change.abs() as f32 / total_previous as f32) * 100.0
        } else {
            100.0 // If previous was empty, consider any findings as 100% change
        };

        let is_significant_change = change_percent >= self.config.significance_threshold_percent
            || !critical_new_findings.is_empty()
            || severity_changes.iter().any(|sc| {
                matches!(sc.change_type, SeverityChangeType::Increased)
                    && sc.current_severity >= self.config.min_severity_for_significant_change
            });

        // Detailed trend analysis (optional)
        let trend_analysis = if self.config.enable_trend_analysis {
            Some(self.analyze_trends(previous_scan, current_scan)?)
        } else {
            None
        };

        // Simple risk trend derived from net finding count and trend direction
        let risk_direction = match &trend_analysis {
            Some(trend) => {
                if trend
                    .worsening_trends
                    .iter()
                    .any(|t| t.severity >= self.config.min_severity_for_significant_change)
                {
                    TrendDirection::Worsening
                } else if trend
                    .improving_trends
                    .iter()
                    .any(|t| t.severity >= self.config.min_severity_for_significant_change)
                {
                    TrendDirection::Improving
                } else {
                    TrendDirection::Stable
                }
            }
            None => TrendDirection::Stable,
        };
        let risk_trend = RiskTrend {
            overall_change: net_change.clamp(i8::MIN as i32, i8::MAX as i32) as i8,
            trend_direction: risk_direction,
            key_factors: vec![
                format!("{} new findings", new_findings.len()),
                format!("{} resolved findings", resolved_findings.len()),
                format!("{} severity changes", severity_changes.len()),
            ],
        };

        // Create the analysis result
        let analysis = ScanDiffAnalysis {
            baseline_scan_id: previous_scan.metadata.scan_id,
            previous_scan_id: previous_scan.metadata.scan_id,
            current_scan_id: current_scan.metadata.scan_id,
            comparison_timestamp: Utc::now(),
            total_findings_previous: total_previous,
            total_findings_current: total_current,
            net_change,
            change_percentage: change_percent,
            is_significant_change,
            new_findings: new_findings.iter().map(|f| f.id).collect(),
            fixed_findings: Vec::new(),
            regressed_findings: Vec::new(),
            resolved_findings: resolved_findings.iter().map(|f| f.id).collect(),
            persistent_findings: persistent_findings
                .iter()
                .map(|(_, current)| current.id)
                .collect(),
            significant_new_findings: significant_new_findings.iter().map(|f| f.id).collect(),
            critical_new_findings: critical_new_findings.iter().map(|f| f.id).collect(),
            severity_changes,
            confidence_changes,
            technology_changes: Vec::new(),
            trend_analysis,
            risk_trend,
        };

        Ok(analysis)
    }

    /// Analyze trends over multiple scans
    fn analyze_trends(
        &self,
        previous_scan: &ScanData,
        current_scan: &ScanData,
    ) -> IntelligenceResult<TrendAnalysis> {
        // For now, we'll implement a basic trend analysis
        // In a real implementation, this would look at historical scan data

        let previous_findings = &previous_scan.findings;
        let current_findings = &current_scan.findings;

        // Count findings by severity in both scans
        let mut prev_severity_counts = HashMap::new();
        let mut curr_severity_counts = HashMap::new();

        for finding in previous_findings {
            *prev_severity_counts.entry(finding.severity).or_insert(0) += 1;
        }

        for finding in current_findings {
            *curr_severity_counts.entry(finding.severity).or_insert(0) += 1;
        }

        // Identify trends
        let mut improving_trends = Vec::new();
        let mut worsening_trends = Vec::new();

        // Check each severity level for changes
        for severity in &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let prev_count = *prev_severity_counts.get(&(*severity).into()).unwrap_or(&0);
            let curr_count = *curr_severity_counts.get(&(*severity).into()).unwrap_or(&0);

            if curr_count < prev_count {
                improving_trends.push(SeverityTrend {
                    severity: *severity,
                    previous_count: prev_count,
                    current_count: curr_count,
                    change: prev_count as i32 - curr_count as i32,
                });
            } else if curr_count > prev_count {
                worsening_trends.push(SeverityTrend {
                    severity: *severity,
                    previous_count: prev_count,
                    current_count: curr_count,
                    change: curr_count as i32 - prev_count as i32,
                });
            }
        }

        let trend_direction = if worsening_trends
            .iter()
            .any(|t| t.severity >= self.config.min_severity_for_significant_change)
        {
            TrendDirection::Worsening
        } else if improving_trends
            .iter()
            .any(|t| t.severity >= self.config.min_severity_for_significant_change)
        {
            TrendDirection::Improving
        } else {
            TrendDirection::Stable
        };

        Ok(TrendAnalysis {
            trend_direction,
            improving_trends,
            worsening_trends,
            time_period_hours: 24, // Default assumption
        })
    }

    /// Generate a human-readable diff report
    pub fn generate_diff_report(
        &self,
        analysis: &ScanDiffAnalysis,
        previous_scan: &ScanData,
        current_scan: &ScanData,
    ) -> String {
        let mut report = String::new();
        report.push_str("# Scan Difference Analysis Report\n\n");

        // Basic statistics
        report.push_str("## Summary\n");
        report
            .push_str(&format!("- Previous scan findings: {}\n", analysis.total_findings_previous));
        report.push_str(&format!("- Current scan findings: {}\n", analysis.total_findings_current));
        report.push_str(&format!(
            "- Net change: {:+} ({:+.1}%)\n",
            analysis.net_change, analysis.change_percentage
        ));

        if analysis.is_significant_change {
            report.push_str("- **SIGNIFICANT CHANGE DETECTED**\n");
        } else {
            report.push_str("- No significant changes detected\n");
        }

        report.push('\n');

        // New findings
        if !analysis.new_findings.is_empty() {
            report.push_str(&format!("## New Findings ({})\n", analysis.new_findings.len()));

            // Critical new findings
            if !analysis.critical_new_findings.is_empty() {
                report.push_str(&format!(
                    "### Critical New Findings ({})\n",
                    analysis.critical_new_findings.len()
                ));
                for finding_id in &analysis.critical_new_findings {
                    if let Some(finding) =
                        current_scan.findings.iter().find(|f| f.id == *finding_id)
                    {
                        report.push_str(&format!(
                            "- **{}** - {}\n",
                            finding.title, finding.description
                        ));
                    }
                }
                report.push('\n');
            }

            // Significant new findings
            if !analysis.significant_new_findings.is_empty() {
                report.push_str(&format!(
                    "### Significant New Findings ({})\n",
                    analysis.significant_new_findings.len()
                ));
                for finding_id in &analysis.significant_new_findings {
                    if let Some(finding) =
                        current_scan.findings.iter().find(|f| f.id == *finding_id)
                    {
                        report.push_str(&format!(
                            "- **{}** ({:?}) - {}\n",
                            finding.title, finding.severity, finding.description
                        ));
                    }
                }
                report.push('\n');
            }

            // All new findings
            if analysis.new_findings.len()
                > (analysis.critical_new_findings.len() + analysis.significant_new_findings.len())
            {
                report.push_str("### Other New Findings\n");
                for finding_id in &analysis.new_findings {
                    // Skip if already listed above
                    if !analysis.critical_new_findings.contains(finding_id)
                        && !analysis.significant_new_findings.contains(finding_id)
                    {
                        if let Some(finding) =
                            current_scan.findings.iter().find(|f| f.id == *finding_id)
                        {
                            report.push_str(&format!(
                                "- {} ({:?})\n",
                                finding.title, finding.severity
                            ));
                        }
                    }
                }
                report.push('\n');
            }
        }

        // Resolved findings
        if !analysis.resolved_findings.is_empty() {
            report.push_str(&format!(
                "## Resolved Findings ({})\n",
                analysis.resolved_findings.len()
            ));

            let critical_resolved: Vec<FindingId> = analysis
                .resolved_findings
                .iter()
                .filter(|id| {
                    previous_scan
                        .findings
                        .iter()
                        .find(|f| &f.id == *id)
                        .map(|f| f.severity == Severity::Critical.into())
                        .unwrap_or(false)
                })
                .copied()
                .collect();

            if !critical_resolved.is_empty() {
                report.push_str(&format!(
                    "### Critical Issues Resolved ({})\n",
                    critical_resolved.len()
                ));
                for finding_id in &critical_resolved {
                    if let Some(finding) =
                        previous_scan.findings.iter().find(|f| &f.id == finding_id)
                    {
                        report
                            .push_str(&format!("- {} - {}\n", finding.title, finding.description));
                    }
                }
                report.push('\n');
            }

            // Show other resolved findings
            if analysis.resolved_findings.len() > critical_resolved.len() {
                report.push_str("### Other Resolved Issues\n");
                for finding_id in &analysis.resolved_findings {
                    if !critical_resolved.contains(finding_id) {
                        if let Some(finding) =
                            previous_scan.findings.iter().find(|f| &f.id == finding_id)
                        {
                            report.push_str(&format!(
                                "- {} ({:?})\n",
                                finding.title, finding.severity
                            ));
                        }
                    }
                }
                report.push('\n');
            }
        }

        // Severity changes
        if !analysis.severity_changes.is_empty() {
            report
                .push_str(&format!("## Severity Changes ({})\n", analysis.severity_changes.len()));

            let increased_severity: Vec<&SeverityChange> = analysis
                .severity_changes
                .iter()
                .filter(|sc| matches!(sc.change_type, SeverityChangeType::Increased))
                .collect();

            let decreased_severity: Vec<&SeverityChange> = analysis
                .severity_changes
                .iter()
                .filter(|sc| matches!(sc.change_type, SeverityChangeType::Decreased))
                .collect();

            if !increased_severity.is_empty() {
                report
                    .push_str(&format!("### Severity Increased ({})\n", increased_severity.len()));
                for change in &increased_severity {
                    if let Some(finding) =
                        current_scan.findings.iter().find(|f| f.id == change.finding_id)
                    {
                        report.push_str(&format!(
                            "- {} - {:?} → {:?}\n",
                            finding.title,
                            Severity::from(change.previous_severity),
                            Severity::from(change.current_severity)
                        ));
                    }
                }
                report.push('\n');
            }

            if !decreased_severity.is_empty() {
                report
                    .push_str(&format!("### Severity Decreased ({})\n", decreased_severity.len()));
                for change in &decreased_severity {
                    if let Some(finding) =
                        current_scan.findings.iter().find(|f| f.id == change.finding_id)
                    {
                        report.push_str(&format!(
                            "- {} - {:?} → {:?}\n",
                            finding.title,
                            Severity::from(change.previous_severity),
                            Severity::from(change.current_severity)
                        ));
                    }
                }
                report.push('\n');
            }
        }

        // Trend analysis
        if let Some(trend) = &analysis.trend_analysis {
            report.push_str("## Trend Analysis\n");
            match trend.trend_direction {
                TrendDirection::Improving => {
                    report.push_str("- **Overall Security Posture: IMPROVING**\n")
                }
                TrendDirection::Worsening => {
                    report.push_str("- **Overall Security Posture: WORSENING**\n")
                }
                TrendDirection::Stable => report.push_str("- Overall Security Posture: Stable\n"),
                TrendDirection::Mixed => {
                    report.push_str("- Overall Security Posture: MIXED RESULTS\n")
                }
            }

            if !trend.improving_trends.is_empty() {
                report.push_str("\n### Improvements\n");
                for trend_item in &trend.improving_trends {
                    report.push_str(&format!(
                        "- {:?} findings decreased: {} → {}\n",
                        trend_item.severity, trend_item.previous_count, trend_item.current_count
                    ));
                }
            }

            if !trend.worsening_trends.is_empty() {
                report.push_str("\n### Deteriorations\n");
                for trend_item in &trend.worsening_trends {
                    report.push_str(&format!(
                        "- {:?} findings increased: {} → {}\n",
                        trend_item.severity, trend_item.previous_count, trend_item.current_count
                    ));
                }
            }

            report.push('\n');
        }

        // Recommendations
        report.push_str("## Recommendations\n");

        if !analysis.critical_new_findings.is_empty() {
            report.push_str("- **IMMEDIATE ACTION REQUIRED**: Address all critical new findings\n");
        }

        if analysis.net_change > 0 {
            report.push_str(&format!(
                "- Investigate the {} new findings, particularly those with high severity\n",
                analysis.new_findings.len()
            ));
        }

        if !analysis.severity_changes.is_empty() {
            let increased_count = analysis
                .severity_changes
                .iter()
                .filter(|sc| matches!(sc.change_type, SeverityChangeType::Increased))
                .count();
            if increased_count > 0 {
                report.push_str(&format!(
                    "- Review {} findings with increased severity\n",
                    increased_count
                ));
            }
        }

        if let Some(trend) = &analysis.trend_analysis {
            match trend.trend_direction {
                TrendDirection::Improving => {
                    report.push_str(
                        "- Continue current security practices that are showing positive results\n",
                    );
                }
                TrendDirection::Worsening => {
                    report.push_str(
                        "- Review recent changes that may have introduced new vulnerabilities\n",
                    );
                    report.push_str("- Consider additional security testing before deployment\n");
                }
                TrendDirection::Stable => {
                    report.push_str("- Maintain current security practices while monitoring for emerging threats\n");
                }
                TrendDirection::Mixed => {
                    report.push_str(
                        "- Review mixed results to understand which areas improved or regressed\n",
                    );
                }
            }
        }

        report
    }

    /// Identify findings that require immediate attention
    pub fn identify_priority_findings(
        &self,
        analysis: &ScanDiffAnalysis,
        current_scan: &ScanData,
    ) -> Vec<FindingId> {
        let mut priority_findings = HashSet::new();

        // All critical new findings
        priority_findings.extend(analysis.critical_new_findings.iter());

        // Significant new findings
        priority_findings.extend(analysis.significant_new_findings.iter());

        // Findings with increased severity to high/critical
        for change in &analysis.severity_changes {
            if matches!(change.change_type, SeverityChangeType::Increased)
                && change.current_severity >= self.config.min_severity_for_significant_change
            {
                priority_findings.insert(change.finding_id);
            }
        }

        // Convert to vector
        priority_findings.into_iter().collect()
    }
}

/// Data structure representing a scan for diff analysis
#[derive(Debug, Clone)]
pub struct ScanData {
    pub metadata: ScanMetadata,
    pub findings: Vec<Finding>,
}

impl ScanData {
    pub fn new(metadata: ScanMetadata, findings: Vec<Finding>) -> Self {
        Self { metadata, findings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use std::collections::HashMap;

    fn create_test_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity,
            confidence: Confidence::High,
            category: Category::Injection,
            target: "https://example.com".to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: Some(60),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some(format!("test-fp-{}", title)),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    fn create_test_scan_data(findings: Vec<Finding>) -> ScanData {
        let scan_id = ScanId::new();
        let metadata = ScanMetadata {
            scan_id,
            start_time: Utc::now(),
            end_time: Some(Utc::now()),
            target: "https://example.com".to_string(),
            plugins_used: vec!["test-plugin".to_string()],
            configuration: HashMap::new(),
            tags: Vec::new(),
        };

        ScanData::new(metadata, findings)
    }

    #[test]
    fn test_scan_comparison_basic() {
        let analyzer = ScanDiffAnalyzer::new();

        // Create previous scan with 2 findings
        let prev_findings = vec![
            create_test_finding("SQL Injection", Severity::High),
            create_test_finding("XSS", Severity::Medium),
        ];
        let previous_scan = create_test_scan_data(prev_findings);

        // Create current scan with 3 findings (1 new, 1 existing, 1 different)
        let mut curr_findings = vec![
            create_test_finding("SQL Injection", Severity::High), // Same as before
            create_test_finding("CSRF", Severity::Medium),        // New finding
            create_test_finding("Path Traversal", Severity::Critical), // New critical finding
        ];
        // Add the existing finding with a different ID to simulate a new finding
        curr_findings.push(create_test_finding("Command Injection", Severity::High));

        let current_scan = create_test_scan_data(curr_findings);

        let analysis = analyzer.compare_scans(&previous_scan, &current_scan).unwrap();

        // Should have 3 new findings (CSRF, Path Traversal, Command Injection)
        assert_eq!(analysis.new_findings.len(), 3);

        // Should have 1 resolved finding (XSS)
        assert_eq!(analysis.resolved_findings.len(), 1);

        // Should have 1 persistent finding (SQL Injection)
        assert_eq!(analysis.persistent_findings.len(), 1);

        // Should identify 1 critical new finding
        assert_eq!(analysis.critical_new_findings.len(), 1);

        // Should be a significant change due to the critical finding
        assert!(analysis.is_significant_change);
    }

    #[test]
    fn test_severity_change_detection() {
        let analyzer = ScanDiffAnalyzer::new();

        // Create previous scan with a medium severity finding
        let prev_findings = vec![create_test_finding("Vulnerable Component", Severity::Medium)];
        let previous_scan = create_test_scan_data(prev_findings);

        // Create current scan with the same finding but higher severity
        let mut curr_findings = vec![create_test_finding("Vulnerable Component", Severity::High)];
        // Add another finding to avoid empty current scan
        curr_findings.push(create_test_finding("New Finding", Severity::Low));

        let current_scan = create_test_scan_data(curr_findings);

        let analysis = analyzer.compare_scans(&previous_scan, &current_scan).unwrap();

        // Should detect the severity change
        assert_eq!(analysis.severity_changes.len(), 1);

        let severity_change = &analysis.severity_changes[0];
        assert_eq!(severity_change.change_type, SeverityChangeType::Increased);
        assert_eq!(severity_change.previous_severity, Severity::Medium);
        assert_eq!(severity_change.current_severity, Severity::High);
    }

    #[test]
    fn test_no_significant_change() {
        let analyzer = ScanDiffAnalyzer::new();

        // Create two scans with similar findings
        let prev_findings = vec![
            create_test_finding("Finding 1", Severity::Low),
            create_test_finding("Finding 2", Severity::Low),
        ];
        let previous_scan = create_test_scan_data(prev_findings);

        let curr_findings = vec![
            create_test_finding("Finding 1", Severity::Low),
            create_test_finding("Finding 3", Severity::Low), // Replaced one finding
        ];
        let current_scan = create_test_scan_data(curr_findings);

        let analysis = analyzer.compare_scans(&previous_scan, &current_scan).unwrap();

        // Should not be a significant change (only low severity findings)
        assert!(!analysis.is_significant_change);
        assert_eq!(analysis.new_findings.len(), 1);
        assert_eq!(analysis.resolved_findings.len(), 1);
    }

    #[test]
    fn test_priority_findings_identification() {
        let analyzer = ScanDiffAnalyzer::new();

        // Create a mock analysis with critical and significant findings
        let critical_finding_id = FindingId::new();
        let significant_finding_id = FindingId::new();
        let increased_severity_id = FindingId::new();

        let analysis = ScanDiffAnalysis {
            baseline_scan_id: ScanId::new(),
            previous_scan_id: ScanId::new(),
            current_scan_id: ScanId::new(),
            comparison_timestamp: Utc::now(),
            total_findings_previous: 5,
            total_findings_current: 8,
            net_change: 3,
            change_percentage: 60.0,
            is_significant_change: true,
            new_findings: vec![critical_finding_id, significant_finding_id],
            fixed_findings: vec![],
            regressed_findings: vec![],
            resolved_findings: vec![],
            persistent_findings: vec![increased_severity_id],
            significant_new_findings: vec![significant_finding_id],
            critical_new_findings: vec![critical_finding_id],
            severity_changes: vec![SeverityChange {
                finding_id: increased_severity_id,
                fingerprint: "test-fingerprint".to_string(),
                previous_severity: Severity::Medium,
                current_severity: Severity::High,
                change_magnitude: 1,
                change_type: SeverityChangeType::Increased,
            }],
            confidence_changes: vec![],
            technology_changes: vec![],
            trend_analysis: None,
            risk_trend: RiskTrend {
                overall_change: 20,
                trend_direction: TrendDirection::Worsening,
                key_factors: vec!["New critical findings".to_string()],
            },
        };

        let curr_findings = vec![
            create_test_finding("Critical Finding", Severity::Critical),
            create_test_finding("Significant Finding", Severity::High),
            create_test_finding("Increased Severity", Severity::High),
        ];
        let current_scan = create_test_scan_data(curr_findings);

        let priority_findings = analyzer.identify_priority_findings(&analysis, &current_scan);

        // Should identify all three as priority findings
        assert_eq!(priority_findings.len(), 3);
        assert!(priority_findings.contains(&critical_finding_id));
        assert!(priority_findings.contains(&significant_finding_id));
        assert!(priority_findings.contains(&increased_severity_id));
    }
}
