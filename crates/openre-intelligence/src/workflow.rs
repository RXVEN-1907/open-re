//! Workflow Features - Finding acknowledgment, false positive marking, ignore rules

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use chrono::{DateTime, Utc};
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Finding, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Configuration for workflow features
#[derive(Debug, Clone)]
pub struct WorkflowConfig {
    /// Enable finding acknowledgment tracking
    pub enable_acknowledgment: bool,

    /// Enable false positive marking
    pub enable_false_positive: bool,

    /// Enable ignore rules
    pub enable_ignore_rules: bool,

    /// Default expiration time for temporary ignores (in days)
    pub default_temp_ignore_days: u32,

    /// Maximum number of ignore rules allowed
    pub max_ignore_rules: usize,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            enable_acknowledgment: true,
            enable_false_positive: true,
            enable_ignore_rules: true,
            default_temp_ignore_days: 30,
            max_ignore_rules: 1000,
        }
    }
}

/// Workflow manager for handling finding lifecycle
pub struct WorkflowManager {
    config: WorkflowConfig,
    acknowledged_findings: HashMap<FindingId, Acknowledgment>,
    false_positives: HashMap<FindingId, FalsePositiveRecord>,
    ignore_rules: Vec<IgnoreRule>,
    ignore_patterns: Vec<Arc<Regex>>,
}

impl WorkflowManager {
    /// Create a new workflow manager with default configuration
    pub fn new() -> Self {
        Self {
            config: WorkflowConfig::default(),
            acknowledged_findings: HashMap::new(),
            false_positives: HashMap::new(),
            ignore_rules: Vec::new(),
            ignore_patterns: Vec::new(),
        }
    }

    /// Create a new workflow manager with custom configuration
    pub fn with_config(config: WorkflowConfig) -> Self {
        Self {
            config,
            acknowledged_findings: HashMap::new(),
            false_positives: HashMap::new(),
            ignore_rules: Vec::new(),
            ignore_patterns: Vec::new(),
        }
    }

    /// Acknowledge a finding
    pub fn acknowledge_finding(
        &mut self,
        finding_id: FindingId,
        user: &str,
        notes: Option<&str>,
    ) -> IntelligenceResult<()> {
        if !self.config.enable_acknowledgment {
            return Err(IntelligenceError::WorkflowFeatureDisabled(
                "acknowledgment".to_string(),
            ));
        }

        let acknowledgment = Acknowledgment {
            finding_id,
            acknowledged_by: user.to_string(),
            acknowledged_at: Utc::now(),
            notes: notes.map(|s| s.to_string()),
            status: AcknowledgmentStatus::Acknowledged,
        };

        self.acknowledged_findings
            .insert(finding_id, acknowledgment);
        Ok(())
    }

    /// Mark a finding as false positive
    pub fn mark_false_positive(
        &mut self,
        finding_id: FindingId,
        user: &str,
        reason: &str,
    ) -> IntelligenceResult<()> {
        if !self.config.enable_false_positive {
            return Err(IntelligenceError::WorkflowFeatureDisabled(
                "false positive".to_string(),
            ));
        }

        let record = FalsePositiveRecord {
            finding_id,
            marked_by: user.to_string(),
            marked_at: Utc::now(),
            reason: reason.to_string(),
            evidence: None, // Could be extended to include evidence
        };

        self.false_positives.insert(finding_id, record);

        // Also acknowledge the finding when marking as false positive
        self.acknowledge_finding(finding_id, user, Some("Marked as false positive"))?;

        Ok(())
    }

    /// Add an ignore rule for a specific pattern
    pub fn add_ignore_rule(&mut self, rule: IgnoreRule) -> IntelligenceResult<()> {
        if !self.config.enable_ignore_rules {
            return Err(IntelligenceError::WorkflowFeatureDisabled(
                "ignore rules".to_string(),
            ));
        }

        // Check limit
        if self.ignore_rules.len() >= self.config.max_ignore_rules {
            return Err(IntelligenceError::IgnoreRuleLimitExceeded(
                self.config.max_ignore_rules,
            ));
        }

        // Compile regex pattern for faster matching
        let regex = Regex::new(&rule.pattern)
            .map_err(|e| IntelligenceError::InvalidIgnorePattern(e.to_string()))?;

        self.ignore_patterns.push(Arc::new(regex));
        self.ignore_rules.push(rule);

        Ok(())
    }

    /// Temporarily ignore a finding for a specified number of days
    pub fn temporarily_ignore_finding(
        &mut self,
        finding: &Finding,
        user: &str,
        days: Option<u32>,
    ) -> IntelligenceResult<()> {
        if !self.config.enable_ignore_rules {
            return Err(IntelligenceError::WorkflowFeatureDisabled(
                "ignore rules".to_string(),
            ));
        }

        let ignore_days = days.unwrap_or(self.config.default_temp_ignore_days);

        // Create a fingerprint-based ignore rule
        let pattern = if let Some(fingerprint) = &finding.fingerprint {
            format!("fingerprint:{}", fingerprint)
        } else {
            // Fallback to title-based pattern
            format!(r"title:\b{}\b", regex::escape(&finding.title))
        };

        let rule = IgnoreRule {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: pattern.clone(),
            reason: "Temporary ignore".to_string(),
            author: user.to_string(),
            created_by: user.to_string(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(ignore_days as i64)),
            scope: IgnoreScope {
                targets: vec![finding.target.clone()],
                categories: vec![finding.category.clone()],
                severities: vec![finding.severity],
                tags: Vec::new(),
            },
            severity_threshold: None, // Apply to this specific finding
            target_pattern: Some(regex::escape(&finding.target)),
        };

        self.add_ignore_rule(rule)?;
        Ok(())
    }

    /// Check if a finding should be ignored based on rules
    pub fn should_ignore_finding(&self, finding: &Finding) -> bool {
        if !self.config.enable_ignore_rules {
            return false;
        }

        // Check if explicitly marked as false positive
        if self.false_positives.contains_key(&finding.id) {
            return true;
        }

        // Check ignore rules
        for (i, regex) in self.ignore_patterns.iter().enumerate() {
            if i < self.ignore_rules.len() {
                let rule = &self.ignore_rules[i];

                // Check expiration
                if let Some(expires_at) = rule.expires_at {
                    if Utc::now() > expires_at {
                        continue; // Skip expired rules
                    }
                }

                // Check severity threshold
                if let Some(threshold) = rule.severity_threshold {
                    if finding.severity < threshold.into() {
                        continue; // Below threshold, skip rule
                    }
                }

                // Check target pattern if specified
                if let Some(target_pattern) = &rule.target_pattern {
                    if let Ok(target_regex) = Regex::new(target_pattern) {
                        if !target_regex.is_match(&finding.target) {
                            continue; // Target doesn't match, skip rule
                        }
                    }
                }

                // Check if finding matches the ignore pattern
                let finding_text = format!(
                    "title:{} description:{} target:{} fingerprint:{}",
                    finding.title,
                    finding.description,
                    finding.target,
                    finding.fingerprint.as_deref().unwrap_or("")
                );

                if regex.is_match(&finding_text) {
                    return true;
                }
            }
        }

        false
    }

    /// Get acknowledgment status for a finding
    pub fn get_acknowledgment_status(&self, finding_id: FindingId) -> Option<&Acknowledgment> {
        self.acknowledged_findings.get(&finding_id)
    }

    /// Get false positive status for a finding
    pub fn get_false_positive_status(&self, finding_id: FindingId) -> Option<&FalsePositiveRecord> {
        self.false_positives.get(&finding_id)
    }

    /// List all active ignore rules
    pub fn list_ignore_rules(&self) -> &[IgnoreRule] {
        &self.ignore_rules
    }

    /// Remove expired ignore rules
    pub fn cleanup_expired_rules(&mut self) -> usize {
        let now = Utc::now();
        let initial_count = self.ignore_rules.len();

        // Retain only non-expired rules
        let mut active_rules = Vec::new();
        let mut active_patterns = Vec::new();

        for (i, rule) in self.ignore_rules.iter().enumerate() {
            if let Some(expires_at) = rule.expires_at {
                if now <= expires_at {
                    // Keep active rule
                    if i < self.ignore_patterns.len() {
                        active_rules.push(rule.clone());
                        active_patterns.push(self.ignore_patterns[i].clone());
                    }
                }
            } else {
                // Keep rules without expiration
                if i < self.ignore_patterns.len() {
                    active_rules.push(rule.clone());
                    active_patterns.push(self.ignore_patterns[i].clone());
                }
            }
        }

        self.ignore_rules = active_rules;
        self.ignore_patterns = active_patterns;

        initial_count - self.ignore_rules.len()
    }

    /// Process findings through workflow filters
    pub fn process_findings(
        &mut self,
        findings: &mut Vec<Finding>,
    ) -> IntelligenceResult<WorkflowProcessingResult> {
        let mut result = WorkflowProcessingResult {
            total_findings: findings.len(),
            acknowledged_count: 0,
            false_positive_count: 0,
            ignored_count: 0,
            remaining_count: 0,
            filtered_findings: Vec::new(),
        };

        // Clean up expired rules first
        let expired_count = self.cleanup_expired_rules();
        if expired_count > 0 {
            info!("Cleaned up {} expired ignore rules", expired_count);
        }

        // Filter findings based on workflow status
        let mut filtered_findings = Vec::new();

        for finding in findings.drain(..) {
            let finding_id = finding.id;

            // Check if marked as false positive FIRST (FP implies acknowledgment)
            if self.false_positives.contains_key(&finding_id) {
                result.false_positive_count += 1;
                // Add metadata and filter out
                let mut updated_finding = finding.clone();
                updated_finding.metadata.insert(
                    "workflow_false_positive".to_string(),
                    serde_json::Value::Bool(true),
                );
                if let Some(fp) = self.false_positives.get(&finding_id) {
                    updated_finding.metadata.insert(
                        "workflow_false_positive_marked_by".to_string(),
                        serde_json::Value::String(fp.marked_by.clone()),
                    );
                    updated_finding.metadata.insert(
                        "workflow_false_positive_reason".to_string(),
                        serde_json::Value::String(fp.reason.clone()),
                    );
                }
                // Don't add to filtered findings - remove from results
                continue;
            }

            // Check if acknowledged
            if self.acknowledged_findings.contains_key(&finding_id) {
                result.acknowledged_count += 1;
                // Acknowledged findings are tracked and excluded from active results
                continue;
            }

            // Check if should be ignored by rules
            if self.should_ignore_finding(&finding) {
                result.ignored_count += 1;
                // Add metadata and filter out
                let mut updated_finding = finding.clone();
                updated_finding.metadata.insert(
                    "workflow_ignored".to_string(),
                    serde_json::Value::Bool(true),
                );
                // Don't add to filtered findings - remove from results
                continue;
            }

            // Finding passes all filters, keep it
            filtered_findings.push(finding);
        }

        result.remaining_count = filtered_findings.len();
        result.filtered_findings = filtered_findings;

        *findings = result.filtered_findings.clone();

        Ok(result)
    }

    /// Generate workflow status report
    pub fn generate_workflow_report(&mut self) -> String {
        let mut report = String::new();
        report.push_str("# Workflow Status Report\n\n");

        report.push_str(&format!("## Summary\n"));
        report.push_str(&format!(
            "- Acknowledged findings: {}\n",
            self.acknowledged_findings.len()
        ));
        report.push_str(&format!(
            "- False positive findings: {}\n",
            self.false_positives.len()
        ));
        report.push_str(&format!(
            "- Active ignore rules: {}\n",
            self.ignore_rules.len()
        ));
        report.push_str(&format!(
            "- Expired rules cleaned up: {}\n\n",
            self.cleanup_expired_rules()
        ));

        if !self.acknowledged_findings.is_empty() {
            report.push_str("## Acknowledged Findings\n");
            for (finding_id, ack) in &self.acknowledged_findings {
                report.push_str(&format!(
                    "- {} by {} at {}\n",
                    finding_id,
                    ack.acknowledged_by,
                    ack.acknowledged_at.format("%Y-%m-%d %H:%M:%S")
                ));
                if let Some(notes) = &ack.notes {
                    report.push_str(&format!("  Notes: {}\n", notes));
                }
            }
            report.push('\n');
        }

        if !self.false_positives.is_empty() {
            report.push_str("## False Positive Findings\n");
            for (finding_id, fp) in &self.false_positives {
                report.push_str(&format!(
                    "- {} by {} at {}\n",
                    finding_id,
                    fp.marked_by,
                    fp.marked_at.format("%Y-%m-%d %H:%M:%S")
                ));
                report.push_str(&format!("  Reason: {}\n", fp.reason));
            }
            report.push('\n');
        }

        if !self.ignore_rules.is_empty() {
            report.push_str("## Active Ignore Rules\n");
            for rule in &self.ignore_rules {
                report.push_str(&format!("- Pattern: {}\n", rule.pattern));
                report.push_str(&format!("  Reason: {}\n", rule.reason));
                report.push_str(&format!(
                    "  Created by: {} at {}\n",
                    rule.created_by,
                    rule.created_at.format("%Y-%m-%d %H:%M:%S")
                ));

                if let Some(expires_at) = rule.expires_at {
                    report.push_str(&format!(
                        "  Expires at: {}\n",
                        expires_at.format("%Y-%m-%d %H:%M:%S")
                    ));
                }

                if let Some(threshold) = rule.severity_threshold {
                    report.push_str(&format!("  Severity threshold: {:?}\n", threshold));
                }

                if let Some(target_pattern) = &rule.target_pattern {
                    report.push_str(&format!("  Target pattern: {}\n", target_pattern));
                }

                report.push('\n');
            }
        }

        report
    }

    /// Export workflow data for persistence
    pub fn export_workflow_data(&self) -> WorkflowDataSnapshot {
        WorkflowDataSnapshot {
            acknowledged_findings: self.acknowledged_findings.clone(),
            false_positives: self.false_positives.clone(),
            ignore_rules: self.ignore_rules.clone(),
            exported_at: Utc::now(),
        }
    }

    /// Import workflow data from a snapshot
    pub fn import_workflow_data(
        &mut self,
        snapshot: WorkflowDataSnapshot,
    ) -> IntelligenceResult<()> {
        self.acknowledged_findings = snapshot.acknowledged_findings;
        self.false_positives = snapshot.false_positives;
        self.ignore_rules = snapshot.ignore_rules;

        // Re-compile regex patterns
        self.ignore_patterns.clear();
        for rule in &self.ignore_rules {
            if let Ok(regex) = Regex::new(&rule.pattern) {
                self.ignore_patterns.push(Arc::new(regex));
            } else {
                warn!("Failed to compile ignore pattern: {}", rule.pattern);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openre_core::ids::FindingId;
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
            fingerprint: Some(format!(
                "test-fingerprint-{}",
                title.to_lowercase().replace(" ", "-")
            )),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[test]
    fn test_finding_acknowledgment() {
        let mut manager = WorkflowManager::new();
        let finding_id = FindingId::new();
        let user = "test_user";

        // Acknowledge a finding
        assert!(manager
            .acknowledge_finding(finding_id, user, Some("Test acknowledgment"))
            .is_ok());

        // Check acknowledgment status
        let ack_status = manager.get_acknowledgment_status(finding_id);
        assert!(ack_status.is_some());

        let ack = ack_status.unwrap();
        assert_eq!(ack.finding_id, finding_id);
        assert_eq!(ack.acknowledged_by, user);
        assert_eq!(ack.notes, Some("Test acknowledgment".to_string()));
        assert_eq!(ack.status, AcknowledgmentStatus::Acknowledged);
    }

    #[test]
    fn test_false_positive_marking() {
        let mut manager = WorkflowManager::new();
        let finding_id = FindingId::new();
        let user = "test_user";
        let reason = "This is clearly not a vulnerability";

        // Mark as false positive
        assert!(manager
            .mark_false_positive(finding_id, user, reason)
            .is_ok());

        // Check false positive status
        let fp_status = manager.get_false_positive_status(finding_id);
        assert!(fp_status.is_some());

        let fp = fp_status.unwrap();
        assert_eq!(fp.finding_id, finding_id);
        assert_eq!(fp.marked_by, user);
        assert_eq!(fp.reason, reason);

        // Should also be acknowledged
        let ack_status = manager.get_acknowledgment_status(finding_id);
        assert!(ack_status.is_some());
    }

    #[test]
    fn test_ignore_rule_matching() {
        let mut manager = WorkflowManager::new();

        // Add an ignore rule
        let rule = IgnoreRule {
            id: "test-rule-1".to_string(),
            pattern: r"title:.*SQL Injection.*".to_string(),
            reason: "Known false positive in test environment".to_string(),
            author: "test_user".to_string(),
            created_by: "test_user".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            scope: IgnoreScope {
                targets: Vec::new(),
                categories: Vec::new(),
                severities: Vec::new(),
                tags: Vec::new(),
            },
            severity_threshold: None,
            target_pattern: None,
        };

        assert!(manager.add_ignore_rule(rule).is_ok());

        // Create a finding that should match the rule
        let mut sql_finding = create_test_finding("SQL Injection in login form", Severity::High);
        sql_finding.title = "SQL Injection vulnerability detected".to_string();

        // Should be ignored
        assert!(manager.should_ignore_finding(&sql_finding));

        // Create a finding that should not match
        let other_finding = create_test_finding("Cross-site Scripting", Severity::Medium);

        // Should not be ignored
        assert!(!manager.should_ignore_finding(&other_finding));
    }

    #[test]
    fn test_workflow_processing() {
        let mut manager = WorkflowManager::new();

        // Create test findings
        let mut finding1 = create_test_finding("SQL Injection", Severity::High);
        let finding2 = create_test_finding("XSS", Severity::Medium);
        let mut finding3 = create_test_finding("Path Traversal", Severity::Critical);

        // Acknowledge one finding
        manager
            .acknowledge_finding(finding1.id, "user1", Some("Reviewed"))
            .unwrap();

        // Mark another as false positive
        manager
            .mark_false_positive(finding3.id, "user2", "Test environment artifact")
            .unwrap();

        let mut findings = vec![finding1.clone(), finding2.clone(), finding3.clone()];
        let result = manager.process_findings(&mut findings).unwrap();

        // Should have filtered out the false positive
        assert_eq!(result.total_findings, 3);
        assert_eq!(result.acknowledged_count, 1);
        assert_eq!(result.false_positive_count, 1);
        assert_eq!(result.remaining_count, 1); // Only finding2 should remain
        assert_eq!(findings.len(), 1);

        // The remaining finding should be the XSS one
        assert_eq!(findings[0].title, "XSS");
    }

    #[test]
    fn test_temporary_ignore() {
        let mut manager = WorkflowManager::new();
        let finding = create_test_finding("Test Vulnerability", Severity::Medium);
        let user = "test_user";

        // Temporarily ignore the finding
        assert!(manager
            .temporarily_ignore_finding(&finding, user, Some(7))
            .is_ok());

        // Should now be ignored
        assert!(manager.should_ignore_finding(&finding));

        // Check that rule was created
        assert_eq!(manager.list_ignore_rules().len(), 1);

        let rule = &manager.list_ignore_rules()[0];
        assert!(rule.pattern.contains("test-fingerprint"));
        assert_eq!(rule.reason, "Temporary ignore");
    }

    #[test]
    fn test_expired_rule_cleanup() {
        let mut manager = WorkflowManager::new();

        // Add an expired rule
        let expired_rule = IgnoreRule {
            id: "expired-rule".to_string(),
            pattern: r"title:.*Old.*".to_string(),
            reason: "Temporary rule".to_string(),
            author: "test_user".to_string(),
            created_by: "test_user".to_string(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)), // Expired yesterday
            scope: IgnoreScope {
                targets: Vec::new(),
                categories: Vec::new(),
                severities: Vec::new(),
                tags: Vec::new(),
            },
            severity_threshold: None,
            target_pattern: None,
        };

        manager.add_ignore_rule(expired_rule).unwrap();

        // Add a non-expired rule
        let active_rule = IgnoreRule {
            id: "active-rule".to_string(),
            pattern: r"title:.*Active.*".to_string(),
            reason: "Permanent rule".to_string(),
            author: "test_user".to_string(),
            created_by: "test_user".to_string(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(30)), // Expires in 30 days
            scope: IgnoreScope {
                targets: Vec::new(),
                categories: Vec::new(),
                severities: Vec::new(),
                tags: Vec::new(),
            },
            severity_threshold: None,
            target_pattern: None,
        };

        manager.add_ignore_rule(active_rule).unwrap();

        // Should have 2 rules initially
        assert_eq!(manager.list_ignore_rules().len(), 2);

        // Clean up expired rules
        let cleaned_count = manager.cleanup_expired_rules();

        // Should have cleaned 1 expired rule
        assert_eq!(cleaned_count, 1);

        // Should now have only 1 active rule
        assert_eq!(manager.list_ignore_rules().len(), 1);
    }
}
