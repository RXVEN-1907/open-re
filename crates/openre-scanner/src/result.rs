//! Result Aggregator - Re-exports core finding model for scanner with deduplication

use crate::error::{ScannerError, ScannerResult};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
pub use openre_core::ids::FindingId;
use openre_core::result::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// Re-export core types
pub use openre_core::result::{
    AssetCriticality, AttackComplexity, AttackVector, BusinessImpactAssessment, Category,
    CertificateInfo, CodeExample, Confidence, Evidence, EvidenceType, ExploitabilityAssessment,
    Finding, FindingFilter, FindingSort, FindingStats, HttpRequestEvidence, HttpResponseEvidence,
    ImpactLevel, PayloadEvidence, PrivilegesRequired, Reference, ReferenceType, RegulatoryImpact,
    RemediationEffort, RemediationGuidance, RemediationPriority, ReproductionDifficulty,
    ReproductionSteps, Scope, Severity, TimingEvidence, TlsInfo, UserInteraction,
};

/// Result Aggregator - aggregates findings from multiple plugins with deduplication
pub struct ResultAggregator {
    /// Findings storage
    findings: Arc<DashMap<FindingId, Finding>>,
    /// Findings by scan ID
    by_scan: Arc<DashMap<openre_core::ids::ScanId, Vec<FindingId>>>,
    /// Findings by fingerprint (for deduplication)
    by_fingerprint: Arc<DashMap<String, FindingId>>,
}

impl ResultAggregator {
    /// Create a new result aggregator
    pub fn new() -> Self {
        Self {
            findings: Arc::new(DashMap::new()),
            by_scan: Arc::new(DashMap::new()),
            by_fingerprint: Arc::new(DashMap::new()),
        }
    }

    /// Add a finding with automatic deduplication
    pub fn add_finding(&self, mut finding: Finding) -> FindingId {
        // Generate fingerprint if not present
        if finding.fingerprint.is_none() {
            finding.fingerprint = Some(finding.generate_fingerprint());
        }
        let fingerprint = finding.fingerprint.clone().unwrap();

        // Check for duplicate
        if let Some(existing_id) = self.by_fingerprint.get(&fingerprint) {
            let existing_id = *existing_id;
            // Merge with existing finding
            if let Some(mut existing) = self.findings.get_mut(&existing_id) {
                self.merge_findings(&mut existing, &finding);
                return existing_id;
            }
        }

        let id = finding.id;
        let scan_id = finding.scan_id;

        self.by_fingerprint.insert(fingerprint, id);
        self.by_scan.entry(scan_id).or_default().push(id);
        self.findings.insert(id, finding);
        id
    }

    /// Add multiple findings
    pub fn add_findings(&self, findings: Vec<Finding>) -> Vec<FindingId> {
        let mut ids = Vec::new();
        for finding in findings {
            ids.push(self.add_finding(finding));
        }
        ids
    }

    /// Merge two findings (keep the one with higher confidence/severity)
    fn merge_findings(&self, existing: &mut Finding, new: &Finding) {
        // Update confidence if new is higher
        if new.confidence > existing.confidence {
            existing.confidence = new.confidence;
        }
        // Update severity if new is higher
        if new.severity > existing.severity {
            existing.severity = new.severity;
        }
        // Merge evidence
        existing.evidence.extend(new.evidence.clone());
        // Merge references
        existing.references.extend(new.references.clone());
        // Merge tags
        existing.tags.extend(new.tags.clone());
        // Add related finding
        existing.related_findings.push(new.id);
        // Update metadata
        existing.metadata.extend(new.metadata.clone());
        // Update risk score
        existing.risk_score = Some(existing.calculate_advanced_risk_score());
    }

    /// Get a finding by ID
    pub fn get_finding(&self, id: &FindingId) -> Option<Finding> {
        self.findings.get(id).map(|f| f.clone())
    }

    /// Get all findings for a scan
    pub fn get_findings_for_scan(&self, scan_id: &openre_core::ids::ScanId) -> Vec<Finding> {
        self.by_scan
            .get(scan_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.findings.get(id).map(|f| f.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get findings with filter
    pub fn get_findings(
        &self,
        filter: FindingFilter,
        sort: FindingSort,
        limit: usize,
        offset: usize,
    ) -> Vec<Finding> {
        let mut results: Vec<Finding> = self
            .findings
            .iter()
            .filter_map(|entry| {
                let finding = entry.value();
                if self.matches_filter(finding, &filter) {
                    Some(finding.clone())
                } else {
                    None
                }
            })
            .collect();

        // Sort
        self.sort_findings(&mut results, sort);

        // Paginate
        results.into_iter().skip(offset).take(limit).collect()
    }

    /// Check if finding matches filter
    fn matches_filter(&self, finding: &Finding, filter: &FindingFilter) -> bool {
        if let Some(severities) = &filter.severity {
            if !severities.contains(&finding.severity) {
                return false;
            }
        }
        if let Some(confidences) = &filter.confidence {
            if !confidences.contains(&finding.confidence) {
                return false;
            }
        }
        if let Some(categories) = &filter.category {
            if !categories.contains(&finding.category) {
                return false;
            }
        }
        if let Some(target) = &filter.target {
            if !finding.target.contains(target) {
                return false;
            }
        }
        if let Some(plugin) = &filter.plugin_source {
            if finding.plugin_source != *plugin {
                return false;
            }
        }
        if let Some(scan_id) = &filter.scan_id {
            if finding.scan_id != *scan_id {
                return false;
            }
        }
        if let Some(verified) = filter.verified {
            if finding.verified != verified {
                return false;
            }
        }
        if let Some(false_positive) = filter.false_positive {
            if finding.false_positive != false_positive {
                return false;
            }
        }
        if let Some(tags) = &filter.tags {
            if !tags.iter().all(|t| finding.tags.contains(t)) {
                return false;
            }
        }
        if let Some(date_from) = filter.date_from {
            if finding.timestamp < date_from {
                return false;
            }
        }
        if let Some(date_to) = filter.date_to {
            if finding.timestamp > date_to {
                return false;
            }
        }
        if let Some(search) = &filter.search {
            let search_lower = search.to_lowercase();
            if !finding.title.to_lowercase().contains(&search_lower)
                && !finding.description.to_lowercase().contains(&search_lower)
            {
                return false;
            }
        }
        if let Some(min_score) = filter.min_risk_score {
            if finding.risk_score.unwrap_or(0) < min_score {
                return false;
            }
        }
        if let Some(max_score) = filter.max_risk_score {
            if finding.risk_score.unwrap_or(100) > max_score {
                return false;
            }
        }
        if let Some(cwe_id) = &filter.cwe_id {
            if !finding.cwe_ids.contains(cwe_id) {
                return false;
            }
        }
        if let Some(capec_id) = &filter.capec_id {
            if !finding.capec_ids.contains(capec_id) {
                return false;
            }
        }
        if let Some(mitre_id) = &filter.mitre_attack_id {
            if !finding.mitre_attack_ids.contains(mitre_id) {
                return false;
            }
        }
        if let Some(owasp) = &filter.owasp_category {
            if finding.owasp_category.as_ref() != Some(owasp) {
                return false;
            }
        }
        if let Some(fingerprint) = &filter.fingerprint {
            if finding.fingerprint.as_ref() != Some(fingerprint) {
                return false;
            }
        }
        if let Some(priority) = &filter.remediation_priority {
            if finding.remediation.as_ref().map(|r| r.priority) != Some(*priority) {
                return false;
            }
        }
        if let Some(min_exp) = filter.min_exploitability_score {
            if finding
                .exploitability
                .as_ref()
                .map(|e| e.score)
                .unwrap_or(0.0)
                < min_exp
            {
                return false;
            }
        }
        if let Some(max_exp) = filter.max_exploitability_score {
            if finding
                .exploitability
                .as_ref()
                .map(|e| e.score)
                .unwrap_or(10.0)
                > max_exp
            {
                return false;
            }
        }
        if let Some(min_impact) = filter.min_business_impact_score {
            if finding
                .business_impact
                .as_ref()
                .map(|b| b.score)
                .unwrap_or(0.0)
                < min_impact
            {
                return false;
            }
        }
        if let Some(max_impact) = filter.max_business_impact_score {
            if finding
                .business_impact
                .as_ref()
                .map(|b| b.score)
                .unwrap_or(10.0)
                > max_impact
            {
                return false;
            }
        }
        true
    }

    /// Sort findings
    fn sort_findings(&self, findings: &mut [Finding], sort: FindingSort) {
        match sort {
            FindingSort::SeverityDesc => findings.sort_by(|a, b| b.severity.cmp(&a.severity)),
            FindingSort::SeverityAsc => findings.sort_by(|a, b| a.severity.cmp(&b.severity)),
            FindingSort::ConfidenceDesc => findings.sort_by(|a, b| b.confidence.cmp(&a.confidence)),
            FindingSort::TimestampDesc => findings.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)),
            FindingSort::TimestampAsc => findings.sort_by(|a, b| a.timestamp.cmp(&b.timestamp)),
            FindingSort::RiskScoreDesc => {
                findings.sort_by(|a, b| b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0)))
            }
            FindingSort::TargetAsc => findings.sort_by(|a, b| a.target.cmp(&b.target)),
        }
    }

    /// Get finding statistics
    pub fn get_stats(&self, scan_id: Option<openre_core::ids::ScanId>) -> FindingStats {
        let findings: Vec<Finding> = if let Some(scan_id) = scan_id {
            self.get_findings_for_scan(&scan_id)
        } else {
            self.findings.iter().map(|f| f.clone()).collect()
        };

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

        for finding in &findings {
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
                *by_remediation_priority
                    .entry(remediation.priority)
                    .or_insert(0) += 1;
            }

            if finding.verified {
                verified += 1;
            }
            if finding.false_positive {
                false_positives += 1;
            }

            if let Some(score) = finding.risk_score {
                total_risk_score += score as u32;
                risk_score_count += 1;
                max_risk_score = max_risk_score.max(score);
            }

            let advanced_score = finding.calculate_advanced_risk_score();
            total_advanced_risk_score += advanced_score as u32;
            max_advanced_risk_score = max_advanced_risk_score.max(advanced_score);

            if let Some(exploitability) = &finding.exploitability {
                if exploitability.exploit_available {
                    exploit_available_count += 1;
                }
                if exploitability.exploited_in_wild {
                    exploited_in_wild_count += 1;
                }
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
            avg_risk_score: if risk_score_count > 0 {
                total_risk_score as f32 / risk_score_count as f32
            } else {
                0.0
            },
            max_risk_score,
            by_owasp_category,
            by_cwe,
            avg_advanced_risk_score: if risk_score_count > 0 {
                total_advanced_risk_score as f32 / risk_score_count as f32
            } else {
                0.0
            },
            max_advanced_risk_score,
            by_remediation_priority,
            exploit_available_count,
            exploited_in_wild_count,
        }
    }

    /// Update a finding
    pub fn update_finding(&self, finding: Finding) -> ScannerResult<()> {
        if self.findings.contains_key(&finding.id) {
            // Update fingerprint index if fingerprint changed
            if let Some(old_finding) = self.findings.get(&finding.id) {
                if let Some(old_fp) = &old_finding.fingerprint {
                    if finding.fingerprint.as_ref() != Some(old_fp) {
                        self.by_fingerprint.remove(old_fp);
                        if let Some(new_fp) = &finding.fingerprint {
                            self.by_fingerprint.insert(new_fp.clone(), finding.id);
                        }
                    }
                }
            }
            self.findings.insert(finding.id, finding);
            Ok(())
        } else {
            Err(ScannerError::FindingNotFound(finding.id.to_string()))
        }
    }

    /// Delete a finding
    pub fn delete_finding(&self, id: &FindingId) -> bool {
        if let Some((_, finding)) = self.findings.remove(id) {
            if let Some(fp) = &finding.fingerprint {
                self.by_fingerprint.remove(fp);
            }
            if let Some(mut ids) = self.by_scan.get_mut(&finding.scan_id) {
                ids.retain(|fid| fid != id);
            }
            true
        } else {
            false
        }
    }

    /// Get all findings
    pub fn list_all(&self) -> Vec<Finding> {
        self.findings.iter().map(|f| f.clone()).collect()
    }

    /// Count findings
    pub fn count(&self) -> usize {
        self.findings.len()
    }

    /// Count findings for scan
    pub fn count_for_scan(&self, scan_id: &openre_core::ids::ScanId) -> usize {
        self.by_scan.get(scan_id).map(|ids| ids.len()).unwrap_or(0)
    }

    /// Deduplicate all findings
    pub fn deduplicate(&self) -> usize {
        let mut seen = HashMap::new();
        let mut to_remove = Vec::new();
        let mut removed = 0;

        for entry in self.findings.iter() {
            let finding = entry.value();
            let fingerprint = finding
                .fingerprint
                .clone()
                .unwrap_or_else(|| finding.generate_fingerprint());
            if let Some(existing_id) = seen.get(&fingerprint) {
                // Merge into existing
                if let Some(mut existing) = self.findings.get_mut(existing_id) {
                    self.merge_findings(&mut existing, finding);
                }
                to_remove.push(entry.key().clone());
                removed += 1;
            } else {
                seen.insert(fingerprint, entry.key().clone());
            }
        }

        // Remove duplicates
        for id in to_remove {
            self.delete_finding(&id);
        }

        removed
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn make_finding(
        title: String,
        description: String,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        target: String,
        plugin_source: &str,
        scan_id: openre_core::ids::ScanId,
    ) -> Finding {
        Finding::new(FindingConfig {
            title,
            description,
            severity,
            confidence,
            category,
            target,
            target_type: "rest_api".to_string(),
            plugin_source: plugin_source.to_string(),
            plugin_version: "1.0".to_string(),
            scan_id,
        })
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::VeryHigh > Confidence::High);
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
        assert!(Confidence::Low > Confidence::VeryLow);
    }

    #[test]
    fn test_finding_creation() {
        let scan_id = openre_core::ids::ScanId::new();
        let finding = make_finding(
            "SQL Injection".to_string(),
            "SQL injection in login form".to_string(),
            Severity::High,
            Confidence::High,
            Category::Injection,
            "https://example.com/login".to_string(),
            "sql-injection-scanner",
            scan_id,
        );

        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.category, Category::Injection);
        assert!(!finding.id.to_string().is_empty());
    }

    #[test]
    fn test_finding_risk_score() {
        let scan_id = openre_core::ids::ScanId::new();
        let finding = make_finding(
            "Test".to_string(),
            "Test".to_string(),
            Severity::Critical,
            Confidence::VeryHigh,
            Category::Injection,
            "target".to_string(),
            "plugin",
            scan_id,
        );

        let score = finding.calculate_risk_score();
        assert_eq!(score, 100); // Max score
    }

    #[test]
    fn test_result_aggregator() {
        let aggregator = ResultAggregator::new();
        let scan_id = openre_core::ids::ScanId::new();

        let finding = make_finding(
            "Test".to_string(),
            "Test".to_string(),
            Severity::Medium,
            Confidence::Medium,
            Category::Xss,
            "target".to_string(),
            "plugin",
            scan_id,
        );

        let id = aggregator.add_finding(finding);
        assert_eq!(aggregator.count(), 1);
        assert_eq!(aggregator.count_for_scan(&scan_id), 1);

        let retrieved = aggregator.get_finding(&id).unwrap();
        assert_eq!(retrieved.title, "Test");
    }

    #[test]
    fn test_finding_filter() {
        let aggregator = ResultAggregator::new();
        let scan_id = openre_core::ids::ScanId::new();

        let finding1 = make_finding(
            "High Severity".to_string(),
            "Desc".to_string(),
            Severity::High,
            Confidence::High,
            Category::Injection,
            "target1".to_string(),
            "plugin1",
            scan_id,
        );

        let finding2 = make_finding(
            "Low Severity".to_string(),
            "Desc".to_string(),
            Severity::Low,
            Confidence::Low,
            Category::Xss,
            "target2".to_string(),
            "plugin2",
            scan_id,
        );

        aggregator.add_finding(finding1);
        aggregator.add_finding(finding2);

        let filter = FindingFilter {
            severity: Some(vec![Severity::High]),
            ..Default::default()
        };

        let results = aggregator.get_findings(filter, FindingSort::SeverityDesc, 10, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::High);
    }
}
