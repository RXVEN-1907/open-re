//! Remediation Verification
//!
//! This module provides verification of remediation efforts by comparing
//! baseline and current scans to confirm fixes.

use crate::{error::IntelligenceError, IntelligenceResult};
use openre_core::evidence::{
    FindingVerifier, VerificationStatus, VerificationStatus as EvidenceVerificationStatus,
};
use openre_core::ids::{FindingId, RecheckId, RemediationId, ScanId};
use openre_core::relationships::FindingRelationshipGraph;
use openre_core::remediation::{
    AuthChanges, EndpointChanges, EnhancedScanDiff, FindingChanges, RecheckFrequency,
    RecheckStatus, RemediationResult, RemediationSeverityStats, RemediationStatus,
    RemediationStatusType, RemediationSummary, RemediationVerifierConfig, RiskTrend,
    ScheduledRecheck, TechnologyChanges, VerificationResult as RemediationVerificationResult,
    VerificationStatus as RemediationVerificationStatus,
};
use openre_core::result::Finding;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Remediation verifier for confirming fixes
pub struct RemediationVerifier {
    config: RemediationVerifierConfig,
    http_client: Client,
    verification_engine: Arc<crate::verification::VerificationEngine>,
    storage: Arc<dyn ScanStorage>,
    scheduled_rechecks: Arc<RwLock<HashMap<RecheckId, ScheduledRecheck>>>,
}

/// Trait for scan storage (to be implemented by openre-storage)
#[async_trait::async_trait]
pub trait ScanStorage: Send + Sync {
    async fn get_scan(&self, scan_id: ScanId) -> IntelligenceResult<ScanData>;
    async fn get_findings(&self, scan_id: ScanId) -> IntelligenceResult<Vec<Finding>>;
    async fn save_remediation_status(&self, status: &RemediationStatus) -> IntelligenceResult<()>;
    async fn get_remediation_status(
        &self,
        finding_id: FindingId,
        baseline_scan: ScanId,
    ) -> IntelligenceResult<Option<RemediationStatus>>;
    async fn save_scheduled_recheck(&self, recheck: &ScheduledRecheck) -> IntelligenceResult<()>;
    async fn get_scheduled_rechecks(&self) -> IntelligenceResult<Vec<ScheduledRecheck>>;
    async fn update_scheduled_recheck(&self, recheck: &ScheduledRecheck) -> IntelligenceResult<()>;
}

/// Scan data for remediation verification
#[derive(Debug, Clone)]
pub struct ScanData {
    pub scan_id: ScanId,
    pub findings: Vec<Finding>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub target: String,
}

impl RemediationVerifier {
    /// Create a new remediation verifier
    pub fn new(
        config: RemediationVerifierConfig,
        storage: Arc<dyn ScanStorage>,
        verification_engine: Arc<crate::verification::VerificationEngine>,
    ) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.verification_timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            verification_engine,
            storage,
            scheduled_rechecks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Verify remediation for a specific finding
    pub async fn verify_remediation(
        &self,
        baseline_scan: ScanId,
        finding_id: FindingId,
    ) -> IntelligenceResult<RemediationResult> {
        // Get baseline scan data
        let baseline_data = self.storage.get_scan(baseline_scan).await?;
        let baseline_finding =
            baseline_data.findings.iter().find(|f| f.id == finding_id).ok_or_else(|| {
                IntelligenceError::NotFound(format!("Finding {} not in baseline scan", finding_id))
            })?;

        // Get current scan data (latest scan for same target)
        let current_findings = self.get_latest_findings_for_target(&baseline_data.target).await?;

        // Check if finding still exists in current scan
        let current_finding =
            current_findings.iter().find(|f| self.findings_match(baseline_finding, f));

        let (status, new_evidence, verification_result) = match current_finding {
            Some(current) => {
                // Finding still exists - check if severity changed
                if current.severity < baseline_finding.severity {
                    (RemediationStatusType::PartiallyFixed, self.extract_evidence(current), None)
                } else if current.severity == baseline_finding.severity {
                    (RemediationStatusType::NotFixed, self.extract_evidence(current), None)
                } else {
                    (RemediationStatusType::NotFixed, self.extract_evidence(current), None)
                }
            }
            None => {
                // Finding not found in current scan - verify it's actually fixed
                let verification_result = self.verify_finding_fixed(baseline_finding).await?;
                let status = match verification_result.status {
                    openre_core::remediation::VerificationStatus::Verified => {
                        RemediationStatusType::Fixed
                    }
                    openre_core::remediation::VerificationStatus::FalsePositive => {
                        RemediationStatusType::CannotVerify
                    }
                    _ => RemediationStatusType::CannotVerify,
                };
                (status, None, Some(verification_result))
            }
        };

        let remediation_result = RemediationResult {
            remediation_id: RemediationId::new(),
            finding_id,
            status,
            verification_result,
            risk_score_before: baseline_finding.risk_score.unwrap_or(50),
            risk_score_after: current_finding.and_then(|f| f.risk_score),
            evidence_comparison: openre_core::remediation::EvidenceComparison {
                trigger_condition_changed: true,
                http_interaction_changed: true,
                response_analysis_changed: true,
                configuration_changed: true,
                new_evidence_count: new_evidence.as_ref().map(|_| 1).unwrap_or(0),
                removed_evidence_count: baseline_finding.evidence.len(),
                similarity_score: 0.3,
            },
            verified_at: chrono::Utc::now(),
            verified_by: "RemediationVerifier".to_string(),
        };

        // Save remediation status
        let remediation_status = RemediationStatus {
            remediation_id: remediation_result.remediation_id,
            finding_id,
            baseline_scan,
            current_scan: self.get_latest_scan_id(&baseline_data.target).await,
            status,
            old_evidence: self.extract_finding_evidence(baseline_finding),
            new_evidence,
            verified_at: Some(chrono::Utc::now()),
            verified_by: Some("RemediationVerifier".to_string()),
            verification_method: Some("Automated verification".to_string()),
            notes: Some(
                remediation_result
                    .verification_result
                    .as_ref()
                    .map(|v| v.notes.clone())
                    .unwrap_or_default(),
            ),
            regression_detected: false,
            regression_scan: None,
        };

        self.storage.save_remediation_status(&remediation_status).await?;

        // Schedule recheck if configured
        if self.config.schedule_rechecks_for_fixed && matches!(status, RemediationStatusType::Fixed)
        {
            self.schedule_recheck(finding_id, baseline_scan).await?;
        }

        Ok(remediation_result)
    }

    /// Verify all remediations between two scans
    pub async fn verify_all_remediations(
        &self,
        baseline_scan: ScanId,
        current_scan: ScanId,
    ) -> IntelligenceResult<Vec<RemediationResult>> {
        let baseline_data = self.storage.get_scan(baseline_scan).await?;
        let current_data = self.storage.get_scan(current_scan).await?;

        let mut results = Vec::new();

        // Check each finding in baseline
        for baseline_finding in &baseline_data.findings {
            let current_finding =
                current_data.findings.iter().find(|f| self.findings_match(baseline_finding, f));

            let (status, new_evidence, verification_result) = match current_finding {
                Some(current) => {
                    if current.severity < baseline_finding.severity {
                        (
                            RemediationStatusType::PartiallyFixed,
                            self.extract_evidence(current),
                            None,
                        )
                    } else {
                        (RemediationStatusType::NotFixed, self.extract_evidence(current), None)
                    }
                }
                None => {
                    let verification_result = self.verify_finding_fixed(baseline_finding).await?;
                    let status = match verification_result.status {
                        openre_core::remediation::VerificationStatus::Verified => {
                            RemediationStatusType::Fixed
                        }
                        _ => RemediationStatusType::CannotVerify,
                    };
                    (status, None, Some(verification_result))
                }
            };

            let result = RemediationResult {
                remediation_id: RemediationId::new(),
                finding_id: baseline_finding.id,
                status,
                verification_result,
                risk_score_before: baseline_finding.risk_score.unwrap_or(50),
                risk_score_after: current_finding.and_then(|f| f.risk_score),
                evidence_comparison: openre_core::remediation::EvidenceComparison {
                    trigger_condition_changed: true,
                    http_interaction_changed: true,
                    response_analysis_changed: true,
                    configuration_changed: true,
                    new_evidence_count: new_evidence.as_ref().map(|_| 1).unwrap_or(0),
                    removed_evidence_count: baseline_finding.evidence.len(),
                    similarity_score: 0.3,
                },
                verified_at: chrono::Utc::now(),
                verified_by: "RemediationVerifier".to_string(),
            };

            results.push(result);
        }

        Ok(results)
    }

    /// Schedule a recheck for a finding
    pub async fn schedule_recheck(
        &self,
        finding_id: FindingId,
        scan_id: ScanId,
    ) -> IntelligenceResult<ScheduledRecheck> {
        let recheck = ScheduledRecheck {
            recheck_id: RecheckId::new(),
            finding_id,
            scan_id,
            scheduled_at: chrono::Utc::now() + chrono::Duration::weeks(1),
            frequency: self.config.recheck_frequency,
            max_retries: self.config.max_retries,
            current_retries: 0,
            status: RecheckStatus::Scheduled,
            last_run: None,
            next_run: Some(chrono::Utc::now() + chrono::Duration::weeks(1)),
            created_by: "RemediationVerifier".to_string(),
        };

        self.storage.save_scheduled_recheck(&recheck).await?;
        self.scheduled_rechecks.write().await.insert(recheck.recheck_id, recheck.clone());

        Ok(recheck)
    }

    /// Run scheduled rechecks
    pub async fn run_scheduled_rechecks(&self) -> IntelligenceResult<Vec<RemediationResult>> {
        let rechecks = self.storage.get_scheduled_rechecks().await?;
        let mut results = Vec::new();

        for recheck in rechecks {
            if recheck.status != RecheckStatus::Scheduled {
                continue;
            }

            if let Some(next_run) = recheck.next_run {
                if chrono::Utc::now() < next_run {
                    continue; // Not time yet
                }
            }

            // Update status to running
            let mut updated_recheck = recheck.clone();
            updated_recheck.status = RecheckStatus::Running;
            updated_recheck.current_retries += 1;
            updated_recheck.last_run = Some(chrono::Utc::now());
            self.storage.update_scheduled_recheck(&updated_recheck).await?;

            // Run verification
            match self.verify_remediation(recheck.scan_id, recheck.finding_id).await {
                Ok(result) => {
                    updated_recheck.status = RecheckStatus::Completed;
                    results.push(result);
                }
                Err(e) => {
                    if updated_recheck.current_retries >= updated_recheck.max_retries {
                        updated_recheck.status = RecheckStatus::Failed;
                    } else {
                        updated_recheck.status = RecheckStatus::Scheduled;
                        // Schedule retry
                        updated_recheck.next_run =
                            Some(chrono::Utc::now() + chrono::Duration::hours(1));
                    }
                    warn!("Recheck failed for finding {}: {}", recheck.finding_id, e);
                }
            }

            self.storage.update_scheduled_recheck(&updated_recheck).await?;
        }

        Ok(results)
    }

    /// Verify a finding is actually fixed by running verification
    async fn verify_finding_fixed(
        &self,
        finding: &Finding,
    ) -> IntelligenceResult<RemediationVerificationResult> {
        // Run the verification engine to check if the finding is still present
        let evidence_result = self.verification_engine.verify_finding(finding).await?;

        // Convert evidence VerificationResult to remediation VerificationResult
        self.convert_verification_result(&evidence_result)
    }

    /// Convert VerificationMethod to string
    fn verification_method_to_string(method: &openre_core::evidence::VerificationMethod) -> String {
        match method {
            openre_core::evidence::VerificationMethod::SafeRequest { .. } => {
                "SafeRequest".to_string()
            }
            openre_core::evidence::VerificationMethod::HeaderCheck { .. } => {
                "HeaderCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::StatusCodeCheck { .. } => {
                "StatusCodeCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::BodyPatternCheck { .. } => {
                "BodyPatternCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::DifferentialCheck { .. } => {
                "DifferentialCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::ConfigurationCheck { .. } => {
                "ConfigurationCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::VersionCheck { .. } => {
                "VersionCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::RateLimitCheck { .. } => {
                "RateLimitCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::CorsCheck { .. } => "CorsCheck".to_string(),
            openre_core::evidence::VerificationMethod::DirectoryListingCheck { .. } => {
                "DirectoryListingCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::AuthenticationCheck { .. } => {
                "AuthenticationCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::SslTlsCheck { .. } => {
                "SslTlsCheck".to_string()
            }
            openre_core::evidence::VerificationMethod::Custom { description, .. } => {
                format!("Custom: {}", description)
            }
        }
    }

    /// Convert evidence VerificationResult to remediation VerificationResult
    fn convert_verification_result(
        &self,
        evidence_result: &openre_core::evidence::VerificationResult,
    ) -> IntelligenceResult<RemediationVerificationResult> {
        let remediation_status = match evidence_result.status {
            openre_core::evidence::VerificationStatus::Confirmed => {
                openre_core::remediation::VerificationStatus::Verified
            }
            openre_core::evidence::VerificationStatus::Likely => {
                openre_core::remediation::VerificationStatus::Verified
            }
            openre_core::evidence::VerificationStatus::Unconfirmed => {
                openre_core::remediation::VerificationStatus::NotVerified
            }
            openre_core::evidence::VerificationStatus::NotReproducible => {
                openre_core::remediation::VerificationStatus::FalsePositive
            }
            openre_core::evidence::VerificationStatus::Error => {
                openre_core::remediation::VerificationStatus::CannotVerify
            }
            openre_core::evidence::VerificationStatus::Skipped => {
                openre_core::remediation::VerificationStatus::NotVerified
            }
        };

        // Convert evidence VerificationResult to remediation VerificationResult
        Ok(RemediationVerificationResult {
            status: remediation_status,
            confidence: evidence_result.confidence,
            notes: evidence_result.notes.clone(),
            method: Self::verification_method_to_string(&evidence_result.method_used),
        })
    }

    /// Check if two findings match (same issue)
    fn findings_match(&self, baseline: &Finding, current: &Finding) -> bool {
        // Match by fingerprint if available
        if let (Some(fp1), Some(fp2)) = (&baseline.fingerprint, &current.fingerprint) {
            return fp1 == fp2;
        }

        // Match by title and target
        baseline.title == current.title && baseline.target == current.target
    }

    /// Extract evidence from finding
    fn extract_evidence(
        &self,
        finding: &Finding,
    ) -> Option<openre_core::remediation::FindingEvidence> {
        // Convert finding evidence to FindingEvidence
        // This is simplified - in practice would do full conversion
        Some(openre_core::remediation::FindingEvidence {
            finding_id: finding.id,
            trigger_condition: finding.title.clone(),
            http_interaction_summary: "N/A".to_string(),
            response_analysis_summary: finding.description.clone(),
            evidence_count: finding.evidence.len(),
        })
    }

    /// Extract finding evidence for remediation status
    fn extract_finding_evidence(
        &self,
        finding: &Finding,
    ) -> openre_core::remediation::FindingEvidence {
        openre_core::remediation::FindingEvidence {
            finding_id: finding.id,
            trigger_condition: finding.title.clone(),
            http_interaction_summary: "N/A".to_string(),
            response_analysis_summary: finding.description.clone(),
            evidence_count: finding.evidence.len(),
        }
    }

    /// Get latest scan ID for target
    async fn get_latest_scan_id(&self, target: &str) -> Option<ScanId> {
        // This would query storage for latest scan
        None
    }

    /// Get latest findings for target
    async fn get_latest_findings_for_target(
        &self,
        target: &str,
    ) -> IntelligenceResult<Vec<Finding>> {
        // This would query storage for latest scan findings
        Ok(Vec::new())
    }

    /// Generate remediation summary
    pub async fn generate_summary(
        &self,
        scan_id: ScanId,
    ) -> IntelligenceResult<RemediationSummary> {
        let remediation_statuses = self.get_remediation_statuses_for_scan(scan_id).await?;

        let total = remediation_statuses.len();
        let fixed = remediation_statuses
            .iter()
            .filter(|s| s.status == RemediationStatusType::Fixed)
            .count();
        let partially_fixed = remediation_statuses
            .iter()
            .filter(|s| s.status == RemediationStatusType::PartiallyFixed)
            .count();
        let not_fixed = remediation_statuses
            .iter()
            .filter(|s| s.status == RemediationStatusType::NotFixed)
            .count();
        let regressed = remediation_statuses
            .iter()
            .filter(|s| s.status == RemediationStatusType::Regressed)
            .count();
        let cannot_verify = remediation_statuses
            .iter()
            .filter(|s| s.status == RemediationStatusType::CannotVerify)
            .count();

        let fix_rate =
            if total > 0 { (fixed + partially_fixed) as f32 / total as f32 } else { 0.0 };
        let regression_rate = if total > 0 { regressed as f32 / total as f32 } else { 0.0 };

        // Group by severity
        let mut by_severity = HashMap::new();
        for status in &remediation_statuses {
            // Would need to get finding severity from storage
        }

        Ok(RemediationSummary {
            total_findings: total,
            fixed,
            partially_fixed,
            not_fixed,
            regressed,
            cannot_verify,
            in_progress: 0,
            pending_verification: 0,
            fix_rate,
            regression_rate,
            average_time_to_fix_days: None,
            by_severity,
        })
    }

    async fn get_remediation_statuses_for_scan(
        &self,
        _scan_id: ScanId,
    ) -> IntelligenceResult<Vec<RemediationStatus>> {
        // Would query storage
        Ok(Vec::new())
    }
}

/// Mock scan storage for testing
pub struct MockScanStorage {
    scans: HashMap<ScanId, ScanData>,
}

impl MockScanStorage {
    pub fn new() -> Self {
        Self { scans: HashMap::new() }
    }

    pub fn add_scan(&mut self, scan: ScanData) {
        self.scans.insert(scan.scan_id, scan);
    }
}

#[async_trait::async_trait]
impl ScanStorage for MockScanStorage {
    async fn get_scan(&self, scan_id: ScanId) -> IntelligenceResult<ScanData> {
        self.scans
            .get(&scan_id)
            .cloned()
            .ok_or_else(|| IntelligenceError::NotFound(format!("Scan {} not found", scan_id)))
    }

    async fn get_findings(&self, scan_id: ScanId) -> IntelligenceResult<Vec<Finding>> {
        Ok(self.scans.get(&scan_id).map(|s| s.findings.clone()).unwrap_or_default())
    }

    async fn save_remediation_status(&self, _status: &RemediationStatus) -> IntelligenceResult<()> {
        Ok(())
    }

    async fn get_remediation_status(
        &self,
        _finding_id: FindingId,
        _baseline_scan: ScanId,
    ) -> IntelligenceResult<Option<RemediationStatus>> {
        Ok(None)
    }

    async fn save_scheduled_recheck(&self, _recheck: &ScheduledRecheck) -> IntelligenceResult<()> {
        Ok(())
    }

    async fn get_scheduled_rechecks(&self) -> IntelligenceResult<Vec<ScheduledRecheck>> {
        Ok(Vec::new())
    }

    async fn update_scheduled_recheck(
        &self,
        _recheck: &ScheduledRecheck,
    ) -> IntelligenceResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, RecheckId, RemediationId, ScanId};
    use openre_core::remediation::{RecheckFrequency, RecheckStatus, RemediationStatusType};
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use uuid::Uuid;

    fn create_test_finding(
        title: &str,
        category: Category,
        severity: Severity,
        target: &str,
    ) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity,
            confidence: Confidence::High,
            category,
            target: target.to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: Default::default(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: Some(50),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some(Uuid::new_v4().to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[test]
    fn test_remediation_status_types() {
        assert_eq!(RemediationStatusType::Fixed as u8, 0);
        assert_eq!(RemediationStatusType::PartiallyFixed as u8, 1);
        assert_eq!(RemediationStatusType::NotFixed as u8, 2);
        assert_eq!(RemediationStatusType::Regressed as u8, 3);
        assert_eq!(RemediationStatusType::CannotVerify as u8, 4);
    }

    #[test]
    fn test_recheck_frequency() {
        assert_eq!(RecheckFrequency::Once as u8, 0);
        assert_eq!(RecheckFrequency::Daily as u8, 1);
        assert_eq!(RecheckFrequency::Weekly as u8, 2);
        assert_eq!(RecheckFrequency::Monthly as u8, 3);
        assert_eq!(RecheckFrequency::Quarterly as u8, 4);
    }

    #[test]
    fn test_recheck_status() {
        assert_eq!(RecheckStatus::Scheduled as u8, 0);
        assert_eq!(RecheckStatus::Running as u8, 1);
        assert_eq!(RecheckStatus::Completed as u8, 2);
        assert_eq!(RecheckStatus::Failed as u8, 3);
        assert_eq!(RecheckStatus::Cancelled as u8, 4);
        assert_eq!(RecheckStatus::Skipped as u8, 5);
    }

    #[test]
    fn test_scheduled_recheck() {
        let recheck = ScheduledRecheck {
            recheck_id: RecheckId::new(),
            finding_id: FindingId::new(),
            scan_id: ScanId::new(),
            scheduled_at: Utc::now() + chrono::Duration::weeks(1),
            frequency: RecheckFrequency::Weekly,
            max_retries: 3,
            current_retries: 0,
            status: RecheckStatus::Scheduled,
            last_run: None,
            next_run: Some(Utc::now() + chrono::Duration::weeks(1)),
            created_by: "test".to_string(),
        };

        assert_eq!(recheck.status, RecheckStatus::Scheduled);
        assert_eq!(recheck.frequency, RecheckFrequency::Weekly);
        assert_eq!(recheck.max_retries, 3);
    }

    #[tokio::test]
    async fn test_mock_storage() {
        let mut storage = MockScanStorage::new();
        let scan_id = ScanId::new();
        let finding =
            create_test_finding("Test", Category::Injection, Severity::High, "https://example.com");

        storage.add_scan(ScanData {
            scan_id,
            findings: vec![finding.clone()],
            timestamp: Utc::now(),
            target: "https://example.com".to_string(),
        });

        let scan = storage.get_scan(scan_id).await.unwrap();
        assert_eq!(scan.findings.len(), 1);
    }
}
