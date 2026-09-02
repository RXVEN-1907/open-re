//! Remediation types for tracking fix verification and scan comparison

use crate::ids::{FindingId, RecheckId, RemediationId, ScanId};
use crate::result::{Confidence, Finding, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Enhanced scan diff with remediation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedScanDiff {
    /// Baseline scan ID
    pub baseline_scan: ScanId,
    /// Current scan ID
    pub current_scan: ScanId,
    /// Finding changes
    pub finding_changes: FindingChanges,
    /// Endpoint changes
    pub endpoint_changes: EndpointChanges,
    /// Technology changes
    pub technology_changes: TechnologyChanges,
    /// Authentication changes
    pub auth_changes: AuthChanges,
    /// Risk trend
    pub risk_trend: RiskTrend,
    /// Remediation status per finding
    pub remediation_status: Vec<RemediationStatus>,
    /// Comparison timestamp
    pub compared_at: DateTime<Utc>,
}

/// Finding changes between scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingChanges {
    /// New findings in current scan
    pub new: Vec<Finding>,
    /// Resolved findings (present in baseline, not in current)
    pub resolved: Vec<Finding>,
    /// Persistent findings (in both scans)
    pub persistent: Vec<PersistentFinding>,
    /// Findings with severity changes
    pub severity_changed: Vec<SeverityChange>,
    /// Findings with evidence changes
    pub evidence_changed: Vec<EvidenceChange>,
    /// Findings with verification status changes
    pub verification_status_changed: Vec<VerificationChange>,
}

/// Persistent finding with comparison data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentFinding {
    pub baseline_finding: Finding,
    pub current_finding: Finding,
    pub risk_score_delta: i16,
    pub confidence_delta: i8,
}

/// Severity change for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    pub finding_id: FindingId,
    pub fingerprint: String,
    pub previous_severity: Severity,
    pub current_severity: Severity,
    pub change_magnitude: i8, // -4 to +4
    pub change_type: SeverityChangeType,
}

/// Severity change direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityChangeType {
    Increased,
    Decreased,
}

/// Evidence change for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChange {
    pub finding_id: FindingId,
    pub fingerprint: String,
    pub previous_evidence_count: usize,
    pub current_evidence_count: usize,
    pub evidence_added: Vec<String>,
    pub evidence_removed: Vec<String>,
    pub evidence_modified: Vec<String>,
}

/// Verification status change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationChange {
    pub finding_id: FindingId,
    pub fingerprint: String,
    pub previous_status: Option<VerificationStatus>,
    pub current_status: Option<VerificationStatus>,
}

/// Verification status for remediation tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    NotVerified,
    Verified,
    FalsePositive,
    CannotVerify,
}

/// Endpoint changes between scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointChanges {
    pub new_endpoints: Vec<EndpointInfo>,
    pub removed_endpoints: Vec<EndpointInfo>,
    pub changed_endpoints: Vec<EndpointChange>,
}

/// Endpoint info for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub path: String,
    pub methods: Vec<String>,
    pub parameters: Vec<String>,
    pub auth_required: bool,
    pub sensitivity: String,
}

/// Endpoint change details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointChange {
    pub path: String,
    pub change_type: EndpointChangeType,
    pub details: String,
    pub previous: Option<EndpointInfo>,
    pub current: Option<EndpointInfo>,
}

/// Endpoint change types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointChangeType {
    Added,
    Removed,
    ParametersChanged,
    AuthChanged,
    SensitivityChanged,
    TechnologyChanged,
    RateLimitChanged,
    CorsChanged,
}

/// Technology changes between scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyChanges {
    pub added: Vec<TechnologyChangeInfo>,
    pub removed: Vec<TechnologyChangeInfo>,
    pub version_changed: Vec<TechnologyVersionChange>,
    pub configuration_changed: Vec<TechnologyConfigChange>,
}

/// Technology change info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyChangeInfo {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub confidence: f32,
}

/// Technology version change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyVersionChange {
    pub name: String,
    pub previous_version: String,
    pub current_version: String,
    pub is_vulnerable: bool,
    pub cve_count: usize,
}

/// Technology configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyConfigChange {
    pub technology: String,
    pub config_key: String,
    pub previous_value: String,
    pub current_value: String,
    pub security_impact: String,
}

/// Authentication changes between scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChanges {
    pub auth_endpoints_added: Vec<String>,
    pub auth_endpoints_removed: Vec<String>,
    pub auth_method_changed: Vec<AuthMethodChange>,
    pub session_management_changed: Vec<SessionManagementChange>,
    pub mfa_status_changed: bool,
}

/// Authentication method change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethodChange {
    pub endpoint: String,
    pub previous_method: String,
    pub current_method: String,
    pub security_impact: String,
}

/// Session management change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionManagementChange {
    pub endpoint: String,
    pub change_type: SessionChangeType,
    pub details: String,
}

/// Session change types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionChangeType {
    CookieNameChanged,
    HttpOnlyChanged,
    SecureFlagChanged,
    SameSiteChanged,
    ExpiryChanged,
    NewSessionMechanism,
}

/// Risk trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTrend {
    pub overall_change: i16, // -100 to +100
    pub trend_direction: RemediationTrendDirection,
    pub key_factors: Vec<String>,
    pub risk_score_baseline: u8,
    pub risk_score_current: u8,
    pub severity_distribution_change: HashMap<Severity, i16>,
}

/// Trend directions for remediation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationTrendDirection {
    Improving,
    Worsening,
    Stable,
    Mixed,
}

/// Remediation status for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStatus {
    pub remediation_id: RemediationId,
    pub finding_id: FindingId,
    pub baseline_scan: ScanId,
    pub current_scan: Option<ScanId>,
    pub status: RemediationStatusType,
    pub old_evidence: FindingEvidence,
    pub new_evidence: Option<FindingEvidence>,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_by: Option<String>,
    pub verification_method: Option<String>,
    pub notes: Option<String>,
    pub regression_detected: bool,
    pub regression_scan: Option<ScanId>,
}

/// Finding evidence reference (simplified for remediation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub finding_id: FindingId,
    pub trigger_condition: String,
    pub http_interaction_summary: String,
    pub response_analysis_summary: String,
    pub evidence_count: usize,
}

/// Remediation status types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatusType {
    /// Finding no longer present, verified fixed
    Fixed,
    /// Severity reduced, evidence changed
    PartiallyFixed,
    /// Still present with same evidence
    NotFixed,
    /// Was fixed, now present again
    Regressed,
    /// Unable to verify (auth, network, etc.)
    CannotVerify,
    /// Fix in progress
    InProgress,
    /// Fix deployed, awaiting verification
    PendingVerification,
}

/// Remediation verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    pub remediation_id: RemediationId,
    pub finding_id: FindingId,
    pub status: RemediationStatusType,
    pub verification_result: Option<VerificationResult>,
    pub risk_score_before: u8,
    pub risk_score_after: Option<u8>,
    pub evidence_comparison: EvidenceComparison,
    pub verified_at: DateTime<Utc>,
    pub verified_by: String,
}

/// Verification result (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    pub confidence: f32,
    pub notes: String,
    pub method: String,
}

/// Evidence comparison for remediation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceComparison {
    pub trigger_condition_changed: bool,
    pub http_interaction_changed: bool,
    pub response_analysis_changed: bool,
    pub configuration_changed: bool,
    pub new_evidence_count: usize,
    pub removed_evidence_count: usize,
    pub similarity_score: f32, // 0.0 - 1.0
}

/// Scheduled recheck for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRecheck {
    pub recheck_id: RecheckId,
    pub finding_id: FindingId,
    pub scan_id: ScanId,
    pub scheduled_at: DateTime<Utc>,
    pub frequency: RecheckFrequency,
    pub max_retries: u32,
    pub current_retries: u32,
    pub status: RecheckStatus,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub created_by: String,
}

/// Recheck frequency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecheckFrequency {
    Once,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Custom,
}

/// Recheck status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecheckStatus {
    Scheduled,
    Running,
    Completed,
    Failed,
    Cancelled,
    Skipped,
}

/// Remediation verifier configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationVerifierConfig {
    pub auto_verify_on_scan: bool,
    pub verification_timeout_seconds: u64,
    pub max_concurrent_verifications: usize,
    pub retry_failed_verifications: bool,
    pub retry_delay_seconds: u64,
    pub max_retries: u32,
    pub schedule_rechecks_for_fixed: bool,
    pub recheck_frequency: RecheckFrequency,
    pub notify_on_regression: bool,
}

impl Default for RemediationVerifierConfig {
    fn default() -> Self {
        Self {
            auto_verify_on_scan: true,
            verification_timeout_seconds: 300,
            max_concurrent_verifications: 10,
            retry_failed_verifications: true,
            retry_delay_seconds: 60,
            max_retries: 3,
            schedule_rechecks_for_fixed: true,
            recheck_frequency: RecheckFrequency::Weekly,
            notify_on_regression: true,
        }
    }
}

/// Remediation tracking summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSummary {
    pub total_findings: usize,
    pub fixed: usize,
    pub partially_fixed: usize,
    pub not_fixed: usize,
    pub regressed: usize,
    pub cannot_verify: usize,
    pub in_progress: usize,
    pub pending_verification: usize,
    pub fix_rate: f32, // 0.0 - 1.0
    pub regression_rate: f32,
    pub average_time_to_fix_days: Option<f32>,
    pub by_severity: HashMap<Severity, RemediationSeverityStats>,
}

/// Remediation stats by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSeverityStats {
    pub total: usize,
    pub fixed: usize,
    pub partially_fixed: usize,
    pub not_fixed: usize,
    pub regressed: usize,
    pub fix_rate: f32,
}

/// Export formats for remediation reports
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationExportFormat {
    Json,
    Csv,
    Html,
    Pdf,
    Sarif,
}

impl std::str::FromStr for RemediationExportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(RemediationExportFormat::Json),
            "csv" => Ok(RemediationExportFormat::Csv),
            "html" => Ok(RemediationExportFormat::Html),
            "pdf" => Ok(RemediationExportFormat::Pdf),
            "sarif" => Ok(RemediationExportFormat::Sarif),
            _ => Err(format!("Invalid export format: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FindingId, RecheckId, RemediationId, ScanId};
    use crate::result::{Category, Confidence, Finding, Severity};
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_enhanced_scan_diff() {
        let diff = EnhancedScanDiff {
            baseline_scan: ScanId::new(),
            current_scan: ScanId::new(),
            finding_changes: FindingChanges {
                new: vec![],
                resolved: vec![],
                persistent: vec![],
                severity_changed: vec![],
                evidence_changed: vec![],
                verification_status_changed: vec![],
            },
            endpoint_changes: EndpointChanges {
                new_endpoints: vec![],
                removed_endpoints: vec![],
                changed_endpoints: vec![],
            },
            technology_changes: TechnologyChanges {
                added: vec![],
                removed: vec![],
                version_changed: vec![],
                configuration_changed: vec![],
            },
            auth_changes: AuthChanges {
                auth_endpoints_added: vec![],
                auth_endpoints_removed: vec![],
                auth_method_changed: vec![],
                session_management_changed: vec![],
                mfa_status_changed: false,
            },
            risk_trend: RiskTrend {
                overall_change: -10,
                trend_direction: RemediationTrendDirection::Improving,
                key_factors: vec!["Fixed 3 critical findings".to_string()],
                risk_score_baseline: 75,
                risk_score_current: 65,
                severity_distribution_change: HashMap::new(),
            },
            remediation_status: vec![],
            compared_at: Utc::now(),
        };

        assert_eq!(diff.risk_trend.trend_direction, RemediationTrendDirection::Improving);
        assert_eq!(diff.risk_trend.overall_change, -10);
    }

    #[test]
    fn test_remediation_status() {
        let status = RemediationStatus {
            remediation_id: RemediationId::new(),
            finding_id: FindingId::new(),
            baseline_scan: ScanId::new(),
            current_scan: Some(ScanId::new()),
            status: RemediationStatusType::Fixed,
            old_evidence: FindingEvidence {
                finding_id: FindingId::new(),
                trigger_condition: "Missing CSP header".to_string(),
                http_interaction_summary: "HEAD request to /".to_string(),
                response_analysis_summary: "CSP header absent".to_string(),
                evidence_count: 2,
            },
            new_evidence: Some(FindingEvidence {
                finding_id: FindingId::new(),
                trigger_condition: "CSP header present".to_string(),
                http_interaction_summary: "HEAD request to /".to_string(),
                response_analysis_summary: "CSP header present with default-src 'self'".to_string(),
                evidence_count: 3,
            }),
            verified_at: Some(Utc::now()),
            verified_by: Some("security-team".to_string()),
            verification_method: Some("HeaderCheck".to_string()),
            notes: Some("CSP header implemented".to_string()),
            regression_detected: false,
            regression_scan: None,
        };

        assert_eq!(status.status, RemediationStatusType::Fixed);
        assert!(status.new_evidence.is_some());
        assert!(!status.regression_detected);
    }

    #[test]
    fn test_remediation_result() {
        let result = RemediationResult {
            remediation_id: RemediationId::new(),
            finding_id: FindingId::new(),
            status: RemediationStatusType::Fixed,
            verification_result: Some(VerificationResult {
                status: VerificationStatus::Verified,
                confidence: 0.95,
                notes: "CSP header verified present".to_string(),
                method: "HeaderCheck".to_string(),
            }),
            risk_score_before: 85,
            risk_score_after: Some(45),
            evidence_comparison: EvidenceComparison {
                trigger_condition_changed: true,
                http_interaction_changed: false,
                response_analysis_changed: true,
                configuration_changed: true,
                new_evidence_count: 1,
                removed_evidence_count: 1,
                similarity_score: 0.3,
            },
            verified_at: Utc::now(),
            verified_by: "security-team".to_string(),
        };

        assert_eq!(result.status, RemediationStatusType::Fixed);
        assert_eq!(result.risk_score_before, 85);
        assert_eq!(result.risk_score_after, Some(45));
        assert!(result.evidence_comparison.similarity_score < 0.5);
    }

    #[test]
    fn test_scheduled_recheck() {
        let recheck = ScheduledRecheck {
            recheck_id: RecheckId::new(),
            finding_id: FindingId::new(),
            scan_id: ScanId::new(),
            scheduled_at: Utc::now() + chrono::Duration::days(7),
            frequency: RecheckFrequency::Weekly,
            max_retries: 3,
            current_retries: 0,
            status: RecheckStatus::Scheduled,
            last_run: None,
            next_run: Some(Utc::now() + chrono::Duration::days(7)),
            created_by: "security-team".to_string(),
        };

        assert_eq!(recheck.status, RecheckStatus::Scheduled);
        assert_eq!(recheck.frequency, RecheckFrequency::Weekly);
        assert_eq!(recheck.max_retries, 3);
    }

    #[test]
    fn test_remediation_summary() {
        let mut by_severity = HashMap::new();
        by_severity.insert(
            Severity::Critical,
            RemediationSeverityStats {
                total: 5,
                fixed: 4,
                partially_fixed: 1,
                not_fixed: 0,
                regressed: 0,
                fix_rate: 0.8,
            },
        );

        let summary = RemediationSummary {
            total_findings: 20,
            fixed: 12,
            partially_fixed: 3,
            not_fixed: 4,
            regressed: 1,
            cannot_verify: 0,
            in_progress: 0,
            pending_verification: 0,
            fix_rate: 0.6,
            regression_rate: 0.05,
            average_time_to_fix_days: Some(14.5),
            by_severity,
        };

        assert_eq!(summary.fix_rate, 0.6);
        assert_eq!(summary.regression_rate, 0.05);
        assert_eq!(summary.by_severity.get(&Severity::Critical).unwrap().fix_rate, 0.8);
    }

    #[test]
    fn test_export_format_parsing() {
        assert_eq!(
            "json".parse::<RemediationExportFormat>().unwrap(),
            RemediationExportFormat::Json
        );
        assert_eq!("CSV".parse::<RemediationExportFormat>().unwrap(), RemediationExportFormat::Csv);
        assert_eq!(
            "html".parse::<RemediationExportFormat>().unwrap(),
            RemediationExportFormat::Html
        );
        assert_eq!(
            "sarif".parse::<RemediationExportFormat>().unwrap(),
            RemediationExportFormat::Sarif
        );
        assert!("invalid".parse::<RemediationExportFormat>().is_err());
    }
}
