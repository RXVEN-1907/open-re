//! History and artifacts persistence layer for scan tracking

use crate::result::*;
use crate::ids::{ScanId, ProjectId, FindingId, TargetId};
use crate::reporting::{ScanComparison, RiskLevel, ReportFormat, ReportConfig, ScanInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// History manager for persisting scan history and artifacts
pub struct HistoryManager {
    /// Storage backend
    storage: Box<dyn HistoryStorage>,
}

/// Trait for history storage backends
#[async_trait::async_trait]
pub trait HistoryStorage: Send + Sync {
    /// Save scan summary
    async fn save_scan_summary(&self, summary: &ScanSummary) -> Result<(), HistoryError>;
    /// Get scan summary
    async fn get_scan_summary(&self, scan_id: &ScanId) -> Result<Option<ScanSummary>, HistoryError>;
    /// List scan summaries
    async fn list_scan_summaries(&self, project_id: Option<ProjectId>, limit: usize, offset: usize) -> Result<Vec<ScanSummary>, HistoryError>;
    /// Delete scan summary
    async fn delete_scan_summary(&self, scan_id: &ScanId) -> Result<bool, HistoryError>;

    /// Save report artifact
    async fn save_report_artifact(&self, artifact: &ReportArtifact) -> Result<(), HistoryError>;
    /// Get report artifact
    async fn get_report_artifact(&self, artifact_id: &str) -> Result<Option<ReportArtifact>, HistoryError>;
    /// List report artifacts
    async fn list_report_artifacts(&self, scan_id: Option<ScanId>, limit: usize, offset: usize) -> Result<Vec<ReportArtifact>, HistoryError>;
    /// Delete report artifact
    async fn delete_report_artifact(&self, artifact_id: &str) -> Result<bool, HistoryError>;

    /// Save evidence object
    async fn save_evidence(&self, evidence: &StoredEvidence) -> Result<(), HistoryError>;
    /// Get evidence
    async fn get_evidence(&self, evidence_id: &str) -> Result<Option<StoredEvidence>, HistoryError>;
    /// List evidence for finding
    async fn list_evidence_for_finding(&self, finding_id: &FindingId) -> Result<Vec<StoredEvidence>, HistoryError>;

    /// Save deduplicated findings
    async fn save_deduplicated_findings(&self, scan_id: &ScanId, findings: &[Finding]) -> Result<(), HistoryError>;
    /// Get deduplicated findings
    async fn get_deduplicated_findings(&self, scan_id: &ScanId) -> Result<Vec<Finding>, HistoryError>;

    /// Save comparison result
    async fn save_comparison(&self, comparison: &ScanComparison) -> Result<(), HistoryError>;
    /// Get comparison
    async fn get_comparison(&self, comparison_id: &str) -> Result<Option<ScanComparison>, HistoryError>;
    /// List comparisons
    async fn list_comparisons(&self, project_id: Option<ProjectId>, limit: usize, offset: usize) -> Result<Vec<ScanComparison>, HistoryError>;

    /// Save risk metrics
    async fn save_risk_metrics(&self, metrics: &RiskMetrics) -> Result<(), HistoryError>;
    /// Get risk metrics
    async fn get_risk_metrics(&self, project_id: &ProjectId, date_from: Option<DateTime<Utc>>, date_to: Option<DateTime<Utc>>) -> Result<Vec<RiskMetrics>, HistoryError>;
    /// Get latest risk metrics
    async fn get_latest_risk_metrics(&self, project_id: &ProjectId) -> Result<Option<RiskMetrics>, HistoryError>;
}

/// History error
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Database error: {0}")]
    Database(String),
}

/// Scan summary for history tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Scan ID
    pub scan_id: ScanId,
    /// Project ID
    pub project_id: Option<ProjectId>,
    /// Target ID
    pub target_id: TargetId,
    /// Scan name
    pub name: String,
    /// Scan description
    pub description: Option<String>,
    /// Scan status
    pub status: String,
    /// Scan configuration
    pub config: ScanConfigSummary,
    /// Scan progress at completion
    pub progress: ScanProgressSummary,
    /// Finding statistics
    pub finding_stats: FindingStats,
    /// Risk metrics
    pub risk_metrics: RiskMetricsSummary,
    /// Plugin executions summary
    pub plugin_executions: Vec<PluginExecutionSummary>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Started at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Duration in seconds
    pub duration_seconds: Option<u64>,
    /// Tags
    pub tags: Vec<String>,
}

/// Scan configuration summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigSummary {
    /// Scan name
    pub name: String,
    /// Target URL
    pub target_url: String,
    /// Plugins enabled
    pub plugins: Vec<String>,
    /// Rate limit
    pub rate_limit: Option<u32>,
    /// Timeout
    pub timeout_seconds: Option<u32>,
    /// Authentication configured
    pub auth_configured: bool,
    /// Custom headers count
    pub custom_headers_count: usize,
}

/// Scan progress summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgressSummary {
    /// Total endpoints
    pub total_endpoints: usize,
    /// Endpoints scanned
    pub endpoints_scanned: usize,
    /// Endpoints failed
    pub endpoints_failed: usize,
    /// Percentage complete
    pub percentage: f32,
}

/// Plugin execution summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionSummary {
    /// Plugin ID
    pub plugin_id: String,
    /// Plugin name
    pub plugin_name: String,
    /// Plugin version
    pub plugin_version: String,
    /// Status
    pub status: String,
    /// Findings count
    pub findings_count: usize,
    /// Duration seconds
    pub duration_seconds: Option<u64>,
    /// Error message
    pub error: Option<String>,
}

/// Risk metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMetricsSummary {
    /// Overall risk score
    pub overall_risk_score: u8,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Critical findings
    pub critical_count: usize,
    /// High findings
    pub high_count: usize,
    /// Medium findings
    pub medium_count: usize,
    /// Low findings
    pub low_count: usize,
    /// Info findings
    pub info_count: usize,
    /// Average risk score
    pub avg_risk_score: f32,
    /// Max risk score
    pub max_risk_score: u8,
}

/// Report artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportArtifact {
    /// Artifact ID
    pub id: String,
    /// Scan ID
    pub scan_id: ScanId,
    /// Project ID
    pub project_id: Option<ProjectId>,
    /// Report format
    pub format: ReportFormat,
    /// Report title
    pub title: String,
    /// File path or storage key
    pub storage_path: String,
    /// File size in bytes
    pub size_bytes: u64,
    /// Checksum (SHA256)
    pub checksum: String,
    /// Generated at
    pub generated_at: DateTime<Utc>,
    /// Generated by
    pub generated_by: String,
    /// Report configuration
    pub config: ReportConfig,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Stored evidence object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvidence {
    /// Evidence ID
    pub id: String,
    /// Finding ID
    pub finding_id: FindingId,
    /// Scan ID
    pub scan_id: ScanId,
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Description
    pub description: String,
    /// Raw data (compressed/encoded)
    pub data: Option<Vec<u8>>,
    /// Location
    pub location: Option<String>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// HTTP request (if applicable)
    pub http_request: Option<HttpRequestEvidence>,
    /// HTTP response (if applicable)
    pub http_response: Option<HttpResponseEvidence>,
    /// Timing (if applicable)
    pub timing: Option<TimingEvidence>,
    /// Payload (if applicable)
    pub payload: Option<PayloadEvidence>,
    /// Reproduction steps (if applicable)
    pub reproduction_steps: Option<ReproductionSteps>,
    /// Captured at
    pub captured_at: DateTime<Utc>,
    /// Plugin source
    pub plugin_source: String,
}

/// Risk metrics for trend tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMetrics {
    /// Metrics ID
    pub id: String,
    /// Project ID
    pub project_id: ProjectId,
    /// Scan ID (if from single scan)
    pub scan_id: Option<ScanId>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Overall risk score
    pub overall_risk_score: u8,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Findings by severity
    pub by_severity: HashMap<Severity, usize>,
    /// Findings by category
    pub by_category: HashMap<Category, usize>,
    /// Average risk score
    pub avg_risk_score: f32,
    /// Max risk score
    pub max_risk_score: u8,
    /// Critical count
    pub critical_count: usize,
    /// High count
    pub high_count: usize,
    /// Medium count
    pub medium_count: usize,
    /// Low count
    pub low_count: usize,
    /// Info count
    pub info_count: usize,
    /// Verified findings
    pub verified_count: usize,
    /// False positive count
    pub false_positive_count: usize,
    /// Exploit available count
    pub exploit_available_count: usize,
    /// Exploited in wild count
    pub exploited_in_wild_count: usize,
    /// Top CWEs
    pub top_cwes: Vec<(String, usize)>,
    /// Top OWASP categories
    pub top_owasp: Vec<(String, usize)>,
    /// Remediation priority distribution
    pub remediation_priority: HashMap<RemediationPriority, usize>,
    /// Trend indicators
    pub trends: RiskTrends,
}

/// Risk trends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTrends {
    /// Risk score change (vs previous)
    pub risk_score_change: i8,
    /// Critical findings change
    pub critical_change: i32,
    /// High findings change
    pub high_change: i32,
    /// New findings since last scan
    pub new_findings: usize,
    /// Fixed findings since last scan
    pub fixed_findings: usize,
    /// Regressed findings
    pub regressed_findings: usize,
    /// Overall trend direction
    pub trend_direction: TrendDirection,
}

impl Default for RiskTrends {
    fn default() -> Self {
        Self {
            risk_score_change: 0,
            critical_change: 0,
            high_change: 0,
            new_findings: 0,
            fixed_findings: 0,
            regressed_findings: 0,
            trend_direction: TrendDirection::Unknown,
        }
    }
}

/// Trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    /// Improving
    Improving,
    /// Stable
    Stable,
    /// Degrading
    Degrading,
    /// Unknown (first scan)
    Unknown,
}

impl HistoryManager {
    /// Create a new history manager
    pub fn new(storage: Box<dyn HistoryStorage>) -> Self {
        Self { storage }
    }

    /// Record a completed scan
    pub async fn record_scan(&self, summary: ScanSummary) -> Result<(), HistoryError> {
        self.storage.save_scan_summary(&summary).await?;
        
        // Also save risk metrics for trend tracking
        let risk_metrics = RiskMetrics {
            id: Uuid::new_v4().to_string(),
            project_id: summary.project_id.unwrap_or_else(ProjectId::new),
            scan_id: Some(summary.scan_id),
            timestamp: Utc::now(),
            overall_risk_score: summary.risk_metrics.overall_risk_score,
            risk_level: summary.risk_metrics.risk_level,
            by_severity: summary.finding_stats.by_severity.clone(),
            by_category: summary.finding_stats.by_category.clone(),
            avg_risk_score: summary.finding_stats.avg_risk_score,
            max_risk_score: summary.finding_stats.max_risk_score,
            critical_count: summary.risk_metrics.critical_count,
            high_count: summary.risk_metrics.high_count,
            medium_count: summary.risk_metrics.medium_count,
            low_count: summary.risk_metrics.low_count,
            info_count: summary.risk_metrics.info_count,
            verified_count: summary.finding_stats.verified,
            false_positive_count: summary.finding_stats.false_positives,
            exploit_available_count: summary.finding_stats.exploit_available_count,
            exploited_in_wild_count: summary.finding_stats.exploited_in_wild_count,
            top_cwes: summary.finding_stats.by_cwe.iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            top_owasp: summary.finding_stats.by_owasp_category.iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            remediation_priority: summary.finding_stats.by_remediation_priority.clone(),
            trends: RiskTrends {
                risk_score_change: 0,
                critical_change: 0,
                high_change: 0,
                new_findings: 0,
                fixed_findings: 0,
                regressed_findings: 0,
                trend_direction: TrendDirection::Unknown,
            },
        };
        
        self.storage.save_risk_metrics(&risk_metrics).await?;
        Ok(())
    }

    /// Get scan history for a project
    pub async fn get_project_history(&self, project_id: &ProjectId, limit: usize, offset: usize) -> Result<Vec<ScanSummary>, HistoryError> {
        self.storage.list_scan_summaries(Some(*project_id), limit, offset).await
    }

    /// Get all scan history
    pub async fn get_all_history(&self, limit: usize, offset: usize) -> Result<Vec<ScanSummary>, HistoryError> {
        self.storage.list_scan_summaries(None, limit, offset).await
    }

    /// Get scan summary
    pub async fn get_scan_summary(&self, scan_id: &ScanId) -> Result<Option<ScanSummary>, HistoryError> {
        self.storage.get_scan_summary(scan_id).await
    }

    /// Save report artifact
    pub async fn save_report(&self, artifact: ReportArtifact) -> Result<(), HistoryError> {
        self.storage.save_report_artifact(&artifact).await
    }

    /// Get report artifact
    pub async fn get_report(&self, artifact_id: &str) -> Result<Option<ReportArtifact>, HistoryError> {
        self.storage.get_report_artifact(artifact_id).await
    }

    /// List reports for a scan
    pub async fn list_reports_for_scan(&self, scan_id: &ScanId) -> Result<Vec<ReportArtifact>, HistoryError> {
        self.storage.list_report_artifacts(Some(*scan_id), 100, 0).await
    }

    /// Store evidence
    pub async fn store_evidence(&self, evidence: StoredEvidence) -> Result<(), HistoryError> {
        self.storage.save_evidence(&evidence).await
    }

    /// Get evidence for finding
    pub async fn get_evidence_for_finding(&self, finding_id: &FindingId) -> Result<Vec<StoredEvidence>, HistoryError> {
        self.storage.list_evidence_for_finding(finding_id).await
    }

    /// Save deduplicated findings
    pub async fn save_deduplicated(&self, scan_id: &ScanId, findings: &[Finding]) -> Result<(), HistoryError> {
        self.storage.save_deduplicated_findings(scan_id, findings).await
    }

    /// Get deduplicated findings
    pub async fn get_deduplicated(&self, scan_id: &ScanId) -> Result<Vec<Finding>, HistoryError> {
        self.storage.get_deduplicated_findings(scan_id).await
    }

    /// Save scan comparison
    pub async fn save_comparison(&self, comparison: ScanComparison) -> Result<(), HistoryError> {
        self.storage.save_comparison(&comparison).await
    }

    /// Get comparison
    pub async fn get_comparison(&self, comparison_id: &str) -> Result<Option<ScanComparison>, HistoryError> {
        self.storage.get_comparison(comparison_id).await
    }

    /// List comparisons
    pub async fn list_comparisons(&self, project_id: Option<ProjectId>, limit: usize, offset: usize) -> Result<Vec<ScanComparison>, HistoryError> {
        self.storage.list_comparisons(project_id, limit, offset).await
    }

    /// Get risk metrics history
    pub async fn get_risk_history(&self, project_id: &ProjectId, date_from: Option<DateTime<Utc>>, date_to: Option<DateTime<Utc>>) -> Result<Vec<RiskMetrics>, HistoryError> {
        self.storage.get_risk_metrics(project_id, date_from, date_to).await
    }

    /// Get latest risk metrics
    pub async fn get_latest_risk(&self, project_id: &ProjectId) -> Result<Option<RiskMetrics>, HistoryError> {
        self.storage.get_latest_risk_metrics(project_id).await
    }

    /// Calculate trends between two risk metrics
    pub fn calculate_trends(current: &RiskMetrics, previous: &RiskMetrics) -> RiskTrends {
        let risk_score_change = current.overall_risk_score as i8 - previous.overall_risk_score as i8;
        let critical_change = current.critical_count as i32 - previous.critical_count as i32;
        let high_change = current.high_count as i32 - previous.high_count as i32;

        let trend_direction = if risk_score_change < -5 || critical_change < 0 {
            TrendDirection::Improving
        } else if risk_score_change > 5 || critical_change > 0 || high_change > 2 {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        };

        RiskTrends {
            risk_score_change,
            critical_change,
            high_change,
            new_findings: 0, // Would need comparison logic
            fixed_findings: 0,
            regressed_findings: 0,
            trend_direction,
        }
    }
}

// Note: SqliteHistoryStorage implementation is moved to openre-storage crate
// to avoid sqlite dependency conflicts. The HistoryStorage trait can be
// implemented by any storage backend.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ScanId, ProjectId, TargetId, FindingId};
    use chrono::Utc;

    fn create_test_scan_summary() -> ScanSummary {
        ScanSummary {
            scan_id: ScanId::new(),
            project_id: Some(ProjectId::new()),
            target_id: TargetId::new(),
            name: "Test Scan".to_string(),
            description: Some("Test description".to_string()),
            status: "completed".to_string(),
            config: ScanConfigSummary {
                name: "Test Scan".to_string(),
                target_url: "http://example.com".to_string(),
                plugins: vec!["sql-injection".to_string()],
                rate_limit: Some(10),
                timeout_seconds: Some(300),
                auth_configured: false,
                custom_headers_count: 0,
            },
            progress: ScanProgressSummary {
                total_endpoints: 100,
                endpoints_scanned: 100,
                endpoints_failed: 0,
                percentage: 100.0,
            },
            finding_stats: FindingStats {
                total: 5,
                by_severity: HashMap::new(),
                by_confidence: HashMap::new(),
                by_category: HashMap::new(),
                by_plugin: HashMap::new(),
                verified: 3,
                false_positives: 1,
                avg_risk_score: 65.0,
                max_risk_score: 90,
                by_owasp_category: HashMap::new(),
                by_cwe: HashMap::new(),
                avg_advanced_risk_score: 70.0,
                max_advanced_risk_score: 95,
                by_remediation_priority: HashMap::new(),
                exploit_available_count: 2,
                exploited_in_wild_count: 1,
            },
            risk_metrics: RiskMetricsSummary {
                overall_risk_score: 70,
                risk_level: RiskLevel::High,
                critical_count: 1,
                high_count: 2,
                medium_count: 1,
                low_count: 1,
                info_count: 0,
                avg_risk_score: 65.0,
                max_risk_score: 90,
            },
            plugin_executions: vec![],
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            duration_seconds: Some(60),
            tags: vec!["test".to_string()],
        }
    }

    #[test]
    fn test_risk_trends_calculation() {
        let mut previous = RiskMetrics {
            id: "1".to_string(),
            project_id: ProjectId::new(),
            scan_id: None,
            timestamp: Utc::now() - chrono::Duration::days(1),
            overall_risk_score: 80,
            risk_level: RiskLevel::High,
            by_severity: HashMap::new(),
            by_category: HashMap::new(),
            avg_risk_score: 75.0,
            max_risk_score: 90,
            critical_count: 2,
            high_count: 3,
            medium_count: 5,
            low_count: 2,
            info_count: 1,
            verified_count: 10,
            false_positive_count: 1,
            exploit_available_count: 3,
            exploited_in_wild_count: 1,
            top_cwes: vec![],
            top_owasp: vec![],
            remediation_priority: HashMap::new(),
            trends: RiskTrends::default(),
        };

        let mut current = previous.clone();
        current.id = "2".to_string();
        current.timestamp = Utc::now();
        current.overall_risk_score = 60;
        current.critical_count = 1;
        current.high_count = 2;

        let trends = HistoryManager::calculate_trends(&current, &previous);
        assert_eq!(trends.trend_direction, TrendDirection::Improving);
        assert_eq!(trends.risk_score_change, -20);
        assert_eq!(trends.critical_change, -1);
    }

    #[test]
    fn test_trend_direction_degrading() {
        let mut previous = RiskMetrics {
            id: "1".to_string(),
            project_id: ProjectId::new(),
            scan_id: None,
            timestamp: Utc::now() - chrono::Duration::days(1),
            overall_risk_score: 50,
            risk_level: RiskLevel::Medium,
            by_severity: HashMap::new(),
            by_category: HashMap::new(),
            avg_risk_score: 45.0,
            max_risk_score: 70,
            critical_count: 0,
            high_count: 1,
            medium_count: 3,
            low_count: 2,
            info_count: 1,
            verified_count: 5,
            false_positive_count: 0,
            exploit_available_count: 1,
            exploited_in_wild_count: 0,
            top_cwes: vec![],
            top_owasp: vec![],
            remediation_priority: HashMap::new(),
            trends: RiskTrends::default(),
        };

        let mut current = previous.clone();
        current.id = "2".to_string();
        current.timestamp = Utc::now();
        current.overall_risk_score = 75;
        current.critical_count = 2;
        current.high_count = 3;

        let trends = HistoryManager::calculate_trends(&current, &previous);
        assert_eq!(trends.trend_direction, TrendDirection::Degrading);
    }
}