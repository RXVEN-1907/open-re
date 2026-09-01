//! Storage layer for persisting scans, targets, plugin executions, findings, logs, and timing information

use crate::error::{ScannerError, ScannerResult};
use crate::plugin::PluginId;
use crate::result::{Finding, FindingFilter, FindingId, FindingSort, FindingStats};
use crate::scan::{ScanId, ScanLogEntry, ScanProgress, ScanSession, ScanStatus};
use crate::target::{ScanConfig, Target, TargetId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use openre_core::ids::ProjectId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Scan record for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: ScanId,
    pub project_id: Option<ProjectId>,
    pub target_id: TargetId,
    pub name: String,
    pub description: Option<String>,
    pub status: ScanStatus,
    pub config: ScanConfig,
    pub progress: ScanProgress,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration: Option<std::time::Duration>,
    pub tags: Vec<String>,
}

/// Finding record for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: FindingId,
    pub scan_id: ScanId,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub target: String,
    pub target_type: String,
    pub evidence: serde_json::Value,
    pub references: serde_json::Value,
    pub plugin_source: String,
    pub plugin_version: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
    pub tags: serde_json::Value,
    pub verified: bool,
    pub false_positive: bool,
    pub risk_score: Option<u8>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f32>,
}

/// Plugin execution record for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionRecord {
    pub id: Uuid,
    pub scan_id: ScanId,
    pub plugin_id: PluginId,
    pub plugin_name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String,
    pub findings_count: usize,
    pub error: Option<String>,
    pub duration: Option<std::time::Duration>,
}

/// Target record for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRecord {
    pub id: TargetId,
    pub project_id: Option<ProjectId>,
    pub target_type: String,
    pub name: String,
    pub description: Option<String>,
    pub base_url: String,
    pub headers: serde_json::Value,
    pub cookies: serde_json::Value,
    pub auth: Option<serde_json::Value>,
    pub rate_limit: Option<serde_json::Value>,
    pub tls_config: Option<serde_json::Value>,
    pub proxy: Option<serde_json::Value>,
    pub custom: serde_json::Value,
    pub tags: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Trait for scan storage
#[async_trait]
pub trait ScanStorage: Send + Sync {
    async fn save_scan(&self, session: &ScanSession) -> ScannerResult<()>;
    async fn get_scan(&self, scan_id: &ScanId) -> ScannerResult<Option<ScanSession>>;
    async fn list_scans(
        &self,
        limit: usize,
        offset: usize,
        project_id: Option<ProjectId>,
    ) -> ScannerResult<Vec<ScanSession>>;
    async fn delete_scan(&self, scan_id: &ScanId) -> ScannerResult<bool>;
    async fn save_finding(&self, scan_id: ScanId, finding: &Finding) -> ScannerResult<()>;
    async fn get_findings(&self, scan_id: &ScanId) -> ScannerResult<Vec<Finding>>;
    async fn get_findings_filtered(
        &self,
        filter: FindingFilter,
        sort: FindingSort,
        limit: usize,
        offset: usize,
    ) -> ScannerResult<Vec<Finding>>;
    async fn list_findings(
        &self,
        filter: FindingFilter,
        sort: FindingSort,
        limit: usize,
        offset: usize,
    ) -> ScannerResult<Vec<Finding>>;
    async fn count_findings(&self, filter: FindingFilter) -> ScannerResult<u64>;
    async fn get_finding(&self, finding_id: &FindingId) -> ScannerResult<Option<Finding>>;
    async fn get_finding_stats(&self, filter: FindingFilter) -> ScannerResult<FindingStats>;
    async fn save_log(&self, scan_id: ScanId, log: &ScanLogEntry) -> ScannerResult<()>;
    async fn get_logs(&self, scan_id: &ScanId) -> ScannerResult<Vec<ScanLogEntry>>;
    async fn save_target(&self, target: &Target) -> ScannerResult<()>;
    async fn get_target(&self, target_id: &TargetId) -> ScannerResult<Option<Target>>;
    async fn list_targets(&self, project_id: Option<ProjectId>) -> ScannerResult<Vec<Target>>;
    async fn delete_target(&self, target_id: &TargetId) -> ScannerResult<bool>;
    async fn save_plugin_execution(&self, record: &PluginExecutionRecord) -> ScannerResult<()>;
    async fn get_plugin_executions(
        &self,
        scan_id: &ScanId,
    ) -> ScannerResult<Vec<PluginExecutionRecord>>;
}

/// SQLite-based scan storage implementation
///
/// NOTE: the SQLite backend is not wired up yet. This workspace links
/// `rusqlite` (via `openre-core`) and Cargo only allows one package to link
/// the native `sqlite3` library, so sqlx's `sqlite` feature cannot be enabled
/// here. The public type is kept so callers keep compiling; every persistence
/// operation currently returns a clear "not yet supported" error. Use
/// [`MemoryScanStorage`] in the meantime.
#[derive(Clone)]
pub struct SqliteScanStorage {
    #[allow(dead_code)]
    database_url: String,
}

impl SqliteScanStorage {
    /// Create a new SQLite scan storage
    pub async fn new(database_url: &str) -> ScannerResult<Self> {
        Ok(Self { database_url: database_url.to_string() })
    }

    /// Placeholder error until the SQLite backend is implemented
    fn unsupported<T>() -> ScannerResult<T> {
        Err(ScannerError::Internal(
            "SQLite persistence is not yet supported; use MemoryScanStorage".to_string(),
        ))
    }
}

#[async_trait]
impl ScanStorage for SqliteScanStorage {
    async fn save_scan(&self, _session: &ScanSession) -> ScannerResult<()> {
        Self::unsupported()
    }

    async fn get_scan(&self, _scan_id: &ScanId) -> ScannerResult<Option<ScanSession>> {
        Self::unsupported()
    }

    async fn list_scans(
        &self,
        _limit: usize,
        _offset: usize,
        _project_id: Option<ProjectId>,
    ) -> ScannerResult<Vec<ScanSession>> {
        Self::unsupported()
    }

    async fn delete_scan(&self, _scan_id: &ScanId) -> ScannerResult<bool> {
        Self::unsupported()
    }

    async fn save_finding(&self, _scan_id: ScanId, _finding: &Finding) -> ScannerResult<()> {
        Self::unsupported()
    }

    async fn get_findings(&self, _scan_id: &ScanId) -> ScannerResult<Vec<Finding>> {
        Self::unsupported()
    }

    async fn get_findings_filtered(
        &self,
        _filter: FindingFilter,
        _sort: FindingSort,
        _limit: usize,
        _offset: usize,
    ) -> ScannerResult<Vec<Finding>> {
        Self::unsupported()
    }

    async fn list_findings(
        &self,
        filter: FindingFilter,
        sort: FindingSort,
        limit: usize,
        offset: usize,
    ) -> ScannerResult<Vec<Finding>> {
        self.get_findings_filtered(filter, sort, limit, offset).await
    }

    async fn count_findings(&self, _filter: FindingFilter) -> ScannerResult<u64> {
        Self::unsupported()
    }

    async fn get_finding(&self, _finding_id: &FindingId) -> ScannerResult<Option<Finding>> {
        Self::unsupported()
    }

    async fn get_finding_stats(&self, _filter: FindingFilter) -> ScannerResult<FindingStats> {
        Self::unsupported()
    }

    async fn save_log(&self, _scan_id: ScanId, _log: &ScanLogEntry) -> ScannerResult<()> {
        Self::unsupported()
    }

    async fn get_logs(&self, _scan_id: &ScanId) -> ScannerResult<Vec<ScanLogEntry>> {
        Self::unsupported()
    }

    async fn save_target(&self, _target: &Target) -> ScannerResult<()> {
        Self::unsupported()
    }

    async fn get_target(&self, _target_id: &TargetId) -> ScannerResult<Option<Target>> {
        Self::unsupported()
    }

    async fn list_targets(&self, _project_id: Option<ProjectId>) -> ScannerResult<Vec<Target>> {
        Self::unsupported()
    }

    async fn delete_target(&self, _target_id: &TargetId) -> ScannerResult<bool> {
        Self::unsupported()
    }

    async fn save_plugin_execution(&self, _record: &PluginExecutionRecord) -> ScannerResult<()> {
        Self::unsupported()
    }

    async fn get_plugin_executions(
        &self,
        _scan_id: &ScanId,
    ) -> ScannerResult<Vec<PluginExecutionRecord>> {
        Self::unsupported()
    }
}

/// In-memory scan storage for testing
pub struct MemoryScanStorage {
    scans: Arc<dashmap::DashMap<ScanId, ScanSession>>,
    findings: Arc<dashmap::DashMap<FindingId, Finding>>,
    findings_by_scan: Arc<dashmap::DashMap<ScanId, Vec<FindingId>>>,
    targets: Arc<dashmap::DashMap<TargetId, Target>>,
    plugin_executions: Arc<dashmap::DashMap<ScanId, Vec<PluginExecutionRecord>>>,
    logs: Arc<dashmap::DashMap<ScanId, Vec<ScanLogEntry>>>,
}

impl MemoryScanStorage {
    /// Create a new in-memory scan storage
    pub fn new() -> Self {
        Self {
            scans: Arc::new(dashmap::DashMap::new()),
            findings: Arc::new(dashmap::DashMap::new()),
            findings_by_scan: Arc::new(dashmap::DashMap::new()),
            targets: Arc::new(dashmap::DashMap::new()),
            plugin_executions: Arc::new(dashmap::DashMap::new()),
            logs: Arc::new(dashmap::DashMap::new()),
        }
    }
}

#[async_trait]
impl ScanStorage for MemoryScanStorage {
    async fn save_scan(&self, session: &ScanSession) -> ScannerResult<()> {
        self.scans.insert(session.id, session.clone());
        Ok(())
    }

    async fn get_scan(&self, scan_id: &ScanId) -> ScannerResult<Option<ScanSession>> {
        Ok(self.scans.get(scan_id).map(|s| s.clone()))
    }

    async fn list_scans(
        &self,
        limit: usize,
        offset: usize,
        _project_id: Option<ProjectId>,
    ) -> ScannerResult<Vec<ScanSession>> {
        let mut scans: Vec<ScanSession> = self.scans.iter().map(|s| s.clone()).collect();
        scans.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(scans.into_iter().skip(offset).take(limit).collect())
    }

    async fn delete_scan(&self, scan_id: &ScanId) -> ScannerResult<bool> {
        self.findings_by_scan.remove(scan_id);
        self.plugin_executions.remove(scan_id);
        self.logs.remove(scan_id);
        Ok(self.scans.remove(scan_id).is_some())
    }

    async fn save_finding(&self, scan_id: ScanId, finding: &Finding) -> ScannerResult<()> {
        self.findings.insert(finding.id, finding.clone());
        self.findings_by_scan.entry(scan_id).or_default().push(finding.id);
        Ok(())
    }

    async fn get_findings(&self, scan_id: &ScanId) -> ScannerResult<Vec<Finding>> {
        let ids = self.findings_by_scan.get(scan_id).map(|v| v.clone()).unwrap_or_default();
        Ok(ids.iter().filter_map(|id| self.findings.get(id).map(|f| f.clone())).collect())
    }

    async fn list_findings(
        &self,
        filter: FindingFilter,
        sort: FindingSort,
        limit: usize,
        offset: usize,
    ) -> ScannerResult<Vec<Finding>> {
        self.get_findings_filtered(filter, sort, limit, offset).await
    }

    async fn count_findings(&self, filter: FindingFilter) -> ScannerResult<u64> {
        let findings =
            self.get_findings_filtered(filter, FindingSort::SeverityDesc, usize::MAX, 0).await?;
        Ok(findings.len() as u64)
    }

    async fn get_finding(&self, finding_id: &FindingId) -> ScannerResult<Option<Finding>> {
        Ok(self.findings.get(finding_id).map(|f| f.clone()))
    }

    async fn get_findings_filtered(
        &self,
        filter: FindingFilter,
        sort: FindingSort,
        limit: usize,
        offset: usize,
    ) -> ScannerResult<Vec<Finding>> {
        let mut findings: Vec<Finding> = self.findings.iter().map(|f| f.clone()).collect();

        // Apply filter
        findings.retain(|f| {
            if let Some(severities) = &filter.severity {
                if !severities.contains(&f.severity) {
                    return false;
                }
            }
            if let Some(confidences) = &filter.confidence {
                if !confidences.contains(&f.confidence) {
                    return false;
                }
            }
            if let Some(categories) = &filter.category {
                if !categories.contains(&f.category) {
                    return false;
                }
            }
            if let Some(target) = &filter.target {
                if !f.target.contains(target) {
                    return false;
                }
            }
            if let Some(plugin) = &filter.plugin_source {
                if f.plugin_source != *plugin {
                    return false;
                }
            }
            if let Some(scan_id) = &filter.scan_id {
                if f.scan_id != *scan_id {
                    return false;
                }
            }
            if let Some(verified) = filter.verified {
                if f.verified != verified {
                    return false;
                }
            }
            if let Some(false_positive) = filter.false_positive {
                if f.false_positive != false_positive {
                    return false;
                }
            }
            if let Some(tags) = &filter.tags {
                if !tags.iter().all(|t| f.tags.contains(t)) {
                    return false;
                }
            }
            if let Some(date_from) = filter.date_from {
                if f.timestamp < date_from {
                    return false;
                }
            }
            if let Some(date_to) = filter.date_to {
                if f.timestamp > date_to {
                    return false;
                }
            }
            if let Some(search) = &filter.search {
                let search_lower = search.to_lowercase();
                if !f.title.to_lowercase().contains(&search_lower)
                    && !f.description.to_lowercase().contains(&search_lower)
                {
                    return false;
                }
            }
            if let Some(min_score) = filter.min_risk_score {
                if f.risk_score.unwrap_or(0) < min_score {
                    return false;
                }
            }
            if let Some(max_score) = filter.max_risk_score {
                if f.risk_score.unwrap_or(100) > max_score {
                    return false;
                }
            }
            true
        });

        // Sort
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

        Ok(findings.into_iter().skip(offset).take(limit).collect())
    }

    async fn get_finding_stats(&self, filter: FindingFilter) -> ScannerResult<FindingStats> {
        let findings =
            self.get_findings_filtered(filter, FindingSort::SeverityDesc, usize::MAX, 0).await?;

        let mut by_severity = HashMap::new();
        let mut by_confidence = HashMap::new();
        let mut by_category = HashMap::new();
        let mut by_plugin = HashMap::new();
        let mut verified = 0;
        let mut false_positives = 0;
        let mut total_risk_score = 0u32;
        let mut risk_score_count = 0;
        let mut max_risk_score = 0u8;

        for finding in &findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
            *by_confidence.entry(finding.confidence).or_insert(0) += 1;
            *by_category.entry(finding.category.clone()).or_insert(0) += 1;
            *by_plugin.entry(finding.plugin_source.clone()).or_insert(0) += 1;
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
        }

        Ok(FindingStats {
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
            by_owasp_category: HashMap::new(),
            by_cwe: HashMap::new(),
            avg_advanced_risk_score: 0.0,
            max_advanced_risk_score: 0,
            by_remediation_priority: HashMap::new(),
            exploit_available_count: 0,
            exploited_in_wild_count: 0,
        })
    }

    async fn save_log(&self, scan_id: ScanId, log: &ScanLogEntry) -> ScannerResult<()> {
        self.logs.entry(scan_id).or_default().push(log.clone());
        Ok(())
    }

    async fn get_logs(&self, scan_id: &ScanId) -> ScannerResult<Vec<ScanLogEntry>> {
        Ok(self.logs.get(scan_id).map(|l| l.clone()).unwrap_or_default())
    }

    async fn save_target(&self, target: &Target) -> ScannerResult<()> {
        self.targets.insert(target.id, target.clone());
        Ok(())
    }

    async fn get_target(&self, target_id: &TargetId) -> ScannerResult<Option<Target>> {
        Ok(self.targets.get(target_id).map(|t| t.clone()))
    }

    async fn list_targets(&self, _project_id: Option<ProjectId>) -> ScannerResult<Vec<Target>> {
        Ok(self.targets.iter().map(|t| t.clone()).collect())
    }

    async fn delete_target(&self, target_id: &TargetId) -> ScannerResult<bool> {
        Ok(self.targets.remove(target_id).is_some())
    }

    async fn save_plugin_execution(&self, record: &PluginExecutionRecord) -> ScannerResult<()> {
        self.plugin_executions.entry(record.scan_id).or_default().push(record.clone());
        Ok(())
    }

    async fn get_plugin_executions(
        &self,
        scan_id: &ScanId,
    ) -> ScannerResult<Vec<PluginExecutionRecord>> {
        Ok(self.plugin_executions.get(scan_id).map(|v| v.clone()).unwrap_or_default())
    }
}

impl Default for MemoryScanStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryScanStorage::new();
        let scan_id = ScanId::new();
        let target_id = TargetId::new();

        let target = Target::new(
            crate::target::TargetType::RestApi,
            crate::target::TargetMetadata::new(
                "Test".to_string(),
                "https://example.com".parse().unwrap(),
            ),
        );

        storage.save_target(&target).await.unwrap();
        let retrieved = storage.get_target(&target_id).await.unwrap();
        assert!(retrieved.is_none()); // Different ID

        let retrieved = storage.get_target(&target.id).await.unwrap();
        assert!(retrieved.is_some());
    }
}
