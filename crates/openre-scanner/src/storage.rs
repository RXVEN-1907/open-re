//! Storage layer for persisting scans, targets, plugin executions, findings, logs, and timing information

use crate::error::{ScannerError, ScannerResult};
use crate::result::{Finding, FindingId, FindingFilter, FindingSort, FindingStats};
use crate::scan::{ScanSession, ScanId, ScanProgress, ScanStatus, PluginExecutionRecord, ScanLogEntry};
use crate::target::{Target, TargetId, TargetMetadata, ScanConfig};
use crate::plugin::{PluginInfo, PluginId, PluginConfig};
use openre_core::ids::ProjectId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, Row};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
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
    async fn list_scans(&self, limit: usize, offset: usize, project_id: Option<ProjectId>) -> ScannerResult<Vec<ScanSession>>;
    async fn delete_scan(&self, scan_id: &ScanId) -> ScannerResult<bool>;
    async fn save_finding(&self, scan_id: ScanId, finding: &Finding) -> ScannerResult<()>;
    async fn get_findings(&self, scan_id: &ScanId) -> ScannerResult<Vec<Finding>>;
    async fn get_findings_filtered(&self, filter: FindingFilter, sort: FindingSort, limit: usize, offset: usize) -> ScannerResult<Vec<Finding>>;
    async fn list_findings(&self, filter: FindingFilter, sort: FindingSort, limit: usize, offset: usize) -> ScannerResult<Vec<Finding>>;
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
    async fn get_plugin_executions(&self, scan_id: &ScanId) -> ScannerResult<Vec<PluginExecutionRecord>>;
}

/// SQLite-based scan storage implementation
pub struct SqliteScanStorage {
    pool: Pool<Sqlite>,
}

impl SqliteScanStorage {
    /// Create a new SQLite scan storage
    pub async fn new(database_url: &str) -> ScannerResult<Self> {
        let pool = Pool::<Sqlite>::connect(database_url).await?;
        let storage = Self { pool };
        storage.migrate().await?;
        Ok(storage)
    }

    /// Run database migrations
    async fn migrate(&self) -> ScannerResult<()> {
        // Create scans table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                target_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                config TEXT NOT NULL,
                progress TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                duration_ms INTEGER,
                tags TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create findings table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                category TEXT NOT NULL,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                evidence TEXT NOT NULL,
                references TEXT NOT NULL,
                plugin_source TEXT NOT NULL,
                plugin_version TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata TEXT NOT NULL,
                tags TEXT NOT NULL,
                verified BOOLEAN NOT NULL DEFAULT 0,
                false_positive BOOLEAN NOT NULL DEFAULT 0,
                risk_score INTEGER,
                cvss_vector TEXT,
                cvss_score REAL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create plugin_executions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS plugin_executions (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                plugin_id TEXT NOT NULL,
                plugin_name TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                findings_count INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                duration_ms INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create targets table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                target_type TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                base_url TEXT NOT NULL,
                headers TEXT NOT NULL,
                cookies TEXT NOT NULL,
                auth TEXT,
                rate_limit TEXT,
                tls_config TEXT,
                proxy TEXT,
                custom TEXT NOT NULL,
                tags TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create scan_logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                plugin TEXT,
                message TEXT NOT NULL,
                metadata TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_findings_plugin_source ON findings(plugin_source)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_plugin_executions_scan_id ON plugin_executions(scan_id)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_targets_project_id ON targets(project_id)").execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id)").execute(&self.pool).await?;

        Ok(())
    }

    /// Convert ScanSession to ScanRecord
    fn session_to_record(&self, session: &ScanSession) -> ScanRecord {
        ScanRecord {
            id: session.id,
            project_id: None, // Would be set from context
            target_id: session.target.id,
            name: session.config.name.clone(),
            description: session.config.description.clone(),
            status: session.status.clone(),
            config: session.config.clone(),
            progress: session.progress.clone(),
            created_at: session.created_at,
            started_at: session.started_at,
            completed_at: session.completed_at,
            duration: session.completed_at.zip(session.started_at).map(|(end, start)| {
                (end - start).to_std().unwrap_or_default()
            }),
            tags: session.config.tags.clone(),
        }
    }

    /// Convert ScanRecord to ScanSession
    fn record_to_session(&self, record: ScanRecord) -> ScanSession {
        ScanSession {
            id: record.id,
            config: record.config,
            target: Target::new(record.target_id, TargetMetadata::new("".to_string(), record.config.target_id.into())), // Placeholder
            status: record.status,
            progress: record.progress,
            findings: Vec::new(), // Loaded separately
            plugin_executions: Vec::new(), // Loaded separately
            logs: Vec::new(), // Loaded separately
            created_at: record.created_at,
            started_at: record.started_at,
            completed_at: record.completed_at,
            cancellation_token: None,
        }
    }
}

#[async_trait]
impl ScanStorage for SqliteScanStorage {
    async fn save_scan(&self, session: &ScanSession) -> ScannerResult<()> {
        let record = self.session_to_record(session);
        let config_json = serde_json::to_string(&record.config)?;
        let progress_json = serde_json::to_string(&record.progress)?;
        let tags_json = serde_json::to_string(&record.tags)?;

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO scans (id, project_id, target_id, name, description, status, config, progress, created_at, started_at, completed_at, duration_ms, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(record.id.to_string())
        .bind(record.project_id.map(|p| p.to_string()))
        .bind(record.target_id.to_string())
        .bind(&record.name)
        .bind(&record.description)
        .bind(record.status.to_string())
        .bind(&config_json)
        .bind(&progress_json)
        .bind(record.created_at.to_rfc3339())
        .bind(record.started_at.map(|dt| dt.to_rfc3339()))
        .bind(record.completed_at.map(|dt| dt.to_rfc3339()))
        .bind(record.duration.map(|d| d.as_millis() as i64))
        .bind(&tags_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_scan(&self, scan_id: &ScanId) -> ScannerResult<Option<ScanSession>> {
        let row = sqlx::query("SELECT * FROM scans WHERE id = ?")
            .bind(scan_id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            let record = ScanRecord {
                id: ScanId::from_string(&row.get::<String, _>("id"))?,
                project_id: row.get::<Option<String>, _>("project_id").map(|s| ProjectId::from_string(&s).unwrap()),
                target_id: TargetId::from_string(&row.get::<String, _>("target_id"))?,
                name: row.get("name"),
                description: row.get("description"),
                status: row.get::<String, _>("status").parse()?,
                config: serde_json::from_str(&row.get::<String, _>("config"))?,
                progress: serde_json::from_str(&row.get::<String, _>("progress"))?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                started_at: row.get::<Option<String>, _>("started_at").map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                completed_at: row.get::<Option<String>, _>("completed_at").map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                duration: row.get::<Option<i64>, _>("duration_ms").map(|ms| std::time::Duration::from_millis(ms as u64)),
                tags: serde_json::from_str(&row.get::<String, _>("tags"))?,
            };

            // Load findings
            let findings = self.get_findings(scan_id).await?;
            // Load plugin executions
            let plugin_executions = self.get_plugin_executions(scan_id).await?;
            // Load logs
            let logs = self.get_logs(scan_id).await?;

            let mut session = self.record_to_session(record);
            session.findings = findings;
            session.plugin_executions = plugin_executions;
            session.logs = logs;

            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn list_scans(&self, limit: usize, offset: usize, project_id: Option<ProjectId>) -> ScannerResult<Vec<ScanSession>> {
        let query = if project_id.is_some() {
            "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
        } else {
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?"
        };

        let mut query_builder = sqlx::query(query);
        if let Some(pid) = project_id {
            query_builder = query_builder.bind(pid.to_string());
        }
        query_builder = query_builder.bind(limit as i64).bind(offset as i64);

        let rows = query_builder.fetch_all(&self.pool).await?;

        let mut sessions = Vec::new();
        for row in rows {
            let record = ScanRecord {
                id: ScanId::from_string(&row.get::<String, _>("id"))?,
                project_id: row.get::<Option<String>, _>("project_id").map(|s| ProjectId::from_string(&s).unwrap()),
                target_id: TargetId::from_string(&row.get::<String, _>("target_id"))?,
                name: row.get("name"),
                description: row.get("description"),
                status: row.get::<String, _>("status").parse()?,
                config: serde_json::from_str(&row.get::<String, _>("config"))?,
                progress: serde_json::from_str(&row.get::<String, _>("progress"))?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                started_at: row.get::<Option<String>, _>("started_at").map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                completed_at: row.get::<Option<String>, _>("completed_at").map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                duration: row.get::<Option<i64>, _>("duration_ms").map(|ms| std::time::Duration::from_millis(ms as u64)),
                tags: serde_json::from_str(&row.get::<String, _>("tags"))?,
            };

            let mut session = self.record_to_session(record);
            session.findings = self.get_findings(&session.id).await?;
            session.plugin_executions = self.get_plugin_executions(&session.id).await?;
            session.logs = self.get_logs(&session.id).await?;

            sessions.push(session);
        }

        Ok(sessions)
    }

    async fn delete_scan(&self, scan_id: &ScanId) -> ScannerResult<bool> {
        let result = sqlx::query("DELETE FROM scans WHERE id = ?")
            .bind(scan_id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn save_finding(&self, scan_id: ScanId, finding: &Finding) -> ScannerResult<()> {
        let evidence_json = serde_json::to_string(&finding.evidence)?;
        let references_json = serde_json::to_string(&finding.references)?;
        let metadata_json = serde_json::to_string(&finding.metadata)?;
        let tags_json = serde_json::to_string(&finding.tags)?;

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO findings (id, scan_id, title, description, severity, confidence, category, target, target_type, evidence, references, plugin_source, plugin_version, timestamp, metadata, tags, verified, false_positive, risk_score, cvss_vector, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(finding.id.to_string())
        .bind(scan_id.to_string())
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(finding.severity.to_string())
        .bind(finding.confidence.to_string())
        .bind(finding.category.to_string())
        .bind(&finding.target)
        .bind(&finding.target_type)
        .bind(&evidence_json)
        .bind(&references_json)
        .bind(&finding.plugin_source)
        .bind(&finding.plugin_version)
        .bind(finding.timestamp.to_rfc3339())
        .bind(&metadata_json)
        .bind(&tags_json)
        .bind(finding.verified)
        .bind(finding.false_positive)
        .bind(finding.risk_score.map(|s| s as i64))
        .bind(&finding.cvss_vector)
        .bind(finding.cvss_score)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_findings(&self, scan_id: &ScanId) -> ScannerResult<Vec<Finding>> {
        let rows = sqlx::query("SELECT * FROM findings WHERE scan_id = ? ORDER BY timestamp DESC")
            .bind(scan_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(Finding {
                id: FindingId::from_string(&row.get::<String, _>("id"))?,
                title: row.get("title"),
                description: row.get("description"),
                severity: row.get::<String, _>("severity").parse()?,
                confidence: row.get::<String, _>("confidence").parse()?,
                category: row.get::<String, _>("category").parse()?,
                target: row.get("target"),
                target_type: row.get("target_type"),
                evidence: serde_json::from_str(&row.get::<String, _>("evidence"))?,
                references: serde_json::from_str(&row.get::<String, _>("references"))?,
                plugin_source: row.get("plugin_source"),
                plugin_version: row.get("plugin_version"),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<String, _>("timestamp"))?.with_timezone(&Utc),
                metadata: serde_json::from_str(&row.get::<String, _>("metadata"))?,
                tags: serde_json::from_str(&row.get::<String, _>("tags"))?,
                verified: row.get("verified"),
                false_positive: row.get("false_positive"),
                risk_score: row.get::<Option<i64>, _>("risk_score").map(|s| s as u8),
                cvss_vector: row.get("cvss_vector"),
                cvss_score: row.get("cvss_score"),
                scan_id: *scan_id,
            });
        }

        Ok(findings)
    }

    async fn get_findings_filtered(&self, filter: FindingFilter, sort: FindingSort, limit: usize, offset: usize) -> ScannerResult<Vec<Finding>> {
        let mut query = "SELECT * FROM findings WHERE 1=1".to_string();
        let mut params: Vec<String> = Vec::new();

        if let Some(severities) = filter.severity {
            let placeholders = severities.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND severity IN ({})", placeholders));
            for s in severities {
                params.push(s.to_string());
            }
        }

        if let Some(confidences) = filter.confidence {
            let placeholders = confidences.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND confidence IN ({})", placeholders));
            for c in confidences {
                params.push(c.to_string());
            }
        }

        if let Some(categories) = filter.category {
            let placeholders = categories.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND category IN ({})", placeholders));
            for c in categories {
                params.push(c.to_string());
            }
        }

        if let Some(target) = filter.target {
            query.push_str(" AND target LIKE ?");
            params.push(format!("%{}%", target));
        }

        if let Some(plugin) = filter.plugin_source {
            query.push_str(" AND plugin_source = ?");
            params.push(plugin);
        }

        if let Some(scan_id) = filter.scan_id {
            query.push_str(" AND scan_id = ?");
            params.push(scan_id.to_string());
        }

        if let Some(verified) = filter.verified {
            query.push_str(" AND verified = ?");
            params.push(verified.to_string());
        }

        if let Some(false_positive) = filter.false_positive {
            query.push_str(" AND false_positive = ?");
            params.push(false_positive.to_string());
        }

        if let Some(date_from) = filter.date_from {
            query.push_str(" AND timestamp >= ?");
            params.push(date_from.to_rfc3339());
        }

        if let Some(date_to) = filter.date_to {
            query.push_str(" AND timestamp <= ?");
            params.push(date_to.to_rfc3339());
        }

        if let Some(search) = filter.search {
            query.push_str(" AND (title LIKE ? OR description LIKE ?)");
            params.push(format!("%{}%", search));
            params.push(format!("%{}%", search));
        }

        // Add sorting
        let sort_clause = match sort {
            FindingSort::SeverityDesc => "ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC",
            FindingSort::SeverityAsc => "ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END ASC",
            FindingSort::ConfidenceDesc => "ORDER BY CASE confidence WHEN 'very_high' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC",
            FindingSort::TimestampDesc => "ORDER BY timestamp DESC",
            FindingSort::TimestampAsc => "ORDER BY timestamp ASC",
            FindingSort::RiskScoreDesc => "ORDER BY risk_score DESC NULLS LAST",
            FindingSort::TargetAsc => "ORDER BY target ASC",
        };
        query.push_str(&format!(" {}", sort_clause));

        // Add pagination
        query.push_str(" LIMIT ? OFFSET ?");
        params.push(limit.to_string());
        params.push(offset.to_string());

        // Execute query with dynamic parameters
        let mut query_builder = sqlx::query(&query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        let rows = query_builder.fetch_all(&self.pool).await?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(Finding {
                id: FindingId::from_string(&row.get::<String, _>("id"))?,
                title: row.get("title"),
                description: row.get("description"),
                severity: row.get::<String, _>("severity").parse()?,
                confidence: row.get::<String, _>("confidence").parse()?,
                category: row.get::<String, _>("category").parse()?,
                target: row.get("target"),
                target_type: row.get("target_type"),
                evidence: serde_json::from_str(&row.get::<String, _>("evidence"))?,
                references: serde_json::from_str(&row.get::<String, _>("references"))?,
                plugin_source: row.get("plugin_source"),
                plugin_version: row.get("plugin_version"),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<String, _>("timestamp"))?.with_timezone(&Utc),
                metadata: serde_json::from_str(&row.get::<String, _>("metadata"))?,
                tags: serde_json::from_str(&row.get::<String, _>("tags"))?,
                verified: row.get("verified"),
                false_positive: row.get("false_positive"),
                risk_score: row.get::<Option<i64>, _>("risk_score").map(|s| s as u8),
                cvss_vector: row.get("cvss_vector"),
                cvss_score: row.get("cvss_score"),
                scan_id: ScanId::from_string(&row.get::<String, _>("scan_id"))?,
            });
        }

        Ok(findings)
    }

    async fn list_findings(&self, filter: FindingFilter, sort: FindingSort, limit: usize, offset: usize) -> ScannerResult<Vec<Finding>> {
        self.get_findings_filtered(filter, sort, limit, offset).await
    }

    async fn count_findings(&self, filter: FindingFilter) -> ScannerResult<u64> {
        let mut query = "SELECT COUNT(*) as count FROM findings WHERE 1=1".to_string();
        let mut params: Vec<String> = Vec::new();

        if let Some(severities) = filter.severity {
            let placeholders = severities.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND severity IN ({})", placeholders));
            for s in severities {
                params.push(s.to_string());
            }
        }

        if let Some(confidences) = filter.confidence {
            let placeholders = confidences.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND confidence IN ({})", placeholders));
            for c in confidences {
                params.push(c.to_string());
            }
        }

        if let Some(categories) = filter.category {
            let placeholders = categories.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND category IN ({})", placeholders));
            for c in categories {
                params.push(c.to_string());
            }
        }

        if let Some(target) = filter.target {
            query.push_str(" AND target LIKE ?");
            params.push(format!("%{}%", target));
        }

        if let Some(plugin) = filter.plugin_source {
            query.push_str(" AND plugin_source = ?");
            params.push(plugin);
        }

        if let Some(scan_id) = filter.scan_id {
            query.push_str(" AND scan_id = ?");
            params.push(scan_id.to_string());
        }

        if let Some(verified) = filter.verified {
            query.push_str(" AND verified = ?");
            params.push(verified.to_string());
        }

        if let Some(false_positive) = filter.false_positive {
            query.push_str(" AND false_positive = ?");
            params.push(false_positive.to_string());
        }

        if let Some(date_from) = filter.date_from {
            query.push_str(" AND timestamp >= ?");
            params.push(date_from.to_rfc3339());
        }

        if let Some(date_to) = filter.date_to {
            query.push_str(" AND timestamp <= ?");
            params.push(date_to.to_rfc3339());
        }

        if let Some(search) = filter.search {
            query.push_str(" AND (title LIKE ? OR description LIKE ?)");
            params.push(format!("%{}%", search));
            params.push(format!("%{}%", search));
        }

        if let Some(min_score) = filter.min_risk_score {
            query.push_str(" AND risk_score >= ?");
            params.push(min_score.to_string());
        }

        if let Some(max_score) = filter.max_risk_score {
            query.push_str(" AND risk_score <= ?");
            params.push(max_score.to_string());
        }

        let mut query_builder = sqlx::query(&query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        let row = query_builder.fetch_one(&self.pool).await?;
        let count: i64 = row.get("count");
        Ok(count as u64)
    }

    async fn get_finding(&self, finding_id: &FindingId) -> ScannerResult<Option<Finding>> {
        let row = sqlx::query("SELECT * FROM findings WHERE id = ?")
            .bind(finding_id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            Ok(Some(Finding {
                id: FindingId::from_string(&row.get::<String, _>("id"))?,
                title: row.get("title"),
                description: row.get("description"),
                severity: row.get::<String, _>("severity").parse()?,
                confidence: row.get::<String, _>("confidence").parse()?,
                category: row.get::<String, _>("category").parse()?,
                target: row.get("target"),
                target_type: row.get("target_type"),
                evidence: serde_json::from_str(&row.get::<String, _>("evidence"))?,
                references: serde_json::from_str(&row.get::<String, _>("references"))?,
                plugin_source: row.get("plugin_source"),
                plugin_version: row.get("plugin_version"),
                timestamp: DateTime::parse_from_rfc3339(&row.get::<String, _>("timestamp"))?.with_timezone(&Utc),
                metadata: serde_json::from_str(&row.get::<String, _>("metadata"))?,
                tags: serde_json::from_str(&row.get::<String, _>("tags"))?,
                verified: row.get("verified"),
                false_positive: row.get("false_positive"),
                risk_score: row.get::<Option<i64>, _>("risk_score").map(|s| s as u8),
                cvss_vector: row.get("cvss_vector"),
                cvss_score: row.get("cvss_score"),
                scan_id: ScanId::from_string(&row.get::<String, _>("scan_id"))?,
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_finding_stats(&self, filter: FindingFilter) -> ScannerResult<FindingStats> {
        let mut query = "SELECT * FROM findings WHERE 1=1".to_string();
        let mut params: Vec<String> = Vec::new();

        if let Some(severities) = filter.severity {
            let placeholders = severities.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND severity IN ({})", placeholders));
            for s in severities {
                params.push(s.to_string());
            }
        }

        if let Some(confidences) = filter.confidence {
            let placeholders = confidences.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND confidence IN ({})", placeholders));
            for c in confidences {
                params.push(c.to_string());
            }
        }

        if let Some(categories) = filter.category {
            let placeholders = categories.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            query.push_str(&format!(" AND category IN ({})", placeholders));
            for c in categories {
                params.push(c.to_string());
            }
        }

        if let Some(target) = filter.target {
            query.push_str(" AND target LIKE ?");
            params.push(format!("%{}%", target));
        }

        if let Some(plugin) = filter.plugin_source {
            query.push_str(" AND plugin_source = ?");
            params.push(plugin);
        }

        if let Some(scan_id) = filter.scan_id {
            query.push_str(" AND scan_id = ?");
            params.push(scan_id.to_string());
        }

        if let Some(verified) = filter.verified {
            query.push_str(" AND verified = ?");
            params.push(verified.to_string());
        }

        if let Some(false_positive) = filter.false_positive {
            query.push_str(" AND false_positive = ?");
            params.push(false_positive.to_string());
        }

        if let Some(date_from) = filter.date_from {
            query.push_str(" AND timestamp >= ?");
            params.push(date_from.to_rfc3339());
        }

        if let Some(date_to) = filter.date_to {
            query.push_str(" AND timestamp <= ?");
            params.push(date_to.to_rfc3339());
        }

        if let Some(search) = filter.search {
            query.push_str(" AND (title LIKE ? OR description LIKE ?)");
            params.push(format!("%{}%", search));
            params.push(format!("%{}%", search));
        }

        if let Some(min_score) = filter.min_risk_score {
            query.push_str(" AND risk_score >= ?");
            params.push(min_score.to_string());
        }

        if let Some(max_score) = filter.max_risk_score {
            query.push_str(" AND risk_score <= ?");
            params.push(max_score.to_string());
        }

        let mut query_builder = sqlx::query(&query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        let rows = query_builder.fetch_all(&self.pool).await?;

        let mut by_severity = HashMap::new();
        let mut by_confidence = HashMap::new();
        let mut by_category = HashMap::new();
        let mut by_plugin = HashMap::new();
        let mut verified = 0;
        let mut false_positives = 0;
        let mut total_risk_score = 0u32;
        let mut risk_score_count = 0;

        for row in rows {
            let severity: String = row.get("severity");
            let confidence: String = row.get("confidence");
            let category: String = row.get("category");
            let plugin: String = row.get("plugin_source");
            let verified_flag: bool = row.get("verified");
            let fp_flag: bool = row.get("false_positive");
            let risk_score: Option<i64> = row.get("risk_score");

            *by_severity.entry(severity.parse()?).or_insert(0) += 1;
            *by_confidence.entry(confidence.parse()?).or_insert(0) += 1;
            *by_category.entry(category.parse()?).or_insert(0) += 1;
            *by_plugin.entry(plugin).or_insert(0) += 1;

            if verified_flag { verified += 1; }
            if fp_flag { false_positives += 1; }
            if let Some(score) = risk_score {
                total_risk_score += score as u32;
                risk_score_count += 1;
            }
        }

        Ok(FindingStats {
            total: by_severity.values().sum(),
            by_severity,
            by_confidence,
            by_category,
            by_plugin,
            verified,
            false_positives,
            avg_risk_score: if risk_score_count > 0 { total_risk_score as f32 / risk_score_count as f32 } else { 0.0 },
        })
    }

    async fn save_log(&self, scan_id: ScanId, log: &ScanLogEntry) -> ScannerResult<()> {
        let metadata_json = serde_json::to_string(&log.metadata)?;

        sqlx::query(
            r#"
            INSERT INTO scan_logs (scan_id, timestamp, level, plugin, message, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(scan_id.to_string())
        .bind(log.timestamp.to_rfc3339())
        .bind(&log.level)
        .bind(&log.plugin)
        .bind(&log.message)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_logs(&self, scan_id: &ScanId) -> ScannerResult<Vec<ScanLogEntry>> {
        let rows = sqlx::query("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY timestamp ASC")
            .bind(scan_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(ScanLogEntry {
                timestamp: DateTime::parse_from_rfc3339(&row.get::<String, _>("timestamp"))?.with_timezone(&Utc),
                level: row.get("level"),
                plugin: row.get("plugin"),
                message: row.get("message"),
                metadata: serde_json::from_str(&row.get::<String, _>("metadata"))?,
            });
        }

        Ok(logs)
    }

    async fn save_target(&self, target: &Target) -> ScannerResult<()> {
        let headers_json = serde_json::to_string(&target.metadata.headers)?;
        let cookies_json = serde_json::to_string(&target.metadata.cookies)?;
        let auth_json = target.metadata.auth.as_ref().map(serde_json::to_string).transpose()?;
        let rate_limit_json = target.metadata.rate_limit.as_ref().map(serde_json::to_string).transpose()?;
        let tls_json = target.metadata.tls_config.as_ref().map(serde_json::to_string).transpose()?;
        let proxy_json = target.metadata.proxy.as_ref().map(serde_json::to_string).transpose()?;
        let custom_json = serde_json::to_string(&target.metadata.custom)?;
        let tags_json = serde_json::to_string(&target.metadata.tags)?;

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO targets (id, project_id, target_type, name, description, base_url, headers, cookies, auth, rate_limit, tls_config, proxy, custom, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(target.id.to_string())
        .bind(None::<String>) // project_id
        .bind(target.target_type.to_string())
        .bind(&target.metadata.name)
        .bind(&target.metadata.description)
        .bind(target.metadata.base_url.to_string())
        .bind(&headers_json)
        .bind(&cookies_json)
        .bind(&auth_json)
        .bind(&rate_limit_json)
        .bind(&tls_json)
        .bind(&proxy_json)
        .bind(&custom_json)
        .bind(&tags_json)
        .bind(target.created_at.to_rfc3339())
        .bind(target.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_target(&self, target_id: &TargetId) -> ScannerResult<Option<Target>> {
        let row = sqlx::query("SELECT * FROM targets WHERE id = ?")
            .bind(target_id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            let target = Target {
                id: TargetId::from_string(&row.get::<String, _>("id"))?,
                target_type: row.get::<String, _>("target_type").parse()?,
                metadata: TargetMetadata {
                    name: row.get("name"),
                    description: row.get("description"),
                    base_url: row.get::<String, _>("base_url").parse()?,
                    headers: serde_json::from_str(&row.get::<String, _>("headers"))?,
                    cookies: serde_json::from_str(&row.get::<String, _>("cookies"))?,
                    auth: row.get::<Option<String>, _>("auth").map(|s| serde_json::from_str(&s)).transpose()?,
                    rate_limit: row.get::<Option<String>, _>("rate_limit").map(|s| serde_json::from_str(&s)).transpose()?,
                    tls_config: row.get::<Option<String>, _>("tls_config").map(|s| serde_json::from_str(&s)).transpose()?,
                    proxy: row.get::<Option<String>, _>("proxy").map(|s| serde_json::from_str(&s)).transpose()?,
                    custom: serde_json::from_str(&row.get::<String, _>("custom"))?,
                    tags: serde_json::from_str(&row.get::<String, _>("tags"))?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))?.with_timezone(&Utc),
                },
                scan_configs: Vec::new(),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))?.with_timezone(&Utc),
            };
            Ok(Some(target))
        } else {
            Ok(None)
        }
    }

    async fn list_targets(&self, project_id: Option<ProjectId>) -> ScannerResult<Vec<Target>> {
        let query = if project_id.is_some() {
            "SELECT * FROM targets WHERE project_id = ? ORDER BY created_at DESC"
        } else {
            "SELECT * FROM targets ORDER BY created_at DESC"
        };

        let mut query_builder = sqlx::query(query);
        if let Some(pid) = project_id {
            query_builder = query_builder.bind(pid.to_string());
        }

        let rows = query_builder.fetch_all(&self.pool).await?;

        let mut targets = Vec::new();
        for row in rows {
            targets.push(Target {
                id: TargetId::from_string(&row.get::<String, _>("id"))?,
                target_type: row.get::<String, _>("target_type").parse()?,
                metadata: TargetMetadata {
                    name: row.get("name"),
                    description: row.get("description"),
                    base_url: row.get::<String, _>("base_url").parse()?,
                    headers: serde_json::from_str(&row.get::<String, _>("headers"))?,
                    cookies: serde_json::from_str(&row.get::<String, _>("cookies"))?,
                    auth: row.get::<Option<String>, _>("auth").map(|s| serde_json::from_str(&s)).transpose()?,
                    rate_limit: row.get::<Option<String>, _>("rate_limit").map(|s| serde_json::from_str(&s)).transpose()?,
                    tls_config: row.get::<Option<String>, _>("tls_config").map(|s| serde_json::from_str(&s)).transpose()?,
                    proxy: row.get::<Option<String>, _>("proxy").map(|s| serde_json::from_str(&s)).transpose()?,
                    custom: serde_json::from_str(&row.get::<String, _>("custom"))?,
                    tags: serde_json::from_str(&row.get::<String, _>("tags"))?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))?.with_timezone(&Utc),
                },
                scan_configs: Vec::new(),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))?.with_timezone(&Utc),
            });
        }

        Ok(targets)
    }

    async fn delete_target(&self, target_id: &TargetId) -> ScannerResult<bool> {
        let result = sqlx::query("DELETE FROM targets WHERE id = ?")
            .bind(target_id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn save_plugin_execution(&self, record: &PluginExecutionRecord) -> ScannerResult<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO plugin_executions (id, scan_id, plugin_id, plugin_name, started_at, completed_at, status, findings_count, error, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(record.id.to_string())
        .bind(record.scan_id.to_string())
        .bind(record.plugin_id.to_string())
        .bind(&record.plugin_name)
        .bind(record.started_at.to_rfc3339())
        .bind(record.completed_at.map(|dt| dt.to_rfc3339()))
        .bind(&record.status)
        .bind(record.findings_count as i64)
        .bind(&record.error)
        .bind(record.duration.map(|d| d.as_millis() as i64))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_plugin_executions(&self, scan_id: &ScanId) -> ScannerResult<Vec<PluginExecutionRecord>> {
        let rows = sqlx::query("SELECT * FROM plugin_executions WHERE scan_id = ? ORDER BY started_at ASC")
            .bind(scan_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let mut executions = Vec::new();
        for row in rows {
            executions.push(PluginExecutionRecord {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                scan_id: ScanId::from_string(&row.get::<String, _>("scan_id"))?,
                plugin_id: PluginId::from_string(&row.get::<String, _>("plugin_id"))?,
                plugin_name: row.get("plugin_name"),
                started_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("started_at"))?.with_timezone(&Utc),
                completed_at: row.get::<Option<String>, _>("completed_at").map(|s| DateTime::parse_from_rfc3339(&s).unwrap().with_timezone(&Utc)),
                status: row.get("status"),
                findings_count: row.get::<i64, _>("findings_count") as usize,
                error: row.get("error"),
                duration: row.get::<Option<i64>, _>("duration_ms").map(|ms| std::time::Duration::from_millis(ms as u64)),
            });
        }

        Ok(executions)
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

    async fn list_scans(&self, limit: usize, offset: usize, _project_id: Option<ProjectId>) -> ScannerResult<Vec<ScanSession>> {
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

    async fn list_findings(&self, filter: FindingFilter, sort: FindingSort, limit: usize, offset: usize) -> ScannerResult<Vec<Finding>> {
        self.get_findings_filtered(filter, sort, limit, offset).await
    }

    async fn count_findings(&self, filter: FindingFilter) -> ScannerResult<u64> {
        let findings = self.get_findings_filtered(filter, FindingSort::SeverityDesc, usize::MAX, 0).await?;
        Ok(findings.len() as u64)
    }

    async fn get_finding(&self, finding_id: &FindingId) -> ScannerResult<Option<Finding>> {
        Ok(self.findings.get(finding_id).map(|f| f.clone()))
    }

    async fn get_findings_filtered(&self, filter: FindingFilter, sort: FindingSort, limit: usize, offset: usize) -> ScannerResult<Vec<Finding>> {
        let mut findings: Vec<Finding> = self.findings.iter().map(|f| f.clone()).collect();

        // Apply filter
        findings.retain(|f| {
            if let Some(severities) = &filter.severity {
                if !severities.contains(&f.severity) { return false; }
            }
            if let Some(confidences) = &filter.confidence {
                if !confidences.contains(&f.confidence) { return false; }
            }
            if let Some(categories) = &filter.category {
                if !categories.contains(&f.category) { return false; }
            }
            if let Some(target) = &filter.target {
                if !f.target.contains(target) { return false; }
            }
            if let Some(plugin) = &filter.plugin_source {
                if f.plugin_source != *plugin { return false; }
            }
            if let Some(scan_id) = &filter.scan_id {
                if f.scan_id != *scan_id { return false; }
            }
            if let Some(verified) = filter.verified {
                if f.verified != verified { return false; }
            }
            if let Some(false_positive) = filter.false_positive {
                if f.false_positive != false_positive { return false; }
            }
            if let Some(tags) = &filter.tags {
                if !tags.iter().all(|t| f.tags.contains(t)) { return false; }
            }
            if let Some(date_from) = filter.date_from {
                if f.timestamp < date_from { return false; }
            }
            if let Some(date_to) = filter.date_to {
                if f.timestamp > date_to { return false; }
            }
            if let Some(search) = &filter.search {
                let search_lower = search.to_lowercase();
                if !f.title.to_lowercase().contains(&search_lower) && !f.description.to_lowercase().contains(&search_lower) {
                    return false;
                }
            }
            if let Some(min_score) = filter.min_risk_score {
                if f.risk_score.unwrap_or(0) < min_score { return false; }
            }
            if let Some(max_score) = filter.max_risk_score {
                if f.risk_score.unwrap_or(100) > max_score { return false; }
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
            FindingSort::RiskScoreDesc => findings.sort_by(|a, b| b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0))),
            FindingSort::TargetAsc => findings.sort_by(|a, b| a.target.cmp(&b.target)),
        }

        Ok(findings.into_iter().skip(offset).take(limit).collect())
    }

    async fn get_finding_stats(&self, filter: FindingFilter) -> ScannerResult<FindingStats> {
        let findings = self.get_findings_filtered(filter, FindingSort::SeverityDesc, usize::MAX, 0).await?;

        let mut by_severity = HashMap::new();
        let mut by_confidence = HashMap::new();
        let mut by_category = HashMap::new();
        let mut by_plugin = HashMap::new();
        let mut verified = 0;
        let mut false_positives = 0;
        let mut total_risk_score = 0u32;
        let mut risk_score_count = 0;

        for finding in &findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
            *by_confidence.entry(finding.confidence).or_insert(0) += 1;
            *by_category.entry(finding.category.clone()).or_insert(0) += 1;
            *by_plugin.entry(finding.plugin_source.clone()).or_insert(0) += 1;
            if finding.verified { verified += 1; }
            if finding.false_positive { false_positives += 1; }
            if let Some(score) = finding.risk_score {
                total_risk_score += score as u32;
                risk_score_count += 1;
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
            avg_risk_score: if risk_score_count > 0 { total_risk_score as f32 / risk_score_count as f32 } else { 0.0 },
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

    async fn get_plugin_executions(&self, scan_id: &ScanId) -> ScannerResult<Vec<PluginExecutionRecord>> {
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
            crate::target::TargetMetadata::new("Test".to_string(), "https://example.com".parse().unwrap()),
        );

        storage.save_target(&target).await.unwrap();
        let retrieved = storage.get_target(&target_id).await.unwrap();
        assert!(retrieved.is_none()); // Different ID

        let retrieved = storage.get_target(&target.id).await.unwrap();
        assert!(retrieved.is_some());
    }
}