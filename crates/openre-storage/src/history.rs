//! History storage (SQLite) for scan history, artifacts, and evidence persistence
//!
//! Implements the `HistoryStorage` trait from `openre-core::history` using SQLite/rusqlite.

use openre_core::error::OpenreResult;
use openre_core::ids::{FindingId, ProjectId, ScanId};
// Types defined in history.rs module itself
#[allow(unused_imports)]
use openre_core::history::{
    HistoryError, HistoryStorage, ReportArtifact, RiskMetrics, RiskMetricsSummary,
    ScanConfigSummary, ScanProgressSummary, ScanSummary, StoredEvidence,
};
use openre_core::reporting::ScanComparison;
#[allow(unused_imports)]
use openre_core::{Finding, FindingStats, RiskTrends, TrendDirection};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// SQLite-backed implementation of the HistoryStorage trait.
/// Stores scan summaries, report artifacts, evidence objects, deduplicated findings,
/// comparisons, and risk metrics in a local SQLite database file.
pub struct SqliteHistoryStorage {
    #[allow(dead_code)]
    db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl SqliteHistoryStorage {
    /// Create a new storage instance at the given path.
    pub fn new(db_path: &PathBuf) -> OpenreResult<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(db_path)?;

        // Performance pragmas (same pattern as ProjectStore)
        // Use prepare+step for PRAGMAs that may return rows in rusqlite 0.31+
        let _ = conn.prepare("PRAGMA journal_mode=WAL")?.query([])?;
        let _ = conn.prepare("PRAGMA synchronous=NORMAL")?.query([])?;
        let _ = conn.prepare("PRAGMA foreign_keys=ON")?.query([])?;
        let _ = conn.prepare("PRAGMA cache_size=-100000")?.query([])?; // 100MB
        let _ = conn.prepare("PRAGMA mmap_size=268435456")?.query([])?; // 256MB
        let _ = conn.prepare("PRAGMA temp_store=MEMORY")?.query([])?;
        let _ = conn.prepare("PRAGMA busy_timeout=30000")?.query([])?;

        let storage = Self { db_path: db_path.clone(), conn: Arc::new(Mutex::new(conn)) };

        Ok(storage)
    }

    /// Ensure all tables exist. Called automatically on first use but can be called explicitly.
    pub async fn ensure_schema(&self) -> OpenreResult<()> {
        let conn = self.conn.lock().await;
        Self::create_schema(&conn)?;
        Ok(())
    }

    /// Get a connection guard for database operations
    async fn conn(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        self.conn.lock().await
    }
}

// --- Helper methods (outside trait impl, called from trait methods) ---

impl SqliteHistoryStorage {
    /// Create database schema for history storage
    fn create_schema(conn: &Connection) -> OpenreResult<()> {
        // Scan summaries table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS scan_summaries (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                target_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                config_json TEXT NOT NULL,
                progress_json TEXT NOT NULL,
                finding_stats_json TEXT NOT NULL,
                risk_metrics_json TEXT NOT NULL,
                plugin_executions_json TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                duration_seconds INTEGER,
                tags_json TEXT NOT NULL
            )"#,
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_summaries_project ON scan_summaries(project_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_summaries_target ON scan_summaries(target_id)",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_summaries_created ON scan_summaries(created_at DESC)", [])?;

        // Report artifacts table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS report_artifacts (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                project_id TEXT,
                format TEXT NOT NULL,
                title TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                generated_at TIMESTAMP NOT NULL,
                generated_by TEXT NOT NULL,
                config_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            )"#,
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_report_artifacts_scan ON report_artifacts(scan_id)",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_report_artifacts_project ON report_artifacts(project_id)", [])?;

        // Evidence table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                description TEXT NOT NULL,
                data BLOB,
                location TEXT,
                metadata_json TEXT NOT NULL,
                http_request_json TEXT,
                http_response_json TEXT,
                timing_json TEXT,
                payload_json TEXT,
                reproduction_steps_json TEXT,
                captured_at TIMESTAMP NOT NULL,
                plugin_source TEXT NOT NULL
            )"#,
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id)",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id)", [])?;

        // Deduplicated findings table (stored as JSON per scan)
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS deduplicated_findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL UNIQUE,
                data_json TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"#,
            [],
        )?;

        // Scan comparisons table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS scan_comparisons (
                id TEXT PRIMARY KEY,
                baseline_scan_id TEXT NOT NULL,
                current_scan_id TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_comparisons_baseline ON scan_comparisons(baseline_scan_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_comparisons_current ON scan_comparisons(current_scan_id)", [])?;

        // Risk metrics table
        conn.execute(
            r#"CREATE TABLE IF NOT EXISTS risk_metrics (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                scan_id TEXT,
                timestamp TIMESTAMP NOT NULL,
                overall_risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                by_severity_json TEXT NOT NULL,
                by_category_json TEXT NOT NULL,
                avg_risk_score REAL NOT NULL,
                max_risk_score INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                info_count INTEGER NOT NULL,
                verified_count INTEGER NOT NULL,
                false_positive_count INTEGER NOT NULL,
                exploit_available_count INTEGER NOT NULL,
                exploited_in_wild_count INTEGER NOT NULL,
                top_cwes_json TEXT NOT NULL,
                top_owasp_json TEXT NOT NULL,
                remediation_priority_json TEXT NOT NULL,
                trends_json TEXT NOT NULL
            )"#,
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_risk_metrics_project ON risk_metrics(project_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_risk_metrics_timestamp ON risk_metrics(timestamp DESC)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_risk_metrics_scan ON risk_metrics(scan_id)",
            [],
        )?;

        Ok(())
    }

    fn deserialize_scan_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanSummary> {
        let config_json: String = row.get::<_, String>("config_json")?;
        let progress_json: String = row.get::<_, String>("progress_json")?;
        let finding_stats_json: String = row.get::<_, String>("finding_stats_json")?;
        let risk_metrics_json: String = row.get::<_, String>("risk_metrics_json")?;
        let plugin_executions_json: String = row.get::<_, String>("plugin_executions_json")?;
        let tags_json: String = row.get::<_, String>("tags_json")?;
        let id_str: String = row.get("id")?;
        let project_id_str: Option<String> = row.get("project_id")?;
        let target_str: String = row.get("target_id")?;

        Ok(ScanSummary {
            scan_id: ScanId::from_uuid(uuid::Uuid::parse_str(&id_str).unwrap_or_default()),
            project_id: project_id_str
                .map(|s| ProjectId::from_uuid(uuid::Uuid::parse_str(&s).unwrap_or_default())),
            target_id: openre_core::ids::TargetId::from_uuid(
                uuid::Uuid::parse_str(&target_str).unwrap_or_default(),
            ),
            name: row.get("name")?,
            description: row.get("description")?,
            status: row.get("status")?,
            config: serde_json::from_str(&config_json).unwrap(),
            progress: serde_json::from_str(&progress_json).unwrap(),
            finding_stats: serde_json::from_str(&finding_stats_json).unwrap(),
            risk_metrics: serde_json::from_str(&risk_metrics_json).unwrap(),
            plugin_executions: serde_json::from_str(&plugin_executions_json).unwrap(),
            created_at: row.get("created_at")?,
            started_at: row.get("started_at")?,
            completed_at: row.get("completed_at")?,
            duration_seconds: row.get::<_, Option<i64>>("duration_seconds")?.map(|v| v as u64),
            tags: serde_json::from_str(&tags_json).unwrap(),
        })
    }

    fn list_all_summaries(
        conn: &Connection,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<Vec<ScanSummary>, HistoryError> {
        let sql = r#"SELECT id, project_id, target_id, name, description, status, config_json, progress_json, finding_stats_json, risk_metrics_json, plugin_executions_json, created_at, started_at, completed_at, duration_seconds, tags_json FROM scan_summaries ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"#;
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(params![limit as i64, offset as i64], Self::deserialize_scan_summary)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }

    fn list_summaries_with_project(
        conn: &Connection,
        project_id_str: &str,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<Vec<ScanSummary>, HistoryError> {
        let sql = r#"SELECT id, project_id, target_id, name, description, status, config_json, progress_json, finding_stats_json, risk_metrics_json, plugin_executions_json, created_at, started_at, completed_at, duration_seconds, tags_json FROM scan_summaries WHERE project_id = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3"#;
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(
                params![project_id_str, limit as i64, offset as i64],
                Self::deserialize_scan_summary,
            )
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }

    fn deserialize_report_artifact(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReportArtifact> {
        let format_str: String = row.get("format")?;
        let config_json: String = row.get("config_json")?;
        let metadata_json: String = row.get("metadata_json")?;
        let scan_id_str: String = row.get("scan_id")?;

        Ok(ReportArtifact {
            id: row.get("id")?,
            scan_id: ScanId::from_uuid(uuid::Uuid::parse_str(&scan_id_str).unwrap_or_default()),
            project_id: row
                .get::<_, Option<String>>("project_id")?
                .map(|s| ProjectId::from_uuid(uuid::Uuid::parse_str(&s).unwrap_or_default())),
            format: serde_json::from_str(&format_str).unwrap(),
            title: row.get("title")?,
            storage_path: row.get("storage_path")?,
            size_bytes: row.get::<_, i64>("size_bytes")? as u64,
            checksum: row.get("checksum")?,
            generated_at: row.get("generated_at")?,
            generated_by: row.get("generated_by")?,
            config: serde_json::from_str(&config_json).unwrap(),
            metadata: serde_json::from_str(&metadata_json).unwrap(),
        })
    }

    fn list_all_artifacts(
        conn: &Connection,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<Vec<ReportArtifact>, HistoryError> {
        let sql = "SELECT id, scan_id, project_id, format, title, storage_path, size_bytes, checksum, generated_at, generated_by, config_json, metadata_json FROM report_artifacts ORDER BY generated_at DESC LIMIT ?1 OFFSET ?2";
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(params![limit as i64, offset as i64], Self::deserialize_report_artifact)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }

    fn list_artifacts_with_scan(
        conn: &Connection,
        scan_id_str: &str,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<Vec<ReportArtifact>, HistoryError> {
        let sql = "SELECT id, scan_id, project_id, format, title, storage_path, size_bytes, checksum, generated_at, generated_by, config_json, metadata_json FROM report_artifacts WHERE scan_id = ?1 ORDER BY generated_at DESC LIMIT ?2 OFFSET ?3";
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(
                params![scan_id_str, limit as i64, offset as i64],
                Self::deserialize_report_artifact,
            )
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }

    fn deserialize_evidence_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvidence> {
        let evidence_type_str: String = row.get("evidence_type")?;

        Ok(StoredEvidence {
            id: row.get("id")?,
            finding_id: FindingId::from_uuid(
                uuid::Uuid::parse_str(&row.get::<_, String>("finding_id")?).unwrap_or_default(),
            ),
            scan_id: ScanId::from_uuid(
                uuid::Uuid::parse_str(&row.get::<_, String>("scan_id")?).unwrap_or_default(),
            ),
            evidence_type: serde_json::from_str(&evidence_type_str).unwrap(),
            description: row.get("description")?,
            data: row.get::<_, Option<Vec<u8>>>("data").ok().flatten(),
            location: row.get("location").ok().flatten(),
            metadata: serde_json::from_str(
                row.get::<_, Option<String>>("metadata_json")
                    .ok()
                    .flatten()
                    .as_deref()
                    .unwrap_or("{}"),
            )
            .unwrap_or_default(),
            http_request: row
                .get::<_, Option<String>>("http_request_json")?
                .and_then(|s| serde_json::from_str(&s).ok()),
            http_response: row
                .get::<_, Option<String>>("http_response_json")?
                .and_then(|s| serde_json::from_str(&s).ok()),
            timing: row
                .get::<_, Option<String>>("timing_json")?
                .and_then(|s| serde_json::from_str(&s).ok()),
            payload: row
                .get::<_, Option<String>>("payload_json")?
                .and_then(|s| serde_json::from_str(&s).ok()),
            reproduction_steps: row
                .get::<_, Option<String>>("reproduction_steps_json")?
                .and_then(|s| serde_json::from_str(&s).ok()),
            captured_at: row.get("captured_at")?,
            plugin_source: row.get("plugin_source")?,
        })
    }

    fn deserialize_risk_metrics_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RiskMetrics> {
        let risk_level_str: String = row.get("risk_level")?;
        let trends_json_val: Option<String> = row.get("trends_json").ok();

        Ok(RiskMetrics {
            id: row.get("id")?,
            project_id: ProjectId::from_uuid(
                uuid::Uuid::parse_str(&row.get::<_, String>("project_id")?).unwrap_or_default(),
            ),
            scan_id: row
                .get::<_, Option<String>>("scan_id")?
                .map(|s| ScanId::from_uuid(uuid::Uuid::parse_str(&s).unwrap_or_default())),
            timestamp: row.get("timestamp")?,
            overall_risk_score: row.get::<_, i64>("overall_risk_score")? as u8,
            risk_level: serde_json::from_str(&risk_level_str).unwrap(),
            by_severity: serde_json::from_str(row.get::<_, String>("by_severity_json")?.as_str())
                .unwrap_or_default(),
            by_category: serde_json::from_str(row.get::<_, String>("by_category_json")?.as_str())
                .unwrap_or_default(),
            avg_risk_score: row.get("avg_risk_score")?,
            max_risk_score: row.get::<_, i64>("max_risk_score")? as u8,
            critical_count: row.get::<_, i64>("critical_count")? as usize,
            high_count: row.get::<_, i64>("high_count")? as usize,
            medium_count: row.get::<_, i64>("medium_count")? as usize,
            low_count: row.get::<_, i64>("low_count")? as usize,
            info_count: row.get::<_, i64>("info_count")? as usize,
            verified_count: row.get::<_, i64>("verified_count")? as usize,
            false_positive_count: row.get::<_, i64>("false_positive_count")? as usize,
            exploit_available_count: row.get::<_, i64>("exploit_available_count")? as usize,
            exploited_in_wild_count: row.get::<_, i64>("exploited_in_wild_count")? as usize,
            top_cwes: serde_json::from_str(row.get::<_, String>("top_cwes_json")?.as_str())
                .unwrap_or_default(),
            top_owasp: serde_json::from_str(row.get::<_, String>("top_owasp_json")?.as_str())
                .unwrap_or_default(),
            remediation_priority: serde_json::from_str(
                row.get::<_, String>("remediation_priority_json")?.as_str(),
            )
            .unwrap_or_default(),
            trends: serde_json::from_str(trends_json_val.as_deref().unwrap_or("{}")).unwrap_or(
                RiskTrends {
                    risk_score_change: 0,
                    critical_change: 0,
                    high_change: 0,
                    new_findings: 0,
                    fixed_findings: 0,
                    regressed_findings: 0,
                    trend_direction: TrendDirection::Unknown,
                },
            ),
        })
    }

    fn query_all_risk_metrics(
        conn: &Connection,
        project_id_str: &str,
    ) -> std::result::Result<Vec<RiskMetrics>, HistoryError> {
        let sql = r#"SELECT id, project_id, scan_id, timestamp, overall_risk_score, risk_level, by_severity_json, by_category_json, avg_risk_score, max_risk_score, critical_count, high_count, medium_count, low_count, info_count, verified_count, false_positive_count, exploit_available_count, exploited_in_wild_count, top_cwes_json, top_owasp_json, remediation_priority_json, trends_json FROM risk_metrics WHERE project_id = ?1 ORDER BY timestamp DESC"#;
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(params![project_id_str], Self::deserialize_risk_metrics_row)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }

    fn query_risk_metrics_range(
        conn: &Connection,
        project_id_str: &str,
        date_from: chrono::DateTime<chrono::Utc>,
        date_to: chrono::DateTime<chrono::Utc>,
    ) -> std::result::Result<Vec<RiskMetrics>, HistoryError> {
        let sql = r#"SELECT id, project_id, scan_id, timestamp, overall_risk_score, risk_level, by_severity_json, by_category_json, avg_risk_score, max_risk_score, critical_count, high_count, medium_count, low_count, info_count, verified_count, false_positive_count, exploit_available_count, exploited_in_wild_count, top_cwes_json, top_owasp_json, remediation_priority_json, trends_json FROM risk_metrics WHERE project_id = ?1 AND timestamp >= ?2 AND timestamp <= ?3 ORDER BY timestamp DESC"#;
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(
                params![project_id_str, date_from, date_to],
                Self::deserialize_risk_metrics_row,
            )
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }

    fn query_risk_metrics_since(
        conn: &Connection,
        project_id_str: &str,
        date_from: chrono::DateTime<chrono::Utc>,
    ) -> std::result::Result<Vec<RiskMetrics>, HistoryError> {
        let sql = r#"SELECT id, project_id, scan_id, timestamp, overall_risk_score, risk_level, by_severity_json, by_category_json, avg_risk_score, max_risk_score, critical_count, high_count, medium_count, low_count, info_count, verified_count, false_positive_count, exploit_available_count, exploited_in_wild_count, top_cwes_json, top_owasp_json, remediation_priority_json, trends_json FROM risk_metrics WHERE project_id = ?1 AND timestamp >= ?2 ORDER BY timestamp DESC"#;
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(params![project_id_str, date_from], Self::deserialize_risk_metrics_row)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }

    fn query_risk_metrics_until(
        conn: &Connection,
        project_id_str: &str,
        date_to: chrono::DateTime<chrono::Utc>,
    ) -> std::result::Result<Vec<RiskMetrics>, HistoryError> {
        let sql = r#"SELECT id, project_id, scan_id, timestamp, overall_risk_score, risk_level, by_severity_json, by_category_json, avg_risk_score, max_risk_score, critical_count, high_count, medium_count, low_count, info_count, verified_count, false_positive_count, exploit_available_count, exploited_in_wild_count, top_cwes_json, top_owasp_json, remediation_priority_json, trends_json FROM risk_metrics WHERE project_id = ?1 AND timestamp <= ?2 ORDER BY timestamp DESC"#;
        Ok(conn
            .prepare(sql)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .query_map(params![project_id_str, date_to], Self::deserialize_risk_metrics_row)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>())
    }
}

// --- Trait implementation ---

#[async_trait::async_trait]
impl HistoryStorage for SqliteHistoryStorage {
    async fn save_scan_summary(&self, summary: &ScanSummary) -> Result<(), HistoryError> {
        let conn = self.conn().await;
        let id_str = summary.scan_id.to_string();
        let project_id = summary.project_id.map(|p| p.to_string());
        let config_json =
            serde_json::to_string(&summary.config).map_err(HistoryError::Serialization)?;
        let progress_json =
            serde_json::to_string(&summary.progress).map_err(HistoryError::Serialization)?;
        let finding_stats_json =
            serde_json::to_string(&summary.finding_stats).map_err(HistoryError::Serialization)?;
        let risk_metrics_json =
            serde_json::to_string(&summary.risk_metrics).map_err(HistoryError::Serialization)?;
        let plugin_executions_json = serde_json::to_string(&summary.plugin_executions)
            .map_err(HistoryError::Serialization)?;
        let tags_json =
            serde_json::to_string(&summary.tags).map_err(HistoryError::Serialization)?;

        conn.execute(
            r#"INSERT OR REPLACE INTO scan_summaries (
                id, project_id, target_id, name, description, status, config_json, progress_json,
                finding_stats_json, risk_metrics_json, plugin_executions_json, created_at, started_at,
                completed_at, duration_seconds, tags_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"#,
            params![
                id_str, project_id, summary.target_id.to_string(), &summary.name, &summary.description,
                &summary.status, config_json, progress_json, finding_stats_json, risk_metrics_json,
                plugin_executions_json, summary.created_at, summary.started_at, summary.completed_at,
                summary.duration_seconds, tags_json
            ],
        ).map_err(|e| HistoryError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_scan_summary(
        &self,
        scan_id: &ScanId,
    ) -> Result<Option<ScanSummary>, HistoryError> {
        let conn = self.conn().await;
        let id_str = scan_id.to_string();

        conn.query_row(
            r#"SELECT id, project_id, target_id, name, description, status, config_json, progress_json, finding_stats_json, risk_metrics_json, plugin_executions_json, created_at, started_at, completed_at, duration_seconds, tags_json FROM scan_summaries WHERE id = ?1"#,
            params![id_str],
            Self::deserialize_scan_summary,
        ).optional().map_err(|e| HistoryError::Storage(e.to_string()))
    }

    async fn list_scan_summaries(
        &self,
        project_id: Option<ProjectId>,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<Vec<ScanSummary>, HistoryError> {
        let conn = self.conn().await;

        if let Some(pid) = project_id {
            Self::list_summaries_with_project(&conn, &pid.to_string(), limit, offset)
        } else {
            Self::list_all_summaries(&conn, limit, offset)
        }
    }

    async fn delete_scan_summary(&self, scan_id: &ScanId) -> Result<bool, HistoryError> {
        let conn = self.conn().await;
        let id_str = scan_id.to_string();
        let deleted = conn
            .execute("DELETE FROM scan_summaries WHERE id = ?1", params![id_str])
            .map_err(|e| HistoryError::Storage(e.to_string()))?;
        Ok(deleted > 0)
    }

    async fn save_report_artifact(&self, artifact: &ReportArtifact) -> Result<(), HistoryError> {
        let conn = self.conn().await;
        let config_json =
            serde_json::to_string(&artifact.config).map_err(HistoryError::Serialization)?;
        let metadata_json =
            serde_json::to_string(&artifact.metadata).map_err(HistoryError::Serialization)?;

        conn.execute(
            r#"INSERT OR REPLACE INTO report_artifacts (
                id, scan_id, project_id, format, title, storage_path, size_bytes, checksum,
                generated_at, generated_by, config_json, metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
            params![
                &artifact.id,
                artifact.scan_id.to_string(),
                artifact.project_id.map(|p| p.to_string()),
                serde_json::to_string(&artifact.format).unwrap_or_default(),
                &artifact.title,
                &artifact.storage_path,
                artifact.size_bytes as i64,
                &artifact.checksum,
                artifact.generated_at,
                &artifact.generated_by,
                config_json,
                metadata_json
            ],
        )
        .map_err(|e| HistoryError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_report_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ReportArtifact>, HistoryError> {
        let conn = self.conn().await;
        conn.query_row(
            "SELECT id, scan_id, project_id, format, title, storage_path, size_bytes, checksum, generated_at, generated_by, config_json, metadata_json FROM report_artifacts WHERE id = ?1",
            params![artifact_id],
            Self::deserialize_report_artifact,
        ).optional().map_err(|e| HistoryError::Storage(e.to_string()))
    }

    async fn list_report_artifacts(
        &self,
        scan_id: Option<ScanId>,
        limit: usize,
        offset: usize,
    ) -> std::result::Result<Vec<ReportArtifact>, HistoryError> {
        let conn = self.conn().await;

        if let Some(sid) = scan_id {
            Self::list_artifacts_with_scan(&conn, &sid.to_string(), limit, offset)
        } else {
            Self::list_all_artifacts(&conn, limit, offset)
        }
    }

    async fn delete_report_artifact(&self, artifact_id: &str) -> Result<bool, HistoryError> {
        let conn = self.conn().await;
        let deleted = conn
            .execute("DELETE FROM report_artifacts WHERE id = ?1", params![artifact_id])
            .map_err(|e| HistoryError::Storage(e.to_string()))?;
        Ok(deleted > 0)
    }

    async fn save_evidence(&self, evidence: &StoredEvidence) -> Result<(), HistoryError> {
        let conn = self.conn().await;

        let evidence_type_str = serde_json::to_string(&evidence.evidence_type).unwrap_or_default();
        let metadata_json =
            serde_json::to_string(&evidence.metadata).map_err(HistoryError::Serialization)?;
        let http_request_json = evidence
            .http_request
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(HistoryError::Serialization)?;
        let http_response_json = evidence
            .http_response
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(HistoryError::Serialization)?;
        let timing_json = evidence
            .timing
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(HistoryError::Serialization)?;
        let payload_json = evidence
            .payload
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(HistoryError::Serialization)?;
        let reproduction_steps_json = evidence
            .reproduction_steps
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(HistoryError::Serialization)?;

        conn.execute(
            r#"INSERT OR REPLACE INTO evidence (
                id, finding_id, scan_id, evidence_type, description, data, location, metadata_json,
                http_request_json, http_response_json, timing_json, payload_json, reproduction_steps_json,
                captured_at, plugin_source
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
            params![
                &evidence.id, evidence.finding_id.to_string(), evidence.scan_id.to_string(),
                evidence_type_str, &evidence.description, evidence.data.as_deref(),
                &evidence.location, metadata_json, http_request_json, http_response_json,
                timing_json, payload_json, reproduction_steps_json, evidence.captured_at,
                &evidence.plugin_source
            ],
        ).map_err(|e| HistoryError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Option<StoredEvidence>, HistoryError> {
        let conn = self.conn().await;
        conn.query_row(
            r#"SELECT id, finding_id, scan_id, evidence_type, description, data, location, metadata_json, http_request_json, http_response_json, timing_json, payload_json, reproduction_steps_json, captured_at, plugin_source FROM evidence WHERE id = ?1"#,
            params![evidence_id],
            Self::deserialize_evidence_row,
        ).optional().map_err(|e| HistoryError::Storage(e.to_string()))
    }

    async fn list_evidence_for_finding(
        &self,
        finding_id: &FindingId,
    ) -> Result<Vec<StoredEvidence>, HistoryError> {
        let conn = self.conn().await;
        let fid_str = finding_id.to_string();
        let mut stmt = conn.prepare(
            r#"SELECT id, finding_id, scan_id, evidence_type, description, data, location, metadata_json, http_request_json, http_response_json, timing_json, payload_json, reproduction_steps_json, captured_at, plugin_source FROM evidence WHERE finding_id = ?1 ORDER BY captured_at DESC"#
        ).map_err(|e| HistoryError::Storage(e.to_string()))?;

        let rows: Vec<StoredEvidence> = stmt
            .query_map(params![fid_str], Self::deserialize_evidence_row)
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rows)
    }

    async fn save_deduplicated_findings(
        &self,
        scan_id: &ScanId,
        findings: &[Finding],
    ) -> Result<(), HistoryError> {
        let conn = self.conn().await;
        let id_str = Uuid::new_v4().to_string();
        let sid_str = scan_id.to_string();
        let data_json = serde_json::to_string(findings).map_err(HistoryError::Serialization)?;

        conn.execute("DELETE FROM deduplicated_findings WHERE scan_id = ?1", params![sid_str])
            .map_err(|e| HistoryError::Storage(e.to_string()))?;

        conn.execute(
            "INSERT INTO deduplicated_findings (id, scan_id, data_json) VALUES (?1, ?2, ?3)",
            params![id_str, sid_str, data_json],
        )
        .map_err(|e| HistoryError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_deduplicated_findings(
        &self,
        scan_id: &ScanId,
    ) -> Result<Vec<Finding>, HistoryError> {
        let conn = self.conn().await;
        let sid_str = scan_id.to_string();
        let data_json: String = conn.query_row(
            "SELECT data_json FROM deduplicated_findings WHERE scan_id = ?1 ORDER BY created_at DESC LIMIT 1",
            params![sid_str],
            |row| row.get(0),
        ).optional().map_err(|e| HistoryError::Storage(e.to_string()))?
        .ok_or_else(|| HistoryError::NotFound(format!("No deduplicated findings for scan: {}", scan_id)))?;

        serde_json::from_str(&data_json).map_err(HistoryError::Serialization)
    }

    async fn save_comparison(&self, comparison: &ScanComparison) -> Result<(), HistoryError> {
        let conn = self.conn().await;
        let id_str = Uuid::new_v4().to_string();
        let data_json = serde_json::to_string(comparison).map_err(HistoryError::Serialization)?;

        conn.execute(
            r#"INSERT OR REPLACE INTO scan_comparisons (id, baseline_scan_id, current_scan_id, data_json) VALUES (?1, ?2, ?3, ?4)"#,
            params![id_str, comparison.baseline_scan_id.to_string(), comparison.current_scan_id.to_string(), data_json],
        ).map_err(|e| HistoryError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_comparison(
        &self,
        comparison_id: &str,
    ) -> Result<Option<ScanComparison>, HistoryError> {
        let conn = self.conn().await;
        conn.query_row(
            "SELECT data_json FROM scan_comparisons WHERE id = ?1",
            params![comparison_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| HistoryError::Storage(e.to_string()))?
        .map(|data_json| serde_json::from_str(&data_json).map_err(HistoryError::Serialization))
        .transpose()
    }

    async fn list_comparisons(
        &self,
        _project_id: Option<ProjectId>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ScanComparison>, HistoryError> {
        let conn = self.conn().await;
        let mut stmt = conn.prepare(
            "SELECT data_json FROM scan_comparisons ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        ).map_err(|e| HistoryError::Storage(e.to_string()))?;

        let rows: Vec<String> = stmt
            .query_map(params![limit as i64, offset as i64], |row| row.get::<_, String>(0))
            .map_err(|e| HistoryError::Storage(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rows.iter().filter_map(|json| serde_json::from_str(json).ok()).collect())
    }

    async fn save_risk_metrics(&self, metrics: &RiskMetrics) -> Result<(), HistoryError> {
        let conn = self.conn().await;

        let by_severity_json =
            serde_json::to_string(&metrics.by_severity).map_err(HistoryError::Serialization)?;
        let by_category_json =
            serde_json::to_string(&metrics.by_category).map_err(HistoryError::Serialization)?;
        let top_cwes_json =
            serde_json::to_string(&metrics.top_cwes).map_err(HistoryError::Serialization)?;
        let top_owasp_json =
            serde_json::to_string(&metrics.top_owasp).map_err(HistoryError::Serialization)?;
        let remediation_priority_json = serde_json::to_string(&metrics.remediation_priority)
            .map_err(HistoryError::Serialization)?;
        let trends_json =
            serde_json::to_string(&metrics.trends).map_err(HistoryError::Serialization)?;

        conn.execute(
            r#"INSERT OR REPLACE INTO risk_metrics (
                id, project_id, scan_id, timestamp, overall_risk_score, risk_level, by_severity_json,
                by_category_json, avg_risk_score, max_risk_score, critical_count, high_count, medium_count,
                low_count, info_count, verified_count, false_positive_count, exploit_available_count,
                exploited_in_wild_count, top_cwes_json, top_owasp_json, remediation_priority_json, trends_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)"#,
            params![
                &metrics.id, metrics.project_id.to_string(),
                metrics.scan_id.map(|s| s.to_string()), metrics.timestamp, metrics.overall_risk_score as i64,
                serde_json::to_string(&metrics.risk_level).unwrap_or_default(), by_severity_json, by_category_json,
                metrics.avg_risk_score, metrics.max_risk_score as i64, metrics.critical_count as i64,
                metrics.high_count as i64, metrics.medium_count as i64, metrics.low_count as i64,
                metrics.info_count as i64, metrics.verified_count as i64, metrics.false_positive_count as i64,
                metrics.exploit_available_count as i64, metrics.exploited_in_wild_count as i64, top_cwes_json,
                top_owasp_json, remediation_priority_json, trends_json
            ],
        ).map_err(|e| HistoryError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn get_risk_metrics(
        &self,
        project_id: &ProjectId,
        date_from: Option<chrono::DateTime<chrono::Utc>>,
        date_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> std::result::Result<Vec<RiskMetrics>, HistoryError> {
        let conn = self.conn().await;
        let pid_str = project_id.to_string();

        match (date_from, date_to) {
            (Some(from), Some(to)) => Self::query_risk_metrics_range(&conn, &pid_str, from, to),
            (Some(from), None) => Self::query_risk_metrics_since(&conn, &pid_str, from),
            (None, Some(to)) => Self::query_risk_metrics_until(&conn, &pid_str, to),
            (None, None) => Self::query_all_risk_metrics(&conn, &pid_str),
        }
    }

    async fn get_latest_risk_metrics(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<RiskMetrics>, HistoryError> {
        let conn = self.conn().await;
        let pid_str = project_id.to_string();

        conn.query_row(
            r#"SELECT id, project_id, scan_id, timestamp, overall_risk_score, risk_level, by_severity_json, by_category_json, avg_risk_score, max_risk_score, critical_count, high_count, medium_count, low_count, info_count, verified_count, false_positive_count, exploit_available_count, exploited_in_wild_count, top_cwes_json, top_owasp_json, remediation_priority_json, trends_json FROM risk_metrics WHERE project_id = ?1 ORDER BY timestamp DESC LIMIT 1"#,
            params![pid_str],
            Self::deserialize_risk_metrics_row,
        ).optional().map_err(|e| HistoryError::Storage(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{ProjectId, TargetId};
    use tempfile::tempdir;

    async fn create_test_storage() -> (SqliteHistoryStorage, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_history.db");
        let storage = SqliteHistoryStorage::new(&db_path).unwrap();
        storage.ensure_schema().await.unwrap();
        (storage, dir)
    }

    fn create_test_scan_summary() -> ScanSummary {
        use std::collections::HashMap;
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
                risk_level: openre_core::reporting::RiskLevel::High,
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

    #[tokio::test]
    async fn test_save_and_get_scan_summary() {
        let (storage, _dir) = create_test_storage().await;
        let summary = create_test_scan_summary();
        let scan_id = summary.scan_id;

        storage.save_scan_summary(&summary).await.unwrap();
        let retrieved = storage.get_scan_summary(&scan_id).await.unwrap().unwrap();

        assert_eq!(retrieved.name, "Test Scan");
        assert_eq!(retrieved.status, "completed");
    }

    #[tokio::test]
    async fn test_delete_scan_summary() {
        let (storage, _dir) = create_test_storage().await;
        let summary = create_test_scan_summary();
        let scan_id = summary.scan_id;

        storage.save_scan_summary(&summary).await.unwrap();
        assert!(storage.delete_scan_summary(&scan_id).await.unwrap());
        assert!(storage.get_scan_summary(&scan_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_scan_summaries() {
        let (storage, _dir) = create_test_storage().await;
        for i in 0..3 {
            let mut summary = create_test_scan_summary();
            summary.name = format!("Test Scan {}", i);
            storage.save_scan_summary(&summary).await.unwrap();
        }

        let summaries = storage.list_scan_summaries(None, 10, 0).await.unwrap();
        assert_eq!(summaries.len(), 3);
    }
}
