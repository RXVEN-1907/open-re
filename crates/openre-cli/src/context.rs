//! CLI context

use crate::{CliConfig, CliError, OutputFormat};
use openre_core::ids::{ProjectId, ScanId, UserId};
use openre_storage::project::ProjectStore;
use reqwest::Client;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// CLI execution context
pub struct Context {
    pub config: CliConfig,
    pub client: Client,
    pub server_url: String,
    pub api_key: Option<String>,
    pub output_format: OutputFormat,
    pub verbose: bool,
    pub offline: bool,
    pub local_db_path: Option<std::path::PathBuf>,
    pub local_store: Option<Arc<OfflineStore>>,
}

/// Project metadata for offline storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineProject {
    pub id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    pub is_public: bool,
    pub settings: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Scan metadata for offline storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineScan {
    pub id: ScanId,
    pub project_id: ProjectId,
    pub name: String,
    pub target: String,
    pub profile: String,
    pub status: String,
    pub progress: f32,
    pub findings_count: u64,
    pub checks_total: u32,
    pub checks_completed: u32,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Analysis job metadata for offline storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineAnalysisJob {
    pub id: openre_core::ids::JobId,
    pub project_id: ProjectId,
    pub file_id: openre_core::ids::FileId,
    pub name: String,
    pub status: String,
    pub progress: f32,
    pub current_stage: Option<String>,
    pub stages_completed: u32,
    pub total_stages: u32,
    pub ai_enabled: bool,
    pub stages: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Offline store for local operations
pub struct OfflineStore {
    project_store: ProjectStore,
    meta_conn: Arc<tokio::sync::Mutex<Option<Connection>>>,
}

impl OfflineStore {
    pub fn new(db_path: Option<PathBuf>) -> Result<Self, crate::error::CliError> {
        let base_path = db_path.unwrap_or_else(|| {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("openre")
        });

        std::fs::create_dir_all(&base_path)?;
        let meta_db_path = base_path.join("offline_meta.db");

        // Initialize metadata connection
        let conn = Connection::open(&meta_db_path)?;
        // Use prepare+query for PRAGMAs that may return rows in rusqlite 0.31+
        let _ = conn.prepare("PRAGMA journal_mode=WAL")?.query([])?;
        let _ = conn.prepare("PRAGMA foreign_keys=ON")?.query([])?;
        let _ = conn.prepare("PRAGMA busy_timeout=30000")?.query([])?;

        // Create projects table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                owner_id TEXT NOT NULL,
                is_public INTEGER NOT NULL DEFAULT 0,
                settings TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id)",
            [],
        )?;

        // Create scans table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                progress REAL NOT NULL DEFAULT 0.0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                checks_total INTEGER NOT NULL DEFAULT 0,
                checks_completed INTEGER NOT NULL DEFAULT 0,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id)",
            [],
        )?;

        // Create analysis_jobs table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                progress REAL NOT NULL DEFAULT 0.0,
                current_stage TEXT,
                stages_completed INTEGER NOT NULL DEFAULT 0,
                total_stages INTEGER NOT NULL DEFAULT 0,
                ai_enabled INTEGER NOT NULL DEFAULT 0,
                stages TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT
            )
            "#,
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_project ON analysis_jobs(project_id)",
            [],
        )?;

        let project_id = ProjectId::new();
        let project_store = ProjectStore::new(project_id, &base_path)?;

        Ok(Self {
            project_store,
            meta_conn: Arc::new(tokio::sync::Mutex::new(Some(conn))),
        })
    }

    /// Get the project analysis store
    pub fn project_store(&self) -> &ProjectStore {
        &self.project_store
    }

    /// Take the metadata connection
    async fn take_meta_conn(&self) -> Result<Connection, CliError> {
        let mut guard = self.meta_conn.lock().await;
        guard.take().ok_or_else(|| {
            CliError::Internal("Metadata connection already in use".to_string())
        })
    }

    /// Put the metadata connection back
    async fn put_meta_conn(&self, conn: Connection) {
        let mut guard = self.meta_conn.lock().await;
        *guard = Some(conn);
    }

    /// Create a new project
    pub async fn create_project(&self, project: OfflineProject) -> Result<(), CliError> {
        let mut conn = self.take_meta_conn().await?;
        conn.execute(
            r#"
            INSERT INTO projects (id, name, description, owner_id, is_public, settings, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                project.id.to_string(),
                project.name,
                project.description,
                project.owner_id,
                project.is_public as i32,
                project.settings.map(|s| s.to_string()),
                project.created_at.to_rfc3339(),
                project.updated_at.to_rfc3339(),
            ],
        )?;
        self.put_meta_conn(conn).await;
        Ok(())
    }

    /// List projects with pagination
    pub async fn list_projects(
        &self,
        page: u32,
        per_page: u32,
        search: Option<String>,
    ) -> Result<Vec<OfflineProject>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let offset = (page - 1) * per_page;

        let projects = if let Some(search) = search {
            let pattern = format!("%{}%", search);
            let mut stmt = conn.prepare(
                r#"
                SELECT id, name, description, owner_id, is_public, settings, created_at, updated_at
                FROM projects
                WHERE name LIKE ?1
                ORDER BY created_at DESC
                LIMIT ?2 OFFSET ?3
                "#,
            )?;
            let rows = stmt.query_map(params![&pattern, &per_page, &offset], |row| {
                Ok(OfflineProject {
                    id: row.get::<_, String>(0)?.parse::<ProjectId>().unwrap(),
                    name: row.get(1)?,
                    description: row.get(2)?,
                    owner_id: row.get(3)?,
                    is_public: row.get::<_, i32>(4)? != 0,
                    settings: row.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?).unwrap().with_timezone(&chrono::Utc),
                })
            })?;
            let mut projects = Vec::new();
            for row in rows {
                projects.push(row?);
            }
            projects
        } else {
            let mut stmt = conn.prepare(
                r#"
                SELECT id, name, description, owner_id, is_public, settings, created_at, updated_at
                FROM projects
                ORDER BY created_at DESC
                LIMIT ?1 OFFSET ?2
                "#,
            )?;
            let rows = stmt.query_map(params![&per_page, &offset], |row| {
                Ok(OfflineProject {
                    id: row.get::<_, String>(0)?.parse::<ProjectId>().unwrap(),
                    name: row.get(1)?,
                    description: row.get(2)?,
                    owner_id: row.get(3)?,
                    is_public: row.get::<_, i32>(4)? != 0,
                    settings: row.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?).unwrap().with_timezone(&chrono::Utc),
                })
            })?;
            let mut projects = Vec::new();
            for row in rows {
                projects.push(row?);
            }
            projects
        };

        self.put_meta_conn(conn).await;
        Ok(projects)
    }

    /// Get project by ID
    pub async fn get_project(&self, id: &ProjectId) -> Result<Option<OfflineProject>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let id_str = id.to_string();
        let result = {
            let mut stmt = conn.prepare(
                r#"
                SELECT id, name, description, owner_id, is_public, settings, created_at, updated_at
                FROM projects
                WHERE id = ?1
                "#,
            )?;
            stmt.query_row(params![id_str], |row| {
                Ok(OfflineProject {
                    id: row.get::<_, String>(0)?.parse::<ProjectId>().unwrap(),
                    name: row.get(1)?,
                    description: row.get(2)?,
                    owner_id: row.get(3)?,
                    is_public: row.get::<_, i32>(4)? != 0,
                    settings: row.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?).unwrap().with_timezone(&chrono::Utc),
                })
            })
        };

        self.put_meta_conn(conn).await;
        match result {
            Ok(project) => Ok(Some(project)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update project
    pub async fn update_project(
        &self,
        id: &ProjectId,
        name: Option<String>,
        description: Option<String>,
        is_public: Option<bool>,
    ) -> Result<Option<OfflineProject>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let id_str = id.to_string();

        // Check if project exists
        let exists: bool = conn.query_row(
            "SELECT 1 FROM projects WHERE id = ?1",
            params![&id_str],
            |_| Ok(true),
        ).unwrap_or(false);

        if !exists {
            self.put_meta_conn(conn).await;
            return Ok(None);
        }

        // Build dynamic update
        let mut updates = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(name) = name {
            updates.push("name = ?");
            params_vec.push(Box::new(name));
        }
        if let Some(description) = description {
            updates.push("description = ?");
            params_vec.push(Box::new(description));
        }
        if let Some(is_public) = is_public {
            updates.push("is_public = ?");
            params_vec.push(Box::new(is_public as i32));
        }

        if updates.is_empty() {
            self.put_meta_conn(conn).await;
            return self.get_project(id).await;
        }

        updates.push("updated_at = ?");
        params_vec.push(Box::new(chrono::Utc::now().to_rfc3339()));

        let sql = format!(
            "UPDATE projects SET {} WHERE id = ?",
            updates.join(", ")
        );

        let mut param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
        param_refs.push(&id_str);

        conn.execute(&sql, param_refs.as_slice())?;
        self.put_meta_conn(conn).await;

        self.get_project(id).await
    }

    /// Delete project
    pub async fn delete_project(&self, id: &ProjectId) -> Result<bool, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let deleted = conn.execute("DELETE FROM projects WHERE id = ?1", params![id.to_string()])?;
        self.put_meta_conn(conn).await;
        Ok(deleted > 0)
    }

    /// Count projects
    pub async fn count_projects(&self, search: Option<String>) -> Result<u64, CliError> {
        let mut conn = self.take_meta_conn().await?;

        let count: u64 = if let Some(search) = search {
            let pattern = format!("%{}%", search);
            conn.query_row(
                "SELECT COUNT(*) FROM projects WHERE name LIKE ?1",
                params![pattern],
                |row| row.get(0),
            )?
        } else {
            conn.query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?
        };

        self.put_meta_conn(conn).await;
        Ok(count)
    }

    // ==================== Scan Operations ====================

    /// Create a new scan
    pub async fn create_scan(&self, scan: OfflineScan) -> Result<(), CliError> {
        let mut conn = self.take_meta_conn().await?;
        conn.execute(
            r#"
            INSERT INTO scans (id, project_id, name, target, profile, status, progress, findings_count, checks_total, checks_completed, started_at, completed_at, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                scan.id.to_string(),
                scan.project_id.to_string(),
                scan.name,
                scan.target,
                scan.profile,
                scan.status,
                scan.progress,
                scan.findings_count,
                scan.checks_total,
                scan.checks_completed,
                scan.started_at.map(|dt| dt.to_rfc3339()),
                scan.completed_at.map(|dt| dt.to_rfc3339()),
                scan.created_at.to_rfc3339(),
                scan.updated_at.to_rfc3339(),
            ],
        )?;
        self.put_meta_conn(conn).await;
        Ok(())
    }

    /// List scans with pagination
    pub async fn list_scans(
        &self,
        project_id: &ProjectId,
        page: u32,
        per_page: u32,
        status_filter: Option<String>,
    ) -> Result<Vec<OfflineScan>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let offset = (page - 1) * per_page;
        let project_id_str = project_id.to_string();

        let scans = if let Some(status) = status_filter {
            let mut stmt = conn.prepare(
                r#"
                SELECT id, project_id, name, target, profile, status, progress, findings_count, checks_total, checks_completed, started_at, completed_at, created_at, updated_at
                FROM scans
                WHERE project_id = ?1 AND status = ?2
                ORDER BY created_at DESC
                LIMIT ?3 OFFSET ?4
                "#,
            )?;
            let rows = stmt.query_map(params![&project_id_str, &status, &per_page, &offset], |row| {
                Ok(OfflineScan {
                    id: row.get::<_, String>(0)?.parse::<ScanId>().unwrap(),
                    project_id: row.get::<_, String>(1)?.parse::<ProjectId>().unwrap(),
                    name: row.get(2)?,
                    target: row.get(3)?,
                    profile: row.get(4)?,
                    status: row.get(5)?,
                    progress: row.get(6)?,
                    findings_count: row.get(7)?,
                    checks_total: row.get(8)?,
                    checks_completed: row.get(9)?,
                    started_at: row.get::<_, Option<String>>(10)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    completed_at: row.get::<_, Option<String>>(11)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(13)?).unwrap().with_timezone(&chrono::Utc),
                })
            })?;
            let mut scans = Vec::new();
            for row in rows {
                scans.push(row?);
            }
            scans
        } else {
            let mut stmt = conn.prepare(
                r#"
                SELECT id, project_id, name, target, profile, status, progress, findings_count, checks_total, checks_completed, started_at, completed_at, created_at, updated_at
                FROM scans
                WHERE project_id = ?1
                ORDER BY created_at DESC
                LIMIT ?2 OFFSET ?3
                "#,
            )?;
            let rows = stmt.query_map(params![&project_id_str, &per_page, &offset], |row| {
                Ok(OfflineScan {
                    id: row.get::<_, String>(0)?.parse::<ScanId>().unwrap(),
                    project_id: row.get::<_, String>(1)?.parse::<ProjectId>().unwrap(),
                    name: row.get(2)?,
                    target: row.get(3)?,
                    profile: row.get(4)?,
                    status: row.get(5)?,
                    progress: row.get(6)?,
                    findings_count: row.get(7)?,
                    checks_total: row.get(8)?,
                    checks_completed: row.get(9)?,
                    started_at: row.get::<_, Option<String>>(10)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    completed_at: row.get::<_, Option<String>>(11)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(13)?).unwrap().with_timezone(&chrono::Utc),
                })
            })?;
            let mut scans = Vec::new();
            for row in rows {
                scans.push(row?);
            }
            scans
        };

        self.put_meta_conn(conn).await;
        Ok(scans)
    }

    /// Get scan by ID
    pub async fn get_scan(&self, id: &ScanId) -> Result<Option<OfflineScan>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let id_str = id.to_string();
        let result = {
            let mut stmt = conn.prepare(
                r#"
                SELECT id, project_id, name, target, profile, status, progress, findings_count, checks_total, checks_completed, started_at, completed_at, created_at, updated_at
                FROM scans
                WHERE id = ?1
                "#,
            )?;
            stmt.query_row(params![id_str], |row| {
                Ok(OfflineScan {
                    id: row.get::<_, String>(0)?.parse::<ScanId>().unwrap(),
                    project_id: row.get::<_, String>(1)?.parse::<ProjectId>().unwrap(),
                    name: row.get(2)?,
                    target: row.get(3)?,
                    profile: row.get(4)?,
                    status: row.get(5)?,
                    progress: row.get(6)?,
                    findings_count: row.get(7)?,
                    checks_total: row.get(8)?,
                    checks_completed: row.get(9)?,
                    started_at: row.get::<_, Option<String>>(10)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    completed_at: row.get::<_, Option<String>>(11)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(13)?).unwrap().with_timezone(&chrono::Utc),
                })
            })
        };

        self.put_meta_conn(conn).await;
        match result {
            Ok(scan) => Ok(Some(scan)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update scan
    pub async fn update_scan(
        &self,
        id: &ScanId,
        status: Option<String>,
        progress: Option<f32>,
        findings_count: Option<u64>,
        checks_completed: Option<u32>,
        started_at: Option<chrono::DateTime<chrono::Utc>>,
        completed_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Option<OfflineScan>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let id_str = id.to_string();

        // Check if scan exists
        let exists: bool = conn.query_row(
            "SELECT 1 FROM scans WHERE id = ?1",
            params![&id_str],
            |_| Ok(true),
        ).unwrap_or(false);

        if !exists {
            self.put_meta_conn(conn).await;
            return Ok(None);
        }

        // Build dynamic update
        let mut updates = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(status) = status {
            updates.push("status = ?");
            params_vec.push(Box::new(status));
        }
        if let Some(progress) = progress {
            updates.push("progress = ?");
            params_vec.push(Box::new(progress));
        }
        if let Some(findings_count) = findings_count {
            updates.push("findings_count = ?");
            params_vec.push(Box::new(findings_count as i64));
        }
        if let Some(checks_completed) = checks_completed {
            updates.push("checks_completed = ?");
            params_vec.push(Box::new(checks_completed as i32));
        }
        if let Some(started_at) = started_at {
            updates.push("started_at = ?");
            params_vec.push(Box::new(started_at.to_rfc3339()));
        }
        if let Some(completed_at) = completed_at {
            updates.push("completed_at = ?");
            params_vec.push(Box::new(completed_at.to_rfc3339()));
        }

        if updates.is_empty() {
            self.put_meta_conn(conn).await;
            return self.get_scan(id).await;
        }

        updates.push("updated_at = ?");
        params_vec.push(Box::new(chrono::Utc::now().to_rfc3339()));

        let sql = format!(
            "UPDATE scans SET {} WHERE id = ?",
            updates.join(", ")
        );

        let mut param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
        param_refs.push(&id_str);

        conn.execute(&sql, param_refs.as_slice())?;
        self.put_meta_conn(conn).await;

        self.get_scan(id).await
    }

    /// Delete scan
    pub async fn delete_scan(&self, id: &ScanId) -> Result<bool, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let deleted = conn.execute("DELETE FROM scans WHERE id = ?1", params![id.to_string()])?;
        self.put_meta_conn(conn).await;
        Ok(deleted > 0)
    }

    /// Count scans for a project
    pub async fn count_scans(&self, project_id: &ProjectId, status_filter: Option<String>) -> Result<u64, CliError> {
        let mut conn = self.take_meta_conn().await?;

        let count: u64 = if let Some(status) = status_filter {
            conn.query_row(
                "SELECT COUNT(*) FROM scans WHERE project_id = ?1 AND status = ?2",
                params![project_id.to_string(), status],
                |row| row.get(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM scans WHERE project_id = ?1",
                params![project_id.to_string()],
                |row| row.get(0),
            )?
        };

        self.put_meta_conn(conn).await;
        Ok(count)
    }

    /// Resolve project ID by name or UUID
    pub async fn resolve_project_id(&self, project: &str) -> Result<ProjectId, CliError> {
        // Try to parse as UUID first
        if let Ok(pid) = project.parse::<ProjectId>() {
            return Ok(pid);
        }

        // Otherwise, search by name
        let mut conn = self.take_meta_conn().await?;
        let result = {
            let mut stmt = conn.prepare(
                "SELECT id FROM projects WHERE name = ?1 LIMIT 1"
            )?;
            stmt.query_row(params![project], |row| {
                Ok(row.get::<_, String>(0)?.parse::<ProjectId>().unwrap())
            })
        };

        self.put_meta_conn(conn).await;
        match result {
            Ok(pid) => Ok(pid),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(CliError::InvalidInput(format!("Project not found: {}", project))),
            Err(e) => Err(e.into()),
        }
    }

    // ==================== Analysis Job Operations ====================

    /// Create a new analysis job
    pub async fn create_analysis_job(&self, job: OfflineAnalysisJob) -> Result<(), CliError> {
        let mut conn = self.take_meta_conn().await?;
        conn.execute(
            r#"
            INSERT INTO analysis_jobs (id, project_id, file_id, name, status, progress, current_stage, stages_completed, total_stages, ai_enabled, stages, created_at, updated_at, started_at, completed_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
            params![
                job.id.to_string(),
                job.project_id.to_string(),
                job.file_id.to_string(),
                job.name,
                job.status,
                job.progress,
                job.current_stage,
                job.stages_completed,
                job.total_stages,
                job.ai_enabled as i32,
                serde_json::to_string(&job.stages)?,
                job.created_at.to_rfc3339(),
                job.updated_at.to_rfc3339(),
                job.started_at.map(|dt| dt.to_rfc3339()),
                job.completed_at.map(|dt| dt.to_rfc3339()),
            ],
        )?;
        self.put_meta_conn(conn).await;
        Ok(())
    }

    /// Get analysis job by ID
    pub async fn get_analysis_job(&self, id: &openre_core::ids::JobId) -> Result<Option<OfflineAnalysisJob>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let id_str = id.to_string();
        let result = {
            let mut stmt = conn.prepare(
                r#"
                SELECT id, project_id, file_id, name, status, progress, current_stage, stages_completed, total_stages, ai_enabled, stages, created_at, updated_at, started_at, completed_at
                FROM analysis_jobs
                WHERE id = ?1
                "#,
            )?;
            stmt.query_row(params![id_str], |row| {
                Ok(OfflineAnalysisJob {
                    id: row.get::<_, String>(0)?.parse::<openre_core::ids::JobId>().unwrap(),
                    project_id: row.get::<_, String>(1)?.parse::<ProjectId>().unwrap(),
                    file_id: row.get::<_, String>(2)?.parse::<openre_core::ids::FileId>().unwrap(),
                    name: row.get(3)?,
                    status: row.get(4)?,
                    progress: row.get(5)?,
                    current_stage: row.get(6)?,
                    stages_completed: row.get(7)?,
                    total_stages: row.get(8)?,
                    ai_enabled: row.get::<_, i32>(9)? != 0,
                    stages: serde_json::from_str(&row.get::<_, String>(10)?).unwrap_or_default(),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(11)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?).unwrap().with_timezone(&chrono::Utc),
                    started_at: row.get::<_, Option<String>>(13)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    completed_at: row.get::<_, Option<String>>(14)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                })
            })
        };

        self.put_meta_conn(conn).await;
        match result {
            Ok(job) => Ok(Some(job)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update analysis job
    pub async fn update_analysis_job(
        &self,
        id: &openre_core::ids::JobId,
        status: Option<String>,
        progress: Option<f32>,
        current_stage: Option<String>,
        stages_completed: Option<u32>,
        started_at: Option<chrono::DateTime<chrono::Utc>>,
        completed_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Option<OfflineAnalysisJob>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let id_str = id.to_string();

        // Check if job exists
        let exists: bool = conn.query_row(
            "SELECT 1 FROM analysis_jobs WHERE id = ?1",
            params![&id_str],
            |_| Ok(true),
        ).unwrap_or(false);

        if !exists {
            self.put_meta_conn(conn).await;
            return Ok(None);
        }

        // Build dynamic update
        let mut updates = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(status) = status {
            updates.push("status = ?");
            params_vec.push(Box::new(status));
        }
        if let Some(progress) = progress {
            updates.push("progress = ?");
            params_vec.push(Box::new(progress));
        }
        if let Some(current_stage) = current_stage {
            updates.push("current_stage = ?");
            params_vec.push(Box::new(current_stage));
        }
        if let Some(stages_completed) = stages_completed {
            updates.push("stages_completed = ?");
            params_vec.push(Box::new(stages_completed as i32));
        }
        if let Some(started_at) = started_at {
            updates.push("started_at = ?");
            params_vec.push(Box::new(started_at.to_rfc3339()));
        }
        if let Some(completed_at) = completed_at {
            updates.push("completed_at = ?");
            params_vec.push(Box::new(completed_at.to_rfc3339()));
        }

        if updates.is_empty() {
            self.put_meta_conn(conn).await;
            return self.get_analysis_job(id).await;
        }

        updates.push("updated_at = ?");
        params_vec.push(Box::new(chrono::Utc::now().to_rfc3339()));

        let sql = format!(
            "UPDATE analysis_jobs SET {} WHERE id = ?",
            updates.join(", ")
        );

        let mut param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();
        param_refs.push(&id_str);

        conn.execute(&sql, param_refs.as_slice())?;
        self.put_meta_conn(conn).await;

        self.get_analysis_job(id).await
    }

    /// List analysis jobs for a project
    pub async fn list_analysis_jobs(
        &self,
        project_id: &ProjectId,
        page: u32,
        per_page: u32,
    ) -> Result<Vec<OfflineAnalysisJob>, CliError> {
        let mut conn = self.take_meta_conn().await?;
        let offset = (page - 1) * per_page;
        let project_id_str = project_id.to_string();

        let jobs = {
            let mut stmt = conn.prepare(
                r#"
                SELECT id, project_id, file_id, name, status, progress, current_stage, stages_completed, total_stages, ai_enabled, stages, created_at, updated_at, started_at, completed_at
                FROM analysis_jobs
                WHERE project_id = ?1
                ORDER BY created_at DESC
                LIMIT ?2 OFFSET ?3
                "#,
            )?;
            let rows = stmt.query_map(params![&project_id_str, &per_page, &offset], |row| {
                Ok(OfflineAnalysisJob {
                    id: row.get::<_, String>(0)?.parse::<openre_core::ids::JobId>().unwrap(),
                    project_id: row.get::<_, String>(1)?.parse::<ProjectId>().unwrap(),
                    file_id: row.get::<_, String>(2)?.parse::<openre_core::ids::FileId>().unwrap(),
                    name: row.get(3)?,
                    status: row.get(4)?,
                    progress: row.get(5)?,
                    current_stage: row.get(6)?,
                    stages_completed: row.get(7)?,
                    total_stages: row.get(8)?,
                    ai_enabled: row.get::<_, i32>(9)? != 0,
                    stages: serde_json::from_str(&row.get::<_, String>(10)?).unwrap_or_default(),
                    created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(11)?).unwrap().with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?).unwrap().with_timezone(&chrono::Utc),
                    started_at: row.get::<_, Option<String>>(13)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                    completed_at: row.get::<_, Option<String>>(14)?.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
                })
            })?;
            let mut jobs = Vec::new();
            for row in rows {
                jobs.push(row?);
            }
            jobs
        };

        self.put_meta_conn(conn).await;
        Ok(jobs)
    }
}

impl Context {
    /// Create a new context
    pub fn new(
        config: CliConfig,
        client: Client,
        server_url: String,
        api_key: Option<String>,
        output_format: OutputFormat,
        verbose: bool,
        offline: bool,
        local_db_path: Option<PathBuf>,
    ) -> Result<Self, crate::error::CliError> {
        let local_db_path_clone = local_db_path.clone();
        let local_store = if offline {
            let db_path = local_db_path_clone.clone().unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("openre")
            });
            Some(Arc::new(OfflineStore::new(local_db_path_clone)?))
        } else {
            None
        };

        Ok(Self {
            config,
            client,
            server_url,
            api_key,
            output_format,
            verbose,
            offline,
            local_db_path,
            local_store,
        })
    }

    /// Get authentication token
    pub fn get_token(&self) -> Result<String, CliError> {
        self.config.get_token()
    }

    /// Make GET request (works in both online and offline mode)
    pub async fn get(&self, path: &str) -> Result<reqwest::Response, CliError> {
        if self.offline {
            return Err(CliError::OfflineMode("GET not supported in offline mode".to_string()));
        }
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }

        Ok(response)
    }

    /// Make POST request
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, CliError> {
        if self.offline {
            return Err(CliError::OfflineMode("POST not supported in offline mode".to_string()));
        }
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }

        Ok(response)
    }

    /// Make PUT request
    pub async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, CliError> {
        if self.offline {
            return Err(CliError::OfflineMode("PUT not supported in offline mode".to_string()));
        }
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = self
            .client
            .put(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }

        Ok(response)
    }

    /// Make DELETE request
    pub async fn delete(&self, path: &str) -> Result<reqwest::Response, CliError> {
        if self.offline {
            return Err(CliError::OfflineMode("DELETE not supported in offline mode".to_string()));
        }
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }

        Ok(response)
    }

    /// Get local store for offline operations
    pub fn local_store(&self) -> Option<Arc<OfflineStore>> {
        self.local_store.clone()
    }
}
