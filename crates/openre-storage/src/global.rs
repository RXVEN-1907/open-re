//! Global storage (PostgreSQL) for open-re

#[cfg(feature = "postgres")]
use openre_config::DatabaseConfig;
#[cfg(feature = "postgres")]
use openre_core::error::{Error, OpenreResult as Result};
#[cfg(feature = "postgres")]
use openre_core::ids::{FileFormat, FileId, JobId, JobStatus, ProjectId, UserId};
#[cfg(feature = "postgres")]
use openre_core::traits::{
    AnalysisJob, AnalysisResult, CollaboratorInvite, CollaboratorRole, FileRecord, Project,
    ShareLink,
};
#[cfg(feature = "postgres")]
use openre_telemetry::metrics;
#[cfg(feature = "postgres")]
use sqlx::{postgres::PgConnectOptions, PgPool};
#[cfg(feature = "postgres")]
use std::str::FromStr;
#[cfg(feature = "postgres")]
use std::sync::Arc;
#[cfg(feature = "postgres")]
use tracing::info;
#[cfg(feature = "postgres")]
use uuid::Uuid;

#[cfg(feature = "postgres")]
/// Convert sqlx::Error to openre_core::Error::Database
fn map_sqlx_error(e: sqlx::Error) -> Error {
    Error::Database(e.to_string())
}

#[cfg(feature = "postgres")]
/// Global store for PostgreSQL operations
#[derive(Clone)]
pub struct GlobalStore {
    pool: Arc<PgPool>,
}

#[cfg(feature = "postgres")]
impl GlobalStore {
    /// Create a new global store
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let options = PgConnectOptions::from_str(&config.url).map_err(map_sqlx_error)?;
        let pool = PgPool::connect_with(options).await.map_err(map_sqlx_error)?;

        // Note: Pool options like max_connections, min_connections, etc.
        // are set via the pool builder in sqlx 0.6+
        // For now, we'll use the default pool configuration

        info!("Connected to PostgreSQL database");

        let store = Self { pool: Arc::new(pool) };

        // Run migrations if enabled
        if config.run_migrations {
            store.run_migrations().await?;
        }

        Ok(store)
    }

    /// Get the underlying pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run database migrations
    pub async fn run_migrations(&self) -> Result<()> {
        info!("Running database migrations");
        // Note: sqlx::migrate! requires the "migrate" feature and a migrations directory
        // For now, we'll skip migrations if the directory doesn't exist
        if std::path::Path::new("./migrations").exists() {
            // Use the migrate API directly
            let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
                .await
                .map_err(|e| openre_core::Error::Internal(e.into()))?;
            migrator.run(&*self.pool).await.map_err(|e| openre_core::Error::Internal(e.into()))?;
        }
        info!("Database migrations completed");
        Ok(())
    }

    /// Health check
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&*self.pool).await.map_err(map_sqlx_error)?;
        Ok(())
    }

    /// Get pool stats
    pub fn pool_stats(&self) -> Arc<sqlx::Pool<sqlx::Postgres>> {
        self.pool.clone()
    }
}

// Job operations
#[cfg(feature = "postgres")]
impl GlobalStore {
    pub async fn create_job(&self, job: &AnalysisJob) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            INSERT INTO jobs (id, project_id, file_id, config, status, priority, current_stage, progress, retry_count, max_retries, idempotency_key, created_by, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#
        )
        .bind(job.id.as_uuid())
        .bind(job.project_id.as_uuid())
        .bind(job.file_id.as_uuid())
        .bind(serde_json::to_value(&job.config)?)
        .bind("queued")
        .bind(job.priority)
        .bind(job.config.stages.first().map(|s| s.as_str()))
        .bind(0.0)
        .bind(job.retry_count as i32)
        .bind(job.max_retries as i32)
        .bind(job.idempotency_key.as_deref())
        .bind(job.created_by.as_uuid())
        .bind(job.created_at)
        .bind(job.created_at) // Use created_at as updated_at since there's no updated_at field
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn update_job_status(&self, job_id: JobId, status: &JobStatus) -> Result<()> {
        let start = std::time::Instant::now();
        let (status_str, current_stage, progress, error_message, started_at, completed_at) =
            match status {
                JobStatus::Queued { queued_at } => {
                    ("queued", None, 0.0, None, None, Some(*queued_at))
                }
                JobStatus::Running { worker_id: _worker_id, started_at, stage } => {
                    ("running", Some(stage.as_str()), 0.0, None, Some(*started_at), None)
                }
                JobStatus::Completed { completed_at } => {
                    ("completed", None, 1.0, None, None, Some(*completed_at))
                }
                JobStatus::Failed { error, failed_at, retryable: _retryable } => {
                    ("failed", None, 0.0, Some(error.clone()), None, Some(*failed_at))
                }
                JobStatus::Cancelled { cancelled_at, reason } => {
                    ("cancelled", None, 0.0, Some(reason.clone()), None, Some(*cancelled_at))
                }
                JobStatus::Scheduled { run_at } => {
                    ("scheduled", None, 0.0, None, None, Some(*run_at))
                }
            };

        sqlx::query(
            r#"
            UPDATE jobs SET status = $1, current_stage = $2, progress = $3, error_message = $4, started_at = $5, completed_at = $6, updated_at = NOW()
            WHERE id = $7
            "#
        )
        .bind(status_str)
        .bind(current_stage)
        .bind(progress)
        .bind(error_message)
        .bind(started_at)
        .bind(completed_at)
        .bind(job_id.as_uuid())
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn complete_job(&self, job_id: JobId, _result: &AnalysisResult) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            UPDATE jobs SET status = 'completed', progress = 1.0, completed_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#
        )
        .bind(job_id.as_uuid())
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// Project operations
#[cfg(feature = "postgres")]
impl GlobalStore {
    pub async fn create_project(&self, project: &Project) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            INSERT INTO projects (id, name, description, owner_id, visibility, settings, sqlite_path, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#
        )
        .bind(project.id.as_uuid())
        .bind(project.name.clone())
        .bind(project.description.clone())
        .bind(project.owner_id.as_uuid())
        .bind(project.visibility.clone())
        .bind(serde_json::to_value(&project.settings)?)
        .bind(project.sqlite_path.as_deref())
        .bind(project.created_at)
        .bind(project.updated_at)
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn init_project_db(&self, _project_id: ProjectId) -> Result<()> {
        // This will be called to initialize the SQLite database for the project
        // The actual SQLite initialization happens in ProjectStore
        Ok(())
    }

    pub async fn add_collaborator(
        &self,
        project_id: ProjectId,
        user_id: UserId,
        role: CollaboratorRole,
    ) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            INSERT INTO collaborators (id, project_id, user_id, role, invited_by, invited_at, accepted_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(Uuid::new_v4())
        .bind(project_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(role.as_str())
        .bind(user_id.as_uuid()) // invited_by = user_id for owner
        .bind(chrono::Utc::now())
        .bind(chrono::Utc::now())
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// File operations
#[cfg(feature = "postgres")]
impl GlobalStore {
    pub async fn update_file(&self, file: &FileRecord) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            UPDATE files SET size_bytes = $1, sha256_hash = $2, format = $3, architecture = $4, compiler_info = $5, status = $6, updated_at = NOW()
            WHERE id = $7
            "#
        )
        .bind(file.size as i64)
        .bind(file.hash.clone())
        .bind(file.format.as_ref().map(|f| f.as_str()))
        .bind(file.architecture.as_ref().map(|a| a.as_str()))
        .bind(file.compiler_info.as_ref().map(serde_json::to_value).transpose()?)
        .bind(file.status.as_str())
        .bind(file.id.as_uuid())
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn update_file_format(&self, file_id: FileId, format: FileFormat) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            UPDATE files SET format = $1, status = 'ready', updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(format.as_str())
        .bind(file_id.as_uuid())
        .execute(&*self.pool)
        .await
        .map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// Invite operations
#[cfg(feature = "postgres")]
impl GlobalStore {
    pub async fn create_invite(&self, invite: &CollaboratorInvite) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            INSERT INTO collaborator_invites (id, project_id, email, role, invited_by, token, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(invite.id)
        .bind(invite.project_id.as_uuid())
        .bind(invite.email.clone())
        .bind(invite.role.as_str())
        .bind(invite.invited_by.as_uuid())
        .bind(invite.token.clone())
        .bind(invite.expires_at)
        .bind(invite.created_at)
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// Share link operations
#[cfg(feature = "postgres")]
impl GlobalStore {
    pub async fn create_share_link(&self, link: &ShareLink) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query(
            r#"
            INSERT INTO share_links (id, project_id, analysis_id, permissions, token, created_by, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(link.id.as_uuid())
        .bind(link.project_id.as_uuid())
        .bind(link.analysis_id.as_ref().map(|id| id.as_uuid()))
        .bind(serde_json::to_value(&link.permissions)?)
        .bind(link.token.clone())
        .bind(link.created_by.as_uuid())
        .bind(link.expires_at)
        .bind(link.created_at)
        .execute(&*self.pool)
        .await.map_err(map_sqlx_error)?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}
