//! Global storage (PostgreSQL) for open-re

use openre_config::DatabaseConfig;
use openre_core::error::Result;
use openre_core::ids::*;
use openre_telemetry::metrics;
use sqlx::{PgPool, Pool, Postgres, Row};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Global store for PostgreSQL operations
#[derive(Clone)]
pub struct GlobalStore {
    pool: Arc<PgPool>,
}

impl GlobalStore {
    /// Create a new global store
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let pool = PgPool::connect_with(
            sqlx::postgres::PgConnectOptions::from_str(&config.url)?
                .max_connections(config.max_connections)
                .min_connections(config.min_connections)
                .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
                .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
                .max_lifetime(Duration::from_secs(config.max_lifetime_secs)),
        ).await?;

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
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        info!("Database migrations completed");
        Ok(())
    }

    /// Health check
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Get pool stats
    pub fn pool_stats(&self) -> sqlx::pool::PoolStats {
        self.pool.stats()
    }
}

// Job operations
impl GlobalStore {
    pub async fn create_job(&self, job: &crate::AnalysisJob) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            INSERT INTO jobs (id, project_id, file_id, config, status, priority, current_stage, progress, retry_count, max_retries, idempotency_key, created_by, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            job.id.as_uuid(),
            job.project_id.as_uuid(),
            job.file_id.as_uuid(),
            serde_json::to_value(&job.config)?,
            "queued",
            job.priority.0,
            job.config.stages.first().map(|s| s.as_str()),
            0.0,
            job.retry_count as i32,
            job.max_retries as i32,
            job.idempotency_key.as_deref(),
            job.created_by.as_uuid(),
            job.created_at,
            job.updated_at,
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn update_job_status(&self, job_id: JobId, status: &crate::JobStatus) -> Result<()> {
        let start = std::time::Instant::now();
        let (status_str, current_stage, progress, error_message, started_at, completed_at) = match status {
            crate::JobStatus::Queued { queued_at } => ("queued", None, 0.0, None, None, Some(*queued_at)),
            crate::JobStatus::Running { worker_id, started_at, stage } => ("running", Some(stage.as_str()), 0.0, None, Some(*started_at), None),
            crate::JobStatus::Completed { completed_at } => ("completed", None, 1.0, None, None, Some(*completed_at)),
            crate::JobStatus::Failed { error, failed_at, retryable } => ("failed", None, 0.0, Some(error.clone()), None, Some(*failed_at)),
            crate::JobStatus::Cancelled { cancelled_at, reason } => ("cancelled", None, 0.0, Some(reason.clone()), None, Some(*cancelled_at)),
            crate::JobStatus::Scheduled { run_at } => ("scheduled", None, 0.0, None, None, Some(*run_at)),
        };

        sqlx::query!(
            r#"
            UPDATE jobs SET status = $1, current_stage = $2, progress = $3, error_message = $4, started_at = $5, completed_at = $6, updated_at = NOW()
            WHERE id = $7
            "#,
            status_str,
            current_stage,
            progress,
            error_message,
            started_at,
            completed_at,
            job_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn complete_job(&self, job_id: JobId, result: &crate::AnalysisResult) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            UPDATE jobs SET status = 'completed', progress = 1.0, completed_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
            job_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// Project operations
impl GlobalStore {
    pub async fn create_project(&self, project: &crate::Project) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            INSERT INTO projects (id, name, description, owner_id, visibility, settings, sqlite_path, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            project.id.as_uuid(),
            project.name,
            project.description,
            project.owner_id.as_uuid(),
            project.visibility,
            serde_json::to_value(&project.settings)?,
            project.sqlite_path.as_deref(),
            project.created_at,
            project.updated_at,
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn init_project_db(&self, project_id: ProjectId) -> Result<()> {
        // This will be called to initialize the SQLite database for the project
        // The actual SQLite initialization happens in ProjectStore
        Ok(())
    }

    pub async fn add_collaborator(&self, project_id: ProjectId, user_id: UserId, role: crate::CollaboratorRole) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            INSERT INTO collaborators (id, project_id, user_id, role, invited_by, invited_at, accepted_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            Uuid::new_v4(),
            project_id.as_uuid(),
            user_id.as_uuid(),
            role.as_str(),
            user_id.as_uuid(), // invited_by = user_id for owner
            chrono::Utc::now(),
            chrono::Utc::now(),
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// File operations
impl GlobalStore {
    pub async fn update_file(&self, file: &crate::FileRecord) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            UPDATE files SET size_bytes = $1, sha256_hash = $2, format = $3, architecture = $4, compiler_info = $5, status = $6, updated_at = NOW()
            WHERE id = $7
            "#,
            file.size as i64,
            file.hash,
            file.format.as_deref().map(|f| f.as_str()),
            file.architecture.as_deref().map(|a| a.as_str()),
            file.compiler_info.as_ref().map(serde_json::to_value).transpose()?,
            file.status.as_str(),
            file.id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    pub async fn update_file_format(&self, file_id: FileId, format: crate::FileFormat) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            UPDATE files SET format = $1, status = 'ready', updated_at = NOW()
            WHERE id = $2
            "#,
            format.as_str(),
            file_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// Invite operations
impl GlobalStore {
    pub async fn create_invite(&self, invite: &crate::CollaboratorInvite) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            INSERT INTO collaborator_invites (id, project_id, email, role, invited_by, token, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            invite.id,
            invite.project_id.as_uuid(),
            invite.email,
            invite.role.as_str(),
            invite.invited_by.as_uuid(),
            invite.token,
            invite.expires_at,
            invite.created_at,
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}

// Share link operations
impl GlobalStore {
    pub async fn create_share_link(&self, link: &crate::ShareLink) -> Result<()> {
        let start = std::time::Instant::now();
        sqlx::query!(
            r#"
            INSERT INTO share_links (id, project_id, analysis_id, permissions, token, created_by, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            link.id,
            link.project_id.as_uuid(),
            link.analysis_id.as_ref().map(|id| id.as_uuid()),
            serde_json::to_value(&link.permissions)?,
            link.token,
            link.created_by.as_uuid(),
            link.expires_at,
            link.created_at,
        )
        .execute(&self.pool)
        .await?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}