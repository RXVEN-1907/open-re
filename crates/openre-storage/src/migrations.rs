//! Database migrations for open-re

use openre_core::error::Result;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{info, warn};

/// Migration trait - using a simpler approach for dyn compatibility
pub trait Migration: Send + Sync {
    fn version(&self) -> i64;
    fn name(&self) -> &str;
    fn up_sql(&self) -> &str;
    fn down_sql(&self) -> &str;
}

/// Migration manager
pub struct MigrationManager {
    pool: Arc<PgPool>,
    migrations: Vec<Arc<dyn Migration>>,
}

impl MigrationManager {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self {
            pool,
            migrations: Vec::new(),
        }
    }

    pub fn add_migration(&mut self, migration: Arc<dyn Migration>) {
        self.migrations.push(migration);
    }

    pub async fn migrate(&self) -> Result<()> {
        // Ensure migration table exists
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version BIGINT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#
        )
        .execute(&*self.pool)
        .await?;

        // Get applied migrations
        let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_migrations ORDER BY version")
            .fetch_all(&*self.pool)
            .await?;

        // Sort migrations by version
        let mut migrations = self.migrations.clone();
        migrations.sort_by_key(|m| m.version());

        // Apply pending migrations
        for migration in migrations {
            if !applied.contains(&migration.version()) {
                info!(version = migration.version(), name = migration.name(), "Applying migration");
                sqlx::query(migration.up_sql())
                    .execute(&*self.pool)
                    .await?;
                sqlx::query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)")
                    .bind(migration.version())
                    .bind(migration.name())
                    .execute(&*self.pool)
                    .await?;
                info!(version = migration.version(), name = migration.name(), "Migration applied successfully");
            }
        }

        Ok(())
    }

    pub async fn rollback(&self, target_version: i64) -> Result<()> {
        let applied_rows = sqlx::query("SELECT version, name FROM schema_migrations WHERE version > $1 ORDER BY version DESC")
            .bind(target_version)
            .fetch_all(&*self.pool)
            .await?;

        let applied: Vec<(i64, String)> = applied_rows
            .into_iter()
            .map(|row| {
                (
                    row.get("version"),
                    row.get("name"),
                )
            })
            .collect();

        let mut migrations = self.migrations.clone();
        migrations.sort_by_key(|m| m.version());

        for (version, name) in applied {
            if let Some(migration) = migrations.iter().find(|m| m.version() == version) {
                warn!(version, name, "Rolling back migration");
                sqlx::query(migration.down_sql())
                    .execute(&*self.pool)
                    .await?;
                sqlx::query("DELETE FROM schema_migrations WHERE version = $1")
                    .bind(version)
                    .execute(&*self.pool)
                    .await?;
                warn!(version, name, "Migration rolled back successfully");
            }
        }

        Ok(())
    }

    pub async fn status(&self) -> Result<Vec<MigrationStatus>> {
        let applied_rows = sqlx::query(
            "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
        )
        .fetch_all(&*self.pool)
        .await?;

        let applied: Vec<(i64, String, chrono::DateTime<chrono::Utc>)> = applied_rows
            .into_iter()
            .map(|row| {
                (
                    row.get("version"),
                    row.get("name"),
                    row.get("applied_at"),
                )
            })
            .collect();

        let mut migrations = self.migrations.clone();
        migrations.sort_by_key(|m| m.version());

        let mut status = Vec::new();
        for migration in migrations {
            let applied_info = applied.iter().find(|(v, _, _)| *v == migration.version());
            status.push(MigrationStatus {
                version: migration.version(),
                name: migration.name().to_string(),
                applied: applied_info.is_some(),
                applied_at: applied_info.map(|(_, _, t)| *t),
            });
        }

        Ok(status)
    }
}

/// Migration status
#[derive(Debug, Clone, serde::Serialize)]
pub struct MigrationStatus {
    pub version: i64,
    pub name: String,
    pub applied: bool,
    pub applied_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Initial schema migration
pub struct InitialSchemaMigration;

impl Migration for InitialSchemaMigration {
    fn version(&self) -> i64 { 20260101001 }
    fn name(&self) -> &str { "initial_schema" }
    
    fn up_sql(&self) -> &str {
        r#"
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255),
            full_name VARCHAR(255),
            avatar_url TEXT,
            role VARCHAR(50) DEFAULT 'user',
            status VARCHAR(50) DEFAULT 'active',
            email_verified BOOLEAN DEFAULT FALSE,
            last_login_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        -- Projects table
        CREATE TABLE IF NOT EXISTS projects (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL,
            description TEXT,
            owner_id UUID NOT NULL REFERENCES users(id),
            visibility VARCHAR(20) DEFAULT 'private',
            settings JSONB DEFAULT '{}',
            sqlite_path VARCHAR(500),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            archived_at TIMESTAMPTZ
        );
        CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id);
        CREATE INDEX IF NOT EXISTS idx_projects_visibility ON projects(visibility);

        -- Files table
        CREATE TABLE IF NOT EXISTS files (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            original_name VARCHAR(500) NOT NULL,
            stored_name VARCHAR(500) NOT NULL,
            size_bytes BIGINT NOT NULL,
            sha256_hash VARCHAR(64) NOT NULL,
            format VARCHAR(50),
            architecture VARCHAR(50),
            compiler_info JSONB,
            status VARCHAR(20) DEFAULT 'uploading',
            uploaded_by UUID NOT NULL REFERENCES users(id),
            object_path VARCHAR(500) NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_files_project ON files(project_id);
        CREATE INDEX IF NOT EXISTS idx_files_hash ON files(sha256_hash);
        CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);

        -- Jobs table
        CREATE TABLE IF NOT EXISTS jobs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            config JSONB NOT NULL,
            status VARCHAR(20) DEFAULT 'queued',
            priority INTEGER DEFAULT 0,
            current_stage VARCHAR(50),
            progress FLOAT DEFAULT 0.0,
            error_message TEXT,
            retry_count INTEGER DEFAULT 0,
            max_retries INTEGER DEFAULT 3,
            idempotency_key VARCHAR(100),
            created_by UUID NOT NULL REFERENCES users(id),
            assigned_worker VARCHAR(100),
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_project ON jobs(project_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_file ON jobs(file_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
        CREATE INDEX IF NOT EXISTS idx_jobs_priority_created ON jobs(priority DESC, created_at ASC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency ON jobs(idempotency_key) WHERE idempotency_key IS NOT NULL;

        -- Job stages table
        CREATE TABLE IF NOT EXISTS job_stages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            stage_name VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            input_hash VARCHAR(64),
            output_hash VARCHAR(64),
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            duration_ms BIGINT,
            error_message TEXT,
            metrics JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_job_stages_job ON job_stages(job_id);
        CREATE INDEX IF NOT EXISTS idx_job_stages_status ON job_stages(status);

        -- Job logs table
        CREATE TABLE IF NOT EXISTS job_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            stage_name VARCHAR(50),
            level VARCHAR(10) NOT NULL,
            message TEXT NOT NULL,
            context JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_job_logs_job ON job_logs(job_id);
        CREATE INDEX IF NOT EXISTS idx_job_logs_created ON job_logs(created_at);

        -- Collaborators table
        CREATE TABLE IF NOT EXISTS collaborators (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role VARCHAR(20) NOT NULL,
            invited_by UUID NOT NULL REFERENCES users(id),
            invited_at TIMESTAMPTZ DEFAULT NOW(),
            accepted_at TIMESTAMPTZ,
            UNIQUE(project_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_collaborators_project ON collaborators(project_id);
        CREATE INDEX IF NOT EXISTS idx_collaborators_user ON collaborators(user_id);

        -- Collaborator invites table
        CREATE TABLE IF NOT EXISTS collaborator_invites (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            email VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL,
            invited_by UUID NOT NULL REFERENCES users(id),
            token VARCHAR(100) UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_invites_token ON collaborator_invites(token);
        CREATE INDEX IF NOT EXISTS idx_invites_email ON collaborator_invites(email);

        -- Share links table
        CREATE TABLE IF NOT EXISTS share_links (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            analysis_id UUID REFERENCES jobs(id) ON DELETE SET NULL,
            permissions JSONB NOT NULL,
            token VARCHAR(100) UNIQUE NOT NULL,
            created_by UUID NOT NULL REFERENCES users(id),
            expires_at TIMESTAMPTZ,
            access_count INTEGER DEFAULT 0,
            last_accessed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_share_links_token ON share_links(token);
        CREATE INDEX IF NOT EXISTS idx_share_links_project ON share_links(project_id);

        -- Exports table
        CREATE TABLE IF NOT EXISTS exports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            analysis_id UUID REFERENCES jobs(id) ON DELETE SET NULL,
            format VARCHAR(50) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            object_path VARCHAR(500),
            size_bytes BIGINT,
            requested_by UUID NOT NULL REFERENCES users(id),
            completed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_exports_project ON exports(project_id);

        -- Plugins table
        CREATE TABLE IF NOT EXISTS plugins (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL,
            version VARCHAR(50) NOT NULL,
            type VARCHAR(50) NOT NULL,
            description TEXT,
            author VARCHAR(255),
            license VARCHAR(50),
            repository VARCHAR(500),
            manifest JSONB NOT NULL,
            source VARCHAR(20) DEFAULT 'builtin',
            source_url VARCHAR(500),
            signature VARCHAR(500),
            status VARCHAR(20) DEFAULT 'active',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(name, version)
        );
        CREATE INDEX IF NOT EXISTS idx_plugins_type ON plugins(type);
        CREATE INDEX IF NOT EXISTS idx_plugins_status ON plugins(status);

        -- API keys table
        CREATE TABLE IF NOT EXISTS api_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            key_hash VARCHAR(64) NOT NULL,
            prefix VARCHAR(20) NOT NULL,
            scopes TEXT[] DEFAULT '{}',
            expires_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            revoked_at TIMESTAMPTZ
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
        CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);

        -- Audit logs table (partitioned by month)
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            event_type VARCHAR(50) NOT NULL,
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            ip_address INET,
            user_agent TEXT,
            resource_type VARCHAR(50),
            resource_id UUID,
            action VARCHAR(100) NOT NULL,
            outcome VARCHAR(20) NOT NULL,
            details JSONB,
            risk_level VARCHAR(20) DEFAULT 'low',
            created_at TIMESTAMPTZ DEFAULT NOW()
        ) PARTITION BY RANGE (created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);

        -- Create initial partitions
        CREATE TABLE IF NOT EXISTS audit_logs_2026_01 PARTITION OF audit_logs FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_02 PARTITION OF audit_logs FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_03 PARTITION OF audit_logs FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_04 PARTITION OF audit_logs FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_05 PARTITION OF audit_logs FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_06 PARTITION OF audit_logs FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_07 PARTITION OF audit_logs FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_08 PARTITION OF audit_logs FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_09 PARTITION OF audit_logs FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_10 PARTITION OF audit_logs FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_11 PARTITION OF audit_logs FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
        CREATE TABLE IF NOT EXISTS audit_logs_2026_12 PARTITION OF audit_logs FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
        "#
    }
    
    fn down_sql(&self) -> &str {
        r#"
        DROP TABLE IF EXISTS audit_logs_2026_12;
        DROP TABLE IF EXISTS audit_logs_2026_11;
        DROP TABLE IF EXISTS audit_logs_2026_10;
        DROP TABLE IF EXISTS audit_logs_2026_09;
        DROP TABLE IF EXISTS audit_logs_2026_08;
        DROP TABLE IF EXISTS audit_logs_2026_07;
        DROP TABLE IF EXISTS audit_logs_2026_06;
        DROP TABLE IF EXISTS audit_logs_2026_05;
        DROP TABLE IF EXISTS audit_logs_2026_04;
        DROP TABLE IF EXISTS audit_logs_2026_03;
        DROP TABLE IF EXISTS audit_logs_2026_02;
        DROP TABLE IF EXISTS audit_logs_2026_01;
        DROP TABLE IF EXISTS audit_logs;
        DROP TABLE IF EXISTS api_keys;
        DROP TABLE IF EXISTS plugins;
        DROP TABLE IF EXISTS exports;
        DROP TABLE IF EXISTS share_links;
        DROP TABLE IF EXISTS collaborator_invites;
        DROP TABLE IF EXISTS collaborators;
        DROP TABLE IF EXISTS job_logs;
        DROP TABLE IF EXISTS job_stages;
        DROP TABLE IF EXISTS jobs;
        DROP TABLE IF EXISTS files;
        DROP TABLE IF EXISTS projects;
        DROP TABLE IF EXISTS users;
        "#
    }
}