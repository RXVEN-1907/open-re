//! CLI context

use crate::context::offline::OfflineStore;
use crate::{CliConfig, CliError, OutputFormat};
use reqwest::Client;
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
                    .join("offline.db")
            });
            Some(Arc::new(OfflineStore::new(local_db_path_clone)?))
        } else {
            None
        };

        eprintln!("DEBUG: Context::new offline={}, local_db_path={:?}", offline, local_db_path);
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

/// Offline storage module
pub mod offline {
    use crate::error::CliError;
    use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Offline store for local operations
    pub struct OfflineStore {
        conn: Arc<tokio::sync::Mutex<Connection>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct LocalProject {
        pub id: String,
        pub name: String,
        pub description: Option<String>,
        pub is_public: bool,
        pub created_at: String,
        pub updated_at: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct LocalProjectList {
        pub projects: Vec<LocalProject>,
        pub total: u64,
        pub page: u32,
        pub per_page: u32,
    }

    impl OfflineStore {
        pub fn new(db_path: Option<PathBuf>) -> Result<Self, crate::error::CliError> {
            let base_path = db_path.unwrap_or_else(|| {
                dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("openre")
            });

            std::fs::create_dir_all(&base_path)?;
            let db_path = base_path.join("offline.db");

            let conn = Connection::open(&db_path)?;

            // Create projects table
            conn.execute(
                r#"
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    is_public BOOLEAN NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                "#,
                [],
            )?;

            Ok(Self { conn: Arc::new(tokio::sync::Mutex::new(conn)) })
        }

        pub async fn create_project(
            &self,
            name: String,
            description: Option<String>,
            is_public: bool,
        ) -> Result<LocalProject, CliError> {
            let conn = self.conn.lock().await;
            let id = Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();

            conn.execute(
                "INSERT INTO projects (id, name, description, is_public, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, name, description, is_public as i32, now, now],
            )?;

            Ok(LocalProject {
                id,
                name,
                description,
                is_public,
                created_at: now.clone(),
                updated_at: now,
            })
        }

        pub async fn get_project(&self, id: &str) -> Result<Option<LocalProject>, CliError> {
            let conn = self.conn.lock().await;
            let project = conn
                .query_row(
                    "SELECT id, name, description, is_public, created_at, updated_at FROM projects WHERE id = ?1",
                    params![id],
                    |row| {
                        Ok(LocalProject {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            description: row.get(2)?,
                            is_public: row.get(3)?,
                            created_at: row.get(4)?,
                            updated_at: row.get(5)?,
                        })
                    },
                )
                .optional()?;
            Ok(project)
        }

        pub async fn list_projects(
            &self,
            page: u32,
            per_page: u32,
            search: Option<String>,
        ) -> Result<LocalProjectList, CliError> {
            let conn = self.conn.lock().await;
            let offset = (page - 1) as u64 * per_page as u64;
            let search_term = search.clone();

            let (sql, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if let Some(ref search) =
                search_term
            {
                (
                    format!(
                        "SELECT id, name, description, is_public, created_at, updated_at FROM projects WHERE name LIKE ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3"
                    ),
                    vec![
                        Box::new(format!("%{}%", search)),
                        Box::new(per_page as i64),
                        Box::new(offset as i64),
                    ],
                )
            } else {
                (
                    "SELECT id, name, description, is_public, created_at, updated_at FROM projects ORDER BY created_at DESC LIMIT ?1 OFFSET ?2".to_string(),
                    vec![Box::new(per_page as i64), Box::new(offset as i64)],
                )
            };

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(params), |row| {
                Ok(LocalProject {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_public: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?;

            let mut projects = Vec::new();
            for row in rows {
                projects.push(row?);
            }

            // Get total count
            let total: u64 = if search_term.is_some() {
                conn.query_row(
                    "SELECT COUNT(*) FROM projects WHERE name LIKE ?1",
                    params![format!("%{}%", search_term.unwrap())],
                    |row| row.get(0),
                )?
            } else {
                conn.query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?
            };

            Ok(LocalProjectList { projects, total, page: 1, per_page })
        }

        pub async fn update_project(
            &self,
            id: &str,
            name: Option<String>,
            description: Option<String>,
            public: Option<bool>,
        ) -> Result<LocalProject, CliError> {
            // First check if project exists
            let existing = self
                .get_project(id)
                .await?
                .ok_or(CliError::InvalidInput("Project not found".to_string()))?;

            let now = chrono::Utc::now().to_rfc3339();

            let mut updates = Vec::new();
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(name) = name {
                updates.push("name = ?");
                params.push(Box::new(name) as Box<dyn rusqlite::ToSql>);
            }
            if let Some(description) = description {
                updates.push("description = ?");
                params.push(Box::new(description) as Box<dyn rusqlite::ToSql>);
            }
            if let Some(public) = public {
                updates.push("is_public = ?");
                params.push(Box::new(public as i32) as Box<dyn rusqlite::ToSql>);
            }

            if updates.is_empty() {
                return Ok(existing);
            }

            updates.push("updated_at = ?");
            params.push(Box::new(chrono::Utc::now().to_rfc3339()) as Box<dyn rusqlite::ToSql>);
            params.push(Box::new(id.to_string()) as Box<dyn rusqlite::ToSql>);

            let sql = format!("UPDATE projects SET {} WHERE id = ?", updates.join(", "));
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

            {
                let conn = self.conn.lock().await;
                conn.execute(&sql, params_from_iter(param_refs))?;
            }

            // Fetch the updated project
            self.get_project(id)
                .await?
                .ok_or(CliError::InvalidInput("Project not found".to_string()))
        }

        pub async fn delete_project(&self, id: &str) -> Result<(), CliError> {
            let conn = self.conn.lock().await;
            conn.execute("DELETE FROM projects WHERE id = ?1", params![id])?;
            Ok(())
        }
    }
}
