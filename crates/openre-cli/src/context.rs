//! CLI context

use crate::{CliConfig, CliError, OutputFormat};
use base64::Engine;
use openre_storage::project::ProjectStore;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// CLI execution context
pub struct Context {
    pub config: CliConfig,
    pub client: Option<Client>,
    pub server_url: String,
    pub api_key: Option<String>,
    pub output_format: OutputFormat,
    pub verbose: bool,
    pub offline: bool,
    pub data_dir: PathBuf,
    pub local_store: Option<Arc<Mutex<Option<LocalStore>>>>,
}

impl Context {
    /// Create a new context
    pub fn new(
        config: CliConfig,
        client: Option<Client>,
        server_url: String,
        api_key: Option<String>,
        output_format: OutputFormat,
        verbose: bool,
        offline: bool,
        data_dir: String,
    ) -> Result<Self, CliError> {
        let data_dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&data_dir)?;

        let local_store = if offline {
            Some(Arc::new(Mutex::new(None)))
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
            data_dir,
            local_store,
        })
    }

    /// Get or initialize the local store
    pub async fn local_store(&self) -> Result<Arc<Mutex<Option<LocalStore>>>, CliError> {
        let store = self.local_store.as_ref().ok_or_else(|| {
            CliError::InvalidInput("Local store not available in online mode".to_string())
        })?;

        let mut guard = store.lock().await;
        if guard.is_none() {
            let db_path = self.data_dir.join("openre.db");
            *guard = Some(LocalStore::new(&db_path).await?);
        }
        Ok(store.clone())
    }

    /// Check if running in offline mode
    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// Get authentication token
    pub fn get_token(&self) -> Result<String, CliError> {
        self.config.get_token()
    }

    /// Make GET request (online mode only)
    pub async fn get(&self, path: &str) -> Result<reqwest::Response, CliError> {
        let client = self.client.as_ref().ok_or_else(|| {
            CliError::InvalidInput("HTTP client not available in offline mode".to_string())
        })?;

        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = client
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

    /// Make POST request (online mode only)
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, CliError> {
        let client = self.client.as_ref().ok_or_else(|| {
            CliError::InvalidInput("HTTP client not available in offline mode".to_string())
        })?;

        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = client
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

    /// Make PUT request (online mode only)
    pub async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, CliError> {
        let client = self.client.as_ref().ok_or_else(|| {
            CliError::InvalidInput("HTTP client not available in offline mode".to_string())
        })?;

        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = client
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

    /// Make DELETE request (online mode only)
    pub async fn delete(&self, path: &str) -> Result<reqwest::Response, CliError> {
        let client = self.client.as_ref().ok_or_else(|| {
            CliError::InvalidInput("HTTP client not available in offline mode".to_string())
        })?;

        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;

        let response = client
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

    /// Get the HTTP client for streaming operations (online mode only)
    pub fn client(&self) -> Result<&Client, CliError> {
        self.client.as_ref().ok_or_else(|| {
            CliError::InvalidInput("HTTP client not available in offline mode".to_string())
        })
    }

    /// Get the server URL
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

/// Local storage for offline mode
pub struct LocalStore {
    conn: Arc<Mutex<Option<rusqlite::Connection>>>,
}

impl LocalStore {
    /// Create a new local store
    pub async fn new(db_path: &PathBuf) -> Result<Self, CliError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = rusqlite::Connection::open(db_path)?;

        // Enable WAL mode for better concurrency
        // PRAGMA journal_mode returns a result, so use query_row
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute("PRAGMA synchronous=NORMAL", [])?;
        conn.execute("PRAGMA foreign_keys=ON", [])?;
        // PRAGMA busy_timeout returns a result, so use query_row
        let _: i64 = conn.query_row("PRAGMA busy_timeout=30000", [], |row| row.get(0))?;

        let store = Self {
            conn: Arc::new(Mutex::new(Some(conn))),
        };

        // Initialize schema
        store.init_schema().await?;

        Ok(store)
    }

    /// Take the connection from the mutex for use
    async fn take_conn(&self) -> Result<rusqlite::Connection, CliError> {
        let mut guard = self.conn.lock().await;
        guard.take().ok_or_else(|| {
            CliError::Internal("Connection already in use".to_string())
        })
    }

    /// Put the connection back into the mutex
    async fn put_conn(&self, conn: rusqlite::Connection) {
        let mut guard = self.conn.lock().await;
        *guard = Some(conn);
    }

    /// Initialize database schema
    async fn init_schema(&self) -> Result<(), CliError> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");

        // Projects table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
            [],
        ).map_err(|e| {
            eprintln!("CREATE TABLE projects error: {:?}", e);
            e
        })?;

        // Scans table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                name TEXT,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                progress REAL DEFAULT 0.0,
                findings_count INTEGER DEFAULT 0,
                checks_total INTEGER DEFAULT 0,
                checks_completed INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
            "#,
            [],
        )?;

        // Scan findings table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS scan_findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                category TEXT NOT NULL,
                check_name TEXT NOT NULL,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                evidence TEXT,
                remediation TEXT,
                verified BOOLEAN DEFAULT 0,
                cwe_ids TEXT,
                mitre_attack_ids TEXT,
                owasp_category TEXT,
                tags TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            "#,
            [],
        )?;

        // Indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON scan_findings(severity)", [])?;

        Ok(())
    }

    /// Execute a query and return results as JSON values
    pub async fn query(
        &self,
        sql: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, CliError> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");

        let mut stmt = conn.prepare(sql)?;
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

        // Convert JSON values to SQLite parameters
        let param_values: Vec<Box<dyn rusqlite::ToSql>> = params
            .iter()
            .map(|v| match v {
                serde_json::Value::Null => Box::new(None::<String>) as Box<dyn rusqlite::ToSql>,
                serde_json::Value::Bool(b) => Box::new(*b) as Box<dyn rusqlite::ToSql>,
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Box::new(i) as Box<dyn rusqlite::ToSql>
                    } else if let Some(u) = n.as_u64() {
                        // Handle u64 values that don't fit in i64 by storing as string
                        Box::new(u.to_string()) as Box<dyn rusqlite::ToSql>
                    } else if let Some(f) = n.as_f64() {
                        Box::new(f) as Box<dyn rusqlite::ToSql>
                    } else {
                        Box::new(n.to_string()) as Box<dyn rusqlite::ToSql>
                    }
                }
                serde_json::Value::String(s) => Box::new(s.clone()) as Box<dyn rusqlite::ToSql>,
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                    Box::new(v.to_string()) as Box<dyn rusqlite::ToSql>
                }
            })
            .collect();

        let param_refs: Vec<&dyn rusqlite::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(rusqlite::params_from_iter(param_refs), |row| {
            let mut map = serde_json::Map::new();
            for (i, col) in cols.iter().enumerate() {
                let val: rusqlite::types::Value = row.get(i)?;
                map.insert(col.to_string(), Self::rusqlite_value_to_json(val));
            }
            Ok(serde_json::Value::Object(map))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }

    /// Execute a single statement
    pub async fn execute(&self, sql: &str, params: Vec<serde_json::Value>) -> Result<usize, CliError> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");


        // Convert JSON values to SQLite parameters
        let param_values: Vec<Box<dyn rusqlite::ToSql>> = params
            .iter()
            .map(|v| match v {
                serde_json::Value::Null => Box::new(None::<String>) as Box<dyn rusqlite::ToSql>,
                serde_json::Value::Bool(b) => Box::new(*b) as Box<dyn rusqlite::ToSql>,
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Box::new(i) as Box<dyn rusqlite::ToSql>
                    } else if let Some(u) = n.as_u64() {
                        // Handle u64 values that don't fit in i64 by storing as string
                        Box::new(u.to_string()) as Box<dyn rusqlite::ToSql>
                    } else if let Some(f) = n.as_f64() {
                        Box::new(f) as Box<dyn rusqlite::ToSql>
                    } else {
                        Box::new(n.to_string()) as Box<dyn rusqlite::ToSql>
                    }
                }
                serde_json::Value::String(s) => Box::new(s.clone()) as Box<dyn rusqlite::ToSql>,
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                    Box::new(v.to_string()) as Box<dyn rusqlite::ToSql>
                }
            })
            .collect();

        let param_refs: Vec<&dyn rusqlite::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let rows_affected = conn.execute(sql, rusqlite::params_from_iter(param_refs))?;

        Ok(rows_affected)
    }

    /// Convert rusqlite value to JSON
    fn rusqlite_value_to_json(val: rusqlite::types::Value) -> serde_json::Value {
        match val {
            rusqlite::types::Value::Null => serde_json::Value::Null,
            rusqlite::types::Value::Integer(i) => serde_json::Value::Number(serde_json::Number::from(i)),
            rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
            rusqlite::types::Value::Blob(b) => {
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b))
            }
        }
    }
}
