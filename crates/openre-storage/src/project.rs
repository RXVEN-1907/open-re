//! Project storage (SQLite) for open-re

use openre_config::DatabaseConfig;
use openre_core::error::Result;
use openre_core::ids::*;
use openre_telemetry::metrics;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

/// Project store for SQLite operations
pub struct ProjectStore {
    db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl ProjectStore {
    /// Create a new project store
    pub fn new(project_id: ProjectId, base_path: &PathBuf) -> Result<Self> {
        let db_path = base_path.join(format!("{}.db", project_id));
        
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;
        
        // Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL", [])?;
        conn.execute("PRAGMA synchronous=NORMAL", [])?;
        conn.execute("PRAGMA foreign_keys=ON", [])?;
        conn.execute("PRAGMA cache_size=-100000", [])?; // 100MB cache
        conn.execute("PRAGMA mmap_size=268435456", [])?; // 256MB mmap
        conn.execute("PRAGMA temp_store=MEMORY", [])?;
        conn.execute("PRAGMA busy_timeout=30000", [])?;

        let store = Self {
            db_path,
            conn: Arc::new(Mutex::new(conn)),
        };

        Ok(store)
    }

    /// Ensure schema exists
    pub async fn ensure_schema(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        Self::create_schema(&conn)?;
        Ok(())
    }

    /// Create the database schema
    fn create_schema(conn: &Connection) -> Result<()> {
        // Functions table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS functions (
                id INTEGER PRIMARY KEY,
                address INTEGER NOT NULL UNIQUE,
                name TEXT,
                demangled_name TEXT,
                size INTEGER NOT NULL,
                start_block_id INTEGER,
                end_block_id INTEGER,
                calling_convention TEXT,
                return_type TEXT,
                is_thunk BOOLEAN DEFAULT 0,
                is_library BOOLEAN DEFAULT 0,
                is_entry BOOLEAN DEFAULT 0,
                cyclomatic_complexity INTEGER,
                instruction_count INTEGER,
                block_count INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_functions_address ON functions(address)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name)", [])?;

        // Basic blocks table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS basic_blocks (
                id INTEGER PRIMARY KEY,
                function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
                start_address INTEGER NOT NULL,
                end_address INTEGER NOT NULL,
                size INTEGER NOT NULL,
                instruction_count INTEGER,
                loop_depth INTEGER DEFAULT 0,
                is_entry BOOLEAN DEFAULT 0,
                is_exit BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_basic_blocks_function ON basic_blocks(function_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_basic_blocks_address ON basic_blocks(start_address)", [])?;

        // Instructions table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS instructions (
                id INTEGER PRIMARY KEY,
                block_id INTEGER NOT NULL REFERENCES basic_blocks(id) ON DELETE CASCADE,
                address INTEGER NOT NULL UNIQUE,
                bytes BLOB NOT NULL,
                mnemonic TEXT NOT NULL,
                operands TEXT,
                operand_types TEXT,
                groups TEXT,
                size INTEGER NOT NULL,
                stack_change INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_instructions_block ON instructions(block_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_instructions_address ON instructions(address)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_instructions_mnemonic ON instructions(mnemonic)", [])?;

        // CFG edges table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS cfg_edges (
                id INTEGER PRIMARY KEY,
                from_block_id INTEGER NOT NULL REFERENCES basic_blocks(id) ON DELETE CASCADE,
                to_block_id INTEGER NOT NULL REFERENCES basic_blocks(id) ON DELETE CASCADE,
                edge_type TEXT NOT NULL,
                condition TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(from_block_id, to_block_id, edge_type)
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_cfg_edges_from ON cfg_edges(from_block_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cfg_edges_to ON cfg_edges(to_block_id)", [])?;

        // Call edges table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS call_edges (
                id INTEGER PRIMARY KEY,
                from_function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
                to_function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
                call_site_address INTEGER NOT NULL,
                call_type TEXT NOT NULL,
                is_resolved BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(from_function_id, to_function_id, call_site_address)
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_call_edges_from ON call_edges(from_function_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_call_edges_to ON call_edges(to_function_id)", [])?;

        // Loops table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS loops (
                id INTEGER PRIMARY KEY,
                function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
                header_block_id INTEGER NOT NULL REFERENCES basic_blocks(id),
                loop_type TEXT NOT NULL,
                entry_edges TEXT,
                exit_edges TEXT,
                body_blocks TEXT,
                depth INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_loops_function ON loops(function_id)", [])?;

        // Variables table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS variables (
                id INTEGER PRIMARY KEY,
                function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
                name TEXT,
                type_id INTEGER REFERENCES types(id),
                storage TEXT NOT NULL,
                register TEXT,
                stack_offset INTEGER,
                size INTEGER NOT NULL,
                scope_start INTEGER,
                scope_end INTEGER,
                is_parameter BOOLEAN DEFAULT 0,
                is_return BOOLEAN DEFAULT 0,
                confidence REAL DEFAULT 1.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_variables_function ON variables(function_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_variables_name ON variables(name)", [])?;

        // Types table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS types (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                size INTEGER,
                alignment INTEGER,
                definition TEXT,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_types_name ON types(name)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_types_kind ON types(kind)", [])?;

        // Pseudocode table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS pseudocode (
                id INTEGER PRIMARY KEY,
                function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
                code TEXT NOT NULL,
                language TEXT DEFAULT 'c',
                version INTEGER DEFAULT 1,
                generated_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(function_id, language, version)
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_pseudocode_function ON pseudocode(function_id)", [])?;

        // Annotations table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS annotations (
                id INTEGER PRIMARY KEY,
                address INTEGER NOT NULL,
                function_id INTEGER REFERENCES functions(id) ON DELETE SET NULL,
                annotation_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_annotations_address ON annotations(address)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_annotations_function ON annotations(function_id)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_annotations_type ON annotations(annotation_type)", [])?;

        // Strings table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS strings (
                id INTEGER PRIMARY KEY,
                address INTEGER NOT NULL UNIQUE,
                value TEXT NOT NULL,
                length INTEGER NOT NULL,
                encoding TEXT NOT NULL,
                type TEXT NOT NULL,
                references TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_strings_address ON strings(address)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value)", [])?;
        // FTS5 for full-text search
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS strings_fts USING fts5(value, content='strings', content_rowid='id')", [])?;

        // Constants table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS constants (
                id INTEGER PRIMARY KEY,
                address INTEGER NOT NULL UNIQUE,
                value TEXT NOT NULL,
                size INTEGER NOT NULL,
                base INTEGER DEFAULT 10,
                type TEXT,
                references TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_constants_address ON constants(address)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_constants_value ON constants(value)", [])?;

        // Indexes table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS indexes (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                table_name TEXT NOT NULL,
                columns TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        // Statistics table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS statistics (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#,
            [],
        )?;

        // Insert default statistics
        conn.execute(
            "INSERT OR IGNORE INTO statistics (key, value) VALUES ('total_functions', '0')",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO statistics (key, value) VALUES ('total_instructions', '0')",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO statistics (key, value) VALUES ('total_basic_blocks', '0')",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO statistics (key, value) VALUES ('total_strings', '0')",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO statistics (key, value) VALUES ('analysis_version', '1')",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO statistics (key, value) VALUES ('schema_version', '1')",
            [],
        )?;

        // Migration tracking
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
            [],
        )?;

        Ok(())
    }

    /// Execute a query and return results as JSON values
    pub async fn query(&self, sql: &str, params: Vec<serde_json::Value>) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        let mut stmt = conn.prepare(sql)?;
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(params_from_iter(param_refs), |row| {
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

        metrics::record_db_query(start.elapsed());
        Ok(results)
    }

    /// Convert rusqlite value to JSON
    fn rusqlite_value_to_json(val: rusqlite::types::Value) -> serde_json::Value {
        match val {
            rusqlite::types::Value::Null => serde_json::Value::Null,
            rusqlite::types::Value::Integer(i) => serde_json::Value::Number(serde_json::Number::from(i)),
            rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
            rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
            rusqlite::types::Value::Blob(b) => serde_json::Value::String(base64::encode(b)),
        }
    }

    /// Write identification output
    pub async fn write_identification(&self, output: &crate::IdentificationOutput) -> Result<()> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        conn.execute(
            r#"
            INSERT OR REPLACE INTO statistics (key, value, updated_at) VALUES 
            ('format', ?1, CURRENT_TIMESTAMP),
            ('architecture', ?2, CURRENT_TIMESTAMP),
            ('compiler_info', ?3, CURRENT_TIMESTAMP),
            ('confidence', ?4, CURRENT_TIMESTAMP)
            "#,
            params![
                output.format.as_str(),
                output.architecture.as_str(),
                serde_json::to_string(&output.compiler_info)?,
                output.confidence.to_string(),
            ],
        )?;

        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    // Note: DisassemblyOutput, ControlFlowOutput, DataFlowOutput, TypeRecoveryOutput types are not yet defined
    // These methods will be implemented when those features are added
    /*
    /// Write disassembly output
    pub async fn write_disassembly(&self, output: &crate::DisassemblyOutput) -> Result<()> {
        // TODO: Implement when disassembly is added
        Ok(())
    }

    /// Write control flow output
    pub async fn write_control_flow(&self, output: &crate::ControlFlowOutput) -> Result<()> {
        // TODO: Implement when control flow analysis is added
        Ok(())
    }

    /// Write data flow output
    pub async fn write_data_flow(&self, output: &crate::DataFlowOutput) -> Result<()> {
        // TODO: Implement when data flow analysis is added
        Ok(())
    }

    /// Write type recovery output
    pub async fn write_type_recovery(&self, output: &crate::TypeRecoveryOutput) -> Result<()> {
        // TODO: Implement when type recovery is added
        Ok(())
    }
    */

    /// Finalize the project database
    pub async fn finalize(&self, project_id: ProjectId) -> Result<()> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        // Update statistics
        let total_functions: i64 = conn.query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))?;
        let total_instructions: i64 = conn.query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))?;
        let total_basic_blocks: i64 = conn.query_row("SELECT COUNT(*) FROM basic_blocks", [], |row| row.get(0))?;
        let total_strings: i64 = conn.query_row("SELECT COUNT(*) FROM strings", [], |row| row.get(0))?;

        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_functions'", params![total_functions.to_string()])?;
        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_instructions'", params![total_instructions.to_string()])?;
        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_basic_blocks'", params![total_basic_blocks.to_string()])?;
        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_strings'", params![total_strings.to_string()])?;

        // Run ANALYZE for query planner
        conn.execute("ANALYZE", [])?;

        metrics::record_db_query(start.elapsed());
        Ok(())
    }
}