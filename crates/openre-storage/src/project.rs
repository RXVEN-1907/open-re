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
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(params_from_iter(param_refs), |row| {
            let cols = row.column_names();
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

    /// Write disassembly output
    pub async fn write_disassembly(&self, output: &crate::DisassemblyOutput) -> Result<()> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        let tx = conn.transaction()?;
        
        // Insert functions
        for func in &output.function_boundaries {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO functions (id, address, name, size, start_block_id, end_block_id, is_entry, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                "#,
                params![
                    func.id.0 as i64,
                    func.address as i64,
                    func.name,
                    func.size as i64,
                    func.start_block_id.map(|b| b.0 as i64),
                    func.end_block_id.map(|b| b.0 as i64),
                    func.is_entry,
                ],
            )?;
        }

        // Insert basic blocks
        for block in &output.basic_blocks {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO basic_blocks (id, function_id, start_address, end_address, size, instruction_count, is_entry, is_exit, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP)
                "#,
                params![
                    block.id.0 as i64,
                    block.function_id.0 as i64,
                    block.start_address as i64,
                    block.end_address as i64,
                    block.size as i64,
                    block.instruction_count as i64,
                    block.is_entry,
                    block.is_exit,
                ],
            )?;
        }

        // Insert instructions
        for instr in &output.instructions {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO instructions (id, block_id, address, bytes, mnemonic, operands, operand_types, groups, size, stack_change, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, CURRENT_TIMESTAMP)
                "#,
                params![
                    instr.id.0 as i64,
                    instr.block_id.0 as i64,
                    instr.address as i64,
                    instr.bytes.as_slice(),
                    instr.mnemonic,
                    serde_json::to_string(&instr.operands)?,
                    serde_json::to_string(&instr.operand_types)?,
                    serde_json::to_string(&instr.groups)?,
                    instr.size as i64,
                    instr.stack_change as i64,
                ],
            )?;
        }

        tx.commit()?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    /// Write control flow output
    pub async fn write_control_flow(&self, output: &crate::ControlFlowOutput) -> Result<()> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        let tx = conn.transaction()?;
        
        // Insert CFG edges
        for edge in &output.cfg_edges {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO cfg_edges (id, from_block_id, to_block_id, edge_type, condition, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
                "#,
                params![
                    edge.id.0 as i64,
                    edge.from_block_id.0 as i64,
                    edge.to_block_id.0 as i64,
                    edge.edge_type.as_str(),
                    edge.condition,
                ],
            )?;
        }

        // Insert call edges
        for edge in &output.call_edges {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO call_edges (id, from_function_id, to_function_id, call_site_address, call_type, is_resolved, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)
                "#,
                params![
                    edge.id.0 as i64,
                    edge.from_function_id.0 as i64,
                    edge.to_function_id.0 as i64,
                    edge.call_site_address as i64,
                    edge.call_type.as_str(),
                    edge.is_resolved,
                ],
            )?;
        }

        // Insert loops
        for loop_info in &output.loops {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO loops (id, function_id, header_block_id, loop_type, entry_edges, exit_edges, body_blocks, depth, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP)
                "#,
                params![
                    loop_info.id.0 as i64,
                    loop_info.function_id.0 as i64,
                    loop_info.header_block_id.0 as i64,
                    loop_info.loop_type.as_str(),
                    serde_json::to_string(&loop_info.entry_edges)?,
                    serde_json::to_string(&loop_info.exit_edges)?,
                    serde_json::to_string(&loop_info.body_blocks)?,
                    loop_info.depth as i64,
                ],
            )?;
        }

        tx.commit()?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    /// Write data flow output
    pub async fn write_data_flow(&self, output: &crate::DataFlowOutput) -> Result<()> {
        // Placeholder for data flow output
        Ok(())
    }

    /// Write type recovery output
    pub async fn write_type_recovery(&self, output: &crate::TypeRecoveryOutput) -> Result<()> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        let tx = conn.transaction()?;
        
        // Insert types
        for (id, type_info) in &output.types {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO types (id, name, kind, size, alignment, definition, source, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                "#,
                params![
                    id.0 as i64,
                    type_info.name,
                    type_info.kind.as_str(),
                    type_info.size.map(|s| s as i64),
                    type_info.alignment.map(|a| a as i64),
                    serde_json::to_string(&type_info.definition)?,
                    type_info.source.as_str(),
                ],
            )?;
        }

        // Insert variables
        for var in &output.variables {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO variables (id, function_id, name, type_id, storage, register, stack_offset, size, scope_start, scope_end, is_parameter, is_return, confidence, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                "#,
                params![
                    var.id.0 as i64,
                    var.function_id.0 as i64,
                    var.name,
                    var.type_id.map(|t| t.0 as i64),
                    var.storage.as_str(),
                    var.register,
                    var.stack_offset.map(|o| o as i64),
                    var.size as i64,
                    var.scope_start.map(|s| s as i64),
                    var.scope_end.map(|s| s as i64),
                    var.is_parameter,
                    var.is_return,
                    var.confidence,
                ],
            )?;
        }

        tx.commit()?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    /// Write decompilation output
    pub async fn write_decompilation(&self, output: &crate::DecompilationOutput) -> Result<()> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        let tx = conn.transaction()?;
        
        for (func_id, pseudocode) in &output.pseudocode {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO pseudocode (id, function_id, code, language, version, generated_by, created_at, updated_at)
                VALUES (?1, ?2, ?3, 'c', 1, 'decompiler', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                "#,
                params![
                    Uuid::new_v4().as_u128() as i64,
                    func_id.0 as i64,
                    pseudocode,
                ],
            )?;
        }

        for (func_id, variables) in &output.variables {
            for var in variables {
                tx.execute(
                    r#"
                    INSERT OR REPLACE INTO variables (id, function_id, name, type_id, storage, register, stack_offset, size, scope_start, scope_end, is_parameter, is_return, confidence, created_at, updated_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    "#,
                    params![
                        var.id.0 as i64,
                        func_id.0 as i64,
                        var.name,
                        var.type_id.map(|t| t.0 as i64),
                        var.storage.as_str(),
                        var.register,
                        var.stack_offset.map(|o| o as i64),
                        var.size as i64,
                        var.scope_start.map(|s| s as i64),
                        var.scope_end.map(|s| s as i64),
                        var.is_parameter,
                        var.is_return,
                        var.confidence,
                    ],
                )?;
            }
        }

        tx.commit()?;
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    /// Write annotation
    pub async fn write_annotation(&self, annotation: &crate::Annotation) -> Result<()> {
        let conn = self.conn.lock().await;
        let start = std::time::Instant::now();
        
        conn.execute(
            r#"
            INSERT INTO annotations (address, function_id, annotation_type, value, source, created_by, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            "#,
            params![
                annotation.address as i64,
                annotation.function_id.map(|f| f.0 as i64),
                annotation.annotation_type.as_str(),
                annotation.value,
                annotation.source.as_str(),
                annotation.created_by.map(|u| u.to_string()),
            ],
        )?;

        metrics::record_db_query(start.elapsed());
        Ok(())
    }

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