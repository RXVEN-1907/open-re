//! Project storage (SQLite) for open-re

use base64::engine::Engine;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use openre_telemetry::metrics;
use rusqlite::{params, params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Project store for SQLite operations
///
/// Uses Arc<Mutex<Option<Connection>>> for thread safety. The Connection itself is not Send/Sync
/// due to internal RefCell and raw pointers. We use Option<Connection> inside Mutex so that
/// the Mutex contains an Option (which is Send/Sync) rather than the Connection directly.
/// The connection is taken out of the Option when in use and put back when done.
pub struct ProjectStore {
    #[allow(dead_code)]
    db_path: PathBuf,
    conn: Arc<Mutex<Option<Connection>>>,
}

impl ProjectStore {
    /// Create a new project store
    pub fn new(project_id: ProjectId, base_path: &Path) -> Result<Self> {
        let db_path = base_path.join(format!("{}.db", project_id));

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;

        // Enable WAL mode for better concurrency
        // Use prepare+query for PRAGMAs that may return rows in rusqlite 0.31+
        let _ = conn.prepare("PRAGMA journal_mode=WAL")?.query([])?;
        let _ = conn.prepare("PRAGMA synchronous=NORMAL")?.query([])?;
        let _ = conn.prepare("PRAGMA foreign_keys=ON")?.query([])?;
        let _ = conn.prepare("PRAGMA cache_size=-100000")?.query([])?; // 100MB cache
        let _ = conn.prepare("PRAGMA mmap_size=268435456")?.query([])?; // 256MB mmap
        let _ = conn.prepare("PRAGMA temp_store=MEMORY")?.query([])?;
        let _ = conn.prepare("PRAGMA busy_timeout=30000")?.query([])?;

        let store = Self {
            db_path,
            conn: Arc::new(Mutex::new(Some(conn))),
        };

        Ok(store)
    }

    /// Take the connection from the mutex for use
    async fn take_conn(&self) -> Result<Connection> {
        let mut guard = self.conn.lock().await;
        guard.take().ok_or_else(|| {
            openre_core::Error::Internal(anyhow::anyhow!("Connection already in use"))
        })
    }

    /// Put the connection back into the mutex
    async fn put_conn(&self, conn: Connection) {
        let mut guard = self.conn.lock().await;
        *guard = Some(conn);
    }

    /// Ensure schema exists
    pub async fn ensure_schema(&self) -> Result<()> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");
        Self::create_schema(conn)?;
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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_address ON functions(address)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_basic_blocks_function ON basic_blocks(function_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_basic_blocks_address ON basic_blocks(start_address)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_instructions_block ON instructions(block_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_instructions_address ON instructions(address)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_instructions_mnemonic ON instructions(mnemonic)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cfg_edges_from ON cfg_edges(from_block_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cfg_edges_to ON cfg_edges(to_block_id)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_call_edges_from ON call_edges(from_function_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_call_edges_to ON call_edges(to_function_id)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_loops_function ON loops(function_id)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_variables_function ON variables(function_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_variables_name ON variables(name)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_types_name ON types(name)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_types_kind ON types(kind)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pseudocode_function ON pseudocode(function_id)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_annotations_address ON annotations(address)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_annotations_function ON annotations(function_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_annotations_type ON annotations(annotation_type)",
            [],
        )?;

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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_strings_address ON strings(address)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(value)",
            [],
        )?;
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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_constants_address ON constants(address)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_constants_value ON constants(value)",
            [],
        )?;

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
    pub async fn query(
        &self,
        sql: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");
        let start = std::time::Instant::now();

        let mut stmt = conn.prepare(sql)?;
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let param_refs: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
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
            rusqlite::types::Value::Integer(i) => {
                serde_json::Value::Number(serde_json::Number::from(i))
            }
            rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
            rusqlite::types::Value::Blob(b) => {
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b))
            }
        }
    }

    /// Write identification output
    pub async fn write_identification(
        &self,
        output: &openre_core::traits::IdentificationOutput,
    ) -> Result<()> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");
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
    pub async fn finalize(&self, _project_id: ProjectId) -> Result<()> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");
        let start = std::time::Instant::now();

        // Update statistics
        let total_functions: i64 =
            conn.query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))?;
        let total_instructions: i64 =
            conn.query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))?;
        let total_basic_blocks: i64 =
            conn.query_row("SELECT COUNT(*) FROM basic_blocks", [], |row| row.get(0))?;
        let total_strings: i64 =
            conn.query_row("SELECT COUNT(*) FROM strings", [], |row| row.get(0))?;

        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_functions'", params![total_functions.to_string()])?;
        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_instructions'", params![total_instructions.to_string()])?;
        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_basic_blocks'", params![total_basic_blocks.to_string()])?;
        conn.execute("UPDATE statistics SET value = ?1, updated_at = CURRENT_TIMESTAMP WHERE key = 'total_strings'", params![total_strings.to_string()])?;

        // Run ANALYZE for query planner
        conn.execute("ANALYZE", [])?;

        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    /// Get a function by its ID
    pub async fn get_function(&self, function_id: FunctionId) -> Result<Option<FunctionInfo>> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");
        let start = std::time::Instant::now();

        let mut stmt = conn.prepare(
            "SELECT id, address, name, demangled_name, size, calling_convention, return_type, is_thunk, is_library, is_entry, cyclomatic_complexity, instruction_count, block_count FROM functions WHERE id = ?1"
        )?;

        let result = stmt.query_row(params![function_id.0], |row| {
            Ok(FunctionInfo {
                id: FunctionId(row.get(0)?),
                address: row.get(1)?,
                name: row.get(2)?,
                demangled_name: row.get(3)?,
                size: row.get(4)?,
                calling_convention: row.get(5)?,
                return_type: row.get(6)?,
                is_thunk: row.get(7)?,
                is_library: row.get(8)?,
                is_entry: row.get(9)?,
                cyclomatic_complexity: row.get(10)?,
                instruction_count: row.get(11)?,
                block_count: row.get(12)?,
            })
        });

        metrics::record_db_query(start.elapsed());
        match result {
            Ok(func) => Ok(Some(func)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get basic blocks for a function
    pub async fn get_basic_blocks(&self, function_id: FunctionId) -> Result<Vec<BasicBlockInfo>> {
        let conn = self.take_conn().await?;
        let start = std::time::Instant::now();

        let mut blocks = {
            let mut stmt = conn.prepare(
                "SELECT id, function_id, start_address, end_address, size, instruction_count, loop_depth, is_entry, is_exit FROM basic_blocks WHERE function_id = ?1 ORDER BY start_address"
            )?;

            let rows = stmt.query_map(params![function_id.0], |row| {
                Ok(BasicBlockInfo {
                    id: BlockId::from_uuid(row.get(0)?),
                    function_id: FunctionId(row.get(1)?),
                    start_address: row.get(2)?,
                    end_address: row.get(3)?,
                    size: row.get(4)?,
                    instruction_count: row.get(5)?,
                    loop_depth: row.get(6)?,
                    is_entry: row.get(7)?,
                    is_exit: row.get(8)?,
                    instructions: Vec::new(), // Instructions loaded separately if needed
                })
            })?;

            let mut blocks = Vec::new();
            for row in rows {
                blocks.push(row?);
            }
            blocks
        }; // stmt is dropped here

        // Load instructions for each block
        for block in &mut blocks {
            block.instructions = self.get_instructions_for_block(block.id).await?;
        }

        self.put_conn(conn).await;
        metrics::record_db_query(start.elapsed());
        Ok(blocks)
    }

    /// Get instructions for a basic block
    async fn get_instructions_for_block(&self, block_id: BlockId) -> Result<Vec<InstructionInfo>> {
        let conn = self.take_conn().await?;

        let instructions = {
            let mut stmt = conn.prepare(
                "SELECT id, block_id, address, bytes, mnemonic, operands, operand_types, groups, size, stack_change FROM instructions WHERE block_id = ?1 ORDER BY address"
            )?;

            let rows = stmt.query_map(params![block_id.0], |row| {
                Ok(InstructionInfo {
                    id: row.get(0)?,
                    block_id: BlockId::from_uuid(row.get(1)?),
                    address: row.get(2)?,
                    bytes: row.get(3)?,
                    mnemonic: row.get(4)?,
                    operands: row.get(5)?,
                    operand_types: row.get(6)?,
                    groups: row.get(7)?,
                    size: row.get(8)?,
                    stack_change: row.get(9)?,
                })
            })?;

            let mut instructions = Vec::new();
            for row in rows {
                instructions.push(row?);
            }
            instructions
        }; // stmt is dropped here

        self.put_conn(conn).await;
        Ok(instructions)
    }

    /// Get pseudocode for a function
    pub async fn get_pseudocode(&self, function_id: FunctionId) -> Result<Option<String>> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().expect("Connection not available");
        let start = std::time::Instant::now();

        let mut stmt = conn.prepare(
            "SELECT code FROM pseudocode WHERE function_id = ?1 ORDER BY version DESC LIMIT 1",
        )?;

        let result = stmt.query_row(params![function_id.0], |row| row.get(0));

        metrics::record_db_query(start.elapsed());
        match result {
            Ok(code) => Ok(Some(code)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // Stub methods for AI tools - to be implemented when storage layer is fully developed
    pub async fn add_function_annotation(
        &self,
        _function_id: FunctionId,
        _annotation_type: &str,
        _content: &str,
        _confidence: f32,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn add_instruction_annotation(
        &self,
        _instruction_id: u64,
        _annotation_type: &str,
        _content: &str,
        _confidence: f32,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn add_variable_annotation(
        &self,
        _variable_id: u64,
        _annotation_type: &str,
        _content: &str,
        _confidence: f32,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn add_address_annotation(
        &self,
        _address: u64,
        _annotation_type: &str,
        _content: &str,
        _confidence: f32,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn execute_query(
        &self,
        _query: &str,
        _params: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Value>> {
        Ok(Vec::new())
    }

    pub async fn get_instructions(&self, _block_id: BlockId) -> Result<Vec<InstructionInfo>> {
        Ok(Vec::new())
    }

    pub async fn get_cfg(&self, _function_id: FunctionId) -> Result<serde_json::Value> {
        Ok(serde_json::json!({}))
    }

    pub async fn get_xrefs_to_address(&self, _address: u64) -> Result<Vec<crate::XrefInfo>> {
        Ok(Vec::new())
    }

    pub async fn get_xrefs_to_function(
        &self,
        _function_id: FunctionId,
    ) -> Result<Vec<crate::XrefInfo>> {
        Ok(Vec::new())
    }

    pub async fn get_strings(
        &self,
        _min_length: usize,
        _encoding: &str,
        _address: Option<u64>,
    ) -> Result<Vec<crate::StringInfo>> {
        Ok(Vec::new())
    }

    pub async fn get_symbols(
        &self,
        _symbol_type: &str,
        _name_pattern: Option<&str>,
    ) -> Result<Vec<crate::SymbolInfo>> {
        Ok(Vec::new())
    }

    pub async fn search(
        &self,
        _query: &str,
        _search_type: &str,
        _limit: usize,
    ) -> Result<Vec<crate::SearchResult>> {
        Ok(Vec::new())
    }
}

/// Symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub address: u64,
    pub name: String,
    pub symbol_type: String,
    pub size: u32,
    pub is_export: bool,
}

/// Cross-reference information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefInfo {
    pub from_address: u64,
    pub to_address: u64,
    pub is_to: bool,
    pub xref_type: String,
}

/// Search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub address: u64,
    pub context: String,
    pub match_type: String,
}

/// String information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringInfo {
    pub address: u64,
    pub value: String,
    pub length: u32,
    pub encoding: String,
    pub string_type: String,
}

/// Function information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub id: FunctionId,
    pub address: u64,
    pub name: Option<String>,
    pub demangled_name: Option<String>,
    pub size: u32,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    pub is_thunk: bool,
    pub is_library: bool,
    pub is_entry: bool,
    pub cyclomatic_complexity: Option<u32>,
    pub instruction_count: Option<u32>,
    pub block_count: Option<u32>,
}

/// Basic block information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlockInfo {
    pub id: BlockId,
    pub function_id: FunctionId,
    pub start_address: u64,
    pub end_address: u64,
    pub size: u32,
    pub instruction_count: Option<u32>,
    pub loop_depth: u32,
    pub is_entry: bool,
    pub is_exit: bool,
    pub instructions: Vec<InstructionInfo>,
}

/// Instruction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    pub id: i64,
    pub block_id: BlockId,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Option<String>,
    pub operand_types: Option<String>,
    pub groups: Option<String>,
    pub size: u32,
    pub stack_change: i32,
}
