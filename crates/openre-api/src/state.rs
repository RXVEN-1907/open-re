//! Application state for open-re API

use crate::{ApiError, ApiResult, AuthService};
use governor::{Quota, RateLimiter};
use openre_config::Config;
use openre_core::plugin::PluginRegistry;
use openre_core::plugin::RegistryConfig;
use openre_queue::{CancellationManager, ProgressTracker, QueueManager, Scheduler, metrics::QueueMetrics};
use openre_scanner::storage::{MemoryScanStorage, ScanStorage, SqliteScanStorage};
use openre_storage::{GlobalStore, ObjectStore};
use openre_telemetry::TelemetryHandle;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[cfg(feature = "ai")]
use openre_ai::AiService;
#[cfg(feature = "ai")]
use openre_security_ai::{
    FindingProvider, ScanStorageFindingProvider, SecurityAnalyst, SecurityAnalystImpl,
};

/// Telemetry bundle shared across handlers
pub struct Telemetry {
    pub _handle: TelemetryHandle,
}

impl Telemetry {
    pub fn new(_config: &openre_config::TelemetryConfig) -> ApiResult<Self> {
        Ok(Self { _handle: TelemetryHandle })
    }
}

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub global_store: Arc<GlobalStore>,
    pub object_store: Arc<ObjectStore>,
    pub queue_manager: Arc<QueueManager>,
    pub progress_tracker: Arc<ProgressTracker>,
    pub cancellation_manager: Arc<CancellationManager>,
    pub scheduler: Arc<Scheduler>,
    #[cfg(feature = "ai")]
    pub ai_service: Arc<AiService>,
    #[cfg(feature = "ai")]
    pub analyst: Option<Arc<dyn SecurityAnalyst>>, // AI Security Analyst service
    pub plugin_registry: Arc<PluginRegistry>,
    pub auth_service: Arc<AuthService>,
    pub telemetry: Arc<Telemetry>,
    pub rate_limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
    pub scan_storage: Arc<dyn ScanStorage>,
}

impl AppState {
    /// Create new application state
    pub async fn new(config: Config) -> ApiResult<Self> {
        // Initialize telemetry
        let telemetry = Arc::new(Telemetry::new(&config.telemetry)?);

        // Initialize stores
        let global_store = Arc::new(GlobalStore::new(&config.database).await?);
        let object_store = Arc::new(ObjectStore::new(&config.storage).await?);

        // Initialize queue system
        let client = redis::Client::open(config.redis.url.as_str())
            .map_err(|e| ApiError::Internal(format!("Redis init failed: {}", e)))?;
        let queue_metrics = Arc::new(openre_queue::metrics::QueueMetrics::new());
        let queue_manager =
            Arc::new(QueueManager::new(config.queue.clone(), &config.redis, queue_metrics).await?);

        let progress_tracker = Arc::new(ProgressTracker::new(
            client.clone(),
            Arc::new(openre_queue::metrics::ProgressMetrics::new()),
        ));

        let cancellation_manager = Arc::new(CancellationManager::new(
            queue_manager.clone(),
            client.clone(),
            Arc::new(openre_queue::metrics::CancellationMetrics::new()),
        ));

        let scheduler = Arc::new(Scheduler::new(
            queue_manager.clone(),
            client.clone(),
            Arc::new(openre_queue::metrics::SchedulerMetrics::new()),
        ));

        // Load scheduled jobs from Redis
        scheduler.load_from_redis().await?;

        // Start background tasks
        queue_manager.start_maintenance().await;
        progress_tracker.start_cleanup().await;
        scheduler.start().await;

        // Initialize plugin registry
        let plugin_registry = Arc::new(PluginRegistry::new(RegistryConfig::default())?);

        // Initialize auth service
        let auth_service = Arc::new(AuthService::new(crate::auth::AuthConfig::default()));

        // Initialize rate limiter
        let rps = 100; // default global RPS; per-config tuning pending
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        // Initialize scan storage
        let scan_storage: Arc<dyn ScanStorage> = if config.database.url.starts_with("sqlite") {
            match SqliteScanStorage::new(&config.database.url).await {
                Ok(storage) => Arc::new(storage) as Arc<dyn ScanStorage>,
                Err(e) => return Err(ApiError::Internal(e.to_string())),
            }
        } else {
            Arc::new(MemoryScanStorage::new())
        };

        // Initialize AI service and analyst (only with ai feature)
        #[cfg(feature = "ai")]
        let (ai_service, analyst) = {
            let ai_service = Arc::new(
                AiService::new(config.ai.clone(), global_store.clone(), object_store.clone()).await?,
            );
            let analyst = ai_service
                .list_provider_ids()
                .first()
                .and_then(|provider_id| ai_service.get_provider_arc(provider_id))
                .map(|provider| {
                    let finding_provider =
                        Arc::new(ScanStorageFindingProvider::new(scan_storage.clone()));
                    let analyst_impl = SecurityAnalystImpl::new(finding_provider, provider, 4096);
                    Arc::new(analyst_impl) as Arc<dyn SecurityAnalyst>
                });
            (ai_service, analyst)
        };

        #[cfg(not(feature = "ai"))]
        let (ai_service, analyst) = (std::sync::Arc::new(()), None);

        Ok(Self {
            config: Arc::new(config),
            global_store,
            object_store,
            queue_manager,
            progress_tracker,
            cancellation_manager,
            scheduler,
            #[cfg(feature = "ai")]
            ai_service,
            #[cfg(feature = "ai")]
            analyst,
            plugin_registry,
            auth_service,
            telemetry,
            rate_limiter,
            scan_storage,
        })
    }

    /// Get project store for a project
    pub async fn get_project_store(
        &self,
        project_id: openre_core::ids::ProjectId,
    ) -> ApiResult<Arc<openre_storage::ProjectStore>> {
        Ok(Arc::new(
            openre_storage::ProjectStore::new(project_id, self.config.storage.local_path.as_path())
                .map_err(|e| ApiError::Internal(e.to_string()))?,
        ))
    }

    /// Health check
    pub async fn health_check(&self) -> ApiResult<()> {
        self.global_store.health_check().await?;
        self.queue_manager.health_check().await?;
        Ok(())
    }

    /// Shutdown gracefully
    pub async fn shutdown(&self) -> ApiResult<()> {
        // Stop accepting new requests
        // Wait for in-flight requests
        // Close connections
        Ok(())
    }
}

// Bridge implementations: Implement openre_ai traits for openre_storage types
// This bridges the gap since openre-storage can't depend on openre-ai (circular dependency)
#[cfg(feature = "ai")]
mod ai_bridge {
    use super::*;
    use openre_ai::tools::{GlobalStore as AiGlobalStore, ObjectStore as AiObjectStore, ProjectStore as AiProjectStore};
    use openre_storage::{GlobalStore as StorageGlobalStore, ObjectStore as StorageObjectStore, ProjectStore as StorageProjectStore};
    use openre_ai::tools::{FunctionId, BlockId, FunctionInfo, BasicBlockInfo, InstructionInfo, StringInfo, SymbolInfo, XrefInfo, SearchResult, FileId};
    use openre_core::error::OpenreResult as Result;
    use std::sync::Arc;

    // Implement openre_ai::GlobalStore for openre_storage::GlobalStore
    #[async_trait::async_trait]
    impl AiGlobalStore for StorageGlobalStore {}

    // Implement openre_ai::ObjectStore for openre_storage::ObjectStore
    #[async_trait::async_trait]
    impl AiObjectStore for StorageObjectStore {
        async fn read_file(&self, file_id: FileId, offset: u64, length: u64) -> Result<Vec<u8>> {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            let mut file = self.get_object(file_id).await?;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; length as usize];
            let n = file.read(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
        }
    }

    // Implement openre_ai::ProjectStore for openre_storage::ProjectStore
    #[async_trait::async_trait]
    impl AiProjectStore for StorageProjectStore {
        async fn get_function(&self, function_id: FunctionId) -> Result<Option<FunctionInfo>> {
            self.with_connection(|conn| {
                let row = conn.query_row(
                    "SELECT address, name, demangled_name, size, calling_convention, return_type, is_thunk, is_library, is_entry, cyclomatic_complexity, instruction_count, block_count FROM functions WHERE id = ?",
                    [function_id.0.to_string()],
                    |row| {
                        Ok(FunctionInfo {
                            id: function_id,
                            address: row.get(0)?,
                            name: row.get(1)?,
                            demangled_name: row.get(2)?,
                            size: row.get(3)?,
                            calling_convention: row.get(4)?,
                            return_type: row.get(5)?,
                            is_thunk: row.get(6)?,
                            is_library: row.get(7)?,
                            is_entry: row.get(8)?,
                            cyclomatic_complexity: row.get(9)?,
                            instruction_count: row.get(10)?,
                            block_count: row.get(11)?,
                        })
                    },
                )?;
                Ok(Some(row))
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_basic_blocks(&self, function_id: FunctionId) -> Result<Vec<BasicBlockInfo>> {
            self.with_connection(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, function_id, start_address, end_address, size, instruction_count, loop_depth, is_entry, is_exit FROM basic_blocks WHERE function_id = ?"
                )?;
                let rows = stmt.query_map([function_id.0.to_string()], |row| {
                    Ok(BasicBlockInfo {
                        id: BlockId::from_uuid(uuid::Uuid::from_slice(&row.get::<_, Vec<u8>>(0)?)?),
                        function_id,
                        start_address: row.get(2)?,
                        end_address: row.get(3)?,
                        size: row.get(4)?,
                        instruction_count: row.get(5)?,
                        loop_depth: row.get(6)?,
                        is_entry: row.get(7)?,
                        is_exit: row.get(8)?,
                        instructions: vec![],
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_instructions(&self, block_id: BlockId) -> Result<Vec<InstructionInfo>> {
            self.with_connection(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, block_id, address, bytes, mnemonic, operands, operand_types, groups, size, stack_change FROM instructions WHERE block_id = ?"
                )?;
                let rows = stmt.query_map([block_id.0.to_string()], |row| {
                    Ok(InstructionInfo {
                        id: row.get(0)?,
                        block_id,
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
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_cfg(&self, function_id: FunctionId) -> Result<serde_json::Value> {
            self.with_connection(|conn| {
                let row = conn.query_row(
                    "SELECT cfg_json FROM functions WHERE id = ?",
                    [function_id.0.to_string()],
                    |row| row.get::<_, String>(0),
                )?;
                serde_json::from_str(&row).map_err(|e| openre_core::Error::Database(e.to_string()))
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_pseudocode(&self, function_id: FunctionId) -> Result<Option<String>> {
            self.with_connection(|conn| {
                let row: Option<String> = conn.query_row(
                    "SELECT pseudocode FROM functions WHERE id = ?",
                    [function_id.0.to_string()],
                    |row| row.get(0),
                ).optional()?;
                Ok(row)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_xrefs_to_address(&self, address: u64) -> Result<Vec<XrefInfo>> {
            self.with_connection(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT from_address, to_address, is_to, type FROM xrefs WHERE to_address = ?"
                )?;
                let rows = stmt.query_map([address], |row| {
                    Ok(XrefInfo {
                        from_address: row.get(0)?,
                        to_address: row.get(1)?,
                        is_to: row.get(2)?,
                        xref_type: row.get(3)?,
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_xrefs_to_function(&self, function_id: FunctionId) -> Result<Vec<XrefInfo>> {
            self.with_connection(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT from_address, to_address, is_to, type FROM xrefs WHERE to_address = (SELECT address FROM functions WHERE id = ?)"
                )?;
                let rows = stmt.query_map([function_id.0.to_string()], |row| {
                    Ok(XrefInfo {
                        from_address: row.get(0)?,
                        to_address: row.get(1)?,
                        is_to: row.get(2)?,
                        xref_type: row.get(3)?,
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_strings(&self, min_length: usize, encoding: &str, address: Option<u64>) -> Result<Vec<StringInfo>> {
            self.with_connection(|conn| {
                let mut query = "SELECT address, value, length, encoding, string_type FROM strings WHERE length >= ? AND encoding = ?".to_string();
                let mut params: Vec<&dyn rusqlite::ToSql> = vec![&min_length, &encoding];
                if let Some(addr) = address {
                    query.push_str(" AND address = ?");
                    params.push(&addr);
                }
                let mut stmt = conn.prepare(&query)?;
                let rows = stmt.query_map(params.as_slice(), |row| {
                    Ok(StringInfo {
                        address: row.get(0)?,
                        value: row.get(1)?,
                        length: row.get(2)?,
                        encoding: row.get(3)?,
                        string_type: row.get(4)?,
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn get_symbols(&self, symbol_type: &str, name_pattern: Option<&str>) -> Result<Vec<SymbolInfo>> {
            self.with_connection(|conn| {
                let mut query = "SELECT address, name, symbol_type, size, is_export FROM symbols WHERE symbol_type = ?".to_string();
                let mut params: Vec<&dyn rusqlite::ToSql> = vec![&symbol_type];
                if let Some(pattern) = name_pattern {
                    query.push_str(" AND name LIKE ?");
                    params.push(&format!("%{}%", pattern));
                }
                let mut stmt = conn.prepare(&query)?;
                let rows = stmt.query_map(params.as_slice(), |row| {
                    Ok(SymbolInfo {
                        address: row.get(0)?,
                        name: row.get(1)?,
                        symbol_type: row.get(2)?,
                        size: row.get(3)?,
                        is_export: row.get(4)?,
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn search(&self, query: &str, search_type: &str, limit: usize) -> Result<Vec<SearchResult>> {
            self.with_connection(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT address, context, match_type FROM search_index WHERE content MATCH ? AND type = ? LIMIT ?"
                )?;
                let rows = stmt.query_map([query, search_type, limit], |row| {
                    Ok(SearchResult {
                        address: row.get(0)?,
                        context: row.get(1)?,
                        match_type: row.get(2)?,
                    })
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn add_function_annotation(&self, function_id: FunctionId, annotation_type: &str, content: &str, confidence: f32) -> Result<()> {
            self.with_connection(|conn| {
                conn.execute(
                    "INSERT INTO annotations (function_id, annotation_type, content, confidence, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    [function_id.0.to_string(), annotation_type, content, confidence.to_string()],
                )?;
                Ok(())
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn add_instruction_annotation(&self, instruction_id: u64, annotation_type: &str, content: &str, confidence: f32) -> Result<()> {
            self.with_connection(|conn| {
                conn.execute(
                    "INSERT INTO annotations (instruction_id, annotation_type, content, confidence, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    [instruction_id.to_string(), annotation_type, content, confidence.to_string()],
                )?;
                Ok(())
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn add_variable_annotation(&self, variable_id: u64, annotation_type: &str, content: &str, confidence: f32) -> Result<()> {
            self.with_connection(|conn| {
                conn.execute(
                    "INSERT INTO annotations (variable_id, annotation_type, content, confidence, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    [variable_id.to_string(), annotation_type, content, confidence.to_string()],
                )?;
                Ok(())
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn add_address_annotation(&self, address: u64, annotation_type: &str, content: &str, confidence: f32) -> Result<()> {
            self.with_connection(|conn| {
                conn.execute(
                    "INSERT INTO annotations (address, annotation_type, content, confidence, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    [address.to_string(), annotation_type, content, confidence.to_string()],
                )?;
                Ok(())
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }

        async fn execute_query(&self, query: &str, params: &[serde_json::Value]) -> Result<Vec<serde_json::Value>> {
            self.with_connection(|conn| {
                // For security, only allow SELECT queries
                if !query.trim().to_uppercase().starts_with("SELECT") {
                    return Err(openre_core::Error::InvalidInput("Only SELECT queries are allowed".into()));
                }
                let mut stmt = conn.prepare(query)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|v| {
                    match v {
                        serde_json::Value::String(s) => s.as_str() as &dyn rusqlite::ToSql,
                        serde_json::Value::Number(n) => n.to_string().as_str() as &dyn rusqlite::ToSql,
                        serde_json::Value::Bool(b) => b as &dyn rusqlite::ToSql,
                        _ => "NULL" as &dyn rusqlite::ToSql,
                    }
                }).collect();
                let rows = stmt.query_map(&param_refs[..], |row| {
                    let cols = row.column_names();
                    let mut obj = serde_json::Map::new();
                    for (i, col) in cols.iter().enumerate() {
                        let val: serde_json::Value = match row.get_ref(i).unwrap() {
                            rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                            rusqlite::types::ValueRef::Integer(i) => serde_json::Value::Number(i.into()),
                            rusqlite::types::ValueRef::Real(f) => serde_json::Value::Number(serde_json::Number::from_f64(f).unwrap()),
                            rusqlite::types::ValueRef::Text(s) => serde_json::Value::String(String::from_utf8_lossy(s).to_string()),
                            rusqlite::types::ValueRef::Blob(b) => serde_json::Value::String(base64::prelude::BASE64_STANDARD.encode(b)),
                        };
                        obj.insert(col.to_string(), val);
                    }
                    Ok(serde_json::Value::Object(obj))
                })?;
                let mut results = Vec::new();
                for row in rows {
                    results.push(row?);
                }
                Ok(results)
            }).await.map_err(|e| openre_core::Error::Database(e.to_string()))
        }
    }
}

// Helper for optional query_row
trait OptionalQueryRow {
    type Item;
    fn optional(self) -> Result<Option<Self::Item>, rusqlite::Error>;
}

impl<T> OptionalQueryRow for Result<T, rusqlite::Error> {
    type Item = T;
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
