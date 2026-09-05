//! Service connections for the TUI - connects to real backend services

use crate::state::{
    ProjectInfo, JobStatus, ScanStatus, LogLevel, ReportType, REViewMode, WorkflowViewMode,
    AIViewMode, PluginViewMode, ReportViewMode, FindingsGroupBy, ProjectSortBy, REProject,
    FunctionSummary, DisplayFinding, Workflow, WorkflowExecution, AIAnalysis, ChatMessage,
    ChatRole, PluginInfo, LogEntry, ReportInfo, QueueStats, ActiveScanInfo, FindingDetail,
    EvidenceDetail, RemediationDetail,
};
use openre_config::Config;
use openre_core::ids::{ProjectId, ScanId, JobId, FileId};
use openre_core::result::{Finding, Severity, Category, Confidence};
use openre_queue::{Job, JobStatus as QueueJobStatus, Priority, QueueManager, QueueStats as QueueQueueStats};
use openre_storage::{ProjectStore, global::GlobalStore};
use openre_scanner::{ScanManager, ScanSession, ScanProgress};
#[cfg(feature = "intelligence")]
use openre_intelligence::{WorkflowManager, InvestigationWorkflowEngine, KnowledgeBase};
#[cfg(not(feature = "intelligence"))]
mod dummy_intelligence {
    pub struct WorkflowManager;
    pub struct InvestigationWorkflowEngine;
    pub struct KnowledgeBase;
}
#[cfg(not(feature = "intelligence"))]
use dummy_intelligence::{WorkflowManager, InvestigationWorkflowEngine, KnowledgeBase};
use redis::Client as RedisClient;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Service connections for the TUI
pub struct Services {
    pub config: Config,
    pub queue_manager: Option<Arc<QueueManager>>,
    pub redis_client: Option<RedisClient>,
    pub global_store: Option<Arc<GlobalStore>>,
    pub scan_manager: Option<Arc<ScanManager>>,
    #[cfg(feature = "intelligence")]
    pub workflow_manager: Option<Arc<WorkflowManager>>,
    #[cfg(feature = "intelligence")]
    pub workflow_engine: Option<Arc<InvestigationWorkflowEngine>>,
    #[cfg(feature = "intelligence")]
    pub knowledge_base: Option<Arc<KnowledgeBase>>,
    pub project_stores: Arc<RwLock<HashMap<ProjectId, Arc<ProjectStore>>>>,
}

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("Services");
        ds.field("config", &self.config)
            .field("queue_manager", &self.queue_manager.is_some())
            .field("redis_client", &self.redis_client.is_some())
            .field("global_store", &self.global_store.is_some())
            .field("scan_manager", &self.scan_manager.is_some());
        #[cfg(feature = "intelligence")]
        {
            ds.field("workflow_manager", &self.workflow_manager.is_some())
                .field("workflow_engine", &self.workflow_engine.is_some())
                .field("knowledge_base", &self.knowledge_base.is_some());
        }
        ds.field("project_stores", &format_args!("HashMap<ProjectId, Arc<ProjectStore>>"))
            .finish()
    }
}

impl Services {
    /// Create new service connections from config
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        // Try to connect to Redis for queue
        let (redis_client, queue_manager) = Self::connect_queue(&config).await;

        // Try to connect to PostgreSQL for global store (optional)
        let global_store = Self::connect_global_store(&config).await;

        // Create scan manager (requires plugin_manager and storage - not available in TUI)
        let scan_manager = None;

        // Create workflow manager (requires intelligence feature)
        #[cfg(feature = "intelligence")]
        let workflow_manager: Option<Arc<openre_intelligence::WorkflowManager>> = Some(Arc::new(openre_intelligence::WorkflowManager::new()));
        #[cfg(not(feature = "intelligence"))]
        let workflow_manager: Option<Arc<dummy_intelligence::WorkflowManager>> = None;

        // Create workflow engine (requires intelligence feature)
        #[cfg(feature = "intelligence")]
        let workflow_engine: Option<Arc<openre_intelligence::InvestigationWorkflowEngine>> = Some(Arc::new(openre_intelligence::InvestigationWorkflowEngine::new()));
        #[cfg(not(feature = "intelligence"))]
        let workflow_engine: Option<Arc<dummy_intelligence::InvestigationWorkflowEngine>> = None;

        // Create knowledge base (requires intelligence feature)
        #[cfg(feature = "intelligence")]
        let knowledge_base: Option<Arc<openre_intelligence::KnowledgeBase>> = Some(Arc::new(openre_intelligence::KnowledgeBase::new()));
        #[cfg(not(feature = "intelligence"))]
        let knowledge_base: Option<Arc<dummy_intelligence::KnowledgeBase>> = None;

        Ok(Self {
            config,
            queue_manager,
            redis_client,
            global_store,
            scan_manager,
            #[cfg(feature = "intelligence")]
            workflow_manager,
            #[cfg(feature = "intelligence")]
            workflow_engine,
            #[cfg(feature = "intelligence")]
            knowledge_base,
            project_stores: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Connect to Redis queue
    async fn connect_queue(config: &Config) -> (Option<RedisClient>, Option<Arc<QueueManager>>) {
        match RedisClient::open(config.redis.url.as_str()) {
            Ok(client) => {
                // Test connection
                match client.get_multiplexed_async_connection().await {
                    Ok(mut conn) => {
                        match redis::cmd("PING").query_async::<_, ()>(&mut conn).await {
                            Ok(_) => {
                                info!("Connected to Redis at {}", config.redis.url);
                                // Try to create queue manager
                                match QueueManager::new(
                                    config.queue.clone(),
                                    &config.redis,
                                    Arc::new(openre_telemetry::metrics::QueueMetrics::new(
                                        &openre_telemetry::MetricsRegistry::default(),
                                    )),
                                ).await {
                                    Ok(qm) => {
                                        info!("Queue manager initialized");
                                        (Some(client), Some(Arc::new(qm)))
                                    }
                                    Err(e) => {
                                        warn!("Failed to create queue manager: {}", e);
                                        (Some(client), None)
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Redis PING failed: {}", e);
                                (Some(client), None)
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get Redis connection: {}", e);
                        (Some(client), None)
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create Redis client: {}", e);
                (None, None)
            }
        }
    }

    /// Connect to global store (PostgreSQL) - optional
    async fn connect_global_store(config: &Config) -> Option<Arc<GlobalStore>> {
        #[cfg(feature = "postgres")]
        {
            match GlobalStore::new(&config.database).await {
                Ok(store) => {
                    info!("Connected to PostgreSQL database");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    warn!("Failed to connect to PostgreSQL: {}", e);
                    None
                }
            }
        }
        #[cfg(not(feature = "postgres"))]
        {
            None
        }
    }

    /// Get or create project store for a project
    pub async fn get_project_store(&self, project_id: ProjectId) -> anyhow::Result<Arc<ProjectStore>> {
        let mut stores = self.project_stores.write().await;
        if let Some(store) = stores.get(&project_id) {
            return Ok(store.clone());
        }

        let base_path = PathBuf::from(&self.config.storage.local_path);
        let store = Arc::new(ProjectStore::new(project_id, &base_path)?);
        store.ensure_schema().await?;
        stores.insert(project_id, store.clone());
        Ok(store)
    }

    /// Get queue statistics
    pub async fn get_queue_stats(&self) -> anyhow::Result<QueueStats> {
        if let Some(qm) = &self.queue_manager {
            let stats = qm.get_stats().await?;
            return Ok(QueueStats {
                total_queued: stats.total_queued,
                jobs_queued_by_priority: stats.jobs_queued_by_priority,
                jobs_running: stats.jobs_running,
                jobs_scheduled: stats.jobs_scheduled,
                jobs_dlq: stats.jobs_dlq,
                workers_active: 0, // Would need worker pool integration
                workers_idle: 0,
            });
        }
        Ok(QueueStats::default())
    }

    /// Get all jobs from queue
    pub async fn get_jobs(&self) -> anyhow::Result<Vec<Job>> {
        if let Some(_qm) = &self.queue_manager {
            // This would require scanning Redis streams - not directly exposed
            // For now, return empty - would need to extend QueueManager
            // or use the API server
            return Ok(Vec::new());
        }
        Ok(Vec::new())
    }

    /// Get project list from global store or local storage
    pub async fn get_projects(&self) -> anyhow::Result<Vec<ProjectInfo>> {
        // Try global store first (PostgreSQL)
        if let Some(_gs) = &self.global_store {
            // Project listing not yet implemented in GlobalStore
            // Would need to add list_projects method
        }

        // Fallback: scan local storage directory for project databases
        let base_path = PathBuf::from(&self.config.storage.local_path);
        let mut projects = Vec::new();

        if base_path.exists() {
            if let Ok(entries) = std::fs::read_dir(&base_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("db") {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            let project_id = ProjectId::from_uuid(uuid::Uuid::parse_str(stem).unwrap_or_default());
                            // Try to load basic info from the project database
                            if let Ok(store) = ProjectStore::new(project_id, &base_path) {
                                if store.ensure_schema().await.is_ok() {
                                    // Get basic stats
                                    if let Ok(conn) = store.take_conn().await {
                                        let file_count: i64 = conn
                                            .query_row("SELECT COUNT(*) FROM functions", [], |r| r.get(0))
                                            .unwrap_or(0);
                                        let string_count: i64 = conn
                                            .query_row("SELECT COUNT(*) FROM strings", [], |r| r.get(0))
                                            .unwrap_or(0);
                                        let import_count: i64 = conn
                                            .query_row("SELECT COUNT(*) FROM annotations WHERE annotation_type = 'import'", [], |r| r.get(0))
                                            .unwrap_or(0);
                                        let export_count: i64 = conn
                                            .query_row("SELECT COUNT(*) FROM annotations WHERE annotation_type = 'export'", [], |r| r.get(0))
                                            .unwrap_or(0);
                                        store.put_conn(conn).await;

                                        projects.push(ProjectInfo {
                                            id: project_id,
                                            name: stem.to_string(),
                                            path: path.display().to_string(),
                                            created_at: chrono::Utc::now(),
                                            updated_at: chrono::Utc::now(),
                                            file_count: file_count as usize,
                                            scan_count: 0,
                                            finding_count: 0,
                                            is_active: false,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(projects)
    }

    /// Create a new project
    pub async fn create_project(&self, name: String, path: String) -> anyhow::Result<ProjectId> {
        let project_id = ProjectId::new();
        let base_path = PathBuf::from(&self.config.storage.local_path);
        let store = ProjectStore::new(project_id, &base_path)?;
        store.ensure_schema().await?;

        // Store project metadata in global store if available
        if let Some(_gs) = &self.global_store {
            // Would need to add create_project to GlobalStore with proper ProjectRecord
        }

        // Add to local cache
        let mut stores = self.project_stores.write().await;
        stores.insert(project_id, Arc::new(store));

        Ok(project_id)
    }

    /// Delete a project
    pub async fn delete_project(&self, project_id: ProjectId) -> anyhow::Result<()> {
        // Remove from local cache
        let mut stores = self.project_stores.write().await;
        stores.remove(&project_id);

        // Delete from global store if available
        // Would need to add delete_project to GlobalStore

        // Delete local database file
        let base_path = PathBuf::from(&self.config.storage.local_path);
        let db_path = base_path.join(format!("{}.db", project_id));
        if db_path.exists() {
            std::fs::remove_file(db_path)?;
        }

        Ok(())
    }

    /// Get scan history
    pub async fn get_scans(&self) -> anyhow::Result<Vec<crate::state::ScanInfo>> {
        // Would need integration with scan storage
        Ok(Vec::new())
    }

    /// Start a new scan
    pub async fn start_scan(
        &self,
        target: String,
        profile: String,
        project_id: Option<ProjectId>,
    ) -> anyhow::Result<ScanId> {
        if let Some(sm) = &self.scan_manager {
            // Create a scan target
            let target_id = openre_scanner::target::TargetId::new();
            // This would need proper target creation
            return Ok(ScanId::new());
        }
        Ok(ScanId::new())
    }

    /// Get findings for a project/scan
    pub async fn get_findings(
        &self,
        _project_id: Option<ProjectId>,
        _scan_id: Option<ScanId>,
    ) -> anyhow::Result<Vec<DisplayFinding>> {
        // Would need integration with findings storage
        Ok(Vec::new())
    }

    /// Get RE projects (binaries loaded for analysis)
    pub async fn get_re_projects(&self) -> anyhow::Result<Vec<REProject>> {
        let projects = self.get_projects().await?;
        let mut re_projects = Vec::new();

        for project in projects {
            // Check if this project has RE data (functions, etc.)
            if let Ok(store) = self.get_project_store(project.id).await {
                if let Ok(conn) = store.take_conn().await {
                    let func_count: i64 = conn
                        .query_row("SELECT COUNT(*) FROM functions", [], |r| r.get(0))
                        .unwrap_or(0);
                    let string_count: i64 = conn
                        .query_row("SELECT COUNT(*) FROM strings", [], |r| r.get(0))
                        .unwrap_or(0);
                    let import_count: i64 = conn
                        .query_row("SELECT COUNT(*) FROM annotations WHERE annotation_type = 'import'", [], |r| r.get(0))
                        .unwrap_or(0);
                    let export_count: i64 = conn
                        .query_row("SELECT COUNT(*) FROM annotations WHERE annotation_type = 'export'", [], |r| r.get(0))
                        .unwrap_or(0);
                    store.put_conn(conn).await;

                    if func_count > 0 || string_count > 0 {
                        re_projects.push(REProject {
                            id: project.id,
                            name: project.name,
                            binary_path: project.path,
                            architecture: "unknown".to_string(), // Would need to read from metadata
                            functions: func_count as usize,
                            strings: string_count as usize,
                            imports: import_count as usize,
                            exports: export_count as usize,
                            analysis_status: JobStatus::Completed,
                            last_analyzed: Some(chrono::Utc::now()),
                        });
                    }
                }
            }
        }

        Ok(re_projects)
    }

    /// Get functions for an RE project
    pub async fn get_functions(&self, project_id: ProjectId) -> anyhow::Result<Vec<FunctionSummary>> {
        if let Ok(store) = self.get_project_store(project_id).await {
            if let Ok(conn) = store.take_conn().await {
                let mut stmt = conn.prepare(
                    "SELECT id, address, name, size, cyclomatic_complexity, instruction_count, block_count, is_thunk, is_library FROM functions ORDER BY address"
                )?;

                let rows = stmt.query_map([], |row| {
                    Ok(FunctionSummary {
                        address: row.get(1)?,
                        name: row.get(2)?,
                        size: row.get(3)?,
                        complexity: row.get(4)?,
                        instruction_count: row.get(5)?,
                        block_count: row.get(6)?,
                        is_thunk: row.get(7)?,
                        is_library: row.get(8)?,
                    })
                })?;

                let mut functions = Vec::new();
                for row in rows {
                    functions.push(row?);
                }
                // stmt and rows are dropped here, releasing borrows on conn
                drop(stmt);

                store.put_conn(conn).await;
                return Ok(functions);
            }
        }
        Ok(Vec::new())
    }

    /// Get workflows
    #[cfg(feature = "intelligence")]
    pub async fn get_workflows(&self) -> anyhow::Result<Vec<Workflow>> {
        if let Some(wm) = &self.workflow_manager {
            // Would need to add list_workflows to WorkflowManager
        }
        Ok(Vec::new())
    }

    #[cfg(not(feature = "intelligence"))]
    pub async fn get_workflows(&self) -> anyhow::Result<Vec<Workflow>> {
        Ok(Vec::new())
    }

    /// Execute a workflow
    #[cfg(feature = "intelligence")]
    pub async fn execute_workflow(&self, workflow_id: String) -> anyhow::Result<String> {
        if let Some(wm) = &self.workflow_manager {
            // Would need to add execute_workflow to WorkflowManager
        }
        Ok(uuid::Uuid::new_v4().to_string())
    }

    #[cfg(not(feature = "intelligence"))]
    pub async fn execute_workflow(&self, _workflow_id: String) -> anyhow::Result<String> {
        Ok(uuid::Uuid::new_v4().to_string())
    }

    /// Get AI analyses
    pub async fn get_ai_analyses(&self) -> anyhow::Result<Vec<AIAnalysis>> {
        // Would need integration with AI service
        Ok(Vec::new())
    }

    /// Send chat message to AI
    pub async fn send_chat_message(&self, _message: String) -> anyhow::Result<String> {
        // Would need integration with AI service
        Ok("AI response placeholder".to_string())
    }

    /// Get plugins
    pub async fn get_plugins(&self) -> anyhow::Result<Vec<PluginInfo>> {
        // Would need integration with plugin manager
        Ok(Vec::new())
    }

    /// Get logs
    pub async fn get_logs(&self, _limit: usize) -> anyhow::Result<Vec<LogEntry>> {
        // Would need integration with logging system
        Ok(Vec::new())
    }

    /// Get reports
    pub async fn get_reports(&self) -> anyhow::Result<Vec<ReportInfo>> {
        // Would need integration with report storage
        Ok(Vec::new())
    }

    /// Generate a report
    pub async fn generate_report(
        &self,
        _report_type: ReportType,
        _scan_ids: Vec<ScanId>,
        _project_ids: Vec<ProjectId>,
    ) -> anyhow::Result<String> {
        // Would need integration with report generation
        Ok(uuid::Uuid::new_v4().to_string())
    }
}

/// Background data fetcher for the TUI
pub struct DataFetcher {
    services: Arc<Services>,
    event_tx: tokio::sync::broadcast::Sender<crate::events::Event>,
}

impl DataFetcher {
    pub fn new(services: Arc<Services>, event_tx: tokio::sync::broadcast::Sender<crate::events::Event>) -> Self {
        Self { services, event_tx }
    }

    /// Start background data fetching tasks
    pub fn start(&self) {
        self.start_queue_stats_updater();
        self.start_project_refresher();
        self.start_scan_progress_updater();
        self.start_log_aggregator();
    }

    /// Update queue stats periodically
    fn start_queue_stats_updater(&self) {
        let services = self.services.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                interval.tick().await;
                if let Ok(stats) = services.get_queue_stats().await {
                    let _ = event_tx.send(crate::events::Event::QueueStatsUpdated(stats));
                }
            }
        });
    }

    /// Refresh project list periodically
    fn start_project_refresher(&self) {
        let services = self.services.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                if let Ok(projects) = services.get_projects().await {
                    let _ = event_tx.send(crate::events::Event::ProjectsRefreshed(projects));
                }
            }
        });
    }

    /// Update scan progress
    fn start_scan_progress_updater(&self) {
        let _event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                interval.tick().await;
                // Active scan progress would come from scan manager
                // For now, we'll just check if there's an active scan in state
            }
        });
    }

    /// Aggregate logs from various sources
    fn start_log_aggregator(&self) {
        let _event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                // In a real implementation, this would collect logs from:
                // - Queue manager
                // - Scan manager
                // - Storage operations
                // - API server
                // For now, we don't generate fake logs
            }
        });
    }
}
