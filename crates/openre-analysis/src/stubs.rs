//! Stub types to make openre-analysis compile standalone

use openre_core::ids::{ProjectId, FileId, JobId, StageId, WorkerId, UserId};
use openre_core::error::OpenreResult as Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::info;

/// Stub for ProjectStore
#[derive(Debug, Clone, Default)]
pub struct ProjectStore;

impl ProjectStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    pub async fn write_identification(&self, _output: &crate::orchestrator::IdentificationOutput) -> Result<()> {
        Ok(())
    }

    pub async fn finalize(&self, _project_id: openre_core::ids::ProjectId) -> Result<()> {
        Ok(())
    }
}

/// Stub for ObjectStore
#[derive(Debug, Clone, Default)]
pub struct ObjectStore;

impl ObjectStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

/// Stub for QueueManager
#[derive(Debug, Clone, Default)]
pub struct QueueManager;

impl QueueManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    pub async fn enqueue(&self, _job: crate::orchestrator::AnalysisJob) -> Result<()> {
        Ok(())
    }
}

/// Stub types for orchestrator
#[derive(Debug, Clone, Default)]
pub struct FunctionInfo;
#[derive(Debug, Clone, Default)]
pub struct BasicBlockInfo;
#[derive(Debug, Clone, Default)]
pub struct InstructionInfo;
#[derive(Debug, Clone, Default)]
pub struct CfgEdgeInfo;
#[derive(Debug, Clone, Default)]
pub struct CallEdgeInfo;
#[derive(Debug, Clone, Default)]
pub struct LoopInfo;
#[derive(Debug, Clone, Default)]
pub struct VariableInfo;
#[derive(Debug, Clone, Default)]
pub struct TypeInfo;
#[derive(Debug, Clone, Default)]
pub struct AnnotationInfo;
#[derive(Debug, Clone, Default)]
pub struct StringInfo;
#[derive(Debug, Clone, Default)]
pub struct ConstantInfo;
#[derive(Debug, Clone, Default)]
pub struct AnalysisStatistics;
#[derive(Debug, Clone, Default)]
pub struct FunctionId;

/// Stub for TelemetryHandle
#[derive(Debug, Clone, Default)]
pub struct TelemetryHandle;

impl TelemetryHandle {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    pub fn record_stage_start(&self, _stage: &str) {}
    pub fn record_stage_end(&self, _stage: &str, _duration: Duration) {}
    pub fn record_error(&self, _error: &str) {}
}

/// Stub for AiService
#[async_trait]
pub trait AiService: Send + Sync {
    async fn analyze(&self, _prompt: &str) -> Result<String> {
        Ok("AI analysis not available".to_string())
    }
}

#[derive(Debug, Clone, Default)]
pub struct NoopAiService;

#[async_trait]
impl AiService for NoopAiService {}

/// Cancellation token
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<RwLock<bool>>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(RwLock::new(false)),
        }
    }

    pub fn cancel(&self) {
        let mut cancelled = self.cancelled.write().await;
        *cancelled = true;
    }

    pub async fn is_cancelled(&self) -> bool {
        *self.cancelled.read().await
    }
}

/// Analysis job (local definition)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJob {
    pub id: JobId,
    pub project_id: ProjectId,
    pub file_id: FileId,
    pub priority: i32,
    pub config: AnalysisConfig,
    pub created_at: DateTime<Utc>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub idempotency_key: Option<String>,
    pub tags: Vec<String>,
    pub timeout_secs: u64,
    pub created_by: UserId,
}

/// Analysis config
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisConfig {
    pub stages: Vec<StageId>,
    pub incremental: bool,
    pub timeout_secs: u64,
}

/// Stage result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage_id: StageId,
    pub status: StageStatus,
    pub output: serde_json::Value,
    pub duration_ms: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub error: Option<String>,
}

/// Stage status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

/// Pipeline context
#[derive(Clone)]
pub struct PipelineContext {
    pub job: AnalysisJob,
    pub binary: IsolatedBinary,
    pub project_store: Arc<ProjectStore>,
    pub plugin_registry: Arc<PluginRegistry>,
    pub ai_service: Arc<dyn AiService>,
    pub previous_results: HashMap<StageId, StageResult>,
    pub cancellation: CancellationToken,
    pub telemetry: Arc<TelemetryHandle>,
    pub worker_id: WorkerId,
}

/// Isolated binary (placeholder)
#[derive(Debug, Clone, Copy, Default)]
pub struct IsolatedBinary;

/// Plugin registry (placeholder)
#[derive(Debug, Clone, Default)]
pub struct PluginRegistry;

/// Pipeline stage trait
#[async_trait]
pub trait PipelineStage: Send + Sync {
    fn id(&self) -> StageId;
    fn name(&self) -> &str;
    fn dependencies(&self) -> Vec<StageId>;
    async fn execute(&self, ctx: &PipelineContext) -> Result<StageResult>;
}