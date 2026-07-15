//! Pipeline orchestrator for open-re

use crate::{stages::*, incremental::*, progress::*, metrics::*};
use openre_config::QueueConfig;
use openre_core::error::Result;
use openre_core::ids::*;
use openre_plugins::PluginRegistry;
use openre_queue::QueueManager;
use openre_storage::{GlobalStore, ProjectStore};
use openre_telemetry::{metrics, TelemetryHandle};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, warn, error};

/// Pipeline context passed to stages
#[derive(Clone)]
pub struct PipelineContext {
    pub job: AnalysisJob,
    pub binary: IsolatedBinary,
    pub project_store: Arc<ProjectStore>,
    pub plugin_registry: Arc<PluginRegistry>,
    pub ai_service: Arc<dyn AiService>,
    pub previous_results: HashMap<StageId, StageResult>,
    pub cancellation: CancellationToken,
    pub telemetry: TelemetryHandle,
    pub worker_id: WorkerId,
}

/// Analysis job
#[derive(Debug, Clone)]
pub struct AnalysisJob {
    pub id: JobId,
    pub project_id: ProjectId,
    pub file_id: FileId,
    pub priority: i32,
    pub config: AnalysisConfig,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub idempotency_key: Option<String>,
    pub tags: Vec<String>,
    pub timeout_secs: u64,
    pub created_by: UserId,
}

impl AnalysisJob {
    pub fn new(
        project_id: ProjectId,
        file_id: FileId,
        config: AnalysisConfig,
        created_by: UserId,
    ) -> Self {
        Self {
            id: JobId::new(),
            project_id,
            file_id,
            priority: config.priority.0,
            config,
            created_at: chrono::Utc::now(),
            scheduled_at: None,
            retry_count: 0,
            max_retries: config.max_retries,
            idempotency_key: None,
            tags: Vec::new(),
            timeout_secs: config.timeout_secs,
            created_by,
        }
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        CancellationToken::new()
    }
}

/// Analysis configuration
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub stages: Vec<StageId>,
    pub priority: Priority,
    pub max_retries: u32,
    pub timeout_secs: u64,
    pub ai_enabled: bool,
    pub incremental: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            stages: StageId::all_ordered(),
            priority: Priority::DEFAULT,
            max_retries: 3,
            timeout_secs: 3600,
            ai_enabled: true,
            incremental: false,
        }
    }
}

/// Analysis result
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub job_id: JobId,
    pub status: AnalysisStatus,
    pub functions: Vec<FunctionInfo>,
    pub basic_blocks: Vec<BasicBlockInfo>,
    pub instructions: Vec<InstructionInfo>,
    pub cfg_edges: Vec<CfgEdgeInfo>,
    pub call_edges: Vec<CallEdgeInfo>,
    pub loops: Vec<LoopInfo>,
    pub variables: Vec<VariableInfo>,
    pub types: Vec<TypeInfo>,
    pub pseudocode: HashMap<FunctionId, String>,
    pub annotations: Vec<AnnotationInfo>,
    pub strings: Vec<StringInfo>,
    pub constants: Vec<ConstantInfo>,
    pub statistics: AnalysisStatistics,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisStatus {
    Success,
    Partial,
    Failed,
}

/// Pipeline orchestrator
pub struct Orchestrator {
    stages: Vec<Arc<dyn PipelineStage>>,
    stage_executor: Arc<StageExecutor>,
    project_store: Arc<ProjectStore>,
    plugin_registry: Arc<PluginRegistry>,
    ai_service: Arc<dyn AiService>,
    queue: Arc<QueueManager>,
    telemetry: TelemetryHandle,
}

impl Orchestrator {
    pub fn new(
        stages: Vec<Arc<dyn PipelineStage>>,
        stage_executor: Arc<StageExecutor>,
        project_store: Arc<ProjectStore>,
        plugin_registry: Arc<PluginRegistry>,
        ai_service: Arc<dyn AiService>,
        queue: Arc<QueueManager>,
        telemetry: TelemetryHandle,
    ) -> Self {
        Self {
            stages,
            stage_executor,
            project_store,
            plugin_registry,
            ai_service,
            queue,
            telemetry,
        }
    }

    /// Execute the full analysis pipeline
    pub async fn execute(&self, ctx: PipelineContext) -> Result<AnalysisResult> {
        let span = self.telemetry.span("pipeline.execute", &ctx.job);
        let _guard = span.enter();

        info!(job_id = %ctx.job.id, "Starting analysis pipeline");

        // 1. Build execution DAG
        let dag = self.build_dag(&ctx)?;

        // 2. Execute stages in topological order
        let mut stage_results = HashMap::new();

        for stage_id in dag.topological_order() {
            // Check cancellation
            ctx.cancellation.check()?;

            // Get stage
            let stage = self.stages.iter().find(|s| s.id() == stage_id)
                .ok_or_else(|| openre_core::Error::Internal(format!("Stage not found: {}", stage_id).into()))?;

            // Check if stage can be skipped (incremental)
            if self.can_skip_stage(&ctx, stage_id, &stage_results).await? {
                info!(job_id = %ctx.job.id, stage = %stage_id, "Skipping stage (incremental)");
                continue;
            }

            // Execute stage
            let result = self.execute_stage(&ctx, stage, &stage_results).await?;
            stage_results.insert(stage_id, result);

            // Emit progress
            self.emit_progress(&ctx, stage_id, &stage_results).await?;
        }

        // 3. Aggregate final result
        let result = self.aggregate_results(&ctx, &stage_results).await?;

        info!(job_id = %ctx.job.id, "Analysis pipeline completed");
        Ok(result)
    }

    fn build_dag(&self, ctx: &PipelineContext) -> Result<StageDag> {
        let mut dag = StageDag::new();

        // Add all stages
        for stage in &self.stages {
            dag.add_stage(stage.id(), stage.dependencies());
        }

        // Validate DAG (no cycles)
        dag.validate()?;

        Ok(dag)
    }

    async fn execute_stage(
        &self,
        ctx: &PipelineContext,
        stage: &dyn PipelineStage,
        previous_results: &HashMap<StageId, StageResult>,
    ) -> Result<StageResult> {
        let stage_ctx = StageContext {
            job: ctx.job.clone(),
            binary: ctx.binary.clone(),
            project_store: ctx.project_store.clone(),
            plugin_registry: ctx.plugin_registry.clone(),
            ai_service: ctx.ai_service.clone(),
            previous_results: previous_results.clone(),
            cancellation: ctx.cancellation.clone(),
            telemetry: ctx.telemetry.clone(),
        };

        // Execute with timeout and retry
        self.stage_executor.execute(stage, stage_ctx).await
    }

    async fn can_skip_stage(
        &self,
        ctx: &PipelineContext,
        stage_id: StageId,
        previous_results: &HashMap<StageId, StageResult>,
    ) -> Result<bool> {
        if !ctx.job.config.incremental {
            return Ok(false);
        }

        // Check if stage was already completed successfully
        if let Some(result) = previous_results.get(&stage_id) {
            if result.status == StageStatus::Success {
                // Verify input hasn't changed
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn emit_progress(
        &self,
        ctx: &PipelineContext,
        stage_id: StageId,
        results: &HashMap<StageId, StageResult>,
    ) -> Result<()> {
        let completed = results.len();
        let total = self.stages.len();
        let overall_progress = completed as f32 / total as f32;

        let current_stage_result = results.get(&stage_id);
        let stage_progress = current_stage_result.map(|r| {
            if r.status == StageStatus::Success { 1.0 } else { 0.5 }
        }).unwrap_or(0.0);

        let progress = JobProgress {
            job_id: ctx.job.id,
            status: JobStatus::Running { 
                worker_id: ctx.worker_id.clone(), 
                started_at: ctx.job.created_at, 
                stage: stage_id 
            },
            current_stage: Some(stage_id),
            stage_progress,
            overall_progress,
            message: format!("Running stage: {}", stage_id),
            started_at: ctx.job.created_at,
            updated_at: chrono::Utc::now(),
            estimated_remaining_secs: self.estimate_remaining(results).await,
            stages: self.stages.iter().map(|s| StageProgress {
                name: s.id(),
                status: results.get(&s.id()).map(|r| r.status).unwrap_or(StageStatus::Pending),
                progress: results.get(&s.id()).map(|r| if r.status == StageStatus::Success { 1.0 } else { 0.0 }).unwrap_or(0.0),
                started_at: results.get(&s.id()).map(|r| r.started_at),
                completed_at: results.get(&s.id()).map(|r| r.completed_at),
                duration_ms: results.get(&s.id()).map(|r| (r.completed_at - r.started_at).num_milliseconds() as u64),
            }).collect(),
        };

        self.queue.update_progress(progress).await?;
        Ok(())
    }

    async fn estimate_remaining(&self, results: &HashMap<StageId, StageResult>) -> Option<u64> {
        let completed_stages: Vec<_> = results.values().filter(|r| r.status == StageStatus::Success).collect();
        if completed_stages.is_empty() {
            return None;
        }

        let avg_duration = completed_stages.iter()
            .map(|r| (r.completed_at - r.started_at).num_milliseconds())
            .sum::<i64>() / completed_stages.len() as i64;

        let remaining_stages = self.stages.len() - results.len();
        Some((avg_duration * remaining_stages as i64 / 1000) as u64)
    }

    async fn aggregate_results(
        &self,
        ctx: &PipelineContext,
        stage_results: &HashMap<StageId, StageResult>,
    ) -> Result<AnalysisResult> {
        // In a real implementation, this would aggregate results from all stages
        // For now, return a placeholder
        Ok(AnalysisResult {
            job_id: ctx.job.id,
            status: AnalysisStatus::Success,
            functions: Vec::new(),
            basic_blocks: Vec::new(),
            instructions: Vec::new(),
            cfg_edges: Vec::new(),
            call_edges: Vec::new(),
            loops: Vec::new(),
            variables: Vec::new(),
            types: Vec::new(),
            pseudocode: HashMap::new(),
            annotations: Vec::new(),
            strings: Vec::new(),
            constants: Vec::new(),
            statistics: AnalysisStatistics::default(),
            completed_at: chrono::Utc::now(),
        })
    }
}

/// Stage DAG for pipeline execution
pub struct StageDag {
    stages: HashMap<StageId, Vec<StageId>>,
}

impl StageDag {
    pub fn new() -> Self {
        Self { stages: HashMap::new() }
    }

    pub fn add_stage(&mut self, stage_id: StageId, dependencies: Vec<StageId>) {
        self.stages.insert(stage_id, dependencies);
    }

    pub fn topological_order(&self) -> Vec<StageId> {
        let mut visited = std::collections::HashSet::new();
        let mut temp = std::collections::HashSet::new();
        let mut order = Vec::new();

        fn visit(
            stage_id: StageId,
            stages: &HashMap<StageId, Vec<StageId>>,
            visited: &mut std::collections::HashSet<StageId>,
            temp: &mut std::collections::HashSet<StageId>,
            order: &mut Vec<StageId>,
        ) -> Result<(), String> {
            if temp.contains(&stage_id) {
                return Err(format!("Cycle detected at stage: {}", stage_id));
            }
            if visited.contains(&stage_id) {
                return Ok(());
            }

            temp.insert(stage_id);
            if let Some(deps) = stages.get(&stage_id) {
                for dep in deps {
                    visit(*dep, stages, visited, temp, order)?;
                }
            }
            temp.remove(&stage_id);
            visited.insert(stage_id);
            order.push(stage_id);
            Ok(())
        }

        for stage_id in self.stages.keys() {
            if !visited.contains(stage_id) {
                visit(*stage_id, &self.stages, &mut visited, &mut temp, &mut order)
                    .expect("Cycle detected in pipeline DAG");
            }
        }

        order
    }

    pub fn validate(&self) -> Result<()> {
        let mut visited = std::collections::HashSet::new();
        let mut temp = std::collections::HashSet::new();

        fn visit(
            stage_id: StageId,
            stages: &HashMap<StageId, Vec<StageId>>,
            visited: &mut std::collections::HashSet<StageId>,
            temp: &mut std::collections::HashSet<StageId>,
        ) -> Result<(), String> {
            if temp.contains(&stage_id) {
                return Err(format!("Cycle detected at stage: {}", stage_id));
            }
            if visited.contains(&stage_id) {
                return Ok(());
            }

            temp.insert(stage_id);
            if let Some(deps) = stages.get(&stage_id) {
                for dep in deps {
                    visit(*dep, stages, visited, temp)?;
                }
            }
            temp.remove(&stage_id);
            visited.insert(stage_id);
            Ok(())
        }

        for stage_id in self.stages.keys() {
            if !visited.contains(stage_id) {
                visit(*stage_id, &self.stages, &mut visited, &mut temp)?;
            }
        }

        Ok(())
    }
}

/// Stage executor with timeout and retry
pub struct StageExecutor {
    config: ExecutorConfig,
    telemetry: TelemetryHandle,
}

#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub default_timeout_secs: u64,
    pub max_retries: u32,
    pub retry_base_delay_secs: u64,
    pub retry_max_delay_secs: u64,
    pub enable_parallel: bool,
    pub max_parallel_functions: usize,
}

impl StageExecutor {
    pub fn new(config: ExecutorConfig, telemetry: TelemetryHandle) -> Self {
        Self { config, telemetry }
    }

    pub async fn execute(
        &self,
        stage: &dyn PipelineStage,
        ctx: StageContext,
    ) -> Result<StageResult> {
        let span = self.telemetry.span("stage.execute", stage.id());
        let _guard = span.enter();

        let started_at = chrono::Utc::now();
        let mut attempt = 0;

        loop {
            // Check cancellation
            ctx.cancellation.check()?;

            // Execute with timeout
            let result = tokio::time::timeout(
                Duration::from_secs(self.config.default_timeout_secs),
                stage.execute(ctx.clone()),
            ).await;

            match result {
                Ok(Ok(stage_result)) => {
                    return Ok(stage_result);
                }
                Ok(Err(e)) => {
                    attempt += 1;
                    if attempt >= self.config.max_retries {
                        return Err(e);
                    }
                    // Exponential backoff
                    let delay = Duration::from_secs(
                        (self.config.retry_base_delay_secs as f64 * 2.0_f64.powi(attempt as i32 - 1)) as u64
                    ).min(Duration::from_secs(self.config.retry_max_delay_secs));
                    tokio::time::sleep(delay).await;
                }
                Err(_) => {
                    // Timeout
                    attempt += 1;
                    if attempt >= self.config.max_retries {
                        return Err(openre_core::Error::Timeout(format!("Stage {} timed out", stage.id())));
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}

/// Stage context
#[derive(Clone)]
pub struct StageContext {
    pub job: AnalysisJob,
    pub binary: IsolatedBinary,
    pub project_store: Arc<ProjectStore>,
    pub plugin_registry: Arc<PluginRegistry>,
    pub ai_service: Arc<dyn AiService>,
    pub previous_results: HashMap<StageId, StageResult>,
    pub cancellation: CancellationToken,
    pub telemetry: TelemetryHandle,
}

/// Stage result
#[derive(Debug, Clone)]
pub struct StageResult {
    pub stage_id: StageId,
    pub status: StageStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub output: serde_json::Value,
    pub metrics: StageMetrics,
    pub artifacts: Vec<Artifact>,
}

impl StageResult {
    pub fn skipped(stage_id: StageId) -> Self {
        Self {
            stage_id,
            status: StageStatus::Skipped,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::Value::Null,
            metrics: StageMetrics::default(),
            artifacts: Vec::new(),
        }
    }
}

/// Stage status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageStatus {
    Success,
    PartialSuccess,
    Failed,
    Skipped,
    Cancelled,
}

/// Stage metrics
#[derive(Debug, Clone, Default)]
pub struct StageMetrics {
    pub instructions_processed: u64,
    pub functions_analyzed: u64,
    pub basic_blocks: u64,
    pub edges: u64,
    pub memory_peak_mb: u64,
    pub cpu_time_ms: u64,
    pub plugin_calls: u64,
    pub ai_calls: u64,
}

/// Artifact
#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    pub path: String,
    pub size: u64,
}

/// Cancellation token
#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(openre_core::Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

// Placeholder types
pub struct IsolatedBinary;
pub struct FunctionInfo;
pub struct BasicBlockInfo;
pub struct InstructionInfo;
pub struct CfgEdgeInfo;
pub struct CallEdgeInfo;
pub struct LoopInfo;
pub struct VariableInfo;
pub struct TypeInfo;
pub struct AnnotationInfo;
pub struct StringInfo;
pub struct ConstantInfo;
pub struct AnalysisStatistics;

impl Default for AnalysisStatistics {
    fn default() -> Self {
        Self
    }
}

pub struct AiService;
pub struct JobProgress;
pub struct JobStatus;
pub struct StageProgress;
pub struct StageId;
pub struct Priority;
pub struct WorkerId;
pub struct RequestContext;
pub struct CreateAnalysisRequest;