//! Analysis pipeline stages for open-re

use serde::{Deserialize, Serialize};

use crate::binary::common::{
    BasicBlock, CompilerInfo, ControlFlowOutput, DataFlowOutput, DisassemblyOutput, ExportInfo,
    FunctionBoundary, ImportInfo, Instruction, SectionInfo, SegmentInfo, TypeInfo,
    TypeRecoveryOutput, Variable,
};
use crate::orchestrator::*;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use openre_storage::ProjectStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Relocation information (placeholder until full relocation analysis lands)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocationInfo {
    pub offset: u64,
    pub relocation_type: String,
    pub symbol: Option<String>,
}

/// Loading stage output
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadingOutput {
    pub segments: Vec<SegmentInfo>,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub relocations: Vec<RelocationInfo>,
    pub function_boundaries: Vec<FunctionBoundary>,
}

/// Decompilation stage output
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecompilationOutput {
    pub pseudocode: HashMap<FunctionId, String>,
    pub variables: HashMap<FunctionId, Vec<Variable>>,
}

/// Inference task type for AI enrichment
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    #[default]
    FunctionNaming,
    CommentGeneration,
    VulnerabilityDetection,
    CodeExplanation,
}

/// AI inference request
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub task_type: TaskType,
    pub context: String,
    pub prompt: String,
}

/// AI inference response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InferenceResponse {
    pub content: String,
}

impl InferenceResponse {
    /// Extract a suggested function name from the model output
    pub fn extract_function_name(&self) -> Option<String> {
        let line = self.content.lines().find(|l| !l.trim().is_empty())?;
        let name = line
            .trim()
            .trim_matches(|c| c == '`' || c == '"' || c == '\'');
        let name = name.strip_prefix("Name: ").unwrap_or(name);
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }
}

/// Trait for AI inference backends used by the enrichment stage
#[async_trait::async_trait]
pub trait AiService: Send + Sync {
    async fn batch_infer(&self, requests: Vec<InferenceRequest>) -> Result<Vec<InferenceResponse>>;
}

/// No-op AI service used when no provider is configured
pub struct NoopAiService;

#[async_trait::async_trait]
impl AiService for NoopAiService {
    async fn batch_infer(&self, requests: Vec<InferenceRequest>) -> Result<Vec<InferenceResponse>> {
        Ok(requests
            .into_iter()
            .map(|_| InferenceResponse::default())
            .collect())
    }
}

/// Pipeline stage trait
#[async_trait::async_trait]
pub trait PipelineStage: Send + Sync {
    fn id(&self) -> StageId;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn dependencies(&self) -> Vec<StageId>;
    fn estimated_duration(&self) -> Duration;
    fn can_skip(&self, ctx: &PipelineContext, previous: &HashMap<StageId, StageResult>) -> bool;

    async fn execute(&self, ctx: StageContext) -> Result<StageResult>;
}

/// Stage 1: Identification
pub struct IdentificationStage {
    plugins: Vec<Arc<dyn IdentifierPlugin>>,
}

impl IdentificationStage {
    pub fn new(plugins: Vec<Arc<dyn IdentifierPlugin>>) -> Self {
        Self { plugins }
    }
}

#[async_trait::async_trait]
impl PipelineStage for IdentificationStage {
    fn id(&self) -> StageId {
        StageId::new("identification")
    }
    fn name(&self) -> &str {
        "Identification"
    }
    fn description(&self) -> &str {
        "Identify file format, architecture, and compiler"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn can_skip(&self, _ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        false
    }

    async fn execute(&self, ctx: StageContext) -> Result<StageResult> {
        let mut best: Option<IdentificationResult> = None;

        // Run all identifier plugins and keep the most confident result
        for plugin in &self.plugins {
            let result = plugin.identify(&ctx.binary).await?;
            if best
                .as_ref()
                .map(|b| result.confidence > b.confidence)
                .unwrap_or(true)
            {
                best = Some(result);
            }
        }

        let identified = best.unwrap_or(IdentificationResult {
            format: FileFormat::Unknown,
            architecture: Architecture::Unknown,
            compiler_info: None,
            confidence: 0.0,
        });

        let output = openre_core::traits::IdentificationOutput {
            format: identified.format,
            architecture: identified.architecture,
            compiler_info: serde_json::to_value(identified.compiler_info)?,
            confidence: identified.confidence,
        };

        ctx.project_store.write_identification(&output).await?;

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::json!({
                "format": output.format.as_str(),
                "architecture": output.architecture.as_str(),
                "compiler_info": output.compiler_info,
                "confidence": output.confidence,
            }),
            metrics: StageMetrics::default(),
            artifacts: vec![],
        })
    }
}

/// Stage 2: Loading
pub struct LoadingStage {
    plugins: Vec<Arc<dyn LoaderPlugin>>,
}

impl LoadingStage {
    pub fn new(plugins: Vec<Arc<dyn LoaderPlugin>>) -> Self {
        Self { plugins }
    }
}

#[async_trait::async_trait]
impl PipelineStage for LoadingStage {
    fn id(&self) -> StageId {
        StageId::new("loading")
    }
    fn name(&self) -> &str {
        "Loading"
    }
    fn description(&self) -> &str {
        "Load segments, sections, imports, exports, relocations"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("identification")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(10)
    }
    fn can_skip(&self, _ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        false
    }

    async fn execute(&self, ctx: StageContext) -> Result<StageResult> {
        // Run loader plugins and merge their outputs; fall back to an empty load
        let mut output = LoadingOutput::default();
        for plugin in &self.plugins {
            match plugin.load(&ctx.binary).await {
                Ok(part) => {
                    output.segments.extend(part.segments);
                    output.sections.extend(part.sections);
                    output.imports.extend(part.imports);
                    output.exports.extend(part.exports);
                    output.relocations.extend(part.relocations);
                    if output.function_boundaries.is_empty() {
                        output.function_boundaries = part.function_boundaries;
                    }
                }
                Err(e) => warn!("Loader plugin failed: {}", e),
            }
        }

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::to_value(output)?,
            metrics: StageMetrics::default(),
            artifacts: vec![],
        })
    }
}

/// Stage 3: Disassembly
pub struct DisassemblyStage {
    disassembler: Arc<dyn DisassemblerPlugin>,
    executor: Arc<StageExecutor>,
}

impl DisassemblyStage {
    pub fn new(disassembler: Arc<dyn DisassemblerPlugin>, executor: Arc<StageExecutor>) -> Self {
        Self {
            disassembler,
            executor,
        }
    }
}

#[async_trait::async_trait]
impl PipelineStage for DisassemblyStage {
    fn id(&self) -> StageId {
        StageId::new("disassembly")
    }
    fn name(&self) -> &str {
        "Disassembly"
    }
    fn description(&self) -> &str {
        "Disassemble instructions and identify basic blocks"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("loading")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(60)
    }
    fn can_skip(&self, _ctx: &PipelineContext, prev: &HashMap<StageId, StageResult>) -> bool {
        prev.get(&StageId::new("disassembly"))
            .map(|r| r.status == StageStatus::Success)
            .unwrap_or(false)
    }

    async fn execute(&self, ctx: StageContext) -> Result<StageResult> {
        let loading_result = ctx
            .previous_results
            .get(&StageId::new("loading"))
            .ok_or_else(|| {
                openre_core::Error::Internal(anyhow::anyhow!("loading result missing"))
            })?;
        let loading: LoadingOutput = serde_json::from_value(loading_result.output.clone())?;
        let functions = loading.function_boundaries;

        let semaphore = Arc::new(Semaphore::new(self.executor.max_parallel_functions()));
        let mut tasks = Vec::new();

        for func in functions.clone() {
            let disassembler = self.disassembler.clone();
            let binary = ctx.binary;
            let semaphore = semaphore.clone();
            let cancellation = ctx.cancellation.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await;
                cancellation.check()?;
                disassembler.disassemble_function(&binary, func).await
            }));
        }

        let mut all_instructions = Vec::new();
        let mut all_blocks = Vec::new();
        let mut metrics = StageMetrics::default();

        for task in tasks {
            let result = task.await.map_err(|e| {
                openre_core::Error::Internal(anyhow::anyhow!("disassembly task panicked: {}", e))
            })??;
            metrics.instructions_processed += result.instructions.len() as u64;
            metrics.basic_blocks += result.blocks.len() as u64;
            all_instructions.extend(result.instructions);
            all_blocks.extend(result.blocks);
        }

        let output = DisassemblyOutput {
            function_boundaries: functions,
            basic_blocks: all_blocks,
            instructions: all_instructions,
        };

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::to_value(output)?,
            metrics,
            artifacts: vec![],
        })
    }
}

/// Stage 4: Control Flow
pub struct ControlFlowStage {
    analyzer: Arc<dyn AnalyzerPlugin>,
    executor: Arc<StageExecutor>,
}

impl ControlFlowStage {
    pub fn new(analyzer: Arc<dyn AnalyzerPlugin>, executor: Arc<StageExecutor>) -> Self {
        Self { analyzer, executor }
    }
}

#[async_trait::async_trait]
impl PipelineStage for ControlFlowStage {
    fn id(&self) -> StageId {
        StageId::new("control_flow")
    }
    fn name(&self) -> &str {
        "Control Flow"
    }
    fn description(&self) -> &str {
        "Build CFG, call graph, detect loops"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("disassembly")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(30)
    }
    fn can_skip(&self, _ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        false
    }

    async fn execute(&self, ctx: StageContext) -> Result<StageResult> {
        let loading_result = ctx
            .previous_results
            .get(&StageId::new("loading"))
            .ok_or_else(|| {
                openre_core::Error::Internal(anyhow::anyhow!("loading result missing"))
            })?;
        let loading: LoadingOutput = serde_json::from_value(loading_result.output.clone())?;

        let output = self
            .analyzer
            .analyze_control_flow(&ctx.binary, &loading.function_boundaries)
            .await?;

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::to_value(output)?,
            metrics: StageMetrics::default(),
            artifacts: vec![],
        })
    }
}

/// Stage 5: Data Flow
pub struct DataFlowStage {
    analyzer: Arc<dyn AnalyzerPlugin>,
    executor: Arc<StageExecutor>,
}

impl DataFlowStage {
    pub fn new(analyzer: Arc<dyn AnalyzerPlugin>, executor: Arc<StageExecutor>) -> Self {
        Self { analyzer, executor }
    }
}

#[async_trait::async_trait]
impl PipelineStage for DataFlowStage {
    fn id(&self) -> StageId {
        StageId::new("data_flow")
    }
    fn name(&self) -> &str {
        "Data Flow"
    }
    fn description(&self) -> &str {
        "SSA, def-use chains, taint analysis"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("control_flow")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(60)
    }
    fn can_skip(&self, _ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        false
    }

    async fn execute(&self, _ctx: StageContext) -> Result<StageResult> {
        let output = DataFlowOutput {
            variables: vec![],
            data_dependencies: vec![],
        };

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::to_value(output)?,
            metrics: StageMetrics::default(),
            artifacts: vec![],
        })
    }
}

/// Stage 6: Type Recovery
pub struct TypeRecoveryStage {
    analyzer: Arc<dyn AnalyzerPlugin>,
    executor: Arc<StageExecutor>,
}

impl TypeRecoveryStage {
    pub fn new(analyzer: Arc<dyn AnalyzerPlugin>, executor: Arc<StageExecutor>) -> Self {
        Self { analyzer, executor }
    }
}

#[async_trait::async_trait]
impl PipelineStage for TypeRecoveryStage {
    fn id(&self) -> StageId {
        StageId::new("type_recovery")
    }
    fn name(&self) -> &str {
        "Type Recovery"
    }
    fn description(&self) -> &str {
        "Recover function signatures, variable types, struct definitions"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("data_flow")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(60)
    }
    fn can_skip(&self, _ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        false
    }

    async fn execute(&self, _ctx: StageContext) -> Result<StageResult> {
        let output = TypeRecoveryOutput {
            types: HashMap::new(),
            variables: vec![],
        };

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::to_value(output)?,
            metrics: StageMetrics::default(),
            artifacts: vec![],
        })
    }
}

/// Stage 7: Decompilation
pub struct DecompilationStage {
    decompiler: Arc<dyn DecompilerPlugin>,
    executor: Arc<StageExecutor>,
}

impl DecompilationStage {
    pub fn new(decompiler: Arc<dyn DecompilerPlugin>, executor: Arc<StageExecutor>) -> Self {
        Self {
            decompiler,
            executor,
        }
    }
}

#[async_trait::async_trait]
impl PipelineStage for DecompilationStage {
    fn id(&self) -> StageId {
        StageId::new("decompilation")
    }
    fn name(&self) -> &str {
        "Decompilation"
    }
    fn description(&self) -> &str {
        "Generate pseudocode from CFG and types"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("type_recovery")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(120)
    }
    fn can_skip(&self, _ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        false
    }

    async fn execute(&self, ctx: StageContext) -> Result<StageResult> {
        let type_result = ctx
            .previous_results
            .get(&StageId::new("type_recovery"))
            .ok_or_else(|| {
                openre_core::Error::Internal(anyhow::anyhow!("type_recovery result missing"))
            })?;

        // Recovered types feed the decompiler; CFG construction is not yet wired up,
        // so there are no functions to decompile yet. The plugin hook remains for
        // when CFG data becomes available.
        let _types: TypeRecoveryOutput = serde_json::from_value(type_result.output.clone())
            .unwrap_or_else(|_| TypeRecoveryOutput {
                types: HashMap::new(),
                variables: Vec::new(),
            });

        let pseudocode_map: HashMap<FunctionId, String> = HashMap::new();
        let variables_map: HashMap<FunctionId, Vec<Variable>> = HashMap::new();
        let mut metrics = StageMetrics::default();

        let output = DecompilationOutput {
            pseudocode: pseudocode_map,
            variables: variables_map,
        };

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::to_value(output)?,
            metrics,
            artifacts: vec![],
        })
    }
}

/// Stage 8: AI Enrichment
pub struct AiEnrichmentStage {
    ai_service: Arc<dyn AiService>,
    config: AiEnrichmentConfig,
}

#[derive(Debug, Clone)]
pub struct AiEnrichmentConfig {
    pub enabled: bool,
    pub tasks: Vec<TaskType>,
    pub max_functions: Option<usize>,
    pub min_function_size: usize,
    pub batch_size: usize,
}

impl Default for AiEnrichmentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tasks: vec![TaskType::FunctionNaming],
            max_functions: None,
            min_function_size: 16,
            batch_size: 8,
        }
    }
}

impl AiEnrichmentStage {
    pub fn new(ai_service: Arc<dyn AiService>, config: AiEnrichmentConfig) -> Self {
        Self { ai_service, config }
    }

    async fn build_contexts(
        &self,
        _ctx: &StageContext,
        functions: &[(FunctionId, String)],
    ) -> Result<Vec<String>> {
        Ok(functions.iter().map(|(_, pseudo)| pseudo.clone()).collect())
    }
}

#[async_trait::async_trait]
impl PipelineStage for AiEnrichmentStage {
    fn id(&self) -> StageId {
        StageId::new("ai_enrichment")
    }
    fn name(&self) -> &str {
        "AI Enrichment"
    }
    fn description(&self) -> &str {
        "AI-powered function naming, comments, vulnerability detection"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("decompilation")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(300)
    }
    fn can_skip(&self, ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        !self.config.enabled || !ctx.job.config.ai_enabled
    }

    async fn execute(&self, ctx: StageContext) -> Result<StageResult> {
        if !self.config.enabled || !ctx.job.config.ai_enabled {
            return Ok(StageResult::skipped(self.id()));
        }

        let decomp_result = ctx
            .previous_results
            .get(&StageId::new("decompilation"))
            .ok_or_else(|| {
                openre_core::Error::Internal(anyhow::anyhow!("decompilation result missing"))
            })?;
        let decomp: DecompilationOutput =
            serde_json::from_value(decomp_result.output.clone()).unwrap_or_default();

        let mut enriched = 0;
        let mut metrics = StageMetrics::default();

        for chunk in decomp
            .pseudocode
            .iter()
            .map(|(id, p)| (*id, p.clone()))
            .collect::<Vec<_>>()
            .chunks(self.config.batch_size.max(1))
        {
            ctx.cancellation.check()?;

            let functions: Vec<(FunctionId, String)> = chunk.to_vec();
            let contexts = self.build_contexts(&ctx, &functions).await?;

            let requests: Vec<_> = functions
                .iter()
                .zip(contexts)
                .map(|((_id, _pseudo), context)| InferenceRequest {
                    task_type: TaskType::FunctionNaming,
                    context,
                    ..Default::default()
                })
                .collect();

            let responses = self.ai_service.batch_infer(requests).await?;

            for ((func_id, _), response) in functions.iter().zip(responses) {
                if let Some(name) = response.extract_function_name() {
                    info!(function = %func_id, suggested_name = %name, "AI suggested function name");
                    enriched += 1;
                }
                metrics.ai_calls += 1;
            }
        }

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::json!({"functions_enriched": enriched}),
            metrics,
            artifacts: vec![],
        })
    }
}

/// Stage 9: Finalization
pub struct FinalizationStage {
    exporters: Vec<Arc<dyn ExporterPlugin>>,
}

impl FinalizationStage {
    pub fn new(exporters: Vec<Arc<dyn ExporterPlugin>>) -> Self {
        Self { exporters }
    }
}

#[async_trait::async_trait]
impl PipelineStage for FinalizationStage {
    fn id(&self) -> StageId {
        StageId::new("finalization")
    }
    fn name(&self) -> &str {
        "Finalization"
    }
    fn description(&self) -> &str {
        "Index results, generate exports, cleanup"
    }
    fn dependencies(&self) -> Vec<StageId> {
        vec![StageId::new("ai_enrichment")]
    }
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(10)
    }
    fn can_skip(&self, _ctx: &PipelineContext, _prev: &HashMap<StageId, StageResult>) -> bool {
        false
    }

    async fn execute(&self, ctx: StageContext) -> Result<StageResult> {
        for exporter in &self.exporters {
            match exporter
                .export(ctx.job.project_id, ExportFormat::Json)
                .await
            {
                Ok(result) => info!(path = %result.path, "Export completed"),
                Err(e) => warn!("Exporter failed: {}", e),
            }
        }

        ctx.project_store.finalize(ctx.job.project_id).await?;

        Ok(StageResult {
            stage_id: self.id(),
            status: StageStatus::Success,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output: serde_json::json!({"finalized": true}),
            metrics: StageMetrics::default(),
            artifacts: vec![],
        })
    }
}

// Plugin traits for each stage
#[async_trait::async_trait]
pub trait IdentifierPlugin: Send + Sync {
    async fn identify(&self, binary: &IsolatedBinary) -> Result<IdentificationResult>;
}

#[derive(Debug, Clone)]
pub struct IdentificationResult {
    pub format: openre_core::ids::FileFormat,
    pub architecture: openre_core::ids::Architecture,
    pub compiler_info: Option<CompilerInfo>,
    pub confidence: f32,
}

#[async_trait::async_trait]
pub trait LoaderPlugin: Send + Sync {
    async fn load(&self, binary: &IsolatedBinary) -> Result<LoadingOutput>;
}

#[async_trait::async_trait]
pub trait DisassemblerPlugin: Send + Sync {
    async fn disassemble_function(
        &self,
        binary: &IsolatedBinary,
        func: FunctionBoundary,
    ) -> Result<DisassemblyFunctionResult>;
}

#[derive(Debug, Clone)]
pub struct DisassemblyFunctionResult {
    pub instructions: Vec<Instruction>,
    pub blocks: Vec<BasicBlock>,
}

#[async_trait::async_trait]
pub trait AnalyzerPlugin: Send + Sync {
    async fn analyze_control_flow(
        &self,
        binary: &IsolatedBinary,
        functions: &[FunctionBoundary],
    ) -> Result<ControlFlowOutput>;
    async fn analyze_data_flow(&self, binary: &IsolatedBinary, cfg: &CFG)
        -> Result<DataFlowOutput>;
    async fn recover_types(
        &self,
        binary: &IsolatedBinary,
        data_flow: &DataFlowOutput,
    ) -> Result<TypeRecoveryOutput>;
}

/// Placeholder control-flow graph handle (CFG construction not yet implemented)
#[derive(Debug, Clone, Copy, Default)]
pub struct CFG;

#[async_trait::async_trait]
pub trait DecompilerPlugin: Send + Sync {
    async fn decompile_function(
        &self,
        func_id: FunctionId,
        cfg: &CFG,
        types: &TypeInfo,
    ) -> Result<DecompilationFunctionResult>;
}

#[derive(Debug, Clone)]
pub struct DecompilationFunctionResult {
    pub function_id: FunctionId,
    pub pseudocode: String,
    pub variables: Vec<Variable>,
}

/// Supported export formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Sarif,
    Graphviz,
}

#[async_trait::async_trait]
pub trait ExporterPlugin: Send + Sync {
    async fn export(&self, project_id: ProjectId, format: ExportFormat) -> Result<ExportResult>;
}

#[derive(Debug, Clone)]
pub struct ExportResult {
    pub path: String,
    pub size: u64,
}
