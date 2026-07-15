//! Incremental re-analysis for open-re

use crate::orchestrator::*;
use openre_core::error::Result;
use openre_core::ids::*;
use openre_storage::ProjectStore;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};

/// Incremental analyzer for re-running only affected stages
pub struct IncrementalAnalyzer {
    project_store: Arc<ProjectStore>,
    orchestrator: Arc<Orchestrator>,
}

impl IncrementalAnalyzer {
    pub fn new(project_store: Arc<ProjectStore>, orchestrator: Arc<Orchestrator>) -> Self {
        Self { project_store, orchestrator }
    }

    /// Re-analyze with only affected stages
    pub async fn reanalyze(
        &self,
        job: AnalysisJob,
        changes: AnalysisChanges,
    ) -> Result<AnalysisResult> {
        // 1. Determine affected stages
        let affected_stages = self.compute_affected_stages(&changes)?;

        // 2. Invalidate downstream stages
        self.invalidate_stages(&job.project_id, &affected_stages).await?;

        // 3. Create new job with only affected stages
        let incremental_job = AnalysisJob {
            config: AnalysisConfig {
                stages: affected_stages,
                incremental: true,
                ..job.config
            },
            ..job
        };

        // 4. Execute
        self.orchestrator.execute(PipelineContext::from(incremental_job)).await
    }

    fn compute_affected_stages(&self, changes: &AnalysisChanges) -> Result<Vec<StageId>> {
        let mut affected = Vec::new();

        match changes {
            AnalysisChanges::BinaryModified => {
                // Full re-analysis needed
                affected = StageId::all_ordered();
            }
            AnalysisChanges::AnnotationAdded { function_id, .. } => {
                // Only AI enrichment might be affected
                affected.push(StageId::new("ai_enrichment"));
            }
            AnalysisChanges::TypeChanged { function_id } => {
                // Decompilation and downstream
                affected.extend([
                    StageId::new("decompilation"),
                    StageId::new("ai_enrichment"),
                ]);
            }
            AnalysisChanges::FunctionBoundaryChanged { .. } => {
                // Disassembly and downstream
                affected.extend([
                    StageId::new("disassembly"),
                    StageId::new("control_flow"),
                    StageId::new("data_flow"),
                    StageId::new("type_recovery"),
                    StageId::new("decompilation"),
                    StageId::new("ai_enrichment"),
                ]);
            }
            AnalysisChanges::PluginUpdated { plugin_type } => {
                // Stages using this plugin type
                affected = self.stages_using_plugin(plugin_type);
            }
        }

        Ok(affected)
    }

    fn stages_using_plugin(&self, plugin_type: &str) -> Vec<StageId> {
        match plugin_type {
            "identifier" => vec![StageId::new("identification")],
            "disassembler" => vec![StageId::new("disassembly")],
            "decompiler" => vec![StageId::new("decompilation")],
            "analyzer" => vec![
                StageId::new("control_flow"),
                StageId::new("data_flow"),
                StageId::new("type_recovery"),
            ],
            "ai-enricher" => vec![StageId::new("ai_enrichment")],
            "exporter" => vec![StageId::new("finalization")],
            _ => vec![],
        }
    }

    async fn invalidate_stages(&self, project_id: &ProjectId, stages: &[StageId]) -> Result<()> {
        // In a real implementation, this would mark stages as invalid in the database
        // For now, we just log
        info!(project_id = %project_id, stages = ?stages, "Invalidating stages for incremental re-analysis");
        Ok(())
    }
}

/// Types of analysis changes that trigger incremental re-analysis
#[derive(Debug, Clone)]
pub enum AnalysisChanges {
    BinaryModified,
    AnnotationAdded { function_id: FunctionId, annotation_type: String },
    TypeChanged { function_id: FunctionId },
    FunctionBoundaryChanged { function_id: FunctionId, old_boundary: FunctionBoundary, new_boundary: FunctionBoundary },
    PluginUpdated { plugin_type: String },
}

/// Stage ID utilities
impl StageId {
    pub fn all_ordered() -> Vec<StageId> {
        vec![
            StageId::new("identification"),
            StageId::new("loading"),
            StageId::new("disassembly"),
            StageId::new("control_flow"),
            StageId::new("data_flow"),
            StageId::new("type_recovery"),
            StageId::new("decompilation"),
            StageId::new("ai_enrichment"),
            StageId::new("finalization"),
        ]
    }
}