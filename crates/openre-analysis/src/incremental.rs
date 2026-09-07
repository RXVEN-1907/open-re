//! Incremental re-analysis for open-re

use crate::{binary::common::FunctionBoundary, orchestrator::*};
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use std::sync::Arc;
use tracing::info;

/// Incremental analyzer for re-running only affected stages
pub struct IncrementalAnalyzer {
    orchestrator: Arc<Orchestrator>,
}

impl IncrementalAnalyzer {
    pub fn new(orchestrator: Arc<Orchestrator>) -> Self {
        Self { orchestrator }
    }

    /// Re-analyze with only affected stages
    pub async fn reanalyze(
        &self,
        base_ctx: &PipelineContext,
        changes: &AnalysisChanges,
    ) -> Result<AnalysisResult> {
        // 1. Determine affected stages
        let affected_stages = self.compute_affected_stages(changes)?;

        // 2. Invalidate downstream stages
        self.invalidate_stages(&base_ctx.job.project_id, &affected_stages).await?;

        // 3. Build an incremental execution context with only affected stages
        let mut job = base_ctx.job.clone();
        job.config.stages = affected_stages.clone();
        job.config.incremental = true;

        let mut ctx = base_ctx.clone();
        ctx.job = job;
        ctx.previous_results.clear();

        // 4. Execute
        let start = std::time::Instant::now();
        let _orchestrator_result = self.orchestrator.execute(ctx).await?;

        // Convert to incremental result
        Ok(AnalysisResult {
            stages_completed: affected_stages,
            total_duration_ms: start.elapsed().as_millis() as u64,
            incremental: true,
        })
    }

    fn compute_affected_stages(&self, changes: &AnalysisChanges) -> Result<Vec<StageId>> {
        let mut affected = Vec::new();

        match changes {
            AnalysisChanges::BinaryUpdated => {
                // All stages affected
                affected.extend([
                    StageId::new("disassembly"),
                    StageId::new("control_flow"),
                    StageId::new("data_flow"),
                    StageId::new("type_recovery"),
                    StageId::new("decompilation"),
                ]);
            }
            AnalysisChanges::ConfigChanged { stages } => {
                affected.extend(stages.clone());
            }
            AnalysisChanges::PluginAdded { stage } => {
                affected.push(stage.clone());
            }
        }

        Ok(affected)
    }

    async fn invalidate_stages(&self, _project_id: &ProjectId, stages: &[StageId]) -> Result<()> {
        info!("Invalidating stages: {:?}", stages);
        // In a real implementation, this would clear cached results
        Ok(())
    }
}

/// Changes that trigger incremental re-analysis
#[derive(Debug, Clone)]
pub enum AnalysisChanges {
    BinaryUpdated,
    ConfigChanged { stages: Vec<StageId> },
    PluginAdded { stage: StageId },
}

/// Analysis result
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub stages_completed: Vec<StageId>,
    pub total_duration_ms: u64,
    pub incremental: bool,
}