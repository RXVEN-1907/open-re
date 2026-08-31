//! Incremental re-analysis for open-re

use crate::binary::common::FunctionBoundary;
use crate::orchestrator::*;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use openre_storage::ProjectStore;
use std::sync::Arc;
use tracing::info;

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
        base_ctx: &PipelineContext,
        changes: &AnalysisChanges,
    ) -> Result<AnalysisResult> {
        // 1. Determine affected stages
        let affected_stages = self.compute_affected_stages(changes)?;

        // 2. Invalidate downstream stages
        self.invalidate_stages(&base_ctx.job.project_id, &affected_stages).await?;

        // 3. Build an incremental execution context with only affected stages
        let mut job = base_ctx.job.clone();
        job.config.stages = affected_stages;
        job.config.incremental = true;

        let mut ctx = base_ctx.clone();
        ctx.job = job;
        ctx.previous_results.clear();

        // 4. Execute
        self.orchestrator.execute(ctx).await
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
                affected.extend([StageId::new("decompilation"), StageId::new("ai_enrichment")]);
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
    AnnotationAdded {
        function_id: FunctionId,
        annotation_type: String,
    },
    TypeChanged {
        function_id: FunctionId,
    },
    FunctionBoundaryChanged {
        function_id: FunctionId,
        old_boundary: FunctionBoundary,
        new_boundary: FunctionBoundary,
    },
    PluginUpdated {
        plugin_type: String,
    },
}

// Fingerprint-based Incremental Analysis (Alternative Implementation)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::RwLock;

/// Fingerprint for change detection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash: String,                                 // SHA256 of binary
    pub size: u64,                                    // File size
    pub modified: u64,                                // Modification timestamp
    pub stage_fingerprints: HashMap<StageId, String>, // Per-stage fingerprints
}

impl Fingerprint {
    pub fn from_binary(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)?;
        let bytes = std::fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = format!("{:x}", hasher.finalize());

        Ok(Self {
            hash,
            size: metadata.len(),
            modified: metadata
                .modified()
                .map_err(|e| {
                    openre_core::Error::Internal(anyhow::anyhow!(
                        "Failed to get modification time: {}",
                        e
                    ))
                })?
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| {
                    openre_core::Error::Internal(anyhow::anyhow!("Time conversion failed: {}", e))
                })?
                .as_secs(),
            stage_fingerprints: HashMap::new(),
        })
    }

    pub fn matches(&self, other: &Fingerprint) -> bool {
        self.hash == other.hash && self.size == other.size && self.modified == other.modified
    }

    pub fn stage_matches(&self, stage: &StageId, other: &Fingerprint) -> bool {
        self.stage_fingerprints.get(stage) == other.stage_fingerprints.get(stage)
    }
}

/// Incremental analysis cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalCache {
    fingerprints: HashMap<AnalysisId, Fingerprint>,
    stage_results: HashMap<AnalysisId, HashMap<StageId, CachedStageResult>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedStageResult {
    pub stage_id: StageId,
    pub status: String,
    pub data: serde_json::Value,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_ms: u64,
}

impl Default for IncrementalCache {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalCache {
    pub fn new() -> Self {
        Self { fingerprints: HashMap::new(), stage_results: HashMap::new() }
    }

    pub fn get_fingerprint(&self, analysis_id: &AnalysisId) -> Option<&Fingerprint> {
        self.fingerprints.get(analysis_id)
    }

    pub fn set_fingerprint(&mut self, analysis_id: AnalysisId, fingerprint: Fingerprint) {
        self.fingerprints.insert(analysis_id, fingerprint);
    }

    pub fn get_stage_result(
        &self,
        analysis_id: &AnalysisId,
        stage: &StageId,
    ) -> Option<&CachedStageResult> {
        self.stage_results.get(analysis_id)?.get(stage)
    }

    pub fn set_stage_result(
        &mut self,
        analysis_id: AnalysisId,
        stage: StageId,
        result: CachedStageResult,
    ) {
        self.stage_results.entry(analysis_id).or_default().insert(stage, result);
    }

    pub fn invalidate(&mut self, analysis_id: &AnalysisId) {
        self.fingerprints.remove(analysis_id);
        self.stage_results.remove(analysis_id);
    }

    pub fn invalidate_stage(&mut self, analysis_id: &AnalysisId, stage: &StageId) {
        if let Some(results) = self.stage_results.get_mut(analysis_id) {
            results.remove(stage);
        }
    }
}

/// Fingerprint-based Incremental Analyzer
pub struct FingerprintIncrementalAnalyzer {
    cache: Arc<RwLock<IncrementalCache>>,
    cache_dir: std::path::PathBuf,
}

impl FingerprintIncrementalAnalyzer {
    pub fn new(cache_dir: std::path::PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;

        let cache = if cache_dir.join("cache.json").exists() {
            let content = std::fs::read_to_string(cache_dir.join("cache.json"))?;
            serde_json::from_str(&content)?
        } else {
            IncrementalCache::new()
        };

        Ok(Self { cache: Arc::new(RwLock::new(cache)), cache_dir })
    }

    pub async fn analyze_if_changed(
        &self,
        analysis_id: AnalysisId,
        binary_path: &Path,
        analyzer: impl FnOnce() -> Result<HashMap<StageId, StageResult>> + Send,
    ) -> Result<HashMap<StageId, StageResult>> {
        let current_fp = Fingerprint::from_binary(binary_path)?;
        let cached_fp = self.cache.read().await.get_fingerprint(&analysis_id).cloned();

        if let Some(cached) = cached_fp {
            if cached.matches(&current_fp) {
                // Check if all stages are still cached (none invalidated)
                let cached_results =
                    self.cache.read().await.stage_results.get(&analysis_id).cloned();
                if let Some(cached_results) = cached_results {
                    // Check if the fingerprint has stage fingerprints that we can verify against
                    // For now, if any stage is missing from the cache, we should re-analyze
                    // Get the expected stages from the fingerprint
                    let expected_stages: Vec<StageId> =
                        cached.stage_fingerprints.keys().cloned().collect();
                    let all_stages_present =
                        expected_stages.iter().all(|s| cached_results.contains_key(s));

                    if all_stages_present {
                        // All stages present, return cached results
                        return Ok(cached_results
                            .into_iter()
                            .map(|(stage, _)| {
                                let stage_id = stage.clone();
                                (
                                    stage,
                                    StageResult {
                                        stage_id,
                                        status: StageStatus::Success,
                                        started_at: chrono::Utc::now(),
                                        completed_at: chrono::Utc::now(),
                                        output: serde_json::Value::Null,
                                        metrics: StageMetrics::default(),
                                        artifacts: Vec::new(),
                                    },
                                )
                            })
                            .collect());
                    }
                    // If any stage is missing, fall through to re-analyze
                }
            }
        }

        // Re-analyze (release lock before calling analyzer)
        let results = analyzer()?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.set_fingerprint(analysis_id, current_fp);
            for (stage, result) in &results {
                cache.set_stage_result(
                    analysis_id,
                    stage.clone(),
                    CachedStageResult {
                        stage_id: stage.clone(),
                        status: format!("{:?}", result.status),
                        data: result.output.clone(),
                        started_at: Some(result.started_at.to_rfc3339()),
                        completed_at: Some(result.completed_at.to_rfc3339()),
                        duration_ms: 0,
                    },
                );
            }
        }

        // Persist in background (don't block)
        let cache_dir = self.cache_dir.clone();
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let cache = cache.read().await.clone();
            let content = serde_json::to_string_pretty(&cache).ok();
            if let Some(content) = content {
                let _ = tokio::fs::write(cache_dir.join("cache.json"), content).await;
            }
        });

        Ok(results)
    }

    pub async fn invalidate(&self, analysis_id: &AnalysisId) {
        let mut cache = self.cache.write().await;
        cache.invalidate(analysis_id);
        // Persist in background
        let cache_dir = self.cache_dir.clone();
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let cache = cache.read().await.clone();
            let content = serde_json::to_string_pretty(&cache).ok();
            if let Some(content) = content {
                let _ = tokio::fs::write(cache_dir.join("cache.json"), content).await;
            }
        });
    }

    pub async fn invalidate_stage(&self, analysis_id: &AnalysisId, stage: &StageId) {
        let mut cache = self.cache.write().await;
        cache.invalidate_stage(analysis_id, stage);
        // Also invalidate the fingerprint so we re-analyze
        cache.fingerprints.remove(analysis_id);
        // Persist in background
        let cache_dir = self.cache_dir.clone();
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let cache = cache.read().await.clone();
            let content = serde_json::to_string_pretty(&cache).ok();
            if let Some(content) = content {
                let _ = tokio::fs::write(cache_dir.join("cache.json"), content).await;
            }
        });
    }
}
