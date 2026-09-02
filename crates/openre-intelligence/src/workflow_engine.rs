//! Investigation Workflow Engine - Orchestrate multi-stage security investigations

use crate::{
    correlation::CorrelationEngine,
    error::IntelligenceError,
    knowledge_base::KnowledgeBase,
    types::*,
    verification::VerificationEngine,
    IntelligenceResult,
};
use async_trait::async_trait;
use openre_core::evidence::VerificationStatus;
use openre_core::history::{
    InvestigationStageConfig, StageResult, StageStatus, WorkflowArtifact, WorkflowSession, WorkflowStatus,
    DiscoverConfig, AnalyzeConfig, CorrelateConfig, VerifyConfig, PrioritizeConfig, WorkflowReportConfig,
};
use openre_core::ids::{FindingId, ScanId, WorkflowId};
use openre_core::result::{Finding, Severity, Category};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

/// Investigation stages in the workflow with configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvestigationStage {
    /// Initial discovery and data gathering
    Discover(DiscoverConfig),
    /// Analysis of findings and evidence
    Analyze(AnalyzeConfig),
    /// Correlation of related findings
    Correlate(CorrelateConfig),
    /// Verification of findings
    Verify(VerifyConfig),
    /// Prioritization based on risk
    Prioritize(PrioritizeConfig),
    /// Final reporting
    Report(ReportConfig),
}

/// Alias for InvestigationStage for backwards compatibility
pub type WorkflowStage = InvestigationStage;

/// Report stage configuration (local variant, different from openre_core::history::WorkflowReportConfig)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Report format
    pub format: String,
    /// Include executive summary
    pub include_executive_summary: bool,
    /// Include technical details
    pub include_technical_details: bool,
    /// Include remediation guidance
    pub include_remediation: bool,
    /// Output directory
    pub output_dir: Option<String>,
}

impl InvestigationStage {
    /// Get all stages in order
    pub fn all() -> &'static [&'static str] {
        &[
            "discover",
            "analyze",
            "correlate",
            "verify",
            "prioritize",
            "report",
        ]
    }

    /// Get the stage name
    pub fn name(&self) -> &'static str {
        match self {
            InvestigationStage::Discover(_) => "discover",
            InvestigationStage::Analyze(_) => "analyze",
            InvestigationStage::Correlate(_) => "correlate",
            InvestigationStage::Verify(_) => "verify",
            InvestigationStage::Prioritize(_) => "prioritize",
            InvestigationStage::Report(_) => "report",
        }
    }

    /// Get the stage index
    pub fn index(&self) -> usize {
        match self {
            InvestigationStage::Discover(_) => 0,
            InvestigationStage::Analyze(_) => 1,
            InvestigationStage::Correlate(_) => 2,
            InvestigationStage::Verify(_) => 3,
            InvestigationStage::Prioritize(_) => 4,
            InvestigationStage::Report(_) => 5,
        }
    }

    /// Get the next stage
    pub fn next(&self) -> Option<InvestigationStage> {
        match self {
            InvestigationStage::Discover(_) => Some(InvestigationStage::Analyze(AnalyzeConfig::default())),
            InvestigationStage::Analyze(_) => Some(InvestigationStage::Correlate(CorrelateConfig::default())),
            InvestigationStage::Correlate(_) => Some(InvestigationStage::Verify(VerifyConfig::default())),
            InvestigationStage::Verify(_) => Some(InvestigationStage::Prioritize(PrioritizeConfig::default())),
            InvestigationStage::Prioritize(_) => Some(InvestigationStage::Report(ReportConfig::default())),
            InvestigationStage::Report(_) => None,
        }
    }

    /// Get the previous stage
    pub fn previous(&self) -> Option<InvestigationStage> {
        match self {
            InvestigationStage::Discover(_) => None,
            InvestigationStage::Analyze(_) => Some(InvestigationStage::Discover(DiscoverConfig::default())),
            InvestigationStage::Correlate(_) => Some(InvestigationStage::Analyze(AnalyzeConfig::default())),
            InvestigationStage::Verify(_) => Some(InvestigationStage::Correlate(CorrelateConfig::default())),
            InvestigationStage::Prioritize(_) => Some(InvestigationStage::Verify(VerifyConfig::default())),
            InvestigationStage::Report(_) => Some(InvestigationStage::Prioritize(PrioritizeConfig::default())),
        }
    }
}

/// Convert from config to stage for convenience
impl From<DiscoverConfig> for InvestigationStage {
    fn from(cfg: DiscoverConfig) -> Self {
        InvestigationStage::Discover(cfg)
    }
}

impl From<AnalyzeConfig> for InvestigationStage {
    fn from(cfg: AnalyzeConfig) -> Self {
        InvestigationStage::Analyze(cfg)
    }
}

impl From<CorrelateConfig> for InvestigationStage {
    fn from(cfg: CorrelateConfig) -> Self {
        InvestigationStage::Correlate(cfg)
    }
}

impl From<VerifyConfig> for InvestigationStage {
    fn from(cfg: VerifyConfig) -> Self {
        InvestigationStage::Verify(cfg)
    }
}

impl From<PrioritizeConfig> for InvestigationStage {
    fn from(cfg: PrioritizeConfig) -> Self {
        InvestigationStage::Prioritize(cfg)
    }
}

impl From<ReportConfig> for InvestigationStage {
    fn from(cfg: ReportConfig) -> Self {
        InvestigationStage::Report(cfg)
    }
}

/// Investigation workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationWorkflow {
    /// Workflow ID
    pub id: WorkflowId,
    /// Workflow name
    pub name: String,
    /// Stages in the workflow
    pub stages: Vec<InvestigationStage>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
    /// Workflow status
    pub status: WorkflowStatus,
    /// Current stage index
    pub current_stage: usize,
    /// Stage results
    pub stage_results: HashMap<usize, StageResult>,
    /// Artifacts generated during workflow
    pub artifacts: Vec<WorkflowArtifact>,
}

impl InvestigationWorkflow {
    /// Create a new investigation workflow
    pub fn new(name: String, stages: Vec<InvestigationStage>) -> Self {
        let now = Utc::now();
        Self {
            id: WorkflowId::new(),
            name,
            stages,
            created_at: now,
            updated_at: now,
            status: WorkflowStatus::Pending,
            current_stage: 0,
            stage_results: HashMap::new(),
            artifacts: Vec::new(),
        }
    }

    /// Create a default investigation workflow
    pub fn default_workflow(name: String) -> Self {
        let stages = vec![
            InvestigationStage::Discover(DiscoverConfig::default()),
            InvestigationStage::Analyze(AnalyzeConfig::default()),
            InvestigationStage::Correlate(CorrelateConfig::default()),
            InvestigationStage::Verify(VerifyConfig::default()),
            InvestigationStage::Prioritize(PrioritizeConfig::default()),
            InvestigationStage::Report(ReportConfig::default()),
        ];
        Self::new(name, stages)
    }

    /// Get the current stage
    pub fn current_stage(&self) -> Option<&InvestigationStage> {
        self.stages.get(self.current_stage)
    }

    /// Advance to the next stage
    pub fn advance_stage(&mut self) -> bool {
        if self.current_stage + 1 < self.stages.len() {
            self.current_stage += 1;
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Mark workflow as completed
    pub fn mark_completed(&mut self) {
        self.status = WorkflowStatus::Completed;
        self.updated_at = Utc::now();
    }

    /// Mark workflow as failed
    pub fn mark_failed(&mut self, error: String) {
        self.status = WorkflowStatus::Failed;
        self.updated_at = Utc::now();
    }

    /// Mark workflow as paused
    pub fn mark_paused(&mut self) {
        self.status = WorkflowStatus::Paused;
        self.updated_at = Utc::now();
    }

    /// Mark workflow as running
    pub fn mark_running(&mut self) {
        self.status = WorkflowStatus::Running;
        self.updated_at = Utc::now();
    }

    /// Convert to WorkflowSession for persistence
    pub fn to_session(&self) -> WorkflowSession {
        let mut config = HashMap::new();
        config.insert("name".to_string(), serde_json::to_value(&self.name).unwrap_or_default());

        WorkflowSession {
            id: self.id,
            name: self.name.clone(),
            target: String::new(), // Will be set by engine
            scan_id: None,
            stages: self.stages.iter().map(|s| s.clone().into()).collect(),
            current_stage_index: self.current_stage,
            status: self.status,
            stage_results: self.stage_results.clone(),
            artifacts: self.artifacts.clone(),
            config,
            error: None,
            created_at: self.created_at,
            updated_at: self.updated_at,
            completed_at: if self.status == WorkflowStatus::Completed { Some(self.updated_at) } else { None },
        }
    }
}

/// Convert InvestigationStage to InvestigationStageConfig for persistence
impl From<InvestigationStage> for InvestigationStageConfig {
    fn from(stage: InvestigationStage) -> Self {
        match stage {
            InvestigationStage::Discover(cfg) => InvestigationStageConfig::Discover(cfg),
            InvestigationStage::Analyze(cfg) => InvestigationStageConfig::Analyze(cfg),
            InvestigationStage::Correlate(cfg) => InvestigationStageConfig::Correlate(cfg),
            InvestigationStage::Verify(cfg) => InvestigationStageConfig::Verify(cfg),
            InvestigationStage::Prioritize(cfg) => InvestigationStageConfig::Prioritize(cfg),
            InvestigationStage::Report(cfg) => InvestigationStageConfig::Report(
                openre_core::history::WorkflowReportConfig {
                    format: cfg.format,
                    include_executive_summary: cfg.include_executive_summary,
                    include_technical_details: cfg.include_technical_details,
                    include_remediation: cfg.include_remediation,
                    output_dir: cfg.output_dir,
                }
            ),
        }
    }
}

/// Convert InvestigationStageConfig to InvestigationStage for execution
impl From<InvestigationStageConfig> for InvestigationStage {
    fn from(config: InvestigationStageConfig) -> Self {
        match config {
            InvestigationStageConfig::Discover(cfg) => InvestigationStage::Discover(cfg),
            InvestigationStageConfig::Analyze(cfg) => InvestigationStage::Analyze(cfg),
            InvestigationStageConfig::Correlate(cfg) => InvestigationStage::Correlate(cfg),
            InvestigationStageConfig::Verify(cfg) => InvestigationStage::Verify(cfg),
            InvestigationStageConfig::Prioritize(cfg) => InvestigationStage::Prioritize(cfg),
            InvestigationStageConfig::Report(cfg) => InvestigationStage::Report(ReportConfig {
                format: cfg.format,
                include_executive_summary: cfg.include_executive_summary,
                include_technical_details: cfg.include_technical_details,
                include_remediation: cfg.include_remediation,
                output_dir: cfg.output_dir,
            }),
        }
    }
}

/// Context passed between stages during execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvestigationContext {
    /// Target being investigated
    pub target: String,
    /// Scan ID (if associated with a scan)
    pub scan_id: Option<ScanId>,
    /// All findings discovered so far
    pub findings: Vec<Finding>,
    /// Stage results history
    pub stage_results: HashMap<usize, StageResult>,
    /// Configuration
    pub config: HashMap<String, serde_json::Value>,
    /// Shared state between stages
    pub shared_state: HashMap<String, serde_json::Value>,
    /// Cancellation token
    #[serde(skip)]
    pub cancellation_token: Arc<tokio::sync::Notify>,
    /// Paused state
    #[serde(skip)]
    pub paused: Arc<RwLock<bool>>,
}

impl InvestigationContext {
    /// Create a new investigation context
    pub fn new(target: String) -> Self {
        Self {
            target,
            scan_id: None,
            findings: Vec::new(),
            stage_results: HashMap::new(),
            config: HashMap::new(),
            shared_state: HashMap::new(),
            cancellation_token: Arc::new(tokio::sync::Notify::new()),
            paused: Arc::new(RwLock::new(false)),
        }
    }

    /// Request cancellation
    pub fn cancel(&self) {
        self.cancellation_token.notify_waiters();
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        // This is a simplified check - in practice you'd use a proper cancellation token
        false
    }

    /// Pause the investigation
    pub async fn pause(&self) {
        *self.paused.write().await = true;
    }

    /// Resume the investigation
    pub async fn resume(&self) {
        *self.paused.write().await = false;
    }

    /// Check if paused
    pub async fn is_paused(&self) -> bool {
        *self.paused.read().await
    }

    /// Wait if paused
    pub async fn wait_if_paused(&self) {
        let mut paused = self.paused.write().await;
        while *paused {
            drop(paused);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            paused = self.paused.write().await;
        }
    }
}

/// Trait for investigation stage handlers
#[async_trait]
pub trait InvestigationStageHandler: Send + Sync {
    /// Get the stage this handler handles
    fn stage_type(&self) -> &'static str;

    /// Get the stage index
    fn stage_index(&self) -> usize;

    /// Execute the stage
    async fn execute(&self, context: &mut InvestigationContext) -> IntelligenceResult<StageResult>;

    /// Check if this stage can run (preconditions)
    async fn can_run(&self, context: &InvestigationContext) -> bool {
        true // Default: can always run
    }

    /// Validate input before execution
    fn validate_input(&self, _context: &InvestigationContext) -> IntelligenceResult<()> {
        Ok(())
    }

    /// Estimate duration in seconds
    fn estimate_duration(&self, _context: &InvestigationContext) -> u64 {
        300 // 5 minutes default
    }

    /// Get stage configuration
    fn stage_config(&self) -> InvestigationStageConfig;
}

/// Default Discover stage handler
pub struct DiscoverStageHandler {
    pub scanner_agents: Vec<Arc<dyn ScannerAgent>>,
    pub config: DiscoverConfig,
}

impl DiscoverStageHandler {
    pub fn new(scanner_agents: Vec<Arc<dyn ScannerAgent>>, config: DiscoverConfig) -> Self {
        Self { scanner_agents, config }
    }
}

#[async_trait]
impl InvestigationStageHandler for DiscoverStageHandler {
    fn stage_type(&self) -> &'static str {
        "discover"
    }

    fn stage_index(&self) -> usize {
        0
    }

    fn stage_config(&self) -> InvestigationStageConfig {
        InvestigationStageConfig::Discover(self.config.clone())
    }

    async fn execute(&self, context: &mut InvestigationContext) -> IntelligenceResult<StageResult> {
        let started_at = Utc::now();
        let mut new_findings = Vec::new();

        for agent in &self.scanner_agents {
            // Check for cancellation
            context.cancellation_token.notified().await;

            match agent.scan(&context.target).await {
                Ok(findings) => new_findings.extend(findings),
                Err(e) => {
                    warn!("Scanner agent {} failed: {}", agent.name(), e);
                }
            }
        }

        context.findings.extend(new_findings.clone());

        let completed_at = Utc::now();
        Ok(StageResult {
            stage_index: self.stage_index(),
            status: StageStatus::Completed,
            input: serde_json::to_value(&context.target).unwrap_or_default(),
            output: serde_json::to_value(&new_findings).unwrap_or_default(),
            errors: Vec::new(),
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            started_at,
            completed_at: Some(completed_at),
        })
    }

    async fn can_run(&self, _context: &InvestigationContext) -> bool {
        true // Discover is always the first stage
    }
}

/// Scanner agent trait
#[async_trait]
pub trait ScannerAgent: Send + Sync {
    fn name(&self) -> &str;
    async fn scan(&self, target: &str) -> IntelligenceResult<Vec<Finding>>;
}

/// Default Analyze stage handler
pub struct AnalyzeStageHandler {
    pub knowledge_base: Arc<KnowledgeBase>,
    pub config: AnalyzeConfig,
}

impl AnalyzeStageHandler {
    pub fn new(knowledge_base: Arc<KnowledgeBase>, config: AnalyzeConfig) -> Self {
        Self { knowledge_base, config }
    }
}

#[async_trait]
impl InvestigationStageHandler for AnalyzeStageHandler {
    fn stage_type(&self) -> &'static str {
        "analyze"
    }

    fn stage_index(&self) -> usize {
        1
    }

    fn stage_config(&self) -> InvestigationStageConfig {
        InvestigationStageConfig::Analyze(self.config.clone())
    }

    async fn execute(&self, context: &mut InvestigationContext) -> IntelligenceResult<StageResult> {
        let started_at = Utc::now();
        let mut enriched_findings = Vec::new();

        for finding in &mut context.findings {
            context.cancellation_token.notified().await;

            if let Ok(Some(entry)) = self.knowledge_base.enrich_single_finding(finding) {
                enriched_findings.push(finding.clone());
            }
        }

        let completed_at = Utc::now();
        Ok(StageResult {
            stage_index: self.stage_index(),
            status: StageStatus::Completed,
            input: serde_json::to_value(&context.findings).unwrap_or_default(),
            output: serde_json::to_value(&enriched_findings).unwrap_or_default(),
            errors: Vec::new(),
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            started_at,
            completed_at: Some(completed_at),
        })
    }

    async fn can_run(&self, context: &InvestigationContext) -> bool {
        // Can run if Discover stage completed
        context.stage_results.get(&0).map(|r| r.status == StageStatus::Completed).unwrap_or(false)
    }
}

/// Default Correlate stage handler
pub struct CorrelateStageHandler {
    pub correlation_engine: Arc<CorrelationEngine>,
    pub config: CorrelateConfig,
}

impl CorrelateStageHandler {
    pub fn new(correlation_engine: Arc<CorrelationEngine>, config: CorrelateConfig) -> Self {
        Self { correlation_engine, config }
    }
}

#[async_trait]
impl InvestigationStageHandler for CorrelateStageHandler {
    fn stage_type(&self) -> &'static str {
        "correlate"
    }

    fn stage_index(&self) -> usize {
        2
    }

    fn stage_config(&self) -> InvestigationStageConfig {
        InvestigationStageConfig::Correlate(self.config.clone())
    }

    async fn execute(&self, context: &mut InvestigationContext) -> IntelligenceResult<StageResult> {
        let started_at = Utc::now();

        // Apply correlation configuration
        let mut engine = (*self.correlation_engine).clone();
        // Note: In practice, you'd apply the config to the engine

        let finding_relationships = self.correlation_engine.correlate_findings(&context.findings).await?;

        // Convert FindingRelationship to EnhancedCorrelation
        let correlations: Vec<EnhancedCorrelation> = finding_relationships.into_iter().map(|rel| {
            EnhancedCorrelation {
                finding_ids: vec![rel.source_finding, rel.target_finding],
                correlation_type: match rel.relationship_type {
                    openre_core::relationships::FindingRelationshipType::Enables => CorrelationType::Enables,
                    openre_core::relationships::FindingRelationshipType::Amplifies => CorrelationType::Strengthening,
                    openre_core::relationships::FindingRelationshipType::Requires => CorrelationType::Requires,
                    openre_core::relationships::FindingRelationshipType::SameRootCause => CorrelationType::SameRootCause,
                    openre_core::relationships::FindingRelationshipType::ChainedExploit => CorrelationType::ChainedExploit,
                    openre_core::relationships::FindingRelationshipType::Mitigates => CorrelationType::Mitigates,
                    openre_core::relationships::FindingRelationshipType::Duplicate => CorrelationType::Duplicate,
                    openre_core::relationships::FindingRelationshipType::SharedComponent => CorrelationType::SharedComponent,
                    openre_core::relationships::FindingRelationshipType::SharedAttackSurface => CorrelationType::SharedAttackSurface,
                    openre_core::relationships::FindingRelationshipType::InformationLeakage => CorrelationType::InformationLeakage,
                    openre_core::relationships::FindingRelationshipType::PrivilegeEscalation => CorrelationType::PrivilegeEscalation,
                    openre_core::relationships::FindingRelationshipType::LateralMovement => CorrelationType::LateralMovement,
                    openre_core::relationships::FindingRelationshipType::DataExfiltration => CorrelationType::DataExfiltration,
                    openre_core::relationships::FindingRelationshipType::Prerequisite => CorrelationType::Prerequisite,
                    openre_core::relationships::FindingRelationshipType::MutuallyExclusive => CorrelationType::MutuallyExclusive,
                    openre_core::relationships::FindingRelationshipType::Temporal => CorrelationType::Temporal,
                    openre_core::relationships::FindingRelationshipType::Spatial => CorrelationType::Spatial,
                    openre_core::relationships::FindingRelationshipType::Custom => CorrelationType::Custom,
                },
                confidence: rel.confidence,
                description: rel.explanation,
                evidence: rel.evidence.iter().map(|e| e.description.clone()).collect(),
                combined_risk: RiskAssessment {
                    individual_scores: vec![],
                    combined_score: 0,
                    explanation: String::new(),
                },
                mitigation_approach: String::new(),
            }
        }).collect();

        let completed_at = Utc::now();
        Ok(StageResult {
            stage_index: self.stage_index(),
            status: StageStatus::Completed,
            input: serde_json::to_value(&context.findings).unwrap_or_default(),
            output: serde_json::to_value(&correlations).unwrap_or_default(),
            errors: Vec::new(),
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            started_at,
            completed_at: Some(completed_at),
        })
    }

    async fn can_run(&self, context: &InvestigationContext) -> bool {
        // Can run if Analyze stage completed
        context.stage_results.get(&1).map(|r| r.status == StageStatus::Completed).unwrap_or(false)
    }
}

/// Default Verify stage handler
pub struct VerifyStageHandler {
    pub verification_engine: Arc<VerificationEngine>,
    pub http_client: Arc<Client>,
    pub config: VerifyConfig,
}

impl VerifyStageHandler {
    pub fn new(verification_engine: Arc<VerificationEngine>, http_client: Arc<Client>, config: VerifyConfig) -> Self {
        Self { verification_engine, http_client, config }
    }
}

#[async_trait]
impl InvestigationStageHandler for VerifyStageHandler {
    fn stage_type(&self) -> &'static str {
        "verify"
    }

    fn stage_index(&self) -> usize {
        3
    }

    fn stage_config(&self) -> InvestigationStageConfig {
        InvestigationStageConfig::Verify(self.config.clone())
    }

    async fn execute(&self, context: &mut InvestigationContext) -> IntelligenceResult<StageResult> {
        let started_at = Utc::now();
        let mut verification_results = Vec::new();

        for finding in &context.findings {
            context.cancellation_token.notified().await;
            context.wait_if_paused().await;

            match self.verification_engine.verify_finding(finding).await {
                Ok(evidence_result) => {
                    // Convert evidence VerificationResult to workflow_engine VerificationResult
                    let workflow_result = VerificationResult {
                        finding_id: evidence_result.finding_id,
                        verified: matches!(evidence_result.status, VerificationStatus::Confirmed | VerificationStatus::Likely),
                        confidence: evidence_result.confidence,
                        evidence: vec![evidence_result.notes],
                        false_positive: matches!(evidence_result.status, VerificationStatus::NotReproducible),
                    };
                    verification_results.push(workflow_result);
                }
                Err(e) => {
                    warn!("Verification failed for finding {}: {}", finding.id, e);
                }
            }
        }

        let completed_at = Utc::now();
        Ok(StageResult {
            stage_index: self.stage_index(),
            status: StageStatus::Completed,
            input: serde_json::to_value(&context.findings).unwrap_or_default(),
            output: serde_json::to_value(&verification_results).unwrap_or_default(),
            errors: Vec::new(),
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            started_at,
            completed_at: Some(completed_at),
        })
    }

    async fn can_run(&self, context: &InvestigationContext) -> bool {
        // Can run if Correlate stage completed
        context.stage_results.get(&2).map(|r| r.status == StageStatus::Completed).unwrap_or(false)
    }
}

/// Verification result for workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub finding_id: FindingId,
    pub verified: bool,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub false_positive: bool,
}

/// Default Prioritize stage handler
pub struct PrioritizeStageHandler {
    pub risk_scorer: Arc<dyn RiskScorer>,
    pub config: PrioritizeConfig,
}

impl PrioritizeStageHandler {
    pub fn new(risk_scorer: Arc<dyn RiskScorer>, config: PrioritizeConfig) -> Self {
        Self { risk_scorer, config }
    }
}

#[async_trait]
impl InvestigationStageHandler for PrioritizeStageHandler {
    fn stage_type(&self) -> &'static str {
        "prioritize"
    }

    fn stage_index(&self) -> usize {
        4
    }

    fn stage_config(&self) -> InvestigationStageConfig {
        InvestigationStageConfig::Prioritize(self.config.clone())
    }

    async fn execute(&self, context: &mut InvestigationContext) -> IntelligenceResult<StageResult> {
        let started_at = Utc::now();
        let mut prioritized_findings = Vec::new();

        for finding in &context.findings {
            context.cancellation_token.notified().await;
            context.wait_if_paused().await;

            let risk_score = self.risk_scorer.calculate_risk_score(finding).await?;
            let priority = match risk_score {
                86..=100 => PrioritizationLevel::Critical,
                61..=85 => PrioritizationLevel::High,
                36..=60 => PrioritizationLevel::Medium,
                16..=35 => PrioritizationLevel::Low,
                _ => PrioritizationLevel::Informational,
            };

            prioritized_findings.push(PrioritizedFinding {
                finding_id: finding.id,
                priority,
                risk_score,
                rationale: format!("Risk score: {} ({})", risk_score, priority),
            });
        }

        // Sort by priority (highest first)
        prioritized_findings.sort_by(|a, b| b.priority.cmp(&a.priority).then(b.risk_score.cmp(&a.risk_score)));

        let completed_at = Utc::now();
        Ok(StageResult {
            stage_index: self.stage_index(),
            status: StageStatus::Completed,
            input: serde_json::to_value(&context.findings).unwrap_or_default(),
            output: serde_json::to_value(&prioritized_findings).unwrap_or_default(),
            errors: Vec::new(),
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            started_at,
            completed_at: Some(completed_at),
        })
    }

    async fn can_run(&self, context: &InvestigationContext) -> bool {
        // Can run if Verify stage completed
        context.stage_results.get(&3).map(|r| r.status == StageStatus::Completed).unwrap_or(false)
    }
}

/// Prioritization levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrioritizationLevel {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for PrioritizationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrioritizationLevel::Critical => write!(f, "Critical"),
            PrioritizationLevel::High => write!(f, "High"),
            PrioritizationLevel::Medium => write!(f, "Medium"),
            PrioritizationLevel::Low => write!(f, "Low"),
            PrioritizationLevel::Informational => write!(f, "Informational"),
        }
    }
}

/// Prioritized finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedFinding {
    pub finding_id: FindingId,
    pub priority: PrioritizationLevel,
    pub risk_score: u8,
    pub rationale: String,
}

/// Risk scorer trait
#[async_trait]
pub trait RiskScorer: Send + Sync {
    async fn calculate_risk_score(&self, finding: &Finding) -> IntelligenceResult<u8>;
}

/// Default Report stage handler
pub struct ReportStageHandler {
    pub config: ReportConfig,
}

impl ReportStageHandler {
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl InvestigationStageHandler for ReportStageHandler {
    fn stage_type(&self) -> &'static str {
        "report"
    }

    fn stage_index(&self) -> usize {
        5
    }

    fn stage_config(&self) -> InvestigationStageConfig {
        InvestigationStageConfig::Report(
            openre_core::history::WorkflowReportConfig {
                format: self.config.format.clone(),
                include_executive_summary: self.config.include_executive_summary,
                include_technical_details: self.config.include_technical_details,
                include_remediation: self.config.include_remediation,
                output_dir: self.config.output_dir.clone(),
            }
        )
    }

    async fn execute(&self, context: &mut InvestigationContext) -> IntelligenceResult<StageResult> {
        let started_at = Utc::now();

        // Get prioritized findings from previous stage
        let prioritized = context.stage_results.get(&4)
            .map(|r| r.output.clone())
            .and_then(|v| serde_json::from_value::<Vec<PrioritizedFinding>>(v).ok())
            .unwrap_or_default();

        // Get verification results
        let verified = context.stage_results.get(&3)
            .map(|r| r.output.clone())
            .and_then(|v| serde_json::from_value::<Vec<VerificationResult>>(v).ok())
            .unwrap_or_default();

        // Build summary
        let mut findings_by_severity = HashMap::new();
        for finding in &context.findings {
            *findings_by_severity.entry(finding.severity).or_insert(0) += 1;
        }

        let report = InvestigationReport {
            investigation_id: Uuid::new_v4(),
            target: context.target.clone(),
            scan_id: context.scan_id,
            summary: format!(
                "Investigation of {} found {} findings ({} verified)",
                context.target,
                context.findings.len(),
                verified.iter().filter(|v| v.verified).count()
            ),
            findings_by_severity,
            top_risks: prioritized.into_iter().take(10).collect(),
            recommendations: vec![
                "Review and remediate critical findings first".to_string(),
                "Implement secure coding practices".to_string(),
                "Enable security monitoring".to_string(),
            ],
            generated_at: Utc::now(),
        };

        let completed_at = Utc::now();
        Ok(StageResult {
            stage_index: self.stage_index(),
            status: StageStatus::Completed,
            input: serde_json::to_value(&context.findings).unwrap_or_default(),
            output: serde_json::to_value(&report).unwrap_or_default(),
            errors: Vec::new(),
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            started_at,
            completed_at: Some(completed_at),
        })
    }

    async fn can_run(&self, context: &InvestigationContext) -> bool {
        // Can run if Prioritize stage completed
        context.stage_results.get(&4).map(|r| r.status == StageStatus::Completed).unwrap_or(false)
    }
}

/// Investigation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationReport {
    pub investigation_id: Uuid,
    pub target: String,
    pub scan_id: Option<ScanId>,
    pub summary: String,
    pub findings_by_severity: HashMap<Severity, usize>,
    pub top_risks: Vec<PrioritizedFinding>,
    pub recommendations: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

/// Default risk scorer implementation
struct DefaultRiskScorer;

#[async_trait]
impl RiskScorer for DefaultRiskScorer {
    async fn calculate_risk_score(&self, finding: &Finding) -> IntelligenceResult<u8> {
        let base_score = finding.calculate_risk_score();

        // Adjust based on exploitability
        let exploitability_bonus = finding.exploitability.as_ref()
            .map(|e| (e.score / 10.0 * 20.0) as u8)
            .unwrap_or(0);

        // Adjust based on business impact
        let impact_bonus = finding.business_impact.as_ref()
            .map(|b| (b.score / 10.0 * 15.0) as u8)
            .unwrap_or(0);

        // Adjust based on asset criticality
        let asset_bonus = finding.business_impact.as_ref()
            .map(|b| match b.asset_criticality {
                openre_core::result::AssetCriticality::Critical => 15,
                openre_core::result::AssetCriticality::High => 10,
                openre_core::result::AssetCriticality::Medium => 5,
                openre_core::result::AssetCriticality::Low => 0,
            })
            .unwrap_or(0);

        Ok((base_score as u16 + exploitability_bonus as u16 + impact_bonus as u16 + asset_bonus as u16).min(100) as u8)
    }
}

/// Investigation workflow engine configuration
#[derive(Clone)]
pub struct WorkflowEngineConfig {
    /// Whether to continue on stage failure
    pub continue_on_failure: bool,
    /// Maximum number of retries for failed stages
    pub max_retries: u32,
    /// Timeout for each stage in seconds
    pub stage_timeout_seconds: u64,
    /// Enable checkpointing after each stage
    pub enable_checkpointing: bool,
    /// Storage for persistence (optional)
    pub storage: Option<Arc<dyn openre_core::history::HistoryStorage>>,
}

impl Default for WorkflowEngineConfig {
    fn default() -> Self {
        Self {
            continue_on_failure: false,
            max_retries: 2,
            stage_timeout_seconds: 300,
            enable_checkpointing: true,
            storage: None,
        }
    }
}

/// Investigation workflow engine
pub struct InvestigationWorkflowEngine {
    handlers: Vec<Arc<dyn InvestigationStageHandler>>,
    config: WorkflowEngineConfig,
    /// Progress sender for real-time updates
    progress_tx: Option<mpsc::UnboundedSender<WorkflowProgress>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowProgress {
    pub workflow_id: WorkflowId,
    pub stage_index: usize,
    pub stage_name: String,
    pub status: StageStatus,
    pub progress: f32,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl InvestigationWorkflowEngine {
    /// Create a new workflow engine with default handlers
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            config: WorkflowEngineConfig::default(),
            progress_tx: None,
        }
    }

    /// Create with custom config
    pub fn with_config(config: WorkflowEngineConfig) -> Self {
        Self {
            handlers: Vec::new(),
            config,
            progress_tx: None,
        }
    }

    /// Set progress sender
    pub fn with_progress_sender(mut self, tx: mpsc::UnboundedSender<WorkflowProgress>) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    /// Add a stage handler
    pub fn add_handler(&mut self, handler: Arc<dyn InvestigationStageHandler>) {
        self.handlers.push(handler);
    }

    /// Add default handlers
    pub fn add_default_handlers(
        &mut self,
        knowledge_base: Arc<KnowledgeBase>,
        correlation_engine: Arc<CorrelationEngine>,
        verification_engine: Arc<VerificationEngine>,
        http_client: Arc<Client>,
    ) {
        self.add_handler(Arc::new(AnalyzeStageHandler::new(knowledge_base, AnalyzeConfig::default())));
        self.add_handler(Arc::new(CorrelateStageHandler::new(correlation_engine, CorrelateConfig::default())));
        self.add_handler(Arc::new(VerifyStageHandler::new(verification_engine, http_client, VerifyConfig::default())));
        self.add_handler(Arc::new(PrioritizeStageHandler::new(Arc::new(DefaultRiskScorer), PrioritizeConfig::default())));
        self.add_handler(Arc::new(ReportStageHandler::new(ReportConfig::default())));
    }

    /// Execute the full investigation workflow
    pub async fn execute(
        &self,
        workflow: &mut InvestigationWorkflow,
        target: String,
        initial_findings: Vec<Finding>,
    ) -> IntelligenceResult<InvestigationContext> {
        let mut context = InvestigationContext::new(target);
        context.findings = initial_findings;

        // Sort handlers by stage order
        let mut sorted_handlers = self.handlers.clone();
        sorted_handlers.sort_by_key(|h| h.stage_index());

        workflow.mark_running();

        let total_stages = sorted_handlers.len();

        // Save initial checkpoint
        if self.config.enable_checkpointing {
            if let Some(storage) = &self.config.storage {
                let mut session = workflow.to_session();
                session.target = context.target.clone();
                session.scan_id = context.scan_id;
                session.status = WorkflowStatus::Running;
                let _ = storage.save_workflow_session(&session).await;
            }
        }

        for handler in sorted_handlers {
            let stage_index = handler.stage_index();
            let stage_name = handler.stage_type().to_string();

            // Check if we can run this stage
            if !handler.can_run(&context).await {
                warn!("Skipping stage {} - preconditions not met", stage_name);
                continue;
            }

            // Validate input
            if let Err(e) = handler.validate_input(&context) {
                error!("Input validation failed for stage {}: {}", stage_name, e);
                let result = StageResult {
                    stage_index,
                    status: StageStatus::Failed,
                    input: serde_json::Value::Null,
                    output: serde_json::Value::Null,
                    errors: vec![e.to_string()],
                    duration_ms: 0,
                    started_at: Utc::now(),
                    completed_at: Some(Utc::now()),
                };
                context.stage_results.insert(stage_index, result);

                if !self.config.continue_on_failure {
                    workflow.mark_failed(e.to_string());
                    return Err(e);
                }
                continue;
            }

            info!("Executing stage: {}", stage_name);
            workflow.current_stage = stage_index;
            workflow.status = WorkflowStatus::Running;

            // Send progress update
            if let Some(tx) = &self.progress_tx {
                let _ = tx.send(WorkflowProgress {
                    workflow_id: workflow.id,
                    stage_index,
                    stage_name: stage_name.clone(),
                    status: StageStatus::Running,
                    progress: stage_index as f32 / total_stages as f32,
                    message: format!("Executing stage: {}", stage_name),
                    timestamp: Utc::now(),
                });
            }

            // Execute with timeout and retries
            let mut result = None;
            let mut last_error = None;

            for attempt in 0..=self.config.max_retries {
                let timeout = tokio::time::Duration::from_secs(self.config.stage_timeout_seconds);
                let exec_future = handler.execute(&mut context);

                match tokio::time::timeout(timeout, exec_future).await {
                    Ok(Ok(r)) => {
                        result = Some(r);
                        break;
                    }
                    Ok(Err(e)) => {
                        last_error = Some(e);
                        warn!("Stage {} attempt {} failed: {}", stage_name, attempt + 1, last_error.as_ref().unwrap());
                        if attempt < self.config.max_retries {
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        }
                    }
                    Err(_) => {
                        last_error = Some(IntelligenceError::WorkflowFeatureDisabled("stage timeout".to_string()));
                        warn!("Stage {} attempt {} timed out", stage_name, attempt + 1);
                        if attempt < self.config.max_retries {
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        }
                    }
                }
            }

            let result = match result {
                Some(r) => r,
                None => {
                    let error_msg = last_error.unwrap_or_else(|| IntelligenceError::WorkflowFeatureDisabled("stage failed after retries".to_string())).to_string();
                    StageResult {
                        stage_index,
                        status: StageStatus::Failed,
                        input: serde_json::Value::Null,
                        output: serde_json::Value::Null,
                        errors: vec![error_msg.clone()],
                        duration_ms: 0,
                        started_at: Utc::now(),
                        completed_at: Some(Utc::now()),
                    }
                }
            };

            // Store stage result
            context.stage_results.insert(stage_index, result.clone());
            workflow.stage_results.insert(stage_index, result.clone());

            // Send progress update
            if let Some(tx) = &self.progress_tx {
                let _ = tx.send(WorkflowProgress {
                    workflow_id: workflow.id,
                    stage_index,
                    stage_name: stage_name.clone(),
                    status: result.status,
                    progress: (stage_index + 1) as f32 / total_stages as f32,
                    message: match result.status {
                        StageStatus::Completed => format!("Stage {} completed", stage_name),
                        StageStatus::Failed => format!("Stage {} failed: {:?}", stage_name, result.errors),
                        _ => format!("Stage {} finished", stage_name),
                    },
                    timestamp: Utc::now(),
                });
            }

            // Checkpoint after each stage
            if self.config.enable_checkpointing && result.status == StageStatus::Completed {
                if let Some(storage) = &self.config.storage {
                    let mut session = workflow.to_session();
                    session.target = context.target.clone();
                    session.scan_id = context.scan_id;
                    session.stage_results = workflow.stage_results.clone();
                    let _ = storage.save_workflow_session(&session).await;
                }
            }

            // Handle failure
            if result.status == StageStatus::Failed && !self.config.continue_on_failure {
                workflow.mark_failed(result.errors.join("; "));
                return Err(IntelligenceError::WorkflowFeatureDisabled(result.errors.join("; ")));
            }
        }

        // Mark workflow as completed
        workflow.mark_completed();
        workflow.updated_at = Utc::now();

        // Final checkpoint
        if self.config.enable_checkpointing {
            if let Some(storage) = &self.config.storage {
                let mut session = workflow.to_session();
                session.target = context.target.clone();
                session.scan_id = context.scan_id;
                session.stage_results = workflow.stage_results.clone();
                session.status = WorkflowStatus::Completed;
                session.completed_at = Some(Utc::now());
                let _ = storage.save_workflow_session(&session).await;
            }
        }

        Ok(context)
    }

    /// Resume workflow from a specific stage
    pub async fn resume_from_stage(
        &self,
        workflow: &mut InvestigationWorkflow,
        target: String,
        initial_findings: Vec<Finding>,
        from_stage: usize,
    ) -> IntelligenceResult<InvestigationContext> {
        let mut context = InvestigationContext::new(target);
        context.findings = initial_findings;

        // Restore stage results from workflow
        context.stage_results = workflow.stage_results.clone();

        // Sort handlers by stage order
        let mut sorted_handlers = self.handlers.clone();
        sorted_handlers.sort_by_key(|h| h.stage_index());

        workflow.mark_running();

        // Execute from the specified stage
        for handler in sorted_handlers.into_iter().skip(from_stage) {
            let stage_index = handler.stage_index();
            let stage_name = handler.stage_type().to_string();

            // Check if we can run this stage
            if !handler.can_run(&context).await {
                warn!("Skipping stage {} - preconditions not met", stage_name);
                continue;
            }

            info!("Resuming stage: {}", stage_name);
            workflow.current_stage = stage_index;

            // Execute with timeout and retries (same logic as execute)
            let mut result = None;
            let mut last_error = None;

            for attempt in 0..=self.config.max_retries {
                let timeout = tokio::time::Duration::from_secs(self.config.stage_timeout_seconds);
                let exec_future = handler.execute(&mut context);

                match tokio::time::timeout(timeout, exec_future).await {
                    Ok(Ok(r)) => {
                        result = Some(r);
                        break;
                    }
                    Ok(Err(e)) => {
                        last_error = Some(e);
                        if attempt < self.config.max_retries {
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        }
                    }
                    Err(_) => {
                        last_error = Some(IntelligenceError::WorkflowFeatureDisabled("stage timeout".to_string()));
                        if attempt < self.config.max_retries {
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        }
                    }
                }
            }

            let result = match result {
                Some(r) => r,
                None => {
                    let error_msg = last_error.unwrap_or_else(|| IntelligenceError::WorkflowFeatureDisabled("stage failed after retries".to_string())).to_string();
                    StageResult {
                        stage_index,
                        status: StageStatus::Failed,
                        input: serde_json::Value::Null,
                        output: serde_json::Value::Null,
                        errors: vec![error_msg.clone()],
                        duration_ms: 0,
                        started_at: Utc::now(),
                        completed_at: Some(Utc::now()),
                    }
                }
            };

            context.stage_results.insert(stage_index, result.clone());
            workflow.stage_results.insert(stage_index, result.clone());

            // Checkpoint after each stage
            if self.config.enable_checkpointing && result.status == StageStatus::Completed {
                if let Some(storage) = &self.config.storage {
                    let mut session = workflow.to_session();
                    session.target = context.target.clone();
                    session.scan_id = context.scan_id;
                    session.stage_results = workflow.stage_results.clone();
                    let _ = storage.save_workflow_session(&session).await;
                }
            }

            if result.status == StageStatus::Failed && !self.config.continue_on_failure {
                workflow.mark_failed(result.errors.join("; "));
                return Err(IntelligenceError::WorkflowFeatureDisabled(result.errors.join("; ")));
            }
        }

        workflow.mark_completed();
        Ok(context)
    }

    /// Pause the workflow
    pub async fn pause(&self, context: &InvestigationContext) {
        context.pause().await;
    }

    /// Resume the workflow
    pub async fn resume(&self, context: &InvestigationContext) {
        context.resume().await;
    }

    /// Cancel the workflow
    pub fn cancel(&self, context: &InvestigationContext) {
        context.cancel();
    }

    /// Load workflow from storage
    pub async fn load_workflow(&self, workflow_id: &WorkflowId) -> IntelligenceResult<Option<InvestigationWorkflow>> {
        if let Some(storage) = &self.config.storage {
            let session = storage.get_workflow_session(workflow_id).await?;
            if let Some(session) = session {
                let mut workflow = InvestigationWorkflow::new(session.name, session.stages.iter().map(|s| s.clone().into()).collect());
                workflow.id = session.id;
                workflow.current_stage = session.current_stage_index;
                workflow.status = session.status;
                workflow.stage_results = session.stage_results;
                workflow.artifacts = session.artifacts;
                workflow.created_at = session.created_at;
                workflow.updated_at = session.updated_at;
                return Ok(Some(workflow));
            }
        }
        Ok(None)
    }

    /// Save workflow to storage
    pub async fn save_workflow(&self, workflow: &InvestigationWorkflow) -> IntelligenceResult<()> {
        if let Some(storage) = &self.config.storage {
            let mut session = workflow.to_session();
            storage.save_workflow_session(&session).await?;
        }
        Ok(())
    }

    /// Get workflow status
    pub fn get_status(&self, workflow: &InvestigationWorkflow) -> WorkflowStatus {
        workflow.status
    }

    /// List workflows from storage
    pub async fn list_workflows(
        &self,
        scan_id: Option<ScanId>,
        status: Option<WorkflowStatus>,
        limit: usize,
        offset: usize,
    ) -> IntelligenceResult<Vec<WorkflowSession>> {
        if let Some(storage) = &self.config.storage {
            storage.list_workflow_sessions(scan_id, status, limit, offset).await
                .map_err(|e| IntelligenceError::Storage(e.to_string()))
        } else {
            Ok(Vec::new())
        }
    }
}

impl Default for InvestigationWorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId, WorkflowId};
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use std::collections::HashMap;

    fn create_test_finding(title: &str, category: Category, severity: Severity) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity,
            confidence: Confidence::High,
            category,
            target: "https://example.com".to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: Some(60),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some("test-fingerprint".to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[tokio::test]
    async fn test_workflow_creation() {
        let workflow = InvestigationWorkflow::default_workflow("Test Workflow".to_string());
        assert_eq!(workflow.stages.len(), 6);
        assert_eq!(workflow.name, "Test Workflow");
        assert_eq!(workflow.status, WorkflowStatus::Pending);
    }

    #[tokio::test]
    async fn test_stage_order() {
        let discover = InvestigationStage::Discover(DiscoverConfig::default());
        let analyze = InvestigationStage::Analyze(AnalyzeConfig::default());
        let correlate = InvestigationStage::Correlate(CorrelateConfig::default());
        let verify = InvestigationStage::Verify(VerifyConfig::default());
        let prioritize = InvestigationStage::Prioritize(PrioritizeConfig::default());
        let report = InvestigationStage::Report(ReportConfig::default());

        assert_eq!(discover.index(), 0);
        assert_eq!(analyze.index(), 1);
        assert_eq!(correlate.index(), 2);
        assert_eq!(verify.index(), 3);
        assert_eq!(prioritize.index(), 4);
        assert_eq!(report.index(), 5);
    }

    #[tokio::test]
    async fn test_workflow_advance() {
        let mut workflow = InvestigationWorkflow::default_workflow("Test".to_string());
        assert_eq!(workflow.current_stage, 0);
        assert!(workflow.advance_stage());
        assert_eq!(workflow.current_stage, 1);

        for _ in 0..4 {
            workflow.advance_stage();
        }
        assert_eq!(workflow.current_stage, 5);
        assert!(!workflow.advance_stage());
    }

    #[tokio::test]
    async fn test_investigation_context() {
        let ctx = InvestigationContext::new("https://example.com".to_string());
        assert_eq!(ctx.target, "https://example.com");
        assert!(!ctx.is_cancelled());
    }
}