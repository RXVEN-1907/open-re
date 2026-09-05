//! Intelligence layer for open-re security scanner
//!
//! This crate provides advanced intelligence capabilities including:
//! - Enhanced finding correlation and relationship analysis
//! - CVE matching against vulnerability databases
//! - Dependency analysis for outdated/vulnerable packages
//! - Security knowledge base with CWE/OWASP/CAPEC mapping
//! - Root cause analysis for underlying issues
//! - Scan diff intelligence for change tracking
//! - Developer workflow enhancements
//! - Performance optimizations with caching and incremental processing
//! - TUI enhancements for improved developer experience
//! - Attack path analysis and exploitation chain building
//! - Finding verification framework
//! - Remediation verification
//! - Enhanced risk scoring
//! - Investigation workflow engine

pub mod agents;
pub mod attack_path;
pub mod correlation;
pub mod cve_intelligence;
pub mod dependency_analysis;
pub mod error;
pub mod job;
pub mod knowledge_base;
pub mod performance;
pub mod remediation;
pub mod root_cause;
pub mod scan_diff;
pub mod tui_enhancements;
pub mod types;
pub mod verification;
pub mod workflow;
pub mod workflow_engine;

#[cfg(test)]
mod comprehensive_test;

// Re-export main components
pub use agents::{
    AgentCapability, AgentCoordinator, AgentContext, AgentHealth, AgentMetadata,
    AgentResult, AgentStatus, AgentTask, AgentTaskResult, AgentType, AgentWorkflowBuilder,
    AiService, BaseAgent, CancellationToken, CoordinatorConfig, CoordinatorStats,
    CorrelationAgent, RemediationAgent, ReconAgent, ReportingAgent, ResearchAgent,
    ScanStorage, SecurityAgent, TelemetryHandle, VerificationAgent, WebAnalysisAgent,
    WorkflowSession, create_investigation_workflow,
    // Context types (re-exported from context)
    ReconInput, ReconOutput, DiscoveredUrl, DiscoveredEndpoint, DetectedTechnology,
    AuthEndpoint, DiscoveredForm, FormField, EndpointParameter,
    WebAnalysisInput, WebAnalysisOutput, ClientSideIssue,
    ApiAnalysisInput, ApiAnalysisOutput, ApiEndpoint, SchemaIssue,
    CorrelationInput, CorrelationOutput,
    VerificationInput, VerificationOutput,
    RemediationInput, RemediationOutput, RemediationSuggestion,
    ReportingInput, ReportingOutput, ReportMetadata,
    ResearchInput, ResearchOutput,
    // Traits
    AgentInput, AgentOutput,
};
pub use attack_path::{
    map_findings_to_attack_techniques, AttackPathAnalyzer, AttackPathBuilder, AttackPathStatistics,
};
pub use correlation::CorrelationEngine;
pub use cve_intelligence::{CveIntelligence, CveProvider};
pub use dependency_analysis::DependencyAnalyzer;
pub use error::IntelligenceError;
pub use knowledge_base::KnowledgeBase;
pub use performance::PerformanceOptimizer;
pub use remediation::RemediationVerifier;
pub use root_cause::RootCauseAnalyzer;
pub use scan_diff::ScanDiffAnalyzer;
pub use tui_enhancements::TuiEnhancer;
pub use scan_diff::ScanData;
pub use verification::VerificationEngine;
pub use workflow::WorkflowManager;
pub use types::{CorrelationType, EnhancedCorrelation, RiskAssessment};
pub use workflow_engine::{
    InvestigationStage, InvestigationStageHandler, InvestigationWorkflow,
    InvestigationWorkflowEngine, WorkflowEngineConfig, WorkflowProgress,
    WorkflowStage, PrioritizedFinding, VerificationResult,
    InvestigationReport, InvestigationContext, RiskScorer, ScannerAgent,
    DiscoverStageHandler, AnalyzeStageHandler, CorrelateStageHandler,
    VerifyStageHandler, PrioritizeStageHandler, ReportStageHandler,
};
pub use openre_core::history::{
    InvestigationStageConfig, StageResult, StageStatus, WorkflowArtifact, WorkflowStatus,
    DiscoverConfig, AnalyzeConfig, CorrelateConfig, VerifyConfig, PrioritizeConfig, WorkflowReportConfig,
};

/// Intelligence module result type
pub type IntelligenceResult<T> = Result<T, error::IntelligenceError>;
