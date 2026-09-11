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
    create_investigation_workflow,
    AgentCapability,
    AgentContext,
    AgentCoordinator,
    AgentHealth,
    // Traits
    AgentInput,
    AgentMetadata,
    AgentOutput,
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentTaskResult,
    AgentType,
    AgentWorkflowBuilder,
    AiService,
    ApiAnalysisInput,
    ApiAnalysisOutput,
    ApiEndpoint,
    AuthEndpoint,
    BaseAgent,
    CancellationToken,
    ClientSideIssue,
    CoordinatorConfig,
    CoordinatorStats,
    CorrelationAgent,
    CorrelationInput,
    CorrelationOutput,
    DetectedTechnology,
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredUrl,
    EndpointParameter,
    FormField,
    ReconAgent,
    // Context types (re-exported from context)
    ReconInput,
    ReconOutput,
    RemediationAgent,
    RemediationInput,
    RemediationOutput,
    RemediationSuggestion,
    ReportMetadata,
    ReportingAgent,
    ReportingInput,
    ReportingOutput,
    ResearchAgent,
    ResearchInput,
    ResearchOutput,
    ScanStorage,
    SchemaIssue,
    SecurityAgent,
    TelemetryHandle,
    VerificationAgent,
    VerificationInput,
    VerificationOutput,
    WebAnalysisAgent,
    WebAnalysisInput,
    WebAnalysisOutput,
    WorkflowSession,
};
pub use attack_path::{
    map_findings_to_attack_techniques, AttackPathAnalyzer, AttackPathBuilder, AttackPathStatistics,
};
pub use correlation::CorrelationEngine;
pub use cve_intelligence::{CveIntelligence, CveProvider};
pub use dependency_analysis::DependencyAnalyzer;
pub use error::IntelligenceError;
pub use knowledge_base::KnowledgeBase;
pub use openre_core::history::{
    AnalyzeConfig, CorrelateConfig, DiscoverConfig, InvestigationStageConfig, PrioritizeConfig,
    StageResult, StageStatus, VerifyConfig, WorkflowArtifact, WorkflowReportConfig, WorkflowStatus,
};
pub use performance::PerformanceOptimizer;
pub use remediation::RemediationVerifier;
pub use root_cause::RootCauseAnalyzer;
pub use scan_diff::ScanData;
pub use scan_diff::ScanDiffAnalyzer;
pub use tui_enhancements::TuiEnhancer;
pub use types::{CorrelationType, EnhancedCorrelation, RiskAssessment};
pub use verification::VerificationEngine;
pub use workflow::WorkflowManager;
pub use workflow_engine::{
    AnalyzeStageHandler, CorrelateStageHandler, DiscoverStageHandler, InvestigationContext,
    InvestigationReport, InvestigationStage, InvestigationStageHandler, InvestigationWorkflow,
    InvestigationWorkflowEngine, PrioritizeStageHandler, PrioritizedFinding, ReportStageHandler,
    RiskScorer, ScannerAgent, VerificationResult, VerifyStageHandler, WorkflowEngineConfig,
    WorkflowProgress, WorkflowStage,
};

/// Intelligence module result type
pub type IntelligenceResult<T> = Result<T, error::IntelligenceError>;
