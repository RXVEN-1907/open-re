//! Agent architecture for open-re intelligence

pub mod context;
pub mod coordinator;
pub mod types;
pub mod agent_trait;

// Agent implementations
pub mod recon_agent;
pub mod web_analysis_agent;
pub mod api_analysis_agent;
pub mod correlation_agent;
pub mod verification_agent;
pub mod remediation_agent;
pub mod reporting_agent;
pub mod research_agent;

// Re-exports
pub use context::*;
pub use coordinator::{
    AgentCoordinator, CoordinatorConfig, CoordinatorStats, AgentTask, AgentTaskResult,
    AgentDependencyGraph, AgentWorkflowBuilder, create_investigation_workflow,
};
pub use types::{
    AgentType, AgentCapability, AgentHealth, AgentStatus, AgentMetadata, AgentResult,
};
pub use agent_trait::{
    SecurityAgent, AgentContext, AgentInput, AgentOutput, AiService, ScanStorage,
    CancellationToken, TelemetryHandle, BaseAgent, WorkflowSession,
};

pub use recon_agent::ReconAgent;
pub use web_analysis_agent::WebAnalysisAgent;
pub use api_analysis_agent::ApiAnalysisAgent;
pub use correlation_agent::CorrelationAgent;
pub use verification_agent::VerificationAgent;
pub use remediation_agent::RemediationAgent;
pub use reporting_agent::ReportingAgent;
pub use research_agent::ResearchAgent;