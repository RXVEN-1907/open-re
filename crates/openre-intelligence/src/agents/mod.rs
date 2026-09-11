//! Agent architecture for open-re intelligence

pub mod agent_trait;
pub mod context;
pub mod coordinator;
pub mod types;

// Agent implementations
pub mod api_analysis_agent;
pub mod correlation_agent;
pub mod recon_agent;
pub mod remediation_agent;
pub mod reporting_agent;
pub mod research_agent;
pub mod verification_agent;
pub mod web_analysis_agent;

// Re-exports
pub use agent_trait::{
    AgentContext, AgentInput, AgentOutput, AiService, BaseAgent, CancellationToken, ScanStorage,
    SecurityAgent, TelemetryHandle, WorkflowSession,
};
pub use context::*;
pub use coordinator::{
    create_investigation_workflow, AgentCoordinator, AgentDependencyGraph, AgentTask,
    AgentTaskResult, AgentWorkflowBuilder, CoordinatorConfig, CoordinatorStats,
};
pub use types::{AgentCapability, AgentHealth, AgentMetadata, AgentResult, AgentStatus, AgentType};

pub use api_analysis_agent::ApiAnalysisAgent;
pub use correlation_agent::CorrelationAgent;
pub use recon_agent::ReconAgent;
pub use remediation_agent::RemediationAgent;
pub use reporting_agent::ReportingAgent;
pub use research_agent::ResearchAgent;
pub use verification_agent::VerificationAgent;
pub use web_analysis_agent::WebAnalysisAgent;
