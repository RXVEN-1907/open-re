//! Agent types and capabilities

use openre_core::ids::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Re-export AgentInput and AgentOutput from agent_trait
pub use crate::agents::agent_trait::{AgentInput, AgentOutput};

/// Type of security agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    /// Discovers URLs, endpoints, technologies
    Recon,
    /// Analyzes web applications for vulnerabilities
    WebAnalysis,
    /// Analyzes REST/GraphQL APIs
    ApiAnalysis,
    /// Correlates findings, builds attack paths
    Correlation,
    /// Verifies findings with safe checks
    Verification,
    /// Suggests and verifies fixes
    Remediation,
    /// Generates reports, summaries
    Reporting,
    /// Fetches CVE, CWE, CAPEC, ATT&CK data
    Research,
}

impl AgentType {
    /// Get all agent types
    pub fn all() -> &'static [AgentType] {
        &[
            AgentType::Recon,
            AgentType::WebAnalysis,
            AgentType::ApiAnalysis,
            AgentType::Correlation,
            AgentType::Verification,
            AgentType::Remediation,
            AgentType::Reporting,
            AgentType::Research,
        ]
    }

    /// Get the agent type name
    pub fn name(&self) -> &'static str {
        match self {
            AgentType::Recon => "recon",
            AgentType::WebAnalysis => "web_analysis",
            AgentType::ApiAnalysis => "api_analysis",
            AgentType::Correlation => "correlation",
            AgentType::Verification => "verification",
            AgentType::Remediation => "remediation",
            AgentType::Reporting => "reporting",
            AgentType::Research => "research",
        }
    }

    /// Get the agent type display name
    pub fn display_name(&self) -> &'static str {
        match self {
            AgentType::Recon => "Recon",
            AgentType::WebAnalysis => "Web Analysis",
            AgentType::ApiAnalysis => "API Analysis",
            AgentType::Correlation => "Correlation",
            AgentType::Verification => "Verification",
            AgentType::Remediation => "Remediation",
            AgentType::Reporting => "Reporting",
            AgentType::Research => "Research",
        }
    }

    /// Get default capabilities for this agent type
    pub fn default_capabilities(&self) -> Vec<AgentCapability> {
        match self {
            AgentType::Recon => vec![
                AgentCapability::UrlDiscovery,
                AgentCapability::EndpointDiscovery,
                AgentCapability::TechnologyDetection,
                AgentCapability::HeaderAnalysis,
                AgentCapability::CookieAnalysis,
                AgentCapability::AuthDiscovery,
            ],
            AgentType::WebAnalysis => vec![
                AgentCapability::VulnerabilityScanning,
                AgentCapability::SecurityHeaderAnalysis,
                AgentCapability::ClientSideAnalysis,
                AgentCapability::FormAnalysis,
                AgentCapability::InputValidationTesting,
            ],
            AgentType::ApiAnalysis => vec![
                AgentCapability::ApiSchemaAnalysis,
                AgentCapability::GraphqlAnalysis,
                AgentCapability::RestEndpointTesting,
                AgentCapability::AuthTokenTesting,
                AgentCapability::RateLimitTesting,
            ],
            AgentType::Correlation => vec![
                AgentCapability::FindingCorrelation,
                AgentCapability::AttackPathBuilding,
                AgentCapability::RootCauseAnalysis,
                AgentCapability::RiskAggregation,
            ],
            AgentType::Verification => vec![
                AgentCapability::SafeVerification,
                AgentCapability::DifferentialTesting,
                AgentCapability::ConfigurationVerification,
                AgentCapability::EvidenceValidation,
            ],
            AgentType::Remediation => vec![
                AgentCapability::FixSuggestion,
                AgentCapability::PatchVerification,
                AgentCapability::RegressionTesting,
                AgentCapability::CodeFixGeneration,
            ],
            AgentType::Reporting => vec![
                AgentCapability::ReportGeneration,
                AgentCapability::ExecutiveSummary,
                AgentCapability::ComplianceMapping,
                AgentCapability::RiskVisualization,
            ],
            AgentType::Research => vec![
                AgentCapability::CveLookup,
                AgentCapability::CweMapping,
                AgentCapability::CapecMapping,
                AgentCapability::MitreAttackMapping,
                AgentCapability::ExploitLookup,
            ],
        }
    }
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for AgentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "recon" => Ok(AgentType::Recon),
            "web_analysis" | "web" => Ok(AgentType::WebAnalysis),
            "api_analysis" | "api" => Ok(AgentType::ApiAnalysis),
            "correlation" => Ok(AgentType::Correlation),
            "verification" => Ok(AgentType::Verification),
            "remediation" => Ok(AgentType::Remediation),
            "reporting" => Ok(AgentType::Reporting),
            "research" => Ok(AgentType::Research),
            _ => Err(format!("Unknown agent type: {}", s)),
        }
    }
}

/// Agent capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCapability {
    // Recon capabilities
    UrlDiscovery,
    EndpointDiscovery,
    TechnologyDetection,
    HeaderAnalysis,
    CookieAnalysis,
    AuthDiscovery,
    // Web Analysis capabilities
    VulnerabilityScanning,
    SecurityHeaderAnalysis,
    ClientSideAnalysis,
    FormAnalysis,
    InputValidationTesting,
    // API Analysis capabilities
    ApiSchemaAnalysis,
    GraphqlAnalysis,
    RestEndpointTesting,
    AuthTokenTesting,
    RateLimitTesting,
    // Correlation capabilities
    FindingCorrelation,
    AttackPathBuilding,
    RootCauseAnalysis,
    RiskAggregation,
    // Verification capabilities
    SafeVerification,
    DifferentialTesting,
    ConfigurationVerification,
    EvidenceValidation,
    // Remediation capabilities
    FixSuggestion,
    PatchVerification,
    RegressionTesting,
    CodeFixGeneration,
    // Reporting capabilities
    ReportGeneration,
    ExecutiveSummary,
    ComplianceMapping,
    RiskVisualization,
    // Research capabilities
    CveLookup,
    CweMapping,
    CapecMapping,
    MitreAttackMapping,
    ExploitLookup,
}

impl AgentCapability {
    /// Get the capability name
    pub fn name(&self) -> &'static str {
        match self {
            AgentCapability::UrlDiscovery => "url_discovery",
            AgentCapability::EndpointDiscovery => "endpoint_discovery",
            AgentCapability::TechnologyDetection => "technology_detection",
            AgentCapability::HeaderAnalysis => "header_analysis",
            AgentCapability::CookieAnalysis => "cookie_analysis",
            AgentCapability::AuthDiscovery => "auth_discovery",
            AgentCapability::VulnerabilityScanning => "vulnerability_scanning",
            AgentCapability::SecurityHeaderAnalysis => "security_header_analysis",
            AgentCapability::ClientSideAnalysis => "client_side_analysis",
            AgentCapability::FormAnalysis => "form_analysis",
            AgentCapability::InputValidationTesting => "input_validation_testing",
            AgentCapability::ApiSchemaAnalysis => "api_schema_analysis",
            AgentCapability::GraphqlAnalysis => "graphql_analysis",
            AgentCapability::RestEndpointTesting => "rest_endpoint_testing",
            AgentCapability::AuthTokenTesting => "auth_token_testing",
            AgentCapability::RateLimitTesting => "rate_limit_testing",
            AgentCapability::FindingCorrelation => "finding_correlation",
            AgentCapability::AttackPathBuilding => "attack_path_building",
            AgentCapability::RootCauseAnalysis => "root_cause_analysis",
            AgentCapability::RiskAggregation => "risk_aggregation",
            AgentCapability::SafeVerification => "safe_verification",
            AgentCapability::DifferentialTesting => "differential_testing",
            AgentCapability::ConfigurationVerification => "configuration_verification",
            AgentCapability::EvidenceValidation => "evidence_validation",
            AgentCapability::FixSuggestion => "fix_suggestion",
            AgentCapability::PatchVerification => "patch_verification",
            AgentCapability::RegressionTesting => "regression_testing",
            AgentCapability::CodeFixGeneration => "code_fix_generation",
            AgentCapability::ReportGeneration => "report_generation",
            AgentCapability::ExecutiveSummary => "executive_summary",
            AgentCapability::ComplianceMapping => "compliance_mapping",
            AgentCapability::RiskVisualization => "risk_visualization",
            AgentCapability::CveLookup => "cve_lookup",
            AgentCapability::CweMapping => "cwe_mapping",
            AgentCapability::CapecMapping => "capec_mapping",
            AgentCapability::MitreAttackMapping => "mitre_attack_mapping",
            AgentCapability::ExploitLookup => "exploit_lookup",
        }
    }
}

impl std::fmt::Display for AgentCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Agent health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealth {
    /// Agent is healthy and ready
    Healthy,
    /// Agent is degraded but operational
    Degraded,
    /// Agent is unhealthy
    Unhealthy,
    /// Agent is starting up
    Starting,
    /// Agent is shutting down
    Stopping,
}

/// Agent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// Agent is starting
    Starting,
    /// Agent is running
    Running,
    /// Agent is idle (waiting for work)
    Idle,
    /// Agent is processing a task
    Processing,
    /// Agent is stopping
    Stopping,
    /// Agent has stopped
    Stopped,
    /// Agent has failed
    Failed,
}

/// Agent metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    /// Agent ID
    pub id: AgentId,
    /// Agent name
    pub name: String,
    /// Agent type
    pub agent_type: AgentType,
    /// Agent capabilities
    pub capabilities: Vec<AgentCapability>,
    /// Current status
    pub status: AgentStatus,
    /// Health status
    pub health: AgentHealth,
    /// When the agent was started
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Last heartbeat
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    /// Current task ID (if any)
    pub current_task: Option<String>,
    /// Tasks completed
    pub tasks_completed: u64,
    /// Tasks failed
    pub tasks_failed: u64,
    /// CPU usage percentage
    pub cpu_usage: Option<f32>,
    /// Memory usage in bytes
    pub memory_usage: Option<u64>,
    /// Custom metadata
    pub custom: HashMap<String, serde_json::Value>,
}

impl AgentMetadata {
    /// Create new agent metadata
    pub fn new(id: AgentId, name: String, agent_type: AgentType) -> Self {
        let capabilities = agent_type.default_capabilities();
        Self {
            id,
            name,
            agent_type,
            capabilities,
            status: AgentStatus::Starting,
            health: AgentHealth::Starting,
            started_at: chrono::Utc::now(),
            last_heartbeat: None,
            current_task: None,
            tasks_completed: 0,
            tasks_failed: 0,
            cpu_usage: None,
            memory_usage: None,
            custom: HashMap::new(),
        }
    }
}

/// Result of an agent execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResult<O> {
    /// Whether the execution was successful
    pub success: bool,
    /// Output data
    pub output: Option<O>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Evidence produced
    pub evidence: Vec<serde_json::Value>,
    /// Metrics
    pub metrics: HashMap<String, serde_json::Value>,
}

impl<O> AgentResult<O> {
    /// Create a successful result
    pub fn success(output: O, duration_ms: u64) -> Self {
        Self {
            success: true,
            output: Some(output),
            error: None,
            duration_ms,
            evidence: Vec::new(),
            metrics: HashMap::new(),
        }
    }

    /// Create a failed result
    pub fn failure(error: String, duration_ms: u64) -> Self {
        Self {
            success: false,
            output: None,
            error: Some(error),
            duration_ms,
            evidence: Vec::new(),
            metrics: HashMap::new(),
        }
    }
}