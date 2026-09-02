//! Security agent trait

use crate::agents::context::ReportingInput;
use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use openre_core::ids::AgentId;
use crate::ScanData;
use async_trait::async_trait;
use openre_core::ids::WorkflowId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Input for agent execution
pub trait AgentInput: Send + Sync + Serialize + for<'de> Deserialize<'de> {}

/// Output from agent execution
pub trait AgentOutput: Send + Sync + Serialize + for<'de> Deserialize<'de> {}

// Wrapper type for dynamic agent input/output to satisfy orphan rule
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DynamicAgentInput(pub serde_json::Value);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DynamicAgentOutput(pub serde_json::Value);

impl AgentInput for DynamicAgentInput {}
impl AgentOutput for DynamicAgentOutput {}

/// Shared state key-value store
pub type SharedState = Arc<dashmap::DashMap<String, serde_json::Value>>;

/// HTTP client type alias
pub type HttpClient = Arc<reqwest::Client>;

/// AI service trait
#[async_trait]
pub trait AiService: Send + Sync {
    /// Generate a completion
    async fn complete(&self, prompt: String) -> anyhow::Result<String>;

    /// Generate a completion with system prompt
    async fn complete_with_system(&self, system: String, prompt: String) -> anyhow::Result<String>;

    /// Check if service is available
    async fn health_check(&self) -> anyhow::Result<bool>;
}

/// Storage trait for scan data
#[async_trait]
pub trait ScanStorage: Send + Sync {
    /// Get scan by ID
    async fn get_scan(&self, scan_id: openre_core::ids::ScanId) -> anyhow::Result<Option<ScanData>>;

    /// Get findings for a scan
    async fn get_findings(&self, scan_id: openre_core::ids::ScanId) -> anyhow::Result<Vec<openre_core::result::Finding>>;

    /// Store findings
    async fn store_findings(&self, scan_id: openre_core::ids::ScanId, findings: Vec<openre_core::result::Finding>) -> anyhow::Result<()>;

    /// Get workflow session
    async fn get_workflow_session(&self, workflow_id: WorkflowId) -> anyhow::Result<Option<WorkflowSession>>;

    /// Save workflow session
    async fn save_workflow_session(&self, session: &WorkflowSession) -> anyhow::Result<()>;
}

/// Workflow session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSession {
    pub id: WorkflowId,
    pub target: String,
    pub scan_id: openre_core::ids::ScanId,
    pub current_stage: String,
    pub stage_results: serde_json::Value,
    pub shared_state: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

/// Cancellation token
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<tokio::sync::watch::Sender<bool>>,
    receiver: Arc<tokio::sync::watch::Receiver<bool>>,
}

impl CancellationToken {
    /// Create a new cancellation token
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        Self {
            inner: Arc::new(tx),
            receiver: Arc::new(rx),
        }
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Cancel
    pub fn cancel(&self) {
        let _ = self.inner.send(true);
    }

    /// Wait for cancellation
    pub async fn wait_cancelled(&self) {
        let mut rx = (*self.receiver).clone();
        let _ = rx.changed().await;
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Telemetry handle
#[derive(Clone)]
pub struct TelemetryHandle {
    inner: Arc<dyn TelemetryInner>,
}

trait TelemetryInner: Send + Sync {
    fn record_metric(&self, name: &str, value: f64, labels: HashMap<String, String>);
    fn record_event(&self, name: &str, attributes: HashMap<String, String>);
    fn start_span(&self, name: &str) -> Box<dyn TelemetrySpan>;
}

pub trait TelemetrySpan: Send + Sync {
    fn set_attribute(&mut self, key: &str, value: String);
    fn end(&mut self);
}

impl TelemetryHandle {
    /// Create a new telemetry handle
    pub fn new(inner: Arc<dyn TelemetryInner>) -> Self {
        Self { inner }
    }

    /// Record a metric
    pub fn record_metric(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        self.inner.record_metric(name, value, labels);
    }

    /// Record an event
    pub fn record_event(&self, name: &str, attributes: HashMap<String, String>) {
        self.inner.record_event(name, attributes);
    }

    /// Start a span
    pub fn start_span(&self, name: &str) -> Box<dyn TelemetrySpan> {
        self.inner.start_span(name)
    }
}

impl Default for TelemetryHandle {
    fn default() -> Self {
        struct NoopTelemetry;
        impl TelemetryInner for NoopTelemetry {
            fn record_metric(&self, _name: &str, _value: f64, _labels: HashMap<String, String>) {}
            fn record_event(&self, _name: &str, _attributes: HashMap<String, String>) {}
            fn start_span(&self, _name: &str) -> Box<dyn TelemetrySpan> {
                struct NoopSpan;
                impl TelemetrySpan for NoopSpan {
                    fn set_attribute(&mut self, _key: &str, _value: String) {}
                    fn end(&mut self) {}
                }
                Box::new(NoopSpan)
            }
        }
        Self::new(Arc::new(NoopTelemetry))
    }
}

use std::collections::HashMap;

/// Agent context passed to all agent executions
#[derive(Clone)]
pub struct AgentContext {
    /// Workflow ID (if part of a workflow)
    pub workflow_id: Option<WorkflowId>,
    /// Shared state between agents
    pub shared_state: SharedState,
    /// HTTP client for making requests
    pub http_client: HttpClient,
    /// Storage for scan data
    pub storage: Arc<dyn ScanStorage>,
    /// AI service for LLM operations
    pub ai_service: Arc<dyn AiService>,
    /// Cancellation token
    pub cancellation: CancellationToken,
    /// Telemetry handle
    pub telemetry: TelemetryHandle,
}

impl AgentContext {
    /// Create a new agent context
    pub fn new(
        http_client: HttpClient,
        storage: Arc<dyn ScanStorage>,
        ai_service: Arc<dyn AiService>,
    ) -> Self {
        Self {
            workflow_id: None,
            shared_state: Arc::new(dashmap::DashMap::new()),
            http_client,
            storage,
            ai_service,
            cancellation: CancellationToken::new(),
            telemetry: TelemetryHandle::default(),
        }
    }

    /// Create a new agent context with workflow
    pub fn with_workflow(
        workflow_id: WorkflowId,
        http_client: HttpClient,
        storage: Arc<dyn ScanStorage>,
        ai_service: Arc<dyn AiService>,
    ) -> Self {
        let mut ctx = Self::new(http_client, storage, ai_service);
        ctx.workflow_id = Some(workflow_id);
        ctx
    }

    /// Get a value from shared state
    pub fn get_shared<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.shared_state.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Set a value in shared state
    pub fn set_shared<T: Serialize>(&self, key: &str, value: T) -> anyhow::Result<()> {
        self.shared_state.insert(key.to_string(), serde_json::to_value(value)?);
        Ok(())
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// Trait for all security agents
#[async_trait]
pub trait SecurityAgent: Send + Sync {
    /// Input type for this agent
    type Input: AgentInput;
    /// Output type for this agent
    type Output: AgentOutput;

    /// Get the unique agent ID
    fn agent_id(&self) -> AgentId;

    /// Get the agent type
    fn agent_type(&self) -> AgentType;

    /// Get the agent capabilities
    fn capabilities(&self) -> Vec<AgentCapability>;

    /// Get the agent name
    fn name(&self) -> &str;

    /// Execute the agent
    async fn execute(&self, input: Self::Input, ctx: AgentContext) -> anyhow::Result<AgentResult<Self::Output>>;

    /// Health check
    async fn health_check(&self) -> AgentHealth;

    /// Shutdown the agent
    async fn shutdown(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Generate a suggestion for a finding
    fn generate_suggestion(&self, _finding: &openre_core::result::Finding) -> anyhow::Result<String> {
        Ok("No suggestion available".to_string())
    }

    /// Count findings by severity
    fn count_by_severity(&self, findings: &[openre_core::result::Finding]) -> std::collections::HashMap<String, usize> {
        let mut counts = std::collections::HashMap::new();
        for finding in findings {
            *counts.entry(format!("{:?}", finding.severity)).or_insert(0) += 1;
        }
        counts
    }

    /// Generate JSON report
    fn generate_json_report(&self, _input: &ReportingInput) -> String {
        "{}".to_string()
    }

    /// Generate HTML report
    fn generate_html_report(&self, _input: &ReportingInput) -> String {
        String::new()
    }

    /// Generate SARIF report
    fn generate_sarif_report(&self, _input: &ReportingInput) -> String {
        String::new()
    }

    /// Generate text report
    fn generate_text_report(&self, _input: &ReportingInput) -> String {
        String::new()
    }
}

/// Base agent implementation with common functionality
pub struct BaseAgent {
    id: AgentId,
    name: String,
    agent_type: AgentType,
    capabilities: Vec<AgentCapability>,
}

impl BaseAgent {
    /// Create a new base agent
    pub fn new(name: String, agent_type: AgentType) -> Self {
        let id = AgentId::new();
        let capabilities = agent_type.default_capabilities();
        Self {
            id,
            name,
            agent_type,
            capabilities,
        }
    }

    /// Create a new base agent with custom ID
    pub fn with_id(id: AgentId, name: String, agent_type: AgentType) -> Self {
        let capabilities = agent_type.default_capabilities();
        Self {
            id,
            name,
            agent_type,
            capabilities,
        }
    }

    /// Create a new base agent with custom capabilities
    pub fn with_capabilities(
        id: AgentId,
        name: String,
        agent_type: AgentType,
        capabilities: Vec<AgentCapability>,
    ) -> Self {
        Self {
            id,
            name,
            agent_type,
            capabilities,
        }
    }
}

impl BaseAgent {
    /// Get the agent ID
    pub fn agent_id(&self) -> AgentId {
        self.id
    }

    /// Get the agent type
    pub fn agent_type(&self) -> AgentType {
        self.agent_type
    }

    /// Get the agent capabilities
    pub fn capabilities(&self) -> Vec<AgentCapability> {
        self.capabilities.clone()
    }

    /// Get the agent name
    pub fn name(&self) -> &str {
        &self.name
    }
}