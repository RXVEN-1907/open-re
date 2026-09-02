//! Agent coordinator for managing agent execution

use crate::agents::context::*;
use crate::agents::agent_trait::{AgentContext, AiService, CancellationToken, ScanStorage, SecurityAgent, SharedState};
use crate::agents::types::{AgentCapability, AgentHealth, AgentMetadata, AgentResult, AgentStatus, AgentType};
use openre_core::ids::AgentId;
use crate::error::IntelligenceError;
use crate::types::*;
use openre_core::ids::{FindingId, ScanId, WorkflowId};
use openre_queue::{Job, JobStatus, Priority, QueueManager};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::toposort;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Agent task for the queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    /// Task ID
    pub id: String,
    /// Agent type to execute
    pub agent_type: AgentType,
    /// Agent ID (if specific agent)
    pub agent_id: Option<AgentId>,
    /// Input data
    pub input: serde_json::Value,
    /// Workflow ID (if part of workflow)
    pub workflow_id: Option<WorkflowId>,
    /// Dependencies (task IDs that must complete first)
    pub dependencies: Vec<String>,
    /// Priority
    pub priority: Priority,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Scheduled at
    pub scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Timeout in seconds
    pub timeout_seconds: Option<u64>,
    /// Retry count
    pub retry_count: u32,
    /// Max retries
    pub max_retries: u32,
}

/// Agent task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTaskResult {
    /// Task ID
    pub task_id: String,
    /// Agent ID that executed
    pub agent_id: AgentId,
    /// Success
    pub success: bool,
    /// Output data
    pub output: Option<serde_json::Value>,
    /// Error message
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Completed at
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

/// Agent dependency graph
pub struct AgentDependencyGraph {
    graph: DiGraph<String, ()>,
    node_indices: HashMap<String, NodeIndex>,
}

impl AgentDependencyGraph {
    /// Create a new dependency graph
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
        }
    }

    /// Add a task
    pub fn add_task(&mut self, task_id: &str) -> NodeIndex {
        if let Some(idx) = self.node_indices.get(task_id) {
            return *idx;
        }
        let idx = self.graph.add_node(task_id.to_string());
        self.node_indices.insert(task_id.to_string(), idx);
        idx
    }

    /// Add a dependency
    pub fn add_dependency(&mut self, from: &str, to: &str) {
        let from_idx = self.add_task(from);
        let to_idx = self.add_task(to);
        self.graph.add_edge(from_idx, to_idx, ());
    }

    /// Get topological order of tasks
    pub fn topological_order(&self) -> Result<Vec<String>, IntelligenceError> {
        let order = toposort(&self.graph, None)
            .map_err(|_| IntelligenceError::WorkflowFeatureDisabled("Cycle detected in dependency graph".to_string()))?;
        Ok(order.into_iter().map(|idx| self.graph[idx].clone()).collect())
    }

    /// Get tasks with no dependencies (can run in parallel)
    pub fn get_ready_tasks(&self, completed: &HashSet<String>) -> Vec<String> {
        self.graph
            .node_indices()
            .filter_map(|idx| {
                let task_id = &self.graph[idx];
                if completed.contains(task_id) {
                    return None;
                }
                // Check if all dependencies are completed
                let deps_complete = self
                    .graph
                    .neighbors_directed(idx, petgraph::Direction::Incoming)
                    .all(|dep_idx| completed.contains(&self.graph[dep_idx]));
                if deps_complete {
                    Some(task_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check for cycles
    pub fn has_cycles(&self) -> bool {
        toposort(&self.graph, None).is_err()
    }
}

impl Default for AgentDependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Agent coordinator configuration
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Maximum concurrent agents
    pub max_concurrent_agents: usize,
    /// Default task timeout in seconds
    pub default_timeout_seconds: u64,
    /// Maximum retries for failed tasks
    pub max_retries: u32,
    /// Health check interval in seconds
    pub health_check_interval_seconds: u64,
    /// Enable parallel execution
    pub enable_parallel: bool,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_agents: 10,
            default_timeout_seconds: 300,
            max_retries: 3,
            health_check_interval_seconds: 30,
            enable_parallel: true,
        }
    }
}

/// Registered agent info
struct RegisteredAgent {
    agent: Arc<dyn SecurityAgent<Input = crate::agents::agent_trait::DynamicAgentInput, Output = crate::agents::agent_trait::DynamicAgentOutput>>,
    metadata: AgentMetadata,
    semaphore: Arc<Semaphore>,
}

/// Agent coordinator
pub struct AgentCoordinator {
    config: CoordinatorConfig,
    queue_manager: Arc<QueueManager>,
    registered_agents: Arc<RwLock<HashMap<AgentId, RegisteredAgent>>>,
    agent_by_type: Arc<RwLock<HashMap<AgentType, Vec<AgentId>>>>,
    task_results: Arc<RwLock<HashMap<String, AgentTaskResult>>>,
    dependency_graph: Arc<RwLock<AgentDependencyGraph>>,
    running_tasks: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
    semaphore: Arc<Semaphore>,
    http_client: Arc<reqwest::Client>,
    storage: Arc<dyn ScanStorage>,
    ai_service: Arc<dyn AiService>,
    cancellation: CancellationToken,
}

impl AgentCoordinator {
    /// Create a new agent coordinator
    pub fn new(
        config: CoordinatorConfig,
        queue_manager: Arc<QueueManager>,
        http_client: Arc<reqwest::Client>,
        storage: Arc<dyn ScanStorage>,
        ai_service: Arc<dyn AiService>,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_agents));
        Self {
            config,
            queue_manager,
            registered_agents: Arc::new(RwLock::new(HashMap::new())),
            agent_by_type: Arc::new(RwLock::new(HashMap::new())),
            task_results: Arc::new(RwLock::new(HashMap::new())),
            dependency_graph: Arc::new(RwLock::new(AgentDependencyGraph::new())),
            running_tasks: Arc::new(RwLock::new(HashMap::new())),
            semaphore,
            http_client,
            storage,
            ai_service,
            cancellation: CancellationToken::new(),
        }
    }

    /// Register an agent
    pub async fn register_agent(
        &self,
        agent: Arc<dyn SecurityAgent<Input = crate::agents::agent_trait::DynamicAgentInput, Output = crate::agents::agent_trait::DynamicAgentOutput>>,
    ) -> anyhow::Result<AgentId> {
        let agent_id = agent.agent_id();
        let agent_type = agent.agent_type();
        let name = agent.name().to_string();
        let capabilities = agent.capabilities();

        let metadata = AgentMetadata::new(agent_id, name, agent_type);

        let registered = RegisteredAgent {
            agent,
            metadata,
            semaphore: Arc::new(Semaphore::new(1)),
        };

        let mut agents = self.registered_agents.write().await;
        agents.insert(agent_id, registered);

        let mut by_type = self.agent_by_type.write().await;
        by_type.entry(agent_type).or_default().push(agent_id);

        info!("Registered agent: {} (type: {:?})", agent_id, agent_type);
        Ok(agent_id)
    }

    /// Unregister an agent
    pub async fn unregister_agent(&self, agent_id: AgentId) -> anyhow::Result<()> {
        let mut agents = self.registered_agents.write().await;
        if let Some(registered) = agents.remove(&agent_id) {
            let mut by_type = self.agent_by_type.write().await;
            if let Some(vec) = by_type.get_mut(&registered.metadata.agent_type) {
                vec.retain(|id| *id != agent_id);
            }
            info!("Unregistered agent: {}", agent_id);
        }
        Ok(())
    }

    /// Get agent metadata
    pub async fn get_agent_metadata(&self, agent_id: AgentId) -> Option<AgentMetadata> {
        let agents = self.registered_agents.read().await;
        agents.get(&agent_id).map(|r| r.metadata.clone())
    }

    /// List all agents
    pub async fn list_agents(&self) -> Vec<AgentMetadata> {
        let agents = self.registered_agents.read().await;
        agents.values().map(|r| r.metadata.clone()).collect()
    }

    /// List agents by type
    pub async fn list_agents_by_type(&self, agent_type: AgentType) -> Vec<AgentMetadata> {
        let by_type = self.agent_by_type.read().await;
        let agents = self.registered_agents.read().await;
        by_type
            .get(&agent_type)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| agents.get(id).map(|r| r.metadata.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Submit a task for execution
    pub async fn submit_task(&self, task: AgentTask) -> anyhow::Result<String> {
        let task_id = task.id.clone();

        // Add to dependency graph
        {
            let mut graph = self.dependency_graph.write().await;
            graph.add_task(&task_id);
            for dep in &task.dependencies {
                graph.add_dependency(dep, &task_id);
            }

            // Check for cycles
            if graph.has_cycles() {
                return Err(anyhow::anyhow!("Adding task would create a cycle in dependency graph"));
            }
        }

        // Enqueue to Redis queue
        let mut job = Job::new(openre_core::traits::JobType::Custom(
            format!("agent_task:{}", task.agent_type.name())
        ));
        job.id = task_id.parse::<openre_core::ids::JobId>()
            .unwrap_or_else(|_| openre_core::ids::JobId::new());
        job.payload = task.input;
        job.priority = task.priority;
        job.status = JobStatus::Queued;

        if let Some(scheduled) = task.scheduled_at {
            self.queue_manager.enqueue_scheduled(job, scheduled).await?;
        } else {
            self.queue_manager.enqueue(job).await?;
        }

        info!("Submitted task: {} (agent type: {:?})", task_id, task.agent_type);
        Ok(task_id)
    }

    /// Submit multiple tasks with dependencies
    pub async fn submit_workflow(&self, tasks: Vec<AgentTask>) -> anyhow::Result<Vec<String>> {
        let mut task_ids = Vec::new();
        for task in tasks {
            let id = self.submit_task(task).await?;
            task_ids.push(id);
        }
        Ok(task_ids)
    }

    /// Get task result
    pub async fn get_task_result(&self, task_id: &str) -> Option<AgentTaskResult> {
        let results = self.task_results.read().await;
        results.get(task_id).cloned()
    }

    /// Wait for task completion
    pub async fn wait_for_task(&self, task_id: &str, timeout: Duration) -> anyhow::Result<AgentTaskResult> {
        let start = std::time::Instant::now();
        loop {
            if let Some(result) = self.get_task_result(task_id).await {
                return Ok(result);
            }
            if start.elapsed() > timeout {
                return Err(anyhow::anyhow!("Task timed out"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait for multiple tasks
    pub async fn wait_for_tasks(&self, task_ids: &[String], timeout: Duration) -> anyhow::Result<Vec<AgentTaskResult>> {
        let mut results = Vec::new();
        for task_id in task_ids {
            results.push(self.wait_for_task(task_id, timeout).await?);
        }
        Ok(results)
    }

    /// Execute a task directly (bypassing queue)
    pub async fn execute_task_direct(&self, task: AgentTask) -> anyhow::Result<AgentTaskResult> {
        let agent_id = if let Some(id) = task.agent_id {
            id
        } else {
            // Find an available agent of the right type
            self.find_available_agent(task.agent_type).await?
        };

        let agent = {
            let agents = self.registered_agents.read().await;
            agents.get(&agent_id)
                .ok_or_else(|| anyhow::anyhow!("Agent not found: {}", agent_id))?
                .agent.clone()
        };

        let started_at = chrono::Utc::now();
        let timeout = Duration::from_secs(task.timeout_seconds.unwrap_or(self.config.default_timeout_seconds));

        // Create agent context
        let ctx = AgentContext::new(
            self.http_client.clone(),
            self.storage.clone(),
            self.ai_service.clone(),
        );

        // Execute with timeout
        let task_id = task.id.clone();
        let input = crate::agents::agent_trait::DynamicAgentInput(task.input);
        let result = match tokio::time::timeout(timeout, agent.execute(input, ctx)).await {
            Ok(Ok(agent_result)) => {
                let completed_at = chrono::Utc::now();
                AgentTaskResult {
                    task_id: task_id.clone(),
                    agent_id,
                    success: agent_result.success,
                    output: agent_result.output.map(|v| v.0),
                    error: agent_result.error,
                    duration_ms: agent_result.duration_ms,
                    completed_at,
                }
            }
            Ok(Err(e)) => {
                let completed_at = chrono::Utc::now();
                AgentTaskResult {
                    task_id: task_id.clone(),
                    agent_id,
                    success: false,
                    output: None,
                    error: Some(e.to_string()),
                    duration_ms: started_at.timestamp_millis() as u64,
                    completed_at,
                }
            }
            Err(_) => {
                let completed_at = chrono::Utc::now();
                AgentTaskResult {
                    task_id: task_id.clone(),
                    agent_id,
                    success: false,
                    output: None,
                    error: Some("Task timeout".to_string()),
                    duration_ms: timeout.as_millis() as u64,
                    completed_at,
                }
            }
        };

        // Store result
        let mut task_results = self.task_results.write().await;
        task_results.insert(task_id.clone(), result.clone());

        Ok(result)
    }

    /// Find an available agent of the given type
    async fn find_available_agent(&self, agent_type: AgentType) -> anyhow::Result<AgentId> {
        let by_type = self.agent_by_type.read().await;
        let agents = self.registered_agents.read().await;

        if let Some(ids) = by_type.get(&agent_type) {
            for id in ids {
                if let Some(registered) = agents.get(id) {
                    // Check if agent is healthy and not busy
                    if registered.metadata.status == AgentStatus::Idle || registered.metadata.status == AgentStatus::Running {
                        if let AgentHealth::Healthy | AgentHealth::Degraded = registered.metadata.health {
                            return Ok(*id);
                        }
                    }
                }
            }
        }

        Err(anyhow::anyhow!("No available agent of type {:?}", agent_type))
    }

    /// Start the coordinator (process tasks from queue)
    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Starting agent coordinator");
        let coordinator = self.clone();
        tokio::spawn(async move {
            coordinator.process_queue().await;
        });

        // Start health check
        let coordinator = self.clone();
        tokio::spawn(async move {
            coordinator.health_check_loop().await;
        });

        Ok(())
    }

    /// Process tasks from the queue
    async fn process_queue(&self) {
        let worker_id = format!("coordinator-{}", Uuid::new_v4());

        loop {
            if self.cancellation.is_cancelled() {
                info!("Coordinator cancelled, stopping queue processing");
                break;
            }

            // Try to dequeue a job
            match self.queue_manager.dequeue(&worker_id, &[Priority::High, Priority::Default, Priority::Low]).await {
                Ok(Some(job)) => {
                    let coordinator = self.clone();
                    let job_id = job.id;
                    tokio::spawn(async move {
                        if let Err(e) = coordinator.process_job(job).await {
                            error!("Error processing job {}: {}", job_id, e);
                        }
                    });
                }
                Ok(None) => {
                    // No jobs available, wait a bit
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!("Error dequeuing job: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Process a single job
    async fn process_job(&self, mut job: openre_queue::Job) -> anyhow::Result<()> {
        let job_id = job.id.to_string();

        // Parse task from job data (clone payload to avoid move)
        let payload = job.payload.clone();
        let task: AgentTask = serde_json::from_value(payload)?;

        // Check dependencies
        {
            let graph = self.dependency_graph.read().await;
            let completed: HashSet<String> = self.task_results.read().await.keys().cloned().collect();
            let ready = graph.get_ready_tasks(&completed);

            if !ready.contains(&task.id) {
                // Re-queue for later
                job.status = JobStatus::Queued;
                self.queue_manager.enqueue(job).await?;
                return Ok(());
            }
        }

        // Execute task
        let result = self.execute_task_direct(task).await?;

        // Complete or fail the job
        if result.success {
            self.queue_manager.complete(job.id, serde_json::to_value(&result)?).await?;
        } else {
            self.queue_manager.fail(job.id, result.error.clone().unwrap_or_else(|| "Unknown error".to_string()), result.error.is_some()).await?;
        }

        Ok(())
    }

    /// Health check loop
    async fn health_check_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.health_check_interval_seconds));

        loop {
            interval.tick().await;

            if self.cancellation.is_cancelled() {
                break;
            }

            let agents = self.registered_agents.read().await;
            for (id, registered) in agents.iter() {
                let health = registered.agent.health_check().await;
                let mut metadata = registered.metadata.clone();
                metadata.health = health;
                metadata.last_heartbeat = Some(chrono::Utc::now());

                // Update metadata
                let mut agents_write = self.registered_agents.write().await;
                if let Some(reg) = agents_write.get_mut(id) {
                    reg.metadata = metadata;
                }
            }
        }
    }

    /// Stop the coordinator
    pub async fn stop(&self) -> anyhow::Result<()> {
        info!("Stopping agent coordinator");
        self.cancellation.cancel();

        // Wait for running tasks
        let mut running = self.running_tasks.write().await;
        for (task_id, handle) in running.drain() {
            handle.abort();
            warn!("Aborted running task: {}", task_id);
        }

        Ok(())
    }

    /// Get coordinator stats
    pub async fn get_stats(&self) -> CoordinatorStats {
        let agents = self.registered_agents.read().await;
        let task_results = self.task_results.read().await;
        let queue_stats = self.queue_manager.get_stats().await.unwrap_or_default();

        let mut agents_by_type = HashMap::new();
        let mut agents_by_status = HashMap::new();
        let mut agents_by_health = HashMap::new();

        for registered in agents.values() {
            *agents_by_type.entry(registered.metadata.agent_type).or_insert(0) += 1;
            *agents_by_status.entry(registered.metadata.status).or_insert(0) += 1;
            *agents_by_health.entry(registered.metadata.health).or_insert(0) += 1;
        }

        CoordinatorStats {
            total_agents: agents.len(),
            agents_by_type,
            agents_by_status,
            agents_by_health,
            total_tasks_completed: task_results.values().filter(|r| r.success).count(),
            total_tasks_failed: task_results.values().filter(|r| !r.success).count(),
            queue_stats,
        }
    }
}

impl Clone for AgentCoordinator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            queue_manager: self.queue_manager.clone(),
            registered_agents: self.registered_agents.clone(),
            agent_by_type: self.agent_by_type.clone(),
            task_results: self.task_results.clone(),
            dependency_graph: self.dependency_graph.clone(),
            running_tasks: self.running_tasks.clone(),
            semaphore: self.semaphore.clone(),
            http_client: self.http_client.clone(),
            storage: self.storage.clone(),
            ai_service: self.ai_service.clone(),
            cancellation: self.cancellation.clone(),
        }
    }
}

/// Coordinator statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub total_agents: usize,
    pub agents_by_type: HashMap<AgentType, usize>,
    pub agents_by_status: HashMap<AgentStatus, usize>,
    pub agents_by_health: HashMap<AgentHealth, usize>,
    pub total_tasks_completed: usize,
    pub total_tasks_failed: usize,
    pub queue_stats: openre_queue::QueueStats,
}

/// Builder for creating agent workflows
pub struct AgentWorkflowBuilder {
    tasks: Vec<AgentTask>,
    next_id: u64,
}

impl AgentWorkflowBuilder {
    /// Create a new workflow builder
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            next_id: 0,
        }
    }

    /// Add a task
    pub fn add_task(
        &mut self,
        agent_type: AgentType,
        input: serde_json::Value,
        dependencies: Vec<String>,
    ) -> String {
        let task_id = format!("task-{}", self.next_id);
        self.next_id += 1;

        let task = AgentTask {
            id: task_id.clone(),
            agent_type,
            agent_id: None,
            input,
            workflow_id: None,
            dependencies,
            priority: Priority::Default,
            created_at: chrono::Utc::now(),
            scheduled_at: None,
            timeout_seconds: None,
            retry_count: 0,
            max_retries: 3,
        };

        self.tasks.push(task);
        task_id
    }

    /// Add a recon task
    pub fn add_recon(&mut self, target: String, dependencies: Vec<String>) -> String {
        let input = ReconInput {
            target,
            max_depth: Some(3),
            include_auth: true,
            include_params: true,
            headers: HashMap::new(),
            timeout_seconds: Some(60),
        };
        self.add_task(AgentType::Recon, serde_json::to_value(input).unwrap(), dependencies)
    }

    /// Add a web analysis task
    pub fn add_web_analysis(&mut self, target: String, dependencies: Vec<String>) -> String {
        let input = WebAnalysisInput {
            target,
            recon_output: None,
            scan_id: None,
            tests: None,
            exclude_tests: None,
            config: HashMap::new(),
        };
        self.add_task(AgentType::WebAnalysis, serde_json::to_value(input).unwrap(), dependencies)
    }

    /// Add a correlation task
    pub fn add_correlation(&mut self, dependencies: Vec<String>) -> String {
        let input = CorrelationInput {
            findings: Vec::new(),
            app_map: None,
            min_confidence: Some(0.5),
            correlation_types: None,
        };
        self.add_task(AgentType::Correlation, serde_json::to_value(input).unwrap(), dependencies)
    }

    /// Add a verification task
    pub fn add_verification(&mut self, target: String, dependencies: Vec<String>) -> String {
        let input = VerificationInput {
            findings: Vec::new(),
            methods: None,
            safe_only: true,
            target,
        };
        self.add_task(AgentType::Verification, serde_json::to_value(input).unwrap(), dependencies)
    }

    /// Add a remediation task
    pub fn add_remediation(&mut self, target: String, dependencies: Vec<String>) -> String {
        let input = RemediationInput {
            findings: Vec::new(),
            target,
            technologies: Vec::new(),
            fix_types: None,
        };
        self.add_task(AgentType::Remediation, serde_json::to_value(input).unwrap(), dependencies)
    }

    /// Add a reporting task
    pub fn add_reporting(&mut self, scan_id: ScanId, format: String, dependencies: Vec<String>) -> String {
        let input = ReportingInput {
            scan_id,
            findings: Vec::new(),
            correlations: None,
            attack_paths: None,
            verification: None,
            remediation: None,
            format,
            report_type: "technical".to_string(),
        };
        self.add_task(AgentType::Reporting, serde_json::to_value(input).unwrap(), dependencies)
    }

    /// Add a research task
    pub fn add_research(&mut self, dependencies: Vec<String>) -> String {
        let finding = openre_core::result::Finding {
            id: openre_core::ids::FindingId::new(),
            title: "Placeholder finding for research".to_string(),
            description: "This finding will be replaced with actual finding during workflow execution".to_string(),
            severity: openre_core::result::Severity::Info,
            confidence: openre_core::result::Confidence::Low,
            category: openre_core::result::Category::InformationDisclosure,
            target: "unknown".to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "workflow".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: chrono::Utc::now(),
            scan_id: openre_core::ids::ScanId::new(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: None,
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: None,
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        };
        let input = ResearchInput {
            finding,
            research_types: vec!["cve".to_string(), "cwe".to_string(), "capec".to_string(), "mitre".to_string()],
            technologies: Vec::new(),
        };
        self.add_task(AgentType::Research, serde_json::to_value(input).unwrap(), dependencies)
    }

    /// Build the workflow
    pub fn build(self) -> Vec<AgentTask> {
        self.tasks
    }
}

impl Default for AgentWorkflowBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a standard investigation workflow
pub fn create_investigation_workflow(
    target: String,
    scan_id: ScanId,
) -> Vec<AgentTask> {
    let mut builder = AgentWorkflowBuilder::new();

    let recon_id = builder.add_recon(target.clone(), vec![]);
    let web_analysis_id = builder.add_web_analysis(target.clone(), vec![recon_id.clone()]);
    let correlation_id = builder.add_correlation(vec![web_analysis_id.clone()]);
    let verification_id = builder.add_verification(target.clone(), vec![correlation_id.clone()]);
    let remediation_id = builder.add_remediation(target, vec![verification_id.clone()]);
    let _reporting_id = builder.add_reporting(scan_id, "json".to_string(), vec![remediation_id]);

    builder.build()
}