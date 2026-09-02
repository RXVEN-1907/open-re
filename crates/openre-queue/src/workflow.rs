//! Workflow/Pipeline system for open-re queue system

use crate::job::{Job, JobStatus, Priority};
use openre_core::ids::JobId;
use openre_core::traits::JobType;
use crate::job_manager::BackgroundJobManager;
use crate::QueueManager;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::{FileId, ProjectId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Workflow step definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Step name
    pub name: String,
    /// Job type for this step
    pub job_type: JobType,
    /// Step dependencies (step names that must complete first)
    pub depends_on: Vec<String>,
    /// Step-specific payload template
    pub payload_template: Option<serde_json::Value>,
    /// Step priority
    pub priority: Option<Priority>,
    /// Step timeout override
    pub timeout_seconds: Option<u64>,
    /// Retry policy for this step
    pub retry_policy: Option<crate::job::JobRetryPolicy>,
}

/// Workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    /// Workflow name
    pub name: String,
    /// Workflow version
    pub version: String,
    /// Workflow description
    pub description: String,
    /// Steps in the workflow
    pub steps: Vec<WorkflowStep>,
    /// Default payload for the workflow
    pub default_payload: Option<serde_json::Value>,
}

/// Workflow execution state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    /// Execution ID
    pub id: JobId,
    /// Workflow definition
    pub workflow: WorkflowDefinition,
    /// Current status
    pub status: WorkflowStatus,
    /// Step executions
    pub step_executions: HashMap<String, StepExecution>,
    /// Input payload
    pub input_payload: serde_json::Value,
    /// Output payload (final result)
    pub output_payload: Option<serde_json::Value>,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Started at
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Completed at
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Error if failed
    pub error: Option<String>,
}

/// Step execution state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecution {
    /// Step name
    pub step_name: String,
    /// Job ID for this step
    pub job_id: Option<JobId>,
    /// Status
    pub status: JobStatus,
    /// Started at
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Completed at
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Output
    pub output: Option<serde_json::Value>,
    /// Error if failed
    pub error: Option<String>,
}

/// Workflow status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

/// Workflow manager for orchestrating multi-step workflows
pub struct WorkflowManager {
    job_manager: Arc<BackgroundJobManager>,
    workflows: Arc<RwLock<HashMap<String, WorkflowDefinition>>>,
    executions: Arc<RwLock<HashMap<JobId, WorkflowExecution>>>,
}

impl WorkflowManager {
    /// Create a new workflow manager
    pub fn new(job_manager: Arc<BackgroundJobManager>) -> Self {
        Self {
            job_manager,
            workflows: Arc::new(RwLock::new(HashMap::new())),
            executions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a workflow definition
    pub async fn register_workflow(&self, workflow: WorkflowDefinition) -> Result<()> {
        // Validate workflow
        self.validate_workflow(&workflow)?;

        let mut workflows = self.workflows.write().await;
        workflows.insert(workflow.name.clone(), workflow.clone());

        info!("Registered workflow: {}", workflow.name);
        Ok(())
    }

    /// Validate workflow definition
    fn validate_workflow(&self, workflow: &WorkflowDefinition) -> Result<()> {
        // Check for duplicate step names
        let mut names = HashSet::new();
        for step in &workflow.steps {
            if !names.insert(&step.name) {
                return Err(openre_core::Error::InvalidInput(
                    format!("Duplicate step name: {}", step.name)
                ));
            }
        }

        // Check that all dependencies exist
        let step_names: HashSet<&String> = workflow.steps.iter().map(|s| &s.name).collect();
        for step in &workflow.steps {
            for dep in &step.depends_on {
                if !step_names.contains(dep) {
                    return Err(openre_core::Error::InvalidInput(
                        format!("Step '{}' depends on non-existent step '{}'", step.name, dep)
                    ));
                }
            }
        }

        // Check for cycles
        self.check_cycles(workflow)?;

        Ok(())
    }

    /// Check for cycles in workflow dependencies
    fn check_cycles(&self, workflow: &WorkflowDefinition) -> Result<()> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        fn visit(
            step_name: &str,
            workflow: &WorkflowDefinition,
            visited: &mut HashSet<String>,
            rec_stack: &mut HashSet<String>,
        ) -> Result<()> {
            visited.insert(step_name.to_string());
            rec_stack.insert(step_name.to_string());

            let step = workflow.steps.iter().find(|s| s.name == step_name).unwrap();
            for dep in &step.depends_on {
                if !visited.contains(dep) {
                    visit(dep, workflow, visited, rec_stack)?;
                } else if rec_stack.contains(dep) {
                    return Err(openre_core::Error::InvalidInput(
                        format!("Cycle detected in workflow: {} -> {}", step_name, dep)
                    ));
                }
            }

            rec_stack.remove(step_name);
            Ok(())
        }

        for step in &workflow.steps {
            if !visited.contains(&step.name) {
                visit(&step.name, workflow, &mut visited, &mut rec_stack)?;
            }
        }

        Ok(())
    }

    /// Get a workflow definition
    pub async fn get_workflow(&self, name: &str) -> Result<Option<WorkflowDefinition>> {
        let workflows = self.workflows.read().await;
        Ok(workflows.get(name).cloned())
    }

    /// List all registered workflows
    pub async fn list_workflows(&self) -> Vec<WorkflowDefinition> {
        let workflows = self.workflows.read().await;
        workflows.values().cloned().collect()
    }

    /// Start a workflow execution
    pub async fn start_workflow(
        &self,
        workflow_name: &str,
        input_payload: serde_json::Value,
        project_id: Option<ProjectId>,
        file_id: Option<FileId>,
    ) -> Result<JobId> {
        let workflow = self.get_workflow(workflow_name).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("Workflow '{}' not found", workflow_name)))?;

        let execution_id = JobId::new();

        // Create execution state
        let mut step_executions = HashMap::new();
        for step in &workflow.steps {
            step_executions.insert(step.name.clone(), StepExecution {
                step_name: step.name.clone(),
                job_id: None,
                status: JobStatus::Pending,
                started_at: None,
                completed_at: None,
                output: None,
                error: None,
            });
        }

        let execution = WorkflowExecution {
            id: execution_id,
            workflow: workflow.clone(),
            status: WorkflowStatus::Pending,
            step_executions,
            input_payload: input_payload.clone(),
            output_payload: None,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            error: None,
        };

        // Store execution
        self.executions.write().await.insert(execution_id, execution.clone());

        // Start the workflow execution
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.execute_workflow(execution_id).await {
                error!("Workflow execution {} failed: {}", execution_id, e);
            }
        });

        info!("Started workflow execution {} for workflow {}", execution_id, workflow_name);
        Ok(execution_id)
    }

    /// Execute workflow steps in dependency order
    async fn execute_workflow(&self, execution_id: JobId) -> Result<()> {
        // Update status to running
        {
            let mut executions = self.executions.write().await;
            if let Some(execution) = executions.get_mut(&execution_id) {
                execution.status = WorkflowStatus::Running;
                execution.started_at = Some(chrono::Utc::now());
            }
        }

        let workflow = {
            let executions = self.executions.read().await;
            executions.get(&execution_id).unwrap().workflow.clone()
        };

        // Build dependency graph
        let mut pending_steps: VecDeque<&WorkflowStep> = VecDeque::new();
        let mut completed_steps = HashSet::new();
        let mut step_map: HashMap<&String, &WorkflowStep> = HashMap::new();

        for step in &workflow.steps {
            step_map.insert(&step.name, step);
        }

        // Find steps with no dependencies (can start immediately)
        for step in &workflow.steps {
            if step.depends_on.is_empty() {
                pending_steps.push_back(step);
            }
        }

        while let Some(step) = pending_steps.pop_front() {
            // Check if workflow was cancelled
            {
                let executions = self.executions.read().await;
                if let Some(execution) = executions.get(&execution_id) {
                    if execution.status == WorkflowStatus::Cancelled {
                        return Ok(());
                    }
                }
            }

            // Execute step
            let job_id = self.execute_step(execution_id, step).await?;

            // Wait for step completion
            let result = self.wait_for_step(execution_id, &step.name, job_id).await?;

            // Update step execution
            {
                let mut executions = self.executions.write().await;
                if let Some(execution) = executions.get_mut(&execution_id) {
                    if let Some(step_exec) = execution.step_executions.get_mut(&step.name) {
                        step_exec.job_id = Some(job_id);
                        step_exec.status = result.status;
                        step_exec.completed_at = Some(chrono::Utc::now());
                        step_exec.output = result.output;
                        step_exec.error = result.error.clone();

                        if result.status == JobStatus::Failed {
                            execution.status = WorkflowStatus::Failed;
                            execution.error = result.error;
                            execution.completed_at = Some(chrono::Utc::now());
                            return Ok(());
                        }
                    }
                }
            }

            completed_steps.insert(step.name.clone());

            // Check if any dependent steps can now run
            for next_step in &workflow.steps {
                if completed_steps.contains(&next_step.name) {
                    continue;
                }

                // Check if all dependencies are completed
                let all_deps_met = next_step.depends_on.iter().all(|dep| completed_steps.contains(dep));
                if all_deps_met {
                    pending_steps.push_back(next_step);
                }
            }
        }

        // Mark workflow as completed
        {
            let mut executions = self.executions.write().await;
            if let Some(execution) = executions.get_mut(&execution_id) {
                execution.status = WorkflowStatus::Completed;
                execution.completed_at = Some(chrono::Utc::now());
                // Aggregate outputs
                execution.output_payload = self.aggregate_outputs(execution).await;
            }
        }

        info!("Workflow execution {} completed successfully", execution_id);
        Ok(())
    }

    /// Execute a single workflow step
    async fn execute_step(
        &self,
        execution_id: JobId,
        step: &WorkflowStep,
    ) -> Result<JobId> {
        // Build payload for this step
        let mut payload = step.payload_template.clone().unwrap_or(serde_json::Value::Null);

        // Merge with execution input
        if let serde_json::Value::Object(ref mut payload_obj) = payload {
            if let serde_json::Value::Object(ref input_obj) = self.get_execution_input(execution_id).await {
                for (k, v) in input_obj {
                    payload_obj.entry(k.clone()).or_insert(v.clone());
                }
            }
        }

        // Add execution context
        if let serde_json::Value::Object(ref mut payload_obj) = payload {
            payload_obj.insert("execution_id".to_string(), serde_json::Value::String(execution_id.to_string()));
            payload_obj.insert("step_name".to_string(), serde_json::Value::String(step.name.clone()));
        }

        // Create job
        let mut job = Job::new(step.job_type.clone())
            .with_payload(payload)
            .with_priority(step.priority.unwrap_or(Priority::Default));

        if let Some(timeout) = step.timeout_seconds {
            job = job.with_timeout(std::time::Duration::from_secs(timeout));
        }

        if let Some(retry_policy) = step.retry_policy.clone() {
            job = job.with_retry_policy(retry_policy);
        }

        // Add dependencies on previous step jobs
        // This would be handled by the workflow engine
        // For now, we rely on the sequential execution

        // Start job
        let job_id = self.job_manager.start_job(job).await?;

        info!("Started step '{}' as job {}", step.name, job_id);
        Ok(job_id)
    }

    /// Wait for a step to complete
    async fn wait_for_step(
        &self,
        execution_id: JobId,
        step_name: &str,
        job_id: JobId,
    ) -> Result<StepResult> {
        let timeout = std::time::Duration::from_secs(3600); // 1 hour default
        let job = self.job_manager.wait_for_job(job_id, timeout).await?;

        Ok(StepResult {
            status: job.status,
            output: job.result,
            error: job.error,
        })
    }

    /// Get execution input payload
    async fn get_execution_input(&self, execution_id: JobId) -> serde_json::Value {
        let executions = self.executions.read().await;
        executions.get(&execution_id)
            .map(|e| e.input_payload.clone())
            .unwrap_or(serde_json::Value::Null)
    }

    /// Aggregate step outputs into final workflow output
    async fn aggregate_outputs(&self, execution: &WorkflowExecution) -> Option<serde_json::Value> {
        let mut aggregated = serde_json::Map::new();

        for (step_name, step_exec) in &execution.step_executions {
            if let Some(output) = &step_exec.output {
                aggregated.insert(format!("step_{}", step_name), output.clone());
            }
        }

        if aggregated.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(aggregated))
        }
    }

    /// Get workflow execution status
    pub async fn get_execution(&self, execution_id: JobId) -> Result<Option<WorkflowExecution>> {
        let executions = self.executions.read().await;
        Ok(executions.get(&execution_id).cloned())
    }

    /// Cancel a workflow execution
    pub async fn cancel_workflow(&self, execution_id: JobId) -> Result<()> {
        let mut executions = self.executions.write().await;
        if let Some(execution) = executions.get_mut(&execution_id) {
            execution.status = WorkflowStatus::Cancelled;
            execution.completed_at = Some(chrono::Utc::now());

            // Cancel running steps
            for step_exec in execution.step_executions.values() {
                if let Some(job_id) = step_exec.job_id {
                    if step_exec.status == JobStatus::Running || step_exec.status == JobStatus::Queued {
                        let _ = self.job_manager.cancel_job(job_id).await;
                    }
                }
            }

            info!("Cancelled workflow execution {}", execution_id);
            Ok(())
        } else {
            Err(openre_core::Error::NotFound(format!("Workflow execution {} not found", execution_id)))
        }
    }

    /// Pause a workflow execution
    pub async fn pause_workflow(&self, execution_id: JobId) -> Result<()> {
        let mut executions = self.executions.write().await;
        if let Some(execution) = executions.get_mut(&execution_id) {
            execution.status = WorkflowStatus::Paused;

            // Pause running steps
            for step_exec in execution.step_executions.values() {
                if let Some(job_id) = step_exec.job_id {
                    if step_exec.status == JobStatus::Running {
                        let _ = self.job_manager.pause_job(job_id).await;
                    }
                }
            }

            info!("Paused workflow execution {}", execution_id);
            Ok(())
        } else {
            Err(openre_core::Error::NotFound(format!("Workflow execution {} not found", execution_id)))
        }
    }

    /// Resume a workflow execution
    pub async fn resume_workflow(&self, execution_id: JobId) -> Result<()> {
        let mut executions = self.executions.write().await;
        if let Some(execution) = executions.get_mut(&execution_id) {
            if execution.status != WorkflowStatus::Paused {
                return Err(openre_core::Error::InvalidInput("Workflow is not paused".to_string()));
            }

            execution.status = WorkflowStatus::Running;

            // Resume paused steps
            for step_exec in execution.step_executions.values() {
                if let Some(job_id) = step_exec.job_id {
                    if step_exec.status == JobStatus::Running {
                        let _ = self.job_manager.resume_job(job_id).await;
                    }
                }
            }

            info!("Resumed workflow execution {}", execution_id);
            Ok(())
        } else {
            Err(openre_core::Error::NotFound(format!("Workflow execution {} not found", execution_id)))
        }
    }

    /// Get standard security analysis workflow
    pub fn get_security_analysis_workflow() -> WorkflowDefinition {
        WorkflowDefinition {
            name: "security_analysis".to_string(),
            version: "1.0.0".to_string(),
            description: "Standard security analysis pipeline: binary -> identify -> disassemble -> detect suspicious -> AI analysis -> security finding -> remediation -> verification".to_string(),
            steps: vec![
                WorkflowStep {
                    name: "binary_upload".to_string(),
                    job_type: JobType::Import,
                    depends_on: vec![],
                    payload_template: None,
                    priority: Some(Priority::High),
                    timeout_seconds: Some(300),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "identify".to_string(),
                    job_type: JobType::Identification,
                    depends_on: vec!["binary_upload".to_string()],
                    payload_template: None,
                    priority: Some(Priority::High),
                    timeout_seconds: Some(600),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "disassemble".to_string(),
                    job_type: JobType::Disassembly,
                    depends_on: vec!["identify".to_string()],
                    payload_template: None,
                    priority: Some(Priority::Default),
                    timeout_seconds: Some(1800),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "control_flow".to_string(),
                    job_type: JobType::ControlFlow,
                    depends_on: vec!["disassemble".to_string()],
                    payload_template: None,
                    priority: Some(Priority::Default),
                    timeout_seconds: Some(1800),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "data_flow".to_string(),
                    job_type: JobType::DataFlow,
                    depends_on: vec!["control_flow".to_string()],
                    payload_template: None,
                    priority: Some(Priority::Default),
                    timeout_seconds: Some(1800),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "type_recovery".to_string(),
                    job_type: JobType::TypeRecovery,
                    depends_on: vec!["data_flow".to_string()],
                    payload_template: None,
                    priority: Some(Priority::Default),
                    timeout_seconds: Some(1800),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "decompilation".to_string(),
                    job_type: JobType::Decompilation,
                    depends_on: vec!["type_recovery".to_string()],
                    payload_template: None,
                    priority: Some(Priority::Default),
                    timeout_seconds: Some(3600),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "detect_suspicious".to_string(),
                    job_type: JobType::Analysis,
                    depends_on: vec!["decompilation".to_string()],
                    payload_template: Some(serde_json::json!({"analysis_type": "suspicious_pattern"})),
                    priority: Some(Priority::High),
                    timeout_seconds: Some(1800),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "ai_analysis".to_string(),
                    job_type: JobType::AiEnrichment,
                    depends_on: vec!["detect_suspicious".to_string()],
                    payload_template: None,
                    priority: Some(Priority::High),
                    timeout_seconds: Some(300),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "security_finding".to_string(),
                    job_type: JobType::Analysis,
                    depends_on: vec!["ai_analysis".to_string()],
                    payload_template: Some(serde_json::json!({"analysis_type": "security_finding"})),
                    priority: Some(Priority::High),
                    timeout_seconds: Some(600),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "remediation".to_string(),
                    job_type: JobType::PluginExecution,
                    depends_on: vec!["security_finding".to_string()],
                    payload_template: Some(serde_json::json!({"plugin": "remediation"})),
                    priority: Some(Priority::Default),
                    timeout_seconds: Some(600),
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "verification".to_string(),
                    job_type: JobType::Analysis,
                    depends_on: vec!["remediation".to_string()],
                    payload_template: Some(serde_json::json!({"analysis_type": "verification"})),
                    priority: Some(Priority::High),
                    timeout_seconds: Some(600),
                    retry_policy: None,
                },
            ],
            default_payload: None,
        }
    }
}

/// Result of a step execution
#[derive(Debug, Clone)]
struct StepResult {
    status: JobStatus,
    output: Option<serde_json::Value>,
    error: Option<String>,
}

impl Clone for WorkflowManager {
    fn clone(&self) -> Self {
        Self {
            job_manager: self.job_manager.clone(),
            workflows: self.workflows.clone(),
            executions: self.executions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_workflow() {
        let workflow = WorkflowManager::get_security_analysis_workflow();
        assert_eq!(workflow.name, "security_analysis");
        assert_eq!(workflow.steps.len(), 12);
        assert_eq!(workflow.steps[0].name, "binary_upload");
        assert_eq!(workflow.steps[11].name, "verification");
    }

    #[test]
    fn test_workflow_validation() {
        let workflow = WorkflowDefinition {
            name: "test".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            steps: vec![
                WorkflowStep {
                    name: "a".to_string(),
                    job_type: JobType::Analysis,
                    depends_on: vec!["b".to_string()],
                    payload_template: None,
                    priority: None,
                    timeout_seconds: None,
                    retry_policy: None,
                },
                WorkflowStep {
                    name: "b".to_string(),
                    job_type: JobType::Analysis,
                    depends_on: vec!["a".to_string()],
                    payload_template: None,
                    priority: None,
                    timeout_seconds: None,
                    retry_policy: None,
                },
            ],
            default_payload: None,
        };

        // This should fail due to cycle
        let manager = WorkflowManager::new(BackgroundJobManager::new_for_testing());
        assert!(manager.validate_workflow(&workflow).is_err());
    }
}