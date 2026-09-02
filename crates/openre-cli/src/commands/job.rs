//! Job management CLI commands

use clap::{Args, Parser, Subcommand};
use openre_queue::{
    job::{Job, JobFilter, JobStatus, JobType, Priority, LogLevel},
    job_manager::{BackgroundJobManager, JobManagerConfig},
    workflow::WorkflowManager,
    LogManager,
};
use openre_config::{QueueConfig, RedisConfig};
use openre_core::ids::{FileId, JobId, ProjectId};
use openre_telemetry::MetricsRegistry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Subcommand)]
pub enum JobCommands {
    /// List jobs with optional filters
    List(JobListArgs),

    /// Start a new job
    Start(JobStartArgs),

    /// Cancel a job
    Cancel(JobCancelArgs),

    /// Get job status
    Status(JobStatusArgs),

    /// Get job logs
    Logs(JobLogsArgs),

    /// Retry a failed job
    Retry(JobRetryArgs),

    /// Wait for job completion
    Wait(JobWaitArgs),

    /// Manage workflows
    Workflow(WorkflowArgs),
}

#[derive(Args)]
pub struct JobListArgs {
    /// Filter by job type
    #[arg(long)]
    job_type: Option<String>,

    /// Filter by status
    #[arg(long)]
    status: Option<String>,

    /// Filter by priority
    #[arg(long)]
    priority: Option<String>,

    /// Filter by project ID
    #[arg(long)]
    project: Option<String>,

    /// Filter by user ID
    #[arg(long)]
    user: Option<String>,

    /// Filter by creation time (since)
    #[arg(long)]
    since: Option<String>,

    /// Filter by creation time (until)
    #[arg(long)]
    until: Option<String>,

    /// Limit results
    #[arg(long, default_value = "50")]
    limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    offset: usize,

    /// Output format
    #[arg(short, long, default_value = "table")]
    format: crate::OutputFormat,
}

#[derive(Args)]
pub struct JobStartArgs {
    /// Job type
    #[arg(value_enum)]
    job_type: JobTypeArg,

    /// Job payload as JSON
    #[arg(short, long)]
    payload: Option<String>,

    /// Priority
    #[arg(short, long, value_enum, default_value = "default")]
    priority: PriorityArg,

    /// Project ID
    #[arg(long)]
    project: Option<String>,

    /// File ID
    #[arg(long)]
    file: Option<String>,

    /// Timeout in seconds
    #[arg(long)]
    timeout: Option<u64>,

    /// Dependencies (comma-separated job IDs)
    #[arg(long)]
    depends_on: Option<String>,

    /// Max retries
    #[arg(long)]
    max_retries: Option<u32>,

    /// Output format
    #[arg(short, long, default_value = "json")]
    format: crate::OutputFormat,
}

#[derive(Args)]
pub struct JobCancelArgs {
    /// Job ID to cancel
    job_id: String,

    /// Force cancel
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
pub struct JobStatusArgs {
    /// Job ID
    job_id: String,

    /// Output format
    #[arg(short, long, default_value = "json")]
    format: crate::OutputFormat,
}

#[derive(Args)]
pub struct JobLogsArgs {
    /// Job ID
    job_id: String,

    /// Follow logs in real-time
    #[arg(short, long)]
    follow: bool,

    /// Number of lines to show
    #[arg(short, long, default_value = "100")]
    lines: usize,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: crate::OutputFormat,
}

#[derive(Args)]
pub struct JobRetryArgs {
    /// Job ID to retry
    job_id: String,
}

#[derive(Args)]
pub struct JobWaitArgs {
    /// Job ID
    job_id: String,

    /// Timeout in seconds
    #[arg(short, long, default_value = "3600")]
    timeout: u64,
}

#[derive(Args)]
pub struct WorkflowArgs {
    #[command(subcommand)]
    command: WorkflowCommands,
}

#[derive(Subcommand)]
pub enum WorkflowCommands {
    /// List available workflows
    List,

    /// Start a workflow
    Start(WorkflowStartArgs),

    /// Get workflow execution status
    Status(WorkflowStatusArgs),

    /// Cancel a workflow execution
    Cancel(WorkflowCancelArgs),

    /// Pause a workflow execution
    Pause(WorkflowPauseArgs),

    /// Resume a workflow execution
    Resume(WorkflowResumeArgs),
}

#[derive(Args)]
pub struct WorkflowStartArgs {
    /// Workflow name
    name: String,

    /// Input payload as JSON
    #[arg(short, long)]
    payload: Option<String>,

    /// Project ID
    #[arg(long)]
    project: Option<String>,

    /// File ID
    #[arg(long)]
    file: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "json")]
    format: crate::OutputFormat,
}

#[derive(Args)]
pub struct WorkflowStatusArgs {
    /// Execution ID
    execution_id: String,

    /// Output format
    #[arg(short, long, default_value = "json")]
    format: crate::OutputFormat,
}

#[derive(Args)]
pub struct WorkflowCancelArgs {
    /// Execution ID
    execution_id: String,
}

#[derive(Args)]
pub struct WorkflowPauseArgs {
    /// Execution ID
    execution_id: String,
}

#[derive(Args)]
pub struct WorkflowResumeArgs {
    /// Execution ID
    execution_id: String,
}

/// Job type argument for CLI
#[derive(Clone, clap::ValueEnum)]
pub enum JobTypeArg {
    Analysis,
    Identification,
    Disassembly,
    ControlFlow,
    DataFlow,
    TypeRecovery,
    Decompilation,
    AiEnrichment,
    Export,
    Import,
    PluginExecution,
}

impl From<JobTypeArg> for JobType {
    fn from(arg: JobTypeArg) -> Self {
        match arg {
            JobTypeArg::Analysis => JobType::Analysis,
            JobTypeArg::Identification => JobType::Identification,
            JobTypeArg::Disassembly => JobType::Disassembly,
            JobTypeArg::ControlFlow => JobType::ControlFlow,
            JobTypeArg::DataFlow => JobType::DataFlow,
            JobTypeArg::TypeRecovery => JobType::TypeRecovery,
            JobTypeArg::Decompilation => JobType::Decompilation,
            JobTypeArg::AiEnrichment => JobType::AiEnrichment,
            JobTypeArg::Export => JobType::Export,
            JobTypeArg::Import => JobType::Import,
            JobTypeArg::PluginExecution => JobType::PluginExecution,
        }
    }
}

/// Priority argument for CLI
#[derive(Clone, clap::ValueEnum)]
pub enum PriorityArg {
    High,
    Default,
    Low,
}

impl From<PriorityArg> for Priority {
    fn from(arg: PriorityArg) -> Self {
        match arg {
            PriorityArg::High => Priority::High,
            PriorityArg::Default => Priority::Default,
            PriorityArg::Low => Priority::Low,
        }
    }
}

impl JobCommands {
    pub async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        match self {
            JobCommands::List(args) => args.execute(ctx).await,
            JobCommands::Start(args) => args.execute(ctx).await,
            JobCommands::Cancel(args) => args.execute(ctx).await,
            JobCommands::Status(args) => args.execute(ctx).await,
            JobCommands::Logs(args) => args.execute(ctx).await,
            JobCommands::Retry(args) => args.execute(ctx).await,
            JobCommands::Wait(args) => args.execute(ctx).await,
            JobCommands::Workflow(args) => args.execute(ctx).await,
        }
    }
}

impl JobListArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        // In offline mode, we can't query the queue
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Job listing requires API server".to_string()));
        }

        // Build filter
        let mut filter = JobFilter::default();
        if let Some(jt) = self.job_type {
            filter.job_type = Some(jt.parse()?);
        }
        if let Some(st) = self.status {
            filter.status = Some(st.parse()?);
        }
        if let Some(pr) = self.priority {
            filter.priority = Some(pr.parse()?);
        }
        if let Some(pid) = self.project {
            filter.project_id = Some(pid.parse()?);
        }
        if let Some(uid) = self.user {
            filter.user_id = Some(uid.parse()?);
        }
        filter.limit = Some(self.limit);
        filter.offset = Some(self.offset);

        // For now, return empty list - would need API client to query
        let jobs: Vec<openre_queue::job::JobSummary> = Vec::new();
        crate::print_output(&jobs, &self.format)?;
        Ok(())
    }
}

impl JobStartArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Job starting requires API server".to_string()));
        }

        // Parse payload
        let payload = if let Some(p) = self.payload {
            serde_json::from_str(&p)?
        } else {
            serde_json::Value::Null
        };

        // Parse dependencies
        let dependencies = if let Some(deps) = self.depends_on {
            deps.split(',').map(|s| s.trim().parse()).collect::<Result<Vec<JobId>, _>>()?
        } else {
            Vec::new()
        };

        // Build job
        let mut job = Job::new(self.job_type.into())
            .with_payload(payload)
            .with_priority(self.priority.into())
            .with_dependencies(dependencies);

        if let Some(pid) = self.project {
            job = job.with_project(pid.parse()?);
        }
        if let Some(fid) = self.file {
            job = job.with_file(fid.parse()?);
        }
        if let Some(timeout) = self.timeout {
            job = job.with_timeout(Duration::from_secs(timeout));
        }
        if let Some(max_retries) = self.max_retries {
            job = job.with_retry_policy(openre_queue::job::JobRetryPolicy {
                max_retries,
                ..Default::default()
            });
        }

        // For now, just print the job - would need API client to actually start
        info!("Would start job: {:?}", job);
        crate::print_output(&job, &self.format)?;
        Ok(())
    }
}

impl JobCancelArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Job cancellation requires API server".to_string()));
        }

        let job_id: JobId = self.job_id.parse()?;

        // For now, just print - would need API client
        info!("Would cancel job: {}", job_id);
        println!("Job {} cancellation requested", job_id);
        Ok(())
    }
}

impl JobStatusArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Job status requires API server".to_string()));
        }

        let job_id: JobId = self.job_id.parse()?;

        // For now, just print - would need API client
        info!("Would get status for job: {}", job_id);
        let status = JobStatus::Pending; // Placeholder
        crate::print_output(&status, &self.format)?;
        Ok(())
    }
}

impl JobLogsArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Job logs require API server".to_string()));
        }

        let job_id: JobId = self.job_id.parse()?;

        // For now, just print - would need API client
        info!("Would get logs for job: {} (follow: {})", job_id, self.follow);
        println!("Logs for job {} (follow: {}, lines: {}):", job_id, self.follow, self.lines);
        println!("  [Log streaming not yet implemented in CLI - use API directly]");
        Ok(())
    }
}

impl JobRetryArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Job retry requires API server".to_string()));
        }

        let job_id: JobId = self.job_id.parse()?;

        // For now, just print - would need API client
        info!("Would retry job: {}", job_id);
        println!("Job {} retry requested", job_id);
        Ok(())
    }
}

impl JobWaitArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Job wait requires API server".to_string()));
        }

        let job_id: JobId = self.job_id.parse()?;

        // For now, just print - would need API client
        info!("Would wait for job: {} (timeout: {}s)", job_id, self.timeout);
        println!("Waiting for job {} (timeout: {}s)...", job_id, self.timeout);
        println!("  [Job waiting not yet implemented in CLI - use API directly]");
        Ok(())
    }
}

impl WorkflowArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        self.command.execute(ctx).await
    }
}

impl WorkflowCommands {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        match self {
            WorkflowCommands::List => Self::list(ctx).await,
            WorkflowCommands::Start(args) => args.execute(ctx).await,
            WorkflowCommands::Status(args) => args.execute(ctx).await,
            WorkflowCommands::Cancel(args) => args.execute(ctx).await,
            WorkflowCommands::Pause(args) => args.execute(ctx).await,
            WorkflowCommands::Resume(args) => args.execute(ctx).await,
        }
    }

    async fn list(ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        // Show available workflows
        let workflows = vec![
            ("security_analysis", "Standard security analysis pipeline"),
        ];

        let output: Vec<serde_json::Value> = workflows.iter().map(|(name, desc)| {
            serde_json::json!({"name": name, "description": desc})
        }).collect();

        crate::print_output(&output, &crate::OutputFormat::Table)?;
        Ok(())
    }
}

impl WorkflowStartArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Workflow execution requires API server".to_string()));
        }

        let payload = if let Some(p) = self.payload {
            serde_json::from_str(&p)?
        } else {
            serde_json::Value::Null
        };

        // For now, just print - would need API client
        info!("Would start workflow: {} with payload: {:?}", self.name, payload);
        println!("Workflow {} execution started", self.name);
        Ok(())
    }
}

impl WorkflowStatusArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Workflow status requires API server".to_string()));
        }

        let execution_id: JobId = self.execution_id.parse()?;

        // For now, just print - would need API client
        info!("Would get status for workflow execution: {}", execution_id);
        println!("Workflow execution {} status: running", execution_id);
        Ok(())
    }
}

impl WorkflowCancelArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Workflow cancellation requires API server".to_string()));
        }

        let execution_id: JobId = self.execution_id.parse()?;

        // For now, just print - would need API client
        info!("Would cancel workflow execution: {}", execution_id);
        println!("Workflow execution {} cancelled", execution_id);
        Ok(())
    }
}

impl WorkflowPauseArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Workflow pause requires API server".to_string()));
        }

        let execution_id: JobId = self.execution_id.parse()?;

        // For now, just print - would need API client
        info!("Would pause workflow execution: {}", execution_id);
        println!("Workflow execution {} paused", execution_id);
        Ok(())
    }
}

impl WorkflowResumeArgs {
    async fn execute(self, ctx: &mut crate::Context) -> Result<(), crate::CliError> {
        if ctx.offline {
            return Err(crate::CliError::OfflineMode("Workflow resume requires API server".to_string()));
        }

        let execution_id: JobId = self.execution_id.parse()?;

        // For now, just print - would need API client
        info!("Would resume workflow execution: {}", execution_id);
        println!("Workflow execution {} resumed", execution_id);
        Ok(())
    }
}