//! Job queue management commands

use crate::{print_output, CliError, Context, OutputFormat, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_config::{Config, QueueConfig, RedisConfig};
use openre_core::ids::JobId;
use openre_core::traits::JobType;
use openre_queue::queue_manager::QueueStats;
use openre_queue::{Job, JobStatus, Priority, QueueManager};
use std::path::PathBuf;
use tabled::{settings::Style, Table};
use tracing::{info, warn};

#[derive(Subcommand, Debug)]
pub enum QueueCommands {
    /// Submit a new job to the queue
    Submit(SubmitArgs),
    /// Get status of a job
    Status(StatusArgs),
    /// Cancel a pending/running job
    Cancel(CancelArgs),
    /// Retry a failed job
    Retry(RetryArgs),
    /// Get logs for a job
    Logs(LogsArgs),
    /// Show queue statistics
    Stats(StatsArgs),
    /// List jobs with optional filters
    List(ListArgs),
}

#[derive(Args, Debug)]
struct SubmitArgs {
    /// Job type
    #[arg(long, value_enum, default_value = "analysis")]
    job_type: JobTypeArg,

    /// Job priority
    #[arg(short = 'P', long, value_enum, default_value = "default")]
    priority: PriorityArg,

    /// Job payload as JSON string or path to JSON file (prefixed with @)
    #[arg(short, long)]
    payload: String,

    /// Maximum retry attempts
    #[arg(long, default_value = "3")]
    max_attempts: u32,

    /// Schedule job for later (RFC3339 timestamp, e.g., 2024-01-15T10:30:00Z)
    #[arg(long)]
    schedule_at: Option<String>,

    /// Project ID
    #[arg(long)]
    project_id: Option<String>,

    /// File ID
    #[arg(long)]
    file_id: Option<String>,

    /// User ID
    #[arg(long)]
    user_id: Option<String>,

    /// Timeout in seconds
    #[arg(long)]
    timeout: Option<u64>,

    /// Tags (key=value, can be repeated)
    #[arg(long, value_name = "TAG")]
    tag: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormatArg,
}

#[derive(Args, Debug)]
struct StatusArgs {
    /// Job ID
    job_id: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormatArg,
}

#[derive(Args, Debug)]
struct CancelArgs {
    /// Job ID
    job_id: String,

    /// Reason for cancellation
    #[arg(long, default_value = "User requested cancellation")]
    reason: String,
}

#[derive(Args, Debug)]
struct RetryArgs {
    /// Job ID
    job_id: String,
}

#[derive(Args, Debug)]
struct LogsArgs {
    /// Job ID
    job_id: String,

    /// Maximum number of log entries to show
    #[arg(short, long, default_value = "100")]
    limit: usize,

    /// Follow logs (like tail -f)
    #[arg(short = 'F', long)]
    follow: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormatArg,
}

#[derive(Args, Debug)]
struct StatsArgs {
    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormatArg,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Filter by job status
    #[arg(long, value_enum)]
    status: Option<JobStatusArg>,

    /// Filter by job type
    #[arg(long, value_enum)]
    job_type: Option<JobTypeArg>,

    /// Filter by priority
    #[arg(long, value_enum)]
    priority: Option<PriorityArg>,

    /// Filter by project ID
    #[arg(long)]
    project_id: Option<String>,

    /// Maximum number of jobs to show
    #[arg(short, long, default_value = "50")]
    limit: usize,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormatArg,
}

#[derive(Debug, Clone, ValueEnum)]
enum JobTypeArg {
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

#[derive(Debug, Clone, ValueEnum)]
enum PriorityArg {
    Low,
    Default,
    High,
}

impl From<PriorityArg> for Priority {
    fn from(arg: PriorityArg) -> Self {
        match arg {
            PriorityArg::Low => Priority::Low,
            PriorityArg::Default => Priority::Default,
            PriorityArg::High => Priority::High,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum JobStatusArg {
    Pending,
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Scheduled,
}

impl From<JobStatusArg> for JobStatus {
    fn from(arg: JobStatusArg) -> Self {
        match arg {
            JobStatusArg::Pending => JobStatus::Pending,
            JobStatusArg::Queued => JobStatus::Queued,
            JobStatusArg::Running => JobStatus::Running,
            JobStatusArg::Completed => JobStatus::Completed,
            JobStatusArg::Failed => JobStatus::Failed,
            JobStatusArg::Cancelled => JobStatus::Cancelled,
            JobStatusArg::Scheduled => JobStatus::Scheduled,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormatArg {
    Table,
    Json,
    Yaml,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Table => OutputFormat::Table,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Yaml => OutputFormat::Yaml,
        }
    }
}

impl QueueCommands {
    pub async fn execute(self, ctx: Context) -> Result<()> {
        // Create queue manager
        let queue_manager = create_queue_manager(&ctx).await?;

        match self {
            QueueCommands::Submit(args) => submit_job(queue_manager, ctx, args).await,
            QueueCommands::Status(args) => get_job_status(queue_manager, ctx, args).await,
            QueueCommands::Cancel(args) => cancel_job(queue_manager, ctx, args).await,
            QueueCommands::Retry(args) => retry_job(queue_manager, ctx, args).await,
            QueueCommands::Logs(args) => get_job_logs(queue_manager, ctx, args).await,
            QueueCommands::Stats(args) => show_queue_stats(queue_manager, ctx, args).await,
            QueueCommands::List(args) => list_jobs(queue_manager, ctx, args).await,
        }
    }
}

async fn create_queue_manager(ctx: &Context) -> Result<QueueManager> {
    // Get Redis config from context/config
    let config =
        Config::load().map_err(|e| CliError::Internal(format!("Failed to load config: {}", e)))?;
    let redis_config = config.redis;

    let queue_config = QueueConfig::default();
    let metrics = std::sync::Arc::new(openre_queue::metrics::QueueMetrics::new());

    QueueManager::new(queue_config, &redis_config, metrics)
        .await
        .map_err(|e| CliError::Internal(format!("Failed to connect to queue: {}", e)))
}

async fn submit_job(queue_manager: QueueManager, ctx: Context, args: SubmitArgs) -> Result<()> {
    let payload: serde_json::Value = if args.payload.starts_with('@') {
        let path = &args.payload[1..];
        let content = std::fs::read_to_string(path).map_err(|e| CliError::Io(e))?;
        serde_json::from_str(&content)
            .map_err(|e| CliError::Internal(format!("Invalid JSON in payload file: {}", e)))?
    } else {
        serde_json::from_str(&args.payload)
            .map_err(|e| CliError::Internal(format!("Invalid JSON payload: {}", e)))?
    };

    let mut job =
        Job::new(args.job_type.into()).with_payload(payload).with_priority(args.priority.into());

    if let Some(max_attempts) = args.max_attempts.checked_sub(1) {
        job.retry_policy = Some(openre_queue::JobRetryPolicy {
            max_retries: args.max_attempts,
            base_delay_ms: 1000,
            max_delay_ms: 60000,
            multiplier: 2.0,
            jitter: true,
            retryable_errors: vec![],
        });
    }

    if let Some(project_id) = args.project_id {
        job.project_id = Some(
            project_id
                .parse()
                .map_err(|e| CliError::Internal(format!("Invalid project ID: {}", e)))?,
        );
    }

    if let Some(file_id) = args.file_id {
        job.file_id = Some(
            file_id.parse().map_err(|e| CliError::Internal(format!("Invalid file ID: {}", e)))?,
        );
    }

    if let Some(user_id) = args.user_id {
        job.user_id = Some(
            user_id.parse().map_err(|e| CliError::Internal(format!("Invalid user ID: {}", e)))?,
        );
    }

    if let Some(timeout) = args.timeout {
        job.timeout_seconds = Some(timeout);
    }

    for tag in args.tag {
        if let Some((k, v)) = tag.split_once('=') {
            job = job.with_tag(k.to_string(), v.to_string());
        }
    }

    if let Some(schedule_str) = args.schedule_at {
        let run_at = chrono::DateTime::parse_from_rfc3339(&schedule_str)
            .map_err(|e| CliError::Internal(format!("Invalid schedule timestamp: {}", e)))?
            .with_timezone(&chrono::Utc);
        job.scheduled_at = Some(run_at);
        job.status = JobStatus::Scheduled;
        let job_id = queue_manager
            .enqueue_scheduled(job, run_at)
            .await
            .map_err(|e| CliError::Internal(format!("Failed to schedule job: {}", e)))?;
        println!("{} Job scheduled with ID: {}", "✓".green().bold(), job_id);
    } else {
        let job_id = queue_manager
            .enqueue(job)
            .await
            .map_err(|e| CliError::Internal(format!("Failed to submit job: {}", e)))?;
        println!("{} Job submitted with ID: {}", "✓".green().bold(), job_id);
    }

    Ok(())
}

async fn get_job_status(queue_manager: QueueManager, ctx: Context, args: StatusArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    let status = queue_manager
        .get_job_status(job_id)
        .await
        .map_err(|e| CliError::Internal(format!("Failed to get job status: {}", e)))?;

    match status {
        Some(s) => {
            let row = JobStatusRow { job_id: job_id.to_string(), status: format!("{:?}", s) };
            match args.format.into() {
                OutputFormat::Table => {
                    let mut table = Table::new(vec![row]);
                    println!("{}", table.with(Style::modern()));
                }
                OutputFormat::Json => {
                    print_output(
                        &serde_json::json!({"job_id": job_id.to_string(), "status": format!("{:?}", s)}),
                        OutputFormat::Json,
                        None,
                    )?;
                }
                OutputFormat::Yaml => {
                    print_output(
                        &serde_json::json!({"job_id": job_id.to_string(), "status": format!("{:?}", s)}),
                        OutputFormat::Yaml,
                        None,
                    )?;
                }
                _ => {
                    println!("Job {}: {:?}", job_id, s);
                }
            }
        }
        None => {
            println!("{} Job not found: {}", "✗".red().bold(), job_id);
        }
    }

    Ok(())
}

async fn cancel_job(queue_manager: QueueManager, ctx: Context, args: CancelArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    let cancelled = queue_manager
        .cancel(job_id)
        .await
        .map_err(|e| CliError::Internal(format!("Failed to cancel job: {}", e)))?;

    if cancelled {
        println!("{} Job {} cancelled", "✓".green().bold(), job_id);
    } else {
        println!("{} Job {} not found or already completed", "⚠".yellow().bold(), job_id);
    }

    Ok(())
}

async fn retry_job(queue_manager: QueueManager, ctx: Context, args: RetryArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    queue_manager
        .retry_job(job_id)
        .await
        .map_err(|e| CliError::Internal(format!("Failed to retry job: {}", e)))?;

    println!("{} Job {} re-queued for retry", "✓".green().bold(), job_id);

    Ok(())
}

async fn get_job_logs(queue_manager: QueueManager, ctx: Context, args: LogsArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    let logs = queue_manager
        .get_job_logs(job_id, Some(args.limit))
        .await
        .map_err(|e| CliError::Internal(format!("Failed to get job logs: {}", e)))?;

    if logs.is_empty() {
        println!("{} No logs found for job {}", "⚠".yellow().bold(), job_id);
        return Ok(());
    }

    match args.format.into() {
        OutputFormat::Table => {
            let rows: Vec<LogRow> = logs
                .into_iter()
                .map(|log| LogRow {
                    timestamp: log.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                    level: format!("{:?}", log.level),
                    message: log.message,
                })
                .collect();

            let mut table = Table::new(rows);
            println!("{}", table.with(Style::modern()));
        }
        OutputFormat::Json => {
            print_output(&logs, OutputFormat::Json, None)?;
        }
        OutputFormat::Yaml => {
            print_output(&logs, OutputFormat::Yaml, None)?;
        }
        _ => {
            for log in logs {
                println!(
                    "[{}] {:?}: {}",
                    log.timestamp.format("%H:%M:%S%.3f"),
                    log.level,
                    log.message
                );
            }
        }
    }

    Ok(())
}

async fn show_queue_stats(
    queue_manager: QueueManager,
    ctx: Context,
    args: StatsArgs,
) -> Result<()> {
    let stats = queue_manager
        .get_stats()
        .await
        .map_err(|e| CliError::Internal(format!("Failed to get queue stats: {}", e)))?;

    match args.format.into() {
        OutputFormat::Table => {
            println!("\n{}", "═".repeat(50).dimmed());
            println!("{}", "📊 Queue Statistics".bold().cyan());
            println!("{}", "═".repeat(50).dimmed());
            println!("  {} {}", "Total Queued:".bold(), stats.total_queued);
            println!("  {} {}", "Jobs Running:".bold(), stats.jobs_running);
            println!("  {} {}", "Jobs Scheduled:".bold(), stats.jobs_scheduled);
            println!("  {} {}", "Jobs in DLQ:".bold(), stats.jobs_dlq);

            if !stats.jobs_queued_by_priority.is_empty() {
                println!("\n{}", "By Priority:".bold());
                for (priority, count) in &stats.jobs_queued_by_priority {
                    println!(
                        "  {} {}: {}",
                        priority.as_str().bold(),
                        " ".repeat(8 - priority.as_str().len()),
                        count
                    );
                }
            }
        }
        OutputFormat::Json => {
            print_output(&stats, OutputFormat::Json, None)?;
        }
        OutputFormat::Yaml => {
            print_output(&stats, OutputFormat::Yaml, None)?;
        }
        _ => {}
    }

    Ok(())
}

async fn list_jobs(queue_manager: QueueManager, ctx: Context, args: ListArgs) -> Result<()> {
    // For now, we'll get stats and show a summary
    // In a full implementation, we'd query the job results store
    let stats = queue_manager
        .get_stats()
        .await
        .map_err(|e| CliError::Internal(format!("Failed to get queue stats: {}", e)))?;

    println!("\n{}", "═".repeat(60).dimmed());
    println!("{}", "📋 Job Queue Summary".bold().cyan());
    println!("{}", "═".repeat(60).dimmed());
    println!("  {} {}", "Total Queued:".bold(), stats.total_queued);
    println!("  {} {}", "Jobs Running:".bold(), stats.jobs_running);
    println!("  {} {}", "Jobs Scheduled:".bold(), stats.jobs_scheduled);
    println!("  {} {}", "Jobs in DLQ:".bold(), stats.jobs_dlq);

    if !stats.jobs_queued_by_priority.is_empty() {
        println!("\n{}", "By Priority:".bold());
        for (priority, count) in &stats.jobs_queued_by_priority {
            println!(
                "  {} {}: {}",
                priority.as_str().bold(),
                " ".repeat(8 - priority.as_str().len()),
                count
            );
        }
    }

    println!(
        "\n{} Use 'openre queue status <JOB_ID>' for details on a specific job.",
        "💡".dimmed()
    );

    Ok(())
}

#[derive(tabled::Tabled)]
struct JobStatusRow {
    #[tabled(rename = "JOB ID")]
    job_id: String,
    #[tabled(rename = "STATUS")]
    status: String,
}

#[derive(tabled::Tabled)]
struct LogRow {
    #[tabled(rename = "TIMESTAMP")]
    timestamp: String,
    #[tabled(rename = "LEVEL")]
    level: String,
    #[tabled(rename = "MESSAGE")]
    message: String,
}
