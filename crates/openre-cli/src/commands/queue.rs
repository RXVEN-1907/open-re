//! Job queue management commands
//!
//! Backed by a local SQLite store under the configured storage path; job
//! execution itself is handled by the analysis pipeline, this store tracks
//! submissions, state transitions, and logs.

use crate::{print_output, CliError, Context, OutputFormat, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::JobId;
use openre_core::traits::JobType;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tabled::{Style, Table, Tabled};
use tracing::{info, warn};
use uuid::Uuid;

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
pub(crate) struct SubmitArgs {
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
pub(crate) struct StatusArgs {
    /// Job ID
    job_id: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormatArg,
}

#[derive(Args, Debug)]
pub(crate) struct CancelArgs {
    /// Job ID
    job_id: String,

    /// Reason for cancellation
    #[arg(long, default_value = "User requested cancellation")]
    reason: String,
}

#[derive(Args, Debug)]
pub(crate) struct RetryArgs {
    /// Job ID
    job_id: String,
}

#[derive(Args, Debug)]
pub(crate) struct LogsArgs {
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
pub(crate) struct StatsArgs {
    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormatArg,
}

#[derive(Args, Debug)]
pub(crate) struct ListArgs {
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

#[derive(Debug, Clone, Copy, ValueEnum)]
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

/// Queue priority bands; stored as an integer weight in the job store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Priority {
    Low,
    Default,
    High,
}

impl Priority {
    fn weight(self) -> i64 {
        match self {
            Priority::Low => 10,
            Priority::Default => 50,
            Priority::High => 90,
        }
    }

    fn from_weight(weight: i64) -> Self {
        if weight >= 90 {
            Priority::High
        } else if weight <= 10 {
            Priority::Low
        } else {
            Priority::Default
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Priority::Low => "low",
            Priority::Default => "default",
            Priority::High => "high",
        }
    }

    /// Reads the priority back from the persisted job row.
    #[allow(dead_code)]
    fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Priority::Low),
            "default" => Some(Priority::Default),
            "high" => Some(Priority::High),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum JobStatus {
    Pending,
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Scheduled,
}

impl JobStatus {
    fn as_str(self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::Queued => "queued",
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
            JobStatus::Cancelled => "cancelled",
            JobStatus::Scheduled => "scheduled",
        }
    }

    /// Reads the priority back from the persisted job row.
    #[allow(dead_code)]
    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(JobStatus::Pending),
            "queued" => Some(JobStatus::Queued),
            "running" => Some(JobStatus::Running),
            "completed" => Some(JobStatus::Completed),
            "failed" => Some(JobStatus::Failed),
            "cancelled" => Some(JobStatus::Cancelled),
            "scheduled" => Some(JobStatus::Scheduled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
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

#[derive(Debug, Clone, Copy, ValueEnum)]
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

#[derive(Debug, Clone, Copy, ValueEnum)]
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

/// Job row as stored in the local queue database.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Job {
    id: JobId,
    job_type: String,
    priority: i64,
    status: String,
    payload: serde_json::Value,
    max_attempts: u32,
    attempts: u32,
    timeout_seconds: Option<u64>,
    project_id: Option<String>,
    file_id: Option<String>,
    user_id: Option<String>,
    tags: serde_json::Value,
    scheduled_at: Option<String>,
    created_at: String,
    updated_at: String,
}

fn open_queue_db(ctx: &Context) -> Result<Connection> {
    let db_path: PathBuf = ctx.config.storage.local_path.join("queue.db");
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(&db_path)?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        CREATE TABLE IF NOT EXISTS queue_jobs (
            id TEXT PRIMARY KEY,
            job_type TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 50,
            status TEXT NOT NULL DEFAULT 'queued',
            payload TEXT NOT NULL DEFAULT '{}',
            max_attempts INTEGER NOT NULL DEFAULT 3,
            attempts INTEGER NOT NULL DEFAULT 0,
            timeout_seconds INTEGER,
            project_id TEXT,
            file_id TEXT,
            user_id TEXT,
            tags TEXT NOT NULL DEFAULT '{}',
            scheduled_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_queue_jobs_status ON queue_jobs(status);
        CREATE TABLE IF NOT EXISTS queue_job_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL REFERENCES queue_jobs(id),
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_queue_job_logs_job ON queue_job_logs(job_id);
        "#,
    )?;
    Ok(conn)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn append_log(conn: &Connection, job_id: &str, level: &str, message: &str) {
    let _ = conn.execute(
        "INSERT INTO queue_job_logs (job_id, timestamp, level, message) VALUES (?1, ?2, ?3, ?4)",
        params![job_id, now_rfc3339(), level, message],
    );
}

fn load_job(conn: &Connection, job_id: &JobId) -> Result<Option<Job>> {
    let mut stmt =
        conn.prepare("SELECT id, job_type, priority, status, payload, max_attempts, attempts, timeout_seconds, project_id, file_id, user_id, tags, scheduled_at, created_at, updated_at FROM queue_jobs WHERE id = ?1")?;
    let mut rows = stmt.query_map(params![job_id.to_string()], map_job)?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

fn parse_job_id(raw: String) -> rusqlite::Result<JobId> {
    Uuid::parse_str(&raw).map(JobId).map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "id".to_string(), rusqlite::types::Type::Text)
    })
}

fn map_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<Job> {
    Ok(Job {
        id: parse_job_id(row.get::<_, String>(0)?)?,
        job_type: row.get(1)?,
        priority: row.get(2)?,
        status: row.get(3)?,
        payload: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or(serde_json::Value::Null),
        max_attempts: row.get(5)?,
        attempts: row.get(6)?,
        timeout_seconds: row.get(7)?,
        project_id: row.get(8)?,
        file_id: row.get(9)?,
        user_id: row.get(10)?,
        tags: serde_json::from_str(&row.get::<_, String>(11)?).unwrap_or(serde_json::Value::Null),
        scheduled_at: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

impl QueueCommands {
    pub async fn execute(self, ctx: Context) -> Result<()> {
        let conn = open_queue_db(&ctx)?;
        match self {
            QueueCommands::Submit(args) => submit_job(conn, ctx, args).await,
            QueueCommands::Status(args) => get_job_status(conn, args).await,
            QueueCommands::Cancel(args) => cancel_job(conn, args).await,
            QueueCommands::Retry(args) => retry_job(conn, args).await,
            QueueCommands::Logs(args) => get_job_logs(conn, args).await,
            QueueCommands::Stats(args) => show_queue_stats(conn, args).await,
            QueueCommands::List(args) => list_jobs(conn, args).await,
        }
    }
}

async fn submit_job(conn: Connection, _ctx: Context, args: SubmitArgs) -> Result<()> {
    let payload: serde_json::Value = if args.payload.starts_with('@') {
        let path = &args.payload[1..];
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| CliError::Internal(format!("Invalid JSON in payload file: {}", e)))?
    } else {
        serde_json::from_str(&args.payload)
            .map_err(|e| CliError::Internal(format!("Invalid JSON payload: {}", e)))?
    };

    let job_type: JobType = args.job_type.into();
    let priority: Priority = args.priority.into();
    let status = if args.schedule_at.is_some() { JobStatus::Scheduled } else { JobStatus::Queued };
    let now = now_rfc3339();
    let job = Job {
        id: JobId::new(),
        job_type: job_type.as_str().to_string(),
        priority: priority.weight(),
        status: status.as_str().to_string(),
        payload,
        max_attempts: args.max_attempts,
        attempts: 0,
        timeout_seconds: args.timeout,
        project_id: args.project_id,
        file_id: args.file_id,
        user_id: args.user_id,
        tags: tags_to_json(&args.tag),
        scheduled_at: args.schedule_at,
        created_at: now.clone(),
        updated_at: now,
    };

    conn.execute(
        r#"INSERT INTO queue_jobs
           (id, job_type, priority, status, payload, max_attempts, attempts, timeout_seconds, project_id, file_id, user_id, tags, scheduled_at, created_at, updated_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
        params![
            job.id.to_string(),
            job.job_type,
            job.priority,
            job.status,
            serde_json::to_string(&job.payload).unwrap_or_default(),
            job.max_attempts,
            job.attempts,
            job.timeout_seconds.map(|t| t as i64),
            job.project_id,
            job.file_id,
            job.user_id,
            serde_json::to_string(&job.tags).unwrap_or_default(),
            job.scheduled_at,
            job.created_at,
            job.updated_at,
        ],
    )?;

    append_log(&conn, &job.id.to_string(), "info", &format!("job submitted as {}", job.status));

    if status == JobStatus::Scheduled {
        println!("{} Job scheduled with ID: {}", "✓".green().bold(), job.id);
    } else {
        println!("{} Job submitted with ID: {}", "✓".green().bold(), job.id);
    }
    info!("queue job {} ({}) submitted", job.id, job.job_type);
    Ok(())
}

fn tags_to_json(tags: &[String]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for tag in tags {
        if let Some((k, v)) = tag.split_once('=') {
            map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
    serde_json::Value::Object(map)
}

async fn get_job_status(conn: Connection, args: StatusArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    match load_job(&conn, &job_id)? {
        Some(job) => {
            let row = JobStatusRow { job_id: job.id.to_string(), status: job.status.clone() };
            match args.format.into() {
                OutputFormat::Table => {
                    let mut table = Table::new(vec![row]);
                    println!("{}", table.with(Style::modern()));
                }
                format => {
                    print_output(
                        &serde_json::json!({
                            "job_id": job.id.to_string(),
                            "status": job.status,
                            "job_type": job.job_type,
                            "attempts": job.attempts,
                            "max_attempts": job.max_attempts,
                            "created_at": job.created_at,
                            "updated_at": job.updated_at,
                        }),
                        format,
                        None,
                    )?;
                }
            }
        }
        None => {
            println!("{} Job not found: {}", "✗".red().bold(), job_id);
        }
    }

    Ok(())
}

async fn cancel_job(conn: Connection, args: CancelArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    let cancelled = cancel_if_active(&conn, &job_id, &args.reason)?;

    if cancelled {
        println!("{} Job {} cancelled", "✓".green().bold(), job_id);
    } else {
        println!("{} Job {} not found or already completed", "⚠".yellow().bold(), job_id);
    }

    Ok(())
}

fn cancel_if_active(conn: &Connection, job_id: &JobId, reason: &str) -> Result<bool> {
    let job = match load_job(conn, job_id)? {
        Some(job) => job,
        None => return Ok(false),
    };
    let active = matches!(job.status.as_str(), "pending" | "queued" | "running" | "scheduled");
    if !active {
        return Ok(false);
    }
    let now = now_rfc3339();
    conn.execute(
        "UPDATE queue_jobs SET status = 'cancelled', updated_at = ?2 WHERE id = ?1",
        params![job_id.to_string(), now],
    )?;
    append_log(conn, &job_id.to_string(), "warn", &format!("cancelled: {}", reason));
    Ok(true)
}

async fn retry_job(conn: Connection, args: RetryArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    let job =
        load_job(&conn, &job_id)?.ok_or_else(|| CliError::NotFound(format!("Job {}", job_id)))?;
    if job.status != "failed" && job.status != "cancelled" {
        return Err(CliError::InvalidArgs(format!(
            "Job {} is {} and cannot be retried",
            job_id, job.status
        )));
    }
    if job.attempts >= job.max_attempts {
        return Err(CliError::InvalidArgs(format!(
            "Job {} exhausted its {} attempt(s)",
            job_id, job.max_attempts
        )));
    }

    let now = now_rfc3339();
    conn.execute(
        "UPDATE queue_jobs SET status = 'queued', updated_at = ?2 WHERE id = ?1",
        params![job_id.to_string(), now],
    )?;
    append_log(&conn, &job_id.to_string(), "info", "re-queued for retry");
    warn!("queue job {} re-queued by user", job_id);

    println!("{} Job {} re-queued for retry", "✓".green().bold(), job_id);

    Ok(())
}

async fn get_job_logs(conn: Connection, args: LogsArgs) -> Result<()> {
    let job_id =
        args.job_id.parse().map_err(|e| CliError::Internal(format!("Invalid job ID: {}", e)))?;

    if load_job(&conn, &job_id)?.is_none() {
        println!("{} Job not found: {}", "⚠".yellow().bold(), job_id);
        return Ok(());
    }

    if args.follow {
        // Poll for new log rows until the job reaches a terminal state.
        let mut last_id: i64 = 0;
        loop {
            last_id = drain_new_logs(&conn, &job_id, last_id)?;
            let state = load_job(&conn, &job_id)?.map(|j| j.status).unwrap_or_default();
            if matches!(state.as_str(), "completed" | "failed" | "cancelled") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        return Ok(());
    }

    let mut stmt = conn.prepare(
        "SELECT timestamp, level, message FROM queue_job_logs WHERE job_id = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![job_id.to_string(), args.limit as i64], |row| {
        Ok(LogEntry { timestamp: row.get(0)?, level: row.get(1)?, message: row.get(2)? })
    })?;

    let mut logs = Vec::new();
    for row in rows {
        logs.push(row?);
    }
    logs.reverse();

    if logs.is_empty() {
        println!("{} No logs found for job {}", "⚠".yellow().bold(), job_id);
        return Ok(());
    }

    match args.format.into() {
        OutputFormat::Table => {
            let rows: Vec<LogRow> = logs
                .iter()
                .map(|log| LogRow {
                    timestamp: normalize_timestamp(&log.timestamp),
                    level: log.level.clone(),
                    message: log.message.clone(),
                })
                .collect();
            let mut table = Table::new(rows);
            println!("{}", table.with(Style::modern()));
        }
        format => {
            print_output(&logs, format, None)?;
        }
    }

    Ok(())
}

fn drain_new_logs(conn: &Connection, job_id: &JobId, last_id: i64) -> Result<i64> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, level, message FROM queue_job_logs WHERE job_id = ?1 AND id > ?2 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![job_id.to_string(), last_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut newest = last_id;
    for row in rows {
        let (id, timestamp, level, message) = row?;
        println!("[{}] {}: {}", timestamp, level, message);
        newest = id;
    }
    Ok(newest)
}

fn normalize_timestamp(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_else(|_| ts.to_string())
}

async fn show_queue_stats(conn: Connection, args: StatsArgs) -> Result<()> {
    let stats = collect_stats(&conn)?;

    match args.format.into() {
        OutputFormat::Table => {
            println!("\n{}", "═".repeat(50).dimmed());
            println!("{}", "📊 Queue Statistics".bold().cyan());
            println!("{}", "═".repeat(50).dimmed());
            println!("  {} {}", "Total Queued:".bold(), stats.total_queued);
            println!("  {} {}", "Jobs Running:".bold(), stats.jobs_running);
            println!("  {} {}", "Jobs Scheduled:".bold(), stats.jobs_scheduled);
            println!("  {} {}", "Jobs in DLQ (failed):".bold(), stats.jobs_failed);

            if !stats.jobs_by_priority.is_empty() {
                println!("\n{}", "By Priority:".bold());
                for (priority, count) in &stats.jobs_by_priority {
                    println!("  {} {}", priority.as_str().bold(), count);
                }
            }
        }
        format => {
            print_output(&stats, format, None)?;
        }
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct QueueStats {
    total_queued: u64,
    jobs_running: u64,
    jobs_scheduled: u64,
    jobs_failed: u64,
    jobs_by_priority: Vec<(Priority, u64)>,
}

fn collect_stats(conn: &Connection) -> Result<QueueStats> {
    let count = |status: &str, conn: &Connection| -> Result<u64> {
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM queue_jobs WHERE status = ?1",
            params![status],
            |row| row.get(0),
        )?;
        Ok(n as u64)
    };

    let mut jobs_by_priority = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT priority, COUNT(*) FROM queue_jobs WHERE status IN ('pending', 'queued') GROUP BY priority",
    )?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
    for row in rows {
        let (weight, count) = row?;
        jobs_by_priority.push((Priority::from_weight(weight), count as u64));
    }
    jobs_by_priority.sort_by_key(|(p, _)| p.weight());

    Ok(QueueStats {
        total_queued: count("pending", conn)? + count("queued", conn)?,
        jobs_running: count("running", conn)?,
        jobs_scheduled: count("scheduled", conn)?,
        jobs_failed: count("failed", conn)?,
        jobs_by_priority,
    })
}

async fn list_jobs(conn: Connection, args: ListArgs) -> Result<()> {
    let mut query = String::from(
        "SELECT id, job_type, priority, status, attempts, max_attempts, project_id, created_at, updated_at FROM queue_jobs",
    );
    let mut conditions: Vec<String> = Vec::new();
    if let Some(status) = &args.status {
        conditions.push(format!("status = '{}'", JobStatus::from(*status).as_str()));
    }
    if let Some(job_type) = &args.job_type {
        conditions.push(format!("job_type = '{}'", JobType::from(*job_type).as_str()));
    }
    if let Some(priority) = &args.priority {
        conditions.push(format!("priority = {}", Priority::from(*priority).weight()));
    }
    if let Some(project_id) = &args.project_id {
        conditions.push(format!("project_id = '{}'", project_id.replace('\'', "''")));
    }
    if !conditions.is_empty() {
        query.push_str(" WHERE ");
        query.push_str(&conditions.join(" AND "));
    }
    query.push_str(&format!(" ORDER BY priority DESC, created_at DESC LIMIT {}", args.limit));

    let mut stmt = conn.prepare(&query)?;
    let rows = stmt.query_map([], |row| {
        Ok(JobListRow {
            job_id: row.get::<_, String>(0)?,
            job_type: row.get::<_, String>(1)?,
            priority: Priority::from_weight(row.get::<_, i64>(2)?).as_str().to_string(),
            status: row.get::<_, String>(3)?,
            attempts: format!("{}/{}", row.get::<_, u32>(4)?, row.get::<_, u32>(5)?),
            project_id: row.get::<_, Option<String>>(6)?.unwrap_or_else(|| "-".to_string()),
            created_at: row.get::<_, String>(7)?,
            updated_at: row.get::<_, String>(8)?,
        })
    })?;

    let mut jobs = Vec::new();
    for row in rows {
        jobs.push(row?);
    }

    if jobs.is_empty() {
        println!("{} No jobs found", "ℹ".blue());
        return Ok(());
    }

    match args.format.into() {
        OutputFormat::Table => {
            let mut table = Table::new(jobs);
            println!("{}", table.with(Style::modern()));
        }
        format => {
            print_output(&jobs, format, None)?;
        }
    }

    println!(
        "\n{} Use 'openre queue status <JOB_ID>' for details on a specific job.",
        "💡".dimmed()
    );

    Ok(())
}

#[derive(tabled::Tabled, serde::Serialize)]
struct JobListRow {
    #[tabled(rename = "JOB ID")]
    job_id: String,
    #[tabled(rename = "TYPE")]
    job_type: String,
    #[tabled(rename = "PRIORITY")]
    priority: String,
    #[tabled(rename = "STATUS")]
    status: String,
    #[tabled(rename = "ATTEMPTS")]
    attempts: String,
    #[tabled(rename = "PROJECT")]
    project_id: String,
    #[tabled(rename = "CREATED")]
    created_at: String,
    #[tabled(rename = "UPDATED")]
    updated_at: String,
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

#[derive(serde::Serialize)]
struct LogEntry {
    timestamp: String,
    level: String,
    message: String,
}
