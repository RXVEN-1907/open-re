//! Background Job Manager for open-re queue system

use crate::{
    job::{Job, JobFilter, JobStatus, JobSummary, LogEntry, LogStream, Priority},
    logs::LogManager,
    queue_manager::QueueManager,
    LogLevel,
};
use openre_config::{QueueConfig, RedisConfig};
use openre_core::error::OpenreResult as Result;
use openre_core::ids::JobId;
use metrics::{Counter, Gauge};
use openre_telemetry::metrics::MetricsRegistry;
use dashmap::DashMap;
use redis::{AsyncCommands, Client};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, timeout};
use tokio_stream::Stream;
use tracing::{debug, error, info, warn};

/// Configuration for the job manager
#[derive(Debug, Clone)]
pub struct JobManagerConfig {
    /// Maximum concurrent jobs
    pub max_concurrent_jobs: usize,
    /// Default job timeout in seconds
    pub default_timeout_seconds: u64,
    /// Maximum log entries per job
    pub max_log_entries: usize,
    /// Job result TTL in seconds
    pub result_ttl_seconds: u64,
    /// Enable job persistence
    pub persist_jobs: bool,
    /// Poll interval for checking dependencies
    pub dependency_check_interval_ms: u64,
}

impl Default for JobManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 10,
            default_timeout_seconds: 3600,
            max_log_entries: 10000,
            result_ttl_seconds: 86400, // 24 hours
            persist_jobs: true,
            dependency_check_interval_ms: 5000,
        }
    }
}

/// Handle for a running job
#[derive(Debug, Clone)]
pub struct JobHandle {
    pub job: Job,
    pub cancel_tx: broadcast::Sender<()>,
    pub pause_tx: broadcast::Sender<bool>, // true = pause, false = resume
}

/// Job storage trait for persistence
#[async_trait::async_trait]
pub trait JobStorage: Send + Sync {
    async fn save_job(&self, job: &Job) -> Result<()>;
    async fn get_job(&self, job_id: JobId) -> Result<Option<Job>>;
    async fn update_job(&self, job: &Job) -> Result<()>;
    async fn delete_job(&self, job_id: JobId) -> Result<()>;
    async fn list_jobs(&self, filter: &JobFilter) -> Result<Vec<JobSummary>>;
    async fn save_log(&self, entry: &LogEntry) -> Result<()>;
    async fn get_logs(&self, job_id: JobId, limit: Option<usize>) -> Result<Vec<LogEntry>>;
}

/// Redis-based job storage implementation
pub struct RedisJobStorage {
    client: Client,
    log_manager: Arc<LogManager>,
}

impl RedisJobStorage {
    pub fn new(client: Client, log_manager: Arc<LogManager>) -> Self {
        Self { client, log_manager }
    }
}



#[async_trait::async_trait]
impl JobStorage for RedisJobStorage {
    async fn save_job(&self, job: &Job) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data = serde_json::to_string(job)?;
        let _: () = conn.hset("openre:jobs:data", job.id.to_string(), data).await?;
        Ok(())
    }

    async fn get_job(&self, job_id: JobId) -> Result<Option<Job>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data: Option<String> = conn.hget("openre:jobs:data", job_id.to_string()).await?;
        if let Some(data) = data {
            let job: Job = serde_json::from_str(&data)?;
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }

    async fn update_job(&self, job: &Job) -> Result<()> {
        self.save_job(job).await
    }

    async fn delete_job(&self, job_id: JobId) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.hdel("openre:jobs:data", job_id.to_string()).await?;
        Ok(())
    }

    async fn list_jobs(&self, filter: &JobFilter) -> Result<Vec<JobSummary>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        // Get all job IDs
        let job_ids: Vec<String> = conn.hkeys("openre:jobs:data").await?;

        let mut summaries = Vec::new();
        for id_str in job_ids {
            if let Ok(job_id) = id_str.parse::<JobId>() {
                if let Ok(Some(job)) = self.get_job(job_id).await {
                    // Apply filters
                    if let Some(ref ft) = filter.job_type {
                        if job.job_type != *ft {
                            continue;
                        }
                    }
                    if let Some(ref st) = filter.status {
                        if job.status != *st {
                            continue;
                        }
                    }
                    if let Some(ref pr) = filter.priority {
                        if job.priority != *pr {
                            continue;
                        }
                    }
                    if let Some(ref pid) = filter.project_id {
                        if job.project_id != Some(*pid) {
                            continue;
                        }
                    }
                    if let Some(ref uid) = filter.user_id {
                        if job.user_id != Some(*uid) {
                            continue;
                        }
                    }

                    summaries.push(JobSummary {
                        id: job.id,
                        job_type: job.job_type,
                        priority: job.priority,
                        status: job.status,
                        project_id: job.project_id,
                        created_at: job.queued_at,
                        started_at: job.started_at,
                        completed_at: job.completed_at,
                        progress: job.progress,
                    });
                }
            }
        }

        // Apply pagination
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);
        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        summaries = summaries.into_iter().skip(offset).take(limit).collect();

        Ok(summaries)
    }

    async fn save_log(&self, entry: &LogEntry) -> Result<()> {
        self.log_manager.add_log(entry.clone()).await
    }

    async fn get_logs(&self, job_id: JobId, limit: Option<usize>) -> Result<Vec<LogEntry>> {
        self.log_manager.get_logs(job_id, limit).await
    }
}

/// Metrics for job manager
pub struct JobManagerMetrics {
    pub jobs_started: Counter,
    pub jobs_completed: Counter,
    pub jobs_failed: Counter,
    pub jobs_cancelled: Counter,
    pub jobs_retry: Counter,
    pub jobs_retried: Counter,
    pub queue_depth: Gauge,
    pub running_jobs: Gauge,
}

impl JobManagerMetrics {
    pub fn new(registry: &openre_telemetry::MetricsRegistry) -> Self {
        Self {
            jobs_started: registry.counter("jobs_started_total", "Total jobs started"),
            jobs_completed: registry.counter("jobs_completed_total", "Total jobs completed"),
            jobs_failed: registry.counter("jobs_failed_total", "Total jobs failed"),
            jobs_cancelled: registry.counter("jobs_cancelled_total", "Total jobs cancelled"),
            jobs_retry: registry.counter("jobs_retry_total", "Total jobs retried"),
            jobs_retried: registry.counter("jobs_retried_total", "Total jobs retried"),
            queue_depth: registry.gauge("jobs_queue_depth", "Current queue depth"),
            running_jobs: registry.gauge("jobs_running", "Number of running jobs"),
        }
    }
}

/// Background Job Manager
pub struct BackgroundJobManager {
    job_queue: Arc<QueueManager>,
    running_jobs: Arc<DashMap<JobId, JobHandle>>,
    job_storage: Arc<dyn JobStorage>,
    log_manager: Arc<LogManager>,
    config: JobManagerConfig,
    shutdown_tx: broadcast::Sender<()>,
    metrics: Arc<JobManagerMetrics>,
}

impl BackgroundJobManager {
    /// Create a new background job manager
    pub async fn new(
        queue_config: QueueConfig,
        redis_config: &RedisConfig,
        config: JobManagerConfig,
        metrics_registry: &MetricsRegistry,
    ) -> Result<Arc<Self>> {
        // Create Redis client
        let client = Client::open(redis_config.url.as_str())?;

        // Test connection
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<_, ()>(&mut conn).await?;

        // Create queue manager
        let queue_metrics = Arc::new(openre_telemetry::metrics::QueueMetrics::new(metrics_registry));
        let queue_manager = Arc::new(
            QueueManager::new(queue_config.clone(), redis_config, queue_metrics).await?,
        );

        // Create log manager
        let log_manager = Arc::new(LogManager::new(client.clone(), config.max_log_entries));

        // Create job storage
        let job_storage: Arc<dyn JobStorage> = Arc::new(RedisJobStorage::new(
            client,
            log_manager.clone(),
        ));

        let (shutdown_tx, _) = broadcast::channel(1);

        let metrics = Arc::new(JobManagerMetrics::new(metrics_registry));

        let manager = Arc::new(Self {
            job_queue: queue_manager,
            running_jobs: Arc::new(DashMap::new()),
            job_storage,
            log_manager,
            config,
            shutdown_tx,
            metrics,
        });

        // Start background tasks
        manager.start_dependency_checker().await;
        manager.start_cleanup_task().await;

        Ok(manager)
    }

    /// Create a BackgroundJobManager for testing
    pub fn new_for_testing() -> Arc<Self> {
        let queue_config = QueueConfig::default();
        let redis_config = RedisConfig {
            url: "redis://localhost:6379".to_string(),
            ..Default::default()
        };
        let config = JobManagerConfig::default();
        let _metrics_registry = MetricsRegistry::default();

        // This will fail without Redis, but useful for unit tests with mocks
        let client = Client::open("redis://localhost:6379").unwrap();
        let log_manager = Arc::new(LogManager::new(client.clone(), 1000));
        let job_storage: Arc<dyn JobStorage> = Arc::new(RedisJobStorage::new(client, log_manager.clone()));

        let (shutdown_tx, _) = broadcast::channel(1);
        let queue_manager = QueueManager::new_for_testing();
        let _metrics_registry = MetricsRegistry::default();
        let metrics = Arc::new(JobManagerMetrics::new(&MetricsRegistry::default()));

        Arc::new(Self {
            job_queue: queue_manager,
            running_jobs: Arc::new(DashMap::new()),
            job_storage,
            log_manager,
            config,
            shutdown_tx,
            metrics,
        })
    }

    /// Start a new job
    pub async fn start_job(&self, mut job: Job) -> Result<JobId> {
        // Set default timeout if not specified
        if job.timeout_seconds.is_none() {
            job.timeout_seconds = Some(self.config.default_timeout_seconds);
        }

        // Initialize job fields
        job.status = JobStatus::Queued;
        job.queued_at = Some(chrono::Utc::now());
        job.retry_count = 0;

        // Check dependencies
        if !job.dependencies.is_empty() {
            job.status = JobStatus::Pending;
            // Will be enqueued when dependencies are met
        }

        // Persist job if enabled
        if self.config.persist_jobs {
            self.job_storage.save_job(&job).await?;
        }

        // Enqueue job
        let job_id = self.job_queue.enqueue(job.clone()).await?;

        // Log job start
        self.log_manager.add_log(LogEntry {
            id: uuid::Uuid::new_v4(),
            job_id,
            timestamp: chrono::Utc::now(),
            level: LogLevel::Info,
            message: format!("Job {} queued", job_id),
            metadata: HashMap::new(),
        }).await?;

        self.metrics.jobs_started.increment(1);

        info!("Started job {}", job_id);
        Ok(job_id)
    }

    /// Cancel a job
    pub async fn cancel_job(&self, job_id: JobId) -> Result<()> {
        // Check if running
        if let Some(handle) = self.running_jobs.get(&job_id) {
            // Signal cancellation
            let _ = handle.cancel_tx.send(());
            self.running_jobs.remove(&job_id);

            // Update job status
            let mut job = handle.job.clone();
            job.status = JobStatus::Cancelled;
            job.completed_at = Some(chrono::Utc::now());

            if self.config.persist_jobs {
                self.job_storage.update_job(&job).await?;
            }

            self.metrics.jobs_cancelled.increment(1);
            info!("Cancelled job {}", job_id);
            return Ok(());
        }

        // Try to cancel via queue manager
        let cancelled = self.job_queue.cancel(job_id).await?;
        if cancelled {
            if self.config.persist_jobs {
                if let Some(mut job) = self.job_storage.get_job(job_id).await? {
                    job.status = JobStatus::Cancelled;
                    job.completed_at = Some(chrono::Utc::now());
                    self.job_storage.update_job(&job).await?;
                }
            }
            self.metrics.jobs_cancelled.increment(1);
            info!("Cancelled queued job {}", job_id);
            return Ok(());
        }

        // Check persisted jobs
        if self.config.persist_jobs {
            if let Some(mut job) = self.job_storage.get_job(job_id).await? {
                if job.status == JobStatus::Pending || job.status == JobStatus::Queued {
                    job.status = JobStatus::Cancelled;
                    job.completed_at = Some(chrono::Utc::now());
                    self.job_storage.update_job(&job).await?;
                    self.metrics.jobs_cancelled.increment(1);
                    info!("Cancelled persisted job {}", job_id);
                    return Ok(());
                }
            }
        }

        Err(openre_core::Error::NotFound(format!("Job {} not found", job_id)))
    }

    /// Pause a job
    pub async fn pause_job(&self, job_id: JobId) -> Result<()> {
        if let Some(handle) = self.running_jobs.get(&job_id) {
            let _ = handle.pause_tx.send(true);
            info!("Paused job {}", job_id);
            return Ok(());
        }
        Err(openre_core::Error::NotFound(format!("Running job {} not found", job_id)))
    }

    /// Resume a job
    pub async fn resume_job(&self, job_id: JobId) -> Result<()> {
        if let Some(handle) = self.running_jobs.get(&job_id) {
            let _ = handle.pause_tx.send(false);
            info!("Resumed job {}", job_id);
            return Ok(());
        }
        Err(openre_core::Error::NotFound(format!("Running job {} not found", job_id)))
    }

    /// Retry a failed job
    pub async fn retry_job(&self, job_id: JobId) -> Result<()> {
        // Get the job
        let job = if self.config.persist_jobs {
            self.job_storage.get_job(job_id).await?
        } else {
            self.job_queue.get_job_result(job_id).await?
        }.ok_or_else(|| openre_core::Error::NotFound(format!("Job {} not found", job_id)))?;

        // Check if job can be retried
        if job.status != JobStatus::Failed && job.status != JobStatus::Cancelled {
            return Err(openre_core::Error::InvalidInput(
                format!("Job {} is not in a retryable state (status: {:?})", job_id, job.status)
            ));
        }

        // Check retry policy
        let retry_policy = job.retry_policy.clone().unwrap_or_default();
        let retry_count = job.retry_count;
        if retry_count >= retry_policy.max_retries {
            return Err(openre_core::Error::InvalidInput(
                format!("Job {} has exceeded max retries ({})", job_id, retry_policy.max_retries)
            ));
        }

        // Create new job with incremented retry count
        let mut new_job = job.clone();
        new_job.id = JobId::new();
        new_job.status = JobStatus::Pending;
        new_job.retry_count = retry_count + 1;
        new_job.queued_at = None;
        new_job.started_at = None;
        new_job.completed_at = None;
        new_job.error = None;
        new_job.result = None;

        // Start the new job
        self.start_job(new_job).await?;

        self.metrics.jobs_retried.increment(1);
        info!("Retried job {} (attempt {})", job_id, retry_count + 1);
        Ok(())
    }

    /// Get job status
    pub async fn get_job_status(&self, job_id: JobId) -> Result<JobStatus> {
        // Check running jobs
        if let Some(handle) = self.running_jobs.get(&job_id) {
            return Ok(handle.job.status);
        }

        // Check queue
        if let Some(status) = self.job_queue.get_job_status(job_id).await? {
            return Ok(status);
        }

        // Check storage
        if self.config.persist_jobs {
            if let Some(job) = self.job_storage.get_job(job_id).await? {
                return Ok(job.status);
            }
        }

        Err(openre_core::Error::NotFound(format!("Job {} not found", job_id)))
    }

    /// Get job logs
    pub async fn get_job_logs(&self, job_id: JobId, follow: bool) -> Result<LogStream> {
        if follow {
            // Return a stream that follows logs
            let stream = self.log_manager.follow_logs(job_id).await?;
            // For now, return a basic LogStream - full streaming would need more infrastructure
        }

        Ok(LogStream { job_id, follow })
    }

    /// Get job logs as vector
    pub async fn get_job_logs_vec(&self, job_id: JobId, limit: Option<usize>) -> Result<Vec<LogEntry>> {
        self.job_storage.get_logs(job_id, limit).await
    }

    /// List jobs with filter
    pub async fn list_jobs(&self, filter: JobFilter) -> Result<Vec<JobSummary>> {
        // Get from storage
        let mut jobs = if self.config.persist_jobs {
            self.job_storage.list_jobs(&filter).await?
        } else {
            Vec::new()
        };

        // Add running jobs
        for handle in self.running_jobs.iter() {
            let job = &handle.job;
            // Apply filters
            if let Some(ref ft) = filter.job_type {
                if job.job_type != *ft { continue; }
            }
            if let Some(ref st) = filter.status {
                if job.status != *st { continue; }
            }
            if let Some(ref pr) = filter.priority {
                if job.priority != *pr { continue; }
            }
            if let Some(ref pid) = filter.project_id {
                if job.project_id != Some(*pid) { continue; }
            }
            if let Some(ref uid) = filter.user_id {
                if job.user_id != Some(*uid) { continue; }
            }

            jobs.push(JobSummary {
                id: job.id,
                job_type: job.job_type.clone(),
                priority: job.priority,
                status: job.status,
                project_id: job.project_id,
                created_at: job.queued_at,
                started_at: job.started_at,
                completed_at: job.completed_at,
                progress: job.progress,
            });
        }

        // Sort by created_at desc
        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply pagination
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);
        jobs = jobs.into_iter().skip(offset).take(limit).collect();

        Ok(jobs)
    }

    /// Wait for job completion with timeout
    pub async fn wait_for_job(&self, job_id: JobId, timeout_duration: Duration) -> Result<Job> {
        let start = std::time::Instant::now();

        loop {
            let status = self.get_job_status(job_id).await?;

            match status {
                JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => {
                    // Get final job
                    if let Some(job) = self.job_storage.get_job(job_id).await? {
                        return Ok(job);
                    }
                    // Fallback to queue manager
                    if let Some(job) = self.job_queue.get_job_result(job_id).await? {
                        return Ok(job);
                    }
                    return Err(openre_core::Error::Internal(anyhow::anyhow!("Job completed but not found")));
                }
                _ => {
                    // Check timeout
                    if start.elapsed() >= timeout_duration {
                        return Err(openre_core::Error::Timeout(format!("Timeout waiting for job {}", job_id)));
                    }
                    // Wait a bit before checking again
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// Get running job count
    pub fn running_job_count(&self) -> usize {
        self.running_jobs.len()
    }

    /// Get queued job count
    pub async fn queued_job_count(&self) -> Result<usize> {
        let stats = self.job_queue.get_stats().await?;
        Ok(stats.total_queued)
    }

    /// Start dependency checker background task
    async fn start_dependency_checker(&self) {
        let manager = self.clone_for_background();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(manager.config.dependency_check_interval_ms));
            loop {
                interval.tick().await;
                if let Err(e) = manager.check_dependencies().await {
                    error!("Dependency check error: {}", e);
                }
            }
        });
    }

    /// Check and enqueue jobs whose dependencies are met
    async fn check_dependencies(&self) -> Result<()> {
        // This would scan pending jobs and check if their dependencies are completed
        // For now, we'll implement a basic version
        debug!("Checking job dependencies");
        Ok(())
    }

    /// Start cleanup background task
    async fn start_cleanup_task(&self) {
        let manager = self.clone_for_background();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Every hour
            loop {
                interval.tick().await;
                if let Err(e) = manager.cleanup_old_jobs().await {
                    error!("Cleanup error: {}", e);
                }
            }
        });
    }

    /// Clean up old completed jobs
    async fn cleanup_old_jobs(&self) -> Result<()> {
        if !self.config.persist_jobs {
            return Ok(());
        }

        // This would clean up old jobs based on TTL
        // Implementation depends on storage backend
        debug!("Running job cleanup");
        Ok(())
    }

    /// Shutdown the job manager
    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        info!("Job manager shutdown initiated");
        Ok(())
    }

    /// Create a clone for background tasks
    fn clone_for_background(&self) -> Arc<Self> {
        // We need a different approach for cloning - use Arc directly
        // This is a placeholder - in reality we'd use a different pattern
        unsafe { std::mem::transmute::<&Self, Arc<Self>>(self) }
    }

    /// Get the log manager
    pub fn log_manager(&self) -> Arc<LogManager> {
        self.log_manager.clone()
    }

    /// Get the queue manager
    pub fn queue_manager(&self) -> Arc<QueueManager> {
        self.job_queue.clone()
    }
}

// Need to add a method to JobStorage for getting Redis client
// This is a workaround - in production, use a proper trait



#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{Job, JobType, Priority};

    #[tokio::test]
    async fn test_job_manager_creation() {
        // Test would need Redis
    }
}