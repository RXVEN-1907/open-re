//! Queue manager for Redis Streams

use crate::{Job, JobStatus, Priority, QueueConfig, QueueMetrics};
use openre_core::error::Result;
use openre_core::ids::{JobId, ProjectId, UserId};
use openre_telemetry::metrics::QueueMetrics as TelemetryQueueMetrics;
use redis::{AsyncCommands, Client, StreamsMaxlen, StreamsRange, XReadOptions};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// Queue manager for Redis Streams
pub struct QueueManager {
    client: Client,
    config: QueueConfig,
    metrics: Arc<TelemetryQueueMetrics>,
    consumer_groups: Arc<RwLock<HashMap<String, ConsumerGroupInfo>>>,
    pending_jobs: Arc<RwLock<HashMap<JobId, PendingJob>>>,
    semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
struct ConsumerGroupInfo {
    name: String,
    stream: String,
    last_delivered_id: String,
}

#[derive(Debug, Clone)]
struct PendingJob {
    job: Job,
    attempts: u32,
    last_attempt: chrono::DateTime<chrono::Utc>,
    assigned_worker: Option<String>,
}

impl QueueManager {
    pub async fn new(config: QueueConfig, metrics: Arc<TelemetryQueueMetrics>) -> Result<Self> {
        let client = Client::open(config.redis_url.as_str())?;
        
        // Test connection
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async(&mut conn).await?;

        // Create consumer groups for each priority
        let manager = Self {
            client,
            config: config.clone(),
            metrics,
            consumer_groups: Arc::new(RwLock::new(HashMap::new())),
            pending_jobs: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_jobs)),
        };

        manager.init_consumer_groups().await?;
        
        Ok(manager)
    }

    async fn init_consumer_groups(&self) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        for priority in [Priority::High, Priority::Default, Priority::Low] {
            let stream = self.stream_name(priority);
            let group = format!("openre-workers-{}", priority.as_str().to_lowercase());
            
            // Create consumer group if not exists
            let result: Result<String, _> = redis::cmd("XGROUP")
                .arg("CREATE")
                .arg(&stream)
                .arg(&group)
                .arg("$") // Start from new messages only
                .query_async(&mut conn)
                .await;
            
            match result {
                Ok(_) => info!("Created consumer group {} for stream {}", group, stream),
                Err(e) if e.to_string().contains("BUSYGROUP") => {
                    debug!("Consumer group {} already exists", group);
                }
                Err(e) => return Err(openre_core::Error::Internal(e.into())),
            }

            let mut groups = self.consumer_groups.write().await;
            groups.insert(priority.as_str().to_string(), ConsumerGroupInfo {
                name: group,
                stream: stream.clone(),
                last_delivered_id: "0-0".to_string(),
            });
        }

        // Create scheduled jobs stream
        let _: () = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg("openre:scheduled")
            .arg("openre-scheduler")
            .arg("$")
            .query_async(&mut conn)
            .await
            .ok(); // Ignore if exists

        // Create dead letter queue stream
        let _: () = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg("openre:dlq")
            .arg("openre-dlq-processor")
            .arg("$")
            .query_async(&mut conn)
            .await
            .ok();

        Ok(())
    }

    fn stream_name(&self, priority: Priority) -> String {
        format!("openre:jobs:{}", priority.as_str().to_lowercase())
    }

    /// Enqueue a job
    pub async fn enqueue(&self, mut job: Job) -> Result<JobId> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        job.status = JobStatus::Queued;
        job.queued_at = Some(chrono::Utc::now());
        
        let job_data = serde_json::to_string(&job)?;
        let stream = self.stream_name(job.priority);
        
        let id: String = conn.xadd(&stream, "*", &[("data", job_data)]).await?;
        
        // Update metrics
        self.metrics.jobs_queued.inc();
        self.metrics.jobs_by_priority.with_label_values(&[job.priority.as_str()]).inc();
        
        info!("Enqueued job {} to stream {} with ID {}", job.id, stream, id);
        
        Ok(job.id)
    }

    /// Enqueue a scheduled job
    pub async fn enqueue_scheduled(&self, job: Job, run_at: chrono::DateTime<chrono::Utc>) -> Result<JobId> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        let job_data = serde_json::to_string(&job)?;
        let score = run_at.timestamp_millis() as f64;
        
        // Use sorted set for scheduled jobs
        let _: () = conn.zadd("openre:scheduled:jobs", job.id.to_string(), score).await?;
        let _: () = conn.hset("openre:scheduled:data", job.id.to_string(), job_data).await?;
        
        self.metrics.jobs_scheduled.inc();
        
        info!("Scheduled job {} for {}", job.id, run_at);
        
        Ok(job.id)
    }

    /// Dequeue a job for processing
    pub async fn dequeue(&self, worker_id: &str, priorities: &[Priority]) -> Result<Option<Job>> {
        let _permit = self.semaphore.acquire().await.map_err(|_| openre_core::Error::Internal("Semaphore closed".into()))?;
        
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        for priority in priorities {
            let stream = self.stream_name(*priority);
            let group = format!("openre-workers-{}", priority.as_str().to_lowercase());
            
            // Read from stream with blocking
            let options = XReadOptions::default()
                .count(1)
                .block(Duration::from_millis(self.config.poll_interval_ms));
            
            let streams: Vec<(String, String)> = vec![(stream.clone(), ">".to_string())];
            let result: Option<Vec<redis::streams::StreamReadReply>> = conn.xread_options(&streams, &options).await?;
            
            if let Some(replies) = result {
                for reply in replies {
                    for entry in reply.ids {
                        if let Some(data) = entry.map.get("data") {
                            let job_data: String = redis::from_redis_value(data)?;
                            let mut job: Job = serde_json::from_str(&job_data)?;
                            
                            // Update job status
                            job.status = JobStatus::Running;
                            job.started_at = Some(chrono::Utc::now());
                            job.worker_id = Some(worker_id.to_string());
                            
                            // Track pending job
                            let mut pending = self.pending_jobs.write().await;
                            pending.insert(job.id, PendingJob {
                                job: job.clone(),
                                attempts: 1,
                                last_attempt: chrono::Utc::now(),
                                assigned_worker: Some(worker_id.to_string()),
                            });
                            
                            // Update metrics
                            self.metrics.jobs_dequeued.inc();
                            self.metrics.jobs_running.inc();
                            
                            // Acknowledge message
                            let _: () = conn.xack(&stream, &group, &[entry.id]).await?;
                            
                            return Ok(Some(job));
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// Complete a job successfully
    pub async fn complete(&self, job_id: JobId, result: serde_json::Value) -> Result<()> {
        let mut pending = self.pending_jobs.write().await;
        
        if let Some(mut pending_job) = pending.remove(&job_id) {
            pending_job.job.status = JobStatus::Completed;
            pending_job.job.completed_at = Some(chrono::Utc::now());
            pending_job.job.result = Some(result);
            
            // Store result
            self.store_job_result(&pending_job.job).await?;
            
            self.metrics.jobs_completed.inc();
            self.metrics.jobs_running.dec();
            
            info!("Job {} completed successfully", job_id);
        }
        
        Ok(())
    }

    /// Fail a job (with retry logic)
    pub async fn fail(&self, job_id: JobId, error: String, retry: bool) -> Result<()> {
        let mut pending = self.pending_jobs.write().await;
        
        if let Some(mut pending_job) = pending.remove(&job_id) {
            pending_job.attempts += 1;
            pending_job.last_attempt = chrono::Utc::now();
            
            if retry && pending_job.attempts <= self.config.max_retries {
                // Re-queue with backoff
                let delay = self.calculate_backoff(pending_job.attempts);
                pending_job.job.status = JobStatus::Queued;
                pending_job.job.scheduled_at = Some(chrono::Utc::now() + delay);
                
                self.enqueue_scheduled(pending_job.job, pending_job.job.scheduled_at.unwrap()).await?;
                
                self.metrics.jobs_retried.inc();
                warn!("Job {} failed, retry {}/{} in {:?}", job_id, pending_job.attempts, self.config.max_retries, delay);
            } else {
                // Move to DLQ
                pending_job.job.status = JobStatus::Failed;
                pending_job.job.completed_at = Some(chrono::Utc::now());
                pending_job.job.error = Some(error.clone());
                
                self.move_to_dlq(&pending_job.job, error).await?;
                
                self.metrics.jobs_failed.inc();
                self.metrics.jobs_running.dec();
                
                error!("Job {} failed permanently after {} attempts", job_id, pending_job.attempts);
            }
        }
        
        Ok(())
    }

    /// Cancel a job
    pub async fn cancel(&self, job_id: JobId) -> Result<bool> {
        let mut pending = self.pending_jobs.write().await;
        
        if let Some(pending_job) = pending.remove(&job_id) {
            // If running, we'd need to signal the worker
            // For now, just mark as cancelled
            let mut job = pending_job.job;
            job.status = JobStatus::Cancelled;
            job.completed_at = Some(chrono::Utc::now());
            
            self.store_job_result(&job).await?;
            
            self.metrics.jobs_cancelled.inc();
            if pending_job.assigned_worker.is_some() {
                self.metrics.jobs_running.dec();
            }
            
            info!("Job {} cancelled", job_id);
            Ok(true)
        } else {
            // Check if still in queue (not yet dequeued)
            // This would require scanning streams, which is expensive
            // For now, return false
            Ok(false)
        }
    }

    /// Get job status
    pub async fn get_job_status(&self, job_id: JobId) -> Result<Option<JobStatus>> {
        // Check pending jobs first
        {
            let pending = self.pending_jobs.read().await;
            if let Some(p) = pending.get(&job_id) {
                return Ok(Some(p.job.status));
            }
        }
        
        // Check stored results
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let result: Option<String> = conn.hget("openre:job:results", job_id.to_string()).await?;
        
        if let Some(data) = result {
            let job: Job = serde_json::from_str(&data)?;
            return Ok(Some(job.status));
        }
        
        Ok(None)
    }

    /// Get job result
    pub async fn get_job_result(&self, job_id: JobId) -> Result<Option<Job>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let result: Option<String> = conn.hget("openre:job:results", job_id.to_string()).await?;
        
        if let Some(data) = result {
            let job: Job = serde_json::from_str(&data)?;
            return Ok(Some(job));
        }
        
        Ok(None)
    }

    async fn store_job_result(&self, job: &Job) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data = serde_json::to_string(job)?;
        let _: () = conn.hset("openre:job:results", job.id.to_string(), data).await?;
        
        // Set TTL for cleanup
        let _: () = conn.expire("openre:job:results", self.config.result_ttl_seconds).await?;
        
        Ok(())
    }

    async fn move_to_dlq(&self, job: &Job, error: String) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        let dlq_entry = serde_json::json!({
            "job": job,
            "error": error,
            "failed_at": chrono::Utc::now(),
            "attempts": job.retry_count,
        });
        
        let _: () = conn.xadd("openre:dlq", "*", &[("data", serde_json::to_string(&dlq_entry)?)])?;
        
        self.metrics.jobs_dlq.inc();
        
        Ok(())
    }

    fn calculate_backoff(&self, attempt: u32) -> chrono::Duration {
        let base = self.config.base_retry_delay_ms;
        let max = self.config.max_retry_delay_ms;
        let delay_ms = (base as f64 * 2_f64.powi(attempt as i32 - 1)).min(max as f64) as i64;
        
        // Add jitter
        let jitter = (rand::random::<f64>() * 0.2 * delay_ms as f64) as i64;
        
        chrono::Duration::milliseconds(delay_ms + jitter)
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> Result<QueueStats> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        let mut stats = QueueStats::default();
        
        for priority in [Priority::High, Priority::Default, Priority::Low] {
            let stream = self.stream_name(priority);
            let len: usize = conn.xlen(&stream).await?;
            stats.jobs_queued_by_priority.insert(priority, len);
            stats.total_queued += len;
        }
        
        let pending = self.pending_jobs.read().await;
        stats.jobs_running = pending.len();
        
        let dlq_len: usize = conn.xlen("openre:dlq").await?;
        stats.jobs_dlq = dlq_len;
        
        let scheduled_count: usize = conn.zcard("openre:scheduled:jobs").await?;
        stats.jobs_scheduled = scheduled_count;
        
        Ok(stats)
    }

    /// Start background maintenance tasks
    pub async fn start_maintenance(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = manager.cleanup_stale_jobs().await {
                    error!("Cleanup stale jobs error: {}", e);
                }
                if let Err(e) = manager.process_scheduled_jobs().await {
                    error!("Process scheduled jobs error: {}", e);
                }
            }
        });
    }

    async fn cleanup_stale_jobs(&self) -> Result<()> {
        let mut pending = self.pending_jobs.write().await;
        let now = chrono::Utc::now();
        let stale_threshold = chrono::Duration::minutes(self.config.stale_job_timeout_minutes);
        
        let mut to_remove = Vec::new();
        for (job_id, pj) in pending.iter() {
            if now - pj.last_attempt > stale_threshold {
                to_remove.push(*job_id);
            }
        }
        
        for job_id in to_remove {
            if let Some(pj) = pending.remove(&job_id) {
                // Re-queue the job
                let mut job = pj.job;
                job.status = JobStatus::Queued;
                job.retry_count += 1;
                self.enqueue(job).await?;
                
                self.metrics.jobs_stale_recovered.inc();
                warn!("Recovered stale job {}", job_id);
            }
        }
        
        Ok(())
    }

    async fn process_scheduled_jobs(&self) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let now = chrono::Utc::now().timestamp_millis() as f64;
        
        // Get jobs that are due
        let due_jobs: Vec<String> = conn.zrangebyscore("openre:scheduled:jobs", 0, now).await?;
        
        for job_id_str in due_jobs {
            let job_data: Option<String> = conn.hget("openre:scheduled:data", &job_id_str).await?;
            
            if let Some(data) = job_data {
                let job: Job = serde_json::from_str(&data)?;
                
                // Remove from scheduled
                let _: () = conn.zrem("openre:scheduled:jobs", &job_id_str).await?;
                let _: () = conn.hdel("openre:scheduled:data", &job_id_str).await?;
                
                // Enqueue to appropriate priority queue
                self.enqueue(job).await?;
            }
        }
        
        Ok(())
    }
}

impl Clone for QueueManager {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            consumer_groups: self.consumer_groups.clone(),
            pending_jobs: self.pending_jobs.clone(),
            semaphore: self.semaphore.clone(),
        }
    }
}

/// Queue statistics
#[derive(Debug, Default, Clone)]
pub struct QueueStats {
    pub total_queued: usize,
    pub jobs_queued_by_priority: HashMap<Priority, usize>,
    pub jobs_running: usize,
    pub jobs_scheduled: usize,
    pub jobs_dlq: usize,
}