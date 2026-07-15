//! Job scheduler for recurring and delayed jobs

use crate::{QueueManager, Job, JobId, Priority};
use openre_core::error::Result;
use openre_telemetry::metrics::SchedulerMetrics;
use cron::Schedule;
use redis::{AsyncCommands, Client};
use std::collections::HashMap;
use std::sync::Arc;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// Job scheduler for recurring and delayed jobs
pub struct Scheduler {
    queue_manager: Arc<QueueManager>,
    client: Client,
    metrics: Arc<SchedulerMetrics>,
    scheduled_jobs: Arc<RwLock<HashMap<JobId, ScheduledJob>>>,
    recurring_jobs: Arc<RwLock<HashMap<String, RecurringJob>>>,
}

#[derive(Debug, Clone)]
struct ScheduledJob {
    job: Job,
    run_at: chrono::DateTime<chrono::Utc>,
    recurring: bool,
}

#[derive(Debug, Clone)]
struct RecurringJob {
    id: String,
    name: String,
    cron_schedule: Schedule,
    job_template: Job,
    next_run: chrono::DateTime<chrono::Utc>,
    enabled: bool,
    last_run: Option<chrono::DateTime<chrono::Utc>>,
    run_count: u64,
}

impl Scheduler {
    pub fn new(
        queue_manager: Arc<QueueManager>,
        client: Client,
        metrics: Arc<SchedulerMetrics>,
    ) -> Self {
        Self {
            queue_manager,
            client,
            metrics,
            scheduled_jobs: Arc::new(RwLock::new(HashMap::new())),
            recurring_jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Schedule a one-time job
    pub async fn schedule_once(&self, job: Job, run_at: chrono::DateTime<chrono::Utc>) -> Result<JobId> {
        let job_id = job.id;
        
        // Store in Redis sorted set for persistence
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let job_data = serde_json::to_string(&job)?;
        let score = run_at.timestamp_millis() as f64;
        
        let _: () = conn.zadd("openre:scheduler:once", job_id.to_string(), score).await?;
        let _: () = conn.hset("openre:scheduler:once:data", job_id.to_string(), job_data).await?;
        
        // Track in memory
        self.scheduled_jobs.write().await.insert(job_id, ScheduledJob {
            job,
            run_at,
            recurring: false,
        });
        
        self.metrics.jobs_scheduled.inc();
        
        info!("Scheduled one-time job {} for {}", job_id, run_at);
        
        Ok(job_id)
    }

    /// Schedule a recurring job (cron)
    pub async fn schedule_recurring(
        &self,
        name: String,
        cron_expr: &str,
        job_template: Job,
    ) -> Result<String> {
        let schedule = Schedule::from_str(cron_expr)
            .map_err(|e| openre_core::Error::InvalidInput(format!("Invalid cron expression: {}", e)))?;
        
        let next_run = schedule.upcoming(chrono::Utc).next()
            .ok_or_else(|| openre_core::Error::InvalidInput("Could not compute next run time".into()))?;
        
        let recurring_job = RecurringJob {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.clone(),
            cron_schedule: schedule,
            job_template,
            next_run,
            enabled: true,
            last_run: None,
            run_count: 0,
        };
        
        let job_id = recurring_job.id.clone();
        
        // Store in Redis
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data = serde_json::to_string(&recurring_job)?;
        let _: () = conn.hset("openre:scheduler:recurring", &job_id, data).await?;
        
        // Track in memory
        self.recurring_jobs.write().await.insert(job_id.clone(), recurring_job);
        
        self.metrics.recurring_jobs.inc();
        
        info!("Scheduled recurring job '{}' ({}) with cron '{}', next run: {}", name, job_id, cron_expr, next_run);
        
        Ok(job_id)
    }

    /// Enable/disable a recurring job
    pub async fn set_recurring_enabled(&self, job_id: &str, enabled: bool) -> Result<()> {
        let mut recurring = self.recurring_jobs.write().await;
        
        if let Some(job) = recurring.get_mut(job_id) {
            job.enabled = enabled;
            
            // Persist
            let mut conn = self.client.get_multiplexed_async_connection().await?;
            let data = serde_json::to_string(job)?;
            let _: () = conn.hset("openre:scheduler:recurring", job_id, data).await?;
            
            info!("Recurring job {} {}", job_id, if enabled { "enabled" } else { "disabled" });
            Ok(())
        } else {
            Err(openre_core::Error::NotFound(format!("Recurring job not found: {}", job_id)))
        }
    }

    /// Remove a scheduled job
    pub async fn remove_scheduled(&self, job_id: JobId) -> Result<bool> {
        let mut scheduled = self.scheduled_jobs.write().await;
        let removed = scheduled.remove(&job_id).is_some();
        
        if removed {
            let mut conn = self.client.get_multiplexed_async_connection().await?;
            let _: () = conn.zrem("openre:scheduler:once", job_id.to_string()).await?;
            let _: () = conn.hdel("openre:scheduler:once:data", job_id.to_string()).await?;
            self.metrics.jobs_unscheduled.inc();
        }
        
        Ok(removed)
    }

    /// Remove a recurring job
    pub async fn remove_recurring(&self, job_id: &str) -> Result<bool> {
        let mut recurring = self.recurring_jobs.write().await;
        let removed = recurring.remove(job_id).is_some();
        
        if removed {
            let mut conn = self.client.get_multiplexed_async_connection().await?;
            let _: () = conn.hdel("openre:scheduler:recurring", job_id).await?;
            self.metrics.recurring_jobs_removed.inc();
        }
        
        Ok(removed)
    }

    /// Get next run time for a recurring job
    pub async fn get_next_run(&self, job_id: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let recurring = self.recurring_jobs.read().await;
        Ok(recurring.get(job_id).map(|j| j.next_run))
    }

    /// List all recurring jobs
    pub async fn list_recurring(&self) -> Vec<RecurringJobInfo> {
        let recurring = self.recurring_jobs.read().await;
        recurring.values().map(|j| RecurringJobInfo {
            id: j.id.clone(),
            name: j.name.clone(),
            cron_expression: j.cron_schedule.to_string(),
            next_run: j.next_run,
            enabled: j.enabled,
            last_run: j.last_run,
            run_count: j.run_count,
        }).collect()
    }

    /// Start the scheduler loop
    pub async fn start(&self) {
        let scheduler = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                if let Err(e) = scheduler.process_due_jobs().await {
                    error!("Scheduler error: {}", e);
                }
            }
        });
    }

    async fn process_due_jobs(&self) -> Result<()> {
        let now = chrono::Utc::now();
        let now_ms = now.timestamp_millis() as f64;
        
        // Process one-time scheduled jobs
        self.process_one_time_jobs(now_ms).await?;
        
        // Process recurring jobs
        self.process_recurring_jobs(now).await?;
        
        Ok(())
    }

    async fn process_one_time_jobs(&self, now_ms: f64) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        // Get due jobs
        let due_jobs: Vec<String> = conn.zrangebyscore("openre:scheduler:once", 0, now_ms).await?;
        
        for job_id_str in due_jobs {
            let job_data: Option<String> = conn.hget("openre:scheduler:once:data", &job_id_str).await?;
            
            if let Some(data) = job_data {
                let job: Job = serde_json::from_str(&data)?;
                
                // Remove from scheduled
                let _: () = conn.zrem("openre:scheduler:once", &job_id_str).await?;
                let _: () = conn.hdel("openre:scheduler:once:data", &job_id_str).await?;
                
                // Remove from memory
                self.scheduled_jobs.write().await.remove(&job.id);
                
                // Enqueue
                self.queue_manager.enqueue(job).await?;
                
                self.metrics.jobs_triggered.inc();
                info!("Triggered scheduled job {}", job_id_str);
            }
        }
        
        Ok(())
    }

    async fn process_recurring_jobs(&self, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
        let mut recurring = self.recurring_jobs.write().await;
        let mut to_update = Vec::new();
        
        for (id, job) in recurring.iter_mut() {
            if !job.enabled {
                continue;
            }
            
            if job.next_run <= now {
                // Create job instance from template
                let mut job_instance = job.job_template.clone();
                job_instance.id = JobId::new();
                job_instance.scheduled_at = Some(now);
                
                // Enqueue
                if let Err(e) = self.queue_manager.enqueue(job_instance).await {
                    error!("Failed to enqueue recurring job {}: {}", id, e);
                    self.metrics.jobs_failed.inc();
                } else {
                    self.metrics.jobs_triggered.inc();
                    info!("Triggered recurring job '{}' ({})", job.name, id);
                }
                
                // Update next run
                job.last_run = Some(now);
                job.run_count += 1;
                job.next_run = job.cron_schedule.upcoming(chrono::Utc).next()
                    .unwrap_or_else(|| now + chrono::Duration::days(365)); // Far future if no next
                
                to_update.push((id.clone(), job.clone()));
            }
        }
        
        // Persist updates
        if !to_update.is_empty() {
            let mut conn = self.client.get_multiplexed_async_connection().await?;
            for (id, job) in to_update {
                let data = serde_json::to_string(&job)?;
                let _: () = conn.hset("openre:scheduler:recurring", &id, data).await?;
            }
        }
        
        Ok(())
    }

    /// Load scheduled jobs from Redis on startup
    pub async fn load_from_redis(&self) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        // Load one-time jobs
        let scheduled_jobs: Vec<(String, f64)> = conn.zrange_withscores("openre:scheduler:once", 0, -1).await?;
        
        for (job_id_str, score) in scheduled_jobs {
            let job_data: Option<String> = conn.hget("openre:scheduler:once:data", &job_id_str).await?;
            
            if let Some(data) = job_data {
                let job: Job = serde_json::from_str(&data)?;
                let run_at = chrono::DateTime::from_timestamp_millis(score as i64)
                    .unwrap_or(chrono::Utc::now());
                
                self.scheduled_jobs.write().await.insert(job.id, ScheduledJob {
                    job,
                    run_at,
                    recurring: false,
                });
            }
        }
        
        // Load recurring jobs
        let recurring_data: HashMap<String, String> = conn.hgetall("openre:scheduler:recurring").await?;
        
        for (id, data) in recurring_data {
            if let Ok(job) = serde_json::from_str::<RecurringJob>(&data) {
                self.recurring_jobs.write().await.insert(id, job);
            }
        }
        
        info!("Loaded {} scheduled jobs and {} recurring jobs from Redis",
            self.scheduled_jobs.read().await.len(),
            self.recurring_jobs.read().await.len());
        
        Ok(())
    }
}

impl Clone for Scheduler {
    fn clone(&self) -> Self {
        Self {
            queue_manager: self.queue_manager.clone(),
            client: self.client.clone(),
            metrics: self.metrics.clone(),
            scheduled_jobs: self.scheduled_jobs.clone(),
            recurring_jobs: self.recurring_jobs.clone(),
        }
    }
}

/// Recurring job info for listing
#[derive(Debug, Clone)]
pub struct RecurringJobInfo {
    pub id: String,
    pub name: String,
    pub cron_expression: String,
    pub next_run: chrono::DateTime<chrono::Utc>,
    pub enabled: bool,
    pub last_run: Option<chrono::DateTime<chrono::Utc>>,
    pub run_count: u64,
}