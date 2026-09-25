//! Local job/queue types to replace openre_queue dependency

use chrono::{DateTime, Utc};
use openre_config::{QueueConfig, RedisConfig};
use openre_core::ids::{JobId, JobStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub trait QueueMetrics: Send + Sync {}
/// Job priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
pub enum Priority {
    Low = 0,
    #[default]
    Default = 1,
    High = 2,
    Critical = 3,
}

/// Job type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobType {
    Scan,
    Analysis,
    AiAnalysis,
    ReportGeneration,
    PluginExecution,
    Verification,
    Correlation,
    Prioritization,
    Investigation,
    Workflow,
    Maintenance,
}

/// Job payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: JobId,
    pub job_type: JobType,
    pub status: JobStatus,
    pub priority: Priority,
    pub payload: serde_json::Value,
    pub result: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub progress: u32,
    pub attempts: u32,
    pub max_attempts: u32,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub worker_id: Option<String>,
    pub parent_job_id: Option<JobId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Job {
    pub fn new(job_type: JobType, payload: serde_json::Value) -> Self {
        let now = Utc::now();
        Self {
            id: JobId::new(),
            job_type,
            status: JobStatus::Queued { queued_at: now },
            priority: Priority::Default,
            payload,
            result: None,
            error_message: None,
            progress: 0,
            attempts: 0,
            max_attempts: 3,
            scheduled_at: None,
            started_at: None,
            completed_at: None,
            worker_id: None,
            parent_job_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Queue statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub total_queued: usize,
    pub jobs_queued_by_priority: HashMap<Priority, usize>,
    pub jobs_running: usize,
    pub jobs_scheduled: usize,
    pub jobs_dlq: usize,
    pub workers_active: usize,
    pub workers_idle: usize,
}

/// Queue manager trait (simplified)
#[derive(Debug, Clone)]
pub struct QueueManager {
    _queue_config: QueueConfig,
    _redis_config: RedisConfig,
    // Simplified - in reality this would connect to Redis
}

impl QueueManager {
    pub fn new(
        queue_config: QueueConfig,
        redis_config: RedisConfig,
        _metrics: Arc<dyn QueueMetrics + Send + Sync>,
    ) -> Self {
        Self { _queue_config: queue_config, _redis_config: redis_config }
    }

    pub async fn enqueue(&self, _job: Job) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn complete(&self, _job_id: JobId, _result: serde_json::Value) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn fail(&self, _job_id: JobId, _error: String, _retry: bool) -> anyhow::Result<()> {
        Ok(())
    }

    pub async fn get_stats(&self) -> anyhow::Result<QueueStats> {
        Ok(QueueStats {
            total_queued: 0,
            jobs_queued_by_priority: HashMap::new(),
            jobs_running: 0,
            jobs_scheduled: 0,
            jobs_dlq: 0,
            workers_active: 0,
            workers_idle: 0,
        })
    }

    pub async fn cancel(&self, _job_id: JobId) -> bool {
        // Simplified - in reality this would attempt to cancel the job in Redis
        false
    }
}

impl Default for QueueManager {
    fn default() -> Self {
        Self::new(QueueConfig::default(), RedisConfig::default(), Arc::new(NullMetrics))
    }
}

#[derive(Debug, Clone)]
pub struct NullMetrics;

impl QueueMetrics for NullMetrics {}
