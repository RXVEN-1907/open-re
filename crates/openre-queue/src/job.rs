//! Job definitions for open-re queue system

use openre_core::ids::{JobId, ProjectId, FileId, UserId};
use openre_core::traits::JobType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Scheduled,
}

/// Stage status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

/// Job priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    High,
    Default,
    Low,
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::High => "HIGH",
            Priority::Default => "DEFAULT",
            Priority::Low => "LOW",
        }
    }
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Default
    }
}

/// Job retry policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRetryPolicy {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: f64,
    pub jitter: bool,
    pub retryable_errors: Vec<String>,
}

impl Default for JobRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 1000,
            max_delay_ms: 60000,
            multiplier: 2.0,
            jitter: true,
            retryable_errors: vec![],
        }
    }
}

/// Job definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: JobId,
    pub job_type: JobType,
    pub priority: Priority,
    pub status: JobStatus,
    pub project_id: Option<ProjectId>,
    pub file_id: Option<FileId>,
    pub user_id: Option<UserId>,
    pub payload: serde_json::Value,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub retry_count: u32,
    pub retry_policy: Option<JobRetryPolicy>,
    pub queued_at: Option<DateTime<Utc>>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub worker_id: Option<String>,
    pub tags: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub progress: Option<f32>,
}

impl Job {
    pub fn new(job_type: JobType) -> Self {
        Self {
            id: JobId::new(),
            job_type,
            priority: Priority::Default,
            status: JobStatus::Pending,
            project_id: None,
            file_id: None,
            user_id: None,
            payload: serde_json::Value::Null,
            result: None,
            error: None,
            retry_count: 0,
            retry_policy: None,
            queued_at: None,
            scheduled_at: None,
            started_at: None,
            completed_at: None,
            worker_id: None,
            tags: HashMap::new(),
            timeout_seconds: None,
            progress: None,
        }
    }

    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }

    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_project(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    pub fn with_file(mut self, file_id: FileId) -> Self {
        self.file_id = Some(file_id);
        self
    }

    pub fn with_user(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_seconds = Some(timeout.as_secs());
        self
    }

    pub fn with_retry_policy(mut self, policy: JobRetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    pub fn with_tag(mut self, key: String, value: String) -> Self {
        self.tags.insert(key, value);
        self
    }
}

/// Job handler trait
use async_trait::async_trait;

#[async_trait]
pub trait JobHandler: Send + Sync {
    fn job_type(&self) -> JobType;
    fn can_handle(&self, job: &Job) -> bool {
        job.job_type == self.job_type()
    }
    async fn handle(&self, job: Job) -> Result<serde_json::Value>;
    fn should_retry(&self, error: &openre_core::Error) -> bool {
        // Default: retry on timeout, connection errors, resource exhaustion
        matches!(error,
            openre_core::Error::Timeout(_) |
            openre_core::Error::ConnectionError(_) |
            openre_core::Error::ResourceExhausted(_)
        )
    }
}

/// Job result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: JobId,
    pub status: JobStatus,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub worker_id: String,
    pub completed_at: DateTime<Utc>,
}

/// Job progress
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JobProgress {
    pub job_id: JobId,
    pub status: JobStatus,
    pub overall_progress: f32,
    pub current_stage: Option<String>,
    pub stages_completed: u32,
    pub total_stages: u32,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub estimated_remaining: Option<chrono::Duration>,
}

/// Stage progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageProgress {
    pub stage_name: String,
    pub progress: f32,
    pub status: StageStatus,
    pub details: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

use openre_core::error::Result;