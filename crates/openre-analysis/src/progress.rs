//! Progress tracking for analysis jobs

use serde::{Deserialize, Serialize};

use chrono::{DateTime, Utc};
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use openre_queue::QueueManager;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::debug;

/// Job progress for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    pub job_id: JobId,
    pub status: JobStatus,
    pub current_stage: Option<StageId>,
    pub stage_progress: f32,   // 0.0 - 1.0
    pub overall_progress: f32, // 0.0 - 1.0
    pub message: String,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub estimated_remaining_secs: Option<u64>,
    pub stages: Vec<StageProgress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageProgress {
    pub name: StageId,
    pub status: StageStatus,
    pub progress: f32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JobStatus {
    Queued { queued_at: DateTime<Utc> },
    Running { worker_id: WorkerId, started_at: DateTime<Utc>, stage: StageId },
    Completed { completed_at: DateTime<Utc> },
    Failed { error: String, failed_at: DateTime<Utc>, retryable: bool },
    Cancelled { cancelled_at: DateTime<Utc>, reason: String },
    Scheduled { run_at: DateTime<Utc> },
}

/// Progress tracker for real-time updates
pub struct ProgressTracker {
    queue: Arc<QueueManager>,
    cache: Arc<RwLock<HashMap<JobId, JobProgress>>>,
    /// Broadcast channel for real-time progress updates
    progress_tx: broadcast::Sender<JobProgress>,
}

impl ProgressTracker {
    pub fn new(queue: Arc<QueueManager>) -> Self {
        let (tx, _rx) = broadcast::channel(1024);
        Self {
            queue,
            cache: Arc::new(RwLock::new(HashMap::new())),
            progress_tx: tx,
        }
    }

    /// Create a ProgressTracker for testing without QueueManager
    pub fn new_for_testing() -> Self {
        let (tx, _rx) = broadcast::channel(1024);
        Self {
            queue: Arc::new((*QueueManager::new_for_testing()).clone()),
            cache: Arc::new(RwLock::new(HashMap::new())),
            progress_tx: tx,
        }
    }

    /// Subscribe to real-time progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<JobProgress> {
        self.progress_tx.subscribe()
    }

    /// Update job progress (called by worker)
    pub async fn update_progress(&self, progress: JobProgress) -> Result<()> {
        // Store in cache for real-time polling
        self.cache.write().await.insert(progress.job_id, progress.clone());

        // Broadcast to subscribers
        let _ = self.progress_tx.send(progress.clone());

        debug!(job_id = %progress.job_id, progress = progress.overall_progress, "Job progress updated");
        Ok(())
    }

    /// Get current progress
    pub async fn get_progress(&self, job_id: JobId) -> Result<Option<JobProgress>> {
        Ok(self.cache.read().await.get(&job_id).cloned())
    }

    /// Clear progress cache for a job
    pub async fn clear(&self, job_id: JobId) {
        self.cache.write().await.remove(&job_id);
    }

    /// Update job progress (static version for testing without &self)
    pub async fn update_progress_static(tracker: &ProgressTracker, progress: JobProgress) -> Result<()> {
        tracker.cache.write().await.insert(progress.job_id, progress.clone());
        let _ = tracker.progress_tx.send(progress.clone());
        Ok(())
    }
}
