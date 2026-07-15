//! Progress tracking for jobs

use crate::{JobId, StageProgress, JobProgress};
use openre_core::error::Result;
use openre_telemetry::metrics::ProgressMetrics;
use redis::{AsyncCommands, Client};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::time::interval;
use tracing::{debug, info};

/// Progress tracker for job and stage progress
pub struct ProgressTracker {
    client: Client,
    metrics: Arc<ProgressMetrics>,
    progress_cache: Arc<RwLock<HashMap<JobId, JobProgress>>>,
    stage_progress_cache: Arc<RwLock<HashMap<JobId, Vec<StageProgress>>>>,
    update_tx: broadcast::Sender<ProgressUpdate>,
}

#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub job_id: JobId,
    pub progress: JobProgress,
    pub stage_progress: Option<StageProgress>,
}

impl ProgressTracker {
    pub fn new(client: Client, metrics: Arc<ProgressMetrics>) -> Self {
        let (update_tx, _) = broadcast::channel(1000);
        
        Self {
            client,
            metrics,
            progress_cache: Arc::new(RwLock::new(HashMap::new())),
            stage_progress_cache: Arc::new(RwLock::new(HashMap::new())),
            update_tx,
        }
    }

    /// Initialize progress for a job
    pub async fn init_job(&self, job_id: JobId, total_stages: u32) -> Result<()> {
        let progress = JobProgress {
            job_id,
            status: crate::JobStatus::Queued,
            overall_progress: 0.0,
            current_stage: None,
            stages_completed: 0,
            total_stages,
            started_at: None,
            updated_at: chrono::Utc::now(),
            estimated_remaining: None,
        };

        self.progress_cache.write().await.insert(job_id, progress.clone());
        self.persist_progress(&progress).await?;
        
        self.metrics.jobs_tracked.inc();
        
        Ok(())
    }

    /// Update job progress
    pub async fn update_job_progress(
        &self,
        job_id: JobId,
        overall_progress: f32,
        status: crate::JobStatus,
    ) -> Result<()> {
        let mut cache = self.progress_cache.write().await;
        
        if let Some(progress) = cache.get_mut(&job_id) {
            progress.overall_progress = overall_progress.clamp(0.0, 1.0);
            progress.status = status;
            progress.updated_at = chrono::Utc::now();
            
            if status == crate::JobStatus::Running && progress.started_at.is_none() {
                progress.started_at = Some(chrono::Utc::now());
            }
            
            // Estimate remaining time
            if progress.overall_progress > 0.0 && progress.started_at.is_some() {
                let elapsed = chrono::Utc::now() - progress.started_at.unwrap();
                let estimated_total = elapsed / progress.overall_progress;
                progress.estimated_remaining = Some(estimated_total - elapsed);
            }
            
            let progress_clone = progress.clone();
            drop(cache);
            
            self.persist_progress(&progress_clone).await?;
            self.broadcast_update(ProgressUpdate {
                job_id,
                progress: progress_clone,
                stage_progress: None,
            }).await;
        }
        
        Ok(())
    }

    /// Update stage progress
    pub async fn update_stage_progress(
        &self,
        job_id: JobId,
        stage_name: &str,
        stage_progress: f32,
        status: crate::StageStatus,
        details: Option<String>,
    ) -> Result<()> {
        let mut stage_cache = self.stage_progress_cache.write().await;
        let stages = stage_cache.entry(job_id).or_default();
        
        let stage_prog = StageProgress {
            stage_name: stage_name.to_string(),
            progress: stage_progress.clamp(0.0, 1.0),
            status,
            details,
            started_at: None,
            completed_at: None,
        };
        
        // Find or insert stage
        if let Some(existing) = stages.iter_mut().find(|s| s.stage_name == stage_name) {
            *existing = stage_prog.clone();
        } else {
            stages.push(stage_prog.clone());
        }
        
        // Update job's current stage
        if let Some(job_progress) = self.progress_cache.write().await.get_mut(&job_id) {
            job_progress.current_stage = Some(stage_name.to_string());
            job_progress.stages_completed = stages.iter().filter(|s| s.status == crate::StageStatus::Completed).count() as u32;
        }
        
        drop(stage_cache);
        
        self.persist_stage_progress(job_id, &stages).await?;
        self.broadcast_update(ProgressUpdate {
            job_id,
            progress: self.progress_cache.read().await.get(&job_id).cloned().unwrap_or_default(),
            stage_progress: Some(stage_prog),
        }).await;
        
        Ok(())
    }

    /// Mark stage as started
    pub async fn start_stage(&self, job_id: JobId, stage_name: &str) -> Result<()> {
        self.update_stage_progress(job_id, stage_name, 0.0, crate::StageStatus::Running, None).await
    }

    /// Mark stage as completed
    pub async fn complete_stage(&self, job_id: JobId, stage_name: &str, details: Option<String>) -> Result<()> {
        self.update_stage_progress(job_id, stage_name, 1.0, crate::StageStatus::Completed, details).await
    }

    /// Mark stage as failed
    pub async fn fail_stage(&self, job_id: JobId, stage_name: &str, error: String) -> Result<()> {
        self.update_stage_progress(job_id, stage_name, 0.0, crate::StageStatus::Failed, Some(error)).await
    }

    /// Get job progress
    pub async fn get_job_progress(&self, job_id: JobId) -> Result<Option<JobProgress>> {
        // Check cache first
        if let Some(progress) = self.progress_cache.read().await.get(&job_id) {
            return Ok(Some(progress.clone()));
        }
        
        // Load from Redis
        self.load_progress(job_id).await
    }

    /// Get stage progress for a job
    pub async fn get_stage_progress(&self, job_id: JobId) -> Result<Vec<StageProgress>> {
        if let Some(stages) = self.stage_progress_cache.read().await.get(&job_id) {
            return Ok(stages.clone());
        }
        
        self.load_stage_progress(job_id).await
    }

    /// Subscribe to progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressUpdate> {
        self.update_tx.subscribe()
    }

    async fn persist_progress(&self, progress: &JobProgress) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data = serde_json::to_string(progress)?;
        let _: () = conn.hset("openre:job:progress", progress.job_id.to_string(), data).await?;
        let _: () = conn.expire("openre:job:progress", 86400).await?; // 24h TTL
        Ok(())
    }

    async fn persist_stage_progress(&self, job_id: JobId, stages: &[StageProgress]) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data = serde_json::to_string(stages)?;
        let _: () = conn.hset("openre:job:stage_progress", job_id.to_string(), data).await?;
        let _: () = conn.expire("openre:job:stage_progress", 86400).await?;
        Ok(())
    }

    async fn load_progress(&self, job_id: JobId) -> Result<Option<JobProgress>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data: Option<String> = conn.hget("openre:job:progress", job_id.to_string()).await?;
        
        if let Some(data) = data {
            let progress: JobProgress = serde_json::from_str(&data)?;
            self.progress_cache.write().await.insert(job_id, progress.clone());
            Ok(Some(progress))
        } else {
            Ok(None)
        }
    }

    async fn load_stage_progress(&self, job_id: JobId) -> Result<Vec<StageProgress>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data: Option<String> = conn.hget("openre:job:stage_progress", job_id.to_string()).await?;
        
        if let Some(data) = data {
            let stages: Vec<StageProgress> = serde_json::from_str(&data)?;
            self.stage_progress_cache.write().await.insert(job_id, stages.clone());
            Ok(stages)
        } else {
            Ok(Vec::new())
        }
    }

    async fn broadcast_update(&self, update: ProgressUpdate) {
        let _ = self.update_tx.send(update);
    }

    /// Start background cleanup
    pub async fn start_cleanup(&self) {
        let tracker = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                tracker.cleanup_old_progress().await;
            }
        });
    }

    async fn cleanup_old_progress(&self) {
        let mut progress_cache = self.progress_cache.write().await;
        let mut stage_cache = self.stage_progress_cache.write().await;
        let now = chrono::Utc::now();
        let max_age = chrono::Duration::hours(24);
        
        progress_cache.retain(|_, v| now - v.updated_at < max_age);
        stage_cache.retain(|_, v| {
            v.iter().any(|s| now - s.started_at.unwrap_or(now) < max_age)
        });
        
        debug!("Cleaned up old progress entries");
    }
}

impl Clone for ProgressTracker {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            metrics: self.metrics.clone(),
            progress_cache: self.progress_cache.clone(),
            stage_progress_cache: self.stage_progress_cache.clone(),
            update_tx: self.update_tx.clone(),
        }
    }
}