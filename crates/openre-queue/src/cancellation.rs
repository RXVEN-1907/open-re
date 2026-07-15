//! Job cancellation system

use crate::{QueueManager, JobId, JobStatus};
use openre_core::error::Result;
use openre_telemetry::metrics::CancellationMetrics;
use redis::{AsyncCommands, Client};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info, warn};

/// Cancellation manager
pub struct CancellationManager {
    queue_manager: Arc<QueueManager>,
    client: Client,
    metrics: Arc<CancellationMetrics>,
    cancelled_jobs: Arc<RwLock<HashMap<JobId, CancellationInfo>>>,
    cancel_tx: broadcast::Sender<JobId>,
}

#[derive(Debug, Clone)]
struct CancellationInfo {
    job_id: JobId,
    requested_at: chrono::DateTime<chrono::Utc>,
    requested_by: String,
    reason: Option<String>,
    status: CancellationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CancellationStatus {
    Pending,
    Signalled,
    Completed,
    Failed,
}

impl CancellationManager {
    pub fn new(
        queue_manager: Arc<QueueManager>,
        client: Client,
        metrics: Arc<CancellationMetrics>,
    ) -> Self {
        let (cancel_tx, _) = broadcast::channel(1000);
        
        Self {
            queue_manager,
            client,
            metrics,
            cancelled_jobs: Arc::new(RwLock::new(HashMap::new())),
            cancel_tx,
        }
    }

    /// Request cancellation of a job
    pub async fn cancel_job(
        &self,
        job_id: JobId,
        requested_by: String,
        reason: Option<String>,
    ) -> Result<CancellationResult> {
        // Check if already cancelled
        {
            let cancelled = self.cancelled_jobs.read().await;
            if cancelled.contains_key(&job_id) {
                return Ok(CancellationResult::AlreadyCancelled);
            }
        }

        // Try to cancel via queue manager
        let cancelled = self.queue_manager.cancel(job_id).await?;
        
        if cancelled {
            // Mark as cancelled in our tracking
            let info = CancellationInfo {
                job_id,
                requested_at: chrono::Utc::now(),
                requested_by,
                reason,
                status: CancellationStatus::Completed,
            };
            
            self.cancelled_jobs.write().await.insert(job_id, info);
            self.metrics.jobs_cancelled.inc();
            
            // Broadcast cancellation
            let _ = self.cancel_tx.send(job_id);
            
            info!("Job {} cancelled by {}", job_id, requested_by);
            Ok(CancellationResult::Cancelled)
        } else {
            // Job might be running - signal the worker
            let info = CancellationInfo {
                job_id,
                requested_at: chrono::Utc::now(),
                requested_by,
                reason,
                status: CancellationStatus::Pending,
            };
            
            self.cancelled_jobs.write().await.insert(job_id, info);
            
            // Signal worker via Redis
            self.signal_worker(job_id).await?;
            
            self.metrics.cancellation_requests.inc();
            
            Ok(CancellationResult::Signalled)
        }
    }

    /// Signal worker to cancel job
    async fn signal_worker(&self, job_id: JobId) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        // Publish cancellation signal
        let signal = serde_json::json!({
            "job_id": job_id.to_string(),
            "action": "cancel",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        let _: () = conn.publish("openre:cancellation", serde_json::to_string(&signal)?).await?;
        
        // Also add to a cancellation stream for workers to poll
        let _: () = conn.xadd("openre:cancellation:signals", "*", &[("job_id", job_id.to_string())]).await?;
        
        Ok(())
    }

    /// Check if a job has been cancelled (for workers to poll)
    pub async fn is_cancelled(&self, job_id: JobId) -> bool {
        let cancelled = self.cancelled_jobs.read().await;
        cancelled.contains_key(&job_id)
    }

    /// Wait for cancellation signal (for workers)
    pub async fn wait_for_cancellation(&self, job_id: JobId) -> Result<()> {
        let mut rx = self.cancel_tx.subscribe();
        
        loop {
            match rx.recv().await {
                Ok(cancelled_id) if cancelled_id == job_id => {
                    return Ok(());
                }
                Ok(_) => continue, // Different job
                Err(_) => return Err(openre_core::Error::Internal("Cancellation channel closed".into())),
            }
        }
    }

    /// Register cancellation handler for a worker
    pub fn register_handler(&self) -> CancellationHandler {
        CancellationHandler {
            cancel_rx: self.cancel_tx.subscribe(),
            client: self.client.clone(),
        }
    }

    /// Get cancellation status
    pub async fn get_status(&self, job_id: JobId) -> Option<CancellationInfo> {
        self.cancelled_jobs.read().await.get(&job_id).cloned()
    }

    /// Force cancel a job (bypass normal checks)
    pub async fn force_cancel(&self, job_id: JobId, requested_by: String) -> Result<()> {
        let info = CancellationInfo {
            job_id,
            requested_at: chrono::Utc::now(),
            requested_by,
            reason: Some("Force cancelled".to_string()),
            status: CancellationStatus::Completed,
        };
        
        self.cancelled_jobs.write().await.insert(job_id, info);
        
        // Try to cancel in queue manager
        let _ = self.queue_manager.cancel(job_id).await;
        
        // Signal worker
        self.signal_worker(job_id).await?;
        
        // Broadcast
        let _ = self.cancel_tx.send(job_id);
        
        self.metrics.jobs_force_cancelled.inc();
        
        warn!("Job {} force cancelled by {}", job_id, requested_by);
        
        Ok(())
    }

    /// Clean up old cancellation records
    pub async fn cleanup(&self, max_age: Duration) {
        let mut cancelled = self.cancelled_jobs.write().await;
        let now = chrono::Utc::now();
        let max_age_chrono = chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::hours(24));
        
        cancelled.retain(|_, info| now - info.requested_at < max_age_chrono);
        
        debug!("Cleaned up old cancellation records");
    }
}

/// Cancellation handler for workers
pub struct CancellationHandler {
    cancel_rx: broadcast::Receiver<JobId>,
    client: Client,
}

impl CancellationHandler {
    /// Check if current job should be cancelled (non-blocking)
    pub fn check_cancellation(&mut self, job_id: JobId) -> bool {
        // Try to receive without blocking
        while let Ok(cancelled_id) = self.cancel_rx.try_recv() {
            if cancelled_id == job_id {
                return true;
            }
        }
        false
    }

    /// Wait for cancellation signal (blocking)
    pub async fn wait_for_cancellation(&mut self, job_id: JobId) -> Result<()> {
        loop {
            match self.cancel_rx.recv().await {
                Ok(cancelled_id) if cancelled_id == job_id => {
                    return Ok(());
                }
                Ok(_) => continue,
                Err(_) => return Err(openre_core::Error::Internal("Cancellation channel closed".into())),
            }
        }
    }

    /// Poll Redis for cancellation signals (alternative to broadcast)
    pub async fn poll_redis(&self, job_id: JobId) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        // Check cancellation stream
        let entries: Vec<redis::streams::StreamReadReply> = conn
            .xread_options(
                &[("openre:cancellation:signals".to_string(), "0-0".to_string())],
                &redis::XReadOptions::default().count(10).block(Duration::from_millis(100)),
            )
            .await?;
        
        for reply in entries {
            for entry in reply.ids {
                if let Some(job_id_str) = entry.map.get("job_id") {
                    let id_str: String = redis::from_redis_value(job_id_str)?;
                    if id_str == job_id.to_string() {
                        return Ok(true);
                    }
                }
            }
        }
        
        Ok(false)
    }
}

/// Cancellation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationResult {
    Cancelled,
    Signalled,
    AlreadyCancelled,
    NotFound,
}

use std::collections::HashMap;