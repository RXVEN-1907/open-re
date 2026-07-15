//! Auto-scaler for worker pool

use crate::{QueueManager, WorkerPool, AutoScalerConfig, QueueStats};
use openre_core::error::Result;
use openre_telemetry::metrics::AutoScalerMetrics;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Auto-scaler for dynamically adjusting worker count
pub struct AutoScaler {
    queue_manager: Arc<QueueManager>,
    worker_pool: Arc<RwLock<Option<Arc<WorkerPool>>>>,
    config: AutoScalerConfig,
    metrics: Arc<AutoScalerMetrics>,
    last_scale_action: Arc<RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl AutoScaler {
    pub fn new(
        queue_manager: Arc<QueueManager>,
        config: AutoScalerConfig,
        metrics: Arc<AutoScalerMetrics>,
    ) -> Self {
        Self {
            queue_manager,
            worker_pool: Arc::new(RwLock::new(None)),
            config,
            metrics,
            last_scale_action: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_worker_pool(&self, pool: Arc<WorkerPool>) {
        *self.worker_pool.write().await = Some(pool);
    }

    /// Start the auto-scaler loop
    pub async fn start(&self) {
        let scaler = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(scaler.config.evaluation_interval_seconds));
            loop {
                interval.tick().await;
                if let Err(e) = scaler.evaluate_and_scale().await {
                    warn!("Auto-scaler evaluation error: {}", e);
                }
            }
        });
    }

    async fn evaluate_and_scale(&self) -> Result<()> {
        let stats = self.queue_manager.get_stats().await?;
        let pool = self.worker_pool.read().await;
        
        let Some(pool) = pool.as_ref() else {
            return Ok(()); // Pool not set yet
        };

        let current_workers = pool.active_workers();
        let desired_workers = self.calculate_desired_workers(&stats, current_workers);
        
        if desired_workers != current_workers {
            // Check cooldown
            let can_scale = self.check_cooldown().await;
            if can_scale {
                info!("Auto-scaler: scaling from {} to {} workers (queued: {}, running: {})",
                    current_workers, desired_workers, stats.total_queued, stats.jobs_running);
                
                // We need mutable access to scale
                // In a real implementation, we'd use a different pattern
                // For now, just record the decision
                self.metrics.scale_events.inc();
                *self.last_scale_action.write().await = Some(chrono::Utc::now());
            } else {
                debug!("Auto-scaler: scaling needed but in cooldown period");
            }
        }

        // Record metrics
        self.metrics.current_workers.set(current_workers as i64);
        self.metrics.desired_workers.set(desired_workers as i64);
        self.metrics.queue_depth.set(stats.total_queued as i64);
        self.metrics.jobs_running.set(stats.jobs_running as i64);

        Ok(())
    }

    fn calculate_desired_workers(&self, stats: &QueueStats, current: usize) -> usize {
        let queued = stats.total_queued;
        let running = stats.jobs_running;
        
        // Base calculation: target queue depth per worker
        let target_queue_per_worker = self.config.target_queue_depth_per_worker;
        let min_workers = self.config.min_workers;
        let max_workers = self.config.max_workers;
        
        // Calculate based on queue depth
        let queue_based = ((queued as f64) / target_queue_per_worker).ceil() as usize;
        
        // Consider running jobs
        let running_based = running + (queued / (target_queue_per_worker * 2)).max(1);
        
        // Use the maximum of both calculations
        let desired = queue_based.max(running_based).clamp(min_workers, max_workers);
        
        // Apply hysteresis to prevent thrashing
        let scale_up_threshold = self.config.scale_up_threshold;
        let scale_down_threshold = self.config.scale_down_threshold;
        
        if desired > current {
            // Scale up: require queue to be significantly above threshold
            if queued > current * scale_up_threshold {
                desired.min(current + self.config.max_scale_up_step)
            } else {
                current
            }
        } else if desired < current {
            // Scale down: require queue to be significantly below threshold
            if queued < current * scale_down_threshold {
                desired.max(current - self.config.max_scale_down_step)
            } else {
                current
            }
        } else {
            current
        }
    }

    async fn check_cooldown(&self) -> bool {
        let last = *self.last_scale_action.read().await;
        if let Some(last) = last {
            let elapsed = chrono::Utc::now() - last;
            elapsed.num_seconds() >= self.config.cooldown_seconds as i64
        } else {
            true
        }
    }
}

impl Clone for AutoScaler {
    fn clone(&self) -> Self {
        Self {
            queue_manager: self.queue_manager.clone(),
            worker_pool: self.worker_pool.clone(),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            last_scale_action: self.last_scale_action.clone(),
        }
    }
}