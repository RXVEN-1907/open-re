//! Worker pool for open-re queue system

use crate::{QueueManager, Job, JobHandler, WorkerConfig, WorkerMetrics};
use openre_core::error::Result;
use openre_core::ids::WorkerId;
use openre_telemetry::metrics::WorkerMetrics as TelemetryWorkerMetrics;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Worker pool managing multiple workers
pub struct WorkerPool {
    queue_manager: Arc<QueueManager>,
    config: WorkerConfig,
    metrics: Arc<TelemetryWorkerMetrics>,
    workers: Vec<WorkerHandle>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

struct WorkerHandle {
    id: WorkerId,
    handle: JoinHandle<()>,
    shutdown_tx: mpsc::Sender<()>,
}

impl WorkerPool {
    pub fn new(
        queue_manager: Arc<QueueManager>,
        config: WorkerConfig,
        metrics: Arc<TelemetryWorkerMetrics>,
    ) -> Self {
        Self {
            queue_manager,
            config,
            metrics,
            workers: Vec::new(),
            shutdown_tx: None,
        }
    }

    /// Start the worker pool
    pub async fn start(&mut self, handlers: Vec<Box<dyn JobHandler>>) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        let semaphore = Arc::new(Semaphore::new(self.config.max_workers));
        
        for i in 0..self.config.max_workers {
            let worker_id = WorkerId::new();
            let queue_manager = self.queue_manager.clone();
            let config = self.config.clone();
            let metrics = self.metrics.clone();
            let handlers = handlers.clone();
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let (worker_shutdown_tx, worker_shutdown_rx) = mpsc::channel(1);

            let handle = tokio::spawn(async move {
                let _permit = permit; // Hold permit for worker lifetime
                Self::worker_loop(worker_id, queue_manager, config, metrics, handlers, worker_shutdown_rx).await;
            });

            self.workers.push(WorkerHandle {
                id: worker_id,
                handle,
                shutdown_tx: worker_shutdown_tx,
            });

            info!("Started worker {}", worker_id);
        }

        // Start shutdown listener
        let workers = self.workers.clone();
        tokio::spawn(async move {
            shutdown_rx.recv().await;
            info!("Shutdown signal received, stopping workers...");
            for worker in workers {
                let _ = worker.shutdown_tx.send(()).await;
            }
        });

        Ok(())
    }

    async fn worker_loop(
        worker_id: WorkerId,
        queue_manager: Arc<QueueManager>,
        config: WorkerConfig,
        metrics: Arc<TelemetryWorkerMetrics>,
        handlers: Vec<Box<dyn JobHandler>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let priorities = config.priorities.clone();
        let poll_interval = Duration::from_millis(config.poll_interval_ms);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Worker {} shutting down", worker_id);
                    break;
                }
                _ = tokio::time::sleep(poll_interval) => {
                    // Try to dequeue a job
                    match queue_manager.dequeue(&worker_id.to_string(), &priorities).await {
                        Ok(Some(job)) => {
                            metrics.jobs_processed.inc();
                            let start = std::time::Instant::now();
                            
                            // Find handler for job type
                            if let Some(handler) = handlers.iter().find(|h| h.can_handle(&job)) {
                                let result = handler.handle(job.clone()).await;
                                
                                let duration = start.elapsed().as_millis() as u64;
                                metrics.job_duration.observe(duration as f64);
                                
                                match result {
                                    Ok(output) => {
                                        if let Err(e) = queue_manager.complete(job.id, output).await {
                                            error!("Failed to complete job {}: {}", job.id, e);
                                        }
                                        metrics.jobs_succeeded.inc();
                                    }
                                    Err(e) => {
                                        let should_retry = handler.should_retry(&e);
                                        if let Err(e) = queue_manager.fail(job.id, e.to_string(), should_retry).await {
                                            error!("Failed to fail job {}: {}", job.id, e);
                                        }
                                        metrics.jobs_failed.inc();
                                    }
                                }
                            } else {
                                error!("No handler for job type: {}", job.job_type);
                                let _ = queue_manager.fail(job.id, "No handler found".to_string(), false).await;
                                metrics.jobs_failed.inc();
                            }
                        }
                        Ok(None) => {
                            // No job available, continue loop
                        }
                        Err(e) => {
                            error!("Worker {} dequeue error: {}", worker_id, e);
                            metrics.worker_errors.inc();
                        }
                    }
                }
            }
        }
    }

    /// Stop the worker pool
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        // Wait for all workers to finish
        for worker in self.workers.drain(..) {
            if let Err(e) = worker.handle.await {
                error!("Worker {} panicked: {:?}", worker.id, e);
            }
        }

        info!("Worker pool stopped");
        Ok(())
    }

    /// Get number of active workers
    pub fn active_workers(&self) -> usize {
        self.workers.len()
    }

    /// Scale worker pool
    pub async fn scale(&mut self, new_size: usize, handlers: Vec<Box<dyn JobHandler>>) -> Result<()> {
        if new_size > self.config.max_workers {
            return Err(openre_core::Error::InvalidInput("Cannot exceed max_workers".into()));
        }

        let current = self.workers.len();
        
        if new_size > current {
            // Add workers
            for _ in current..new_size {
                let worker_id = WorkerId::new();
                let queue_manager = self.queue_manager.clone();
                let config = self.config.clone();
                let metrics = self.metrics.clone();
                let handlers = handlers.clone();
                let (worker_shutdown_tx, worker_shutdown_rx) = mpsc::channel(1);

                let handle = tokio::spawn(async move {
                    Self::worker_loop(worker_id, queue_manager, config, metrics, handlers, worker_shutdown_rx).await;
                });

                self.workers.push(WorkerHandle {
                    id: worker_id,
                    handle,
                    shutdown_tx: worker_shutdown_tx,
                });

                info!("Scaled up: added worker {}", worker_id);
            }
        } else if new_size < current {
            // Remove workers (send shutdown to excess)
            let to_remove = current - new_size;
            for _ in 0..to_remove {
                if let Some(worker) = self.workers.pop() {
                    let _ = worker.shutdown_tx.send(()).await;
                    info!("Scaled down: removing worker {}", worker.id);
                }
            }
        }

        Ok(())
    }
}