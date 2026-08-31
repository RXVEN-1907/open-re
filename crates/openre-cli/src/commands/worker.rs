//! Worker commands

use crate::{CliError, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_api::{AppState, get_job_handlers};
use openre_config::Config;
use openre_queue::{WorkerPool, WorkerMetrics as QueueWorkerMetrics};
use openre_telemetry::metrics::{MetricsRegistry, WorkerMetrics as TelemetryWorkerMetrics};
use std::sync::Arc;
use tracing::{error, info};

#[derive(Subcommand)]
pub enum WorkerCommands {
    /// Start the worker
    Start {
        /// Number of concurrent jobs
        #[arg(short, long, default_value = "4")]
        concurrency: usize,

        /// Queue priorities to process (comma-separated)
        #[arg(short, long, default_value = "high,default,low")]
        priorities: String,

        /// Enable AI capabilities
        #[arg(long)]
        ai_enabled: bool,
    },
}

impl WorkerCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            WorkerCommands::Start {
                concurrency,
                priorities,
                ai_enabled,
            } => {
                println!("{} Starting worker with concurrency: {}", "✓".green(), concurrency);
                println!("  Priorities: {}", priorities);
                println!("  AI enabled: {}", ai_enabled);

                // Load configuration (uses Figment: config.toml, env vars, etc.)
                let config = Config::load().map_err(CliError::CoreError)?;

                // Create application state (reusing API state creation)
                let state = Arc::new(AppState::new(config.clone()).await.map_err(|e| CliError::ApiError(e.to_string()))?);

                // Get job handlers
                let handlers = get_job_handlers(state.clone());

                // Create worker config from app config
                let worker_config = openre_config::WorkerConfig {
                    min_workers: 1,
                    max_workers: concurrency,
                    max_concurrent_jobs: concurrency,
                    max_memory_mb: 4096,
                    heartbeat_interval_secs: 10,
                    graceful_shutdown_timeout_secs: 60,
                    target_queue_depth_per_worker: 10,
                };

                // Create worker metrics
                let metrics_registry = MetricsRegistry::new();
                let worker_metrics = Arc::new(TelemetryWorkerMetrics::new(&metrics_registry));

                // Create worker pool
                let mut worker_pool = WorkerPool::new(
                    state.queue_manager.clone(),
                    worker_config,
                    config.queue.clone(),
                    worker_metrics,
                );

                // Start the worker pool
                info!("Starting worker pool with {} workers", concurrency);
                worker_pool.start(handlers).await.map_err(|e| CliError::CoreError(e))?;

                // Start scheduler
                info!("Starting scheduler");
                state.scheduler.start().await;

                // Wait for shutdown signal
                tokio::signal::ctrl_c().await?;
                info!("Shutdown signal received, stopping workers...");

                // Graceful shutdown
                worker_pool.stop().await.map_err(|e| CliError::CoreError(e))?;

                println!("{} Worker stopped gracefully", "✓".green());
            }
        }
        Ok(())
    }
}
