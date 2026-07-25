//! Metrics collection for open-re

use openre_config::MetricsConfig;
use openre_core::error::OpenreResult as Result;
use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Initialize metrics
pub fn init_metrics(config: &MetricsConfig) -> Result<MetricsGuard> {
    if !config.enabled {
        return Ok(MetricsGuard);
    }

    let addr: SocketAddr = format!("0.0.0.0:{}", config.port).parse()
        .map_err(|e: std::net::AddrParseError| openre_core::Error::Internal(e.into()))?;
    
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e: metrics_exporter_prometheus::BuildError| openre_core::Error::Internal(e.into()))?;

    // Register common metrics
    register_common_metrics();

    Ok(MetricsGuard)
}

/// Metrics guard
pub struct MetricsGuard;

/// Metrics registry for creating typed metrics
pub struct MetricsRegistry;

impl MetricsRegistry {
    pub fn new() -> Self {
        Self
    }

    pub fn counter(&self, name: &'static str, _description: &str) -> Counter {
        metrics::counter!(name)
    }

    pub fn gauge(&self, name: &'static str, _description: &str) -> Gauge {
        metrics::gauge!(name)
    }

    pub fn histogram(&self, name: &'static str, _description: &str) -> Histogram {
        metrics::histogram!(name)
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        // Metrics are global, nothing to clean up
    }
}

// Re-export metrics types for downstream crates
pub use metrics::{Counter as MetricsCounter, Gauge as MetricsGauge, Histogram as MetricsHistogram};

fn register_common_metrics() {
    // HTTP metrics
    counter!("http_requests_total", "method" => "GET", "status" => "200");
    counter!("http_requests_total", "method" => "POST", "status" => "200");
    histogram!("http_request_duration_seconds");
    
    // Job metrics
    counter!("jobs_total", "status" => "queued");
    counter!("jobs_total", "status" => "running");
    counter!("jobs_total", "status" => "completed");
    counter!("jobs_total", "status" => "failed");
    counter!("jobs_total", "status" => "cancelled");
    histogram!("job_duration_seconds");
    gauge!("jobs_active");
    
    // Stage metrics
    counter!("stage_executions_total", "stage" => "identification", "status" => "success");
    histogram!("stage_duration_seconds", "stage" => "identification");
    
    // Worker metrics
    gauge!("workers_total");
    gauge!("workers_idle");
    gauge!("workers_running");
    histogram!("worker_memory_mb");
    gauge!("worker_cpu_percent");
    
    // Queue metrics
    gauge!("queue_depth", "priority" => "high");
    gauge!("queue_depth", "priority" => "default");
    gauge!("queue_depth", "priority" => "low");
    gauge!("queue_depth", "priority" => "scheduled");
    gauge!("dlq_size");
    
    // AI metrics
    counter!("ai_requests_total", "task" => "function_naming", "provider" => "local");
    counter!("ai_requests_total", "task" => "pseudocode", "provider" => "local");
    histogram!("ai_request_duration_seconds");
    histogram!("ai_tokens_total");
    gauge!("ai_cache_hit_rate");
    
    // Plugin metrics
    counter!("plugin_executions_total", "plugin" => "unknown", "capability" => "unknown", "status" => "success");
    histogram!("plugin_execution_duration_seconds");
    
    // Database metrics
    histogram!("db_query_duration_seconds");
    gauge!("db_pool_connections_active");
    gauge!("db_pool_connections_idle");
    
    // Cache metrics
    counter!("cache_hits_total");
    counter!("cache_misses_total");
    gauge!("cache_size");
}

/// Increment HTTP request counter
pub fn record_http_request(method: &str, status: u16, duration: std::time::Duration) {
    counter!("http_requests_total", "method" => method.to_string(), "status" => status.to_string()).increment(1);
    histogram!("http_request_duration_seconds").record(duration.as_secs_f64());
}

/// Record job metrics
pub fn record_job_queued() {
    counter!("jobs_total", "status" => "queued").increment(1);
    gauge!("jobs_active").increment(1.0);
}

pub fn record_job_started() {
    counter!("jobs_total", "status" => "running").increment(1);
}

pub fn record_job_completed(duration: std::time::Duration) {
    counter!("jobs_total", "status" => "completed").increment(1);
    histogram!("job_duration_seconds").record(duration.as_secs_f64());
    gauge!("jobs_active").decrement(1.0);
}

pub fn record_job_failed(duration: std::time::Duration, retryable: bool) {
    counter!("jobs_total", "status" => "failed").increment(1);
    histogram!("job_duration_seconds").record(duration.as_secs_f64());
    gauge!("jobs_active").decrement(1.0);
}

pub fn record_job_cancelled() {
    counter!("jobs_total", "status" => "cancelled").increment(1);
    gauge!("jobs_active").decrement(1.0);
}

/// Record stage metrics
pub fn record_stage_started(stage: &str) {
    counter!("stage_executions_total", "stage" => stage.to_string(), "status" => "started").increment(1);
}

pub fn record_stage_completed(stage: &str, duration: std::time::Duration) {
    counter!("stage_executions_total", "stage" => stage.to_string(), "status" => "success").increment(1);
    histogram!("stage_duration_seconds", "stage" => stage.to_string()).record(duration.as_secs_f64());
}

pub fn record_stage_failed(stage: &str, duration: std::time::Duration) {
    counter!("stage_executions_total", "stage" => stage.to_string(), "status" => "failed").increment(1);
    histogram!("stage_duration_seconds", "stage" => stage.to_string()).record(duration.as_secs_f64());
}

/// Record worker metrics
pub fn record_worker_started() {
    gauge!("workers_total").increment(1.0);
    gauge!("workers_idle").increment(1.0);
}

pub fn record_worker_stopped() {
    gauge!("workers_total").decrement(1.0);
    gauge!("workers_idle").decrement(1.0);
}

pub fn record_worker_job_started() {
    gauge!("workers_idle").decrement(1.0);
    gauge!("workers_running").increment(1.0);
}

pub fn record_worker_job_completed() {
    gauge!("workers_running").decrement(1.0);
    gauge!("workers_idle").increment(1.0);
}

pub fn record_worker_memory(mb: u64) {
    gauge!("worker_memory_mb").set(mb as f64);
}

pub fn record_worker_cpu(percent: f32) {
    gauge!("worker_cpu_percent").set(percent as f64);
}

/// Record queue metrics
pub fn record_queue_depth(priority: &str, depth: usize) {
    gauge!("queue_depth", "priority" => priority.to_string()).set(depth as f64);
}

pub fn record_dlq_size(size: usize) {
    gauge!("dlq_size").set(size as f64);
}

/// Record AI metrics
pub fn record_ai_request(task: &str, provider: &str, duration: std::time::Duration, tokens: u32, cached: bool) {
    counter!("ai_requests_total", "task" => task.to_string(), "provider" => provider.to_string()).increment(1);
    histogram!("ai_request_duration_seconds").record(duration.as_secs_f64());
    histogram!("ai_tokens_total").record(tokens as f64);
    if cached {
        counter!("cache_hits_total").increment(1);
    } else {
        counter!("cache_misses_total").increment(1);
    }
}

/// Record plugin metrics
pub fn record_plugin_execution(plugin: &str, capability: &str, duration: std::time::Duration, success: bool) {
    let status = if success { "success" } else { "failed" };
    counter!("plugin_executions_total", "plugin" => plugin.to_string(), "capability" => capability.to_string(), "status" => status).increment(1);
    histogram!("plugin_execution_duration_seconds").record(duration.as_secs_f64());
}

/// Record database metrics
pub fn record_db_query(duration: std::time::Duration) {
    histogram!("db_query_duration_seconds").record(duration.as_secs_f64());
}

pub fn record_db_pool(active: usize, idle: usize) {
    gauge!("db_pool_connections_active").set(active as f64);
    gauge!("db_pool_connections_idle").set(idle as f64);
}

/// Queue metrics struct for external use
pub struct QueueMetrics {
    pub jobs_queued: Counter,
    pub jobs_dequeued: Counter,
    pub jobs_completed: Counter,
    pub jobs_failed: Counter,
    pub jobs_retried: Counter,
    pub jobs_cancelled: Counter,
    pub jobs_scheduled: Counter,
    pub jobs_triggered: Counter,
    pub jobs_unscheduled: Counter,
    pub jobs_stale_recovered: Counter,
    pub jobs_dlq: Counter,
    pub jobs_by_priority: Counter,
    pub jobs_running: Gauge,
    pub queue_depth: Gauge,
    pub queue_depth_by_priority: Gauge,
}

impl QueueMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            jobs_queued: counter!("queue_jobs_queued_total"),
            jobs_dequeued: counter!("queue_jobs_dequeued_total"),
            jobs_completed: counter!("queue_jobs_completed_total"),
            jobs_failed: counter!("queue_jobs_failed_total"),
            jobs_retried: counter!("queue_jobs_retried_total"),
            jobs_cancelled: counter!("queue_jobs_cancelled_total"),
            jobs_scheduled: counter!("queue_jobs_scheduled_total"),
            jobs_triggered: counter!("queue_jobs_triggered_total"),
            jobs_unscheduled: counter!("queue_jobs_unscheduled_total"),
            jobs_stale_recovered: counter!("queue_jobs_stale_recovered_total"),
            jobs_dlq: counter!("queue_jobs_dlq_total"),
            jobs_by_priority: counter!("queue_jobs_by_priority_total"),
            jobs_running: gauge!("queue_jobs_running"),
            queue_depth: gauge!("queue_depth"),
            queue_depth_by_priority: gauge!("queue_depth_by_priority"),
        }
    }
}

/// Worker metrics struct for external use
pub struct WorkerMetrics {
    pub jobs_processed: Counter,
    pub jobs_succeeded: Counter,
    pub jobs_failed: Counter,
    pub worker_errors: Counter,
    pub job_duration: Histogram,
    pub active_workers: Gauge,
}

impl WorkerMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            jobs_processed: counter!("worker_jobs_processed_total"),
            jobs_succeeded: counter!("worker_jobs_succeeded_total"),
            jobs_failed: counter!("worker_jobs_failed_total"),
            worker_errors: counter!("worker_errors_total"),
            job_duration: histogram!("worker_job_duration_ms"),
            active_workers: gauge!("worker_active"),
        }
    }
}

/// Auto-scaler metrics struct for external use
pub struct AutoScalerMetrics {
    pub scale_events: Counter,
    pub current_workers: Gauge,
    pub desired_workers: Gauge,
    pub queue_depth: Gauge,
    pub jobs_running: Gauge,
}

impl AutoScalerMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            scale_events: counter!("autoscaler_scale_events_total"),
            current_workers: gauge!("autoscaler_current_workers"),
            desired_workers: gauge!("autoscaler_desired_workers"),
            queue_depth: gauge!("autoscaler_queue_depth"),
            jobs_running: gauge!("autoscaler_jobs_running"),
        }
    }
}

/// Progress metrics struct for external use
pub struct ProgressMetrics {
    pub jobs_tracked: Counter,
    pub progress_updates: Counter,
}

impl ProgressMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            jobs_tracked: counter!("progress_jobs_tracked_total"),
            progress_updates: counter!("progress_progress_updates_total"),
        }
    }
}

/// Cancellation metrics struct for external use
pub struct CancellationMetrics {
    pub cancellations_requested: Counter,
    pub cancellations_completed: Counter,
    pub cancellations_failed: Counter,
}

impl CancellationMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            cancellations_requested: counter!("cancellation_requested_total"),
            cancellations_completed: counter!("cancellation_completed_total"),
            cancellations_failed: counter!("cancellation_failed_total"),
        }
    }
}

/// Scheduler metrics struct for external use
pub struct SchedulerMetrics {
    pub jobs_scheduled: Counter,
    pub jobs_triggered: Counter,
    pub jobs_missed: Counter,
}

impl SchedulerMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            jobs_scheduled: counter!("scheduler_jobs_scheduled_total"),
            jobs_triggered: counter!("scheduler_jobs_triggered_total"),
            jobs_missed: counter!("scheduler_jobs_missed_total"),
        }
    }
}