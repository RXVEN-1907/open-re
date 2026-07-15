//! Metrics collection for open-re

use openre_config::MetricsConfig;
use openre_core::error::Result;
use metrics::{counter, gauge, histogram, Unit};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Initialize metrics
pub fn init_metrics(config: &MetricsConfig) -> Result<MetricsGuard> {
    if !config.enabled {
        return Ok(MetricsGuard);
    }

    let addr: SocketAddr = format!("0.0.0.0:{}", config.port).parse()?;
    
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;

    // Register common metrics
    register_common_metrics();

    Ok(MetricsGuard)
}

/// Metrics guard
pub struct MetricsGuard;

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        // Metrics are global, nothing to clean up
    }
}

fn register_common_metrics() {
    // HTTP metrics
    counter!("http_requests_total", "method" => "GET", "status" => "200");
    counter!("http_requests_total", "method" => "POST", "status" => "200");
    histogram!("http_request_duration_seconds", Unit::Seconds);
    
    // Job metrics
    counter!("jobs_total", "status" => "queued");
    counter!("jobs_total", "status" => "running");
    counter!("jobs_total", "status" => "completed");
    counter!("jobs_total", "status" => "failed");
    counter!("jobs_total", "status" => "cancelled");
    histogram!("job_duration_seconds", Unit::Seconds);
    gauge!("jobs_active");
    
    // Stage metrics
    counter!("stage_executions_total", "stage" => "identification", "status" => "success");
    histogram!("stage_duration_seconds", "stage" => "identification", Unit::Seconds);
    
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
    histogram!("ai_request_duration_seconds", Unit::Seconds);
    histogram!("ai_tokens_total");
    gauge!("ai_cache_hit_rate");
    
    // Plugin metrics
    counter!("plugin_executions_total", "plugin" => "unknown", "capability" => "unknown", "status" => "success");
    histogram!("plugin_execution_duration_seconds", Unit::Seconds);
    
    // Database metrics
    histogram!("db_query_duration_seconds", Unit::Seconds);
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