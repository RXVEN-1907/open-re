//! Metrics collection for open-re

use metrics::{increment_counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use openre_config::MetricsConfig;
use openre_core::error::OpenreResult as Result;
use std::net::SocketAddr;

/// Initialize metrics
pub fn init_metrics(config: &MetricsConfig) -> Result<MetricsGuard> {
    if !config.enabled {
        return Ok(MetricsGuard);
    }

    let addr: SocketAddr = format!("0.0.0.0:{}", config.port)
        .parse()
        .map_err(|e: std::net::AddrParseError| openre_core::Error::Internal(e.into()))?;

    PrometheusBuilder::new().with_http_listener(addr).install().map_err(
        |e: metrics_exporter_prometheus::BuildError| openre_core::Error::Internal(e.into()),
    )?;

    Ok(MetricsGuard)
}

/// Metrics guard
pub struct MetricsGuard;

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        // Metrics are global, nothing to clean up
    }
}

/// Increment HTTP request counter
pub fn record_http_request(method: &str, status: u16, duration: std::time::Duration) {
    increment_counter!("http_requests_total");
    histogram!("http_request_duration_seconds", duration.as_secs_f64());
}

/// Record job metrics
pub fn record_job_queued() {
    increment_counter!("jobs_total_queued");
    gauge!("jobs_active", 1.0);
}

pub fn record_job_started() {
    increment_counter!("jobs_total_running");
}

pub fn record_job_completed(duration: std::time::Duration) {
    increment_counter!("jobs_total_completed");
    histogram!("job_duration_seconds", duration.as_secs_f64());
    gauge!("jobs_active", -1.0);
}

pub fn record_job_failed(duration: std::time::Duration, _retryable: bool) {
    increment_counter!("jobs_total_failed");
    histogram!("job_duration_seconds", duration.as_secs_f64());
    gauge!("jobs_active", -1.0);
}

pub fn record_job_cancelled() {
    increment_counter!("jobs_total_cancelled");
    gauge!("jobs_active", -1.0);
}

/// Record stage metrics
pub fn record_stage_started(stage: &str) {
    increment_counter!("stage_executions_total");
}

pub fn record_stage_completed(stage: &str, duration: std::time::Duration) {
    increment_counter!("stage_executions_total");
    histogram!("stage_duration_seconds", duration.as_secs_f64());
}

pub fn record_stage_failed(stage: &str, duration: std::time::Duration) {
    increment_counter!("stage_executions_total");
    histogram!("stage_duration_seconds", duration.as_secs_f64());
}

/// Record worker metrics
pub fn record_worker_started() {
    gauge!("workers_total", 1.0);
    gauge!("workers_idle", 1.0);
}

pub fn record_worker_stopped() {
    gauge!("workers_total", -1.0);
    gauge!("workers_idle", -1.0);
}

pub fn record_worker_job_started() {
    gauge!("workers_idle", -1.0);
    gauge!("workers_running", 1.0);
}

pub fn record_worker_job_completed() {
    gauge!("workers_running", -1.0);
    gauge!("workers_idle", 1.0);
}

pub fn record_worker_memory(mb: u64) {
    gauge!("worker_memory_mb", mb as f64);
}

pub fn record_worker_cpu(percent: f32) {
    gauge!("worker_cpu_percent", percent as f64);
}

/// Record queue metrics
pub fn record_queue_depth(priority: &str, depth: usize) {
    gauge!("queue_depth", depth as f64);
}

pub fn record_dlq_size(size: usize) {
    gauge!("dlq_size", size as f64);
}

/// Record AI metrics
pub fn record_ai_request(
    task: &str,
    provider: &str,
    duration: std::time::Duration,
    tokens: u32,
    cached: bool,
) {
    increment_counter!("ai_requests_total");
    histogram!("ai_request_duration_seconds", duration.as_secs_f64());
    histogram!("ai_tokens_total", tokens as f64);
    if cached {
        increment_counter!("cache_hits_total");
    } else {
        increment_counter!("cache_misses_total");
    }
}

/// Record plugin metrics
pub fn record_plugin_execution(
    _plugin: &str,
    _capability: &str,
    duration: std::time::Duration,
    _success: bool,
) {
    increment_counter!("plugin_executions_total");
    histogram!("plugin_execution_duration_seconds", duration.as_secs_f64());
}

/// Record database metrics
pub fn record_db_query(duration: std::time::Duration) {
    histogram!("db_query_duration_seconds", duration.as_secs_f64());
}

pub fn record_db_pool(active: usize, idle: usize) {
    gauge!("db_pool_connections_active", active as f64);
    gauge!("db_pool_connections_idle", idle as f64);
}