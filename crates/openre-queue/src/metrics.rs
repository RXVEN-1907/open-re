//! Metrics for queue system

use metrics::{counter, gauge, histogram};
use openre_telemetry::{
    MetricsCounter as Counter, MetricsGauge as Gauge, MetricsHistogram as Histogram,
    MetricsRegistry,
};

/// Queue metrics
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

/// Worker metrics
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

/// Auto-scaler metrics
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

/// Progress metrics
pub struct ProgressMetrics {
    pub jobs_tracked: Counter,
    pub progress_updates: Counter,
}

impl ProgressMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            jobs_tracked: counter!("progress_jobs_tracked_total"),
            progress_updates: counter!("progress_updates_total"),
        }
    }
}

/// Cancellation metrics
pub struct CancellationMetrics {
    pub cancellation_requests: Counter,
    pub jobs_cancelled: Counter,
    pub jobs_force_cancelled: Counter,
}

impl CancellationMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            cancellation_requests: counter!("cancellation_requests_total"),
            jobs_cancelled: counter!("jobs_cancelled_total"),
            jobs_force_cancelled: counter!("jobs_force_cancelled_total"),
        }
    }
}

/// Scheduler metrics
pub struct SchedulerMetrics {
    pub jobs_scheduled: Counter,
    pub recurring_jobs: Counter,
    pub recurring_jobs_removed: Counter,
    pub jobs_triggered: Counter,
    pub jobs_failed: Counter,
}

impl SchedulerMetrics {
    pub fn new(_registry: &MetricsRegistry) -> Self {
        Self {
            jobs_scheduled: counter!("scheduler_jobs_scheduled_total"),
            recurring_jobs: counter!("scheduler_recurring_jobs_total"),
            recurring_jobs_removed: counter!("scheduler_recurring_jobs_removed_total"),
            jobs_triggered: counter!("scheduler_jobs_triggered_total"),
            jobs_failed: counter!("scheduler_jobs_failed_total"),
        }
    }
}
