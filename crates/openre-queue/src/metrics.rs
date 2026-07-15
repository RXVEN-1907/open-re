//! Metrics for queue system

use openre_telemetry::metrics::{Counter, Gauge, Histogram, MetricsRegistry};

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
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            jobs_queued: registry.counter("queue_jobs_queued_total", "Total jobs queued"),
            jobs_dequeued: registry.counter("queue_jobs_dequeued_total", "Total jobs dequeued"),
            jobs_completed: registry.counter("queue_jobs_completed_total", "Total jobs completed"),
            jobs_failed: registry.counter("queue_jobs_failed_total", "Total jobs failed"),
            jobs_retried: registry.counter("queue_jobs_retried_total", "Total jobs retried"),
            jobs_cancelled: registry.counter("queue_jobs_cancelled_total", "Total jobs cancelled"),
            jobs_scheduled: registry.counter("queue_jobs_scheduled_total", "Total jobs scheduled"),
            jobs_triggered: registry.counter("queue_jobs_triggered_total", "Total scheduled jobs triggered"),
            jobs_unscheduled: registry.counter("queue_jobs_unscheduled_total", "Total jobs unscheduled"),
            jobs_stale_recovered: registry.counter("queue_jobs_stale_recovered_total", "Total stale jobs recovered"),
            jobs_dlq: registry.counter("queue_jobs_dlq_total", "Total jobs sent to DLQ"),
            jobs_by_priority: registry.counter("queue_jobs_by_priority_total", "Jobs queued by priority"),
            jobs_running: registry.gauge("queue_jobs_running", "Currently running jobs"),
            queue_depth: registry.gauge("queue_depth", "Total jobs in queue"),
            queue_depth_by_priority: registry.gauge("queue_depth_by_priority", "Jobs in queue by priority"),
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
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            jobs_processed: registry.counter("worker_jobs_processed_total", "Total jobs processed by workers"),
            jobs_succeeded: registry.counter("worker_jobs_succeeded_total", "Total jobs succeeded"),
            jobs_failed: registry.counter("worker_jobs_failed_total", "Total jobs failed in workers"),
            worker_errors: registry.counter("worker_errors_total", "Total worker errors"),
            job_duration: registry.histogram("worker_job_duration_ms", "Job processing duration in ms"),
            active_workers: registry.gauge("worker_active", "Number of active workers"),
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
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            scale_events: registry.counter("autoscaler_scale_events_total", "Total scaling events"),
            current_workers: registry.gauge("autoscaler_current_workers", "Current number of workers"),
            desired_workers: registry.gauge("autoscaler_desired_workers", "Desired number of workers"),
            queue_depth: registry.gauge("autoscaler_queue_depth", "Current queue depth"),
            jobs_running: registry.gauge("autoscaler_jobs_running", "Currently running jobs"),
        }
    }
}

/// Progress metrics
pub struct ProgressMetrics {
    pub jobs_tracked: Counter,
    pub progress_updates: Counter,
}

impl ProgressMetrics {
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            jobs_tracked: registry.counter("progress_jobs_tracked_total", "Total jobs with progress tracking"),
            progress_updates: registry.counter("progress_updates_total", "Total progress updates"),
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
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            cancellation_requests: registry.counter("cancellation_requests_total", "Total cancellation requests"),
            jobs_cancelled: registry.counter("jobs_cancelled_total", "Total jobs cancelled"),
            jobs_force_cancelled: registry.counter("jobs_force_cancelled_total", "Total jobs force cancelled"),
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
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            jobs_scheduled: registry.counter("scheduler_jobs_scheduled_total", "Total jobs scheduled"),
            recurring_jobs: registry.counter("scheduler_recurring_jobs_total", "Total recurring jobs"),
            recurring_jobs_removed: registry.counter("scheduler_recurring_jobs_removed_total", "Total recurring jobs removed"),
            jobs_triggered: registry.counter("scheduler_jobs_triggered_total", "Total scheduled jobs triggered"),
            jobs_failed: registry.counter("scheduler_jobs_failed_total", "Total scheduled jobs failed to trigger"),
        }
    }
}