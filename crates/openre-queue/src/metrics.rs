//! Metrics for queue system

use metrics::{increment_counter, gauge, histogram};

/// Queue metrics - use macros directly instead of storing handles
pub struct QueueMetrics;

impl QueueMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn jobs_queued(&self) {
        increment_counter!("queue_jobs_queued_total");
    }

    pub fn jobs_dequeued(&self) {
        increment_counter!("queue_jobs_dequeued_total");
    }

    pub fn jobs_completed(&self) {
        increment_counter!("queue_jobs_completed_total");
    }

    pub fn jobs_failed(&self) {
        increment_counter!("queue_jobs_failed_total");
    }

    pub fn jobs_retried(&self) {
        increment_counter!("queue_jobs_retried_total");
    }

    pub fn jobs_cancelled(&self) {
        increment_counter!("queue_jobs_cancelled_total");
    }

    pub fn jobs_scheduled(&self) {
        increment_counter!("queue_jobs_scheduled_total");
    }

    pub fn jobs_triggered(&self) {
        increment_counter!("queue_jobs_triggered_total");
    }

    pub fn jobs_unscheduled(&self) {
        increment_counter!("queue_jobs_unscheduled_total");
    }

    pub fn jobs_stale_recovered(&self) {
        increment_counter!("queue_jobs_stale_recovered_total");
    }

    pub fn jobs_dlq(&self) {
        increment_counter!("queue_jobs_dlq_total");
    }

    pub fn jobs_by_priority(&self) {
        increment_counter!("queue_jobs_by_priority_total");
    }

    pub fn jobs_running(&self, delta: f64) {
        gauge!("queue_jobs_running", delta);
    }

    pub fn queue_depth(&self, depth: f64) {
        gauge!("queue_depth", depth);
    }

    pub fn queue_depth_by_priority(&self, depth: f64) {
        gauge!("queue_depth_by_priority", depth);
    }
}

/// Worker metrics
pub struct WorkerMetrics;

impl WorkerMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn jobs_processed(&self) {
        increment_counter!("worker_jobs_processed_total");
    }

    pub fn jobs_succeeded(&self) {
        increment_counter!("worker_jobs_succeeded_total");
    }

    pub fn jobs_failed(&self) {
        increment_counter!("worker_jobs_failed_total");
    }

    pub fn worker_errors(&self) {
        increment_counter!("worker_errors_total");
    }

    pub fn job_duration(&self, duration_ms: f64) {
        histogram!("worker_job_duration_ms", duration_ms);
    }

    pub fn active_workers(&self, delta: f64) {
        gauge!("worker_active", delta);
    }
}

/// Auto-scaler metrics
pub struct AutoScalerMetrics;

impl AutoScalerMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn scale_events(&self) {
        increment_counter!("autoscaler_scale_events_total");
    }

    pub fn current_workers(&self, count: f64) {
        gauge!("autoscaler_current_workers", count);
    }

    pub fn desired_workers(&self, count: f64) {
        gauge!("autoscaler_desired_workers", count);
    }

    pub fn queue_depth(&self, depth: f64) {
        gauge!("autoscaler_queue_depth", depth);
    }

    pub fn jobs_running(&self, count: f64) {
        gauge!("autoscaler_jobs_running", count);
    }
}

/// Progress metrics
pub struct ProgressMetrics;

impl ProgressMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn jobs_tracked(&self) {
        increment_counter!("progress_jobs_tracked_total");
    }

    pub fn progress_updates(&self) {
        increment_counter!("progress_updates_total");
    }
}

/// Cancellation metrics
pub struct CancellationMetrics;

impl CancellationMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn cancellation_requests(&self) {
        increment_counter!("cancellation_requests_total");
    }

    pub fn jobs_cancelled(&self) {
        increment_counter!("jobs_cancelled_total");
    }

    pub fn jobs_force_cancelled(&self) {
        increment_counter!("jobs_force_cancelled_total");
    }
}

/// Scheduler metrics
pub struct SchedulerMetrics;

impl SchedulerMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn jobs_scheduled(&self) {
        increment_counter!("scheduler_jobs_scheduled_total");
    }

    pub fn recurring_jobs(&self) {
        increment_counter!("scheduler_recurring_jobs_total");
    }

    pub fn recurring_jobs_removed(&self) {
        increment_counter!("scheduler_recurring_jobs_removed_total");
    }

    pub fn jobs_triggered(&self) {
        increment_counter!("scheduler_jobs_triggered_total");
    }

    pub fn jobs_failed(&self) {
        increment_counter!("scheduler_jobs_failed_total");
    }

    pub fn jobs_missed(&self) {
        increment_counter!("scheduler_jobs_missed_total");
    }
}