//! Retry policy for job processing

use crate::Job;
use openre_core::error::Result;
use openre_config::RetryConfig;
use std::time::Duration;
use tracing::{debug, warn};

/// Retry policy engine
pub struct RetryPolicy {
    config: RetryConfig,
}

impl RetryPolicy {
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Calculate delay before next retry
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        let base = self.config.base_delay_ms;
        let max = self.config.max_delay_ms;
        let multiplier = self.config.multiplier;
        
        let delay_ms = (base as f64 * multiplier.powi(attempt as i32 - 1)).min(max as f64) as u64;
        
        // Add jitter
        let jitter = if self.config.jitter {
            let jitter_range = (delay_ms as f64 * self.config.jitter_factor) as u64;
            fastrand::u64(0..=jitter_range)
        } else {
            0
        };
        
        Duration::from_millis(delay_ms + jitter)
    }

    /// Check if job should be retried
    pub fn should_retry(&self, job: &Job, error: &openre_core::Error) -> bool {
        // Check max retries
        if job.retry_count >= self.config.max_retries {
            debug!("Job {} exceeded max retries ({})", job.id, self.config.max_retries);
            return false;
        }

        // Check if error is retryable
        if !self.is_retryable_error(error) {
            debug!("Job {} error is not retryable: {}", job.id, error);
            return false;
        }

        // Check job-specific retry policy
        if let Some(job_retry_policy) = &job.retry_policy {
            if !job_retry_policy.should_retry(error) {
                return false;
            }
        }

        true
    }

    /// Determine if an error is retryable
    fn is_retryable_error(&self, error: &openre_core::Error) -> bool {
        match error {
            openre_core::Error::Timeout(_) => true,
            openre_core::Error::ConnectionError(_) => true,
            openre_core::Error::Internal(msg) if self.is_transient_internal(msg) => true,
            openre_core::Error::ResourceExhausted(_) => true,
            openre_core::Error::RateLimited(_) => true,
            _ => false,
        }
    }

    fn is_transient_internal(&self, msg: &str) -> bool {
        let transient_patterns = [
            "connection reset",
            "connection refused",
            "timeout",
            "temporary failure",
            "service unavailable",
            "too many requests",
            "deadlock",
            "lock timeout",
        ];
        
        let lower = msg.to_lowercase();
        transient_patterns.iter().any(|p| lower.contains(p))
    }

    /// Get retry configuration for a job
    pub fn get_job_retry_config(&self, job: &Job) -> JobRetryConfig {
        job.retry_policy.clone().unwrap_or_else(|| JobRetryConfig {
            max_retries: self.config.max_retries,
            base_delay_ms: self.config.base_delay_ms,
            max_delay_ms: self.config.max_delay_ms,
            multiplier: self.config.multiplier,
            jitter: self.config.jitter,
            retryable_errors: self.config.retryable_errors.clone(),
        })
    }
}

/// Job-specific retry configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JobRetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: f64,
    pub jitter: bool,
    pub retryable_errors: Vec<String>,
}

impl JobRetryConfig {
    pub fn should_retry(&self, error: &openre_core::Error) -> bool {
        if self.retryable_errors.is_empty() {
            return true; // Default to retryable
        }
        
        let error_str = error.to_string().to_lowercase();
        self.retryable_errors.iter().any(|e| error_str.contains(&e.to_lowercase()))
    }
}

/// Exponential backoff calculator
pub struct ExponentialBackoff {
    base: Duration,
    max: Duration,
    multiplier: f64,
    jitter: bool,
    jitter_factor: f64,
}

impl ExponentialBackoff {
    pub fn new(base: Duration, max: Duration, multiplier: f64) -> Self {
        Self {
            base,
            max,
            multiplier,
            jitter: true,
            jitter_factor: 0.1,
        }
    }

    pub fn with_jitter(mut self, enabled: bool, factor: f64) -> Self {
        self.jitter = enabled;
        self.jitter_factor = factor;
        self
    }

    pub fn calculate(&self, attempt: u32) -> Duration {
        let base_ms = self.base.as_millis() as f64;
        let max_ms = self.max.as_millis() as f64;
        
        let delay_ms = (base_ms * self.multiplier.powi(attempt as i32 - 1)).min(max_ms) as u64;
        
        let jitter = if self.jitter {
            let jitter_range = (delay_ms as f64 * self.jitter_factor) as u64;
            fastrand::u64(0..=jitter_range)
        } else {
            0
        };
        
        Duration::from_millis(delay_ms + jitter)
    }
}