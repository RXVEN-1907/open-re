//! Stub metrics module for binary analysis

use std::time::Duration;

/// Record an HTTP request metric (stub)
pub fn record_http_request(_method: &str, _status: u16, _duration: Duration) {
    // No-op stub
}

/// Record a stage completion metric (stub)
pub fn record_stage_completed(_stage: &str, _duration: Duration) {
    // No-op stub
}
