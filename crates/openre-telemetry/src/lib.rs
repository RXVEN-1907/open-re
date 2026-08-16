//! Telemetry (logging, metrics, tracing, audit) for open-re

pub mod audit;
pub mod logging;
pub mod metrics;
pub mod tracing;

pub use audit::*;
pub use logging::*;
pub use metrics::*;
pub use tracing::*;

// Re-export metrics types explicitly
pub use metrics::{MetricsCounter, MetricsGauge, MetricsHistogram, MetricsRegistry};

use openre_config::Config;
use openre_core::error::OpenreResult as Result;

/// Initialize all telemetry systems
pub async fn init_telemetry(config: &Config) -> Result<TelemetryGuards> {
    logging::init_logging(&config.telemetry.logging)?;
    let metrics_guard = metrics::init_metrics(&config.telemetry.metrics)?;
    let tracing_guard = tracing::init_tracing(&config.telemetry.tracing)?;
    let audit_guard = audit::init_audit(&config.telemetry.audit).await?;

    Ok(TelemetryGuards {
        _logging: (),
        _metrics: metrics_guard,
        _tracing: tracing_guard,
        _audit: audit_guard,
    })
}

/// Guards for telemetry systems (drop to shutdown)
pub struct TelemetryGuards {
    _logging: (),
    _metrics: MetricsGuard,
    _tracing: TracingGuard,
    _audit: AuditGuard,
}
