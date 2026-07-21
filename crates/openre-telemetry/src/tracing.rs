//! Distributed tracing for open-re

use openre_config::TracingConfig;
use openre_core::error::Result;
use opentelemetry::{global, KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{Sampler, TracerProvider};
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Registry;

/// Initialize tracing
pub fn init_tracing(config: &TracingConfig) -> Result<TracingGuard> {
    if !config.enabled {
        return Ok(TracingGuard);
    }

    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ]);

    let tracer_provider = if let Some(endpoint) = &config.otlp_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;

        TracerProvider::builder()
            .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
            .with_resource(resource)
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .build()
    } else {
        TracerProvider::builder()
            .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
            .with_resource(resource)
            .build()
    };

    let _tracer = tracer_provider.tracer("openre");
    
    // Use a simple tracing layer instead of OpenTelemetryLayer for now
    let registry = Registry::default();
    registry.try_init().ok();

    global::set_tracer_provider(tracer_provider);

    Ok(TracingGuard)
}

/// Tracing guard
pub struct TracingGuard;

impl Drop for TracingGuard {
    fn drop(&mut self) {
        global::shutdown_tracer_provider();
    }
}

/// Create a new span for analysis operations
pub fn analysis_span(job_id: &openre_core::ids::JobId, stage: &str) -> tracing::Span {
    tracing::info_span!("analysis", job_id = %job_id, stage = %stage)
}

/// Create a new span for API operations
pub fn api_span(method: &str, path: &str) -> tracing::Span {
    tracing::info_span!("api", method = %method, path = %path)
}

/// Create a new span for plugin operations
pub fn plugin_span(plugin_id: &openre_core::ids::PluginId, capability: &str) -> tracing::Span {
    tracing::info_span!("plugin", plugin_id = %plugin_id, capability = %capability)
}

/// Create a new span for AI operations
pub fn ai_span(task: &str, model: &str) -> tracing::Span {
    tracing::info_span!("ai", task = %task, model = %model)
}