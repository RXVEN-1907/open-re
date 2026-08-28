//! Application state for open-re API

use crate::{ApiError, ApiResult, AuthService};
use governor::{Quota, RateLimiter};
use openre_ai::AiService;
use openre_config::Config;
use openre_core::plugin::PluginRegistry;
use openre_core::plugin::RegistryConfig;
use openre_queue::{CancellationManager, ProgressTracker, QueueManager, Scheduler};
use openre_scanner::storage::{MemoryScanStorage, ScanStorage, SqliteScanStorage};
use openre_security_ai::{
    FindingProvider, ScanStorageFindingProvider, SecurityAnalyst, SecurityAnalystImpl,
};
use openre_storage::{GlobalStore, ObjectStore};
use openre_telemetry::{metrics::MetricsRegistry, TelemetryHandle};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Telemetry bundle shared across handlers
pub struct Telemetry {
    pub metrics: MetricsRegistry,
    pub _handle: TelemetryHandle,
}

impl Telemetry {
    pub fn new(_config: &openre_config::TelemetryConfig) -> ApiResult<Self> {
        Ok(Self {
            metrics: MetricsRegistry::new(),
            _handle: TelemetryHandle,
        })
    }
}

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub global_store: Arc<GlobalStore>,
    pub object_store: Arc<ObjectStore>,
    pub queue_manager: Arc<QueueManager>,
    pub progress_tracker: Arc<ProgressTracker>,
    pub cancellation_manager: Arc<CancellationManager>,
    pub scheduler: Arc<Scheduler>,
    pub ai_service: Arc<AiService>,
    pub analyst: Option<Arc<dyn SecurityAnalyst>>, // AI Security Analyst service
    pub plugin_registry: Arc<PluginRegistry>,
    pub auth_service: Arc<AuthService>,
    pub telemetry: Arc<Telemetry>,
    pub rate_limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
    pub scan_storage: Arc<dyn ScanStorage>,
}

impl AppState {
    /// Create new application state
    pub async fn new(config: Config) -> ApiResult<Self> {
        // Initialize telemetry
        let telemetry = Arc::new(Telemetry::new(&config.telemetry)?);

        // Initialize stores
        let global_store = Arc::new(GlobalStore::new(&config.database).await?);
        let object_store = Arc::new(ObjectStore::new(&config.storage).await?);

        // Initialize queue system
        use openre_telemetry::metrics::{CancellationMetrics, ProgressMetrics, SchedulerMetrics};
        let client = redis::Client::open(config.redis.url.as_str())
            .map_err(|e| ApiError::Internal(format!("Redis init failed: {}", e)))?;
        let queue_metrics = Arc::new(openre_telemetry::metrics::QueueMetrics::new(
            &telemetry.metrics,
        ));
        let queue_manager =
            Arc::new(QueueManager::new(config.queue.clone(), &config.redis, queue_metrics).await?);

        let progress_tracker = Arc::new(ProgressTracker::new(
            client.clone(),
            Arc::new(ProgressMetrics::new(&telemetry.metrics)),
        ));

        let cancellation_manager = Arc::new(CancellationManager::new(
            queue_manager.clone(),
            client.clone(),
            Arc::new(CancellationMetrics::new(&telemetry.metrics)),
        ));

        let scheduler = Arc::new(Scheduler::new(
            queue_manager.clone(),
            client.clone(),
            Arc::new(SchedulerMetrics::new(&telemetry.metrics)),
        ));

        // Load scheduled jobs from Redis
        scheduler.load_from_redis().await?;

        // Start background tasks
        queue_manager.start_maintenance().await;
        progress_tracker.start_cleanup().await;
        scheduler.start().await;

        // Initialize AI service
        let ai_service = Arc::new(
            AiService::new(
                config.ai.clone(),
                global_store.clone(),
                object_store.clone(),
            )
            .await?,
        );

        // Initialize plugin registry
        let plugin_registry = Arc::new(PluginRegistry::new(RegistryConfig::default())?);

        // Initialize auth service
        let auth_service = Arc::new(AuthService::new(crate::auth::AuthConfig::default()));

        // Initialize rate limiter
        let rps = 100; // default global RPS; per-config tuning pending
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        // Initialize scan storage
        let scan_storage: Arc<dyn ScanStorage> = if config.database.url.starts_with("sqlite") {
            match SqliteScanStorage::new(&config.database.url).await {
                Ok(storage) => Arc::new(storage) as Arc<dyn ScanStorage>,
                Err(e) => return Err(ApiError::Internal(e.to_string())),
            }
        } else {
            Arc::new(MemoryScanStorage::new())
        };

        // Initialize AI Security Analyst if a model provider is available
        let analyst: Option<Arc<dyn SecurityAnalyst>> = ai_service
            .list_provider_ids()
            .first()
            .and_then(|provider_id| ai_service.get_provider_arc(provider_id))
            .map(|provider| {
                let finding_provider =
                    Arc::new(ScanStorageFindingProvider::new(scan_storage.clone()));
                let analyst_impl = SecurityAnalystImpl::new(finding_provider, provider, 4096);
                Arc::new(analyst_impl) as Arc<dyn SecurityAnalyst>
            });

        Ok(Self {
            config: Arc::new(config),
            global_store,
            object_store,
            queue_manager,
            progress_tracker,
            cancellation_manager,
            scheduler,
            ai_service,
            analyst,
            plugin_registry,
            auth_service,
            telemetry,
            rate_limiter,
            scan_storage,
        })
    }

    /// Get project store for a project
    pub async fn get_project_store(
        &self,
        project_id: openre_core::ids::ProjectId,
    ) -> ApiResult<Arc<openre_storage::ProjectStore>> {
        Ok(Arc::new(
            openre_storage::ProjectStore::new(project_id, self.config.storage.local_path.as_path())
                .map_err(|e| ApiError::Internal(e.to_string()))?,
        ))
    }

    /// Health check
    pub async fn health_check(&self) -> ApiResult<()> {
        self.global_store.health_check().await?;
        self.queue_manager.health_check().await?;
        Ok(())
    }

    /// Shutdown gracefully
    pub async fn shutdown(&self) -> ApiResult<()> {
        // Stop accepting new requests
        // Wait for in-flight requests
        // Close connections
        Ok(())
    }
}
