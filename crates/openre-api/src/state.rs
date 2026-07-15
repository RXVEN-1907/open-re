//! Application state for open-re API

use crate::{AuthService, ApiError, ApiResult};
use openre_ai::AiService;
use openre_config::Config;
use openre_plugins::PluginRegistry;
use openre_queue::{QueueManager, ProgressTracker, CancellationManager, Scheduler};
use openre_storage::{GlobalStore, ObjectStore};
use openre_telemetry::Telemetry;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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
    pub plugin_registry: Arc<PluginRegistry>,
    pub auth_service: Arc<AuthService>,
    pub telemetry: Arc<Telemetry>,
    pub rate_limiter: Arc<RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
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
        let queue_metrics = telemetry.metrics.queue_metrics();
        let queue_manager = Arc::new(QueueManager::new(config.queue.clone(), queue_metrics).await?);
        
        let progress_tracker = Arc::new(ProgressTracker::new(
            queue_manager.client().clone(),
            telemetry.metrics.progress_metrics(),
        ));
        
        let cancellation_manager = Arc::new(CancellationManager::new(
            queue_manager.clone(),
            queue_manager.client().clone(),
            telemetry.metrics.cancellation_metrics(),
        ));
        
        let scheduler = Arc::new(Scheduler::new(
            queue_manager.clone(),
            queue_manager.client().clone(),
            telemetry.metrics.scheduler_metrics(),
        ));
        
        // Load scheduled jobs from Redis
        scheduler.load_from_redis().await?;
        
        // Start background tasks
        queue_manager.start_maintenance().await;
        progress_tracker.start_cleanup().await;
        scheduler.start().await;
        
        // Initialize AI service
        let ai_service = Arc::new(AiService::new(
            config.ai.clone(),
            global_store.clone(),
            object_store.clone(),
        ).await?);
        
        // Initialize plugin registry
        let plugin_registry = Arc::new(PluginRegistry::new(&config.plugins).await?);
        
        // Initialize auth service
        let auth_service = Arc::new(AuthService::new(config.auth.clone()));
        
        // Initialize rate limiter
        let quota = Quota::per_minute(NonZeroU32::new(config.rate_limit.requests_per_minute).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        
        Ok(Self {
            config: Arc::new(config),
            global_store,
            object_store,
            queue_manager,
            progress_tracker,
            cancellation_manager,
            scheduler,
            ai_service,
            plugin_registry,
            auth_service,
            telemetry,
            rate_limiter,
        })
    }
    
    /// Get project store for a project
    pub async fn get_project_store(&self, project_id: openre_core::ids::ProjectId) -> ApiResult<Arc<openre_storage::ProjectStore>> {
        self.global_store.get_project_store(project_id).await
            .map_err(|e| ApiError::Internal(e.to_string()))
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