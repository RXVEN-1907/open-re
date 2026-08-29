//! API server binary for open-re

use openre_api::{http::start_server, state::AppState};
use openre_config::Config;
use std::sync::Arc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,openre_api=debug,tower_http=debug".into()),
        )
        .init();

    info!("Starting open-re API server");

    // Load configuration
    let config = Config::load()?;
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Configuration loaded, binding to {}", addr);

    // Initialize application state
    let state = Arc::new(AppState::new(config).await?);
    info!("Application state initialized");

    // Run database migrations if configured
    if state.config.database.run_migrations {
        info!("Running database migrations");
        state.global_store.run_migrations().await?;
        info!("Database migrations completed");
    }

    // Start HTTP server
    info!("Starting HTTP server on {}", addr);
    if let Err(e) = start_server(state, &addr).await {
        error!("HTTP server error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
