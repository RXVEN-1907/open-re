//! API server binary for open-re

use openre_api::{AppState, http::start_server};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration (uses Figment: config.toml, env vars, etc.)
    let config = openre_config::Config::load()?;

    // Create application state
    let state = Arc::new(AppState::new(config).await?);

    // Get server address from environment or use default
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let addr = format!("{}:{}", host, port);

    // Run database migrations
    tracing::info!("Running database migrations...");
    state.global_store.run_migrations().await?;
    tracing::info!("Database migrations completed");

    // Start the server
    tracing::info!("Starting server on {}", addr);
    start_server(state, &addr).await?;

    Ok(())
}
