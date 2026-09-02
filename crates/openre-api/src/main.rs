//! openre-api - REST/gRPC API server for open-re

use openre_api::{http, state::AppState, ApiResult};
use openre_config::Config;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> ApiResult<()> {
    // Load configuration
    let config = Config::load().expect("Failed to load configuration");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting open-re API server v{}", env!("CARGO_PKG_VERSION"));

    // Create application state
    let state = Arc::new(AppState::new(config.clone()).await?);

    // Start HTTP server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting HTTP server on {}", addr);

    http::start_server(state, &addr).await?;

    Ok(())
}
