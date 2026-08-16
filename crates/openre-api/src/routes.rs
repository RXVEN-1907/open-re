//! API routes for open-re

pub mod ai;
pub mod analysis;
pub mod auth;
pub mod exports;
pub mod files;
pub mod functions;
pub mod plugins;
pub mod projects;
pub mod security;
pub mod security_ai;
pub mod users;

use crate::{ApiResult, AppState};
use axum::Router;

/// Create all API routes
pub fn create_routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .nest("/projects", projects::routes(state.clone()))
        .nest("/files", files::routes(state.clone()))
        .nest("/analysis", analysis::routes(state.clone()))
        .nest("/functions", functions::routes(state.clone()))
        .nest("/ai", ai::routes(state.clone()))
        .nest("/plugins", plugins::routes(state.clone()))
        .nest("/auth", auth::routes(state.clone()))
        .nest("/users", users::routes(state.clone()))
        .nest("/exports", exports::routes(state.clone()))
        .nest("/security", security::routes(state.clone()))
        .nest("/analyst", security_ai::routes(state.clone()))
}
