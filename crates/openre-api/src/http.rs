//! HTTP server for open-re API

use crate::{AppState, ApiError, ApiResult};
use axum::{
    Router,
    routing::{get, post, put, delete, patch},
    middleware,
    extract::{State, Extension},
    response::{Html, IntoResponse},
    Json,
};
use axum_extra::extract::CookieJar;
use tower_http::{
    cors::{CorsLayer, Any},
    trace::TraceLayer,
    compression::CompressionLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, error};

/// Create the HTTP router
pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(true);

    let api_routes = routes::create_routes(state.clone());

    Router::new()
        .merge(api_routes)
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .layer(middleware::from_fn_with_state(state.clone(), middleware::request_id))
        .layer(middleware::from_fn_with_state(state.clone(), middleware::logging))
        .layer(middleware::from_fn_with_state(state.clone(), middleware::rate_limit))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(50 * 1024 * 1024)) // 50MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(cors)
        .with_state(state)
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Readiness check endpoint
async fn readiness_check(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    // Check database connectivity
    state.global_store.health_check().await?;
    
    // Check Redis connectivity
    state.queue_manager.health_check().await?;
    
    Ok(Json(serde_json::json!({
        "status": "ready",
        "timestamp": chrono::Utc::now(),
        "checks": {
            "database": "ok",
            "queue": "ok",
        }
    })))
}

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        routes::projects::list_projects,
        routes::projects::create_project,
        routes::projects::get_project,
        routes::projects::update_project,
        routes::projects::delete_project,
        routes::files::upload_file,
        routes::files::list_files,
        routes::files::get_file,
        routes::files::delete_file,
        routes::analysis::start_analysis,
        routes::analysis::get_analysis_status,
        routes::analysis::get_analysis_results,
        routes::functions::list_functions,
        routes::functions::get_function,
        routes::functions::get_function_pseudocode,
        routes::functions::get_function_cfg,
        routes::ai::chat_completion,
        routes::ai::analyze_function,
        routes::plugins::list_plugins,
        routes::plugins::install_plugin,
        routes::auth::login,
        routes::auth::register,
        routes::auth::refresh_token,
    ),
    components(schemas(
        crate::routes::projects::ProjectResponse,
        crate::routes::projects::CreateProjectRequest,
        crate::routes::projects::UpdateProjectRequest,
        crate::routes::files::FileResponse,
        crate::routes::files::UploadFileRequest,
        crate::routes::analysis::AnalysisRequest,
        crate::routes::analysis::AnalysisResponse,
        crate::routes::analysis::AnalysisStatusResponse,
        crate::routes::functions::FunctionResponse,
        crate::routes::functions::PseudocodeResponse,
        crate::routes::functions::CfgResponse,
        crate::routes::ai::ChatCompletionRequest,
        crate::routes::ai::ChatCompletionResponse,
        crate::routes::ai::AnalyzeFunctionRequest,
        crate::routes::plugins::PluginResponse,
        crate::routes::auth::LoginRequest,
        crate::routes::auth::LoginResponse,
        crate::routes::auth::RegisterRequest,
        crate::error::ApiErrorResponse,
    )),
    tags(
        (name = "projects", description = "Project management"),
        (name = "files", description = "File management"),
        (name = "analysis", description = "Binary analysis"),
        (name = "functions", description = "Function analysis"),
        (name = "ai", description = "AI-powered analysis"),
        (name = "plugins", description = "Plugin management"),
        (name = "auth", description = "Authentication"),
    ),
    info(
        title = "open-re API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Reverse engineering platform API",
        contact(
            name = "open-re Team",
            url = "https://github.com/RXVEN-1907/open-re"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "http://localhost:8080", description = "Development server"),
        (url = "https://api.open-re.dev", description = "Production server"),
    )
)]
struct ApiDoc;

/// Start the HTTP server
pub async fn start_server(state: Arc<AppState>, addr: &str) -> Result<(), std::io::Error> {
    let router = create_router(state);
    let listener = TcpListener::bind(addr).await?;
    
    info!("HTTP server listening on {}", addr);
    
    axum::serve(listener, router).await
}