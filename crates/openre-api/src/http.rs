//! HTTP server for open-re API

use crate::middleware as api_middleware;
use crate::routes;
use crate::websocket::ws_handler;
use crate::{ApiError, ApiResult, AppState};
use axum::{
    extract::{Extension, State},
    middleware,
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{error, info};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Create the HTTP router
pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(true);

    let api_routes = crate::routes::create_routes(state.clone());

    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .with_state(state.clone());

    let ws_routes = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state.clone());

    let router: Router = Router::new()
        .merge(api_routes)
        .merge(health_routes)
        .merge(ws_routes)
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_middleware::request_id,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_middleware::logging,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_middleware::rate_limit,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(50 * 1024 * 1024)) // 50MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(cors);
    router
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

    Ok(Json(serde_json::json!({
        "status": "ready",
        "timestamp": chrono::Utc::now(),
        "checks": {
            "database": "ok",
        }
    })))
}

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::projects::list_projects,
        crate::routes::projects::create_project,
        crate::routes::projects::get_project,
        crate::routes::projects::update_project,
        crate::routes::projects::delete_project,
        crate::routes::files::upload_file,
        crate::routes::files::list_files,
        crate::routes::files::get_file,
        crate::routes::files::delete_file,
        crate::routes::analysis::start_analysis,
        crate::routes::analysis::get_analysis_status,
        crate::routes::analysis::get_analysis_results,
        crate::routes::functions::list_functions,
        crate::routes::functions::get_function,
        crate::routes::ai::chat_completion,
        crate::routes::ai::analyze_function,
        crate::routes::plugins::list_plugins,
        crate::routes::plugins::install_plugin,
        crate::routes::auth::login,
        crate::routes::auth::register,
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
        version = "0.1.0",
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
