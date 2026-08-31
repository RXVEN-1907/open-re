//! Export routes

use crate::validation::{IdParam, PaginationParams};
use crate::{ApiResult, AppState};
use axum::Extension;
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use openre_core::ids::{ExportId, ProjectId};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Export routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_exports).post(create_export))
        .route("/:id", get(get_export))
        .route("/:id/download", get(download_export))
        .with_state(state)
}

/// List exports
#[utoipa::path(
    get,
    path = "/api/exports",
    params(PaginationParams, ExportFilterParams),
    responses(
        (status = 200, description = "List of exports", body = ExportListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "exports"
)]
async fn list_exports(
    State(state): State<std::sync::Arc<AppState>>,
    Query(_pagination): Query<PaginationParams>,
    Query(_filter): Query<ExportFilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<ExportListResponse>> {
    let _ = (state, claims);
    // Export persistence is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented("export listing not implemented yet".into()))
}

/// Create export
#[utoipa::path(
    post,
    path = "/api/exports",
    request_body = CreateExportRequest,
    responses(
        (status = 201, description = "Export created", body = ExportResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "exports"
)]
async fn create_export(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<CreateExportRequest>,
) -> ApiResult<Json<ExportResponse>> {
    let _ = claims;
    let project_id: ProjectId = payload.project_id.parse()?;

    // Queue an export job; persistent export records are not yet implemented.
    let job = openre_queue::Job::new(openre_core::traits::JobType::Export).with_payload(
        serde_json::json!({
            "project_id": project_id.to_string(),
            "format": payload.format,
            "include_files": payload.include_files,
            "include_analysis": payload.include_analysis,
        }),
    );

    state.queue_manager.enqueue(job).await?;

    Ok(Json(ExportResponse {
        id: ExportId::new(),
        project_id,
        format: payload.format,
        status: "queued".to_string(),
        download_url: None,
        file_size: None,
        created_at: chrono::Utc::now(),
        completed_at: None,
    }))
}

/// Get export
#[utoipa::path(
    get,
    path = "/api/exports/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "Export details", body = ExportResponse),
        (status = 404, description = "Export not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "exports"
)]
async fn get_export(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ExportId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<ExportResponse>> {
    let _ = (state, id, claims);
    // Export persistence is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented("export retrieval not implemented yet".into()))
}

/// Download export
async fn download_export(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ExportId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<axum::response::Response> {
    let _ = (state, id, claims);
    // Export persistence is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented("export download not implemented yet".into()))
}

// Request/Response types

#[derive(Debug, Deserialize, IntoParams)]
pub struct ExportFilterParams {
    pub project_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExportListResponse {
    pub exports: Vec<ExportResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateExportRequest {
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub project_id: String,

    #[validate(length(min = 1))]
    pub format: String,

    pub include_files: Option<bool>,

    pub include_analysis: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExportResponse {
    pub id: ExportId,
    pub project_id: ProjectId,
    pub format: String,
    pub status: String,
    pub download_url: Option<String>,
    pub file_size: Option<u64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}
