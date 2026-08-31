//! File routes

use crate::validation::{FilterParams, IdParam, PaginationParams};
use crate::{ApiResult, AppState, ValidatedJson};
use axum::Extension;
use axum::{
    extract::{Multipart, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use openre_core::ids::{FileId, ProjectId};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// File routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_files).post(upload_file))
        .route("/:id", get(get_file).delete(delete_file))
        .route("/:id/download", get(download_file))
        .route("/:id/analysis", post(start_analysis))
        .with_state(state)
}

/// List files
#[utoipa::path(
    get,
    path = "/api/files",
    params(PaginationParams, FilterParams),
    responses(
        (status = 200, description = "List of files", body = FileListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "files"
)]
async fn list_files(
    State(state): State<std::sync::Arc<AppState>>,
    Query(_pagination): Query<PaginationParams>,
    Query(_filter): Query<FilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FileListResponse>> {
    let _ = (state, claims);
    // File listing is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented("file listing not implemented yet".into()))
}

/// Upload file
#[utoipa::path(
    post,
    path = "/api/files",
    request_body = UploadFileRequest,
    responses(
        (status = 201, description = "File uploaded", body = FileResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 413, description = "File too large", body = crate::error::ApiErrorResponse),
    ),
    tag = "files"
)]
async fn upload_file(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    mut multipart: Multipart,
) -> ApiResult<Json<FileResponse>> {
    let _ = (&state, &claims, &mut multipart);
    // Object storage + file record persistence are not yet implemented.
    Err(crate::error::ApiError::NotImplemented("file upload storage not implemented yet".into()))
}

/// Get file
#[utoipa::path(
    get,
    path = "/api/files/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "File details", body = FileResponse),
        (status = 404, description = "File not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "files"
)]
async fn get_file(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FileId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FileResponse>> {
    let _ = (state, id, claims);
    // File record storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented("file retrieval not implemented yet".into()))
}

/// Delete file
#[utoipa::path(
    delete,
    path = "/api/files/{id}",
    params(IdParam),
    responses(
        (status = 204, description = "File deleted"),
        (status = 404, description = "File not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    tag = "files"
)]
async fn delete_file(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FileId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let _ = (state, id, claims);
    // File record storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented("file deletion not implemented yet".into()))
}

/// Download file
async fn download_file(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FileId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<axum::response::Response> {
    let _ = (state, id, claims);
    // File record storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented("file download not implemented yet".into()))
}

/// Start analysis
async fn start_analysis(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FileId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<StartAnalysisRequest>,
) -> ApiResult<Json<AnalysisResponse>> {
    let _ = claims;

    // File record storage is not yet available; queue the analysis
    // directly using the supplied file id.
    let job = openre_queue::Job::new(openre_core::traits::JobType::Analysis)
        .with_payload(serde_json::json!({
            "file_id": id.to_string(),
            "stages": payload.stages,
            "config": payload.config,
        }))
        .with_priority(payload.priority.unwrap_or_default());

    let job_id = state.queue_manager.enqueue(job).await?;

    Ok(Json(AnalysisResponse { job_id, status: "queued".to_string() }))
}

// Request/Response types

#[derive(Debug, Serialize, ToSchema)]
pub struct FileResponse {
    pub id: FileId,
    pub user_id: openre_core::ids::UserId,
    pub project_id: Option<ProjectId>,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub object_id: openre_core::ids::ObjectId,
    pub status: String,
    pub hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FileListResponse {
    pub files: Vec<FileResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UploadFileRequest {
    pub project_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct StartAnalysisRequest {
    pub stages: Option<Vec<String>>,
    pub config: Option<serde_json::Value>,
    pub priority: Option<openre_queue::Priority>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnalysisResponse {
    pub job_id: openre_core::ids::JobId,
    pub status: String,
}
