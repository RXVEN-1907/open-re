//! File routes

use crate::{AppState, ApiResult, ValidatedJson};
use axum::{
    extract::{Path, Query, State, Multipart},
    routing::{get, post, delete},
    Json,
    Router,
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
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<FilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FileListResponse>> {
    let files = state.global_store.list_files(
        filter.project_id.as_deref().and_then(|s| s.parse().ok()),
        filter.status.as_deref(),
        pagination.offset(),
        pagination.limit(),
    ).await?;

    let total = state.global_store.count_files(
        filter.project_id.as_deref().and_then(|s| s.parse().ok()),
        filter.status.as_deref(),
    ).await?;

    Ok(Json(FileListResponse {
        files,
        total,
        page: pagination.page(),
        per_page: pagination.per_page(),
    }))
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
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    
    let mut file_data = Vec::new();
    let mut filename = String::new();
    let mut content_type = String::new();
    let mut project_id = None;
    
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_string();
        
        match name.as_str() {
            "file" => {
                filename = field.file_name().unwrap_or("unknown").to_string();
                content_type = field.content_type().unwrap_or("application/octet-stream").to_string();
                file_data = field.bytes().await?.to_vec();
            }
            "project_id" => {
                project_id = Some(field.text().await?);
            }
            _ => {}
        }
    }
    
    if file_data.is_empty() {
        return Err(crate::error::ApiError::BadRequest("No file provided".into()));
    }
    
    // Validate file size
    if file_data.len() > 1024 * 1024 * 1024 { // 1GB
        return Err(crate::error::ApiError::PayloadTooLarge("File too large".into()));
    }
    
    // Store file
    let file_id = state.object_store.store_file(&file_data).await?;
    
    // Create file record
    let file = state.global_store.create_file(
        user_id,
        project_id.and_then(|s| s.parse().ok()),
        filename,
        content_type,
        file_data.len() as u64,
        file_id,
    ).await?;
    
    // Queue initial analysis
    let job = openre_queue::Job::new(openre_core::traits::JobType::FileAnalysis)
        .with_payload(serde_json::json!({
            "file_id": file.id.to_string(),
        }))
        .with_project(file.project_id.unwrap_or_else(|| ProjectId::new()));
    
    state.queue_manager.enqueue(job).await?;
    
    Ok(Json(FileResponse::from(file)))
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
    let file = state.global_store.get_file(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("File not found".into()))?;

    // Check access
    if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        if let Some(project_id) = file.project_id {
            let project = state.global_store.get_project(project_id).await?;
            if !project.map(|p| p.is_public).unwrap_or(false) {
                return Err(crate::error::ApiError::Forbidden("Access denied".into()));
            }
        } else {
            return Err(crate::error::ApiError::Forbidden("Access denied".into()));
        }
    }

    Ok(Json(FileResponse::from(file)))
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
    let file = state.global_store.get_file(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("File not found".into()))?;

    // Check ownership
    if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can delete file".into()));
    }

    // Delete from object store
    state.object_store.delete_file(file.object_id).await?;
    
    // Delete record
    state.global_store.delete_file(id).await?;

    Ok(())
}

/// Download file
async fn download_file(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FileId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<axum::response::Response> {
    let file = state.global_store.get_file(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("File not found".into()))?;

    // Check access
    if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        if let Some(project_id) = file.project_id {
            let project = state.global_store.get_project(project_id).await?;
            if !project.map(|p| p.is_public).unwrap_or(false) {
                return Err(crate::error::ApiError::Forbidden("Access denied".into()));
            }
        } else {
            return Err(crate::error::ApiError::Forbidden("Access denied".into()));
        }
    }

    // Generate presigned URL
    let url = state.object_store.presigned_url(file.object_id, 3600).await?;
    
    // Redirect to presigned URL
    Ok(axum::response::Redirect::to(&url).into_response())
}

/// Start analysis
async fn start_analysis(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FileId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<StartAnalysisRequest>,
) -> ApiResult<Json<AnalysisResponse>> {
    let file = state.global_store.get_file(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("File not found".into()))?;

    // Check access
    if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Access denied".into()));
    }

    // Create analysis job
    let job = openre_queue::Job::new(openre_core::traits::JobType::FullAnalysis)
        .with_payload(serde_json::json!({
            "file_id": file.id.to_string(),
            "stages": payload.stages,
            "config": payload.config,
        }))
        .with_priority(payload.priority.unwrap_or_default())
        .with_project(file.project_id.unwrap_or_else(|| ProjectId::new()));
    
    let job_id = state.queue_manager.enqueue(job).await?;

    Ok(Json(AnalysisResponse {
        job_id,
        status: "queued".to_string(),
    }))
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

impl From<openre_storage::File> for FileResponse {
    fn from(f: openre_storage::File) -> Self {
        Self {
            id: f.id,
            user_id: f.user_id,
            project_id: f.project_id,
            filename: f.filename,
            content_type: f.content_type,
            size: f.size,
            object_id: f.object_id,
            status: f.status,
            hash: f.hash,
            created_at: f.created_at,
            updated_at: f.updated_at,
        }
    }
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