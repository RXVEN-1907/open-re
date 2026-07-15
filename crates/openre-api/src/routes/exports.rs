//! Export routes

use crate::{AppState, ApiResult};
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json,
    Router,
};
use openre_core::ids::{ExportId, ProjectId};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

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
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<ExportFilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<ExportListResponse>> {
    let exports = state.global_store.list_exports(
        filter.project_id.as_deref().and_then(|s| s.parse().ok()),
        pagination.offset(),
        pagination.limit(),
    ).await?;

    let total = state.global_store.count_exports(
        filter.project_id.as_deref().and_then(|s| s.parse().ok()),
    ).await?;

    Ok(Json(ExportListResponse {
        exports: exports.into_iter().map(ExportResponse::from).collect(),
        total,
        page: pagination.page(),
        per_page: pagination.per_page(),
    }))
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
    let project_id: ProjectId = payload.project_id.parse()?;
    
    let project = state.global_store.get_project(project_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check access
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        if !project.is_public {
            return Err(crate::error::ApiError::Forbidden("Access denied".into()));
        }
    }

    let export = state.global_store.create_export(
        project_id,
        payload.format,
        payload.include_files,
        payload.include_analysis,
    ).await?;

    Ok(Json(ExportResponse::from(export)))
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
    let export = state.global_store.get_export(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Export not found".into()))?;

    // Check access via project
    let project = state.global_store.get_project(export.project_id).await?;
    if let Some(project) = project {
        if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
            if !project.is_public {
                return Err(crate::error::ApiError::Forbidden("Access denied".into()));
            }
        }
    }

    Ok(Json(ExportResponse::from(export)))
}

/// Download export
async fn download_export(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ExportId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<axum::response::Response> {
    let export = state.global_store.get_export(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Export not found".into()))?;

    if export.status != "completed" {
        return Err(crate::error::ApiError::BadRequest("Export not ready".into()));
    }

    // Check access
    let project = state.global_store.get_project(export.project_id).await?;
    if let Some(project) = project {
        if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
            if !project.is_public {
                return Err(crate::error::ApiError::Forbidden("Access denied".into()));
            }
        }
    }

    if let Some(url) = export.download_url {
        Ok(axum::response::Redirect::to(&url).into_response())
    } else {
        Err(crate::error::ApiError::NotFound("Export file not found".into()))
    }
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

impl From<openre_storage::Export> for ExportResponse {
    fn from(e: openre_storage::Export) -> Self {
        Self {
            id: e.id,
            project_id: e.project_id,
            format: e.format,
            status: e.status,
            download_url: e.download_url,
            file_size: e.file_size,
            created_at: e.created_at,
            completed_at: e.completed_at,
        }
    }
}