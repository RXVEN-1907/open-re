//! Analysis routes

use crate::{AppState, ApiResult, ValidatedJson};
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json,
    Router,
};
use openre_core::ids::{JobId, ProjectId};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Analysis routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", post(start_analysis))
        .route("/:id", get(get_analysis_status))
        .route("/:id/results", get(get_analysis_results))
        .route("/:id/cancel", post(cancel_analysis))
        .route("/:id/retry", post(retry_analysis))
        .with_state(state)
}

/// Start analysis
#[utoipa::path(
    post,
    path = "/api/analysis",
    request_body = AnalysisRequest,
    responses(
        (status = 201, description = "Analysis started", body = AnalysisResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analysis"
)]
async fn start_analysis(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<AnalysisRequest>,
) -> ApiResult<Json<AnalysisResponse>> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    
    // Verify file access
    let file = state.global_store.get_file(payload.file_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("File not found".into()))?;

    if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Access denied".into()));
    }

    // Create analysis job
    let job = openre_queue::Job::new(openre_core::traits::JobType::FullAnalysis)
        .with_payload(serde_json::json!({
            "file_id": payload.file_id.to_string(),
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

/// Get analysis status
#[utoipa::path(
    get,
    path = "/api/analysis/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "Analysis status", body = AnalysisStatusResponse),
        (status = 404, description = "Analysis not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analysis"
)]
async fn get_analysis_status(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<JobId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<AnalysisStatusResponse>> {
    let job = state.queue_manager.get_job_result(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Analysis not found".into()))?;

    // Check access via file/project
    if let Some(file_id) = job.payload.get("file_id").and_then(|v| v.as_str()) {
        if let Ok(file_id) = file_id.parse::<openre_core::ids::FileId>() {
            let file = state.global_store.get_file(file_id).await?;
            if let Some(file) = file {
                if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
                    return Err(crate::error::ApiError::Forbidden("Access denied".into()));
                }
            }
        }
    }

    let progress = state.progress_tracker.get_job_progress(id).await?;

    Ok(Json(AnalysisStatusResponse {
        job_id: job.id,
        job_type: job.job_type.to_string(),
        status: job.status,
        progress: progress.map(|p| p.overall_progress),
        current_stage: progress.and_then(|p| p.current_stage),
        stages_completed: progress.map(|p| p.stages_completed).unwrap_or(0),
        total_stages: progress.map(|p| p.total_stages).unwrap_or(0),
        error: job.error,
        created_at: job.queued_at.unwrap_or_else(chrono::Utc::now),
        started_at: job.started_at,
        completed_at: job.completed_at,
    }))
}

/// Get analysis results
#[utoipa::path(
    get,
    path = "/api/analysis/{id}/results",
    params(IdParam),
    responses(
        (status = 200, description = "Analysis results", body = AnalysisResultsResponse),
        (status = 404, description = "Analysis not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analysis"
)]
async fn get_analysis_results(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<JobId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<AnalysisResultsResponse>> {
    let job = state.queue_manager.get_job_result(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Analysis not found".into()))?;

    if job.status != openre_queue::JobStatus::Completed {
        return Err(crate::error::ApiError::BadRequest("Analysis not completed".into()));
    }

    // Check access
    if let Some(file_id) = job.payload.get("file_id").and_then(|v| v.as_str()) {
        if let Ok(file_id) = file_id.parse::<openre_core::ids::FileId>() {
            let file = state.global_store.get_file(file_id).await?;
            if let Some(file) = file {
                if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
                    return Err(crate::error::ApiError::Forbidden("Access denied".into()));
                }
            }
        }
    }

    Ok(Json(AnalysisResultsResponse {
        job_id: job.id,
        result: job.result.unwrap_or(serde_json::Value::Null),
        completed_at: job.completed_at.unwrap_or_else(chrono::Utc::now),
    }))
}

/// Cancel analysis
async fn cancel_analysis(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<JobId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<CancelResponse>> {
    let cancelled = state.queue_manager.cancel(id).await?;
    
    Ok(Json(CancelResponse {
        job_id: id,
        cancelled,
    }))
}

/// Retry analysis
async fn retry_analysis(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<JobId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<AnalysisResponse>> {
    let job = state.queue_manager.get_job_result(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Analysis not found".into()))?;

    // Check access
    if let Some(file_id) = job.payload.get("file_id").and_then(|v| v.as_str()) {
        if let Ok(file_id) = file_id.parse::<openre_core::ids::FileId>() {
            let file = state.global_store.get_file(file_id).await?;
            if let Some(file) = file {
                if file.user_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
                    return Err(crate::error::ApiError::Forbidden("Access denied".into()));
                }
            }
        }
    }

    // Create new job with same payload
    let new_job = openre_queue::Job::new(job.job_type)
        .with_payload(job.payload)
        .with_priority(job.priority)
        .with_project(job.project_id.unwrap_or_else(|| ProjectId::new()));
    
    let job_id = state.queue_manager.enqueue(new_job).await?;

    Ok(Json(AnalysisResponse {
        job_id,
        status: "queued".to_string(),
    }))
}

// Request/Response types

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AnalysisRequest {
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub file_id: String,
    
    pub stages: Option<Vec<String>>,
    
    pub config: Option<serde_json::Value>,
    
    pub priority: Option<openre_queue::Priority>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnalysisResponse {
    pub job_id: openre_core::ids::JobId,
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnalysisStatusResponse {
    pub job_id: openre_core::ids::JobId,
    pub job_type: String,
    pub status: openre_queue::JobStatus,
    pub progress: Option<f32>,
    pub current_stage: Option<String>,
    pub stages_completed: u32,
    pub total_stages: u32,
    pub error: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnalysisResultsResponse {
    pub job_id: openre_core::ids::JobId,
    pub result: serde_json::Value,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CancelResponse {
    pub job_id: openre_core::ids::JobId,
    pub cancelled: bool,
}