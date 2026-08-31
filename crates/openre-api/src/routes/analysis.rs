//! Analysis routes

use crate::validation::IdParam;
use crate::{ApiResult, AppState, ValidatedJson};
use axum::Extension;
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
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
    let _ = user_id;

    // File record storage is not yet available in GlobalStore;
    // queue the analysis directly using the supplied file id.
    let job = openre_queue::Job::new(openre_core::traits::JobType::Analysis)
        .with_payload(serde_json::json!({
            "file_id": payload.file_id,
            "stages": payload.stages,
            "config": payload.config,
        }))
        .with_priority(payload.priority.unwrap_or_default());

    let job_id = state.queue_manager.enqueue(job).await?;

    Ok(Json(AnalysisResponse { job_id, status: "queued".to_string() }))
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
    let job = state
        .queue_manager
        .get_job_result(id)
        .await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Analysis not found".into()))?;

    // File-based access checks are unavailable until file storage exists;
    // all authenticated callers may view job status for now.

    let progress = state.progress_tracker.get_job_progress(id).await?;

    let (progress, current_stage, stages_completed, total_stages) = match progress {
        Some(p) => (Some(p.overall_progress), p.current_stage, p.stages_completed, p.total_stages),
        None => (None, None, 0, 0),
    };

    Ok(Json(AnalysisStatusResponse {
        job_id: job.id,
        job_type: job.job_type.to_string(),
        status: job.status,
        progress,
        current_stage,
        stages_completed,
        total_stages,
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
    let job = state
        .queue_manager
        .get_job_result(id)
        .await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Analysis not found".into()))?;

    if job.status != openre_queue::JobStatus::Completed {
        return Err(crate::error::ApiError::BadRequest("Analysis not completed".into()));
    }

    // File-based access checks are unavailable until file storage exists.

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

    Ok(Json(CancelResponse { job_id: id, cancelled }))
}

/// Retry analysis
async fn retry_analysis(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<JobId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<AnalysisResponse>> {
    let job = state
        .queue_manager
        .get_job_result(id)
        .await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Analysis not found".into()))?;

    // File-based access checks are unavailable until file storage exists.

    // Create new job with same payload
    let new_job = openre_queue::Job::new(job.job_type)
        .with_payload(job.payload)
        .with_priority(job.priority)
        .with_project(job.project_id.unwrap_or_else(|| ProjectId::new()));

    let job_id = state.queue_manager.enqueue(new_job).await?;

    Ok(Json(AnalysisResponse { job_id, status: "queued".to_string() }))
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
