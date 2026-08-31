//! API endpoints for scan management

use crate::context::ScanContext;
use crate::error::{ScannerError, ScannerResult};
use crate::plugin::{PluginConfig, PluginId, PluginInfo, PluginManager};
use crate::result::{Finding, FindingFilter, FindingId, FindingSort, FindingStats};
use crate::scan::{ScanId, ScanManager, ScanProgress, ScanSession, ScanStatus};
use crate::storage::{MemoryScanStorage, ScanStorage, SqliteScanStorage};
use crate::target::{ScanConfig, Target, TargetId, TargetMetadata, TargetType};
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use openre_core::ids::ProjectId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use utoipa::{OpenApi, ToSchema};
use validator::Validate;

/// API state
#[derive(Clone)]
pub struct ApiState {
    pub scan_manager: Arc<ScanManager>,
    pub plugin_manager: Arc<PluginManager>,
    pub storage: Arc<dyn ScanStorage>,
    pub target_manager: Arc<crate::target::TargetManager>,
}

/// Create scan request
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateScanRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub target_id: TargetId,
    pub plugins: Option<Vec<String>>,
    pub exclude_plugins: Option<Vec<String>>,
    pub max_duration: Option<u64>,
    pub max_concurrent_plugins: Option<usize>,
    pub plugin_timeout: Option<u64>,
    pub debug: Option<bool>,
    pub plugin_config: Option<HashMap<String, serde_json::Value>>,
    pub tags: Option<Vec<String>>,
}

/// Update scan request
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateScanRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<ScanStatus>,
}

/// Create target request
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateTargetRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub target_type: TargetType,
    pub base_url: String,
    pub headers: Option<HashMap<String, String>>,
    pub cookies: Option<HashMap<String, String>>,
    pub auth: Option<crate::target::AuthConfig>,
    pub rate_limit: Option<crate::target::RateLimitConfig>,
    pub tls_config: Option<crate::target::TlsConfig>,
    pub proxy: Option<crate::target::ProxyConfig>,
    pub custom: Option<HashMap<String, serde_json::Value>>,
    pub tags: Option<Vec<String>>,
}

/// Update target request
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTargetRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub base_url: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub cookies: Option<HashMap<String, String>>,
    pub auth: Option<crate::target::AuthConfig>,
    pub rate_limit: Option<crate::target::RateLimitConfig>,
    pub tls_config: Option<crate::target::TlsConfig>,
    pub proxy: Option<crate::target::ProxyConfig>,
    pub custom: Option<HashMap<String, serde_json::Value>>,
    pub tags: Option<Vec<String>>,
}

/// Pagination parameters
#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct PaginationParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

/// Parse a `FindingSort` from its snake_case name (defaults to severity desc)
fn parse_finding_sort(sort: Option<&str>) -> FindingSort {
    match sort {
        Some("severity_asc") => FindingSort::SeverityAsc,
        Some("confidence_desc") => FindingSort::ConfidenceDesc,
        Some("timestamp_desc") => FindingSort::TimestampDesc,
        Some("timestamp_asc") => FindingSort::TimestampAsc,
        Some("risk_score_desc") => FindingSort::RiskScoreDesc,
        Some("target_asc") => FindingSort::TargetAsc,
        _ => FindingSort::SeverityDesc,
    }
}

/// Finding query parameters
#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct FindingQueryParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    pub severity: Option<Vec<String>>,
    pub confidence: Option<Vec<String>>,
    pub category: Option<Vec<String>>,
    pub target: Option<String>,
    pub plugin_source: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    /// Sort order (snake_case name of a `FindingSort` variant)
    pub sort: Option<String>,
}

/// Scan response
#[derive(Debug, Serialize, ToSchema)]
pub struct ScanResponse {
    pub id: ScanId,
    pub name: String,
    pub description: Option<String>,
    pub target_id: TargetId,
    pub status: ScanStatus,
    pub progress: ScanProgress,
    pub findings_count: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub tags: Vec<String>,
}

impl From<ScanSession> for ScanResponse {
    fn from(session: ScanSession) -> Self {
        let findings_count = session.findings.len();
        Self {
            id: session.id,
            name: session.config.name,
            description: session.config.description,
            target_id: session.target.id,
            status: session.status,
            progress: session.progress,
            findings_count,
            created_at: session.created_at,
            started_at: session.started_at,
            completed_at: session.completed_at,
            tags: session.config.tags,
        }
    }
}

/// Target response
#[derive(Debug, Serialize, ToSchema)]
pub struct TargetResponse {
    pub id: TargetId,
    pub target_type: TargetType,
    pub name: String,
    pub description: Option<String>,
    pub base_url: String,
    pub tags: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Target> for TargetResponse {
    fn from(target: Target) -> Self {
        Self {
            id: target.id,
            target_type: target.target_type,
            name: target.metadata.name,
            description: target.metadata.description,
            base_url: target.metadata.base_url.to_string(),
            tags: target.metadata.tags,
            created_at: target.created_at,
            updated_at: target.updated_at,
        }
    }
}

/// Finding response
#[derive(Debug, Serialize, ToSchema)]
pub struct FindingResponse {
    pub id: FindingId,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub target: String,
    pub target_type: String,
    pub plugin_source: String,
    pub plugin_version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub verified: bool,
    pub false_positive: bool,
    pub risk_score: Option<u8>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f32>,
    pub tags: Vec<String>,
}

impl From<Finding> for FindingResponse {
    fn from(finding: Finding) -> Self {
        Self {
            id: finding.id,
            title: finding.title,
            description: finding.description,
            severity: finding.severity.to_string(),
            confidence: finding.confidence.to_string(),
            category: finding.category.to_string(),
            target: finding.target,
            target_type: finding.target_type,
            plugin_source: finding.plugin_source,
            plugin_version: finding.plugin_version,
            timestamp: finding.timestamp,
            verified: finding.verified,
            false_positive: finding.false_positive,
            risk_score: finding.risk_score,
            cvss_vector: finding.cvss_vector,
            cvss_score: finding.cvss_score,
            tags: finding.tags,
        }
    }
}

/// Plugin response
#[derive(Debug, Serialize, ToSchema)]
pub struct PluginResponse {
    pub id: PluginId,
    pub name: String,
    pub version: String,
    pub description: String,
    pub status: String,
    pub capabilities: Vec<crate::plugin::PluginCapability>,
    pub tags: Vec<String>,
    pub loaded_at: Option<chrono::DateTime<chrono::Utc>>,
    pub health_status: String,
}

impl From<PluginInfo> for PluginResponse {
    fn from(plugin: PluginInfo) -> Self {
        Self {
            id: plugin.id,
            name: plugin.name,
            version: plugin.version,
            description: plugin.description,
            status: format!("{:?}", plugin.status),
            capabilities: plugin.capabilities,
            tags: plugin.tags,
            loaded_at: plugin.loaded_at,
            health_status: format!("{:?}", plugin.health_status),
        }
    }
}

/// Error response
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// API documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        create_scan,
        get_scan,
        list_scans,
        update_scan,
        cancel_scan,
        pause_scan,
        resume_scan,
        get_scan_progress,
        get_scan_findings,
        get_scan_logs,
        create_target,
        get_target,
        list_targets,
        update_target,
        delete_target,
        list_plugins,
        get_plugin,
        enable_plugin,
        disable_plugin,
        get_plugin_config,
        set_plugin_config,
        get_finding_stats,
    ),
    components(schemas(
        CreateScanRequest,
        UpdateScanRequest,
        CreateTargetRequest,
        UpdateTargetRequest,
        ScanResponse,
        TargetResponse,
        FindingResponse,
        PluginResponse,
        ErrorResponse,
        ScanProgress,
        ScanStatus,
        PaginationParams,
        FindingQueryParams,
    )),
    tags(
        (name = "scans", description = "Scan management endpoints"),
        (name = "targets", description = "Target management endpoints"),
        (name = "plugins", description = "Plugin management endpoints"),
        (name = "findings", description = "Finding query endpoints"),
    )
)]
pub struct ApiDoc;

/// Create the API router
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        // Scan endpoints
        .route("/scans", post(create_scan).get(list_scans))
        .route("/scans/:id", get(get_scan).put(update_scan).delete(cancel_scan))
        .route("/scans/:id/cancel", post(cancel_scan))
        .route("/scans/:id/pause", post(pause_scan))
        .route("/scans/:id/resume", post(resume_scan))
        .route("/scans/:id/progress", get(get_scan_progress))
        .route("/scans/:id/findings", get(get_scan_findings))
        .route("/scans/:id/logs", get(get_scan_logs))
        // Target endpoints
        .route("/targets", post(create_target).get(list_targets))
        .route("/targets/:id", get(get_target).put(update_target).delete(delete_target))
        // Plugin endpoints
        .route("/plugins", get(list_plugins))
        .route("/plugins/:id", get(get_plugin))
        .route("/plugins/:id/enable", post(enable_plugin))
        .route("/plugins/:id/disable", post(disable_plugin))
        .route("/plugins/:id/config", get(get_plugin_config).put(set_plugin_config))
        // Finding endpoints
        .route("/findings/stats", get(get_finding_stats))
        // OpenAPI documentation
        .route("/api-docs/openapi.json", get(serve_openapi))
        .with_state(state)
}

/// Serve OpenAPI spec
async fn serve_openapi() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

/// Create a new scan
#[utoipa::path(
    post,
    path = "/scans",
    request_body = CreateScanRequest,
    responses(
        (status = 201, description = "Scan created", body = ScanResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 404, description = "Target not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn create_scan(
    State(state): State<ApiState>,
    Json(request): Json<CreateScanRequest>,
) -> Result<impl IntoResponse, Response> {
    // Validate request
    if let Err(e) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "validation_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response());
    }

    // Get target
    let target = state.target_manager.get(&request.target_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Target {} not found", request.target_id),
                details: None,
            }),
        )
            .into_response()
    })?;

    // Build scan config
    let mut config = ScanConfig {
        target_id: request.target_id,
        name: request.name,
        description: request.description,
        plugins: request.plugins.unwrap_or_default(),
        exclude_plugins: request.exclude_plugins.unwrap_or_default(),
        max_duration: std::time::Duration::from_secs(request.max_duration.unwrap_or(3600)),
        max_concurrent_plugins: request.max_concurrent_plugins.unwrap_or(5),
        plugin_timeout: std::time::Duration::from_secs(request.plugin_timeout.unwrap_or(300)),
        retry_config: Default::default(),
        debug: request.debug.unwrap_or(false),
        plugin_config: request.plugin_config.unwrap_or_default(),
        tags: request.tags.unwrap_or_default(),
    };

    // Start scan
    let scan_id = state.scan_manager.start_scan(config, target).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    // Get created scan
    let scan = state.scan_manager.get_scan(&scan_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: "Failed to retrieve created scan".to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok((StatusCode::CREATED, Json(ScanResponse::from(scan))).into_response())
}

/// Get a scan by ID
#[utoipa::path(
    get,
    path = "/scans/{id}",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "Scan found", body = ScanResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn get_scan(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
) -> Result<impl IntoResponse, Response> {
    let scan = state.scan_manager.get_scan(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Scan {} not found", id),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(ScanResponse::from(scan)).into_response())
}

/// List scans
#[utoipa::path(
    get,
    path = "/scans",
    params(
        PaginationParams,
    ),
    responses(
        (status = 200, description = "List of scans", body = Vec<ScanResponse>),
    ),
    tag = "scans"
)]
async fn list_scans(
    State(state): State<ApiState>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let scans = state.scan_manager.list_scans();
    let scans: Vec<ScanResponse> =
        scans.into_iter().skip(params.offset).take(params.limit).map(ScanResponse::from).collect();
    Json(scans)
}

/// Update a scan
#[utoipa::path(
    put,
    path = "/scans/{id}",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
    ),
    request_body = UpdateScanRequest,
    responses(
        (status = 200, description = "Scan updated", body = ScanResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn update_scan(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
    Json(request): Json<UpdateScanRequest>,
) -> Result<impl IntoResponse, Response> {
    let scan = state.scan_manager.get_scan(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Scan {} not found", id),
                details: None,
            }),
        )
            .into_response()
    })?;

    // Handle status changes
    if let Some(status) = request.status {
        match status {
            ScanStatus::Cancelled => {
                state.scan_manager.cancel_scan(&id).await.map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "scan_error".to_string(),
                            message: e.to_string(),
                            details: None,
                        }),
                    )
                        .into_response()
                })?;
            }
            ScanStatus::Paused => {
                state.scan_manager.pause_scan(&id).await.map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "scan_error".to_string(),
                            message: e.to_string(),
                            details: None,
                        }),
                    )
                        .into_response()
                })?;
            }
            ScanStatus::Running => {
                state.scan_manager.resume_scan(&id).await.map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "scan_error".to_string(),
                            message: e.to_string(),
                            details: None,
                        }),
                    )
                        .into_response()
                })?;
            }
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_status".to_string(),
                        message: "Cannot set this status via update".to_string(),
                        details: None,
                    }),
                )
                    .into_response());
            }
        }
    }

    // Get updated scan
    let scan = state.scan_manager.get_scan(&id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: "Failed to retrieve updated scan".to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(ScanResponse::from(scan)).into_response())
}

/// Cancel a scan
#[utoipa::path(
    post,
    path = "/scans/{id}/cancel",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "Scan cancelled", body = ScanResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn cancel_scan(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
) -> Result<impl IntoResponse, Response> {
    state.scan_manager.cancel_scan(&id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    let scan = state.scan_manager.get_scan(&id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: "Failed to retrieve cancelled scan".to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(ScanResponse::from(scan)).into_response())
}

/// Pause a scan
#[utoipa::path(
    post,
    path = "/scans/{id}/pause",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "Scan paused", body = ScanResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
        (status = 400, description = "Scan not running", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn pause_scan(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
) -> Result<impl IntoResponse, Response> {
    state.scan_manager.pause_scan(&id).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    let scan = state.scan_manager.get_scan(&id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: "Failed to retrieve paused scan".to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(ScanResponse::from(scan)).into_response())
}

/// Resume a scan
#[utoipa::path(
    post,
    path = "/scans/{id}/resume",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "Scan resumed", body = ScanResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
        (status = 400, description = "Scan not paused", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn resume_scan(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
) -> Result<impl IntoResponse, Response> {
    state.scan_manager.resume_scan(&id).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    let scan = state.scan_manager.get_scan(&id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "scan_error".to_string(),
                message: "Failed to retrieve resumed scan".to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(ScanResponse::from(scan)).into_response())
}

/// Get scan progress
#[utoipa::path(
    get,
    path = "/scans/{id}/progress",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "Scan progress", body = ScanProgress),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn get_scan_progress(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
) -> Result<impl IntoResponse, Response> {
    let progress = state.scan_manager.get_progress(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Scan {} not found", id),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(progress).into_response())
}

/// Get scan findings
#[utoipa::path(
    get,
    path = "/scans/{id}/findings",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
        FindingQueryParams,
    ),
    responses(
        (status = 200, description = "Scan findings", body = Vec<FindingResponse>),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn get_scan_findings(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
    Query(params): Query<FindingQueryParams>,
) -> Result<impl IntoResponse, Response> {
    // Verify scan exists
    if state.scan_manager.get_scan(&id).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Scan {} not found", id),
                details: None,
            }),
        )
            .into_response());
    }

    // Build filter
    let filter = FindingFilter {
        severity: params.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
        confidence: params
            .confidence
            .map(|c| c.into_iter().filter_map(|v| v.parse().ok()).collect()),
        category: params.category.map(|c| c.into_iter().filter_map(|v| v.parse().ok()).collect()),
        target: params.target,
        plugin_source: params.plugin_source,
        scan_id: Some(id),
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
        ..Default::default()
    };

    let sort = parse_finding_sort(params.sort.as_deref());
    let findings = state
        .storage
        .get_findings_filtered(filter, sort, params.limit, params.offset)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "storage_error".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            )
                .into_response()
        })?;

    let findings: Vec<FindingResponse> = findings.into_iter().map(FindingResponse::from).collect();
    Ok(Json(findings).into_response())
}

/// Get scan logs
#[utoipa::path(
    get,
    path = "/scans/{id}/logs",
    params(
        ("id" = ScanId, Path, description = "Scan ID"),
        PaginationParams,
    ),
    responses(
        (status = 200, description = "Scan logs", body = Vec<crate::scan::ScanLogEntry>),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
    tag = "scans"
)]
async fn get_scan_logs(
    State(state): State<ApiState>,
    Path(id): Path<ScanId>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, Response> {
    let logs = state.scan_manager.get_logs(&id);
    let logs: Vec<crate::scan::ScanLogEntry> =
        logs.into_iter().skip(params.offset).take(params.limit).collect();
    Ok(Json(logs).into_response())
}

/// Create a new target
#[utoipa::path(
    post,
    path = "/targets",
    request_body = CreateTargetRequest,
    responses(
        (status = 201, description = "Target created", body = TargetResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    ),
    tag = "targets"
)]
async fn create_target(
    State(state): State<ApiState>,
    Json(request): Json<CreateTargetRequest>,
) -> Result<impl IntoResponse, Response> {
    if let Err(e) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "validation_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response());
    }

    let base_url = request.base_url.parse().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_url".to_string(),
                message: format!("Invalid base URL: {}", e),
                details: None,
            }),
        )
            .into_response()
    })?;

    let mut metadata = TargetMetadata::new(request.name, base_url);
    if let Some(desc) = request.description {
        metadata = metadata.with_description(desc);
    }
    if let Some(headers) = request.headers {
        for (k, v) in headers {
            metadata = metadata.with_header(k, v);
        }
    }
    if let Some(cookies) = request.cookies {
        for (k, v) in cookies {
            metadata = metadata.with_cookie(k, v);
        }
    }
    if let Some(auth) = request.auth {
        metadata = metadata.with_auth(auth);
    }
    if let Some(rate_limit) = request.rate_limit {
        metadata = metadata.with_rate_limit(rate_limit);
    }
    if let Some(tls_config) = request.tls_config {
        metadata = metadata.with_tls_config(tls_config);
    }
    if let Some(proxy) = request.proxy {
        metadata = metadata.with_proxy(proxy);
    }
    if let Some(custom) = request.custom {
        for (k, v) in custom {
            metadata = metadata.with_custom(k, v);
        }
    }
    if let Some(tags) = request.tags {
        for tag in tags {
            metadata = metadata.with_tag(tag);
        }
    }

    let target = Target::new(request.target_type, metadata);
    let target_id = state.target_manager.register(target.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "target_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    // Save to storage
    state.storage.save_target(&target).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "storage_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok((StatusCode::CREATED, Json(TargetResponse::from(target))).into_response())
}

/// Get a target by ID
#[utoipa::path(
    get,
    path = "/targets/{id}",
    params(
        ("id" = TargetId, Path, description = "Target ID"),
    ),
    responses(
        (status = 200, description = "Target found", body = TargetResponse),
        (status = 404, description = "Target not found", body = ErrorResponse),
    ),
    tag = "targets"
)]
async fn get_target(
    State(state): State<ApiState>,
    Path(id): Path<TargetId>,
) -> Result<impl IntoResponse, Response> {
    let target = state.target_manager.get(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Target {} not found", id),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(TargetResponse::from(target)).into_response())
}

/// List targets
#[utoipa::path(
    get,
    path = "/targets",
    params(
        PaginationParams,
    ),
    responses(
        (status = 200, description = "List of targets", body = Vec<TargetResponse>),
    ),
    tag = "targets"
)]
async fn list_targets(
    State(state): State<ApiState>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let targets = state.target_manager.list();
    let targets: Vec<TargetResponse> = targets
        .into_iter()
        .skip(params.offset)
        .take(params.limit)
        .map(TargetResponse::from)
        .collect();
    Json(targets)
}

/// Update a target
#[utoipa::path(
    put,
    path = "/targets/{id}",
    params(
        ("id" = TargetId, Path, description = "Target ID"),
    ),
    request_body = UpdateTargetRequest,
    responses(
        (status = 200, description = "Target updated", body = TargetResponse),
        (status = 404, description = "Target not found", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
    ),
    tag = "targets"
)]
async fn update_target(
    State(state): State<ApiState>,
    Path(id): Path<TargetId>,
    Json(request): Json<UpdateTargetRequest>,
) -> Result<impl IntoResponse, Response> {
    let mut target = state.target_manager.get(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Target {} not found", id),
                details: None,
            }),
        )
            .into_response()
    })?;

    if let Some(name) = request.name {
        target.metadata.name = name;
    }
    if let Some(description) = request.description {
        target.metadata.description = Some(description);
    }
    if let Some(base_url) = request.base_url {
        target.metadata.base_url = base_url.parse().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_url".to_string(),
                    message: format!("Invalid base URL: {}", e),
                    details: None,
                }),
            )
                .into_response()
        })?;
    }
    if let Some(headers) = request.headers {
        target.metadata.headers = headers;
    }
    if let Some(cookies) = request.cookies {
        target.metadata.cookies = cookies;
    }
    if let Some(auth) = request.auth {
        target.metadata.auth = Some(auth);
    }
    if let Some(rate_limit) = request.rate_limit {
        target.metadata.rate_limit = Some(rate_limit);
    }
    if let Some(tls_config) = request.tls_config {
        target.metadata.tls_config = Some(tls_config);
    }
    if let Some(proxy) = request.proxy {
        target.metadata.proxy = Some(proxy);
    }
    if let Some(custom) = request.custom {
        target.metadata.custom = custom;
    }
    if let Some(tags) = request.tags {
        target.metadata.tags = tags;
    }

    state.target_manager.update(&id, target.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "target_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    state.storage.save_target(&target).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "storage_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(TargetResponse::from(target)).into_response())
}

/// Delete a target
#[utoipa::path(
    delete,
    path = "/targets/{id}",
    params(
        ("id" = TargetId, Path, description = "Target ID"),
    ),
    responses(
        (status = 204, description = "Target deleted"),
        (status = 404, description = "Target not found", body = ErrorResponse),
    ),
    tag = "targets"
)]
async fn delete_target(
    State(state): State<ApiState>,
    Path(id): Path<TargetId>,
) -> Result<impl IntoResponse, Response> {
    let deleted = state.target_manager.delete(&id);
    if !deleted {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Target {} not found", id),
                details: None,
            }),
        )
            .into_response());
    }

    state.storage.delete_target(&id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "storage_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// List plugins
#[utoipa::path(
    get,
    path = "/plugins",
    responses(
        (status = 200, description = "List of plugins", body = Vec<PluginResponse>),
    ),
    tag = "plugins"
)]
async fn list_plugins(State(state): State<ApiState>) -> Result<impl IntoResponse, Response> {
    let plugins = state.plugin_manager.list_plugins().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "plugin_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    let plugins: Vec<PluginResponse> = plugins.into_iter().map(PluginResponse::from).collect();
    Ok(Json(plugins).into_response())
}

/// Get a plugin by ID
#[utoipa::path(
    get,
    path = "/plugins/{id}",
    params(
        ("id" = PluginId, Path, description = "Plugin ID"),
    ),
    responses(
        (status = 200, description = "Plugin found", body = PluginResponse),
        (status = 404, description = "Plugin not found", body = ErrorResponse),
    ),
    tag = "plugins"
)]
async fn get_plugin(
    State(state): State<ApiState>,
    Path(id): Path<PluginId>,
) -> Result<impl IntoResponse, Response> {
    let plugin = state.plugin_manager.get_plugin(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Plugin {} not found", id),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(PluginResponse::from(plugin)).into_response())
}

/// Enable a plugin
#[utoipa::path(
    post,
    path = "/plugins/{id}/enable",
    params(
        ("id" = PluginId, Path, description = "Plugin ID"),
    ),
    responses(
        (status = 200, description = "Plugin enabled", body = PluginResponse),
        (status = 404, description = "Plugin not found", body = ErrorResponse),
    ),
    tag = "plugins"
)]
async fn enable_plugin(
    State(state): State<ApiState>,
    Path(id): Path<PluginId>,
) -> Result<impl IntoResponse, Response> {
    state.plugin_manager.enable_plugin(&id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    let plugin = state.plugin_manager.get_plugin(&id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "plugin_error".to_string(),
                message: "Failed to retrieve enabled plugin".to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(PluginResponse::from(plugin)).into_response())
}

/// Disable a plugin
#[utoipa::path(
    post,
    path = "/plugins/{id}/disable",
    params(
        ("id" = PluginId, Path, description = "Plugin ID"),
    ),
    responses(
        (status = 200, description = "Plugin disabled", body = PluginResponse),
        (status = 404, description = "Plugin not found", body = ErrorResponse),
    ),
    tag = "plugins"
)]
async fn disable_plugin(
    State(state): State<ApiState>,
    Path(id): Path<PluginId>,
) -> Result<impl IntoResponse, Response> {
    state.plugin_manager.disable_plugin(&id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    let plugin = state.plugin_manager.get_plugin(&id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "plugin_error".to_string(),
                message: "Failed to retrieve disabled plugin".to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(PluginResponse::from(plugin)).into_response())
}

/// Get plugin configuration
#[utoipa::path(
    get,
    path = "/plugins/{id}/config",
    params(
        ("id" = PluginId, Path, description = "Plugin ID"),
    ),
    responses(
        (status = 200, description = "Plugin configuration", body = PluginConfig),
        (status = 404, description = "Plugin not found", body = ErrorResponse),
    ),
    tag = "plugins"
)]
async fn get_plugin_config(
    State(state): State<ApiState>,
    Path(id): Path<PluginId>,
) -> Result<impl IntoResponse, Response> {
    let config = state.plugin_manager.get_plugin_config(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                message: format!("Plugin {} not found", id),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(config).into_response())
}

/// Set plugin configuration
#[utoipa::path(
    put,
    path = "/plugins/{id}/config",
    params(
        ("id" = PluginId, Path, description = "Plugin ID"),
    ),
    request_body = PluginConfig,
    responses(
        (status = 200, description = "Plugin configuration updated", body = PluginConfig),
        (status = 404, description = "Plugin not found", body = ErrorResponse),
    ),
    tag = "plugins"
)]
async fn set_plugin_config(
    State(state): State<ApiState>,
    Path(id): Path<PluginId>,
    Json(config): Json<PluginConfig>,
) -> Result<impl IntoResponse, Response> {
    if config.plugin_id != id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                message: "Plugin ID in path and body must match".to_string(),
                details: None,
            }),
        )
            .into_response());
    }

    state.plugin_manager.set_plugin_config(config.clone()).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "plugin_error".to_string(),
                message: e.to_string(),
                details: None,
            }),
        )
            .into_response()
    })?;

    Ok(Json(config).into_response())
}

/// Get finding statistics
#[utoipa::path(
    get,
    path = "/findings/stats",
    params(
        ("scan_id" = Option<ScanId>, Query, description = "Optional scan ID to filter stats"),
    ),
    responses(
        (status = 200, description = "Finding statistics"),
    ),
    tag = "findings"
)]
async fn get_finding_stats(
    State(state): State<ApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, Response> {
    let scan_id = params.get("scan_id").and_then(|s| s.parse().ok());
    let stats = state
        .storage
        .get_finding_stats(FindingFilter { scan_id, ..Default::default() })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "storage_error".to_string(),
                    message: e.to_string(),
                    details: None,
                }),
            )
                .into_response()
        })?;

    Ok(Json(stats).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_scan_request_validation() {
        let request = CreateScanRequest {
            name: "Test Scan".to_string(),
            description: None,
            target_id: TargetId::new(),
            plugins: None,
            exclude_plugins: None,
            max_duration: None,
            max_concurrent_plugins: None,
            plugin_timeout: None,
            debug: None,
            plugin_config: None,
            tags: None,
        };
        assert!(request.validate().is_ok());

        let invalid_request = CreateScanRequest { name: "".to_string(), ..request };
        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_pagination_params_default() {
        let params: PaginationParams = serde_json::from_str("{}").unwrap();
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 0);
    }
}
