//! Security Analyst AI routes
//!
//! API endpoints for the AI-powered security analyst that interprets,
//! correlates, explains, prioritizes, and assists with security scan findings.

use crate::{ApiError, ApiResult, AppState, ValidatedJson};
use axum::{
    extract::{Extension, Path, Query, State},
    response::{sse::Event, Sse},
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::FindingFilter;
use openre_security_ai::{
    CorrelationReport, ExecutiveSummary, FindingExplanation, PrioritizedFindings, QueryResponse,
    RemediationPlan, ScanComparison, SecurityAnalyst, SummaryAudience as AnalystAudience,
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Security AI analyst routes
pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        // Finding explanation endpoints
        .route("/explain", post(explain_finding))
        .route("/explain/stream", get(stream_explain_finding))
        // Remediation endpoints
        .route("/remediate", post(generate_remediation))
        .route("/remediate/stream", get(stream_generate_remediation))
        // Correlation endpoints
        .route("/correlate", post(correlate_findings))
        .route("/correlate/stream", get(stream_correlate_findings))
        // Prioritization endpoints
        .route("/prioritize", post(prioritize_findings))
        .route("/prioritize/stream", get(stream_prioritize_findings))
        // Executive summary endpoints
        .route("/summarize", post(executive_summary))
        .route("/summarize/stream", get(stream_executive_summary))
        // Query endpoints
        .route("/query", post(query_findings))
        .route("/query/stream", get(stream_query_findings))
        // Scan comparison endpoints
        .route("/compare", post(compare_scans))
        .route("/compare/stream", get(stream_compare_scans))
        .with_state(state)
}

// Request/Response types

/// Request to explain a finding
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ExplainFindingRequest {
    /// Scan ID containing the finding
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub scan_id: String,

    /// Finding ID to explain
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub finding_id: String,
}

/// Request to generate remediation for a finding
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct GenerateRemediationRequest {
    /// Scan ID containing the finding
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub scan_id: String,

    /// Finding ID to remediate
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub finding_id: String,
}

/// Request to correlate findings
#[derive(Debug, Deserialize, ToSchema)]
pub struct CorrelateFindingsRequest {
    /// Scan ID to analyze
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub scan_id: String,

    /// Optional filter for findings to correlate
    pub filter: Option<FindingFilter>,
}

/// Request to prioritize findings
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct PrioritizeFindingsRequest {
    /// Scan ID to prioritize
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub scan_id: String,
}

/// Request for executive summary
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ExecutiveSummaryRequest {
    /// Scan ID to summarize
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub scan_id: String,

    /// Target audience for the summary
    pub audience: SummaryAudience,
}

/// Target audience for summaries
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SummaryAudience {
    Developer,
    SecurityEngineer,
    Manager,
    Executive,
}

impl From<SummaryAudience> for AnalystAudience {
    fn from(audience: SummaryAudience) -> Self {
        match audience {
            SummaryAudience::Developer => AnalystAudience::Developer,
            SummaryAudience::SecurityEngineer => AnalystAudience::SecurityEngineer,
            SummaryAudience::Manager => AnalystAudience::Manager,
            SummaryAudience::Executive => AnalystAudience::Executive,
        }
    }
}

/// Request to query findings with natural language
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct QueryFindingsRequest {
    /// Scan ID to query
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub scan_id: String,

    /// Natural language question
    #[validate(length(min = 1, max = 1000))]
    pub question: String,
}

/// Request to compare two scans
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CompareScansRequest {
    /// Base scan ID for comparison
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub base_scan_id: String,

    /// Target scan ID for comparison
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub target_scan_id: String,
}

// API Endpoints

/// Explain a security finding
#[utoipa::path(
    post,
    path = "/api/analyst/explain",
    request_body = ExplainFindingRequest,
    responses(
        (status = 200, description = "Finding explanation", body = FindingExplanation),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Finding not found", body = crate::error::ApiErrorResponse),
    ),
    tag = "analyst"
)]
async fn explain_finding(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<ExplainFindingRequest>,
) -> ApiResult<Json<FindingExplanation>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse IDs
    let scan_id: ScanId = payload
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;
    let finding_id: FindingId = payload
        .finding_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid finding ID".to_string()))?;

    // Execute explanation
    let explanation = analyst
        .explain_finding(scan_id, finding_id)
        .await
        .map_err(|e| match e {
            openre_security_ai::AiAnalystError::FindingNotFound(_) => {
                ApiError::NotFound("Finding not found".to_string())
            }
            _ => ApiError::Internal(e.to_string()),
        })?;

    Ok(Json(explanation))
}

/// Stream explanation of a security finding
async fn stream_explain_finding(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<ExplainFindingRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse IDs
    let scan_id: ScanId = params
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;
    let finding_id: FindingId = params
        .finding_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid finding ID".to_string()))?;

    // Execute streaming explanation
    let stream = analyst
        .stream_explain_finding(scan_id, finding_id)
        .await
        .map_err(|e| match e {
            openre_security_ai::AiAnalystError::FindingNotFound(_) => {
                ApiError::NotFound("Finding not found".to_string())
            }
            _ => ApiError::Internal(e.to_string()),
        })?;

    let event_stream = stream.map(|result| match result {
        Ok(content) => Ok(Event::default().data(content)),
        Err(e) => Ok(Event::default().data(format!("Error: {}", e))),
    });

    Ok(Sse::new(event_stream))
}

/// Stream remediation plan generation
async fn stream_generate_remediation(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<GenerateRemediationRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse IDs
    let scan_id: ScanId = params
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;
    let finding_id: FindingId = params
        .finding_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid finding ID".to_string()))?;

    // Execute streaming remediation generation
    let stream = analyst
        .stream_generate_remediation(scan_id, finding_id)
        .await
        .map_err(|e| match e {
            openre_security_ai::AiAnalystError::FindingNotFound(_) => {
                ApiError::NotFound("Finding not found".to_string())
            }
            _ => ApiError::Internal(e.to_string()),
        })?;

    let event_stream = stream.map(|result| match result {
        Ok(content) => Ok(Event::default().data(content)),
        Err(e) => Ok(Event::default().data(format!("Error: {}", e))),
    });

    Ok(Sse::new(event_stream))
}

/// Stream finding correlation
async fn stream_correlate_findings(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<CorrelateFindingsRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = params
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Execute streaming correlation
    let stream = analyst
        .stream_correlate_findings(scan_id, params.filter.as_ref())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let event_stream = stream.map(|result| match result {
        Ok(content) => Ok(Event::default().data(content)),
        Err(e) => Ok(Event::default().data(format!("Error: {}", e))),
    });

    Ok(Sse::new(event_stream))
}

/// Stream finding prioritization
async fn stream_prioritize_findings(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<PrioritizeFindingsRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = params
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Execute streaming prioritization
    let stream = analyst
        .stream_prioritize_findings(scan_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let event_stream = stream.map(|result| match result {
        Ok(content) => Ok(Event::default().data(content)),
        Err(e) => Ok(Event::default().data(format!("Error: {}", e))),
    });

    Ok(Sse::new(event_stream))
}

/// Stream executive summary generation
async fn stream_executive_summary(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<ExecutiveSummaryRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = params
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Convert audience
    let audience = AnalystAudience::from(params.audience);

    // Execute streaming summary generation
    let stream = analyst
        .stream_executive_summary(scan_id, audience)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let event_stream = stream.map(|result| match result {
        Ok(content) => Ok(Event::default().data(content)),
        Err(e) => Ok(Event::default().data(format!("Error: {}", e))),
    });

    Ok(Sse::new(event_stream))
}

/// Stream query findings
async fn stream_query_findings(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<QueryFindingsRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = params
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Execute streaming query
    let stream = analyst
        .stream_query_findings(scan_id, &params.question)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let event_stream = stream.map(|result| match result {
        Ok(content) => Ok(Event::default().data(content)),
        Err(e) => Ok(Event::default().data(format!("Error: {}", e))),
    });

    Ok(Sse::new(event_stream))
}

/// Stream scan comparison
async fn stream_compare_scans(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<CompareScansRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse IDs
    let base_scan_id: ScanId = params
        .base_scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid base scan ID".to_string()))?;
    let target_scan_id: ScanId = params
        .target_scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid target scan ID".to_string()))?;

    // Execute streaming comparison
    let stream = analyst
        .stream_compare_scans(base_scan_id, target_scan_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let event_stream = stream.map(|result| match result {
        Ok(content) => Ok(Event::default().data(content)),
        Err(e) => Ok(Event::default().data(format!("Error: {}", e))),
    });

    Ok(Sse::new(event_stream))
}

/// Generate remediation plan for a finding
#[utoipa::path(
    post,
    path = "/api/analyst/remediate",
    request_body = GenerateRemediationRequest,
    responses(
        (status = 200, description = "Remediation plan", body = RemediationPlan),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 404, description = "Finding not found", body = crate::error::ApiErrorResponse),
    ),
    tag = "analyst"
)]
async fn generate_remediation(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<GenerateRemediationRequest>,
) -> ApiResult<Json<RemediationPlan>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse IDs
    let scan_id: ScanId = payload
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;
    let finding_id: FindingId = payload
        .finding_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid finding ID".to_string()))?;

    // Generate remediation
    let plan = analyst
        .generate_remediation(scan_id, finding_id)
        .await
        .map_err(|e| match e {
            openre_security_ai::AiAnalystError::FindingNotFound(_) => {
                ApiError::NotFound("Finding not found".to_string())
            }
            _ => ApiError::Internal(e.to_string()),
        })?;

    Ok(Json(plan))
}

/// Correlate findings to identify relationships
#[utoipa::path(
    post,
    path = "/api/analyst/correlate",
    request_body = CorrelateFindingsRequest,
    responses(
        (status = 200, description = "Correlation report", body = CorrelationReport),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analyst"
)]
async fn correlate_findings(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<CorrelateFindingsRequest>,
) -> ApiResult<Json<CorrelationReport>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = payload
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Correlate findings
    let report = analyst
        .correlate_findings(scan_id, payload.filter.as_ref())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(report))
}

/// Prioritize findings for remediation
#[utoipa::path(
    post,
    path = "/api/analyst/prioritize",
    request_body = PrioritizeFindingsRequest,
    responses(
        (status = 200, description = "Prioritized findings", body = PrioritizedFindings),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analyst"
)]
async fn prioritize_findings(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<PrioritizeFindingsRequest>,
) -> ApiResult<Json<PrioritizedFindings>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = payload
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Prioritize findings
    let prioritized = analyst
        .prioritize_findings(scan_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(prioritized))
}

/// Generate executive summary for different audiences
#[utoipa::path(
    post,
    path = "/api/analyst/summarize",
    request_body = ExecutiveSummaryRequest,
    responses(
        (status = 200, description = "Executive summary", body = ExecutiveSummary),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analyst"
)]
async fn executive_summary(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<ExecutiveSummaryRequest>,
) -> ApiResult<Json<ExecutiveSummary>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = payload
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Convert audience
    let audience: AnalystAudience = payload.audience.into();

    // Generate summary
    let summary = analyst
        .executive_summary(scan_id, audience)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(summary))
}

/// Query findings with natural language
#[utoipa::path(
    post,
    path = "/api/analyst/query",
    request_body = QueryFindingsRequest,
    responses(
        (status = 200, description = "Query response", body = QueryResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analyst"
)]
async fn query_findings(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<QueryFindingsRequest>,
) -> ApiResult<Json<QueryResponse>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse ID
    let scan_id: ScanId = payload
        .scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid scan ID".to_string()))?;

    // Query findings
    let response = analyst
        .query_findings(scan_id, &payload.question)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(response))
}

/// Compare two scans for changes
#[utoipa::path(
    post,
    path = "/api/analyst/compare",
    request_body = CompareScansRequest,
    responses(
        (status = 200, description = "Scan comparison", body = ScanComparison),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "analyst"
)]
async fn compare_scans(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<CompareScansRequest>,
) -> ApiResult<Json<ScanComparison>> {
    // Check if analyst service is configured
    let analyst = state
        .analyst
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("AI analyst not configured".to_string()))?;

    // Parse IDs
    let base_scan_id: ScanId = payload
        .base_scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid base scan ID".to_string()))?;
    let target_scan_id: ScanId = payload
        .target_scan_id
        .parse()
        .map_err(|_| ApiError::BadRequest("Invalid target scan ID".to_string()))?;

    // Compare scans
    let comparison = analyst
        .compare_scans(base_scan_id, target_scan_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(comparison))
}
