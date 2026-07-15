//! Function routes

use crate::{AppState, ApiResult};
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json,
    Router,
};
use openre_core::ids::{FunctionId, ProjectId, FileId};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Function routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_functions))
        .route("/:id", get(get_function))
        .route("/:id/pseudocode", get(get_pseudocode))
        .route("/:id/cfg", get(get_cfg))
        .route("/:id/xrefs", get(get_xrefs))
        .route("/:id/annotations", get(get_annotations))
        .with_state(state)
}

/// List functions
#[utoipa::path(
    get,
    path = "/api/functions",
    params(PaginationParams, FunctionFilterParams),
    responses(
        (status = 200, description = "List of functions", body = FunctionListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "functions"
)]
async fn list_functions(
    State(state): State<std::sync::Arc<AppState>>,
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<FunctionFilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FunctionListResponse>> {
    // Get project store for the project
    let project_id = filter.project_id.as_deref().and_then(|s| s.parse().ok());
    let file_id = filter.file_id.as_deref().and_then(|s| s.parse().ok());
    
    if project_id.is_none() && file_id.is_none() {
        return Err(crate::error::ApiError::BadRequest("project_id or file_id required".into()));
    }
    
    // For now, return empty list - would need project store
    Ok(Json(FunctionListResponse {
        functions: vec![],
        total: 0,
        page: pagination.page(),
        per_page: pagination.per_page(),
    }))
}

/// Get function
#[utoipa::path(
    get,
    path = "/api/functions/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "Function details", body = FunctionResponse),
        (status = 404, description = "Function not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "functions"
)]
async fn get_function(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FunctionId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FunctionResponse>> {
    // Would need project store to get function
    Err(crate::error::ApiError::NotImplemented("Function retrieval not yet implemented".into()))
}

/// Get pseudocode
#[utoipa::path(
    get,
    path = "/api/functions/{id}/pseudocode",
    params(IdParam),
    responses(
        (status = 200, description = "Function pseudocode", body = PseudocodeResponse),
        (status = 404, description = "Function not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "functions"
)]
async fn get_pseudocode(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FunctionId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PseudocodeResponse>> {
    Err(crate::error::ApiError::NotImplemented("Pseudocode retrieval not yet implemented".into()))
}

/// Get CFG
#[utoipa::path(
    get,
    path = "/api/functions/{id}/cfg",
    params(IdParam),
    responses(
        (status = 200, description = "Function CFG", body = CfgResponse),
        (status = 404, description = "Function not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "functions"
)]
async fn get_cfg(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FunctionId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<CfgResponse>> {
    Err(crate::error::ApiError::NotImplemented("CFG retrieval not yet implemented".into()))
}

/// Get xrefs
async fn get_xrefs(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FunctionId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Query(params): Query<XrefParams>,
) -> ApiResult<Json<XrefResponse>> {
    Err(crate::error::ApiError::NotImplemented("Xrefs retrieval not yet implemented".into()))
}

/// Get annotations
async fn get_annotations(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FunctionId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<AnnotationsResponse>> {
    Err(crate::error::ApiError::NotImplemented("Annotations retrieval not yet implemented".into()))
}

// Request/Response types

#[derive(Debug, Deserialize, IntoParams)]
pub struct FunctionFilterParams {
    pub project_id: Option<String>,
    pub file_id: Option<String>,
    pub name: Option<String>,
    pub min_address: Option<u64>,
    pub max_address: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FunctionListResponse {
    pub functions: Vec<FunctionResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FunctionResponse {
    pub id: FunctionId,
    pub file_id: FileId,
    pub name: String,
    pub address: u64,
    pub size: u32,
    pub is_entry: bool,
    pub is_thunk: bool,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    pub parameters: Vec<ParameterInfo>,
    pub stack_frame_size: Option<u32>,
    pub cyclomatic_complexity: Option<u32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ParameterInfo {
    pub name: String,
    pub type_: String,
    pub location: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PseudocodeResponse {
    pub function_id: FunctionId,
    pub pseudocode: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CfgResponse {
    pub function_id: FunctionId,
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CfgNode {
    pub id: String,
    pub address: u64,
    pub instructions: Vec<String>,
    pub is_entry: bool,
    pub is_exit: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CfgEdge {
    pub from: String,
    pub to: String,
    pub type_: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct XrefParams {
    pub direction: Option<String>, // "to", "from", "both"
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct XrefResponse {
    pub function_id: FunctionId,
    pub xrefs: Vec<XrefInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct XrefInfo {
    pub from_address: u64,
    pub to_address: u64,
    pub type_: String,
    pub from_function: Option<FunctionId>,
    pub to_function: Option<FunctionId>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnnotationsResponse {
    pub function_id: FunctionId,
    pub annotations: Vec<AnnotationInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnnotationInfo {
    pub id: String,
    pub type_: String,
    pub content: String,
    pub address: Option<u64>,
    pub author: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}