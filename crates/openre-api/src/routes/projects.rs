//! Project routes

use crate::{AppState, ApiResult, ValidatedJson};
use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put, delete},
    Json,
    Router,
};
use openre_core::ids::ProjectId;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Project routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_projects).post(create_project))
        .route("/:id", get(get_project).put(update_project).delete(delete_project))
        .route("/:id/collaborators", get(list_collaborators).post(add_collaborator))
        .route("/:id/collaborators/:user_id", delete(remove_collaborator))
        .route("/:id/invites", get(list_invites).post(create_invite))
        .route("/:id/invites/:invite_id", delete(revoke_invite))
        .route("/:id/share", post(create_share_link))
        .route("/:id/export", post(export_project))
        .with_state(state)
}

/// List projects
#[utoipa::path(
    get,
    path = "/api/projects",
    params(PaginationParams, FilterParams),
    responses(
        (status = 200, description = "List of projects", body = ProjectListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "projects"
)]
async fn list_projects(
    State(state): State<std::sync::Arc<AppState>>,
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<FilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<ProjectListResponse>> {
    let projects = state.global_store.list_projects(
        claims.sub.parse().ok(),
        filter.project_id.as_deref().and_then(|s| s.parse().ok()),
        pagination.offset(),
        pagination.limit(),
    ).await?;

    let total = state.global_store.count_projects(
        claims.sub.parse().ok(),
        filter.project_id.as_deref().and_then(|s| s.parse().ok()),
    ).await?;

    Ok(Json(ProjectListResponse {
        projects,
        total,
        page: pagination.page(),
        per_page: pagination.per_page(),
    }))
}

/// Create project
#[utoipa::path(
    post,
    path = "/api/projects",
    request_body = CreateProjectRequest,
    responses(
        (status = 201, description = "Project created", body = ProjectResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "projects"
)]
async fn create_project(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<CreateProjectRequest>,
) -> ApiResult<Json<ProjectResponse>> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    
    let project = state.global_store.create_project(
        user_id,
        payload.name,
        payload.description,
        payload.is_public.unwrap_or(false),
        payload.settings,
    ).await?;

    Ok(Json(ProjectResponse::from(project)))
}

/// Get project
#[utoipa::path(
    get,
    path = "/api/projects/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "Project details", body = ProjectResponse),
        (status = 404, description = "Project not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "projects"
)]
async fn get_project(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<ProjectResponse>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check access
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        if !project.is_public {
            return Err(crate::error::ApiError::Forbidden("Access denied".into()));
        }
    }

    Ok(Json(ProjectResponse::from(project)))
}

/// Update project
#[utoipa::path(
    put,
    path = "/api/projects/{id}",
    params(IdParam),
    request_body = UpdateProjectRequest,
    responses(
        (status = 200, description = "Project updated", body = ProjectResponse),
        (status = 404, description = "Project not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    tag = "projects"
)]
async fn update_project(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<UpdateProjectRequest>,
) -> ApiResult<Json<ProjectResponse>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can update project".into()));
    }

    let updated = state.global_store.update_project(
        id,
        payload.name,
        payload.description,
        payload.is_public,
        payload.settings,
    ).await?;

    Ok(Json(ProjectResponse::from(updated)))
}

/// Delete project
#[utoipa::path(
    delete,
    path = "/api/projects/{id}",
    params(IdParam),
    responses(
        (status = 204, description = "Project deleted"),
        (status = 404, description = "Project not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    tag = "projects"
)]
async fn delete_project(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can delete project".into()));
    }

    state.global_store.delete_project(id).await?;

    Ok(())
}

/// List collaborators
async fn list_collaborators(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<CollaboratorResponse>>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check access
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        if !project.is_public {
            return Err(crate::error::ApiError::Forbidden("Access denied".into()));
        }
    }

    let collaborators = state.global_store.list_collaborators(id).await?;

    Ok(Json(collaborators.into_iter().map(CollaboratorResponse::from).collect()))
}

/// Add collaborator
async fn add_collaborator(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<AddCollaboratorRequest>,
) -> ApiResult<Json<CollaboratorResponse>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can add collaborators".into()));
    }

    let collaborator = state.global_store.add_collaborator(
        id,
        payload.user_id,
        payload.role,
    ).await?;

    Ok(Json(CollaboratorResponse::from(collaborator)))
}

/// Remove collaborator
async fn remove_collaborator(
    State(state): State<std::sync::Arc<AppState>>,
    Path((project_id, user_id)): Path<(ProjectId, openre_core::ids::UserId)>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let project = state.global_store.get_project(project_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can remove collaborators".into()));
    }

    state.global_store.remove_collaborator(project_id, user_id).await?;

    Ok(())
}

/// List invites
async fn list_invites(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<InviteResponse>>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can view invites".into()));
    }

    let invites = state.global_store.list_invites(id).await?;

    Ok(Json(invites.into_iter().map(InviteResponse::from).collect()))
}

/// Create invite
async fn create_invite(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<CreateInviteRequest>,
) -> ApiResult<Json<InviteResponse>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can create invites".into()));
    }

    let invite = state.global_store.create_invite(
        id,
        payload.email,
        payload.role,
        payload.expires_at,
    ).await?;

    Ok(Json(InviteResponse::from(invite)))
}

/// Revoke invite
async fn revoke_invite(
    State(state): State<std::sync::Arc<AppState>>,
    Path((project_id, invite_id)): Path<(ProjectId, openre_core::ids::InviteId)>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let project = state.global_store.get_project(project_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can revoke invites".into()));
    }

    state.global_store.revoke_invite(project_id, invite_id).await?;

    Ok(())
}

/// Create share link
async fn create_share_link(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<CreateShareLinkRequest>,
) -> ApiResult<Json<ShareLinkResponse>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check ownership
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Only owner can create share links".into()));
    }

    let link = state.global_store.create_share_link(
        id,
        payload.permission,
        payload.expires_at,
        payload.max_uses,
    ).await?;

    Ok(Json(ShareLinkResponse::from(link)))
}

/// Export project
async fn export_project(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<ExportProjectRequest>,
) -> ApiResult<Json<ExportResponse>> {
    let project = state.global_store.get_project(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Project not found".into()))?;

    // Check access
    if project.owner_id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        if !project.is_public {
            return Err(crate::error::ApiError::Forbidden("Access denied".into()));
        }
    }

    let export = state.global_store.create_export(
        id,
        payload.format,
        payload.include_files,
        payload.include_analysis,
    ).await?;

    Ok(Json(ExportResponse::from(export)))
}

// Request/Response types

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectResponse {
    pub id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: openre_core::ids::UserId,
    pub is_public: bool,
    pub settings: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<openre_storage::Project> for ProjectResponse {
    fn from(p: openre_storage::Project) -> Self {
        Self {
            id: p.id,
            name: p.name,
            description: p.description,
            owner_id: p.owner_id,
            is_public: p.is_public,
            settings: p.settings,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateProjectRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    
    #[validate(length(max = 500))]
    pub description: Option<String>,
    
    pub is_public: Option<bool>,
    
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateProjectRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    
    #[validate(length(max = 500))]
    pub description: Option<String>,
    
    pub is_public: Option<bool>,
    
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CollaboratorResponse {
    pub user_id: openre_core::ids::UserId,
    pub project_id: ProjectId,
    pub role: String,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub user: Option<UserSummary>,
}

impl From<openre_storage::Collaborator> for CollaboratorResponse {
    fn from(c: openre_storage::Collaborator) -> Self {
        Self {
            user_id: c.user_id,
            project_id: c.project_id,
            role: c.role,
            added_at: c.added_at,
            user: None, // Would be populated separately
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AddCollaboratorRequest {
    pub user_id: openre_core::ids::UserId,
    
    #[validate(length(min = 1))]
    pub role: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteResponse {
    pub id: openre_core::ids::InviteId,
    pub project_id: ProjectId,
    pub email: String,
    pub role: String,
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub accepted_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<openre_storage::Invite> for InviteResponse {
    fn from(i: openre_storage::Invite) -> Self {
        Self {
            id: i.id,
            project_id: i.project_id,
            email: i.email,
            role: i.role,
            token: i.token,
            expires_at: i.expires_at,
            created_at: i.created_at,
            accepted_at: i.accepted_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateInviteRequest {
    #[validate(email)]
    pub email: String,
    
    #[validate(length(min = 1))]
    pub role: String,
    
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareLinkResponse {
    pub id: openre_core::ids::ShareLinkId,
    pub project_id: ProjectId,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<openre_storage::ShareLink> for ShareLinkResponse {
    fn from(s: openre_storage::ShareLink) -> Self {
        Self {
            id: s.id,
            project_id: s.project_id,
            token: s.token,
            permission: s.permission,
            expires_at: s.expires_at,
            max_uses: s.max_uses,
            uses: s.uses,
            created_at: s.created_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateShareLinkRequest {
    #[validate(length(min = 1))]
    pub permission: String,
    
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    
    pub max_uses: Option<u32>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ExportProjectRequest {
    #[validate(length(min = 1))]
    pub format: String,
    
    pub include_files: Option<bool>,
    
    pub include_analysis: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExportResponse {
    pub id: openre_core::ids::ExportId,
    pub project_id: ProjectId,
    pub format: String,
    pub status: String,
    pub download_url: Option<String>,
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
            created_at: e.created_at,
            completed_at: e.completed_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserSummary {
    pub id: openre_core::ids::UserId,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
}