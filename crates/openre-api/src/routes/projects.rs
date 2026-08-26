//! Project routes

use crate::validation::{FilterParams, IdParam, PaginationParams};
use crate::{ApiResult, AppState, ValidatedJson};
use axum::Extension;
use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use openre_core::ids::{ExportId, ProjectId, ShareLinkId, UserId};
use openre_core::traits::{
    CollaboratorInvite, CollaboratorRole, Project as ProjectRecord, ShareLink as ShareLinkRecord,
    SharePermissions,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Parse a collaborator role string
fn parse_collaborator_role(role: &str) -> crate::error::ApiResult<CollaboratorRole> {
    match role.to_lowercase().as_str() {
        "owner" => Ok(CollaboratorRole::Owner),
        "admin" => Ok(CollaboratorRole::Admin),
        "member" => Ok(CollaboratorRole::Member),
        "viewer" => Ok(CollaboratorRole::Viewer),
        _ => Err(crate::error::ApiError::BadRequest(format!(
            "Invalid role: {}",
            role
        ))),
    }
}

/// Map a share permission string to permissions struct
fn share_permissions_from_str(permission: &str) -> crate::error::ApiResult<SharePermissions> {
    match permission.to_lowercase().as_str() {
        "view" | "read" => Ok(SharePermissions {
            can_view: true,
            can_comment: false,
            can_download: false,
        }),
        "comment" => Ok(SharePermissions {
            can_view: true,
            can_comment: true,
            can_download: false,
        }),
        "download" | "full" | "edit" => Ok(SharePermissions {
            can_view: true,
            can_comment: true,
            can_download: true,
        }),
        _ => Err(crate::error::ApiError::BadRequest(format!(
            "Invalid permission: {}",
            permission
        ))),
    }
}

/// Project routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_projects).post(create_project))
        .route(
            "/:id",
            get(get_project).put(update_project).delete(delete_project),
        )
        .route(
            "/:id/collaborators",
            get(list_collaborators).post(add_collaborator),
        )
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
    Query(_pagination): Query<PaginationParams>,
    Query(_filter): Query<FilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<ProjectListResponse>> {
    let _ = (state, claims);
    // Project listing is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "project listing not implemented yet".into(),
    ))
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

    let project = ProjectRecord {
        id: ProjectId::new(),
        name: payload.name,
        description: payload.description.unwrap_or_default(),
        owner_id: user_id,
        visibility: if payload.is_public.unwrap_or(false) {
            "public".to_string()
        } else {
            "private".to_string()
        },
        settings: payload.settings.unwrap_or(serde_json::Value::Null),
        sqlite_path: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    state.global_store.create_project(&project).await?;
    state.global_store.init_project_db(project.id).await?;

    Ok(Json(ProjectResponse {
        id: project.id,
        name: project.name,
        description: if project.description.is_empty() {
            None
        } else {
            Some(project.description)
        },
        owner_id: project.owner_id,
        is_public: project.visibility == "public",
        settings: Some(project.settings),
        created_at: project.created_at,
        updated_at: project.updated_at,
    }))
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
    let _ = (state, id, claims);
    // Project retrieval is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "project retrieval not implemented yet".into(),
    ))
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
    let _ = (state, id, payload, claims);
    // Project updates are not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "project updates not implemented yet".into(),
    ))
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
    let _ = (state, id, claims);
    // Project deletion is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "project deletion not implemented yet".into(),
    ))
}

/// List collaborators
async fn list_collaborators(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<CollaboratorResponse>>> {
    let _ = (state, id, claims);
    // Collaborator listing is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "collaborator listing not implemented yet".into(),
    ))
}

/// Add collaborator
async fn add_collaborator(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<AddCollaboratorRequest>,
) -> ApiResult<Json<CollaboratorResponse>> {
    let _ = claims;

    let role = parse_collaborator_role(&payload.role)?;

    state
        .global_store
        .add_collaborator(id, payload.user_id, role)
        .await?;

    Ok(Json(CollaboratorResponse {
        user_id: payload.user_id,
        project_id: id,
        role: payload.role,
        added_at: chrono::Utc::now(),
        user: None,
    }))
}

/// Remove collaborator
async fn remove_collaborator(
    State(state): State<std::sync::Arc<AppState>>,
    Path((project_id, user_id)): Path<(ProjectId, UserId)>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let _ = (state, project_id, user_id, claims);
    // Collaborator removal is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "collaborator removal not implemented yet".into(),
    ))
}

/// List invites
async fn list_invites(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<InviteResponse>>> {
    let _ = (state, id, claims);
    // Invite listing is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "invite listing not implemented yet".into(),
    ))
}

/// Create invite
async fn create_invite(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<CreateInviteRequest>,
) -> ApiResult<Json<InviteResponse>> {
    let invited_by: UserId = claims.sub.parse()?;
    let role = parse_collaborator_role(&payload.role)?;

    let invite = CollaboratorInvite {
        id: uuid::Uuid::new_v4(),
        project_id: id,
        email: payload.email.clone(),
        role,
        invited_by,
        token: uuid::Uuid::new_v4().to_string(),
        expires_at: payload
            .expires_at
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(7)),
        created_at: chrono::Utc::now(),
    };

    state.global_store.create_invite(&invite).await?;

    Ok(Json(InviteResponse {
        id: openre_core::ids::InviteId::from_uuid(invite.id),
        project_id: invite.project_id,
        email: invite.email,
        role: payload.role,
        token: invite.token,
        expires_at: invite.expires_at,
        created_at: invite.created_at,
        accepted_at: None,
    }))
}

/// Revoke invite
async fn revoke_invite(
    State(state): State<std::sync::Arc<AppState>>,
    Path((project_id, invite_id)): Path<(ProjectId, openre_core::ids::InviteId)>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let _ = (state, project_id, invite_id, claims);
    // Invite revocation is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "invite revocation not implemented yet".into(),
    ))
}

/// Create share link
async fn create_share_link(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<CreateShareLinkRequest>,
) -> ApiResult<Json<ShareLinkResponse>> {
    let created_by: UserId = claims.sub.parse()?;
    let permissions = share_permissions_from_str(&payload.permission)?;

    let link = ShareLinkRecord {
        id: ShareLinkId::new(),
        project_id: id,
        analysis_id: None,
        permissions,
        token: uuid::Uuid::new_v4().to_string(),
        created_by,
        expires_at: payload.expires_at,
        created_at: chrono::Utc::now(),
    };

    state.global_store.create_share_link(&link).await?;

    Ok(Json(ShareLinkResponse {
        id: link.id,
        project_id: link.project_id,
        token: link.token,
        permission: payload.permission,
        expires_at: link.expires_at,
        max_uses: payload.max_uses,
        uses: 0,
        created_at: link.created_at,
    }))
}

/// Export project
async fn export_project(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<ProjectId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<ExportProjectRequest>,
) -> ApiResult<Json<ExportResponse>> {
    let _ = claims;

    // Queue an export job; persistent export records are not yet implemented.
    let job = openre_queue::Job::new(openre_core::traits::JobType::Export).with_payload(
        serde_json::json!({
            "project_id": id.to_string(),
            "format": payload.format,
            "include_files": payload.include_files,
            "include_analysis": payload.include_analysis,
        }),
    );

    state.queue_manager.enqueue(job).await?;

    Ok(Json(ExportResponse {
        id: ExportId::new(),
        project_id: id,
        format: payload.format,
        status: "queued".to_string(),
        download_url: None,
        created_at: chrono::Utc::now(),
        completed_at: None,
    }))
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

#[derive(Debug, Serialize, ToSchema)]
pub struct UserSummary {
    pub id: openre_core::ids::UserId,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
}
