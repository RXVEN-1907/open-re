//! User routes

use crate::validation::{IdParam, PaginationParams};
use crate::{ApiResult, AppState};
use axum::Extension;
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use openre_core::ids::UserId;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// User routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_users))
        .route("/:id", get(get_user))
        .with_state(state)
}

/// List users (admin only)
#[utoipa::path(
    get,
    path = "/api/users",
    params(PaginationParams, UserFilterParams),
    responses(
        (status = 200, description = "List of users", body = UserListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    tag = "users"
)]
async fn list_users(
    State(state): State<std::sync::Arc<AppState>>,
    Query(_pagination): Query<PaginationParams>,
    Query(_filter): Query<UserFilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<UserListResponse>> {
    let _ = state;

    // Check admin
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    // User storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

/// Get user
#[utoipa::path(
    get,
    path = "/api/users/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "User details", body = crate::routes::auth::UserResponse),
        (status = 404, description = "User not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "users"
)]
async fn get_user(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<UserId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<crate::routes::auth::UserResponse>> {
    let _ = state;

    // Users can only view themselves unless admin
    if id.to_string() != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Access denied".into()));
    }

    // User storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

// Request/Response types

#[derive(Debug, Deserialize, IntoParams)]
pub struct UserFilterParams {
    pub search: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub users: Vec<crate::routes::auth::UserResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}
