//! Auth routes

use crate::{ApiResult, AppState, ValidatedJson};
use axum::{
    extract::{Extension, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use openre_core::ids::UserId;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Auth routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/refresh", post(refresh_token))
        .route("/logout", post(logout))
        .route("/me", get(get_current_user))
        .route("/password", put(change_password))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/:id", delete(revoke_api_key))
        .with_state(state)
}

/// Login
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Invalid credentials", body = crate::error::ApiErrorResponse),
    ),
    tag = "auth"
)]
async fn login(
    State(state): State<std::sync::Arc<AppState>>,
    ValidatedJson(payload): ValidatedJson<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let _ = (state, payload);
    // User storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

/// Register
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registration successful", body = LoginResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 409, description = "Email already exists", body = crate::error::ApiErrorResponse),
    ),
    tag = "auth"
)]
async fn register(
    State(state): State<std::sync::Arc<AppState>>,
    ValidatedJson(payload): ValidatedJson<RegisterRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let _ = (state, payload);
    // User storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

/// Refresh token
async fn refresh_token(
    State(state): State<std::sync::Arc<AppState>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let _ = (state, payload);
    // Refresh token persistence is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

/// Logout
async fn logout(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let _ = (state, claims);
    // Refresh token persistence is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

/// Get current user
async fn get_current_user(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<UserResponse>> {
    let _ = (&state, &claims);
    // User storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

/// Change password
async fn change_password(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<ChangePasswordRequest>,
) -> ApiResult<()> {
    let _ = (&state, payload, &claims);
    // User storage is not yet implemented in GlobalStore.
    Err(crate::error::ApiError::NotImplemented(
        "user storage not implemented".into(),
    ))
}

/// List API keys
async fn list_api_keys(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<ApiKeyResponse>>> {
    let _ = (state, claims);
    // API key storage is not yet implemented in GlobalStore.
    Ok(Json(Vec::new()))
}

/// Create API key
async fn create_api_key(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<CreateApiKeyRequest>,
) -> ApiResult<Json<ApiKeyCreateResponse>> {
    let user_id: UserId = claims.sub.parse()?;

    // Mint the key via AuthService; persistent key records are not
    // yet supported by GlobalStore.
    let api_key = state.auth_service.create_api_key(
        &user_id.to_string(),
        &payload.name,
        payload.scopes.clone(),
    )?;
    let _ = state;

    let prefix: String = api_key.chars().take(8).collect();

    Ok(Json(ApiKeyCreateResponse {
        api_key, // Only returned once!
        key: ApiKeyResponse {
            id: openre_core::ids::ApiKeyId::new(),
            name: payload.name,
            prefix,
            scopes: payload.scopes,
            expires_at: payload.expires_at,
            last_used: None,
            created_at: chrono::Utc::now(),
        },
    }))
}
/// Revoke API key
async fn revoke_api_key(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<openre_core::ids::ApiKeyId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let _ = (state, id, claims);
    // API key storage is not yet implemented in GlobalStore.
    Ok(())
}

// Request/Response types

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 1))]
    pub password: String,

    pub remember_me: Option<bool>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8, max = 128))]
    pub password: String,

    #[validate(length(min = 1, max = 50))]
    pub username: String,

    pub full_name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1))]
    pub current_password: String,

    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateApiKeyRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,

    #[validate(length(min = 1))]
    pub scopes: Vec<String>,

    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: openre_core::ids::UserId,
    pub email: String,
    pub username: String,
    pub full_name: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyResponse {
    pub id: openre_core::ids::ApiKeyId,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyCreateResponse {
    pub api_key: String,
    pub key: ApiKeyResponse,
}

use axum::extract::Path;
