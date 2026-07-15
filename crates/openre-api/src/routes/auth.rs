//! Auth routes

use crate::{AppState, ApiResult, ValidatedJson};
use axum::{
    extract::{State, Extension},
    routing::{get, post},
    Json,
    Router,
};
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
    let user = state.global_store.get_user_by_email(&payload.email).await?
        .ok_or_else(|| crate::error::ApiError::Unauthorized("Invalid credentials".into()))?;

    if !state.auth_service.verify_password(&payload.password, &user.password_hash)? {
        return Err(crate::error::ApiError::Unauthorized("Invalid credentials".into()));
    }

    let access_token = state.auth_service.create_access_token(
        &user.id.to_string(),
        &user.email,
        user.roles,
        user.permissions,
        None,
    )?;

    let refresh_token = state.auth_service.create_refresh_token(&user.id.to_string())?;

    // Store refresh token
    state.global_store.store_refresh_token(&user.id, &refresh_token).await?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.auth_service.config.access_token_ttl_seconds,
        user: UserResponse::from(user),
    }))
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
    // Check if email exists
    if state.global_store.get_user_by_email(&payload.email).await?.is_some() {
        return Err(crate::error::ApiError::Conflict("Email already registered".into()));
    }

    // Hash password
    let password_hash = state.auth_service.hash_password(&payload.password)?;

    // Create user
    let user = state.global_store.create_user(
        payload.email,
        payload.username,
        password_hash,
        payload.full_name,
    ).await?;

    let access_token = state.auth_service.create_access_token(
        &user.id.to_string(),
        &user.email,
        user.roles.clone(),
        user.permissions.clone(),
        None,
    )?;

    let refresh_token = state.auth_service.create_refresh_token(&user.id.to_string())?;

    state.global_store.store_refresh_token(&user.id, &refresh_token).await?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.auth_service.config.access_token_ttl_seconds,
        user: UserResponse::from(user),
    }))
}

/// Refresh token
async fn refresh_token(
    State(state): State<std::sync::Arc<AppState>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let claims = state.auth_service.validate_refresh_token(&payload.refresh_token)?;

    // Verify refresh token exists in store
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    let stored = state.global_store.get_refresh_token(&user_id).await?;
    
    if stored != Some(payload.refresh_token.clone()) {
        return Err(crate::error::ApiError::Unauthorized("Invalid refresh token".into()));
    }

    let user = state.global_store.get_user(user_id).await?
        .ok_or_else(|| crate::error::ApiError::Unauthorized("User not found".into()))?;

    // Create new tokens
    let access_token = state.auth_service.create_access_token(
        &user.id.to_string(),
        &user.email,
        user.roles.clone(),
        user.permissions.clone(),
        None,
    )?;

    let new_refresh_token = state.auth_service.create_refresh_token(&user.id.to_string())?;

    // Update stored refresh token
    state.global_store.store_refresh_token(&user_id, &new_refresh_token).await?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.auth_service.config.access_token_ttl_seconds,
        user: UserResponse::from(user),
    }))
}

/// Logout
async fn logout(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    state.global_store.revoke_refresh_token(&user_id).await?;
    Ok(())
}

/// Get current user
async fn get_current_user(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<UserResponse>> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    let user = state.global_store.get_user(user_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("User not found".into()))?;

    Ok(Json(UserResponse::from(user)))
}

/// Change password
async fn change_password(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<ChangePasswordRequest>,
) -> ApiResult<()> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    let user = state.global_store.get_user(user_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("User not found".into()))?;

    if !state.auth_service.verify_password(&payload.current_password, &user.password_hash)? {
        return Err(crate::error::ApiError::Unauthorized("Current password incorrect".into()));
    }

    let new_hash = state.auth_service.hash_password(&payload.new_password)?;
    state.global_store.update_password(user_id, new_hash).await?;

    // Revoke all refresh tokens
    state.global_store.revoke_refresh_token(&user_id).await?;

    Ok(())
}

/// List API keys
async fn list_api_keys(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<ApiKeyResponse>>> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    let keys = state.global_store.list_api_keys(user_id).await?;

    Ok(Json(keys.into_iter().map(ApiKeyResponse::from).collect()))
}

/// Create API key
async fn create_api_key(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<CreateApiKeyRequest>,
) -> ApiResult<Json<ApiKeyCreateResponse>> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;

    let api_key = state.auth_service.create_api_key(
        &user_id.to_string(),
        &payload.name,
        payload.scopes,
    )?;

    let key = state.global_store.create_api_key(
        user_id,
        payload.name,
        api_key.clone(),
        payload.scopes,
        payload.expires_at,
    ).await?;

    Ok(Json(ApiKeyCreateResponse {
        api_key, // Only returned once!
        key: ApiKeyResponse::from(key),
    }))
}

/// Revoke API key
async fn revoke_api_key(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<openre_core::ids::ApiKeyId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    let user_id: openre_core::ids::UserId = claims.sub.parse()?;
    state.global_store.revoke_api_key(user_id, id).await?;
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

impl From<openre_storage::User> for UserResponse {
    fn from(u: openre_storage::User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            username: u.username,
            full_name: u.full_name,
            roles: u.roles,
            permissions: u.permissions,
            is_active: u.is_active,
            created_at: u.created_at,
            last_login: u.last_login,
        }
    }
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

impl From<openre_storage::ApiKey> for ApiKeyResponse {
    fn from(k: openre_storage::ApiKey) -> Self {
        Self {
            id: k.id,
            name: k.name,
            prefix: k.prefix,
            scopes: k.scopes,
            expires_at: k.expires_at,
            last_used: k.last_used,
            created_at: k.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyCreateResponse {
    pub api_key: String,
    pub key: ApiKeyResponse,
}

use axum::extract::Path;