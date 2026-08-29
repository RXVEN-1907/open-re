//! Auth routes

use crate::{ApiResult, AppState, ValidatedJson};
use axum::{
    extract::{Extension, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use openre_core::ids::UserId;
use openre_core::traits::User;
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
    // Find user by email
    let user = state
        .global_store
        .get_user_by_email(&payload.email)
        .await?
        .ok_or_else(|| crate::error::ApiError::Unauthorized("Invalid credentials".into()))?;

    // Verify password
    let password_hash = user
        .password_hash
        .ok_or_else(|| crate::error::ApiError::Unauthorized("Invalid credentials".into()))?;

    if !state.auth_service.verify_password(&payload.password, &password_hash)? {
        return Err(crate::error::ApiError::Unauthorized("Invalid credentials".into()));
    }

    // Update last login
    state.global_store.update_user_last_login(user.id).await?;

    // Create tokens
    let access_token = state.auth_service.create_access_token(
        &user.id.to_string(),
        &user.email,
        vec![user.role.clone()],
        vec![],
        None,
    )?;

    let refresh_token = state.auth_service.create_refresh_token(&user.id.to_string())?;

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        username: user.username,
        full_name: user.full_name,
        roles: vec![user.role],
        permissions: vec![],
        is_active: user.status == "active",
        created_at: user.created_at,
        last_login: user.last_login_at,
    };

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.auth_service.jwt_config().access_token_ttl_seconds,
        user: user_response,
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
    // Hash password
    let password_hash = state.auth_service.hash_password(&payload.password)?;

    // Create user - let database handle unique constraints
    let user_id = UserId::new();
    let now = chrono::Utc::now();
    let user = User {
        id: user_id,
        email: payload.email.clone(),
        username: payload.username.clone(),
        password_hash: Some(password_hash),
        full_name: payload.full_name.clone(),
        avatar_url: None,
        role: "user".to_string(),
        status: "active".to_string(),
        email_verified: false,
        last_login_at: None,
        created_at: now,
        updated_at: now,
    };

    // Handle unique constraint violations
    if let Err(e) = state.global_store.create_user(&user).await {
        let err_str = e.to_string();
        if err_str.contains("duplicate key") || err_str.contains("unique constraint") {
            if err_str.contains("email") {
                return Err(crate::error::ApiError::Conflict("Email already registered".into()));
            } else if err_str.contains("username") {
                return Err(crate::error::ApiError::Conflict("Username already taken".into()));
            }
            return Err(crate::error::ApiError::Conflict("User already exists".into()));
        }
        return Err(crate::error::ApiError::Internal(e.to_string()));
    }

    // Create tokens
    let access_token = state.auth_service.create_access_token(
        &user_id.to_string(),
        &user.email,
        vec![user.role.clone()],
        vec![],
        None,
    )?;

    let refresh_token = state.auth_service.create_refresh_token(&user_id.to_string())?;

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        username: user.username,
        full_name: user.full_name,
        roles: vec![user.role],
        permissions: vec![],
        is_active: user.status == "active",
        created_at: user.created_at,
        last_login: user.last_login_at,
    };

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.auth_service.jwt_config().access_token_ttl_seconds,
        user: user_response,
    }))
}

/// Refresh token
async fn refresh_token(
    State(state): State<std::sync::Arc<AppState>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let claims = state.auth_service.validate_refresh_token(&payload.refresh_token)?;
    let user_id: UserId = claims.sub.parse()?;

    let user = state
        .global_store
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| crate::error::ApiError::Unauthorized("User not found".into()))?;

    let access_token = state.auth_service.create_access_token(
        &user_id.to_string(),
        &user.email,
        vec![user.role.clone()],
        vec![],
        None,
    )?;

    let new_refresh_token = state.auth_service.create_refresh_token(&user_id.to_string())?;

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        username: user.username,
        full_name: user.full_name,
        roles: vec![user.role],
        permissions: vec![],
        is_active: user.status == "active",
        created_at: user.created_at,
        last_login: user.last_login_at,
    };

    Ok(Json(LoginResponse {
        access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.auth_service.jwt_config().access_token_ttl_seconds,
        user: user_response,
    }))
}

/// Logout
async fn logout(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    // In a real implementation, we'd revoke the refresh token
    // For now, just return success
    let _ = (state, claims);
    Ok(())
}

/// Get current user
async fn get_current_user(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<UserResponse>> {
    let user_id: UserId = claims.sub.parse()?;
    let user = state
        .global_store
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| crate::error::ApiError::NotFound("User not found".into()))?;

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        username: user.username,
        full_name: user.full_name,
        roles: vec![user.role],
        permissions: vec![],
        is_active: user.status == "active",
        created_at: user.created_at,
        last_login: user.last_login_at,
    };

    Ok(Json(user_response))
}

/// Change password
async fn change_password(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<ChangePasswordRequest>,
) -> ApiResult<()> {
    let user_id: UserId = claims.sub.parse()?;

    let user = state
        .global_store
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| crate::error::ApiError::NotFound("User not found".into()))?;

    let password_hash = user
        .password_hash
        .ok_or_else(|| crate::error::ApiError::Internal("User has no password set".into()))?;

    if !state.auth_service.verify_password(&payload.current_password, &password_hash)? {
        return Err(crate::error::ApiError::Unauthorized("Current password is incorrect".into()));
    }

    let new_password_hash = state.auth_service.hash_password(&payload.new_password)?;
    state.global_store.update_user_password(user_id, &new_password_hash).await?;

    Ok(())
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
