//! Authentication for open-re API

use crate::{AppState, ApiError, ApiResult};
use axum::{
    extract::{State, Extension},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use tracing::{debug, warn};

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // User ID
    pub email: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub project_id: Option<String>,
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at
    pub jti: String,        // JWT ID
    pub token_type: TokenType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
    ApiKey,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub access_token_ttl_seconds: u64,
    pub refresh_token_ttl_seconds: u64,
    pub api_key_prefix: String,
    pub bcrypt_cost: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change-me-in-production".to_string(),
            jwt_issuer: "open-re".to_string(),
            jwt_audience: "open-re-api".to_string(),
            access_token_ttl_seconds: 15 * 60, // 15 minutes
            refresh_token_ttl_seconds: 7 * 24 * 60 * 60, // 7 days
            api_key_prefix: "ore_".to_string(),
            bcrypt_cost: DEFAULT_COST,
        }
    }
}

/// Authentication service
pub struct AuthService {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl AuthService {
    pub fn new(config: AuthConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[config.jwt_issuer.clone()]);
        validation.set_audience(&[config.jwt_audience.clone()]);
        validation.validate_exp = true;
        
        Self {
            config,
            encoding_key,
            decoding_key,
            validation,
        }
    }

    /// Create access token
    pub fn create_access_token(
        &self,
        user_id: &str,
        email: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
        project_id: Option<String>,
    ) -> ApiResult<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        let exp = now + self.config.access_token_ttl_seconds as usize;
        
        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            roles,
            permissions,
            project_id,
            exp,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            token_type: TokenType::Access,
        };
        
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| ApiError::Internal(format!("Failed to create token: {}", e)))
    }

    /// Create refresh token
    pub fn create_refresh_token(&self, user_id: &str) -> ApiResult<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        let exp = now + self.config.refresh_token_ttl_seconds as usize;
        
        let claims = Claims {
            sub: user_id.to_string(),
            email: String::new(),
            roles: vec![],
            permissions: vec![],
            project_id: None,
            exp,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            token_type: TokenType::Refresh,
        };
        
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| ApiError::Internal(format!("Failed to create refresh token: {}", e)))
    }

    /// Create API key
    pub fn create_api_key(&self, user_id: &str, name: &str, scopes: Vec<String>) -> ApiResult<String> {
        let key_id = Uuid::new_v4().to_string();
        let secret = Uuid::new_v4().to_string().replace("-", "");
        let api_key = format!("{}{}_{}", self.config.api_key_prefix, key_id, secret);
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        let exp = now + 365 * 24 * 60 * 60; // 1 year
        
        let claims = Claims {
            sub: user_id.to_string(),
            email: String::new(),
            roles: vec![],
            permissions: scopes,
            project_id: None,
            exp,
            iat: now,
            jti: key_id,
            token_type: TokenType::ApiKey,
        };
        
        // Store the hashed secret for verification
        // In a real implementation, store in database
        
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| ApiError::Internal(format!("Failed to create API key: {}", e)))
    }

    /// Validate token
    pub fn validate_token(&self, token: &str) -> ApiResult<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| ApiError::Unauthorized(format!("Invalid token: {}", e)))?;
        
        Ok(token_data.claims)
    }

    /// Validate access token
    pub fn validate_access_token(&self, token: &str) -> ApiResult<Claims> {
        let claims = self.validate_token(token)?;
        
        if claims.token_type != TokenType::Access {
            return Err(ApiError::Unauthorized("Invalid token type".into()));
        }
        
        Ok(claims)
    }

    /// Validate refresh token
    pub fn validate_refresh_token(&self, token: &str) -> ApiResult<Claims> {
        let claims = self.validate_token(token)?;
        
        if claims.token_type != TokenType::Refresh {
            return Err(ApiError::Unauthorized("Invalid token type".into()));
        }
        
        Ok(claims)
    }

    /// Validate API key
    pub fn validate_api_key(&self, token: &str) -> ApiResult<Claims> {
        let claims = self.validate_token(token)?;
        
        if claims.token_type != TokenType::ApiKey {
            return Err(ApiError::Unauthorized("Invalid token type".into()));
        }
        
        Ok(claims)
    }

    /// Hash password
    pub fn hash_password(&self, password: &str) -> ApiResult<String> {
        hash(password, self.config.bcrypt_cost)
            .map_err(|e| ApiError::Internal(format!("Failed to hash password: {}", e)))
    }

    /// Verify password
    pub fn verify_password(&self, password: &str, hash: &str) -> ApiResult<bool> {
        verify(password, hash)
            .map_err(|e| ApiError::Internal(format!("Failed to verify password: {}", e)))
    }

    /// Extract token from Authorization header
    pub fn extract_token(headers: &HeaderMap) -> Option<String> {
        headers.get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string())
    }

    /// Extract API key from header
    pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
        headers.get("x-api-key")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    }
}

/// Authentication middleware
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    // Try Bearer token first
    if let Some(token) = AuthService::extract_token(&headers) {
        let claims = state.auth_service.validate_access_token(&token)?;
        request.extensions_mut().insert(claims);
        return Ok(next.run(request).await);
    }
    
    // Try API key
    if let Some(api_key) = AuthService::extract_api_key(&headers) {
        let claims = state.auth_service.validate_api_key(&api_key)?;
        request.extensions_mut().insert(claims);
        return Ok(next.run(request).await);
    }
    
    // Try cookie
    if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("access_token=") {
                    let claims = state.auth_service.validate_access_token(token)?;
                    request.extensions_mut().insert(claims);
                    return Ok(next.run(request).await);
                }
            }
        }
    }
    
    Err(ApiError::Unauthorized("Authentication required".into()))
}

/// Optional authentication middleware (doesn't fail if no auth)
pub async fn optional_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(token) = AuthService::extract_token(&headers) {
        if let Ok(claims) = state.auth_service.validate_access_token(&token) {
            request.extensions_mut().insert(claims);
        }
    } else if let Some(api_key) = AuthService::extract_api_key(&headers) {
        if let Ok(claims) = state.auth_service.validate_api_key(&api_key) {
            request.extensions_mut().insert(claims);
        }
    }
    
    next.run(request).await
}

/// Require specific permission
pub fn require_permission(permission: &str) -> impl Fn(Extension<Claims>) -> ApiResult<()> + Clone {
    let perm = permission.to_string();
    move |Extension(claims): Extension<Claims>| {
        if claims.permissions.contains(&perm) || claims.roles.contains(&"admin".to_string()) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("Permission required: {}", perm)))
        }
    }
}

/// Require specific role
pub fn require_role(role: &str) -> impl Fn(Extension<Claims>) -> ApiResult<()> + Clone {
    let r = role.to_string();
    move |Extension(claims): Extension<Claims>| {
        if claims.roles.contains(&r) || claims.roles.contains(&"admin".to_string()) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("Role required: {}", role)))
        }
    }
}

/// Require project access
pub fn require_project_access() -> impl Fn(Extension<Claims>) -> ApiResult<()> + Clone {
    move |Extension(claims): Extension<Claims>| {
        if claims.project_id.is_some() || claims.roles.contains(&"admin".to_string()) {
            Ok(())
        } else {
            Err(ApiError::Forbidden("Project access required".into()))
        }
    }
}