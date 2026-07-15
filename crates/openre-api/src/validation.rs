//! Request validation for open-re API

use crate::{ApiError, ApiResult};
use axum::{
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use validator::{Validate, ValidationErrors};
use std::fmt;

/// Validated JSON extractor
pub struct ValidatedJson<T>(pub T);

#[async_trait::async_trait]
impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + Validate + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await
            .map_err(|e| ApiError::BadRequest(format!("Invalid JSON: {}", e)))?;
        
        value.validate()
            .map_err(|e| ApiError::ValidationError(e))?;
        
        Ok(ValidatedJson(value))
    }
}

/// Validation error response
impl IntoResponse for ValidationErrors {
    fn into_response(self) -> Response {
        let errors: Vec<ValidationErrorResponse> = self.field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |error| ValidationErrorResponse {
                    field: field.to_string(),
                    message: error.message.as_ref().map(|m| m.to_string()).unwrap_or_else(|| "Invalid value".to_string()),
                    code: error.code.to_string(),
                })
            })
            .collect();
        
        let body = serde_json::json!({
            "error": "validation_failed",
            "message": "Request validation failed",
            "details": errors,
        });
        
        (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ValidationErrorResponse {
    field: String,
    message: String,
    code: String,
}

/// Common validation rules
pub mod rules {
    use validator::ValidationError;
    
    /// Validate UUID format
    pub fn validate_uuid(uuid: &str) -> Result<(), ValidationError> {
        if uuid::Uuid::parse_str(uuid).is_ok() {
            Ok(())
        } else {
            Err(ValidationError::new("invalid_uuid"))
        }
    }
    
    /// Validate non-empty string
    pub fn validate_not_empty(s: &str) -> Result<(), ValidationError> {
        if !s.trim().is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new("not_empty"))
        }
    }
    
    /// Validate hex string
    pub fn validate_hex(s: &str) -> Result<(), ValidationError> {
        if s.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(ValidationError::new("invalid_hex"))
        }
    }
    
    /// Validate base64 string
    pub fn validate_base64(s: &str) -> Result<(), ValidationError> {
        if base64::decode(s).is_ok() {
            Ok(())
        } else {
            Err(ValidationError::new("invalid_base64"))
        }
    }
    
    /// Validate file size (in bytes)
    pub fn validate_file_size(size: &u64) -> Result<(), ValidationError> {
        const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
        if *size <= MAX_FILE_SIZE {
            Ok(())
        } else {
            Err(ValidationError::new("file_too_large"))
        }
    }
    
    /// Validate priority
    pub fn validate_priority(priority: &str) -> Result<(), ValidationError> {
        matches!(priority.to_lowercase().as_str(), "high" | "default" | "low")
            .then_some(())
            .ok_or_else(|| ValidationError::new("invalid_priority"))
    }
}

/// Pagination parameters
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct PaginationParams {
    #[validate(range(min = 1, max = 1000))]
    pub page: Option<u32>,
    
    #[validate(range(min = 1, max = 100))]
    pub per_page: Option<u32>,
    
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            per_page: Some(50),
            sort_by: None,
            sort_order: None,
        }
    }
}

impl PaginationParams {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1)
    }
    
    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(50).min(100)
    }
    
    pub fn offset(&self) -> u32 {
        (self.page() - 1) * self.per_page()
    }
    
    pub fn limit(&self) -> u32 {
        self.per_page()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    Desc,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Asc
    }
}

/// Filter parameters
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct FilterParams {
    pub search: Option<String>,
    pub status: Option<String>,
    pub project_id: Option<String>,
    pub user_id: Option<String>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
}

/// Date range parameters
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct DateRangeParams {
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
}

/// ID parameter validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct IdParam {
    #[validate(custom(function = "rules::validate_uuid"))]
    pub id: String,
}

/// Multiple ID parameters
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct IdsParam {
    #[validate(length(min = 1, max = 100))]
    pub ids: Vec<String>,
}

/// File upload validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct FileUploadParams {
    #[validate(length(min = 1, max = 255))]
    pub filename: String,
    
    #[validate(custom(function = "rules::validate_file_size"))]
    pub size: u64,
    
    pub content_type: Option<String>,
    pub project_id: Option<String>,
}

/// Analysis request validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct AnalysisRequestParams {
    #[validate(custom(function = "rules::validate_uuid"))]
    pub file_id: String,
    
    pub project_id: Option<String>,
    
    #[validate(length(min = 1, max = 50))]
    pub stages: Option<Vec<String>>,
    
    pub priority: Option<String>,
    
    pub config: Option<serde_json::Value>,
}

/// AI request validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct AiRequestParams {
    #[validate(length(min = 1, max = 4096))]
    pub prompt: String,
    
    pub model: Option<String>,
    
    #[validate(range(min = 0.0, max = 2.0))]
    pub temperature: Option<f32>,
    
    #[validate(range(min = 1, max = 8192))]
    pub max_tokens: Option<u32>,
    
    pub stream: Option<bool>,
    
    pub tools: Option<Vec<String>>,
}

/// Plugin installation validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct PluginInstallParams {
    #[validate(length(min = 1, max = 100))]
    pub plugin_id: String,
    
    pub version: Option<String>,
    
    pub source: PluginSource,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PluginSource {
    Registry { name: String },
    Local { path: String },
    Git { url: String, rev: Option<String> },
}

/// Project creation validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct CreateProjectParams {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    
    #[validate(length(max = 500))]
    pub description: Option<String>,
    
    pub is_public: Option<bool>,
    
    pub settings: Option<serde_json::Value>,
}

/// Project update validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct UpdateProjectParams {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    
    #[validate(length(max = 500))]
    pub description: Option<String>,
    
    pub is_public: Option<bool>,
    
    pub settings: Option<serde_json::Value>,
}

/// User registration validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct RegisterParams {
    #[validate(email)]
    pub email: String,
    
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    
    #[validate(length(min = 1, max = 50))]
    pub username: String,
    
    pub full_name: Option<String>,
}

/// User login validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct LoginParams {
    #[validate(email)]
    pub email: String,
    
    #[validate(length(min = 1))]
    pub password: String,
    
    pub remember_me: Option<bool>,
}

/// Password change validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct ChangePasswordParams {
    #[validate(length(min = 1))]
    pub current_password: String,
    
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

/// API key creation validation
#[derive(Debug, Clone, serde::Deserialize, Validate)]
pub struct CreateApiKeyParams {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    
    #[validate(length(min = 1))]
    pub scopes: Vec<String>,
    
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}