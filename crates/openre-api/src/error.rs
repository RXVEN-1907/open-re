//! Error handling for open-re API

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use openre_core::error::Error as CoreError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validator::ValidationErrors;

/// API error type
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),
    
    #[error("Rate limited: {0}")]
    RateLimited(String),
    
    #[error("Not acceptable: {0}")]
    NotAcceptable(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Validation error: {0}")]
    ValidationError(ValidationErrors),
    
    #[error("Core error: {0}")]
    Core(#[from] CoreError),
}

/// API result type
pub type ApiResult<T> = Result<T, ApiError>;

/// API error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub request_id: Option<String>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            ApiError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", msg.clone()),
            ApiError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg.clone()),
            ApiError::NotAcceptable(msg) => (StatusCode::NOT_ACCEPTABLE, "not_acceptable", msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg.clone()),
            ApiError::NotImplemented(msg) => (StatusCode::NOT_IMPLEMENTED, "not_implemented", msg.clone()),
            ApiError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", msg.clone()),
            ApiError::ValidationError(errors) => {
                let details = serde_json::to_value(errors).ok();
                return (StatusCode::UNPROCESSABLE_ENTITY, Json(ApiErrorResponse {
                    error: "validation_failed".to_string(),
                    message: "Request validation failed".to_string(),
                    details,
                    request_id: None,
                })).into_response();
            }
            ApiError::Core(e) => {
                return ApiError::Internal(e.to_string()).into_response();
            }
        };

        let body = ApiErrorResponse {
            error: error_code.to_string(),
            message,
            details: None,
            request_id: None, // Would be set by middleware
        };

        (status, Json(body)).into_response()
    }
}

/// Result extension for adding request ID
pub trait ApiResultExt<T> {
    fn with_request_id(self, request_id: String) -> ApiResult<T>;
}

impl<T> ApiResultExt<T> for ApiResult<T> {
    fn with_request_id(self, request_id: String) -> ApiResult<T> {
        self.map_err(|e| match e {
            ApiError::BadRequest(msg) => ApiError::BadRequest(msg),
            ApiError::Unauthorized(msg) => ApiError::Unauthorized(msg),
            ApiError::Forbidden(msg) => ApiError::Forbidden(msg),
            ApiError::NotFound(msg) => ApiError::NotFound(msg),
            ApiError::Conflict(msg) => ApiError::Conflict(msg),
            ApiError::PayloadTooLarge(msg) => ApiError::PayloadTooLarge(msg),
            ApiError::RateLimited(msg) => ApiError::RateLimited(msg),
            ApiError::NotAcceptable(msg) => ApiError::NotAcceptable(msg),
            ApiError::Internal(msg) => ApiError::Internal(msg),
            ApiError::NotImplemented(msg) => ApiError::NotImplemented(msg),
            ApiError::ServiceUnavailable(msg) => ApiError::ServiceUnavailable(msg),
            ApiError::ValidationError(e) => ApiError::ValidationError(e),
            ApiError::Core(e) => ApiError::Core(e),
        })
    }
}