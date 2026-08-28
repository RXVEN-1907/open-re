//! Core error types for open-re

use thiserror::Error;

/// Result type alias for open-re operations
pub type OpenreResult<T> = std::result::Result<T, Error>;

/// Main error type for open-re
#[derive(Debug, Error)]
pub enum Error {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File watcher error: {0}")]
    Notify(#[from] notify::Error),

    #[error("Tracing error: {0}")]
    Tracing(#[from] opentelemetry::trace::TraceError),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Cancelled")]
    Cancelled,

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("SQLite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
}

impl Error {
    /// Get the error code for this error
    pub fn code(&self) -> &'static str {
        match self {
            Error::NotFound(_) => "NOT_FOUND",
            Error::Validation(_) => "VALIDATION_ERROR",
            Error::Config(_) => "CONFIG_ERROR",
            Error::InvalidInput(_) => "INVALID_INPUT",
            Error::Database(_) => "DATABASE_ERROR",
            Error::Serialization(_) => "SERIALIZATION_ERROR",
            Error::Toml(_) => "TOML_ERROR",
            Error::Io(_) => "IO_ERROR",
            Error::Notify(_) => "NOTIFY_ERROR",
            Error::Tracing(_) => "TRACING_ERROR",
            Error::Redis(_) => "REDIS_ERROR",
            Error::Internal(_) => "INTERNAL_ERROR",
            Error::Cancelled => "CANCELLED",
            Error::Timeout(_) => "TIMEOUT",
            Error::ConnectionError(_) => "CONNECTION_ERROR",
            Error::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
            Error::Unauthorized(_) => "UNAUTHORIZED",
            Error::Forbidden(_) => "FORBIDDEN",
            Error::Conflict(_) => "CONFLICT",
            Error::RateLimited { .. } => "RATE_LIMITED",
            Error::BadRequest(_) => "BAD_REQUEST",
            Error::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            Error::NotImplemented(_) => "NOT_IMPLEMENTED",
            Error::Rusqlite(_) => "SQLITE_ERROR",
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Database(_)
                | Error::Timeout(_)
                | Error::ServiceUnavailable(_)
                | Error::Notify(_)
                | Error::Tracing(_)
                | Error::Redis(_)
                | Error::Rusqlite(_)
                | Error::ConnectionError(_)
                | Error::ResourceExhausted(_)
        )
    }

    /// Check if this error is user-facing (safe to show to users)
    pub fn is_user_facing(&self) -> bool {
        !matches!(
            self,
            Error::Internal(_)
                | Error::Database(_)
                | Error::Serialization(_)
                | Error::Io(_)
                | Error::Notify(_)
                | Error::Tracing(_)
                | Error::Redis(_)
                | Error::Rusqlite(_)
                | Error::ConnectionError(_)
                | Error::ResourceExhausted(_)
        )
    }
}

/// Error context for structured error reporting
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErrorContext {
    pub code: &'static str,
    pub retryable: bool,
    pub user_facing: bool,
}

impl Error {
    pub fn context(&self) -> ErrorContext {
        ErrorContext {
            code: self.code(),
            retryable: self.is_retryable(),
            user_facing: self.is_user_facing(),
        }
    }
}
