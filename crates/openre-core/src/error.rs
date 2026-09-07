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

    #[error("Tracing error: {0}")]
    Tracing(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Cancelled")]
    Cancelled,

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),
}