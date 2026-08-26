//! Error types for the AI Security Analyst

use openre_core::ids::{FindingId, ScanId};
use thiserror::Error;

/// Result type alias for AI analyst operations
pub type AiResult<T> = Result<T, AiAnalystError>;

/// Errors that can occur in the AI Security Analyst
#[derive(Debug, Error)]
pub enum AiAnalystError {
    #[error("AI provider not configured")]
    ProviderNotConfigured,

    #[error("Finding not found: {0}")]
    FindingNotFound(FindingId),

    #[error("Scan not found: {0}")]
    ScanNotFound(ScanId),

    #[error("Context too large for model window")]
    ContextTooLarge,

    #[error("Analysis cache error: {0}")]
    CacheError(String),

    #[error("Safety violation: {0}")]
    SafetyViolation(String),

    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<openre_core::Error> for AiAnalystError {
    fn from(error: openre_core::Error) -> Self {
        match error {
            openre_core::Error::NotFound(msg) => AiAnalystError::Internal(msg),
            _ => AiAnalystError::Internal(error.to_string()),
        }
    }
}
