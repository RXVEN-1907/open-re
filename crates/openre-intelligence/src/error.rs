//! Error types for the intelligence module

use thiserror::Error;
use openre_core::error::OpenreError;

/// Intelligence module error types
#[derive(Error, Debug)]
pub enum IntelligenceError {
    #[error("Core error: {0}")]
    Core(#[from] OpenreError),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Cache serialization error: {0}")]
    CacheSerializationError(String),

    #[error("Workflow feature disabled: {0}")]
    WorkflowFeatureDisabled(String),

    #[error("Ignore rule limit exceeded: maximum {0} rules allowed")]
    IgnoreRuleLimitExceeded(usize),

    #[error("Invalid ignore pattern: {0}")]
    InvalidIgnorePattern(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl IntelligenceError {
    /// Check if this is a transient error that might succeed on retry
    pub fn is_transient(&self) -> bool {
        matches!(self,
            IntelligenceError::Network(_) |
            IntelligenceError::Provider(_) |
            IntelligenceError::Cache(_)
        )
    }

    /// Check if this error should be logged as a warning rather than an error
    pub fn is_warning(&self) -> bool {
        matches!(self,
            IntelligenceError::NotFound(_) |
            IntelligenceError::WorkflowFeatureDisabled(_)
        )
    }
}