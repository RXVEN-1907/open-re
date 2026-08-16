//! Error types for the scanning engine

use openre_core::error::OpenreError;
use thiserror::Error;

/// Result type for scanner operations
pub type ScannerResult<T> = Result<T, ScannerError>;

/// Errors that can occur in the scanning engine
#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Target error: {0}")]
    Target(String),

    #[error("Target validation failed: {0}")]
    TargetValidation(String),

    #[error("Target not found: {0}")]
    TargetNotFound(String),

    #[error("Scan error: {0}")]
    Scan(String),

    #[error("Scan not found: {0}")]
    ScanNotFound(String),

    #[error("Scan already running: {0}")]
    ScanAlreadyRunning(String),

    #[error("Scan not running: {0}")]
    ScanNotRunning(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Plugin load failed: {0}")]
    PluginLoadFailed(String),

    #[error("Plugin execution failed: {0}")]
    PluginExecutionFailed(String),

    #[error("Plugin capability mismatch: {0}")]
    PluginCapabilityMismatch(String),

    #[error("Result aggregation error: {0}")]
    ResultAggregation(String),

    #[error("Finding not found: {0}")]
    FindingNotFound(String),

    #[error("Context error: {0}")]
    Context(String),

    #[error("Storage error: {0}")]
    Storage(#[from] openre_core::error::OpenreError),

    #[error("Queue error: {0}")]
    Queue(#[from] openre_core::error::OpenreError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("HTTP client error: {0}")]
    HttpClient(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Cancellation requested")]
    Cancelled,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("Validation error: {0}")]
    Validation(#[from] validator::ValidationErrors),
}

impl From<OpenreError> for ScannerError {
    fn from(err: OpenreError) -> Self {
        ScannerError::Storage(err)
    }
}
