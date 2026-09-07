//! CLI error types

use thiserror::Error;
use crate::ai_stubs::AiError;
use crate::analysis_stubs::AnalysisError;
use crate::intelligence_stubs::IntelligenceError;
#[cfg(feature = "scan")]
use openre_scan::ScanError;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[cfg(feature = "ai")]
    #[error("AI error: {0}")]
    Ai(#[from] AiError),

    #[cfg(feature = "analysis")]
    #[error("Analysis error: {0}")]
    Analysis(#[from] AnalysisError),

    #[cfg(feature = "scan")]
    #[error("Scan error: {0}")]
    Scan(#[from] ScanError),

    #[cfg(feature = "analysis")]
    #[error("Intelligence error: {0}")]
    Intelligence(#[from] IntelligenceError),

    #[error("Invalid arguments: {0}")]
    InvalidArgs(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("Dialoguer error: {0}")]
    Dialoguer(#[from] dialoguer::Error),

    #[error("AI features disabled")]
    AiDisabled,

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Other: {0}")]
    Other(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<String> for CliError {
    fn from(s: String) -> Self {
        CliError::Other(s)
    }
}

impl From<&str> for CliError {
    fn from(s: &str) -> Self {
        CliError::Other(s.to_string())
    }
}

impl From<openre_core::Error> for CliError {
    fn from(e: openre_core::Error) -> Self {
        CliError::Config(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CliError>;