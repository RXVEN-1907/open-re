//! CLI error types

use openre_core::Error as CoreError;
use rusqlite::Error as RusqliteError;
use thiserror::Error;
use uuid::Error as UuidError;

/// CLI error
#[derive(Error, Debug)]
pub enum CliError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("TOML error: {0}")]
    TomlError(#[from] toml::ser::Error),

    #[error("TOML parse error: {0}")]
    TomlParseError(#[from] toml::de::Error),

    #[error("Core error: {0}")]
    CoreError(#[from] CoreError),

    #[error("URL encoding error: {0}")]
    UrlEncodingError(String),

    #[error("Offline mode: {0}")]
    OfflineMode(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] RusqliteError),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<String> for CliError {
    fn from(err: String) -> Self {
        CliError::Other(err)
    }
}

impl From<&str> for CliError {
    fn from(err: &str) -> Self {
        CliError::Other(err.to_string())
    }
}

impl From<UuidError> for CliError {
    fn from(err: UuidError) -> Self {
        CliError::InvalidInput(err.to_string())
    }
}

pub type CliResult<T> = Result<T, CliError>;
