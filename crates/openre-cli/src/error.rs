//! CLI error types

use thiserror::Error;

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
    
    #[error("URL encoding error: {0}")]
    UrlEncodingError(#[from] urlencoding::Error),
}

pub type CliResult<T> = Result<T, CliError>;