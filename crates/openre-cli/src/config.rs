//! CLI configuration

use crate::{CliError, OutputFormat};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;

/// CLI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    pub api_key: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub output_format: OutputFormat,
    pub verbose: bool,
    
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8080".to_string(),
            api_key: None,
            access_token: None,
            refresh_token: None,
            output_format: OutputFormat::Table,
            verbose: false,
            path: None,
        }
    }
}

impl CliConfig {
    /// Load configuration from file
    pub fn load(path: Option<&Path>) -> Result<Self, CliError> {
        let config_path = if let Some(path) = path {
            path.to_path_buf()
        } else {
            Self::default_config_path()?
        };
        
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let mut config: Self = toml::from_str(&content)?;
            config.path = Some(config_path);
            Ok(config)
        } else {
            let mut config = Self::default();
            config.path = Some(config_path);
            Ok(config)
        }
    }
    
    /// Get default config path
    fn default_config_path() -> Result<PathBuf, CliError> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| CliError::ConfigError("Could not find config directory".into()))?;
        
        Ok(config_dir.join("openre").join("config.toml"))
    }
    
    /// Save configuration to file
    pub fn save(&self) -> Result<(), CliError> {
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            let content = toml::to_string_pretty(self)?;
            fs::write(path, content)?;
        }
        Ok(())
    }
    
    /// Save tokens
    pub fn save_tokens(&mut self, access_token: &str, refresh_token: &str) -> Result<(), CliError> {
        self.access_token = Some(access_token.to_string());
        self.refresh_token = Some(refresh_token.to_string());
        self.save()
    }
    
    /// Clear tokens
    pub fn clear_tokens(&mut self) -> Result<(), CliError> {
        self.access_token = None;
        self.refresh_token = None;
        self.save()
    }
    
    /// Get token for authentication
    pub fn get_token(&self) -> Result<String, CliError> {
        if let Some(token) = &self.access_token {
            Ok(token.clone())
        } else if let Some(key) = &self.api_key {
            Ok(key.clone())
        } else {
            Err(CliError::NotAuthenticated)
        }
    }
    
    /// Set a configuration value
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), CliError> {
        match key {
            "server_url" => self.server_url = value.to_string(),
            "api_key" => self.api_key = Some(value.to_string()),
            "output_format" => self.output_format = value.parse()?,
            "verbose" => self.verbose = value.parse()?,
            _ => return Err(CliError::InvalidInput(format!("Unknown config key: {}", key))),
        }
        Ok(())
    }
    
    /// Get a configuration value
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "server_url" => Some(self.server_url.clone()),
            "api_key" => self.api_key.clone(),
            "output_format" => Some(self.output_format.to_string()),
            "verbose" => Some(self.verbose.to_string()),
            _ => None,
        }
    }
    
    /// Reset to defaults
    pub fn reset(&mut self) -> Result<(), CliError> {
        *self = Self::default();
        self.path = Self::default_config_path().ok();
        Ok(())
    }
    
    /// Get config file path
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}