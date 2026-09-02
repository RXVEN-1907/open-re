//! CLI configuration

use crate::{CliError, OutputFormat};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// CLI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    pub api_key: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub output_format: OutputFormat,
    pub verbose: bool,

    // Profile support
    pub profiles: HashMap<String, ProfileConfig>,
    pub current_profile: Option<String>,

    #[serde(skip)]
    path: Option<PathBuf>,
}

/// Profile-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub server_url: Option<String>,
    pub api_key: Option<String>,
    pub output_format: Option<OutputFormat>,
    pub verbose: Option<bool>,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self { server_url: None, api_key: None, output_format: None, verbose: None }
    }
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
            profiles: HashMap::new(),
            current_profile: None,
            path: None,
        }
    }
}

impl CliConfig {
    /// Load configuration from file
    pub fn load(path: Option<&Path>) -> Result<Self, CliError> {
        let config_path =
            if let Some(path) = path { path.to_path_buf() } else { Self::default_config_path()? };

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

    /// Save configuration to a specific path
    pub fn save_to(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
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
            "output_format" => {
                self.output_format = value.parse().map_err(|e: String| CliError::InvalidInput(e))?
            }
            "verbose" => {
                self.verbose = value
                    .parse()
                    .map_err(|_| CliError::InvalidInput(format!("Invalid boolean: {}", value)))?
            }
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

    // Profile methods

    /// List all profiles
    pub fn list_profiles(&self) -> Result<Vec<String>, CliError> {
        Ok(self.profiles.keys().cloned().collect())
    }

    /// Get current profile name
    pub fn current_profile(&self) -> Result<Option<String>, CliError> {
        Ok(self.current_profile.clone())
    }

    /// Switch to a profile
    pub fn use_profile(&mut self, name: &str) -> Result<(), CliError> {
        if !self.profiles.contains_key(name) {
            return Err(CliError::InvalidInput(format!("Profile '{}' does not exist", name)));
        }
        self.current_profile = Some(name.to_string());
        self.apply_profile(name);
        Ok(())
    }

    /// Create a new profile
    pub fn create_profile(&mut self, name: &str, base: Option<&str>) -> Result<(), CliError> {
        if self.profiles.contains_key(name) {
            return Err(CliError::InvalidInput(format!("Profile '{}' already exists", name)));
        }

        let mut profile = ProfileConfig::default();
        if let Some(base_name) = base {
            if let Some(base_profile) = self.profiles.get(base_name) {
                profile = base_profile.clone();
            }
        }

        self.profiles.insert(name.to_string(), profile);
        Ok(())
    }

    /// Delete a profile
    pub fn delete_profile(&mut self, name: &str) -> Result<(), CliError> {
        if name == "default" {
            return Err(CliError::InvalidInput("Cannot delete default profile".into()));
        }
        if self.current_profile.as_deref() == Some(name) {
            return Err(CliError::InvalidInput(
                "Cannot delete active profile. Switch first.".into(),
            ));
        }
        self.profiles.remove(name);
        Ok(())
    }

    /// Reload configuration from file
    pub fn reload(&mut self) -> Result<(), CliError> {
        if let Some(path) = self.path.clone() {
            let reloaded = Self::load(Some(&path))?;
            *self = reloaded;
        }
        Ok(())
    }

    /// Apply profile settings to current config
    fn apply_profile(&mut self, name: &str) {
        if let Some(profile) = self.profiles.get(name) {
            if let Some(url) = &profile.server_url {
                self.server_url = url.clone();
            }
            if let Some(key) = &profile.api_key {
                self.api_key = Some(key.clone());
            }
            if let Some(fmt) = profile.output_format {
                self.output_format = fmt;
            }
            if let Some(verbose) = profile.verbose {
                self.verbose = verbose;
            }
        }
    }

    /// Get access token
    pub fn get_access_token(&self) -> Result<String, CliError> {
        self.access_token.clone().ok_or(CliError::NotAuthenticated)
    }

    /// Get refresh token
    pub fn get_refresh_token(&self) -> Result<String, CliError> {
        self.refresh_token.clone().ok_or(CliError::NotAuthenticated)
    }
}
