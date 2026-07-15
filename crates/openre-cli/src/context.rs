//! CLI context

use crate::{CliConfig, CliError, OutputFormat};
use reqwest::Client;
use std::sync::Arc;

/// CLI execution context
pub struct Context {
    pub config: CliConfig,
    pub client: Client,
    pub server_url: String,
    pub api_key: Option<String>,
    pub output_format: OutputFormat,
    pub verbose: bool,
}

impl Context {
    /// Create a new context
    pub fn new(config: CliConfig, client: Client, server_url: String, api_key: Option<String>, output_format: OutputFormat, verbose: bool) -> Self {
        Self {
            config,
            client,
            server_url,
            api_key,
            output_format,
            verbose,
        }
    }
    
    /// Get authentication token
    pub fn get_token(&self) -> Result<String, CliError> {
        self.config.get_token()
    }
    
    /// Make GET request
    pub async fn get(&self, path: &str) -> Result<reqwest::Response, CliError> {
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }
        
        Ok(response)
    }
    
    /// Make POST request
    pub async fn post(&self, path: &str, body: &serde_json::Value) -> Result<reqwest::Response, CliError> {
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }
        
        Ok(response)
    }
    
    /// Make PUT request
    pub async fn put(&self, path: &str, body: &serde_json::Value) -> Result<reqwest::Response, CliError> {
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;
        
        let response = self.client
            .put(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(body)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }
        
        Ok(response)
    }
    
    /// Make DELETE request
    pub async fn delete(&self, path: &str) -> Result<reqwest::Response, CliError> {
        let url = format!("{}{}", self.server_url, path);
        let token = self.get_token()?;
        
        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(CliError::ApiError(error));
        }
        
        Ok(response)
    }
}