//! Stub AI types (replacing openre-ai)

use thiserror::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AI provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiProvider {
    Local,
    Ollama,
    LlamaCpp,
    Onnx,
    OpenAI,
    Anthropic,
    Vllm,
}

/// AI error
#[derive(Error, Debug)]
pub enum AiError {
    #[error("Provider not available: {0}")]
    ProviderNotAvailable(String),

    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// AI client stub
#[derive(Debug, Clone)]
pub struct AiClient {
    provider: AiProvider,
    model: Option<String>,
}

impl AiClient {
    pub fn new(provider: AiProvider, model: Option<String>) -> anyhow::Result<Self> {
        Ok(Self { provider, model })
    }

    pub async fn chat(
        &self,
        message: &str,
        system: Option<&str>,
        temperature: f32,
        max_tokens: Option<u32>,
    ) -> anyhow::Result<String> {
        // Stub implementation - returns a placeholder response
        let mut response = format!(
            "[AI {} Response] ",
            match self.provider {
                AiProvider::Local => "Local",
                AiProvider::Ollama => "Ollama",
                AiProvider::LlamaCpp => "llama.cpp",
                AiProvider::Onnx => "ONNX",
                AiProvider::OpenAI => "OpenAI",
                AiProvider::Anthropic => "Anthropic",
                AiProvider::Vllm => "vLLM",
            }
        );

        if let Some(sys) = system {
            response.push_str(&format!("[System: {}] ", sys));
        }

        response.push_str(&format!(
            "I would analyze '{}' with temperature {} and max tokens {:?}. This is a stub implementation - AI features require the openre-ai crate to be enabled.",
            message, temperature, max_tokens
        ));

        Ok(response)
    }

    pub async fn analyze(&self, _request: AnalysisRequest) -> anyhow::Result<AnalysisResult> {
        Ok(AnalysisResult {
            summary: "AI analysis not implemented - requires openre-ai crate".to_string(),
            details: vec![],
            recommendations: vec![],
        })
    }

    pub async fn explain(&self, _finding: &crate::intelligence_stubs::Finding, _detail: ExplainDetail, _audience: Audience) -> anyhow::Result<String> {
        Ok("AI explanation not implemented - requires openre-ai crate".to_string())
    }

    pub async fn remediate(&self, _finding: &crate::intelligence_stubs::Finding, _fix_type: FixType, _language: Option<&str>) -> anyhow::Result<String> {
        Ok("AI remediation not implemented - requires openre-ai crate".to_string())
    }

    pub async fn list_providers(&self) -> anyhow::Result<Vec<ProviderInfo>> {
        Ok(vec![
            ProviderInfo {
                name: "OpenAI".to_string(),
                provider_type: "cloud".to_string(),
                available: false,
                models: vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()],
            },
            ProviderInfo {
                name: "Anthropic".to_string(),
                provider_type: "cloud".to_string(),
                available: false,
                models: vec!["claude-3-opus".to_string(), "claude-3-sonnet".to_string()],
            },
            ProviderInfo {
                name: "Ollama".to_string(),
                provider_type: "local".to_string(),
                available: false,
                models: vec!["llama3".to_string(), "codellama".to_string()],
            },
        ])
    }

    pub async fn test_connection(&self, _provider: Option<AiProvider>, _model: Option<&str>) -> anyhow::Result<ConnectionTestResult> {
        Ok(ConnectionTestResult {
            success: false,
            provider: format!("{:?}", self.provider),
            model: self.model.clone().unwrap_or_default(),
            latency_ms: 0,
            error: Some("AI features require openre-ai crate".to_string()),
        })
    }
}

/// Analysis request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub finding: crate::intelligence_stubs::Finding,
    pub analysis_type: AnalysisType,
    pub context: Option<String>,
}

/// Analysis type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum AnalysisType {
    Quick,
    FullAnalysis,
    VulnerabilityAssessment,
    ExploitGeneration,
}

/// Analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub summary: String,
    pub details: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Explain detail level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum ExplainDetail {
    Brief,
    Standard,
    Deep,
}

/// Target audience
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Audience {
    Developer,
    SecurityTeam,
    Management,
    Executive,
}

/// Fix type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum FixType {
    Code,
    Config,
    Architecture,
    Process,
}

/// Provider info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub provider_type: String,
    pub available: bool,
    pub models: Vec<String>,
}

/// Connection test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTestResult {
    pub success: bool,
    pub provider: String,
    pub model: String,
    pub latency_ms: u64,
    pub error: Option<String>,
}