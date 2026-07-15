//! AI model providers for open-re

use crate::{CompletionRequest, CompletionResponse, StreamingResponse, ProviderCapabilities, ProviderId, HealthStatus};
use openre_core::error::Result;
use async_trait::async_trait;
use std::collections::HashMap;

/// Model provider trait
#[async_trait]
pub trait ModelProvider: Send + Sync {
    fn id(&self) -> ProviderId;
    fn name(&self) -> &str;
    fn capabilities(&self) -> ProviderCapabilities;
    fn max_context_tokens(&self) -> usize;
    fn supports_streaming(&self) -> bool;
    fn supports_tools(&self) -> bool;

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
    async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse>;
    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>>;
    async fn health_check(&self) -> Result<HealthStatus>;
}

/// Provider registry
pub struct ProviderRegistry {
    providers: HashMap<ProviderId, Box<dyn ModelProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self { providers: HashMap::new() }
    }

    pub fn register(&mut self, provider: Box<dyn ModelProvider>) {
        let id = provider.id();
        self.providers.insert(id, provider);
    }

    pub fn get(&self, id: &ProviderId) -> Option<&dyn ModelProvider> {
        self.providers.get(id).map(|p| p.as_ref())
    }

    pub fn all(&self) -> Vec<&dyn ModelProvider> {
        self.providers.values().map(|p| p.as_ref()).collect()
    }

    pub fn local_only(&self) -> Vec<&dyn ModelProvider> {
        self.providers.values()
            .filter(|p| matches!(p.id().provider_type.as_str(), "onnx" | "llama.cpp"))
            .map(|p| p.as_ref())
            .collect()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderId {
    pub provider_type: String,
    pub model_name: String,
}

impl ProviderId {
    pub fn new(provider_type: &str, model_name: &str) -> Self {
        Self {
            provider_type: provider_type.to_string(),
            model_name: model_name.to_string(),
        }
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.provider_type, self.model_name)
    }
}

/// Provider capabilities
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    pub chat: bool,
    pub completion: bool,
    pub embedding: bool,
    pub tools: bool,
    pub vision: bool,
    pub audio: bool,
    pub json_mode: bool,
    pub structured_output: bool,
}

/// Completion request
#[derive(Debug, Clone, Default)]
pub struct CompletionRequest {
    pub messages: Vec<Message>,
    pub tools: Option<Vec<ToolDefinition>>,
    pub tool_choice: Option<ToolChoice>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub stop: Option<Vec<String>>,
    pub response_format: Option<ResponseFormat>,
    pub stream: bool,
    pub metadata: HashMap<String, String>,
}

/// Completion response
#[derive(Debug, Clone)]
pub struct CompletionResponse {
    pub id: String,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
    pub created: u64,
}

/// Choice in completion response
#[derive(Debug, Clone)]
pub struct Choice {
    pub index: u32,
    pub message: Message,
    pub finish_reason: FinishReason,
}

/// Message in conversation
#[derive(Debug, Clone)]
pub struct Message {
    pub role: MessageRole,
    pub content: Option<String>,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_call_id: Option<String>,
    pub name: Option<String>,
}

impl Message {
    pub fn user(content: String) -> Self {
        Self { role: MessageRole::User, content: Some(content), tool_calls: None, tool_call_id: None, name: None }
    }

    pub fn assistant(content: String) -> Self {
        Self { role: MessageRole::Assistant, content: Some(content), tool_calls: None, tool_call_id: None, name: None }
    }

    pub fn system(content: String) -> Self {
        Self { role: MessageRole::System, content: Some(content), tool_calls: None, tool_call_id: None, name: None }
    }

    pub fn tool_result(tool_call_id: String, content: String) -> Self {
        Self { role: MessageRole::Tool, content: Some(content), tool_calls: None, tool_call_id: Some(tool_call_id), name: None }
    }
}

/// Message role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

/// Tool call
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Tool definition
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub required: Vec<String>,
}

/// Tool choice
#[derive(Debug, Clone)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Specific(String),
}

/// Response format
#[derive(Debug, Clone)]
pub enum ResponseFormat {
    Text,
    JsonObject,
    JsonSchema(serde_json::Value),
}

/// Finish reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Error,
}

/// Usage statistics
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

impl Usage {
    pub fn estimate(request: &CompletionRequest, response: &str) -> Self {
        let prompt_tokens = request.messages.iter()
            .map(|m| m.content.as_ref().map(|c| c.len() / 4).unwrap_or(0))
            .sum::<usize>() as u32;
        let completion_tokens = response.len() / 4;
        Self {
            prompt_tokens,
            completion_tokens: completion_tokens as u32,
            total_tokens: prompt_tokens + completion_tokens as u32,
        }
    }
}

/// Streaming response
pub struct StreamingResponse {
    pub stream: tokio::sync::mpsc::Receiver<StreamChunk>,
}

/// Stream chunk
#[derive(Debug, Clone)]
pub enum StreamChunk {
    Content(String),
    ToolCall(ToolCall),
    Finish(FinishReason),
}

/// Health status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub healthy: bool,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}