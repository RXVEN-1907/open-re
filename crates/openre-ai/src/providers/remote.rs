//! Remote AI providers (OpenAI, vLLM, Anthropic) for open-re

use crate::providers::*;
use openre_core::error::Result;
use openre_config::RemoteConfig;
use reqwest::Client;
use std::sync::Arc;
use async_trait::async_trait;
use tokio_stream::StreamExt;

/// Remote provider (OpenAI-compatible API)
pub struct RemoteProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    config: RemoteConfig,
}

impl RemoteProvider {
    pub fn openai(api_key: String) -> Self {
        Self {
            client: Client::new(),
            base_url: "https://api.openai.com/v1".to_string(),
            api_key: Some(api_key),
            config: RemoteConfig::default(),
        }
    }

    pub fn vllm(base_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url,
            api_key,
            config: RemoteConfig::default(),
        }
    }

    pub fn anthropic(api_key: String) -> Self {
        Self {
            client: Client::new(),
            base_url: "https://api.anthropic.com/v1".to_string(),
            api_key: Some(api_key),
            config: RemoteConfig::default(),
        }
    }

    pub fn custom(base_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url,
            api_key,
            config: RemoteConfig::default(),
        }
    }
}

#[async_trait]
impl ModelProvider for RemoteProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("remote", &self.base_url)
    }

    fn name(&self) -> &str {
        "Remote Provider"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            completion: true,
            embedding: true,
            tools: true,
            vision: self.config.supports_vision,
            audio: false,
            json_mode: true,
            structured_output: true,
        }
    }

    fn max_context_tokens(&self) -> usize {
        self.config.max_context_tokens
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let url = format!("{}/chat/completions", self.base_url);
        let mut req = self.client.post(&url).json(&request);

        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }

        let response = req.send().await?;
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(openre_core::Error::Internal(format!("Remote API error: {}", error).into()));
        }

        response.json().await.map_err(|e| openre_core::Error::Internal(e.into()))
    }

    async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse> {
        let mut req = request.clone();
        req.stream = true;

        let url = format!("{}/chat/completions", self.base_url);
        let mut request_builder = self.client.post(&url).json(&req);

        if let Some(key) = &self.api_key {
            request_builder = request_builder.bearer_auth(key);
        }

        let response = request_builder.send().await?;
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(openre_core::Error::Internal(format!("Remote API error: {}", error).into()));
        }

        let stream = response.bytes_stream()
            .map(|chunk| parse_sse_chunk(chunk))
            .filter_map(|chunk| async move { chunk.ok() });

        let (tx, rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            let mut stream = Box::pin(stream);
            while let Some(chunk) = stream.next().await {
                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
        });

        Ok(StreamingResponse { stream: rx })
    }

    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        let url = format!("{}/embeddings", self.base_url);
        let mut req = self.client.post(&url).json(&serde_json::json!({
            "input": texts,
            "model": self.config.embedding_model
        }));

        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }

        let response = req.send().await?;
        if !response.status().is_success() {
            let error = response.text().await?;
            return Err(openre_core::Error::Internal(format!("Embedding error: {}", error).into()));
        }

        let result: serde_json::Value = response.json().await?;
        let embeddings = result["data"].as_array()
            .ok_or_else(|| openre_core::Error::Internal("Invalid embedding response".into()))?
            .iter()
            .map(|d| d["embedding"].as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap() as f32)
                .collect())
            .collect();

        Ok(embeddings)
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let url = format!("{}/models", self.base_url);
        let mut req = self.client.get(&url);

        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }

        let start = std::time::Instant::now();
        let response = req.send().await;
        let latency = start.elapsed().as_millis() as u64;

        match response {
            Ok(resp) if resp.status().is_success() => Ok(HealthStatus {
                healthy: true,
                message: Some("OK".to_string()),
                latency_ms: Some(latency),
            }),
            Ok(resp) => Ok(HealthStatus {
                healthy: false,
                message: Some(format!("HTTP {}", resp.status())),
                latency_ms: Some(latency),
            }),
            Err(e) => Ok(HealthStatus {
                healthy: false,
                message: Some(e.to_string()),
                latency_ms: Some(latency),
            }),
        }
    }
}

/// Parse SSE chunk from remote API
fn parse_sse_chunk(chunk: Result<bytes::Bytes, reqwest::Error>) -> Option<StreamChunk> {
    let chunk = chunk.ok()?;
    let text = String::from_utf8_lossy(&chunk);
    
    for line in text.lines() {
        if line.starts_with("data: ") {
            let data = &line[6..];
            if data == "[DONE]" {
                return Some(StreamChunk::Finish(FinishReason::Stop));
            }
            
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(choices) = json["choices"].as_array() {
                    if let Some(choice) = choices.first() {
                        if let Some(delta) = choice["delta"].as_object() {
                            if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
                                return Some(StreamChunk::Content(content.to_string()));
                            }
                            if let Some(tool_calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                                if let Some(tc) = tool_calls.first() {
                                    return Some(StreamChunk::ToolCall(ToolCall {
                                        id: tc["id"].as_str().unwrap_or("").to_string(),
                                        name: tc["function"]["name"].as_str().unwrap_or("").to_string(),
                                        arguments: tc["function"]["arguments"].clone(),
                                    }));
                                }
                            }
                        }
                        if let Some(finish_reason) = choice["finish_reason"].as_str() {
                            return Some(StreamChunk::Finish(match finish_reason {
                                "stop" => FinishReason::Stop,
                                "length" => FinishReason::Length,
                                "tool_calls" => FinishReason::ToolCalls,
                                _ => FinishReason::Stop,
                            }));
                        }
                    }
                }
            }
        }
    }
    None
}