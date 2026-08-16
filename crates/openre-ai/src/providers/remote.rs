//! Remote AI providers (OpenAI, vLLM, Anthropic) for open-re

use crate::providers::*;
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use openre_config::RemoteConfig;
use reqwest::Client;
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
            config: RemoteConfig {
                base_url: "https://api.openai.com/v1".to_string(),
                api_key: None,
                model: "gpt-4".to_string(),
                timeout_secs: 30,
                max_retries: 3,
                supports_vision: true,
                max_context_tokens: 128000,
                embedding_model: "text-embedding-3-small".to_string(),
            },
        }
    }

    pub fn vllm(base_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.clone(),
            api_key,
            config: RemoteConfig {
                base_url,
                api_key: None,
                model: "default".to_string(),
                timeout_secs: 60,
                max_retries: 3,
                supports_vision: false,
                max_context_tokens: 4096,
                embedding_model: "default".to_string(),
            },
        }
    }

    pub fn anthropic(api_key: String) -> Self {
        Self {
            client: Client::new(),
            base_url: "https://api.anthropic.com/v1".to_string(),
            api_key: Some(api_key),
            config: RemoteConfig {
                base_url: "https://api.anthropic.com/v1".to_string(),
                api_key: None,
                model: "claude-3-opus-20240229".to_string(),
                timeout_secs: 60,
                max_retries: 3,
                supports_vision: true,
                max_context_tokens: 200000,
                embedding_model: "".to_string(),
            },
        }
    }

    pub fn custom(base_url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.clone(),
            api_key,
            config: RemoteConfig {
                base_url,
                api_key: None,
                model: "custom".to_string(),
                timeout_secs: 30,
                max_retries: 3,
                supports_vision: false,
                max_context_tokens: 4096,
                embedding_model: "custom".to_string(),
            },
        }
    }

    pub fn from_config(config: RemoteConfig) -> Self {
        Self {
            client: Client::new(),
            base_url: config.base_url.clone(),
            api_key: config.api_key.clone(),
            config,
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

        let response = req.send().await.context("Failed to send request")?;
        if !response.status().is_success() {
            let error = response
                .text()
                .await
                .context("Failed to read error response")?;
            return Err(openre_core::Error::Internal(anyhow::anyhow!(
                "Remote API error: {}",
                error
            )));
        }

        response
            .json()
            .await
            .context("Failed to parse response")
            .map_err(openre_core::Error::Internal)
    }

    async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse> {
        let mut req = request.clone();
        req.stream = true;

        let url = format!("{}/chat/completions", self.base_url);
        let mut request_builder = self.client.post(&url).json(&req);

        if let Some(key) = &self.api_key {
            request_builder = request_builder.bearer_auth(key);
        }

        let response = request_builder
            .send()
            .await
            .context("Failed to send streaming request")?;
        if !response.status().is_success() {
            let error = response
                .text()
                .await
                .context("Failed to read error response")?;
            return Err(openre_core::Error::Internal(anyhow::anyhow!(
                "Remote API error: {}",
                error
            )));
        }

        let stream = response.bytes_stream().filter_map(|result| {
            let chunk = result.ok()?;
            parse_sse_chunk(Ok(chunk))
        });

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

        let response = req
            .send()
            .await
            .context("Failed to send embedding request")?;
        if !response.status().is_success() {
            let error = response
                .text()
                .await
                .context("Failed to read error response")?;
            return Err(openre_core::Error::Internal(anyhow::anyhow!(
                "Embedding error: {}",
                error
            )));
        }

        let result: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse embedding response")?;
        let embeddings = result["data"]
            .as_array()
            .ok_or_else(|| {
                openre_core::Error::Internal(anyhow::anyhow!("Invalid embedding response"))
            })?
            .iter()
            .map(|d| {
                d["embedding"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_f64().unwrap() as f32)
                    .collect()
            })
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
fn parse_sse_chunk(chunk: std::result::Result<Bytes, reqwest::Error>) -> Option<StreamChunk> {
    let chunk = chunk.ok()?;
    let text = String::from_utf8_lossy(&chunk);

    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
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
                            if let Some(tool_calls) =
                                delta.get("tool_calls").and_then(|v| v.as_array())
                            {
                                if let Some(tc) = tool_calls.first() {
                                    return Some(StreamChunk::ToolCall(ToolCall {
                                        id: tc["id"].as_str().unwrap_or("").to_string(),
                                        name: tc["function"]["name"]
                                            .as_str()
                                            .unwrap_or("")
                                            .to_string(),
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
