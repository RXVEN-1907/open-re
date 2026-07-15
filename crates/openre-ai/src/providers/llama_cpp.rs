//! llama.cpp provider for open-re

use crate::providers::*;
use openre_core::error::Result;
use openre_config::LlamaCppConfig;
use llama_cpp_2::{ModelParams, ContextParams, CompletionParams, LlamaModel};
use std::path::Path;
use async_trait::async_trait;

/// llama.cpp provider
pub struct LlamaCppProvider {
    model: LlamaModel,
    config: LlamaCppConfig,
}

impl LlamaCppProvider {
    pub fn new(model_path: &Path, config: LlamaCppConfig) -> Result<Self> {
        let params = ModelParams::default()
            .with_n_gpu_layers(config.gpu_layers)
            .with_n_ctx(config.context_size)
            .with_use_mmap(true)
            .with_use_mlock(config.use_mlock);

        let model = LlamaModel::load_from_file(model_path, params)
            .map_err(|e| openre_core::Error::Internal(e.into()))?;

        Ok(Self { model, config })
    }
}

#[async_trait]
impl ModelProvider for LlamaCppProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("llama.cpp", &self.config.model_name)
    }

    fn name(&self) -> &str {
        &self.config.model_name
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            completion: true,
            embedding: true,
            tools: false,
            vision: false,
            audio: false,
            json_mode: false,
            structured_output: false,
        }
    }

    fn max_context_tokens(&self) -> usize {
        self.config.context_size
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        false
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let mut ctx = self.model.new_context(&ContextParams::default())
            .map_err(|e| openre_core::Error::Internal(e.into()))?;

        // Format prompt using chat template
        let prompt = self.format_chat_template(&request.messages)?;

        let mut output = String::new();
        let mut token_count = 0;

        ctx.completion(&CompletionParams::default()
            .with_prompt(&prompt)
            .with_temperature(request.temperature.unwrap_or(0.7))
            .with_max_tokens(request.max_tokens.unwrap_or(2048) as i32),
            |token| {
                output.push_str(token);
                token_count += 1;
                Ok(true)
            }
        ).map_err(|e| openre_core::Error::Internal(e.into()))?;

        Ok(CompletionResponse {
            id: uuid::Uuid::new_v4().to_string(),
            model: self.config.model_name.clone(),
            choices: vec![Choice {
                index: 0,
                message: Message::assistant(output),
                finish_reason: FinishReason::Stop,
            }],
            usage: Usage {
                prompt_tokens: prompt.len() / 4,
                completion_tokens: token_count,
                total_tokens: (prompt.len() / 4) + token_count,
            },
            created: chrono::Utc::now().timestamp() as u64,
        })
    }

    async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse> {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        
        let model = self.model.clone();
        let config = self.config.clone();
        let request = request.clone();

        tokio::spawn(async move {
            let mut ctx = model.new_context(&ContextParams::default()).unwrap();
            let prompt = Self::format_chat_template_static(&request.messages).unwrap();

            let mut output = String::new();
            let mut token_count = 0;

            ctx.completion(&CompletionParams::default()
                .with_prompt(&prompt)
                .with_temperature(request.temperature.unwrap_or(0.7))
                .with_max_tokens(request.max_tokens.unwrap_or(2048) as i32),
                |token| {
                    output.push_str(token);
                    token_count += 1;
                    let _ = tx.blocking_send(StreamChunk::Content(token.to_string()));
                    Ok(true)
                }
            ).unwrap();

            let _ = tx.blocking_send(StreamChunk::Finish(FinishReason::Stop));
        });

        Ok(StreamingResponse { stream: rx })
    }

    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        let mut ctx = self.model.new_context(&ContextParams::default())
            .map_err(|e| openre_core::Error::Internal(e.into()))?;

        let mut embeddings = Vec::new();
        for text in texts {
            let embedding = ctx.embed(&text)
                .map_err(|e| openre_core::Error::Internal(e.into()))?;
            embeddings.push(embedding);
        }

        Ok(embeddings)
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus { healthy: true, message: None, latency_ms: None })
    }
}

impl LlamaCppProvider {
    fn format_chat_template(&self, messages: &[Message]) -> Result<String> {
        Self::format_chat_template_static(messages)
    }

    fn format_chat_template_static(messages: &[Message]) -> Result<String> {
        let mut prompt = String::new();
        for msg in messages {
            match msg.role {
                MessageRole::System => prompt.push_str(&format!("<|system|>\n{}\n", msg.content.as_deref().unwrap_or(""))),
                MessageRole::User => prompt.push_str(&format!("<|user|>\n{}\n", msg.content.as_deref().unwrap_or(""))),
                MessageRole::Assistant => prompt.push_str(&format!("<|assistant|>\n{}\n", msg.content.as_deref().unwrap_or(""))),
                MessageRole::Tool => prompt.push_str(&format!("<|tool|>\n{}\n", msg.content.as_deref().unwrap_or(""))),
            }
        }
        prompt.push_str("<|assistant|>\n");
        Ok(prompt)
    }
}