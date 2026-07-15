//! ONNX Runtime provider for open-re

use crate::providers::*;
use openre_core::error::Result;
use openre_config::OnnxConfig;
use ort::{Session, GraphOptimizationLevel};
use tokenizers::Tokenizer;
use std::path::Path;
use async_trait::async_trait;

/// ONNX Runtime provider
pub struct OnnxProvider {
    session: Session,
    tokenizer: Tokenizer,
    config: OnnxConfig,
}

impl OnnxProvider {
    pub fn new(model_path: &Path, config: OnnxConfig) -> Result<Self> {
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(config.threads)?
            .with_inter_threads(config.threads)?
            .commit_from_file(model_path)?;

        let tokenizer = Tokenizer::from_file(&config.tokenizer_path)
            .map_err(|e| openre_core::Error::Internal(e.into()))?;

        Ok(Self { session, tokenizer, config })
    }
}

#[async_trait]
impl ModelProvider for OnnxProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("onnx", &self.config.model_name)
    }

    fn name(&self) -> &str {
        &self.config.model_name
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            chat: true,
            completion: true,
            embedding: self.config.supports_embedding,
            tools: false,
            vision: false,
            audio: false,
            json_mode: false,
            structured_output: false,
        }
    }

    fn max_context_tokens(&self) -> usize {
        self.config.max_context
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        false
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        // Tokenize input
        let input_text = request.messages.iter()
            .filter_map(|m| m.content.as_ref())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        let encoding = self.tokenizer.encode(input_text, true)
            .map_err(|e| openre_core::Error::Internal(e.into()))?;
        let input_ids = encoding.get_ids();

        // Run inference
        let inputs = ort::inputs!["input_ids" => input_ids]?;
        let outputs = self.session.run(inputs)?;

        // Get logits and sample next token
        let logits = outputs["logits"].try_extract_tensor::<f32>()?;
        let next_token = self.sample_token(logits, request.temperature.unwrap_or(0.7))?;

        // Decode
        let text = self.tokenizer.decode(&[next_token], false)
            .map_err(|e| openre_core::Error::Internal(e.into()))?;

        Ok(CompletionResponse {
            id: uuid::Uuid::new_v4().to_string(),
            model: self.config.model_name.clone(),
            choices: vec![Choice {
                index: 0,
                message: Message::assistant(text),
                finish_reason: FinishReason::Stop,
            }],
            usage: Usage::estimate(&request, &text),
            created: chrono::Utc::now().timestamp() as u64,
        })
    }

    async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse> {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        
        let session = self.session.clone();
        let tokenizer = self.tokenizer.clone();
        let config = self.config.clone();
        let request = request.clone();

        tokio::spawn(async move {
            let mut generated = String::new();
            let input_text = request.messages.iter()
                .filter_map(|m| m.content.as_ref())
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");

            let mut encoding = tokenizer.encode(input_text, true).unwrap();
            let mut input_ids = encoding.get_ids().to_vec();

            for _ in 0..request.max_tokens.unwrap_or(2048) {
                let inputs = ort::inputs!["input_ids" => input_ids.clone()].unwrap();
                let outputs = session.run(inputs).unwrap();
                let logits = outputs["logits"].try_extract_tensor::<f32>().unwrap();
                let next_token = Self::sample_token_static(logits, request.temperature.unwrap_or(0.7)).unwrap();

                let text = tokenizer.decode(&[next_token], false).unwrap();
                generated.push_str(&text);

                let _ = tx.send(StreamChunk::Content(text)).await;

                if Self::is_stop_token_static(next_token, &request.stop) {
                    break;
                }

                input_ids.push(next_token);
            }

            let _ = tx.send(StreamChunk::Finish(FinishReason::Stop)).await;
        });

        Ok(StreamingResponse { stream: rx })
    }

    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        // Not implemented for this provider
        Err(openre_core::Error::Internal("Embeddings not supported".into()))
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus { healthy: true, message: None, latency_ms: None })
    }
}

impl OnnxProvider {
    fn sample_token(&self, logits: &ort::Tensor<f32>, temperature: f32) -> Result<u32> {
        Self::sample_token_static(logits, temperature)
    }

    fn sample_token_static(logits: &ort::Tensor<f32>, temperature: f32) -> Result<u32> {
        // Simple greedy sampling for now
        let data = logits.as_slice()?;
        let max_idx = data.iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(i, _)| i as u32)
            .unwrap_or(0);
        Ok(max_idx)
    }

    fn is_stop_token(&self, token: u32, stop: &Option<Vec<String>>) -> bool {
        Self::is_stop_token_static(token, stop)
    }

    fn is_stop_token_static(token: u32, stop: &Option<Vec<String>>) -> bool {
        if let Some(stop_tokens) = stop {
            // In a real implementation, check if token matches stop tokens
            false
        } else {
            false
        }
    }
}