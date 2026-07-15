//! Model router for open-re AI

use crate::providers::*;
use openre_core::error::Result;
use openre_config::AiConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Model router for selecting the best provider
pub struct ModelRouter {
    registry: Arc<ProviderRegistry>,
    config: AiConfig,
    usage_stats: Arc<RwLock<HashMap<ProviderId, ProviderStats>>>,
}

impl ModelRouter {
    pub fn new(registry: Arc<ProviderRegistry>, config: AiConfig) -> Self {
        Self {
            registry,
            config,
            usage_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Select the best provider for a request
    pub async fn select_provider(&self, request: &CompletionRequest) -> Result<ProviderId> {
        let candidates = self.get_candidates(request).await?;
        
        if candidates.is_empty() {
            return Err(openre_core::Error::Internal("No suitable provider found".into()));
        }

        // Apply routing strategy
        match self.config.routing_strategy.as_str() {
            "local_first" => self.select_local_first(&candidates).await,
            "cost_optimized" => self.select_cost_optimized(&candidates).await,
            "performance_optimized" => self.select_performance_optimized(&candidates).await,
            "round_robin" => self.select_round_robin(&candidates).await,
            _ => self.select_local_first(&candidates).await,
        }
    }

    /// Get candidate providers that can handle the request
    async fn get_candidates(&self, request: &CompletionRequest) -> Result<Vec<ProviderId>> {
        let mut candidates = Vec::new();
        
        for provider in self.registry.all() {
            if self.can_handle(provider, request) {
                candidates.push(provider.id());
            }
        }

        Ok(candidates)
    }

    /// Check if provider can handle the request
    fn can_handle(&self, provider: &dyn ModelProvider, request: &CompletionRequest) -> bool {
        let caps = provider.capabilities();
        
        // Check basic capabilities
        if request.tools.is_some() && !caps.tools {
            return false;
        }
        
        if request.stream && !provider.supports_streaming() {
            return false;
        }

        // Check context length
        let estimated_tokens = self.estimate_tokens(request);
        if estimated_tokens > provider.max_context_tokens() {
            return false;
        }

        // Check privacy requirements
        if self.config.privacy.local_only && !self.is_local_provider(provider) {
            return false;
        }

        true
    }

    fn is_local_provider(&self, provider: &dyn ModelProvider) -> bool {
        matches!(provider.id().provider_type.as_str(), "onnx" | "llama.cpp")
    }

    fn estimate_tokens(&self, request: &CompletionRequest) -> usize {
        request.messages.iter()
            .filter_map(|m| m.content.as_ref())
            .map(|c| c.len() / 4)
            .sum::<usize>() + request.max_tokens.unwrap_or(2048) as usize
    }

    /// Local-first selection (prefer local providers)
    async fn select_local_first(&self, candidates: &[ProviderId]) -> Result<ProviderId> {
        // First try local providers
        for id in candidates {
            if let Some(provider) = self.registry.get(id) {
                if self.is_local_provider(provider) {
                    return Ok(id.clone());
                }
            }
        }

        // Fallback to remote if allowed
        if !self.config.privacy.local_only {
            for id in candidates {
                if let Some(provider) = self.registry.get(id) {
                    if !self.is_local_provider(provider) {
                        return Ok(id.clone());
                    }
                }
            }
        }

        Err(openre_core::Error::Internal("No local provider available and remote not allowed".into()))
    }

    /// Cost-optimized selection
    async fn select_cost_optimized(&self, candidates: &[ProviderId]) -> Result<ProviderId> {
        let stats = self.usage_stats.read().await;
        
        // Prefer local (free) providers
        for id in candidates {
            if let Some(provider) = self.registry.get(id) {
                if self.is_local_provider(provider) {
                    return Ok(id.clone());
                }
            }
        }

        // Among remote, prefer cheapest
        let mut best: Option<ProviderId> = None;
        let mut best_cost = f64::MAX;

        for id in candidates {
            if let Some(provider) = self.registry.get(id) {
                if !self.is_local_provider(provider) {
                    let cost = self.estimate_cost(provider, &stats);
                    if cost < best_cost {
                        best_cost = cost;
                        best = Some(id.clone());
                    }
                }
            }
        }

        best.ok_or_else(|| openre_core::Error::Internal("No provider available".into()))
    }

    fn estimate_cost(&self, provider: &dyn ModelProvider, stats: &HashMap<ProviderId, ProviderStats>) -> f64 {
        // Simple cost estimation based on provider type and usage
        match provider.id().provider_type.as_str() {
            "openai" => 0.03,  // per 1k tokens
            "anthropic" => 0.015,
            "vllm" => 0.001,   // self-hosted
            _ => 0.01,
        }
    }

    /// Performance-optimized selection
    async fn select_performance_optimized(&self, candidates: &[ProviderId]) -> Result<ProviderId> {
        let stats = self.usage_stats.read().await;
        
        let mut best: Option<ProviderId> = None;
        let mut best_latency = u64::MAX;

        for id in candidates {
            if let Some(provider) = self.registry.get(id) {
                let latency = stats.get(id).map(|s| s.avg_latency_ms).unwrap_or(0);
                if latency < best_latency {
                    best_latency = latency;
                    best = Some(id.clone());
                }
            }
        }

        best.ok_or_else(|| openre_core::Error::Internal("No provider available".into()))
    }

    /// Round-robin selection
    async fn select_round_robin(&self, candidates: &[ProviderId]) -> Result<ProviderId> {
        let mut stats = self.usage_stats.write().await;
        
        // Find least used
        let mut best: Option<ProviderId> = None;
        let mut min_uses = u64::MAX;

        for id in candidates {
            let uses = stats.get(id).map(|s| s.total_requests).unwrap_or(0);
            if uses < min_uses {
                min_uses = uses;
                best = Some(id.clone());
            }
        }

        best.ok_or_else(|| openre_core::Error::Internal("No provider available".into()))
    }

    /// Record usage statistics
    pub async fn record_usage(&self, provider_id: &ProviderId, latency_ms: u64, tokens: u32, success: bool) {
        let mut stats = self.usage_stats.write().await;
        let entry = stats.entry(provider_id.clone()).or_insert_with(ProviderStats::default);
        
        entry.total_requests += 1;
        entry.total_tokens += tokens;
        entry.total_latency_ms += latency_ms;
        entry.avg_latency_ms = entry.total_latency_ms / entry.total_requests;
        
        if success {
            entry.successful_requests += 1;
        } else {
            entry.failed_requests += 1;
        }
    }

    /// Get provider statistics
    pub async fn get_stats(&self, provider_id: &ProviderId) -> Option<ProviderStats> {
        self.usage_stats.read().await.get(provider_id).cloned()
    }

    /// Get all statistics
    pub async fn get_all_stats(&self) -> HashMap<ProviderId, ProviderStats> {
        self.usage_stats.read().await.clone()
    }
}

/// Provider usage statistics
#[derive(Debug, Clone, Default)]
pub struct ProviderStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_tokens: u64,
    pub total_latency_ms: u64,
    pub avg_latency_ms: u64,
}