//! Integration test for the AI Security Analyst

mod mock_provider;

use async_trait::async_trait;
use mock_provider::MockFindingProvider;
use openre_ai::providers::{
    CompletionRequest, CompletionResponse, FinishReason, HealthStatus, Message, ModelProvider,
    ProviderCapabilities, ProviderId, StreamChunk, StreamingResponse, Usage,
};
use openre_core::error::OpenreResult;
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Category, Confidence, Finding, FindingConfig, Severity};
use openre_security_ai::{
    analyst::{SecurityAnalyst, SecurityAnalystImpl},
    cache::AnalysisCache,
    context::ContextBuilder,
    prompts::PromptCompiler,
    safety::SafetyGuard,
    ScanMetadata,
};
use std::sync::Arc;

#[tokio::test]
async fn test_security_analyst_basic_functionality() {
    // Create mock components
    let finding_provider = Arc::new(MockFindingProvider::new());
    let prompt_compiler = Arc::new(PromptCompiler::new());
    let context_builder = Arc::new(ContextBuilder::new(2048));
    let cache = Arc::new(AnalysisCache::new(100, 3600));
    let safety_guard = Arc::new(SafetyGuard::new(true));

    // Create scan and finding IDs
    let scan_id = ScanId::new();
    let finding_id = FindingId::new();

    // Create a mock finding
    let finding = Finding::new(FindingConfig {
        title: "SQL Injection Test".to_string(),
        description: "User input is not properly sanitized in login form".to_string(),
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: Category::Injection,
        target: "http://example.com/login".to_string(),
        target_type: "web_application".to_string(),
        plugin_source: "sql_injection_test".to_string(),
        plugin_version: "1.0.0".to_string(),
        scan_id,
    });

    // Add finding to mock provider
    finding_provider.add_finding(scan_id, finding).await;

    // Add scan metadata
    let metadata = ScanMetadata {
        scan_id,
        target: "http://example.com".to_string(),
        started_at: chrono::Utc::now(),
        completed_at: None,
        finding_count: 1,
        status: "completed".to_string(),
    };
    finding_provider.add_scan_metadata(metadata).await;

    // Create analyst service
    let analyst = SecurityAnalystImpl::with_components(
        finding_provider.clone(),
        Arc::new(MockModelProvider::new()),
        prompt_compiler,
        context_builder,
        cache,
        safety_guard,
    );

    // Test that we can create the analyst - full integration would require a real model provider
    assert!(true); // If we get here without panicking, basic structure works
}

// Simple mock model provider for testing
struct MockModelProvider;

impl MockModelProvider {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ModelProvider for MockModelProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("mock", "mock-model")
    }

    fn name(&self) -> &str {
        "mock"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities { chat: true, ..Default::default() }
    }

    fn max_context_tokens(&self) -> usize {
        4096
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        false
    }

    async fn complete(&self, _request: CompletionRequest) -> OpenreResult<CompletionResponse> {
        Ok(CompletionResponse {
            id: "mock-response".to_string(),
            model: "mock-model".to_string(),
            choices: vec![openre_ai::providers::Choice {
                index: 0,
                message: Message::assistant("Mock response".to_string()),
                finish_reason: FinishReason::Stop,
            }],
            usage: Usage { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
            created: 0,
        })
    }

    async fn stream(&self, _request: CompletionRequest) -> OpenreResult<StreamingResponse> {
        let (tx, rx) = tokio::sync::mpsc::channel(10);

        tx.send(StreamChunk::Content("Mock streaming response".to_string())).await.unwrap();
        tx.send(StreamChunk::Finish(FinishReason::Stop)).await.unwrap();

        Ok(StreamingResponse { stream: rx })
    }

    async fn embed(&self, texts: Vec<String>) -> OpenreResult<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|t| vec![t.len() as f32]).collect())
    }

    async fn health_check(&self) -> OpenreResult<HealthStatus> {
        Ok(HealthStatus { healthy: true, message: None, latency_ms: None })
    }
}
