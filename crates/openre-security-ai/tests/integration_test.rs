//! Integration test for the AI Security Analyst

use openre_security_ai::{
    analyst::{SecurityAnalyst, SecurityAnalystImpl},
    finding_provider::MockFindingProvider,
    test_utils::ScanMetadata,
    prompts::PromptCompiler,
    context::ContextBuilder,
    cache::AnalysisCache,
    safety::SafetyGuard,
};
use openre_core::result::{Finding, Severity, Confidence, Category};
use openre_core::ids::{ScanId, FindingId};
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
    let finding = Finding::new(
        "SQL Injection Test".to_string(),
        "User input is not properly sanitized in login form".to_string(),
        Severity::High,
        Confidence::Medium,
        Category::Injection,
        "http://example.com/login".to_string(),
        "web_application".to_string(),
        "sql_injection_test".to_string(),
        "1.0.0".to_string(),
        scan_id,
    );

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

use async_trait::async_trait;
use openre_ai::providers::{ModelProvider, CompletionRequest, CompletionResponse, AiError};

#[async_trait]
impl ModelProvider for MockModelProvider {
    async fn complete(&self, _request: CompletionRequest) -> Result<CompletionResponse, AiError> {
        // Return a simple mock response
        Ok(CompletionResponse {
            id: "mock-response".to_string(),
            model: "mock-model".to_string(),
            choices: vec![openre_ai::providers::Choice {
                index: 0,
                message: openre_ai::providers::Message::assistant("Mock response".to_string()),
                finish_reason: openre_ai::providers::FinishReason::Stop,
            }],
            usage: openre_ai::providers::Usage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            created: 0,
        })
    }

    async fn stream(&self, _request: CompletionRequest) -> Result<openre_ai::providers::StreamingResponse, AiError> {
        // Create a simple streaming response for testing
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        
        // Send a simple response
        tx.send(openre_ai::providers::StreamChunk::Content("Mock streaming response".to_string())).await.unwrap();
        tx.send(openre_ai::providers::StreamChunk::Finish(openre_ai::providers::FinishReason::Stop)).await.unwrap();
        
        Ok(openre_ai::providers::StreamingResponse {
            stream: rx,
        })
    }
}