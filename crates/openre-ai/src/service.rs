//! AI service for open-re - main entry point

use crate::{
    cache::AiCache,
    privacy::PrivacyController,
    prompt_compiler::PromptCompiler,
    providers::{
        CompletionRequest, CompletionResponse, ModelProvider, ProviderId, ProviderRegistry,
        StreamingResponse,
    },
    router::ModelRouter,
    tools::{ToolContext, ToolPermissions, ToolRegistry},
};
use openre_config::AiConfig;
use openre_core::error::OpenreResult as Result;
use openre_storage::{GlobalStore, ObjectStore, ProjectStore};
use std::sync::Arc;
use tracing;

/// Main AI service
pub struct AiService {
    provider_registry: Arc<ProviderRegistry>,
    prompt_compiler: Arc<PromptCompiler>,
    tool_registry: Arc<ToolRegistry>,
    router: Arc<ModelRouter>,
    cache: Arc<AiCache>,
    privacy: Arc<PrivacyController>,
    #[allow(dead_code)]
    config: AiConfig,
    global_store: Arc<GlobalStore>,
    object_store: Arc<ObjectStore>,
}

impl AiService {
    pub async fn new(
        config: AiConfig,
        global_store: Arc<GlobalStore>,
        object_store: Arc<ObjectStore>,
    ) -> Result<Self> {
        // Initialize provider registry
        let mut provider_registry = ProviderRegistry::new();
        Self::register_providers(&mut provider_registry, &config).await?;
        let provider_registry = Arc::new(provider_registry);

        // Initialize components
        let prompt_compiler = Arc::new(PromptCompiler::new());
        let tool_registry = Arc::new(ToolRegistry::new());
        let router = Arc::new(ModelRouter::new(provider_registry.clone(), config.clone()));
        let cache = Arc::new(AiCache::new(config.cache.clone()).await?);
        let privacy = Arc::new(PrivacyController::new(config.privacy.clone())?);

        Ok(Self {
            provider_registry,
            prompt_compiler,
            tool_registry,
            router,
            cache,
            privacy,
            config,
            global_store,
            object_store,
        })
    }

    async fn register_providers(registry: &mut ProviderRegistry, config: &AiConfig) -> Result<()> {
        // Register ONNX providers (disabled - requires ort dependency)
        // for onnx_config in &config.onnx_models {
        //     let provider = crate::providers::onnx::OnnxProvider::new(
        //         &onnx_config.model_path,
        //         onnx_config.clone(),
        //     )?;
        //     registry.register(Box::new(provider));
        // }

        // Register llama.cpp providers (disabled - requires llama_cpp_2 dependency)
        // for llama_config in &config.llama_cpp_models {
        //     let provider = crate::providers::llama_cpp::LlamaCppProvider::new(
        //         &llama_config.model_path,
        //         llama_config.clone(),
        //     )?;
        //     registry.register(Box::new(provider));
        // }

        // Register remote providers from config
        // Note: Remote provider API keys should be configured via environment variables
        // or a separate secrets management system. The config only specifies which
        // providers are allowed via `allowed_remote_providers`.
        for provider_name in &config.allowed_remote_providers {
            match provider_name.as_str() {
                "openai" => {
                    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
                        registry.register(Box::new(
                            crate::providers::remote::RemoteProvider::openai(api_key),
                        ));
                    }
                }
                "vllm" => {
                    if let Ok(base_url) = std::env::var("VLLM_BASE_URL") {
                        let api_key = std::env::var("VLLM_API_KEY").ok();
                        registry.register(Box::new(
                            crate::providers::remote::RemoteProvider::vllm(base_url, api_key),
                        ));
                    }
                }
                "anthropic" => {
                    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
                        registry.register(Box::new(
                            crate::providers::remote::RemoteProvider::anthropic(api_key),
                        ));
                    }
                }
                _ => {
                    tracing::warn!("Unknown remote provider: {}", provider_name);
                }
            }
        }

        Ok(())
    }

    /// Complete a request using the best available provider
    pub async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        // Check privacy
        let decision = self.privacy.check_request_allowed(&request)?;
        match decision {
            crate::privacy::PrivacyDecision::Denied(reason) => {
                return Err(openre_core::Error::Forbidden(reason));
            }
            crate::privacy::PrivacyDecision::Redacted(_) => {
                // Will be handled by sanitize
            }
            _ => {}
        }

        // Sanitize request
        let mut sanitized_request = request;
        self.privacy.sanitize_request(&mut sanitized_request)?;

        // Check cache
        let cache_key = self.cache.generate_key(&sanitized_request);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        // Select provider
        let provider_id = self.router.select_provider(&sanitized_request).await?;
        let provider = self
            .provider_registry
            .get(&provider_id)
            .ok_or_else(|| openre_core::Error::Internal(anyhow::anyhow!("Provider not found")))?;

        // Execute request
        let start = std::time::Instant::now();
        let response = provider.complete(sanitized_request).await?;
        let latency = start.elapsed().as_millis() as u64;

        // Sanitize response
        let mut sanitized_response = response;
        self.privacy.sanitize_response(&mut sanitized_response)?;

        // Cache response
        self.cache.put(&cache_key, sanitized_response.clone()).await;

        // Record usage
        self.router
            .record_usage(
                &provider_id,
                latency,
                sanitized_response.usage.total_tokens,
                true,
            )
            .await;

        // Audit
        self.privacy
            .audit(crate::privacy::PrivacyAuditEntry {
                timestamp: chrono::Utc::now(),
                action: crate::privacy::PrivacyAction::RequestAllowed,
                provider: Some(provider_id.to_string()),
                classification: crate::privacy::DataClassification::Internal,
                details: "Completion request completed".to_string(),
                user_id: None,
            })
            .await;

        Ok(sanitized_response)
    }

    /// Stream a completion
    pub async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse> {
        // Check privacy
        let decision = self.privacy.check_request_allowed(&request)?;
        if let crate::privacy::PrivacyDecision::Denied(reason) = decision {
            return Err(openre_core::Error::Forbidden(reason));
        }

        // Sanitize request
        let mut sanitized_request = request;
        self.privacy.sanitize_request(&mut sanitized_request)?;

        // Select provider
        let provider_id = self.router.select_provider(&sanitized_request).await?;
        let provider = self
            .provider_registry
            .get(&provider_id)
            .ok_or_else(|| openre_core::Error::Internal(anyhow::anyhow!("Provider not found")))?;

        // Execute streaming request
        let response = provider.stream(sanitized_request).await?;

        // Record usage (will be updated as chunks arrive)
        let provider_id_clone = provider_id.clone();
        let router = self.router.clone();
        let privacy = self.privacy.clone();

        // Wrap stream to record usage and sanitize
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let mut stream = response.stream;

        tokio::spawn(async move {
            let mut total_tokens = 0u32;
            let start = std::time::Instant::now();

            while let Some(chunk) = stream.recv().await {
                // Sanitize chunk if needed
                let sanitized_chunk = match &chunk {
                    crate::providers::StreamChunk::Content(text) => {
                        total_tokens += text.len() as u32 / 4;
                        crate::providers::StreamChunk::Content(text.clone())
                    }
                    _ => chunk,
                };

                if tx.send(sanitized_chunk).await.is_err() {
                    break;
                }
            }

            let latency = start.elapsed().as_millis() as u64;
            router
                .record_usage(&provider_id_clone, latency, total_tokens, true)
                .await;

            privacy
                .audit(crate::privacy::PrivacyAuditEntry {
                    timestamp: chrono::Utc::now(),
                    action: crate::privacy::PrivacyAction::RequestAllowed,
                    provider: Some(provider_id_clone.to_string()),
                    classification: crate::privacy::DataClassification::Internal,
                    details: "Streaming request completed".to_string(),
                    user_id: None,
                })
                .await;
        });

        Ok(StreamingResponse { stream: rx })
    }

    /// Execute a prompt template with context
    pub async fn execute_template(
        &self,
        template_name: &str,
        variables: std::collections::HashMap<String, String>,
        project_store: Option<Arc<ProjectStore>>,
        function_id: Option<openre_core::ids::FunctionId>,
    ) -> Result<CompletionResponse> {
        let compiled = if let (Some(store), Some(fid)) = (project_store, function_id) {
            self.prompt_compiler
                .compile_with_context(template_name, variables, &store, fid)
                .await?
        } else {
            self.prompt_compiler.compile(template_name, variables)?
        };

        let request = compiled.to_completion_request("default", Some(0.7));
        self.complete(request).await
    }

    /// Execute template with streaming
    pub async fn execute_template_stream(
        &self,
        template_name: &str,
        variables: std::collections::HashMap<String, String>,
        project_store: Option<Arc<ProjectStore>>,
        function_id: Option<openre_core::ids::FunctionId>,
    ) -> Result<StreamingResponse> {
        let compiled = if let (Some(store), Some(fid)) = (project_store, function_id) {
            self.prompt_compiler
                .compile_with_context(template_name, variables, &store, fid)
                .await?
        } else {
            self.prompt_compiler.compile(template_name, variables)?
        };

        let request = compiled.to_completion_request("default", Some(0.7));
        self.stream(request).await
    }

    /// Execute with tools
    pub async fn execute_with_tools(
        &self,
        request: CompletionRequest,
        project_store: Option<Arc<ProjectStore>>,
        permissions: ToolPermissions,
    ) -> Result<CompletionResponse> {
        // Add tool definitions to request
        let mut request_with_tools = request;
        request_with_tools.tools = Some(self.tool_registry.to_tool_definitions());

        // Execute with tool calling loop
        let mut current_request = request_with_tools;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 10;

        loop {
            // Clone the request for the completion call since complete() takes ownership
            let request_for_completion = current_request.clone();
            let response = self.complete(request_for_completion).await?;

            // Check for tool calls
            if let Some(choice) = response.choices.first() {
                if let Some(tool_calls) = &choice.message.tool_calls {
                    if !tool_calls.is_empty() && iterations < MAX_ITERATIONS {
                        iterations += 1;

                        // Execute tools
                        let mut tool_results = Vec::new();
                        for tool_call in tool_calls {
                            if let Some(tool) = self.tool_registry.get(&tool_call.name) {
                                let context = ToolContext {
                                    global_store: self.global_store.clone(),
                                    project_store: project_store.clone(),
                                    object_store: self.object_store.clone(),
                                    current_project: None,
                                    current_file: None,
                                    current_function: None,
                                    permissions: permissions.clone(),
                                };

                                let result =
                                    tool.execute(tool_call.arguments.clone(), &context).await?;
                                tool_results.push((tool_call.id.clone(), result));
                            }
                        }

                        // Add tool results to conversation
                        for (tool_call_id, result) in tool_results {
                            current_request
                                .messages
                                .push(crate::providers::Message::tool_result(
                                    tool_call_id,
                                    serde_json::to_string(&result.output)?,
                                ));
                        }

                        continue; // Continue loop for next iteration
                    }
                }
            }

            return Ok(response);
        }
    }

    /// Get available providers
    pub fn list_provider_ids(&self) -> Vec<ProviderId> {
        self.provider_registry
            .all()
            .iter()
            .map(|p| p.id())
            .collect()
    }

    pub fn get_provider_arc(&self, id: &ProviderId) -> Option<Arc<dyn ModelProvider>> {
        self.provider_registry.get_arc(id)
    }

    pub fn list_providers(&self) -> Vec<&dyn ModelProvider> {
        self.provider_registry.all()
    }

    /// Get provider by ID
    pub fn get_provider(&self, id: &ProviderId) -> Option<&dyn ModelProvider> {
        self.provider_registry.get(id)
    }

    /// Get prompt compiler
    pub fn prompt_compiler(&self) -> &PromptCompiler {
        &self.prompt_compiler
    }

    /// Get tool registry
    pub fn tool_registry(&self) -> &ToolRegistry {
        &self.tool_registry
    }

    /// Get router stats
    pub async fn router_stats(
        &self,
    ) -> std::collections::HashMap<ProviderId, crate::router::ProviderStats> {
        self.router.get_all_stats().await
    }

    /// Get cache stats
    pub async fn cache_stats(&self) -> crate::cache::CacheStats {
        self.cache.stats().await
    }

    /// Clear cache
    pub async fn clear_cache(&self) {
        self.cache.clear().await;
    }

    /// Health check all providers
    pub async fn health_check(
        &self,
    ) -> std::collections::HashMap<ProviderId, crate::providers::HealthStatus> {
        let mut results = std::collections::HashMap::new();
        for provider in self.provider_registry.all() {
            if let Ok(status) = provider.health_check().await {
                results.insert(provider.id(), status);
            }
        }
        results
    }
}
