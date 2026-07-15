//! AI service for open-re - main entry point

use crate::{
    providers::{ProviderRegistry, ModelProvider, CompletionRequest, CompletionResponse, StreamingResponse, ProviderId},
    prompt_compiler::PromptCompiler,
    tools::{ToolRegistry, ToolContext, ToolPermissions},
    router::ModelRouter,
    cache::AiCache,
    privacy::PrivacyController,
};
use openre_core::error::Result;
use openre_config::AiConfig;
use openre_storage::{GlobalStore, ProjectStore, ObjectStore};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Main AI service
pub struct AiService {
    provider_registry: Arc<ProviderRegistry>,
    prompt_compiler: Arc<PromptCompiler>,
    tool_registry: Arc<ToolRegistry>,
    router: Arc<ModelRouter>,
    cache: Arc<AiCache>,
    privacy: Arc<PrivacyController>,
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
        let provider_registry = Arc::new(ProviderRegistry::new());
        Self::register_providers(&provider_registry, &config).await?;

        // Initialize components
        let prompt_compiler = Arc::new(PromptCompiler::new());
        let tool_registry = Arc::new(ToolRegistry::new());
        let router = Arc::new(ModelRouter::new(provider_registry.clone(), config.clone()));
        let cache = Arc::new(AiCache::new(config.cache.clone())?);
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

    async fn register_providers(registry: &ProviderRegistry, config: &AiConfig) -> Result<()> {
        // Register ONNX providers
        for onnx_config in &config.onnx_models {
            let provider = crate::providers::onnx::OnnxProvider::new(
                &onnx_config.model_path,
                onnx_config.clone(),
            )?;
            registry.register(Box::new(provider));
        }

        // Register llama.cpp providers
        for llama_config in &config.llama_cpp_models {
            let provider = crate::providers::llama_cpp::LlamaCppProvider::new(
                &llama_config.model_path,
                llama_config.clone(),
            )?;
            registry.register(Box::new(provider));
        }

        // Register remote providers
        if let Some(openai_key) = &config.openai_api_key {
            registry.register(Box::new(crate::providers::remote::RemoteProvider::openai(openai_key.clone())));
        }

        if let Some(vllm_url) = &config.vllm_base_url {
            registry.register(Box::new(crate::providers::remote::RemoteProvider::vllm(
                vllm_url.clone(),
                config.vllm_api_key.clone(),
            )));
        }

        if let Some(anthropic_key) = &config.anthropic_api_key {
            registry.register(Box::new(crate::providers::remote::RemoteProvider::anthropic(anthropic_key.clone())));
        }

        Ok(())
    }

    /// Complete a request using the best available provider
    pub async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        // Check privacy
        let decision = self.privacy.check_request_allowed(&request)?;
        match decision {
            crate::privacy::PrivacyDecision::Denied(reason) => {
                return Err(openre_core::Error::PermissionDenied(reason));
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
        let provider = self.provider_registry.get(&provider_id)
            .ok_or_else(|| openre_core::Error::Internal("Provider not found".into()))?;

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
        self.router.record_usage(&provider_id, latency, sanitized_response.usage.total_tokens, true).await;

        // Audit
        self.privacy.audit(crate::privacy::PrivacyAuditEntry {
            timestamp: chrono::Utc::now(),
            action: crate::privacy::PrivacyAction::RequestAllowed,
            provider: Some(provider_id.to_string()),
            classification: crate::privacy::DataClassification::Internal,
            details: "Completion request completed".to_string(),
            user_id: None,
        }).await;

        Ok(sanitized_response)
    }

    /// Stream a completion
    pub async fn stream(&self, request: CompletionRequest) -> Result<StreamingResponse> {
        // Check privacy
        let decision = self.privacy.check_request_allowed(&request)?;
        match decision {
            crate::privacy::PrivacyDecision::Denied(reason) => {
                return Err(openre_core::Error::PermissionDenied(reason));
            }
            _ => {}
        }

        // Sanitize request
        let mut sanitized_request = request;
        self.privacy.sanitize_request(&mut sanitized_request)?;

        // Select provider
        let provider_id = self.router.select_provider(&sanitized_request).await?;
        let provider = self.provider_registry.get(&provider_id)
            .ok_or_else(|| openre_core::Error::Internal("Provider not found".into()))?;

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
            router.record_usage(&provider_id_clone, latency, total_tokens, true).await;
            
            privacy.audit(crate::privacy::PrivacyAuditEntry {
                timestamp: chrono::Utc::now(),
                action: crate::privacy::PrivacyAction::RequestAllowed,
                provider: Some(provider_id_clone.to_string()),
                classification: crate::privacy::DataClassification::Internal,
                details: "Streaming request completed".to_string(),
                user_id: None,
            }).await;
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
            self.prompt_compiler.compile_with_context(template_name, variables, &store, fid).await?
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
            self.prompt_compiler.compile_with_context(template_name, variables, &store, fid).await?
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
            let response = self.complete(current_request).await?;
            
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

                                let result = tool.execute(tool_call.arguments.clone(), &context).await?;
                                tool_results.push((tool_call.id.clone(), result));
                            }
                        }

                        // Add tool results to conversation
                        for (tool_call_id, result) in tool_results {
                            current_request.messages.push(crate::providers::Message::tool_result(
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
    pub async fn router_stats(&self) -> std::collections::HashMap<ProviderId, crate::router::ProviderStats> {
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
    pub async fn health_check(&self) -> std::collections::HashMap<ProviderId, crate::providers::HealthStatus> {
        let mut results = std::collections::HashMap::new();
        for provider in self.provider_registry.all() {
            if let Ok(status) = provider.health_check().await {
                results.insert(provider.id(), status);
            }
        }
        results
    }
}