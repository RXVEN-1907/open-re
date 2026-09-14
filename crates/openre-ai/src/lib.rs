//! AI service for open-re

pub mod cache;
pub mod grounded;
pub mod privacy;
pub mod prompt_compiler;
pub mod providers;
pub mod router;
pub mod service;
pub mod tools;

pub use cache::*;
pub use grounded::*;
pub use privacy::*;
pub use prompt_compiler::*;
pub use providers::*;
pub use router::*;
pub use service::*;
pub use tools::*;

// Import the proper Result type

// Public types for CLI integration - minimal stub versions
pub mod ai_types {
    /// AI provider type (matches the stubs version for CLI compatibility)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AiProvider {
        Local,
        Ollama,
        LlamaCpp,
        Onnx,
        OpenAI,
        Anthropic,
        Vllm,
    }

    /// AI client stub (minimal version for CLI compatibility)
    #[derive(Debug, Clone)]
    pub struct AiClient {
        // We don't need to store anything for the stub implementation
        _private: (),
    }

    impl AiClient {
        /// Create a new AI client
        pub fn new(_provider: AiProvider, _model: Option<String>) -> anyhow::Result<Self> {
            Ok(Self { _private: () })
        }

        /// Chat with AI assistant - stub implementation
        pub async fn chat(
            &self,
            message: &str,
            _system: Option<&str>,
            _temperature: f32,
            _max_tokens: Option<u32>,
        ) -> anyhow::Result<String> {
            Ok(format!(
                "AI response to: '{}' (this is a stub implementation)",
                message
            ))
        }

        // Stub implementations for other methods
        #[allow(dead_code)]
        pub async fn analyze(&self, _request: ()) -> anyhow::Result<()> {
            Ok(())
        }

        #[allow(dead_code)]
        pub async fn explain(&self, _finding: (), _detail: (), _audience: ()) -> anyhow::Result<String> {
            Ok("AI explanation not implemented - requires openre-ai crate".to_string())
        }

        #[allow(dead_code)]
        pub async fn remediate(&self, _finding: (), _fix_type: (), _language: Option<()>) -> anyhow::Result<String> {
            Ok("AI remediation not implemented - requires openre-ai crate".to_string())
        }

        #[allow(dead_code)]
        pub async fn list_providers(&self) -> anyhow::Result<()> {
            Ok(())
        }

        #[allow(dead_code)]
        pub async fn test_connection(
            &self,
            _provider: Option<AiProvider>,
            _model: Option<&str>,
        ) -> anyhow::Result<(bool, String, u64, Option<String>)> {
            Ok((false, "Stub implementation".to_string(), 0, Some("AI features require proper configuration".to_string())))
        }
    }
}

pub use ai_types::{AiProvider, AiClient};
