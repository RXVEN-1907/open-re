//! Plugin SDK for open-re

use openre_core::ids::{BlockId, FunctionId, InstructionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub use openre_core::error::OpenreResult as Result;
/// Re-export commonly used types for plugin authors
pub use openre_core::ids::{Capability, PluginId};

/// Plugin instance trait for lifecycle management
#[async_trait::async_trait]
pub trait PluginInstance: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn shutdown(&self) -> Result<()>;
    async fn health_check(&self) -> Result<bool>;

    /// Apply a JSON configuration payload to the instance.
    ///
    /// The payload is intentionally untyped so hosts and plugins do not need
    /// to share concrete configuration structs. Default: no-op.
    async fn configure(&self, _config: Value) -> Result<()> {
        Ok(())
    }

    /// Execute a scan task with a serialized input payload, returning the raw
    /// output payload. Default: no-op returning `null`.
    async fn execute(&self, _input: Value) -> Result<Value> {
        Ok(Value::Null)
    }
}

/// Plugin trait that all plugins must implement
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    type Config: for<'de> Deserialize<'de> + Send + Sync + 'static;

    fn new(config: Self::Config) -> Self;
    fn capabilities(&self) -> Vec<Capability>;
    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse>;
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
}

/// Dyn-compatible plugin trait for lifecycle management
pub trait DynPlugin: Send + Sync {
    fn capabilities(&self) -> Vec<Capability>;
    fn execute(
        &self,
        request: CapabilityRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<CapabilityResponse>> + Send + '_>>;
    fn initialize(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}

impl<T: Plugin> DynPlugin for T {
    fn capabilities(&self) -> Vec<Capability> {
        self.capabilities()
    }
    fn execute(
        &self,
        request: CapabilityRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<CapabilityResponse>> + Send + '_>>
    {
        Box::pin(self.execute(request))
    }
    fn initialize(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(self.initialize())
    }
}

/// Capability request from host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub capability: Capability,
    pub context: AnalysisContext,
    pub input: Value,
}

/// Capability response to host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResponse {
    pub success: bool,
    pub output: Option<Value>,
    pub error: Option<String>,
}

impl CapabilityResponse {
    pub fn success(output: Value) -> Self {
        Self {
            success: true,
            output: Some(output),
            error: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            output: None,
            error: Some(error),
        }
    }
}

/// Plugin error for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginError {
    pub code: String,
    pub message: String,
}

impl From<openre_core::Error> for PluginError {
    fn from(err: openre_core::Error) -> Self {
        Self {
            code: err.code().to_string(),
            message: err.to_string(),
        }
    }
}

/// Analysis context provided to plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub job_id: openre_core::ids::JobId,
    pub project_id: openre_core::ids::ProjectId,
    pub file_id: openre_core::ids::FileId,
    pub function_id: Option<FunctionId>,
    pub block_id: Option<BlockId>,
    pub instruction_id: Option<InstructionId>,
    pub binary_size: u64,
    pub binary_hash: String,
    pub architecture: String,
    pub format: String,
}

/// Host functions available to plugins
pub struct HostFunctions {
    pub read_binary: fn(offset: u64, len: u64) -> Result<Vec<u8>>,
    pub write_annotation: fn(annotation: Annotation) -> Result<()>,
    pub query_database: fn(sql: String, params: Vec<Value>) -> Result<Vec<Value>>,
    pub get_config: fn(key: String) -> Result<Value>,
    pub log: fn(level: LogLevel, message: String) -> Result<()>,
    pub emit_progress: fn(stage: String, progress: f32, message: String) -> Result<()>,
    pub call_ai: fn(task: String, context: Value) -> Result<Value>,
}

/// Annotation for writing to database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub address: u64,
    pub annotation_type: AnnotationType,
    pub value: String,
    pub function_id: Option<FunctionId>,
    pub created_by: AnnotationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnotationType {
    Comment,
    Name,
    Type,
    Bookmark,
    Label,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnotationSource {
    User,
    Ai,
    Plugin,
    Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Plugin entry point macro
#[macro_export]
macro_rules! plugin_entry {
    ($plugin_type:ty) => {
        use std::sync::Mutex;
        use $crate::sdk::Plugin;

        static PLUGIN: Mutex<Option<$plugin_type>> = Mutex::new(None);

        #[no_mangle]
        pub extern "C" fn plugin_init(config_ptr: *const u8, config_len: usize) -> i32 {
            if config_ptr.is_null() || config_len == 0 {
                return -1;
            }
            let config_slice = unsafe { std::slice::from_raw_parts(config_ptr, config_len) };
            let config: <$plugin_type as Plugin>::Config =
                match serde_json::from_slice(config_slice) {
                    Ok(c) => c,
                    Err(_) => return -1,
                };
            let plugin = <$plugin_type as Plugin>::new(config);
            *PLUGIN.lock().unwrap() = Some(plugin);
            0
        }

        #[no_mangle]
        pub extern "C" fn plugin_execute(
            request_ptr: *const u8,
            request_len: usize,
            response_ptr: *mut u8,
            response_len: *mut usize,
        ) -> i32 {
            if request_ptr.is_null()
                || request_len == 0
                || response_ptr.is_null()
                || response_len.is_null()
            {
                return -1;
            }
            let request_slice = unsafe { std::slice::from_raw_parts(request_ptr, request_len) };
            let request: $crate::sdk::CapabilityRequest =
                match serde_json::from_slice(request_slice) {
                    Ok(r) => r,
                    Err(_) => return -1,
                };

            let mut plugin_guard = PLUGIN.lock().unwrap();
            let plugin = match plugin_guard.as_mut() {
                Some(p) => p,
                None => return -1,
            };

            let rt = tokio::runtime::Runtime::new().unwrap();
            let result = rt.block_on(async { plugin.execute(request).await });

            let response = match result {
                Ok(r) => r,
                Err(e) => {
                    let plugin_error: $crate::sdk::PluginError = e.into();
                    CapabilityResponse::error(
                        serde_json::to_string(&plugin_error)
                            .unwrap_or_else(|_| "Unknown error".to_string()),
                    )
                }
            };

            let response_json = match serde_json::to_vec(&response) {
                Ok(v) => v,
                Err(_) => return -1,
            };

            if response_json.len() > unsafe { *response_len } {
                return -1;
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    response_json.as_ptr(),
                    response_ptr,
                    response_json.len(),
                );
                *response_len = response_json.len();
            }

            0
        }

        #[no_mangle]
        pub extern "C" fn plugin_shutdown() -> i32 {
            *PLUGIN.lock().unwrap() = None;
            0
        }
    };
}

/// WASM component model exports
#[cfg(target_arch = "wasm32")]
pub mod wasm_exports {
    use super::*;
    use wasmtime::component::bindgen;

    bindgen!({
        world: "plugin",
        path: "wit/plugin.wit",
    });
}
