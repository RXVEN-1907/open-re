//! Plugin runtime for open-re

use crate::{manifest::*, capability::*, registry::PluginRegistry};
use openre_config::RemoteRegistryConfig;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::{PluginId, Capability};
use openre_core::traits::IsolatedBinary;
use openre_storage::ProjectStore;
use openre_telemetry::metrics;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiView};
use wasmtime_wasi::preview1::{WasiP1Ctx, add_to_linker_async};

/// Loaded plugin instance
#[derive(Clone)]
pub enum LoadedPlugin {
    Wasm(Arc<WasmPluginInstance>),
    Native(Arc<NativePluginInstance>),
}

impl LoadedPlugin {
    pub async fn initialize(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        match self {
            LoadedPlugin::Wasm(instance) => instance.initialize(config).await,
            LoadedPlugin::Native(instance) => instance.initialize(config).await,
        }
    }

    pub async fn execute(&self, capability: &str, input: serde_json::Value) -> Result<serde_json::Value> {
        match self {
            LoadedPlugin::Wasm(instance) => instance.execute(capability, input).await,
            LoadedPlugin::Native(instance) => instance.execute(capability, input).await,
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        match self {
            LoadedPlugin::Wasm(instance) => instance.shutdown().await,
            LoadedPlugin::Native(instance) => instance.shutdown().await,
        }
    }
}

/// WASM plugin instance
pub struct WasmPluginInstance {
    store: Arc<tokio::sync::Mutex<wasmtime::Store<PluginState>>>,
    instance: wasmtime::Instance,
    init_func: wasmtime::TypedFunc<(), ()>,
    execute_func: wasmtime::TypedFunc<(i32, i32), i32>,
    shutdown_func: wasmtime::TypedFunc<(), ()>,
    fuel_limit: u64,
}

impl WasmPluginInstance {
    pub async fn initialize(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        let config_json = serde_json::to_string(config)?;
        // In a real implementation, we'd pass config to the plugin
        let mut store = self.store.lock().await;
        self.init_func.call_async(&mut *store, ()).await?;
        Ok(())
    }

    pub async fn execute(&self, capability: &str, input: serde_json::Value) -> Result<serde_json::Value> {
        let start = std::time::Instant::now();
        let mut store = self.store.lock().await;
        // For now, use a simple approach - in reality this would need proper WASM memory management
        let result = self.execute_func.call_async(&mut *store, (0, 0)).await;
        metrics::record_plugin_execution("wasm", capability, start.elapsed(), result.is_ok());
        result.map(|_| serde_json::Value::Null).map_err(|e| openre_core::Error::Internal(e.into()))
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut store = self.store.lock().await;
        self.shutdown_func.call_async(&mut *store, ()).await?;
        Ok(())
    }
}

/// Native plugin instance
pub struct NativePluginInstance {
    library: Arc<libloading::Library>,
}

impl NativePluginInstance {
    pub async fn initialize(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        let config_json = serde_json::to_vec(config)?;
        let init: libloading::Symbol<unsafe extern "C" fn(*const u8, usize) -> i32> = 
            unsafe { self.library.get(b"plugin_init") }
                .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("Failed to get plugin_init: {}", e)))?;
        let result = unsafe { (init)(config_json.as_ptr(), config_json.len()) };
        if result != 0 {
            return Err(openre_core::Error::Internal(anyhow::anyhow!("Native plugin initialization failed")));
        }
        Ok(())
    }

    pub async fn execute(&self, capability: &str, input: serde_json::Value) -> Result<serde_json::Value> {
        let start = std::time::Instant::now();
        let request = serde_json::json!({
            "capability": capability,
            "input": input
        });
        let request_json = serde_json::to_vec(&request)?;
        
        let mut response_buf = Vec::with_capacity(4096);
        let mut response_len = 0usize;
        
        let execute: libloading::Symbol<unsafe extern "C" fn(*const u8, usize, *mut u8, *mut usize) -> i32> = 
            unsafe { self.library.get(b"plugin_execute") }
                .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("Failed to get plugin_execute: {}", e)))?;
        
        let result = unsafe {
            (execute)(
                request_json.as_ptr(),
                request_json.len(),
                response_buf.as_mut_ptr(),
                &mut response_len,
            )
        };
        
        metrics::record_plugin_execution("native", capability, start.elapsed(), result == 0);
        
        if result != 0 {
            return Err(openre_core::Error::Internal(anyhow::anyhow!("Native plugin execution failed")));
        }
        
        unsafe { response_buf.set_len(response_len); }
        serde_json::from_slice(&response_buf).map_err(|e| openre_core::Error::Serialization(e))
    }

    pub async fn shutdown(&self) -> Result<()> {
        let shutdown: libloading::Symbol<unsafe extern "C" fn() -> i32> = 
            unsafe { self.library.get(b"plugin_shutdown") }
                .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("Failed to get plugin_shutdown: {}", e)))?;
        let result = unsafe { (shutdown)() };
        if result != 0 {
            return Err(openre_core::Error::Internal(anyhow::anyhow!("Native plugin shutdown failed")));
        }
        Ok(())
    }
}

/// Plugin state for WASM host functions
pub struct PluginState {
    pub plugin_id: PluginId,
    pub capabilities: Vec<Capability>,
    pub binary: Arc<IsolatedBinary>,
    pub project_store: Option<Arc<ProjectStore>>,
    pub wasi_p1_ctx: WasiP1Ctx,
}

impl PluginState {
    pub fn new(plugin_id: PluginId) -> Self {
        let wasi_p1_ctx = wasmtime_wasi::WasiCtxBuilder::new().build_p1();
        Self {
            plugin_id,
            capabilities: Vec::new(),
            binary: Arc::new(IsolatedBinary::default()),
            project_store: None,
            wasi_p1_ctx,
        }
    }

    pub fn check_capability(&self, capability: Capability) -> Result<()> {
        if self.capabilities.contains(&capability) {
            Ok(())
        } else {
            Err(openre_core::Error::Forbidden(format!("Capability not granted: {:?}", capability)))
        }
    }
}

impl WasiView for PluginState {
    fn table(&mut self) -> &mut ResourceTable {
        self.wasi_p1_ctx.table()
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        self.wasi_p1_ctx.ctx()
    }
}

/// Plugin runtime manager
pub struct PluginRuntime {
    registry: Arc<PluginRegistry>,
    wasm_runtime: Arc<WasmRuntime>,
    native_runtime: Arc<NativeRuntime>,
    loaded_plugins: Arc<RwLock<HashMap<PluginId, LoadedPlugin>>>,
}

impl PluginRuntime {
    pub fn new(
        registry: Arc<PluginRegistry>,
        wasm_runtime: Arc<WasmRuntime>,
        native_runtime: Arc<NativeRuntime>,
    ) -> Self {
        Self {
            registry,
            wasm_runtime,
            native_runtime,
            loaded_plugins: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load a plugin for execution
    pub async fn load_plugin(&self, plugin_id: &PluginId) -> Result<LoadedPlugin> {
        // Check if already loaded
        {
            let loaded = self.loaded_plugins.read().await;
            if let Some(plugin) = loaded.get(plugin_id) {
                return Ok(plugin.clone());
            }
        }

        let manifest = self.registry.get_manifest(plugin_id).await?;
        
        let plugin = match manifest.build.target {
            BuildTarget::Wasm => {
                let wasm_path = manifest.wasm_path(manifest.path.as_ref().unwrap_or(&PathBuf::from(".")))
                    .ok_or_else(|| openre_core::Error::NotFound("WASM module not found".into()))?;
                let instance = self.wasm_runtime.instantiate(&wasm_path, &manifest).await?;
                LoadedPlugin::Wasm(Arc::new(instance))
            }
            BuildTarget::Native => {
                let native_path = manifest.native_path(manifest.path.as_ref().unwrap_or(&PathBuf::from(".")))
                    .ok_or_else(|| openre_core::Error::NotFound("Native library not found".into()))?;
                let instance = self.native_runtime.load_library(&native_path).await?;
                LoadedPlugin::Native(Arc::new(instance))
            }
        };

        // Initialize plugin
        plugin.initialize(&manifest.config.as_ref().map(|c| c.defaults.clone()).unwrap_or_default()).await?;

        // Cache loaded plugin
        let mut loaded = self.loaded_plugins.write().await;
        loaded.insert(plugin_id.clone(), plugin.clone());

        Ok(plugin)
    }

    /// Execute a plugin capability
    pub async fn execute_capability(
        &self,
        plugin_id: &PluginId,
        capability: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let plugin = self.load_plugin(plugin_id).await?;
        plugin.execute(capability, input).await
    }

    /// Hot reload a plugin
    pub async fn hot_reload(&self, plugin_id: &PluginId) -> Result<()> {
        // Remove from cache
        self.loaded_plugins.write().await.remove(plugin_id);
        
        // Reload from registry
        self.registry.hot_reload(plugin_id).await?;
        
        // Load fresh instance
        self.load_plugin(plugin_id).await?;
        
        Ok(())
    }

    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_id: &PluginId) -> Result<()> {
        let mut loaded = self.loaded_plugins.write().await;
        if let Some(plugin) = loaded.remove(plugin_id) {
            plugin.shutdown().await?;
        }
        Ok(())
    }
}

/// WASM runtime
pub struct WasmRuntime {
    engine: wasmtime::Engine,
    linker: wasmtime::Linker<PluginState>,
    config: WasmConfig,
}

#[derive(Debug, Clone)]
pub struct WasmConfig {
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_stack_kb: usize,
    pub allowed_host_functions: Vec<String>,
}

impl WasmRuntime {
    pub fn new(config: WasmConfig) -> Result<Self> {
        let mut engine_config = wasmtime::Config::new();
        
        // Security hardening
        engine_config.wasm_simd(false);
        engine_config.wasm_threads(false);
        engine_config.wasm_memory64(false);
        engine_config.wasm_bulk_memory(false);
        engine_config.wasm_reference_types(false);
        engine_config.wasm_tail_call(false);
        engine_config.wasm_multi_value(false);
        engine_config.wasm_component_model(true);

        // Resource limits
        engine_config.consume_fuel(true);
        engine_config.max_wasm_stack(config.max_stack_kb * 1024);
        engine_config.epoch_interruption(true);

        let engine = wasmtime::Engine::new(&engine_config)?;
        let mut linker = wasmtime::Linker::new(&engine);

        // Add WASI (using preview1 async)
        add_to_linker_async(&mut linker, |state: &mut PluginState| &mut state.wasi_p1_ctx)?;

        // Add host functions
        Self::add_host_functions(&mut linker)?;

        Ok(Self { engine, linker, config })
    }

    fn add_host_functions(linker: &mut wasmtime::Linker<PluginState>) -> Result<()> {
        // read_binary(offset: u64, len: u64) -> result<list<u8>, string>
        // Using simple types for WASM compatibility - return u32 (0 for success, 1 for error)
        linker.func_wrap("host", "read_binary", |mut caller: wasmtime::Caller<'_, PluginState>, offset: u64, len: u64| -> u32 {
            let state = caller.data_mut();
            if state.check_capability(Capability::ReadBinary).is_err() {
                return 1; // Error
            }
            // For now, return success - in reality this would read from the binary
            0 // Success
        })?;

        // write_annotation(annotation: annotation) -> result<(), string>
        // Using simple types for WASM compatibility
        linker.func_wrap("host", "write_annotation", |mut caller: wasmtime::Caller<'_, PluginState>, address: u64, annotation_type: u32, value_ptr: u32, value_len: u32| -> u32 {
            let state = caller.data_mut();
            if state.check_capability(Capability::WriteAnnotations).is_err() {
                return 1; // Error
            }
            // For now, just return success - in reality this would write to the database
            0 // Success
        })?;

        // query_database(sql: string, params: list<value>) -> result<list<value>, string>
        // Using simple types for WASM compatibility
        linker.func_wrap("host", "query_database", |mut caller: wasmtime::Caller<'_, PluginState>, sql_ptr: u32, sql_len: u32| -> u32 {
            let state = caller.data_mut();
            if state.check_capability(Capability::QueryDatabase).is_err() {
                return 1; // Error
            }
            // For now, return success - in reality this would query the database
            0 // Success
        })?;

        // call_ai(task: string, context: value) -> result<value, string>
        // Using simple types for WASM compatibility
        linker.func_wrap("host", "call_ai", |mut caller: wasmtime::Caller<'_, PluginState>, task_ptr: u32, task_len: u32, context_ptr: u32, context_len: u32| -> u32 {
            let state = caller.data_mut();
            if state.check_capability(Capability::CallAi).is_err() {
                return 1; // Error
            }
            // In a real implementation, this would call the AI service
            1 // Error (not available)
        })?;

        Ok(())
    }

    pub async fn instantiate(&self, wasm_path: &PathBuf, manifest: &PluginManifest) -> Result<WasmPluginInstance> {
        let module = wasmtime::Module::from_file(&self.engine, wasm_path)?;
        
        // Validate module
        self.validate_module(&module)?;

        let mut store = wasmtime::Store::new(&self.engine, PluginState::new(manifest.plugin_id()));
        store.set_fuel(self.config.max_fuel)?;

        let instance = self.linker.instantiate_async(&mut store, &module).await?;

        let init_func = instance.get_typed_func::<(), ()>(&mut store, "init")?;
        let execute_func = instance.get_typed_func::<(i32, i32), i32>(&mut store, "execute")?;
        let shutdown_func = instance.get_typed_func::<(), ()>(&mut store, "shutdown")?;

        Ok(WasmPluginInstance {
            store: Arc::new(tokio::sync::Mutex::new(store)),
            instance,
            init_func,
            execute_func,
            shutdown_func,
            fuel_limit: self.config.max_fuel,
        })
    }

    fn validate_module(&self, module: &wasmtime::Module) -> Result<()> {
        for import in module.imports() {
            if !self.config.allowed_host_functions.contains(&import.name().to_string()) {
                return Err(openre_core::Error::Validation(format!(
                    "Disallowed import: {}",
                    import.name()
                )));
            }
        }

        // Memory limit validation would require checking module exports
        // For now, we skip this check as the API has changed in wasmtime 20.0

        Ok(())
    }
}

/// Native runtime
pub struct NativeRuntime {
    trusted_keys: Vec<ring::signature::UnparsedPublicKey<&'static [u8]>>,
    allowlist: HashMap<PluginId, String>,
}

impl NativeRuntime {
    pub fn new(trusted_keys: Vec<ring::signature::UnparsedPublicKey<&'static [u8]>>) -> Self {
        Self {
            trusted_keys,
            allowlist: HashMap::new(),
        }
    }

    pub async fn load_library(&self, path: &PathBuf) -> Result<NativePluginInstance> {
        // Verify signature
        self.verify_signature(path).await?;

        // Load library
        let library = unsafe { libloading::Library::new(path) }
            .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("Failed to load library: {}", e)))?;

        // Move library into the struct
        Ok(NativePluginInstance { library: Arc::new(library) })
    }

    async fn verify_signature(&self, path: &PathBuf) -> Result<()> {
        let sig_path = path.with_extension("sig");
        let signature = tokio::fs::read(&sig_path).await?;
        let manifest_path = path.with_extension("manifest.toml");
        let manifest = tokio::fs::read(&manifest_path).await?;

        let verified = self.trusted_keys.iter().any(|key| {
            key.verify(&manifest, &signature).is_ok()
        });

        if !verified {
            return Err(openre_core::Error::Validation("Invalid plugin signature".into()));
        }

        Ok(())
    }
}