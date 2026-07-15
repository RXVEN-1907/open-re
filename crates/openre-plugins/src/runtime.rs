//! Plugin runtime for open-re

use crate::{manifest::*, capability::*};
use openre_core::error::Result;
use openre_core::ids::{PluginId, Capability};
use openre_storage::ProjectStore;
use openre_telemetry::metrics;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Loaded plugin instance
pub enum LoadedPlugin {
    Wasm(WasmPluginInstance),
    Native(NativePluginInstance),
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
    store: wasmtime::Store<PluginState>,
    instance: wasmtime::Instance,
    init_func: wasmtime::TypedFunc<(), ()>,
    execute_func: wasmtime::TypedFunc<(String, serde_json::Value), serde_json::Value>,
    shutdown_func: wasmtime::TypedFunc<(), ()>,
    fuel_limit: u64,
}

impl WasmPluginInstance {
    pub async fn initialize(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        let config_json = serde_json::to_string(config)?;
        // In a real implementation, we'd pass config to the plugin
        self.init_func.call_async(&mut self.store.clone(), ()).await?;
        Ok(())
    }

    pub async fn execute(&self, capability: &str, input: serde_json::Value) -> Result<serde_json::Value> {
        let start = std::time::Instant::now();
        let result = self.execute_func.call_async(&mut self.store.clone(), (capability.to_string(), input)).await;
        metrics::record_plugin_execution("wasm", capability, start.elapsed(), result.is_ok());
        result.map_err(|e| openre_core::Error::Internal(e.into()))
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.shutdown_func.call_async(&mut self.store.clone(), ()).await?;
        Ok(())
    }
}

/// Native plugin instance
pub struct NativePluginInstance {
    library: libloading::Library,
    init: libloading::Symbol<unsafe extern "C" fn(*const u8, usize) -> i32>,
    execute: libloading::Symbol<unsafe extern "C" fn(*const u8, usize, *mut u8, *mut usize) -> i32>,
    shutdown: libloading::Symbol<unsafe extern "C" fn() -> i32>,
}

impl NativePluginInstance {
    pub async fn initialize(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        let config_json = serde_json::to_vec(config)?;
        let result = unsafe { (self.init)(config_json.as_ptr(), config_json.len()) };
        if result != 0 {
            return Err(openre_core::Error::Internal("Native plugin initialization failed".into()));
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
        
        let result = unsafe {
            (self.execute)(
                request_json.as_ptr(),
                request_json.len(),
                response_buf.as_mut_ptr(),
                &mut response_len,
            )
        };
        
        metrics::record_plugin_execution("native", capability, start.elapsed(), result == 0);
        
        if result != 0 {
            return Err(openre_core::Error::Internal("Native plugin execution failed".into()));
        }
        
        unsafe { response_buf.set_len(response_len); }
        serde_json::from_slice(&response_buf).map_err(|e| openre_core::Error::Serialization(e))
    }

    pub async fn shutdown(&self) -> Result<()> {
        let result = unsafe { (self.shutdown)() };
        if result != 0 {
            return Err(openre_core::Error::Internal("Native plugin shutdown failed".into()));
        }
        Ok(())
    }
}

/// Plugin state for WASM host functions
pub struct PluginState {
    pub plugin_id: PluginId,
    pub capabilities: Vec<Capability>,
    pub binary: Arc<crate::IsolatedBinary>,
    pub project_store: Arc<ProjectStore>,
    pub wasi_ctx: wasmtime_wasi::WasiCtx,
}

impl PluginState {
    pub fn new(plugin_id: PluginId) -> Self {
        Self {
            plugin_id,
            capabilities: Vec::new(),
            binary: Arc::new(crate::IsolatedBinary::default()),
            project_store: Arc::new(ProjectStore::default()),
            wasi_ctx: wasmtime_wasi::WasiCtx::new(),
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
                let wasm_path = manifest.wasm_path(&manifest.path)
                    .ok_or_else(|| openre_core::Error::NotFound("WASM module not found".into()))?;
                let instance = self.wasm_runtime.instantiate(&wasm_path, &manifest).await?;
                LoadedPlugin::Wasm(instance)
            }
            BuildTarget::Native => {
                let native_path = manifest.native_path(&manifest.path)
                    .ok_or_else(|| openre_core::Error::NotFound("Native library not found".into()))?;
                let instance = self.native_runtime.load_library(&native_path).await?;
                LoadedPlugin::Native(instance)
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
        engine_config.wasm_extended_const(false);
        engine_config.wasm_multi_value(false);
        engine_config.wasm_component_model(true);
        engine_config.wasm_component_model_async(true);

        // Resource limits
        engine_config.consume_fuel(true);
        engine_config.max_wasm_stack(config.max_stack_kb * 1024);
        engine_config.epoch_interruption(true);

        let engine = wasmtime::Engine::new(&engine_config)?;
        let mut linker = wasmtime::Linker::new(&engine);

        // Add WASI
        wasmtime_wasi::add_to_linker(&mut linker, |state: &mut PluginState| &mut state.wasi_ctx)?;

        // Add host functions
        Self::add_host_functions(&mut linker)?;

        Ok(Self { engine, linker, config })
    }

    fn add_host_functions(linker: &mut wasmtime::Linker<PluginState>) -> Result<()> {
        // read_binary(offset: u64, len: u64) -> result<list<u8>, string>
        linker.func_wrap("host", "read_binary", |mut caller: wasmtime::Caller<'_, PluginState>, offset: u64, len: u64| {
            let state = caller.data_mut();
            state.check_capability(Capability::ReadBinary)?;
            state.binary.read_at(offset, len as usize)
                .map_err(|e| format!("Read error: {}", e))
        })?;

        // write_annotation(annotation: annotation) -> result<(), string>
        linker.func_wrap("host", "write_annotation", async |mut caller: wasmtime::Caller<'_, PluginState>, annotation: crate::Annotation| {
            let state = caller.data_mut();
            state.check_capability(Capability::WriteAnnotations)?;
            state.project_store.write_annotation(&annotation).await
                .map_err(|e| format!("Write error: {}", e))
        })?;

        // query_database(sql: string, params: list<value>) -> result<list<value>, string>
        linker.func_wrap("host", "query_database", async |mut caller: wasmtime::Caller<'_, PluginState>, sql: String, params: Vec<serde_json::Value>| {
            let state = caller.data_mut();
            state.check_capability(Capability::QueryDatabase)?;
            if !sql.trim().to_uppercase().starts_with("SELECT") {
                return Err("Only SELECT queries allowed".to_string());
            }
            state.project_store.query(&sql, params).await
                .map_err(|e| format!("Query error: {}", e))
        })?;

        // call_ai(task: string, context: value) -> result<value, string>
        linker.func_wrap("host", "call_ai", async |mut caller: wasmtime::Caller<'_, PluginState>, task: String, context: serde_json::Value| {
            let state = caller.data_mut();
            state.check_capability(Capability::CallAi)?;
            // In a real implementation, this would call the AI service
            Err("AI service not available in WASM host".to_string())
        })?;

        Ok(())
    }

    pub async fn instantiate(&self, wasm_path: &PathBuf, manifest: &PluginManifest) -> Result<WasmPluginInstance> {
        let module = wasmtime::Module::from_file(&self.engine, wasm_path)?;
        
        // Validate module
        self.validate_module(&module)?;

        let mut store = wasmtime::Store::new(&self.engine, PluginState::new(manifest.plugin_id()));
        store.add_fuel(self.config.max_fuel)?;
        store.limiter(|store| store.data().fuel_consumed());

        let instance = self.linker.instantiate_async(&mut store, &module).await?;

        let init_func = instance.get_typed_func::<(), ()>(&mut store, "init")?;
        let execute_func = instance.get_typed_func::<(String, serde_json::Value), serde_json::Value>(&mut store, "execute")?;
        let shutdown_func = instance.get_typed_func::<(), ()>(&mut store, "shutdown")?;

        Ok(WasmPluginInstance {
            store,
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

        if let Some(memory) = module.memory() {
            if memory.maximum().unwrap_or(u64::MAX) > self.config.max_memory_mb * 1024 * 1024 {
                return Err(openre_core::Error::Validation("Memory limit exceeded".into()));
            }
        }

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
        let library = unsafe { libloading::Library::new(path) }?;

        // Get entry points
        let init: libloading::Symbol<unsafe extern "C" fn(*const u8, usize) -> i32> = 
            unsafe { library.get(b"plugin_init") }?;
        let execute: libloading::Symbol<unsafe extern "C" fn(*const u8, usize, *mut u8, *mut usize) -> i32> = 
            unsafe { library.get(b"plugin_execute") }?;
        let shutdown: libloading::Symbol<unsafe extern "C" fn() -> i32> = 
            unsafe { library.get(b"plugin_shutdown") }?;

        Ok(NativePluginInstance { library, init, execute, shutdown })
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