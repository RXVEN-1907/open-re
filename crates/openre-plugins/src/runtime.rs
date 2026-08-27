//! WASM Plugin Runtime using Wasmtime

use anyhow::Result;
use std::sync::Arc;
use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{Component, Engine, Linker, Module, Store, WasiCtxBuilder};

use crate::{Capability, CapabilityRequest, CapabilityResponse, PluginManifest};

/// WASM Plugin Runtime with capability-based security
pub struct WasmRuntime {
    engine: Engine,
    component_linker: ComponentLinker<WasmRuntimeState>,
}

struct WasmRuntimeState {
    allowed_capabilities: Vec<Capability>,
    plugin_id: String,
}

impl WasmRuntime {
    pub fn new(allowed_capabilities: Vec<Capability>) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        config.consume_fuel(true);

        let engine = Engine::new(&config)?;

        let mut linker = ComponentLinker::new(&engine);
        // Add WASI support
        wasmtime_wasi::preview2::command::add_to_linker(
            &mut linker,
            |state: &mut WasmRuntimeState| state,
        )?;

        Ok(Self {
            engine,
            component_linker: linker,
        })
    }

    pub async fn load_plugin(&self, wasm_bytes: &[u8], plugin_id: String) -> Result<LoadedPlugin> {
        let component = Component::new(&self.engine, wasm_bytes)?;

        let mut store = Store::new(
            &self.engine,
            WasmRuntimeState {
                allowed_capabilities: vec![],
                plugin_id: plugin_id.clone(),
            },
        );

        // Set fuel limit (10M instructions)
        store.add_fuel(10_000_000)?;

        let instance = self
            .component_linker
            .instantiate_async(&mut store, &component)
            .await?;

        Ok(LoadedPlugin {
            plugin_id,
            instance,
            store,
        })
    }

    pub async fn call_plugin(
        &self,
        plugin: &mut LoadedPlugin,
        function: &str,
        args: &[u8],
    ) -> Result<Vec<u8>> {
        // Implementation for calling plugin functions
        todo!("Implement plugin function calling")
    }
}

pub struct LoadedPlugin {
    plugin_id: String,
    instance: wasmtime::component::Instance,
    store: Store<WasmRuntimeState>,
}

impl LoadedPlugin {
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }
}
