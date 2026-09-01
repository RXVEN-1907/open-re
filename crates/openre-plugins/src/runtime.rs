//! WASM Plugin Runtime using Wasmtime

use anyhow::Result;
use wasmtime::{Engine, Store};

use wasmtime_wasi::{add_to_linker_sync, WasiCtx, WasiCtxBuilder, WasiView};

use crate::Capability;

/// WASM Plugin Runtime with capability-based security
pub struct WasmRuntime {
    engine: Engine,
    component_linker: wasmtime::component::Linker<WasmRuntimeState>,
}

struct WasmRuntimeState {
    _allowed_capabilities: Vec<Capability>,
    _plugin_id: String,
    wasi_ctx: WasiCtx,
    table: wasmtime::component::ResourceTable,
}

impl WasiView for WasmRuntimeState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }

    fn table(&mut self) -> &mut wasmtime::component::ResourceTable {
        &mut self.table
    }
}

impl WasmRuntime {
    pub fn new(_allowed_capabilities: Vec<Capability>) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.async_support(true);

        let engine = Engine::new(&config)?;

        let mut linker = wasmtime::component::Linker::new(&engine);
        // Add WASI support
        add_to_linker_sync(&mut linker)?;

        Ok(Self { engine, component_linker: linker })
    }

    pub async fn load_plugin(&self, wasm_bytes: &[u8], plugin_id: String) -> Result<LoadedPlugin> {
        let component = wasmtime::component::Component::new(&self.engine, wasm_bytes)?;

        let wasi_ctx = WasiCtxBuilder::new().inherit_stdio().build();

        let mut store = Store::new(
            &self.engine,
            WasmRuntimeState {
                _allowed_capabilities: vec![],
                _plugin_id: plugin_id.clone(),
                wasi_ctx,
                table: wasmtime::component::ResourceTable::new(),
            },
        );

        // Fuel limit would be set here if fuel feature was enabled
        // store.add_fuel(10_000_000)?;

        let instance = self.component_linker.instantiate_async(&mut store, &component).await?;

        Ok(LoadedPlugin { plugin_id, _instance: instance, _store: store })
    }

    pub async fn call_plugin(
        &self,
        _plugin: &mut LoadedPlugin,
        _function: &str,
        _args: &[u8],
    ) -> Result<Vec<u8>> {
        // Implementation for calling plugin functions
        todo!("Implement plugin function calling")
    }
}

pub struct LoadedPlugin {
    plugin_id: String,
    _instance: wasmtime::component::Instance,
    _store: Store<WasmRuntimeState>,
}

impl LoadedPlugin {
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }
}
