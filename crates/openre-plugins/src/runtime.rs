//! WASM Plugin Runtime using Wasmtime

use anyhow::Result;
use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

use crate::Capability;

/// WASM Plugin Runtime with capability-based security
pub struct WasmRuntime {
    engine: Engine,
    component_linker: ComponentLinker<WasmRuntimeState>,
}

struct WasmRuntimeState {
    _allowed_capabilities: Vec<Capability>,
    _plugin_id: String,
    table: ResourceTable,
    wasi: WasiCtx,
}

impl WasiView for WasmRuntimeState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

impl WasmRuntime {
    pub fn new(_allowed_capabilities: Vec<Capability>) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        config.consume_fuel(true);

        let engine = Engine::new(&config)?;

        let mut linker = ComponentLinker::new(&engine);
        // Add WASI support (preview2 bindings are at the crate root in wasmtime-wasi 20)
        wasmtime_wasi::add_to_linker_async(&mut linker)?;

        Ok(Self { engine, component_linker: linker })
    }

    pub async fn load_plugin(&self, wasm_bytes: &[u8], plugin_id: String) -> Result<LoadedPlugin> {
        let component = Component::new(&self.engine, wasm_bytes)?;

        let mut store = Store::new(
            &self.engine,
            WasmRuntimeState {
                _allowed_capabilities: vec![],
                _plugin_id: plugin_id.clone(),
                table: ResourceTable::new(),
                wasi: WasiCtxBuilder::new().build(),
            },
        );

        // Set fuel limit (10M instructions)
        store.set_fuel(10_000_000)?;

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
