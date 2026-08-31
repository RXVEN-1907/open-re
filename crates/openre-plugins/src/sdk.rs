//! Plugin SDK - Macros and helpers for plugin development
//!
//! Note: To use the procedural macros (derive_plugin_manifest, plugin_capability,
//! plugin_command, plugin_init), add `openre-plugins-macros` as a dependency:
//!
//! ```toml
//! [dependencies]
//! openre-plugins-macros = { path = "../crates/openre-plugins-macros" }
//! ```

/// Helper types for SDK
pub mod sdk {
    use openre_core::ids::{Capability, CapabilitySet, PluginId};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginInitInfo {
        pub name: &'static str,
        pub version: &'static str,
        #[serde(skip)]
        pub init_fn: Option<fn() -> PluginInstance>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandRegistration {
        pub name: String,
        pub description: String,
        #[serde(skip)]
        pub handler: Option<fn(CommandContext) -> anyhow::Result<CommandResult>>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandContext {
        pub plugin_id: String,
        pub args: HashMap<String, serde_json::Value>,
        pub capabilities: Vec<Capability>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandResult {
        pub success: bool,
        pub output: Option<serde_json::Value>,
        pub error: Option<String>,
    }

    pub type PluginInstance = Box<dyn Plugin>;

    pub trait Plugin: Send + Sync {
        fn metadata(&self) -> PluginMetadata;
        fn capabilities(&self) -> CapabilitySet;
        fn commands(&self) -> Vec<CommandRegistration>;
        fn initialize(&mut self, config: serde_json::Value) -> anyhow::Result<()>;
        fn shutdown(&mut self) -> anyhow::Result<()>;
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginMetadata {
        pub name: String,
        pub version: String,
        pub description: String,
        pub author: String,
        pub license: String,
        pub repository: String,
        pub homepage: Option<String>,
        pub categories: Vec<String>,
        pub keywords: Vec<String>,
    }
}
