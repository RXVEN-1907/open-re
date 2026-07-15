//! Plugin manifest parsing and validation

use openre_core::ids::{PluginId, PluginType, Capability, FileFormat, Architecture};
use openre_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Plugin manifest (plugin.toml)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub plugin: PluginConfig,
    pub build: BuildConfig,
    pub dependencies: HashMap<String, String>,
    pub resources: ResourceConfig,
    pub ui: Option<UiConfig>,
    pub config: Option<ConfigSchema>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginConfig {
    pub r#type: PluginType,
    pub capabilities: Vec<Capability>,
    pub min_core_version: String,
    pub max_core_version: String,
    pub entry: EntryConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EntryConfig {
    pub wasm: Option<String>,
    pub native: HashMap<String, String>, // OS -> path
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildConfig {
    pub target: BuildTarget,
    pub rust_version: String,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildTarget {
    Wasm,
    Native,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceConfig {
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_execution_time_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiConfig {
    pub views: Vec<ViewExtension>,
    pub panels: Vec<PanelExtension>,
    pub menus: Vec<MenuExtension>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ViewExtension {
    pub id: String,
    pub label: String,
    pub icon: String,
    pub component: String,
    pub when: Option<String>, // Condition expression
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PanelExtension {
    pub id: String,
    pub label: String,
    pub position: PanelPosition,
    pub component: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PanelPosition {
    Left,
    Right,
    Bottom,
    Top,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MenuExtension {
    pub id: String,
    pub label: String,
    pub contexts: Vec<String>,
    pub shortcut: Option<String>,
    pub action: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigSchema {
    pub schema: String, // JSON Schema file path
    pub defaults: HashMap<String, serde_json::Value>,
}

impl PluginManifest {
    /// Load manifest from a directory
    pub fn from_dir(dir: &PathBuf) -> Result<Self> {
        let manifest_path = dir.join("plugin.toml");
        if !manifest_path.exists() {
            return Err(openre_core::Error::NotFound(format!(
                "Plugin manifest not found: {}",
                manifest_path.display()
            )));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PluginManifest = toml::from_str(&content)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate the manifest
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(openre_core::Error::Validation("Plugin name cannot be empty".into()));
        }
        if self.version.is_empty() {
            return Err(openre_core::Error::Validation("Plugin version cannot be empty".into()));
        }
        if self.plugin.capabilities.is_empty() {
            return Err(openre_core::Error::Validation("Plugin must declare at least one capability".into()));
        }

        // Validate capabilities match plugin type
        crate::capability::validate_capabilities(self.plugin.r#type, &self.plugin.capabilities)?;

        // Validate entry points exist
        match self.plugin.build.target {
            BuildTarget::Wasm => {
                if self.plugin.entry.wasm.is_none() {
                    return Err(openre_core::Error::Validation("WASM plugin must specify wasm entry point".into()));
                }
            }
            BuildTarget::Native => {
                if self.plugin.entry.native.is_empty() {
                    return Err(openre_core::Error::Validation("Native plugin must specify native entry points".into()));
                }
            }
        }

        Ok(())
    }

    /// Get the plugin ID (name@version)
    pub fn plugin_id(&self) -> PluginId {
        PluginId::from(uuid::Uuid::new_v4()) // In practice, this would be deterministic from name+version
    }

    /// Get the WASM module path
    pub fn wasm_path(&self, base_dir: &PathBuf) -> Option<PathBuf> {
        self.plugin.entry.wasm.as_ref().map(|p| base_dir.join(p))
    }

    /// Get the native library path for current OS
    pub fn native_path(&self, base_dir: &PathBuf) -> Option<PathBuf> {
        let os = std::env::consts::OS;
        self.plugin.entry.native.get(os).map(|p| base_dir.join(p))
    }
}

/// Plugin metadata for registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub id: PluginId,
    pub manifest: PluginManifest,
    pub source: PluginSource,
    pub path: PathBuf,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub status: PluginStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginSource {
    Builtin,
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginStatus {
    Active,
    Inactive,
    Error,
    Updating,
}