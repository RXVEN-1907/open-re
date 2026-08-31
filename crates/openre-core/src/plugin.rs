//! Minimal plugin types and registry for open-re
//!
//! This provides the basic plugin types and registry functionality
//! that were previously in openre-plugins. The full plugin system
//! with WASM runtime is not yet implemented.

use crate::error::{Error, OpenreResult as Result};
use crate::ids::{Capability, PluginId, PluginType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

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
    pub path: Option<PathBuf>, // Added for runtime use
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
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let manifest_path = dir.join("plugin.toml");
        if !manifest_path.exists() {
            return Err(Error::NotFound(format!(
                "Plugin manifest not found: {}",
                manifest_path.display()
            )));
        }

        let content = std::fs::read_to_string(&manifest_path)?;
        let manifest: PluginManifest = toml::from_str(&content)
            .map_err(|e| Error::Internal(anyhow::anyhow!("TOML parse error: {}", e)))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate the manifest
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::Validation("Plugin name cannot be empty".into()));
        }
        if self.version.is_empty() {
            return Err(Error::Validation("Plugin version cannot be empty".into()));
        }
        if self.plugin.capabilities.is_empty() {
            return Err(Error::Validation("Plugin must declare at least one capability".into()));
        }

        // Validate entry points exist
        match self.build.target {
            BuildTarget::Wasm => {
                if self.plugin.entry.wasm.is_none() {
                    return Err(Error::Validation(
                        "WASM plugin must specify wasm entry point".into(),
                    ));
                }
            }
            BuildTarget::Native => {
                if self.plugin.entry.native.is_empty() {
                    return Err(Error::Validation(
                        "Native plugin must specify native entry points".into(),
                    ));
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
    pub fn wasm_path(&self, base_dir: &Path) -> Option<PathBuf> {
        self.plugin.entry.wasm.as_ref().map(|p| base_dir.join(p))
    }

    /// Get the native library path for current OS
    pub fn native_path(&self, base_dir: &Path) -> Option<PathBuf> {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PluginSource {
    Builtin { name: String },
    Local { path: PathBuf },
    Remote { registry_url: String, version: String, checksum: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginStatus {
    Active,
    Inactive,
    Error,
    Updating,
}

/// Plugin registry entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub manifest: PluginManifest,
    pub installed_path: Option<PathBuf>,
    pub enabled: bool,
    pub source: PluginSource,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub local_path: PathBuf,
    pub remote_registries: Vec<String>,
    pub auto_update: bool,
    pub verify_signatures: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        let data_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("openre");

        Self {
            local_path: data_dir.join("plugins"),
            remote_registries: vec!["https://plugins.openre.dev".to_string()],
            auto_update: false,
            verify_signatures: true,
        }
    }
}

/// Plugin Registry
pub struct PluginRegistry {
    config: RegistryConfig,
    entries: Arc<RwLock<HashMap<PluginId, RegistryEntry>>>,
}

impl PluginRegistry {
    pub fn new(config: RegistryConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.local_path)?;

        let registry = Self { config, entries: Arc::new(RwLock::new(HashMap::new())) };

        registry.load_local()?;
        Ok(registry)
    }

    fn load_local(&self) -> Result<()> {
        let entries_dir = self.config.local_path.join("entries");
        if !entries_dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(entries_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = std::fs::read_to_string(&path)?;
                let entry: RegistryEntry = serde_json::from_str(&content)?;
                let id = entry.manifest.plugin_id();
                self.entries.blocking_write().insert(id, entry);
            }
        }
        Ok(())
    }

    pub async fn install(&self, source: PluginSource) -> Result<PluginId> {
        match source {
            PluginSource::Local { path } => self.install_local(path).await,
            PluginSource::Remote { registry_url, version, checksum } => {
                self.install_remote(&registry_url, &version, &checksum).await
            }
            PluginSource::Builtin { name } => self.enable_builtin(&name).await,
        }
    }

    async fn install_local(&self, path: PathBuf) -> Result<PluginId> {
        // Read manifest
        let manifest_path = path.join("plugin.toml");
        let manifest_content = tokio::fs::read_to_string(manifest_path).await?;
        let manifest: PluginManifest = toml::from_str(&manifest_content)?;
        let plugin_id = manifest.plugin_id();

        // Copy to local registry
        let install_path = self.config.local_path.join("installed").join(plugin_id.to_string());
        tokio::fs::create_dir_all(&install_path).await?;

        // Save entry
        let entry = RegistryEntry {
            manifest: manifest.clone(),
            installed_path: Some(install_path),
            enabled: true,
            source: PluginSource::Local { path },
            installed_at: chrono::Utc::now(),
            updated_at: None,
        };

        self.save_entry(&entry).await?;
        self.entries.write().await.insert(plugin_id, entry);

        Ok(plugin_id)
    }

    async fn install_remote(
        &self,
        _registry_url: &str,
        _version: &str,
        _checksum: &str,
    ) -> Result<PluginId> {
        // Download from remote registry
        // Verify checksum
        // Install locally
        Err(Error::NotImplemented("Remote plugin installation not yet implemented".into()))
    }

    async fn enable_builtin(&self, _name: &str) -> Result<PluginId> {
        // Enable built-in plugin
        Err(Error::NotImplemented("Builtin plugin enabling not yet implemented".into()))
    }

    async fn save_entry(&self, entry: &RegistryEntry) -> Result<()> {
        let entries_dir = self.config.local_path.join("entries");
        tokio::fs::create_dir_all(&entries_dir).await?;

        let path = entries_dir.join(format!("{}.json", entry.manifest.plugin_id()));
        let content = serde_json::to_string_pretty(entry)?;
        tokio::fs::write(path, content).await?;
        Ok(())
    }

    pub async fn list_all(&self) -> Vec<RegistryEntry> {
        self.entries.read().await.values().cloned().collect()
    }

    pub async fn get_metadata(&self, id: &PluginId) -> Result<PluginMetadata> {
        let entry = self
            .entries
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("Plugin not found: {}", id)))?;

        Ok(PluginMetadata {
            id: *id,
            manifest: entry.manifest,
            source: entry.source,
            path: entry.installed_path.unwrap_or_default(),
            installed_at: entry.installed_at,
            status: if entry.enabled { PluginStatus::Active } else { PluginStatus::Inactive },
        })
    }

    pub async fn register(&self, metadata: PluginMetadata) -> Result<()> {
        let entry = RegistryEntry {
            manifest: metadata.manifest,
            installed_path: Some(metadata.path),
            enabled: matches!(metadata.status, PluginStatus::Active),
            source: metadata.source,
            installed_at: metadata.installed_at,
            updated_at: None,
        };

        self.save_entry(&entry).await?;
        self.entries.write().await.insert(metadata.id, entry);
        Ok(())
    }

    pub async fn unregister(&self, id: &PluginId) -> Result<()> {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.remove(id) {
            if let Some(path) = entry.installed_path {
                tokio::fs::remove_dir_all(path).await.ok();
            }
            let entry_path = self.config.local_path.join("entries").join(format!("{}.json", id));
            tokio::fs::remove_file(entry_path).await.ok();
        }
        Ok(())
    }

    pub async fn enable(&self, id: &PluginId) -> Result<()> {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(id) {
            entry.enabled = true;
            entry.updated_at = Some(chrono::Utc::now());
            self.save_entry(entry).await?;
        }
        Ok(())
    }

    pub async fn disable(&self, id: &PluginId) -> Result<()> {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(id) {
            entry.enabled = false;
            entry.updated_at = Some(chrono::Utc::now());
            self.save_entry(entry).await?;
        }
        Ok(())
    }
}

/// Plugin capability set (alias for compatibility)
pub type CapabilitySet = Vec<Capability>;

/// Capability request (for SDK compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub capability: Capability,
    pub args: std::collections::HashMap<String, serde_json::Value>,
}

/// Capability response (for SDK compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResponse {
    pub success: bool,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl CapabilityResponse {
    pub fn success(output: serde_json::Value) -> Self {
        Self { success: true, output: Some(output), error: None }
    }

    pub fn failure(error: String) -> Self {
        Self { success: false, output: None, error: Some(error) }
    }
}

/// Plugin metadata for SDK (simpler than registry metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSdkMetadata {
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

/// Command registration (for SDK compatibility)
#[derive(Debug, Clone)]
pub struct CommandRegistration {
    pub name: String,
    pub description: String,
    pub handler: fn(CommandContext) -> anyhow::Result<CommandResult>,
}

/// Command context (for SDK compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandContext {
    pub plugin_id: String,
    pub args: std::collections::HashMap<String, serde_json::Value>,
    pub capabilities: Vec<Capability>,
}

/// Command result (for SDK compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Plugin trait (for SDK compatibility)
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn metadata(&self) -> PluginSdkMetadata;
    fn capabilities(&self) -> CapabilitySet;
    fn commands(&self) -> Vec<CommandRegistration>;
    async fn initialize(&mut self, config: serde_json::Value) -> anyhow::Result<()>;
    async fn shutdown(&mut self) -> anyhow::Result<()>;
}

/// Plugin initialization info (for SDK compatibility)
#[derive(Debug, Clone)]
pub struct PluginInitInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub init_fn: fn() -> Box<dyn Plugin>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_manifest_validation() {
        let manifest = PluginManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test plugin".to_string(),
            author: "Test".to_string(),
            license: "MIT".to_string(),
            repository: None,
            homepage: None,
            plugin: PluginConfig {
                r#type: PluginType::Analyzer,
                capabilities: vec![Capability::ReadBinary],
                min_core_version: "0.1.0".to_string(),
                max_core_version: "1.0.0".to_string(),
                entry: EntryConfig {
                    wasm: Some("plugin.wasm".to_string()),
                    native: HashMap::new(),
                },
            },
            build: BuildConfig {
                target: BuildTarget::Wasm,
                rust_version: "1.70".to_string(),
                features: vec![],
            },
            dependencies: HashMap::new(),
            resources: ResourceConfig {
                max_memory_mb: 100,
                max_fuel: 1000000,
                max_execution_time_secs: 30,
            },
            ui: None,
            config: None,
            path: None,
        };

        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_plugin_manifest_empty_name() {
        let manifest = PluginManifest {
            name: "".to_string(),
            version: "1.0.0".to_string(),
            description: "Test plugin".to_string(),
            author: "Test".to_string(),
            license: "MIT".to_string(),
            repository: None,
            homepage: None,
            plugin: PluginConfig {
                r#type: PluginType::Analyzer,
                capabilities: vec![Capability::ReadBinary],
                min_core_version: "0.1.0".to_string(),
                max_core_version: "1.0.0".to_string(),
                entry: EntryConfig {
                    wasm: Some("plugin.wasm".to_string()),
                    native: HashMap::new(),
                },
            },
            build: BuildConfig {
                target: BuildTarget::Wasm,
                rust_version: "1.70".to_string(),
                features: vec![],
            },
            dependencies: HashMap::new(),
            resources: ResourceConfig {
                max_memory_mb: 100,
                max_fuel: 1000000,
                max_execution_time_secs: 30,
            },
            ui: None,
            config: None,
            path: None,
        };

        assert!(manifest.validate().is_err());
    }
}
