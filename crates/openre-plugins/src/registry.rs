//! Plugin Registry - Local and Remote

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{CapabilitySet, PluginManifest};
use openre_core::ids::PluginId;

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

/// Plugin source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PluginSource {
    Local { path: PathBuf },
    Remote { registry_url: String, version: String, checksum: String },
    Builtin { name: String },
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
                let id = PluginId::from_str(&entry.manifest.name)
                    .map_err(|_| anyhow::anyhow!("Invalid plugin ID"))?;
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
        let manifest_path = path.join("plugin.json");
        let manifest_content = tokio::fs::read_to_string(manifest_path).await?;
        let manifest: PluginManifest = serde_json::from_str(&manifest_content)?;
        let plugin_id =
            PluginId::from_str(&manifest.name).map_err(|_| anyhow::anyhow!("Invalid plugin ID"))?;

        // Copy to local registry
        let install_path = self.config.local_path.join("installed").join(&plugin_id.to_string());
        tokio::fs::create_dir_all(&install_path).await?;

        // Copy plugin files
        // ... (implementation for copying WASM binary, etc.)

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
        self.entries.write().await.insert(plugin_id.clone(), entry);

        Ok(plugin_id)
    }

    async fn install_remote(
        &self,
        registry_url: &str,
        version: &str,
        checksum: &str,
    ) -> Result<PluginId> {
        // Download from remote registry
        // Verify checksum
        // Install locally
        todo!("Implement remote plugin installation")
    }

    async fn enable_builtin(&self, name: &str) -> Result<PluginId> {
        // Enable built-in plugin
        todo!("Implement builtin plugin enabling")
    }

    async fn save_entry(&self, entry: &RegistryEntry) -> Result<()> {
        let entries_dir = self.config.local_path.join("entries");
        tokio::fs::create_dir_all(&entries_dir).await?;

        let path = entries_dir.join(format!("{}.json", entry.manifest.name));
        let content = serde_json::to_string_pretty(entry)?;
        tokio::fs::write(path, content).await?;
        Ok(())
    }

    pub async fn list(&self) -> Vec<RegistryEntry> {
        self.entries.read().await.values().cloned().collect()
    }

    pub async fn get(&self, id: &PluginId) -> Option<RegistryEntry> {
        self.entries.read().await.get(id).cloned()
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

    pub async fn uninstall(&self, id: &PluginId) -> Result<()> {
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

    pub async fn update(&self, id: &PluginId) -> Result<()> {
        // Check for updates and install
        todo!("Implement plugin update")
    }
}
