//! Plugin Lifecycle Management

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{registry::PluginSource, Capability, CapabilitySet, PluginManifest, PluginRegistry};
use openre_core::ids::PluginId;

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub settings: HashMap<String, serde_json::Value>,
    pub granted_capabilities: CapabilitySet,
    pub auto_update: bool,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            settings: HashMap::new(),
            granted_capabilities: CapabilitySet::new(),
            auto_update: false,
            updated_at: None,
        }
    }
}

/// Plugin state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginState {
    pub id: PluginId,
    pub manifest: PluginManifest,
    pub config: PluginConfig,
    pub runtime: Option<PluginRuntimeInfo>,
    pub last_error: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub stopped_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Runtime information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRuntimeInfo {
    pub wasm_path: PathBuf,
    pub instance_id: String,
    pub fuel_consumed: u64,
    pub memory_used: u64,
}

/// Lifecycle manager for plugins
pub struct PluginLifecycleManager {
    registry: Arc<PluginRegistry>,
    states: Arc<RwLock<HashMap<PluginId, PluginState>>>,
    config_dir: PathBuf,
}

impl PluginLifecycleManager {
    pub fn new(registry: Arc<PluginRegistry>, config_dir: PathBuf) -> Result<Self> {
        let manager = Self { registry, states: Arc::new(RwLock::new(HashMap::new())), config_dir };

        manager.load_states()?;
        Ok(manager)
    }

    fn load_states(&self) -> Result<()> {
        let states_file = self.config_dir.join("plugin_states.json");
        if states_file.exists() {
            let content = std::fs::read_to_string(states_file)?;
            let states: HashMap<PluginId, PluginState> = serde_json::from_str(&content)?;
            *self.states.blocking_write() = states;
        }
        Ok(())
    }

    async fn save_states(&self) -> Result<()> {
        let states_file = self.config_dir.join("plugin_states.json");
        let states = self.states.read().await.clone();
        let content = serde_json::to_string_pretty(&states)?;
        tokio::fs::write(states_file, content).await?;
        Ok(())
    }

    pub async fn install(&self, plugin_id: &PluginId, config: PluginConfig) -> Result<()> {
        // Install via registry
        self.registry.install(PluginSource::Builtin { name: plugin_id.to_string() }).await?;

        // Get manifest
        let entry = self
            .registry
            .get(plugin_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Plugin not found after install"))?;

        let state = PluginState {
            id: plugin_id.clone(),
            manifest: entry.manifest,
            config,
            runtime: None,
            last_error: None,
            started_at: None,
            stopped_at: None,
        };

        self.states.write().await.insert(plugin_id.clone(), state);
        self.save_states().await?;
        Ok(())
    }

    pub async fn enable(&self, plugin_id: &PluginId) -> Result<()> {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(plugin_id) {
            state.config.enabled = true;
            self.registry.enable(plugin_id).await?;
            self.save_states().await?;
        }
        Ok(())
    }

    pub async fn disable(&self, plugin_id: &PluginId) -> Result<()> {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(plugin_id) {
            state.config.enabled = false;
            state.runtime = None;
            state.stopped_at = Some(chrono::Utc::now());
            self.registry.disable(plugin_id).await?;
            self.save_states().await?;
        }
        Ok(())
    }

    pub async fn configure(
        &self,
        plugin_id: &PluginId,
        settings: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(plugin_id) {
            state.config.settings = settings;
            self.save_states().await?;
        }
        Ok(())
    }

    pub async fn grant_capability(
        &self,
        plugin_id: &PluginId,
        capability: Capability,
    ) -> Result<()> {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(plugin_id) {
            if state.manifest.plugin.capabilities.iter().any(|c| *c == capability) {
                state.config.granted_capabilities.add(capability);
                state.config.updated_at = Some(chrono::Utc::now());
                self.save_states().await?;
            } else {
                return Err(anyhow::anyhow!(
                    "Plugin does not declare capability: {:?}",
                    capability
                ));
            }
        }
        Ok(())
    }

    pub async fn revoke_capability(
        &self,
        plugin_id: &PluginId,
        capability: Capability,
    ) -> Result<()> {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(plugin_id) {
            state.config.granted_capabilities.remove(capability);
            self.save_states().await?;
        }
        Ok(())
    }

    pub async fn update(&self, plugin_id: &PluginId) -> Result<()> {
        self.registry.update(plugin_id).await?;

        // Reload manifest
        if let Some(entry) = self.registry.get(plugin_id).await {
            let mut states = self.states.write().await;
            if let Some(state) = states.get_mut(plugin_id) {
                state.manifest = entry.manifest;
                state.config.updated_at = Some(chrono::Utc::now());
                self.save_states().await?;
            }
        }
        Ok(())
    }

    pub async fn uninstall(&self, plugin_id: &PluginId) -> Result<()> {
        // Disable first
        self.disable(plugin_id).await?;

        // Remove from registry
        self.registry.uninstall(plugin_id).await?;

        // Remove state
        self.states.write().await.remove(plugin_id);
        self.save_states().await?;
        Ok(())
    }

    pub async fn get_state(&self, plugin_id: &PluginId) -> Option<PluginState> {
        self.states.read().await.get(plugin_id).cloned()
    }

    pub async fn list_plugins(&self) -> Vec<PluginState> {
        self.states.read().await.values().cloned().collect()
    }

    pub async fn get_enabled_plugins(&self) -> Vec<PluginState> {
        self.states.read().await.values().filter(|s| s.config.enabled).cloned().collect()
    }
}
