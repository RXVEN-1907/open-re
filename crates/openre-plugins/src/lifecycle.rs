//! Plugin lifecycle management for open-re

use crate::sdk::{DynPlugin, PluginInstance};
use openre_core::error::OpenreResult as Result;
use openre_core::ids::{Capability, PluginId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Plugin lifecycle state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginLifecycleState {
    /// Plugin is discovered but not loaded
    Discovered,
    /// Plugin is being loaded
    Loading,
    /// Plugin is loaded and initialized
    Loaded,
    /// Plugin is running
    Running,
    /// Plugin is stopped
    Stopped,
    /// Plugin failed to load
    Failed(String),
    /// Plugin is being unloaded
    Unloading,
}

/// Plugin lifecycle manager
pub struct LifecycleManager {
    /// Plugin states
    states: Arc<RwLock<HashMap<PluginId, PluginLifecycleState>>>,
    /// Plugin instances
    instances: Arc<RwLock<HashMap<PluginId, Arc<dyn PluginInstance>>>>,
}

impl LifecycleManager {
    /// Create a new lifecycle manager
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            instances: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the current state of a plugin
    pub async fn get_state(&self, plugin_id: &PluginId) -> Option<PluginLifecycleState> {
        self.states.read().await.get(plugin_id).cloned()
    }

    /// Set the state of a plugin
    pub async fn set_state(&self, plugin_id: PluginId, state: PluginLifecycleState) {
        self.states.write().await.insert(plugin_id, state);
    }

    /// Register a plugin instance
    pub async fn register_instance(&self, plugin_id: PluginId, instance: Arc<dyn PluginInstance>) {
        self.instances.write().await.insert(plugin_id, instance);
    }

    /// Get a plugin instance
    pub async fn get_instance(&self, plugin_id: &PluginId) -> Option<Arc<dyn PluginInstance>> {
        self.instances.read().await.get(plugin_id).cloned()
    }

    /// Remove a plugin instance
    pub async fn remove_instance(&self, plugin_id: &PluginId) -> Option<Arc<dyn PluginInstance>> {
        self.instances.write().await.remove(plugin_id)
    }

    /// Initialize a plugin
    pub async fn initialize(&self, plugin_id: &PluginId, plugin: &dyn DynPlugin) -> Result<()> {
        self.set_state(plugin_id.clone(), PluginLifecycleState::Loading)
            .await;

        plugin.initialize().await?;

        self.set_state(plugin_id.clone(), PluginLifecycleState::Loaded)
            .await;
        Ok(())
    }

    /// Start a plugin
    pub async fn start(&self, plugin_id: &PluginId) -> Result<()> {
        if let Some(instance) = self.get_instance(plugin_id).await {
            self.set_state(plugin_id.clone(), PluginLifecycleState::Running)
                .await;
            instance.start().await?;
        }
        Ok(())
    }

    /// Stop a plugin
    pub async fn stop(&self, plugin_id: &PluginId) -> Result<()> {
        if let Some(instance) = self.get_instance(plugin_id).await {
            instance.stop().await?;
            self.set_state(plugin_id.clone(), PluginLifecycleState::Stopped)
                .await;
        }
        Ok(())
    }

    /// Shutdown a plugin
    pub async fn shutdown(&self, plugin_id: &PluginId) -> Result<()> {
        self.set_state(plugin_id.clone(), PluginLifecycleState::Unloading)
            .await;

        if let Some(instance) = self.remove_instance(plugin_id).await {
            instance.shutdown().await?;
        }

        self.states.write().await.remove(plugin_id);
        Ok(())
    }

    /// Check if a plugin is healthy
    pub async fn health_check(&self, plugin_id: &PluginId) -> Result<bool> {
        if let Some(instance) = self.get_instance(plugin_id).await {
            instance.health_check().await
        } else {
            Ok(false)
        }
    }

    /// Get all plugin states
    pub async fn get_all_states(&self) -> HashMap<PluginId, PluginLifecycleState> {
        self.states.read().await.clone()
    }
}

impl Default for LifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin lifecycle hooks
#[async_trait::async_trait]
pub trait LifecycleHooks: Send + Sync {
    /// Called before plugin initialization
    async fn pre_initialize(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }

    /// Called after plugin initialization
    async fn post_initialize(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }

    /// Called before plugin start
    async fn pre_start(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }

    /// Called after plugin start
    async fn post_start(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }

    /// Called before plugin stop
    async fn pre_stop(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }

    /// Called after plugin stop
    async fn post_stop(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }

    /// Called before plugin shutdown
    async fn pre_shutdown(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }

    /// Called after plugin shutdown
    async fn post_shutdown(&self, _plugin_id: &PluginId) -> Result<()> {
        Ok(())
    }
}

/// Default lifecycle hooks (no-op)
pub struct DefaultLifecycleHooks;

#[async_trait::async_trait]
impl LifecycleHooks for DefaultLifecycleHooks {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lifecycle_manager() {
        let manager = LifecycleManager::new();
        let plugin_id = PluginId::new();

        // Initial state should be None
        assert_eq!(manager.get_state(&plugin_id).await, None);

        // Set state
        manager
            .set_state(plugin_id.clone(), PluginLifecycleState::Discovered)
            .await;
        assert_eq!(
            manager.get_state(&plugin_id).await,
            Some(PluginLifecycleState::Discovered)
        );

        // Update state
        manager
            .set_state(plugin_id.clone(), PluginLifecycleState::Loaded)
            .await;
        assert_eq!(
            manager.get_state(&plugin_id).await,
            Some(PluginLifecycleState::Loaded)
        );
    }

    #[test]
    fn test_plugin_lifecycle_state() {
        assert_eq!(
            PluginLifecycleState::Discovered,
            PluginLifecycleState::Discovered
        );
        assert_ne!(
            PluginLifecycleState::Discovered,
            PluginLifecycleState::Loaded
        );
    }
}
