//! Plugin registry for open-re

use crate::{manifest::*, capability::*};
use openre_config::PluginConfig as ConfigPluginConfig;
use openre_core::error::Result;
use openre_core::ids::{PluginId, PluginType, Capability};
use openre_storage::GlobalStore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Plugin registry
pub struct PluginRegistry {
    config: ConfigPluginConfig,
    global_store: Arc<GlobalStore>,
    index: Arc<RwLock<PluginIndex>>,
    local_watcher: Option<notify::RecommendedWatcher>,
}

#[derive(Debug, Default)]
struct PluginIndex {
    by_id: HashMap<PluginId, PluginMetadata>,
    by_type: HashMap<PluginType, Vec<PluginId>>,
    by_capability: HashMap<Capability, Vec<PluginId>>,
    by_tag: HashMap<String, Vec<PluginId>>,
}

impl PluginRegistry {
    pub fn new(config: ConfigPluginConfig, global_store: Arc<GlobalStore>) -> Self {
        Self {
            config,
            global_store,
            index: Arc::new(RwLock::new(PluginIndex::default())),
            local_watcher: None,
        }
    }

    /// Initialize the registry
    pub async fn initialize(&self) -> Result<()> {
        // 1. Load built-in plugins
        self.load_builtin_plugins().await?;

        // 2. Scan local directory
        self.scan_local().await?;

        // 3. Fetch remote registries (async)
        if let Some(remote) = &self.config.remote_registry {
            self.fetch_remote(remote).await?;
        }

        // 4. Start file watcher for hot reload
        self.start_file_watcher().await?;

        Ok(())
    }

    /// Load built-in plugins
    async fn load_builtin_plugins(&self) -> Result<()> {
        // Built-in plugins are compiled into the binary
        // For now, we just register placeholder entries
        info!("Loading built-in plugins");
        Ok(())
    }

    /// Scan local plugin directory
    async fn scan_local(&self) -> Result<()> {
        let local_dir = &self.config.local_plugin_dir;
        if !local_dir.exists() {
            info!("Local plugin directory does not exist: {}", local_dir.display());
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(local_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(manifest) = PluginManifest::from_dir(&path) {
                    let metadata = PluginMetadata {
                        id: manifest.plugin_id(),
                        manifest,
                        source: PluginSource::Local,
                        path: path.clone(),
                        installed_at: chrono::Utc::now(),
                        status: PluginStatus::Active,
                    };
                    self.register(metadata).await?;
                }
            }
        }

        Ok(())
    }

    /// Fetch plugins from remote registry
    async fn fetch_remote(&self, remote: &crate::manifest::RemoteRegistryConfig) -> Result<()> {
        // In a real implementation, this would fetch from a remote registry
        info!("Fetching plugins from remote registry: {}", remote.url);
        Ok(())
    }

    /// Start file watcher for hot reload
    async fn start_file_watcher(&mut self) -> Result<()> {
        let index = self.index.clone();
        let local_dir = self.config.local_plugin_dir.clone();

        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                if matches!(event.kind, notify::EventKind::Modify(_) | notify::EventKind::Create(_) | notify::EventKind::Remove(_)) {
                    let _ = tx.try_send(event);
                }
            }
        })?;

        watcher.watch(&local_dir, notify::RecursiveMode::Recursive)?;

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                for path in event.paths {
                    if path.is_dir() && path.join("plugin.toml").exists() {
                        // Reload plugin
                        if let Ok(manifest) = PluginManifest::from_dir(&path) {
                            let mut idx = index.write().await;
                            // Remove old entry if exists
                            if let Some(old) = idx.by_id.values().find(|m| m.path == path) {
                                idx.by_id.remove(&old.id);
                                for (_, ids) in idx.by_type.iter_mut() {
                                    ids.retain(|id| id != &old.id);
                                }
                                for (_, ids) in idx.by_capability.iter_mut() {
                                    ids.retain(|id| id != &old.id);
                                }
                            }
                            // Add new entry
                            let metadata = PluginMetadata {
                                id: manifest.plugin_id(),
                                manifest,
                                source: PluginSource::Local,
                                path: path.clone(),
                                installed_at: chrono::Utc::now(),
                                status: PluginStatus::Active,
                            };
                            Self::add_to_index(&mut idx, metadata);
                        }
                    }
                }
            }
        });

        self.local_watcher = Some(watcher);
        Ok(())
    }

    fn add_to_index(index: &mut PluginIndex, metadata: PluginMetadata) {
        let id = metadata.id;
        let plugin_type = metadata.manifest.plugin.r#type;
        let capabilities = metadata.manifest.plugin.capabilities.clone();
        let tags = metadata.manifest.plugin.capabilities.iter().map(|c| format!("{:?}", c)).collect::<Vec<_>>();

        index.by_id.insert(id, metadata);
        index.by_type.entry(plugin_type).or_default().push(id);
        for cap in capabilities {
            index.by_capability.entry(cap).or_default().push(id);
        }
        for tag in tags {
            index.by_tag.entry(tag).or_default().push(id);
        }
    }

    /// Register a plugin
    pub async fn register(&self, metadata: PluginMetadata) -> Result<()> {
        // Validate manifest
        metadata.manifest.validate()?;

        // Check version compatibility
        self.check_version_compatibility(&metadata.manifest)?;

        // Add to index
        let mut index = self.index.write().await;
        Self::add_to_index(&mut index, metadata.clone());

        // Persist to database
        self.persist(&metadata).await?;

        info!("Registered plugin: {} v{}", metadata.manifest.name, metadata.manifest.version);
        Ok(())
    }

    /// Unregister a plugin
    pub async fn unregister(&self, plugin_id: &PluginId) -> Result<()> {
        let mut index = self.index.write().await;
        if let Some(metadata) = index.by_id.remove(plugin_id) {
            for (_, ids) in index.by_type.iter_mut() {
                ids.retain(|id| id != plugin_id);
            }
            for (_, ids) in index.by_capability.iter_mut() {
                ids.retain(|id| id != plugin_id);
            }
            for (_, ids) in index.by_tag.iter_mut() {
                ids.retain(|id| id != plugin_id);
            }

            // Remove from database
            self.remove_from_db(plugin_id).await?;

            info!("Unregistered plugin: {}", metadata.manifest.name);
        }
        Ok(())
    }

    /// Get plugin manifest by ID
    pub async fn get_manifest(&self, plugin_id: &PluginId) -> Result<PluginManifest> {
        let index = self.index.read().await;
        index.by_id.get(plugin_id)
            .map(|m| m.manifest.clone())
            .ok_or_else(|| openre_core::Error::NotFound(format!("Plugin not found: {}", plugin_id)))
    }

    /// Get plugin metadata by ID
    pub async fn get_metadata(&self, plugin_id: &PluginId) -> Result<PluginMetadata> {
        let index = self.index.read().await;
        index.by_id.get(plugin_id)
            .cloned()
            .ok_or_else(|| openre_core::Error::NotFound(format!("Plugin not found: {}", plugin_id)))
    }

    /// Find plugins by capability
    pub async fn find_by_capability(&self, capability: Capability) -> Vec<PluginMetadata> {
        let index = self.index.read().await;
        index.by_capability.get(&capability)
            .map(|ids| ids.iter().filter_map(|id| index.by_id.get(id)).cloned().collect())
            .unwrap_or_default()
    }

    /// Find plugins by type
    pub async fn find_by_type(&self, plugin_type: PluginType) -> Vec<PluginMetadata> {
        let index = self.index.read().await;
        index.by_type.get(&plugin_type)
            .map(|ids| ids.iter().filter_map(|id| index.by_id.get(id)).cloned().collect())
            .unwrap_or_default()
    }

    /// Search plugins by query
    pub async fn search(&self, query: &str) -> Vec<PluginMetadata> {
        let index = self.index.read().await;
        index.by_id.values()
            .filter(|m| {
                m.manifest.name.contains(query) ||
                m.manifest.description.contains(query) ||
                m.manifest.tags.iter().any(|t| t.contains(query))
            })
            .cloned()
            .collect()
    }

    /// List all plugins
    pub async fn list_all(&self) -> Vec<PluginMetadata> {
        let index = self.index.read().await;
        index.by_id.values().cloned().collect()
    }

    /// Check version compatibility
    fn check_version_compatibility(&self, manifest: &PluginManifest) -> Result<()> {
        let min_version = semver::Version::parse(&manifest.plugin.min_core_version)
            .map_err(|e| openre_core::Error::Validation(format!("Invalid min_core_version: {}", e)))?;
        let max_version = semver::Version::parse(&manifest.plugin.max_core_version)
            .map_err(|e| openre_core::Error::Validation(format!("Invalid max_core_version: {}", e)))?;
        let current_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|e| openre_core::Error::Validation(format!("Invalid current version: {}", e)))?;

        if current_version < min_version || current_version >= max_version {
            return Err(openre_core::Error::Validation(format!(
                "Plugin {} v{} requires core version >= {} and < {}, but current is {}",
                manifest.name, manifest.version, min_version, max_version, current_version
            )));
        }

        Ok(())
    }

    /// Persist plugin to database
    async fn persist(&self, metadata: &PluginMetadata) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO plugins (id, name, version, type, description, author, license, repository, manifest, source, source_url, signature, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            ON CONFLICT (name, version) DO UPDATE SET
                manifest = EXCLUDED.manifest,
                source = EXCLUDED.source,
                source_url = EXCLUDED.source_url,
                signature = EXCLUDED.signature,
                status = EXCLUDED.status,
                updated_at = NOW()
            "#,
            metadata.id.as_uuid(),
            metadata.manifest.name,
            metadata.manifest.version,
            metadata.manifest.plugin.r#type.as_str(),
            metadata.manifest.description,
            metadata.manifest.author,
            metadata.manifest.license,
            metadata.manifest.repository,
            serde_json::to_value(&metadata.manifest)?,
            format!("{:?}", metadata.source).to_lowercase(),
            metadata.manifest.repository,
            metadata.manifest.dependencies.get("signature").cloned(),
            format!("{:?}", metadata.status).to_lowercase(),
            metadata.installed_at,
            chrono::Utc::now(),
        )
        .execute(self.global_store.pool())
        .await?;

        Ok(())
    }

    /// Remove plugin from database
    async fn remove_from_db(&self, plugin_id: &PluginId) -> Result<()> {
        sqlx::query!("DELETE FROM plugins WHERE id = $1", plugin_id.as_uuid())
            .execute(self.global_store.pool())
            .await?;
        Ok(())
    }
}