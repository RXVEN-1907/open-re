//! Plugin Manager - Plugin discovery, loading, capability registration, version checking, dependency handling, configuration, health checks, failure isolation

use crate::error::{ScannerError, ScannerResult};
use crate::target::TargetType;
use openre_core::ids::PluginId;
use openre_plugins::{Capability, Manifest, PluginInstance, PluginRuntime};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Plugin information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique plugin ID
    pub id: PluginId,
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Plugin author
    pub author: Option<String>,
    /// Plugin homepage
    pub homepage: Option<String>,
    /// Plugin repository
    pub repository: Option<String>,
    /// Plugin license
    pub license: Option<String>,
    /// Plugin capabilities
    pub capabilities: Vec<PluginCapability>,
    /// Plugin dependencies
    pub dependencies: Vec<PluginDependency>,
    /// Plugin configuration schema
    pub config_schema: Option<serde_json::Value>,
    /// Plugin default configuration
    pub default_config: Option<serde_json::Value>,
    /// Plugin tags
    pub tags: Vec<String>,
    /// Plugin status
    pub status: PluginStatus,
    /// Plugin source path
    pub source_path: Option<PathBuf>,
    /// Loaded timestamp
    pub loaded_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last health check
    pub last_health_check: Option<chrono::DateTime<chrono::Utc>>,
    /// Health check status
    pub health_status: HealthStatus,
}

/// Plugin capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapability {
    /// Capability name
    pub name: String,
    /// Capability description
    pub description: String,
    /// Target types this capability supports
    pub target_types: Vec<TargetType>,
    /// Required permissions
    pub permissions: Vec<String>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Whether this capability is enabled by default
    pub enabled_by_default: bool,
}

/// Plugin dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    /// Dependency plugin ID
    pub plugin_id: PluginId,
    /// Minimum version required
    pub min_version: String,
    /// Maximum version (exclusive)
    pub max_version: Option<String>,
    /// Whether dependency is optional
    pub optional: bool,
}

/// Plugin status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginStatus {
    /// Plugin is discovered but not loaded
    Discovered,
    /// Plugin is loading
    Loading,
    /// Plugin is loaded and ready
    Loaded,
    /// Plugin is enabled
    Enabled,
    /// Plugin is disabled
    Disabled,
    /// Plugin failed to load
    Failed(String),
    /// Plugin is unloading
    Unloading,
}

/// Health status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Health check not performed
    Unknown,
    /// Plugin is healthy
    Healthy,
    /// Plugin has warnings
    Warning(String),
    /// Plugin is unhealthy
    Unhealthy(String),
}

/// Risk level
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// No risk
    None,
    /// Low risk
    Low,
    /// Medium risk
    Medium,
    /// High risk
    High,
    /// Critical risk
    Critical,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Plugin ID
    pub plugin_id: PluginId,
    /// Whether plugin is enabled
    pub enabled: bool,
    /// Plugin-specific configuration
    pub config: serde_json::Value,
    /// Override capabilities
    pub capability_overrides: HashMap<String, bool>,
    /// Resource limits
    pub resource_limits: ResourceLimits,
}

/// Resource limits for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory in MB
    pub max_memory_mb: Option<u64>,
    /// Maximum CPU time in seconds
    pub max_cpu_time_secs: Option<u64>,
    /// Maximum network requests per minute
    pub max_network_requests_per_min: Option<u32>,
    /// Maximum file operations per minute
    pub max_file_ops_per_min: Option<u32>,
    /// Execution timeout
    pub timeout: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: Some(512),
            max_cpu_time_secs: Some(300),
            max_network_requests_per_min: Some(1000),
            max_file_ops_per_min: Some(10000),
            timeout: Duration::from_secs(300),
        }
    }
}

/// Plugin execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionResult {
    /// Plugin ID
    pub plugin_id: PluginId,
    /// Whether execution was successful
    pub success: bool,
    /// Findings discovered
    pub findings: Vec<crate::result::Finding>,
    /// Execution duration
    pub duration: Duration,
    /// Error message if failed
    pub error: Option<String>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Plugin Manager - manages plugin lifecycle
pub struct PluginManager {
    /// Plugin runtime
    runtime: Arc<PluginRuntime>,
    /// Loaded plugins
    plugins: Arc<dashmap::DashMap<PluginId, PluginInfo>>,
    /// Plugin configurations
    configs: Arc<dashmap::DashMap<PluginId, PluginConfig>>,
    /// Plugin instances
    instances: Arc<dashmap::DashMap<PluginId, Arc<dyn PluginInstance>>>,
    /// Plugin directory
    plugin_dir: PathBuf,
    /// Health check interval
    health_check_interval: Duration,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(plugin_dir: PathBuf) -> ScannerResult<Self> {
        let runtime = Arc::new(PluginRuntime::new()?);
        Ok(Self {
            runtime,
            plugins: Arc::new(dashmap::DashMap::new()),
            configs: Arc::new(dashmap::DashMap::new()),
            instances: Arc::new(dashmap::DashMap::new()),
            plugin_dir,
            health_check_interval: Duration::from_secs(300),
        })
    }

    /// Discover plugins in the plugin directory
    pub async fn discover_plugins(&self) -> ScannerResult<Vec<PluginInfo>> {
        let mut discovered = Vec::new();

        if !self.plugin_dir.exists() {
            return Ok(discovered);
        }

        let mut entries = tokio::fs::read_dir(&self.plugin_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                // Check for plugin manifest
                let manifest_path = path.join("plugin.toml");
                if manifest_path.exists() {
                    match self.load_plugin_manifest(&manifest_path).await {
                        Ok(plugin_info) => {
                            discovered.push(plugin_info);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to load plugin manifest at {:?}: {}",
                                manifest_path, e
                            );
                        }
                    }
                }
            } else if path.extension().map_or(false, |ext| ext == "wasm") {
                // WASM plugin
                match self.load_wasm_plugin(&path).await {
                    Ok(plugin_info) => {
                        discovered.push(plugin_info);
                    }
                    Err(e) => {
                        warn!("Failed to load WASM plugin at {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(discovered)
    }

    /// Load plugin manifest
    async fn load_plugin_manifest(&self, manifest_path: &PathBuf) -> ScannerResult<PluginInfo> {
        let content = tokio::fs::read_to_string(manifest_path).await?;
        let manifest: Manifest = toml::from_str(&content)?;

        let plugin_id = PluginId::from_string(&manifest.name)?;
        let plugin_dir = manifest_path.parent().unwrap().to_path_buf();

        let plugin_info = PluginInfo {
            id: plugin_id,
            name: manifest.name,
            version: manifest.version,
            description: manifest.description,
            author: manifest.author,
            homepage: manifest.homepage,
            repository: manifest.repository,
            license: manifest.license,
            capabilities: manifest
                .capabilities
                .into_iter()
                .map(|c| PluginCapability {
                    name: c.name,
                    description: c.description,
                    target_types: c.target_types,
                    permissions: c.permissions,
                    risk_level: c.risk_level,
                    enabled_by_default: c.enabled_by_default,
                })
                .collect(),
            dependencies: manifest
                .dependencies
                .into_iter()
                .map(|d| PluginDependency {
                    plugin_id: PluginId::from_string(&d.name).unwrap(),
                    min_version: d.min_version,
                    max_version: d.max_version,
                    optional: d.optional,
                })
                .collect(),
            config_schema: manifest.config_schema,
            default_config: manifest.default_config,
            tags: manifest.tags,
            status: PluginStatus::Discovered,
            source_path: Some(plugin_dir),
            loaded_at: None,
            last_health_check: None,
            health_status: HealthStatus::Unknown,
        };

        Ok(plugin_info)
    }

    /// Load WASM plugin
    async fn load_wasm_plugin(&self, path: &PathBuf) -> ScannerResult<PluginInfo> {
        // For WASM plugins, we need to load the manifest from the WASM module
        // or from a companion .toml file
        let manifest_path = path.with_extension("toml");
        if manifest_path.exists() {
            return self.load_plugin_manifest(&manifest_path).await;
        }

        // Try to extract metadata from WASM module
        let plugin_id = PluginId::from_string(&path.file_stem().unwrap().to_string_lossy())?;

        let plugin_info = PluginInfo {
            id: plugin_id,
            name: path.file_stem().unwrap().to_string_lossy().to_string(),
            version: "0.1.0".to_string(),
            description: "WASM plugin".to_string(),
            author: None,
            homepage: None,
            repository: None,
            license: None,
            capabilities: Vec::new(),
            dependencies: Vec::new(),
            config_schema: None,
            default_config: None,
            tags: vec!["wasm".to_string()],
            status: PluginStatus::Discovered,
            source_path: Some(path.clone()),
            loaded_at: None,
            last_health_check: None,
            health_status: HealthStatus::Unknown,
        };

        Ok(plugin_info)
    }

    /// Load a plugin
    pub async fn load_plugin(&self, plugin_id: &PluginId) -> ScannerResult<()> {
        let plugin_info = self
            .plugins
            .get(plugin_id)
            .ok_or_else(|| ScannerError::PluginNotFound(plugin_id.to_string()))?
            .clone();

        if plugin_info.status == PluginStatus::Loaded || plugin_info.status == PluginStatus::Enabled
        {
            return Ok(());
        }

        // Update status to loading
        self.update_plugin_status(plugin_id, PluginStatus::Loading)
            .await?;

        let source_path = plugin_info
            .source_path
            .clone()
            .ok_or_else(|| ScannerError::PluginLoadFailed("No source path".to_string()))?;

        // Load plugin instance
        let instance = if source_path.extension().map_or(false, |ext| ext == "wasm") {
            self.runtime.load_wasm_plugin(&source_path).await?
        } else {
            // Load from directory
            self.runtime.load_plugin(&source_path).await?
        };

        // Validate capabilities
        self.validate_capabilities(&plugin_info, &instance).await?;

        // Store instance
        self.instances.insert(*plugin_id, instance);

        // Update status
        let mut updated_info = plugin_info.clone();
        updated_info.status = PluginStatus::Loaded;
        updated_info.loaded_at = Some(chrono::Utc::now());
        self.plugins.insert(*plugin_id, updated_info);

        // Apply configuration
        self.apply_plugin_config(plugin_id).await?;

        info!("Loaded plugin: {}", plugin_id);
        Ok(())
    }

    /// Validate plugin capabilities
    async fn validate_capabilities(
        &self,
        plugin_info: &PluginInfo,
        instance: &Arc<dyn PluginInstance>,
    ) -> ScannerResult<()> {
        let instance_caps = instance.capabilities();
        for cap in &plugin_info.capabilities {
            if !instance_caps.iter().any(|c| c.name == cap.name) {
                return Err(ScannerError::PluginCapabilityMismatch(format!(
                    "Plugin declares capability '{}' but instance doesn't provide it",
                    cap.name
                )));
            }
        }
        Ok(())
    }

    /// Apply plugin configuration
    async fn apply_plugin_config(&self, plugin_id: &PluginId) -> ScannerResult<()> {
        if let Some(config) = self.configs.get(plugin_id) {
            if let Some(instance) = self.instances.get(plugin_id) {
                instance.configure(config.config.clone()).await?;
            }
        }
        Ok(())
    }

    /// Enable a plugin
    pub async fn enable_plugin(&self, plugin_id: &PluginId) -> ScannerResult<()> {
        let mut plugin_info = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| ScannerError::PluginNotFound(plugin_id.to_string()))?;

        if plugin_info.status == PluginStatus::Enabled {
            return Ok(());
        }

        if plugin_info.status != PluginStatus::Loaded {
            self.load_plugin(plugin_id).await?;
        }

        plugin_info.status = PluginStatus::Enabled;
        info!("Enabled plugin: {}", plugin_id);
        Ok(())
    }

    /// Disable a plugin
    pub async fn disable_plugin(&self, plugin_id: &PluginId) -> ScannerResult<()> {
        let mut plugin_info = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| ScannerError::PluginNotFound(plugin_id.to_string()))?;

        plugin_info.status = PluginStatus::Disabled;
        info!("Disabled plugin: {}", plugin_id);
        Ok(())
    }

    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_id: &PluginId) -> ScannerResult<()> {
        let mut plugin_info = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| ScannerError::PluginNotFound(plugin_id.to_string()))?;

        plugin_info.status = PluginStatus::Unloading;

        if let Some((_, instance)) = self.instances.remove(plugin_id) {
            instance.shutdown().await?;
        }

        plugin_info.status = PluginStatus::Discovered;
        plugin_info.loaded_at = None;
        info!("Unloaded plugin: {}", plugin_id);
        Ok(())
    }

    /// Update plugin status
    async fn update_plugin_status(
        &self,
        plugin_id: &PluginId,
        status: PluginStatus,
    ) -> ScannerResult<()> {
        if let Some(mut plugin_info) = self.plugins.get_mut(plugin_id) {
            plugin_info.status = status;
        }
        Ok(())
    }

    /// Get plugin info
    pub fn get_plugin(&self, plugin_id: &PluginId) -> Option<PluginInfo> {
        self.plugins.get(plugin_id).map(|p| p.clone())
    }

    /// List all plugins
    pub async fn list_plugins(&self) -> ScannerResult<Vec<PluginInfo>> {
        Ok(self.plugins.iter().map(|p| p.clone()).collect())
    }

    /// List enabled plugins
    pub async fn list_enabled_plugins(&self) -> ScannerResult<Vec<PluginInfo>> {
        Ok(self
            .plugins
            .iter()
            .filter(|p| p.status == PluginStatus::Enabled)
            .map(|p| p.clone())
            .collect())
    }

    /// Get plugin configuration
    pub fn get_plugin_config(&self, plugin_id: &PluginId) -> Option<PluginConfig> {
        self.configs.get(plugin_id).map(|c| c.clone())
    }

    /// Set plugin configuration
    pub async fn set_plugin_config(&self, config: PluginConfig) -> ScannerResult<()> {
        self.configs.insert(config.plugin_id, config.clone());
        if let Some(instance) = self.instances.get(&config.plugin_id) {
            instance.configure(config.config).await?;
        }
        Ok(())
    }

    /// Execute a plugin
    pub async fn execute_plugin(
        &self,
        plugin_id: &PluginId,
        context: &crate::context::ScanContext,
    ) -> ScannerResult<Vec<crate::result::Finding>> {
        let instance = self
            .instances
            .get(plugin_id)
            .ok_or_else(|| ScannerError::PluginNotFound(plugin_id.to_string()))?;

        let plugin_info = self
            .plugins
            .get(plugin_id)
            .ok_or_else(|| ScannerError::PluginNotFound(plugin_id.to_string()))?;

        if plugin_info.status != PluginStatus::Enabled {
            return Err(ScannerError::Plugin(format!(
                "Plugin {} is not enabled",
                plugin_id
            )));
        }

        // Execute with timeout
        let timeout_duration = self
            .get_plugin_config(plugin_id)
            .map(|c| c.resource_limits.timeout)
            .unwrap_or(Duration::from_secs(300));

        let result = tokio::time::timeout(timeout_duration, instance.execute(context)).await;

        match result {
            Ok(Ok(findings)) => Ok(findings),
            Ok(Err(e)) => Err(ScannerError::PluginExecutionFailed(e.to_string())),
            Err(_) => Err(ScannerError::Timeout(format!(
                "Plugin {} timed out",
                plugin_id
            ))),
        }
    }

    /// Perform health check on a plugin
    pub async fn health_check(&self, plugin_id: &PluginId) -> ScannerResult<HealthStatus> {
        let instance = self
            .instances
            .get(plugin_id)
            .ok_or_else(|| ScannerError::PluginNotFound(plugin_id.to_string()))?;

        let health = instance.health_check().await?;

        let status = match health {
            openre_plugins::HealthStatus::Healthy => HealthStatus::Healthy,
            openre_plugins::HealthStatus::Warning(msg) => HealthStatus::Warning(msg),
            openre_plugins::HealthStatus::Unhealthy(msg) => HealthStatus::Unhealthy(msg),
        };

        if let Some(mut plugin_info) = self.plugins.get_mut(plugin_id) {
            plugin_info.last_health_check = Some(chrono::Utc::now());
            plugin_info.health_status = status.clone();
        }

        Ok(status)
    }

    /// Perform health checks on all loaded plugins
    pub async fn health_check_all(&self) -> ScannerResult<HashMap<PluginId, HealthStatus>> {
        let mut results = HashMap::new();
        for plugin_id in self.instances.iter().map(|p| *p.key()) {
            let status = self.health_check(&plugin_id).await?;
            results.insert(plugin_id, status);
        }
        Ok(results)
    }

    /// Register a plugin manually
    pub fn register_plugin(&self, plugin_info: PluginInfo) {
        self.plugins.insert(plugin_info.id, plugin_info);
    }

    /// Get plugin instance
    pub fn get_instance(&self, plugin_id: &PluginId) -> Option<Arc<dyn PluginInstance>> {
        self.instances.get(plugin_id).map(|i| i.clone())
    }
}

impl Clone for PluginManager {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            plugins: self.plugins.clone(),
            configs: self.configs.clone(),
            instances: self.instances.clone(),
            plugin_dir: self.plugin_dir.clone(),
            health_check_interval: self.health_check_interval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_capability() {
        let cap = PluginCapability {
            name: "test".to_string(),
            description: "Test capability".to_string(),
            target_types: vec![TargetType::RestApi],
            permissions: vec!["network".to_string()],
            risk_level: RiskLevel::Low,
            enabled_by_default: true,
        };
        assert_eq!(cap.name, "test");
        assert_eq!(cap.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_plugin_dependency() {
        let dep = PluginDependency {
            plugin_id: PluginId::from_string("test").unwrap(),
            min_version: "1.0.0".to_string(),
            max_version: Some("2.0.0".to_string()),
            optional: false,
        };
        assert!(!dep.optional);
    }

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_memory_mb, Some(512));
        assert_eq!(limits.timeout, Duration::from_secs(300));
    }
}
