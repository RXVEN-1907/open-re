//! Configuration layers and hot-reload support

use crate::Config;
use figment::{
    providers::{Env, Format, Serialized},
    Figment,
};
use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use openre_core::error::OpenreResult as Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};

/// Configuration watcher for hot-reload
pub struct ConfigWatcher {
    config: Arc<RwLock<Config>>,
    watcher: Option<RecommendedWatcher>,
    tx: broadcast::Sender<Config>,
    _rx: broadcast::Receiver<Config>,
}

impl ConfigWatcher {
    /// Create a new config watcher
    pub fn new(config: Config) -> Self {
        let (tx, rx) = broadcast::channel(16);
        Self { config: Arc::new(RwLock::new(config)), watcher: None, tx, _rx: rx }
    }

    /// Start watching configuration files
    pub async fn start(&mut self, paths: Option<Vec<PathBuf>>) -> Result<()> {
        let config = self.config.clone();
        let tx = self.tx.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: std::result::Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        // Debounce: wait a bit before reloading
                        let config = config.clone();
                        let tx = tx.clone();
                        let paths = event.paths.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            if let Err(e) = Self::reload_config(&config, &tx, &paths).await {
                                warn!("Failed to reload config: {}", e);
                            }
                        });
                    }
                }
            },
            NotifyConfig::default(),
        )?;

        let watch_paths = paths.unwrap_or_else(|| {
            let config_dir = crate::default_config_dir();
            vec![
                config_dir.join("config.toml"),
                config_dir.join("config.local.toml"),
                config_dir.join("config.local.json"),
            ]
        });

        for path in watch_paths {
            if path.exists() {
                watcher.watch(&path, RecursiveMode::NonRecursive)?;
                info!("Watching config file: {}", path.display());
            }
        }

        self.watcher = Some(watcher);
        Ok(())
    }

    /// Reload configuration from files
    async fn reload_config(
        config: &Arc<RwLock<Config>>,
        tx: &broadcast::Sender<Config>,
        _paths: &[PathBuf],
    ) -> Result<()> {
        let config_path = crate::config::default_config_path();
        let config_dir = config_path.parent().unwrap().to_path_buf();
        let local_config_path = config_dir.join("config.local.toml");
        let local_json_path = config_dir.join("config.local.json");

        let figment = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(figment::providers::Toml::file(&config_path))
            .merge(figment::providers::Toml::file(&local_config_path))
            .merge(Env::prefixed("OPENRE_").split("__"))
            .merge(figment::providers::Json::file(&local_json_path));

        let new_config: Config =
            figment.extract().map_err(|e| openre_core::Error::Config(e.to_string()))?;
        new_config.validate()?;

        let mut guard = config.write().await;
        *guard = new_config.clone();
        drop(guard);

        let _ = tx.send(new_config);
        info!("Configuration reloaded successfully");
        Ok(())
    }

    /// Get current configuration
    pub async fn get(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Subscribe to configuration changes
    pub fn subscribe(&self) -> broadcast::Receiver<Config> {
        self.tx.subscribe()
    }

    /// Update configuration programmatically
    pub async fn update<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Config),
    {
        let mut guard = self.config.write().await;
        f(&mut guard);
        guard.validate()?;
        let new_config = guard.clone();
        drop(guard);

        let _ = self.tx.send(new_config);
        Ok(())
    }
}

/// Layered configuration builder
pub struct ConfigBuilder {
    figment: Figment,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self { figment: Figment::new() }
    }

    pub fn defaults<T: Serialize>(mut self, defaults: T) -> Self {
        self.figment = self.figment.merge(Serialized::defaults(defaults));
        self
    }

    pub fn toml_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.figment = self.figment.merge(figment::providers::Toml::file(path.into()));
        self
    }

    pub fn json_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.figment = self.figment.merge(figment::providers::Json::file(path.into()));
        self
    }

    pub fn env(mut self, prefix: &str) -> Self {
        self.figment = self.figment.merge(Env::prefixed(prefix).split("__"));
        self
    }

    pub fn build<T: for<'de> Deserialize<'de>>(self) -> Result<T> {
        self.figment.extract().map_err(|e| openre_core::Error::Config(e.to_string()))
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
