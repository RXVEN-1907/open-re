//! Configuration layers and hot-reload support (stub - no file watching without notify crate)

use crate::Config;
use figment::{
    providers::{Env, Format, Serialized},
    Figment,
};
use openre_core::error::OpenreResult as Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use toml;
use tracing::info;

/// Configuration watcher for hot-reload (stub - disabled without notify crate)
pub struct ConfigWatcher {
    config: Arc<RwLock<Config>>,
    tx: broadcast::Sender<Config>,
    _rx: broadcast::Receiver<Config>,
}

impl ConfigWatcher {
    /// Create a new config watcher
    pub fn new(config: Config) -> Self {
        let (tx, rx) = broadcast::channel(16);
        Self { config: Arc::new(RwLock::new(config)), tx, _rx: rx }
    }

    /// Start watching configuration files (disabled without notify crate)
    pub async fn start(&mut self, _paths: Option<Vec<PathBuf>>) -> Result<()> {
        info!("Config file watching disabled (notify crate not available)");
        Ok(())
    }

    /// Reload configuration from files
    async fn reload_config(
        config: &Arc<RwLock<Config>>,
        tx: &broadcast::Sender<Config>,
        _paths: &[PathBuf],
    ) -> Result<()> {
        let config_path = crate::default_config_path();
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

        let mut config_guard = config.write().await;
        *config_guard = new_config.clone();
        let _ = tx.send(new_config);
        info!("Configuration reloaded");
        Ok(())
    }
}