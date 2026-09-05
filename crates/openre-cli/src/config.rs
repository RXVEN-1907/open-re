//! CLI-specific configuration

use openre_config::{Config as CoreConfig, default_config_path};
use crate::{CliError, Result};
use std::path::PathBuf;

pub struct CliConfig {
    core: CoreConfig,
    path: Option<PathBuf>,
}

impl CliConfig {
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let core = if let Some(path) = config_path {
            CoreConfig::from_file(path)?
        } else {
            CoreConfig::load()?
        };

        Ok(Self {
            core,
            path: config_path.map(|p| p.to_path_buf()),
        })
    }

    pub fn core(&self) -> &CoreConfig {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut CoreConfig {
        &mut self.core
    }

    pub fn save(&self) -> Result<()> {
        if let Some(path) = &self.path {
            self.core.save_to_file(path)?;
        } else {
            self.core.save()?;
        }
        Ok(())
    }
}

// Delegate to core config
impl std::ops::Deref for CliConfig {
    type Target = CoreConfig;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl std::ops::DerefMut for CliConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}