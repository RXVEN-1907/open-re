use crate::error::CliError;
use crate::output::OutputFormat;
use async_trait::async_trait;
use indicatif::{ProgressBar, ProgressStyle};
use openre_ai::tools::{GlobalStore, ObjectStore};
use openre_ai::AiService;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// CLI execution context: loaded config plus shared output/AI state.
pub struct Context {
    pub config: openre_config::Config,
    pub format: OutputFormat,
    pub no_ai: bool,
    ai: OnceCell<Arc<AiService>>,
}

impl Context {
    pub fn new() -> Result<Self, CliError> {
        let config = openre_config::Config::load()?;
        Ok(Self { config, format: OutputFormat::default(), no_ai: false, ai: OnceCell::new() })
    }

    /// Build the AI service from the loaded config on first use.
    pub async fn ai_client(&self) -> Result<Arc<AiService>, CliError> {
        if self.no_ai {
            return Err(CliError::AiDisabled);
        }
        let service = self
            .ai
            .get_or_try_init(|| async {
                let config = self.config.ai.clone();
                let global_store: Arc<dyn GlobalStore> = Arc::new(CliGlobalStore);
                let object_store: Arc<dyn ObjectStore> =
                    Arc::new(CliObjectStore { root: self.config.storage.local_path.clone() });
                AiService::new(config, global_store, object_store)
                    .await
                    .map(Arc::new)
                    .map_err(CliError::from)
            })
            .await?;
        Ok(Arc::clone(service))
    }

    pub fn spinner(&self, msg: impl AsRef<str>) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}").unwrap());
        pb.set_message(msg.as_ref().to_string());
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb
    }
}

/// The CLI registers no tool stores: AI tool execution is not available
/// through chat completion paths used by commands.
struct CliGlobalStore;

#[async_trait]
impl GlobalStore for CliGlobalStore {}

struct CliObjectStore {
    root: std::path::PathBuf,
}

#[async_trait]
impl ObjectStore for CliObjectStore {
    async fn read_file(
        &self,
        file_id: openre_core::ids::FileId,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, openre_core::Error> {
        let path = self.root.join(file_id.as_uuid().to_string());
        let data = std::fs::read(&path)?;
        let start = offset.min(data.len() as u64) as usize;
        let end = start.saturating_add(length as usize).min(data.len());
        Ok(data[start..end].to_vec())
    }
}
