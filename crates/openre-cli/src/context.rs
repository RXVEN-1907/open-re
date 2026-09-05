//! CLI execution context

use openre_config::Config;
use crate::ai_stubs::{AiClient, AiProvider};
use crate::{CliError, OutputFormat};
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;

pub struct Context {
    pub config: Config,
    pub format: OutputFormat,
    pub verbose: bool,
    pub offline: bool,
    pub ai_provider: AiProvider,
    pub ai_model: Option<String>,
    pub no_ai: bool,
    ai_client: Option<Arc<AiClient>>,
}

impl Context {
    pub fn new(
        config: Config,
        format: OutputFormat,
        verbose: bool,
        offline: bool,
        ai_provider: AiProvider,
        ai_model: Option<String>,
        no_ai: bool,
    ) -> Result<Self, CliError> {
        Ok(Self {
            config,
            format,
            verbose,
            offline,
            ai_provider,
            ai_model,
            no_ai,
            ai_client: None,
        })
    }

    pub fn ai_client(&mut self) -> Result<Arc<AiClient>, CliError> {
        if self.no_ai {
            return Err(CliError::AiDisabled);
        }

        if self.ai_client.is_none() {
            let client = AiClient::new(self.ai_provider, self.ai_model.clone())?;
            self.ai_client = Some(Arc::new(client));
        }

        Ok(self.ai_client.as_ref().unwrap().clone())
    }

    pub fn spinner(&self, msg: impl AsRef<str>) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(msg.as_ref().to_string());
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb
    }
}