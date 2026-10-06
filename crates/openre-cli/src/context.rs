use crate::error::CliError;
use std::sync::Arc;
use indicatif::{ProgressBar, ProgressStyle};

/// CLI execution context
pub struct Context;

impl Context {
    pub fn new() -> Self {
        Self
    }

    pub fn ai_client(&mut self) -> Result<Arc<crate::ai_stubs::AiClient>, CliError> {
        Err(CliError::AiDisabled)
    }

    pub fn spinner(&self, msg: impl AsRef<str>) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}").unwrap());
        pb.set_message(msg.as_ref().to_string());
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb
    }
}
