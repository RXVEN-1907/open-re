//! Structured logging for open-re

use openre_config::LoggingConfig;
use openre_core::error::Result;
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use std::io;
use std::fs::File;
use std::path::PathBuf;

/// Initialize logging
pub fn init_logging(config: &LoggingConfig) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    let registry = Registry::default().with(env_filter);

    match config.output {
        openre_config::LogOutput::Stdout => {
            let fmt_layer = fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_writer(io::stdout);
            registry.with(fmt_layer).init();
        }
        openre_config::LogOutput::File => {
            let file = create_log_file(&config.file_path)?;
            let fmt_layer = fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_writer(file);
            registry.with(fmt_layer).init();
        }
        openre_config::LogOutput::Both => {
            let file = create_log_file(&config.file_path)?;
            let fmt_layer_stdout = fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_writer(io::stdout);
            let fmt_layer_file = fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_writer(file);
            registry.with(fmt_layer_stdout).with(fmt_layer_file).init();
        }
    }

    Ok(())
}

fn create_log_file(path: &Option<PathBuf>) -> Result<File> {
    let path = path.clone().unwrap_or_else(|| PathBuf::from("./logs/openre.log"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(File::create(path)?)
}

/// Structured logging macros
#[macro_export]
macro_rules! log_analysis {
    ($level:expr, $job_id:expr, $stage:expr, $msg:expr $(, $($key:expr => $val:expr),*)?) => {
        tracing::$level!(
            job_id = %$job_id,
            stage = %$stage,
            message = $msg,
            $($($key = $val),*)?
        );
    };
}

#[macro_export]
macro_rules! log_api {
    ($level:expr, $method:expr, $path:expr, $status:expr, $duration_ms:expr $(, $($key:expr => $val:expr),*)?) => {
        tracing::$level!(
            http_method = %$method,
            http_path = %$path,
            http_status = %$status,
            duration_ms = $duration_ms,
            $($($key = $val),*)?
        );
    };
}

#[macro_export]
macro_rules! log_plugin {
    ($level:expr, $plugin_id:expr, $capability:expr, $msg:expr $(, $($key:expr => $val:expr),*)?) => {
        tracing::$level!(
            plugin_id = %$plugin_id,
            capability = %$capability,
            message = $msg,
            $($($key = $val),*)?
        );
    };
}

#[macro_export]
macro_rules! log_ai {
    ($level:expr, $task:expr, $model:expr, $tokens:expr, $duration_ms:expr $(, $($key:expr => $val:expr),*)?) => {
        tracing::$level!(
            ai_task = %$task,
            ai_model = %$model,
            tokens = $tokens,
            duration_ms = $duration_ms,
            $($($key = $val),*)?
        );
    };
}