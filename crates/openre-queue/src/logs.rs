//! Job logging infrastructure for open-re queue system

use crate::{LogEntry, LogLevel};
use openre_core::ids::JobId;
use openre_core::error::OpenreResult as Result;
use redis::{AsyncCommands, Client};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};
use tracing::{debug, error, info, warn};

/// Log manager for job logging using Redis Streams
pub struct LogManager {
    client: Client,
    log_streams: Arc<RwLock<HashMap<JobId, broadcast::Sender<LogEntry>>>>,
    max_log_entries: usize,
}

impl LogManager {
    /// Create a new log manager
    pub fn new(client: Client, max_log_entries: usize) -> Self {
        Self {
            client,
            log_streams: Arc::new(RwLock::new(HashMap::new())),
            max_log_entries,
        }
    }

    /// Add a log entry for a job
    pub async fn add_log(&self, entry: LogEntry) -> Result<()> {
        // Store in Redis stream for persistence
        self.store_log(&entry).await?;

        // Broadcast to any listeners
        if let Some(tx) = self.log_streams.read().await.get(&entry.job_id) {
            let _ = tx.send(entry);
        }

        Ok(())
    }

    /// Store log entry in Redis stream
    async fn store_log(&self, entry: &LogEntry) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let stream_name = format!("openre:logs:{}", entry.job_id);
        let log_data = serde_json::to_string(entry)?;

        let _: () = conn.xadd(&stream_name, "*", &[("data", log_data)]).await?;

        // Trim to max entries
        let _: () = conn.xtrim(&stream_name, redis::streams::StreamMaxlen::Approx(self.max_log_entries)).await?;

        Ok(())
    }

    /// Get all logs for a job
    pub async fn get_logs(&self, job_id: JobId, limit: Option<usize>) -> Result<Vec<LogEntry>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;

        let stream_name = format!("openre:logs:{}", job_id);
        let limit = limit.unwrap_or(self.max_log_entries);

        // Get latest entries
        let entries: Vec<redis::streams::StreamReadReply> = redis::cmd("XREVRANGE")
            .arg(&stream_name)
            .arg("+")
            .arg("-")
            .arg("COUNT")
            .arg(limit as isize)
            .query_async(&mut conn)
            .await?;

        let mut logs = Vec::new();
        for reply in entries {
            for key in reply.keys {
                for entry in key.ids {
                    if let Some(data) = entry.map.get("data") {
                        let log_data: String = redis::from_redis_value(data)?;
                        let log_entry: LogEntry = serde_json::from_str(&log_data)?;
                        logs.push(log_entry);
                    }
                }
            }
        }

        // Reverse to get chronological order
        logs.reverse();

        Ok(logs)
    }

    /// Create a log stream for following job logs in real-time
    pub async fn follow_logs(&self, job_id: JobId) -> Result<impl Stream<Item = LogEntry>> {
        // Get or create broadcast channel for this job
        let tx = {
            let mut streams = self.log_streams.write().await;
            streams.entry(job_id).or_insert_with(|| {
                let (tx, _) = broadcast::channel(1000);
                tx
            }).clone()
        };
        let rx = tx.subscribe();
        let stream = BroadcastStream::new(rx).then(|result| async move {
            match result {
                Ok(entry) => Some(entry),
                Err(_) => None,
            }
        })
        .filter_map(|x| x);

        Ok(stream)
    }

    /// Subscribe to log updates for a job (returns a receiver)
    pub async fn subscribe(&self, job_id: JobId) -> broadcast::Receiver<LogEntry> {
        let mut streams = self.log_streams.write().await;
        let tx = streams.entry(job_id).or_insert_with(|| {
            let (tx, _) = broadcast::channel(1000);
            tx
        }).clone();
        tx.subscribe()
    }

    /// Clean up log stream for a completed job
    pub async fn cleanup(&self, job_id: JobId) {
        self.log_streams.write().await.remove(&job_id);
    }

    /// Get log count for a job
    pub async fn get_log_count(&self, job_id: JobId) -> Result<usize> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let stream_name = format!("openre:logs:{}", job_id);
        let count: usize = conn.xlen(&stream_name).await?;
        Ok(count)
    }
}

/// Log writer for jobs to use during execution
pub struct JobLogWriter {
    log_manager: Arc<LogManager>,
    job_id: JobId,
}

impl JobLogWriter {
    /// Create a new log writer for a job
    pub fn new(log_manager: Arc<LogManager>, job_id: JobId) -> Self {
        Self { log_manager, job_id }
    }

    /// Log a trace message
    pub async fn trace(&self, message: impl Into<String>) -> Result<()> {
        self.log(LogLevel::Trace, message.into()).await
    }

    /// Log a debug message
    pub async fn debug(&self, message: impl Into<String>) -> Result<()> {
        self.log(LogLevel::Debug, message.into()).await
    }

    /// Log an info message
    pub async fn info(&self, message: impl Into<String>) -> Result<()> {
        self.log(LogLevel::Info, message.into()).await
    }

    /// Log a warning message
    pub async fn warn(&self, message: impl Into<String>) -> Result<()> {
        self.log(LogLevel::Warn, message.into()).await
    }

    /// Log an error message
    pub async fn error(&self, message: impl Into<String>) -> Result<()> {
        self.log(LogLevel::Error, message.into()).await
    }

    /// Log with metadata
    pub async fn log_with_metadata(
        &self,
        level: LogLevel,
        message: impl Into<String>,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        let entry = LogEntry {
            id: uuid::Uuid::new_v4(),
            job_id: self.job_id,
            timestamp: chrono::Utc::now(),
            level,
            message: message.into(),
            metadata,
        };
        self.log_manager.add_log(entry).await
    }

    async fn log(&self, level: LogLevel, message: String) -> Result<()> {
        let entry = LogEntry {
            id: uuid::Uuid::new_v4(),
            job_id: self.job_id,
            timestamp: chrono::Utc::now(),
            level,
            message,
            metadata: HashMap::new(),
        };
        self.log_manager.add_log(entry).await
    }
}

/// Convenience macro for logging
#[macro_export]
macro_rules! job_log {
    ($writer:expr, $level:ident, $($arg:tt)*) => {
        $writer.$level(format!($($arg)*)).await
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use openre_core::ids::JobId;
    use crate::LogLevel;
    use redis::Client;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_log_manager() {
        // This would need a real Redis connection
        // For now, just test the struct creation
        let client = Client::open("redis://localhost:6379").unwrap();
        let manager = LogManager::new(client, 1000);

        let job_id = JobId::new();
        let entry = LogEntry {
            id: Uuid::new_v4(),
            job_id,
            timestamp: chrono::Utc::now(),
            level: LogLevel::Info,
            message: "Test log".to_string(),
            metadata: HashMap::new(),
        };

        // Would fail without Redis, but struct is correct
        let _ = manager.add_log(entry).await;
    }
}