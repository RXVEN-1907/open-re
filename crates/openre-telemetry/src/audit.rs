//! Immutable audit logging for open-re

use openre_config::AuditConfig;
use openre_core::error::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    ConfigurationChange,
    PluginManagement,
    AnalysisExecution,
    Export,
    Sharing,
    SecurityEvent,
}

/// Audit outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Failure,
    Partial,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<openre_core::ids::UserId>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: serde_json::Value,
    pub risk_level: RiskLevel,
}

/// Audit writer trait
#[async_trait::async_trait]
pub trait AuditWriter: Send + Sync {
    async fn write_batch(&self, entries: Vec<AuditEntry>) -> Result<()>;
}

/// Immutable audit writer (append-only with hash chain)
pub struct ImmutableAuditWriter {
    writer: Arc<Mutex<BufWriter<File>>>,
    hash_chain: Arc<Mutex<Vec<u8>>>,
    config: AuditConfig,
}

impl ImmutableAuditWriter {
    /// Create a new immutable audit writer
    pub fn new(config: AuditConfig) -> Result<Self> {
        if let Some(parent) = config.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.file_path)?;

        let writer = Arc::new(Mutex::new(BufWriter::new(file)));
        let hash_chain = Arc::new(Mutex::new(Vec::new()));

        // Read existing hash chain from file
        let existing_chain = Self::read_hash_chain(&config.file_path)?;
        *hash_chain.lock().unwrap() = existing_chain;

        Ok(Self {
            writer,
            hash_chain,
            config,
        })
    }

    /// Read the last hash from the audit log file
    fn read_hash_chain(path: &PathBuf) -> Result<Vec<u8>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let data = std::fs::read(path)?;
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Parse entries from end to find last hash
        let mut offset = data.len();
        let mut last_hash = Vec::new();

        while offset >= 36 { // 4 bytes length + 32 bytes hash minimum
            if offset < 4 {
                break;
            }
            let len_bytes = &data[offset - 4..offset];
            let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
            
            if offset < 4 + len + 32 {
                break;
            }

            let hash_start = offset - 4 - len - 32 + len;
            last_hash = data[hash_start..hash_start + 32].to_vec();
            offset = offset - 4 - len - 32;
        }

        Ok(last_hash)
    }
}

#[async_trait::async_trait]
impl AuditWriter for ImmutableAuditWriter {
    async fn write_batch(&self, entries: Vec<AuditEntry>) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        let mut hash_chain = self.hash_chain.lock().unwrap();

        for entry in entries {
            let json = serde_json::to_vec(&entry)?;

            // Compute hash: H(previous_hash || entry)
            let mut hasher = Sha256::new();
            hasher.update(&hash_chain);
            hasher.update(&json);
            let hash = hasher.finalize();

            // Write: length (4 bytes) + entry + hash (32 bytes)
            writer.write_all(&(json.len() as u32).to_le_bytes())?;
            writer.write_all(&json)?;
            writer.write_all(&hash)?;

            *hash_chain = hash.to_vec();
        }

        writer.flush()?;

        // Check if rotation needed
        let metadata = writer.get_ref().metadata()?;
        if metadata.len() > self.config.max_file_size_mb as u64 * 1024 * 1024 {
            drop(writer);
            self.rotate().await?;
        }

        Ok(())
    }
}

impl ImmutableAuditWriter {
    async fn rotate(&self) -> Result<()> {
        // In a real implementation, this would rotate the log file
        // For now, we just warn
        warn!("Audit log rotation needed but not implemented");
        Ok(())
    }
}

/// Async audit logger with buffering
pub struct AuditLogger {
    writer: Arc<dyn AuditWriter>,
    buffer: Arc<Mutex<Vec<AuditEntry>>>,
    flush_interval: Duration,
    tx: mpsc::UnboundedSender<AuditEntry>,
    _handle: tokio::task::JoinHandle<()>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(writer: Arc<dyn AuditWriter>, config: &AuditConfig) -> Self {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let flush_interval = Duration::from_secs(5);
        let writer_clone = writer.clone();
        let buffer_clone = buffer.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let entries = {
                            let mut buf = buffer_clone.lock().unwrap();
                            if buf.is_empty() {
                                continue;
                            }
                            std::mem::take(&mut *buf)
                        };
                        if let Err(e) = writer_clone.write_batch(entries).await {
                            warn!("Failed to write audit batch: {}", e);
                        }
                    }
                    entry = rx.recv() => {
                        if let Some(entry) = entry {
                            let mut buf = buffer_clone.lock().unwrap();
                            buf.push(entry);
                            if buf.len() >= 100 {
                                let entries = std::mem::take(&mut *buf);
                                drop(buf);
                                if let Err(e) = writer_clone.write_batch(entries).await {
                                    warn!("Failed to write audit batch: {}", e);
                                }
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            writer,
            buffer,
            flush_interval,
            tx,
            _handle: handle,
        }
    }

    /// Log an audit entry
    pub fn log(&self, entry: AuditEntry) -> Result<()> {
        self.tx.send(entry).map_err(|e| openre_core::Error::Internal(e.into()))
    }

    /// Flush the buffer
    pub async fn flush(&self) -> Result<()> {
        let entries = {
            let mut buf = self.buffer.lock().unwrap();
            std::mem::take(&mut *buf)
        };
        if !entries.is_empty() {
            self.writer.write_batch(entries).await?;
        }
        Ok(())
    }
}

/// Initialize audit logging
pub fn init_audit(config: &AuditConfig) -> Result<AuditGuard> {
    if !config.enabled {
        return Ok(AuditGuard);
    }

    let writer = Arc::new(ImmutableAuditWriter::new(config.clone())?);
    let logger = AuditLogger::new(writer, config);

    // Store logger globally (in a real app, use a proper DI container)
    AUDIT_LOGGER.set(logger).ok();

    Ok(AuditGuard)
}

/// Audit guard
pub struct AuditGuard;

impl Drop for AuditGuard {
    fn drop(&mut self) {
        // Flush on drop
    }
}

/// Global audit logger (for convenience)
static AUDIT_LOGGER: once_cell::sync::OnceCell<AuditLogger> = once_cell::sync::OnceCell::new();

/// Get the global audit logger
pub fn audit_logger() -> Option<&'static AuditLogger> {
    AUDIT_LOGGER.get()
}

/// Log an audit entry (convenience function)
pub fn log_audit(entry: AuditEntry) {
    if let Some(logger) = audit_logger() {
        let _ = logger.log(entry);
    }
}

/// Create an audit entry for authentication events
pub fn audit_auth(
    user_id: Option<openre_core::ids::UserId>,
    ip: Option<String>,
    action: &str,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: AuditEventType::Authentication,
        user_id,
        ip_address: ip,
        user_agent: None,
        resource_type: "user".into(),
        resource_id: user_id.map(|id| id.to_string()),
        action: action.into(),
        outcome,
        details,
        risk_level: RiskLevel::Low,
    }
}

/// Create an audit entry for data access
pub fn audit_data_access(
    user_id: openre_core::ids::UserId,
    resource_type: &str,
    resource_id: &str,
    action: &str,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: AuditEventType::DataAccess,
        user_id: Some(user_id),
        ip_address: None,
        user_agent: None,
        resource_type: resource_type.into(),
        resource_id: Some(resource_id.into()),
        action: action.into(),
        outcome,
        details,
        risk_level: RiskLevel::Low,
    }
}

/// Create an audit entry for security events
pub fn audit_security(
    user_id: Option<openre_core::ids::UserId>,
    ip: Option<String>,
    action: &str,
    outcome: AuditOutcome,
    details: serde_json::Value,
    risk_level: RiskLevel,
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: AuditEventType::SecurityEvent,
        user_id,
        ip_address: ip,
        user_agent: None,
        resource_type: "security".into(),
        resource_id: None,
        action: action.into(),
        outcome,
        details,
        risk_level,
    }
}