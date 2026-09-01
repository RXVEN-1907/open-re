//! Scan Manager - Starting scans, stopping scans, scheduling plugins, tracking progress, timeouts, retries, cancellation

use crate::context::ScanContext;
use crate::error::{ScannerError, ScannerResult};
use crate::plugin::{PluginInfo, PluginManager};
use crate::result::Finding;
use crate::target::{ScanConfig, Target};
pub use openre_core::ids::{JobId, ScanId};
use openre_queue::QueueManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{timeout, Instant};
use tracing::error;

/// Status of a scan
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Scan is pending (queued)
    Pending,
    /// Scan is initializing
    Initializing,
    /// Scan is running
    Running,
    /// Scan is paused
    Paused,
    /// Scan completed successfully
    Completed,
    /// Scan failed
    Failed(String),
    /// Scan was cancelled
    Cancelled,
    /// Scan timed out
    TimedOut,
}

impl ScanStatus {
    /// Check if scan is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ScanStatus::Completed
                | ScanStatus::Failed(_)
                | ScanStatus::Cancelled
                | ScanStatus::TimedOut
        )
    }

    /// Check if scan is active
    pub fn is_active(&self) -> bool {
        matches!(self, ScanStatus::Initializing | ScanStatus::Running)
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Pending => write!(f, "pending"),
            ScanStatus::Initializing => write!(f, "initializing"),
            ScanStatus::Running => write!(f, "running"),
            ScanStatus::Paused => write!(f, "paused"),
            ScanStatus::Completed => write!(f, "completed"),
            ScanStatus::Failed(msg) => write!(f, "failed: {}", msg),
            ScanStatus::Cancelled => write!(f, "cancelled"),
            ScanStatus::TimedOut => write!(f, "timed_out"),
        }
    }
}

impl std::str::FromStr for ScanStatus {
    type Err = ScannerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim() {
            "pending" => ScanStatus::Pending,
            "initializing" => ScanStatus::Initializing,
            "running" => ScanStatus::Running,
            "paused" => ScanStatus::Paused,
            "completed" => ScanStatus::Completed,
            "cancelled" => ScanStatus::Cancelled,
            "timed_out" => ScanStatus::TimedOut,
            other => ScanStatus::Failed(other.to_string()),
        })
    }
}

/// Progress of a scan
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScanProgress {
    /// Scan ID
    pub scan_id: ScanId,
    /// Current status
    pub status: ScanStatus,
    /// Total plugins to run
    pub total_plugins: usize,
    /// Plugins completed
    pub completed_plugins: usize,
    /// Plugins failed
    pub failed_plugins: usize,
    /// Current plugin running
    pub current_plugin: Option<String>,
    /// Total findings found
    pub total_findings: usize,
    /// Findings by severity
    pub findings_by_severity: HashMap<String, usize>,
    /// Start time
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Estimated completion time
    pub estimated_completion: Option<chrono::DateTime<chrono::Utc>>,
    /// Elapsed time
    pub elapsed: Duration,
    /// Progress percentage (0-100)
    pub progress_percent: f32,
}

impl ScanProgress {
    /// Create new scan progress
    pub fn new(scan_id: ScanId) -> Self {
        Self {
            scan_id,
            status: ScanStatus::Pending,
            total_plugins: 0,
            completed_plugins: 0,
            failed_plugins: 0,
            current_plugin: None,
            total_findings: 0,
            findings_by_severity: HashMap::new(),
            started_at: None,
            estimated_completion: None,
            elapsed: Duration::ZERO,
            progress_percent: 0.0,
        }
    }

    /// Update progress
    pub fn update(&mut self, status: ScanStatus, completed: usize, total: usize) {
        self.status = status;
        self.completed_plugins = completed;
        self.total_plugins = total;
        self.progress_percent =
            if total > 0 { (completed as f32 / total as f32) * 100.0 } else { 0.0 };
    }

    /// Add finding
    pub fn add_finding(&mut self, severity: &str) {
        self.total_findings += 1;
        *self.findings_by_severity.entry(severity.to_string()).or_insert(0) += 1;
    }

    /// Set current plugin
    pub fn set_current_plugin(&mut self, plugin: String) {
        self.current_plugin = Some(plugin);
    }
}

/// Scan session containing all scan state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    /// Unique scan ID
    pub id: ScanId,
    /// Scan configuration
    pub config: ScanConfig,
    /// Target being scanned
    pub target: Target,
    /// Current status
    pub status: ScanStatus,
    /// Progress information
    pub progress: ScanProgress,
    /// Findings discovered
    pub findings: Vec<Finding>,
    /// Plugin execution records
    pub plugin_executions: Vec<PluginExecutionRecord>,
    /// Scan logs
    pub logs: Vec<ScanLogEntry>,
    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Started timestamp
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Completed timestamp
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Cancellation token
    #[serde(skip)]
    pub cancellation_token: Option<CancellationToken>,
}

/// Plugin execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionRecord {
    /// Plugin ID
    pub plugin_id: String,
    /// Plugin name
    pub plugin_name: String,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// End time
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Status
    pub status: PluginExecutionStatus,
    /// Findings discovered
    pub findings_count: usize,
    /// Error message if failed
    pub error: Option<String>,
    /// Duration
    pub duration: Option<Duration>,
}

/// Plugin execution status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

/// Scan log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanLogEntry {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Log level
    pub level: String,
    /// Plugin name (if applicable)
    pub plugin: Option<String>,
    /// Message
    pub message: String,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Cancellation token for scan cancellation
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<parking_lot::Mutex<bool>>,
    sender: broadcast::Sender<()>,
}

impl CancellationToken {
    /// Create a new cancellation token
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1);
        Self { cancelled: Arc::new(parking_lot::Mutex::new(false)), sender }
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.lock()
    }

    /// Cancel the token
    pub fn cancel(&self) {
        *self.cancelled.lock() = true;
        let _ = self.sender.send(());
    }

    /// Subscribe to cancellation
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.sender.subscribe()
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan Manager - orchestrates scan execution
pub struct ScanManager {
    /// Queue manager for job scheduling
    queue_manager: Arc<QueueManager>,
    /// Plugin manager
    plugin_manager: Arc<PluginManager>,
    /// Scan storage
    storage: Arc<dyn ScanStorage>,
    /// Active scans
    active_scans: Arc<dashmap::DashMap<ScanId, ScanSession>>,
    /// Progress broadcaster
    progress_tx: broadcast::Sender<ScanProgress>,
    /// Default scan timeout
    default_timeout: Duration,
}

impl ScanManager {
    /// Create a new scan manager
    pub fn new(
        queue_manager: Arc<QueueManager>,
        plugin_manager: Arc<PluginManager>,
        storage: Arc<dyn ScanStorage>,
    ) -> Self {
        let (progress_tx, _) = broadcast::channel(100);
        Self {
            queue_manager,
            plugin_manager,
            storage,
            active_scans: Arc::new(dashmap::DashMap::new()),
            progress_tx,
            default_timeout: Duration::from_secs(3600),
        }
    }

    /// Start a new scan
    pub async fn start_scan(&self, config: ScanConfig, target: Target) -> ScannerResult<ScanId> {
        // Validate target
        target.validate()?;

        // Create scan session
        let scan_id = ScanId::new();
        let cancellation_token = CancellationToken::new();
        let mut progress = ScanProgress::new(scan_id);

        let session = ScanSession {
            id: scan_id,
            config: config.clone(),
            target: target.clone(),
            status: ScanStatus::Initializing,
            progress: progress.clone(),
            findings: Vec::new(),
            plugin_executions: Vec::new(),
            logs: Vec::new(),
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            cancellation_token: Some(cancellation_token.clone()),
        };

        // Store session
        self.active_scans.insert(scan_id, session.clone());
        self.storage.save_scan(&session).await?;

        // Get plugins to run
        let plugins = self.get_plugins_for_scan(&config, &target).await?;
        progress.total_plugins = plugins.len();

        // Update status to running
        self.update_scan_status(scan_id, ScanStatus::Running).await?;
        progress.status = ScanStatus::Running;
        progress.started_at = Some(chrono::Utc::now());
        self.broadcast_progress(progress.clone());

        // Spawn scan execution task
        let scan_manager = self.clone();
        let cancellation_token_clone = cancellation_token.clone();
        tokio::spawn(async move {
            if let Err(e) = scan_manager
                .execute_scan(scan_id, config, target, plugins, cancellation_token_clone)
                .await
            {
                error!("Scan {} failed: {}", scan_id, e);
                let _ = scan_manager
                    .update_scan_status(scan_id, ScanStatus::Failed(e.to_string()))
                    .await;
            }
        });

        Ok(scan_id)
    }

    /// Execute a scan
    async fn execute_scan(
        &self,
        scan_id: ScanId,
        config: ScanConfig,
        target: Target,
        plugins: Vec<PluginInfo>,
        cancellation_token: CancellationToken,
    ) -> ScannerResult<()> {
        let start_time = Instant::now();
        let mut completed = 0;
        let mut failed = 0;
        let mut findings = Vec::new();
        let mut plugin_executions = Vec::new();

        // Create scan context
        let context = ScanContext::new(scan_id, config.clone(), target.clone())?;

        // Run plugins with concurrency control
        let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_plugins));
        let total_plugins = plugins.len();
        let mut handles = Vec::new();

        for plugin in plugins {
            // Check cancellation
            if cancellation_token.is_cancelled() {
                self.update_scan_status(scan_id, ScanStatus::Cancelled).await?;
                return Ok(());
            }

            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let plugin_manager = self.plugin_manager.clone();
            let context = context.clone();
            let _cancellation_token = cancellation_token.clone();
            let plugin_timeout = config.plugin_timeout;
            let plugin_name = plugin.name.clone();
            let plugin_id = plugin.id.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit; // Hold permit for duration
                let execution_start = Instant::now();

                // Create execution record
                let mut execution = PluginExecutionRecord {
                    plugin_id: plugin_id.to_string(),
                    plugin_name: plugin_name.clone(),
                    started_at: chrono::Utc::now(),
                    completed_at: None,
                    status: PluginExecutionStatus::Running,
                    findings_count: 0,
                    error: None,
                    duration: None,
                };

                // Run plugin with timeout
                let result =
                    timeout(plugin_timeout, plugin_manager.execute_plugin(&plugin_id, &context))
                        .await;

                execution.completed_at = Some(chrono::Utc::now());
                execution.duration = Some(execution_start.elapsed());

                match result {
                    Ok(Ok(plugin_findings)) => {
                        execution.status = PluginExecutionStatus::Completed;
                        execution.findings_count = plugin_findings.len();
                        (plugin_findings, execution, None)
                    }
                    Ok(Err(e)) => {
                        execution.status = PluginExecutionStatus::Failed;
                        execution.error = Some(e.to_string());
                        (Vec::new(), execution, Some(e))
                    }
                    Err(_) => {
                        execution.status = PluginExecutionStatus::TimedOut;
                        execution.error = Some("Plugin execution timed out".to_string());
                        (
                            Vec::new(),
                            execution,
                            Some(ScannerError::Timeout(format!(
                                "Plugin {} timed out",
                                plugin_name
                            ))),
                        )
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all plugins to complete
        for handle in handles {
            let (plugin_findings, execution, error) = handle.await.unwrap();
            plugin_executions.push(execution.clone());

            if let Some(e) = error {
                failed += 1;
                self.add_log(
                    scan_id,
                    "error",
                    Some(execution.plugin_name.clone()),
                    &e.to_string(),
                    HashMap::new(),
                )
                .await?;
            } else {
                completed += 1;
                for finding in &plugin_findings {
                    self.add_finding(scan_id, finding.clone()).await?;
                }
                findings.extend(plugin_findings);
            }

            // Update progress
            self.update_scan_progress(scan_id, completed, failed, total_plugins).await?;
        }

        // Finalize scan
        let final_status = if failed > 0 && completed == 0 {
            ScanStatus::Failed("All plugins failed".to_string())
        } else if failed > 0 {
            ScanStatus::Completed // Partial success
        } else {
            ScanStatus::Completed
        };

        self.finalize_scan(
            scan_id,
            final_status,
            findings,
            plugin_executions,
            start_time.elapsed(),
        )
        .await?;

        Ok(())
    }

    /// Get plugins compatible with scan config and target
    async fn get_plugins_for_scan(
        &self,
        config: &ScanConfig,
        target: &Target,
    ) -> ScannerResult<Vec<PluginInfo>> {
        let all_plugins = self.plugin_manager.list_plugins().await?;

        let mut compatible = Vec::new();
        for plugin in all_plugins {
            // Check if plugin is explicitly excluded
            if config.exclude_plugins.contains(&plugin.id.to_string()) {
                continue;
            }

            // Check if plugin is explicitly included (if list not empty)
            if !config.plugins.is_empty() && !config.plugins.contains(&plugin.id.to_string()) {
                continue;
            }

            // Check if plugin supports target type
            if plugin.capabilities.iter().any(|c| c.target_types.contains(&target.target_type)) {
                compatible.push(plugin);
            }
        }

        Ok(compatible)
    }

    /// Update scan status
    async fn update_scan_status(&self, scan_id: ScanId, status: ScanStatus) -> ScannerResult<()> {
        if let Some(mut session) = self.active_scans.get_mut(&scan_id) {
            if status.is_terminal() {
                session.completed_at = Some(chrono::Utc::now());
            }
            session.status = status.clone();
            session.progress.status = status;
            self.storage.save_scan(&session).await?;
            self.broadcast_progress(session.progress.clone());
        }
        Ok(())
    }

    /// Update scan progress
    async fn update_scan_progress(
        &self,
        scan_id: ScanId,
        completed: usize,
        failed: usize,
        total: usize,
    ) -> ScannerResult<()> {
        if let Some(mut session) = self.active_scans.get_mut(&scan_id) {
            let status = session.status.clone();
            session.progress.update(status, completed, total);
            session.progress.failed_plugins = failed;
            session.progress.elapsed = session.started_at.map_or(Duration::ZERO, |start| {
                chrono::Utc::now().signed_duration_since(start).to_std().unwrap_or(Duration::ZERO)
            });
            self.storage.save_scan(&session).await?;
            self.broadcast_progress(session.progress.clone());
        }
        Ok(())
    }

    /// Add finding to scan
    async fn add_finding(&self, scan_id: ScanId, finding: Finding) -> ScannerResult<()> {
        if let Some(mut session) = self.active_scans.get_mut(&scan_id) {
            session.findings.push(finding.clone());
            session.progress.add_finding(&finding.severity.to_string());
            self.storage.save_finding(scan_id, &finding).await?;
        }
        Ok(())
    }

    /// Add log entry
    async fn add_log(
        &self,
        scan_id: ScanId,
        level: &str,
        plugin: Option<String>,
        message: &str,
        metadata: HashMap<String, serde_json::Value>,
    ) -> ScannerResult<()> {
        if let Some(mut session) = self.active_scans.get_mut(&scan_id) {
            let entry = ScanLogEntry {
                timestamp: chrono::Utc::now(),
                level: level.to_string(),
                plugin,
                message: message.to_string(),
                metadata,
            };
            session.logs.push(entry.clone());
            self.storage.save_log(scan_id, &entry).await?;
        }
        Ok(())
    }

    /// Finalize scan
    async fn finalize_scan(
        &self,
        scan_id: ScanId,
        status: ScanStatus,
        findings: Vec<Finding>,
        plugin_executions: Vec<PluginExecutionRecord>,
        duration: Duration,
    ) -> ScannerResult<()> {
        if let Some(mut session) = self.active_scans.get_mut(&scan_id) {
            session.status = status.clone();
            session.progress.status = status;
            session.findings = findings;
            session.plugin_executions = plugin_executions;
            session.completed_at = Some(chrono::Utc::now());
            session.progress.elapsed = duration;
            session.progress.progress_percent = 100.0;

            self.storage.save_scan(&session).await?;
            self.broadcast_progress(session.progress.clone());

            // Remove from active scans after a delay
            let active_scans = self.active_scans.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                active_scans.remove(&scan_id);
            });
        }
        Ok(())
    }

    /// Broadcast progress update
    fn broadcast_progress(&self, progress: ScanProgress) {
        let _ = self.progress_tx.send(progress);
    }

    /// Subscribe to progress updates
    pub fn subscribe_progress(&self) -> broadcast::Receiver<ScanProgress> {
        self.progress_tx.subscribe()
    }

    /// Get scan session
    pub fn get_scan(&self, scan_id: &ScanId) -> Option<ScanSession> {
        self.active_scans.get(scan_id).map(|s| s.clone())
    }

    /// List all scans
    pub fn list_scans(&self) -> Vec<ScanSession> {
        self.active_scans.iter().map(|s| s.clone()).collect()
    }

    /// Cancel a scan
    pub async fn cancel_scan(&self, scan_id: &ScanId) -> ScannerResult<()> {
        if let Some(session) = self.active_scans.get(scan_id) {
            if let Some(token) = &session.cancellation_token {
                token.cancel();
            }
            self.update_scan_status(*scan_id, ScanStatus::Cancelled).await?;
            Ok(())
        } else {
            Err(ScannerError::ScanNotFound(scan_id.to_string()))
        }
    }

    /// Pause a scan
    pub async fn pause_scan(&self, scan_id: &ScanId) -> ScannerResult<()> {
        self.update_scan_status(*scan_id, ScanStatus::Paused).await
    }

    /// Resume a scan
    pub async fn resume_scan(&self, scan_id: &ScanId) -> ScannerResult<()> {
        if let Some(session) = self.active_scans.get(scan_id) {
            if session.status == ScanStatus::Paused {
                self.update_scan_status(*scan_id, ScanStatus::Running).await?;
                Ok(())
            } else {
                Err(ScannerError::Scan("Scan is not paused".to_string()))
            }
        } else {
            Err(ScannerError::ScanNotFound(scan_id.to_string()))
        }
    }

    /// Get scan progress
    pub fn get_progress(&self, scan_id: &ScanId) -> Option<ScanProgress> {
        self.active_scans.get(scan_id).map(|s| s.progress.clone())
    }

    /// Get scan findings
    pub fn get_findings(&self, scan_id: &ScanId) -> Vec<Finding> {
        self.active_scans.get(scan_id).map(|s| s.findings.clone()).unwrap_or_default()
    }

    /// Get scan logs
    pub fn get_logs(&self, scan_id: &ScanId) -> Vec<ScanLogEntry> {
        self.active_scans.get(scan_id).map(|s| s.logs.clone()).unwrap_or_default()
    }
}

impl Clone for ScanManager {
    fn clone(&self) -> Self {
        Self {
            queue_manager: self.queue_manager.clone(),
            plugin_manager: self.plugin_manager.clone(),
            storage: self.storage.clone(),
            active_scans: self.active_scans.clone(),
            progress_tx: self.progress_tx.clone(),
            default_timeout: self.default_timeout,
        }
    }
}

/// Trait for scan storage
#[async_trait::async_trait]
pub trait ScanStorage: Send + Sync {
    async fn save_scan(&self, session: &ScanSession) -> ScannerResult<()>;
    async fn get_scan(&self, scan_id: &ScanId) -> ScannerResult<Option<ScanSession>>;
    async fn list_scans(&self, limit: usize, offset: usize) -> ScannerResult<Vec<ScanSession>>;
    async fn delete_scan(&self, scan_id: &ScanId) -> ScannerResult<bool>;
    async fn save_finding(&self, scan_id: ScanId, finding: &Finding) -> ScannerResult<()>;
    async fn get_findings(&self, scan_id: &ScanId) -> ScannerResult<Vec<Finding>>;
    async fn save_log(&self, scan_id: ScanId, log: &ScanLogEntry) -> ScannerResult<()>;
    async fn get_logs(&self, scan_id: &ScanId) -> ScannerResult<Vec<ScanLogEntry>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_status() {
        assert!(!ScanStatus::Pending.is_terminal());
        assert!(!ScanStatus::Running.is_terminal());
        assert!(ScanStatus::Completed.is_terminal());
        assert!(ScanStatus::Failed("error".to_string()).is_terminal());
        assert!(ScanStatus::Cancelled.is_terminal());
    }

    #[test]
    fn test_scan_progress() {
        let scan_id = ScanId::new();
        let mut progress = ScanProgress::new(scan_id);
        assert_eq!(progress.progress_percent, 0.0);

        progress.update(ScanStatus::Running, 5, 10);
        assert_eq!(progress.progress_percent, 50.0);

        progress.add_finding("high");
        progress.add_finding("medium");
        assert_eq!(progress.total_findings, 2);
        assert_eq!(progress.findings_by_severity.get("high"), Some(&1));
    }

    #[test]
    fn test_cancellation_token() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }
}
